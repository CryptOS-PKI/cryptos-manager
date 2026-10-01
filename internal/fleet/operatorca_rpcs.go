package fleet

/*
Copyright The CryptOS Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// After first run, operator CA changes go through these admin RPCs: register
// a new CA (the old active one becomes retiring, both trusted), retire one,
// and change a CA's CRL source, CRL or OCSP mode. Every change is audited,
// rebuilds the trust store on this replica and moves the trust version, so
// the other replicas follow within one poll. A config-file operator CA can't
// be changed here (1607).

// Retired reasons.
const (
	retiredByAdmin = "retired"
)

// OperatorCAAdmin is what the operator CA admin RPCs need besides the trust
// store: a CRL fetch for CRL URLs, and the OCSP responder probe for url
// mode. A nil Probe uses the revocation engine's OCSP client.
type OperatorCAAdmin struct {
	FetchCRL func(ctx context.Context, url string) ([]byte, error)
	Probe    func(ctx context.Context, anchor *x509.Certificate, url string) (operatorca.OCSPResult, error)
}

// WithOperatorCAAdmin supplies the operator CA admin seams. Returns s for
// chaining.
func (s *Service) WithOperatorCAAdmin(a OperatorCAAdmin) *Service {
	s.caAdmin = a

	return s
}

func (s *Service) probe() func(context.Context, *x509.Certificate, string) (operatorca.OCSPResult, error) {
	if s.caAdmin.Probe != nil {
		return s.caAdmin.Probe
	}
	if s.revocations != nil && s.revocations.OCSP() != nil {
		return s.revocations.OCSP().ProbeResult
	}
	return nil
}

func (s *Service) nodeCAs() []*x509.Certificate {
	return operatorca.NodeCAs(s.store.Nodes(), os.ReadFile, log.Printf)
}

// caErr gives an operator CA refusal its transport code: a 1605 rejection
// is InvalidArgument, any other coded refusal FailedPrecondition.
func caErr(err error) error {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return err
	}
	code, ok := apperr.Code(err)
	switch {
	case ok && code == apperr.CodeOperatorCARejected:
		return connect.NewError(connect.CodeInvalidArgument, err)
	case ok:
		return connect.NewError(connect.CodeFailedPrecondition, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

func caReject(code connect.Code, reason fleetv1.ErrorReason, format string, args ...any) error {
	return connect.NewError(code, apperr.Reasoned(apperr.CodeOperatorCARejected, reason, fmt.Errorf("fleet: "+format, args...)))
}

func failedPrecondition(format string, args ...any) error {
	return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("fleet: "+format, args...))
}

// operatorCAWrite is the gate every operator CA write passes: an admin, an
// operator CA source, and not the config file.
func (s *Service) operatorCAWrite(ctx context.Context, op string) (authz.Identity, store.OperatorTrust, error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return authz.Identity{}, nil, err
	}
	if err := requireAdmin(ctx); err != nil {
		return authz.Identity{}, nil, err
	}
	if !s.hasOperatorCA() {
		return authz.Identity{}, nil, errOperatorCAUnconfigured(op)
	}
	if s.trust.Source().Kind == operatorca.KindFile {
		log.Printf("fleet: %s refused: the operator CA comes from operatorCAPath", op)
		return authz.Identity{}, nil, connect.NewError(connect.CodeFailedPrecondition, apperr.Coded(apperr.CodeOperatorCAManagedByConfig,
			fmt.Errorf("fleet: the operator CA comes from operatorCAPath in the config file (%s); change the config instead", s.trust.Source().Path)))
	}
	ot, ok := s.store.(store.OperatorTrust)
	if !ok {
		return authz.Identity{}, nil, errOperatorCAUnconfigured(op)
	}
	return id, ot, nil
}

// trustedRow returns the active or retiring row with the fingerprint and
// its certificate.
func trustedRow(ctx context.Context, ot store.OperatorTrust, sha string) (store.OperatorCA, *x509.Certificate, error) {
	row, err := findRow(ctx, ot, sha)
	if err != nil {
		return store.OperatorCA{}, nil, err
	}
	if row.State == store.OperatorCARetired {
		return store.OperatorCA{}, nil, failedPrecondition("operator CA %s is retired; register it again to trust it", row.SHA256)
	}
	cert, err := x509.ParseCertificate(row.CertDER)
	if err != nil {
		return store.OperatorCA{}, nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: the stored operator CA %s doesn't parse: %w", row.SHA256, err))
	}
	return row, cert, nil
}

func findRow(ctx context.Context, ot store.OperatorTrust, sha string) (store.OperatorCA, error) {
	sha = normalizeFingerprint(sha)
	rows, err := ot.OperatorCAs(ctx)
	if err != nil {
		return store.OperatorCA{}, connect.NewError(connect.CodeInternal, err)
	}
	for _, r := range rows {
		if r.SHA256 == sha {
			return r, nil
		}
	}
	return store.OperatorCA{}, connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: no operator CA has the SHA-256 %s", sha))
}

// applyTrustChange makes a stored change take effect on this replica at
// once; the others follow on their next poll.
func (s *Service) applyTrustChange(ctx context.Context) error {
	if err := s.trust.Rebuild(ctx); err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: rebuild operator CA trust: %w", err))
	}
	if err := s.revocations.Reload(ctx); err != nil {
		log.Printf("fleet: can't reload operator revocation data after an operator CA change: %v", err)
	}
	return nil
}

func (s *Service) audit(ctx context.Context, kind, sha, summary string) {
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       kind,
		Summary:    summary,
		TargetKind: "operator-ca",
		TargetPath: "/operator-cas/" + sha,
	})
}

func acksOf(in []fleetv1.OperatorCAAcknowledgement) []string {
	out := []string{}
	for _, a := range in {
		if a != fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_UNSPECIFIED {
			out = append(out, strings.TrimPrefix(a.String(), "OPERATOR_CA_ACKNOWLEDGEMENT_"))
		}
	}
	return out
}

func ocspModeOf(m fleetv1.OcspMode) string {
	switch m {
	case fleetv1.OcspMode_OCSP_MODE_OFF:
		return store.OCSPModeOff
	case fleetv1.OcspMode_OCSP_MODE_URL:
		return store.OCSPModeURL
	default:
		return store.OCSPModeAIA
	}
}

// uploadUnderHard refuses an upload CRL source with a hard revocation
// policy: an expired CRL would lock out the admins who upload the next one,
// and the manager would refuse to start with it.
func (s *Service) uploadUnderHard(source string) error {
	if source == store.CRLSourceUpload && s.revocations.Policy() == operatorca.PolicyHard {
		return failedPrecondition("operatorRevocationPolicy is hard, so a CRL can't come by upload: an expired CRL would lock out the admins who upload the next one; use a CRL URL")
	}
	return nil
}

// ListOperatorCAs returns every operator CA: active first, then retiring,
// then retired, newest retirement first. A config-file CA is listed
// read-only. Operator-readable.
func (s *Service) ListOperatorCAs(ctx context.Context, _ *connect.Request[fleetv1.ListOperatorCAsRequest]) (*connect.Response[fleetv1.ListOperatorCAsResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}
	if !s.hasOperatorCA() {
		return nil, errOperatorCAUnconfigured("ListOperatorCAs")
	}
	if s.trust.Source().Kind == operatorca.KindFile {
		return connect.NewResponse(&fleetv1.ListOperatorCAsResponse{Items: s.fileCAs()}), nil
	}
	ot, ok := s.store.(store.OperatorTrust)
	if !ok {
		return nil, errOperatorCAUnconfigured("ListOperatorCAs")
	}
	rows, err := ot.OperatorCAs(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	stored := s.storedCRLs(ctx, ot)
	rank := map[string]int{store.OperatorCAActive: 0, store.OperatorCARetiring: 1, store.OperatorCARetired: 2}
	slices.SortStableFunc(rows, func(a, b store.OperatorCA) int {
		if d := rank[a.State] - rank[b.State]; d != 0 {
			return d
		}
		return b.RetiredAt.Compare(a.RetiredAt)
	})
	items := make([]*fleetv1.OperatorCA, 0, len(rows))
	for _, r := range rows {
		oc, err := s.rowToProto(r, stored)
		if err != nil {
			log.Printf("fleet: ListOperatorCAs: %v", err)
			continue
		}
		items = append(items, oc)
	}
	return connect.NewResponse(&fleetv1.ListOperatorCAsResponse{Items: items}), nil
}

func (s *Service) storedCRLs(ctx context.Context, ot store.OperatorTrust) map[string]store.OperatorCRL {
	crls, err := ot.OperatorCRLs(ctx)
	if err != nil {
		log.Printf("fleet: can't read stored operator CRLs: %v", err)
	}
	out := make(map[string]store.OperatorCRL, len(crls))
	for _, c := range crls {
		out[c.IssuerSHA256] = c
	}
	return out
}

func (s *Service) fileCAs() []*fleetv1.OperatorCA {
	var locations []string
	for _, t := range s.trust.Source().CRLTargets {
		locations = append(locations, t.Location)
	}
	anchors := s.trust.Anchors()
	slices.SortFunc(anchors, func(a, b operatorca.Anchor) int { return strings.Compare(a.SHA256, b.SHA256) })
	items := make([]*fleetv1.OperatorCA, 0, len(anchors))
	for _, a := range anchors {
		oc := describeCA(a.Cert, nil, nil, a.CRLSource, strings.Join(locations, ", "), a.OCSPMode, a.OCSPURL)
		oc.State = fleetv1.OperatorCAState_OPERATOR_CA_STATE_ACTIVE
		oc.ManagedByConfig = true
		s.addRuntimeState(oc, a.Cert, nil)
		items = append(items, oc)
	}
	return items
}

func (s *Service) rowToProto(r store.OperatorCA, stored map[string]store.OperatorCRL) (*fleetv1.OperatorCA, error) {
	cert, err := x509.ParseCertificate(r.CertDER)
	if err != nil {
		return nil, fmt.Errorf("the stored operator CA %s doesn't parse: %w", r.SHA256, err)
	}
	oc := describeCA(cert, r.Warnings, r.Acknowledgements, r.CRLSource, r.CRLURL, r.OCSPMode, r.OCSPURL)
	oc.State = stateEnum(r.State)
	oc.RegisteredAt = rfc3339(r.RegisteredAt)
	oc.RetiredAt = rfc3339(r.RetiredAt)
	oc.RetiredReason = r.RetiredReason
	var rec *store.OperatorCRL
	if c, ok := stored[r.SHA256]; ok {
		rec = &c
	}
	s.addRuntimeState(oc, cert, rec)
	return oc, nil
}

// addRuntimeState adds what this replica knows about the CA: its CRL, the
// last CRL and OCSP errors.
func (s *Service) addRuntimeState(oc *fleetv1.OperatorCA, cert *x509.Certificate, rec *store.OperatorCRL) {
	now := time.Now()
	sha := oc.GetSha256()
	v, ok := s.revocations.CRL(sha)
	if !ok && rec != nil && rec.DER != nil {
		if verified, err := operatorca.VerifyCRL(rec.DER, cert, now); err == nil {
			v, ok = verified, true
		}
	}
	lastError := s.revocations.Status(sha).LastError
	var fetched time.Time
	if rec != nil {
		fetched = rec.FetchedAt
		if lastError == "" {
			lastError = rec.LastError
		}
	}
	if ok {
		oc.Crl = crlStatus(v, fetched, now, lastError)
	} else if lastError != "" {
		oc.Crl = &fleetv1.CrlStatus{LastError: lastError}
	}
	if c := s.revocations.OCSP(); c != nil {
		oc.OcspLastError = c.LastError(sha)
	}
}

func describeCA(cert *x509.Certificate, warnings, acks []string, crlSource, crlLocation, ocspMode, ocspURL string) *fleetv1.OperatorCA {
	oc := &fleetv1.OperatorCA{
		Sha256:      operatorca.Fingerprint(cert),
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotAfter:    cert.NotAfter.UTC().Format(time.RFC3339),
		CrlSource:   crlSourceEnum(crlSource),
		CrlLocation: crlLocation,
		OcspMode:    ocspModeEnum(ocspMode),
		OcspUrl:     ocspURL,
		Warnings:    slices.Clone(warnings),
	}
	for _, a := range acks {
		if v, ok := fleetv1.OperatorCAAcknowledgement_value["OPERATOR_CA_ACKNOWLEDGEMENT_"+a]; ok {
			oc.Acknowledgements = append(oc.Acknowledgements, fleetv1.OperatorCAAcknowledgement(v))
		}
	}
	return oc
}

func crlStatus(v *operatorca.VerifiedCRL, fetched, now time.Time, lastError string) *fleetv1.CrlStatus {
	st := &fleetv1.CrlStatus{
		ThisUpdate:   v.List.ThisUpdate.UTC().Format(time.RFC3339),
		NextUpdate:   v.List.NextUpdate.UTC().Format(time.RFC3339),
		RevokedCount: int64(len(v.Revoked)),
		FetchedAt:    rfc3339(fetched),
		LastError:    lastError,
		Stale:        !v.Fresh(now),
	}
	if v.Number != nil {
		st.CrlNumber = v.Number.String()
	}
	return st
}

func probeToProto(anchor *x509.Certificate, r *operatorca.OCSPResult) *fleetv1.OcspProbeResult {
	if r == nil {
		return nil
	}
	out := &fleetv1.OcspProbeResult{CertStatus: r.Status.String(), Signer: fleetv1.OcspSigner_OCSP_SIGNER_ANCHOR}
	signer := r.Signer
	if signer == nil {
		signer = anchor
	}
	if !signer.Equal(anchor) {
		out.Signer = fleetv1.OcspSigner_OCSP_SIGNER_DELEGATED
	}
	out.SignerSubject = signer.Subject.String()
	out.SignerNotAfter = signer.NotAfter.UTC().Format(time.RFC3339)
	return out
}

func stateEnum(s string) fleetv1.OperatorCAState {
	switch s {
	case store.OperatorCAActive:
		return fleetv1.OperatorCAState_OPERATOR_CA_STATE_ACTIVE
	case store.OperatorCARetiring:
		return fleetv1.OperatorCAState_OPERATOR_CA_STATE_RETIRING
	case store.OperatorCARetired:
		return fleetv1.OperatorCAState_OPERATOR_CA_STATE_RETIRED
	}
	return fleetv1.OperatorCAState_OPERATOR_CA_STATE_UNSPECIFIED
}

func crlSourceEnum(s string) fleetv1.CrlSource {
	switch s {
	case store.CRLSourceNone, "":
		return fleetv1.CrlSource_CRL_SOURCE_NONE
	case store.CRLSourceURL:
		return fleetv1.CrlSource_CRL_SOURCE_URL
	case store.CRLSourceUpload:
		return fleetv1.CrlSource_CRL_SOURCE_UPLOAD
	case store.CRLSourcePath:
		return fleetv1.CrlSource_CRL_SOURCE_PATH
	}
	return fleetv1.CrlSource_CRL_SOURCE_UNSPECIFIED
}

func ocspModeEnum(s string) fleetv1.OcspMode {
	switch s {
	case store.OCSPModeOff:
		return fleetv1.OcspMode_OCSP_MODE_OFF
	case store.OCSPModeURL:
		return fleetv1.OcspMode_OCSP_MODE_URL
	case store.OCSPModeAIA, "":
		return fleetv1.OcspMode_OCSP_MODE_AIA
	}
	return fleetv1.OcspMode_OCSP_MODE_UNSPECIFIED
}

// RegisterOperatorCA previews, then with confirm_sha256 registers, a new
// operator CA after first run, with the first-run checks. The new CA becomes
// active and the previous active CA retiring: still trusted and still
// revocation-checked until it is retired. Refused with 1605
// ROTATION_IN_PROGRESS while a CA is retiring. Admin-gated and audited.
func (s *Service) RegisterOperatorCA(ctx context.Context, req *connect.Request[fleetv1.RegisterOperatorCARequest]) (*connect.Response[fleetv1.RegisterOperatorCAResponse], error) {
	id, ot, err := s.operatorCAWrite(ctx, "RegisterOperatorCA")
	if err != nil {
		return nil, err
	}
	m := req.Msg
	cert, err := operatorca.ParseAnchorUpload(m.GetCaCertDer())
	if err != nil {
		return nil, caErr(err)
	}
	rows, err := ot.OperatorCAs(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	for _, r := range rows {
		if r.State == store.OperatorCARetiring {
			return nil, caReject(connect.CodeFailedPrecondition, fleetv1.ErrorReason_ERROR_REASON_ROTATION_IN_PROGRESS,
				"operator CA %s is still retiring; retire it before registering another CA", r.SHA256)
		}
	}

	choice := operatorca.CRLChoice{Source: store.CRLSourceNone, Acknowledgements: acksOf(m.GetAcknowledgements())}
	switch src := m.GetCrlSource().(type) {
	case *fleetv1.RegisterOperatorCARequest_Url:
		choice.Source, choice.URL = store.CRLSourceURL, src.Url
	case *fleetv1.RegisterOperatorCARequest_CrlDer:
		choice.Source, choice.DER = store.CRLSourceUpload, src.CrlDer
	}
	if err := s.uploadUnderHard(choice.Source); err != nil {
		return nil, err
	}
	now := time.Now()
	warnings, err := operatorca.ValidateAnchor(cert, operatorca.AnchorOptions{
		Now: now, NodeCAs: s.nodeCAs(), CRLSource: choice.Source != store.CRLSourceNone,
	})
	if err != nil {
		return nil, caErr(err)
	}
	crl, err := operatorca.CheckCRLChoice(ctx, cert, choice, now, s.caAdmin.FetchCRL)
	if err != nil {
		return nil, caErr(err)
	}
	mode := ocspModeOf(m.GetOcspMode())
	probe, err := operatorca.CheckOCSPChoice(ctx, cert, mode, m.GetOcspUrl(), s.probe())
	if err != nil {
		if errors.Is(err, operatorca.ErrOCSPURL) {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return nil, caErr(err)
	}
	extfile, err := operatorca.ExtfileSection("admin")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	oc := describeCA(cert, warnings, choice.Acknowledgements, choice.Source, choice.URL, mode, m.GetOcspUrl())
	if crl != nil {
		oc.Crl = crlStatus(crl, time.Time{}, now, "")
	}
	resp := &fleetv1.RegisterOperatorCAResponse{OperatorCa: oc, AdminExtfile: extfile, OcspProbe: probeToProto(cert, probe)}
	if m.GetConfirmSha256() == "" {
		return connect.NewResponse(resp), nil
	}
	fp := oc.GetSha256()
	if normalizeFingerprint(m.GetConfirmSha256()) != fp {
		return nil, caReject(connect.CodeInvalidArgument, fleetv1.ErrorReason_ERROR_REASON_NOT_CONFIRMED,
			"confirm_sha256 doesn't match the uploaded operator CA")
	}

	at := now.UTC()
	row := store.OperatorCA{
		SHA256: fp, CertDER: cert.Raw, State: store.OperatorCAActive,
		CRLSource: choice.Source, CRLURL: choice.URL, OCSPMode: mode, OCSPURL: m.GetOcspUrl(),
		Acknowledgements: choice.Acknowledgements, Warnings: warnings, RegisteredAt: at, RegisteredBy: id.CN,
	}
	crlRow, decide := crlWrite(fp, choice.Source, crl, at)
	if err := ot.RotateOperatorCA(ctx, row, crlRow, decide); err != nil {
		switch {
		case errors.Is(err, store.ErrRotationInProgress):
			return nil, caReject(connect.CodeFailedPrecondition, fleetv1.ErrorReason_ERROR_REASON_ROTATION_IN_PROGRESS,
				"an operator CA is still retiring; retire it before registering another CA")
		case errors.Is(err, store.ErrOperatorCATrusted):
			return nil, failedPrecondition("operator CA %s is already trusted", fp)
		default:
			return nil, caErr(err)
		}
	}
	if err := s.applyTrustChange(ctx); err != nil {
		return nil, err
	}

	previous := "none"
	for _, r := range rows {
		if r.State == store.OperatorCAActive {
			previous = r.SHA256
		}
	}
	log.Printf("fleet: operator CA registered %s, SHA-256 %s, by %s; the previous active CA %s is now retiring",
		cert.Subject, operatorca.ColonFingerprint(cert.Raw), id.CN, previous)
	for _, w := range warnings {
		log.Printf("fleet: WARNING operator CA %s: %s", fp, w)
	}
	s.audit(ctx, "operator-ca-registered", fp, fmt.Sprintf(
		"Registered operator CA %s (SHA-256 %s) as active; previous active CA %s is now retiring. CRL source %s%s, OCSP mode %s%s, acknowledgements [%s], warnings [%s]",
		cert.Subject, fp, previous, choice.Source, prefixed(choice.URL), mode, prefixed(m.GetOcspUrl()),
		strings.Join(choice.Acknowledgements, ", "), strings.Join(warnings, "; ")))

	resp.Confirmed = true
	oc.State = fleetv1.OperatorCAState_OPERATOR_CA_STATE_ACTIVE
	oc.RegisteredAt = at.Format(time.RFC3339)
	if crl != nil {
		oc.Crl = crlStatus(crl, at, now, "")
	}
	return connect.NewResponse(resp), nil
}

// crlWrite is the CRL row to store with a change, and the anti-rollback
// decision for it; both nil when there is no CRL.
func crlWrite(sha, source string, v *operatorca.VerifiedCRL, at time.Time) (*store.OperatorCRL, store.DecideCRL) {
	if v == nil {
		return nil, nil
	}
	row := &store.OperatorCRL{
		IssuerSHA256: sha, DER: v.DER, Number: v.Number, ThisUpdate: v.List.ThisUpdate, NextUpdate: v.List.NextUpdate,
		FetchedAt: at, Source: source,
	}
	return row, func(cur store.OperatorCRL, has bool) (bool, error) { return operatorca.AcceptNewer(cur, has, v) }
}

func prefixed(s string) string {
	if s == "" {
		return ""
	}
	return " " + s
}

// RetireOperatorCA stops trusting a retiring operator CA; its certificates
// are refused from their next request. The active CA can't be retired (1609:
// register its replacement first), and neither can the caller's own CA
// unless i_understand_self_lockout is set. Admin-gated and audited.
func (s *Service) RetireOperatorCA(ctx context.Context, req *connect.Request[fleetv1.RetireOperatorCARequest]) (*connect.Response[fleetv1.RetireOperatorCAResponse], error) {
	id, ot, err := s.operatorCAWrite(ctx, "RetireOperatorCA")
	if err != nil {
		return nil, err
	}
	row, err := findRow(ctx, ot, req.Msg.GetSha256())
	if err != nil {
		return nil, err
	}
	switch row.State {
	case store.OperatorCARetired:
		return nil, failedPrecondition("operator CA %s is already retired", row.SHA256)
	case store.OperatorCAActive:
		return nil, connect.NewError(connect.CodeFailedPrecondition, apperr.Coded(apperr.CodeOperatorCAInUse,
			fmt.Errorf("fleet: operator CA %s is the active CA; retiring it would leave no active operator CA, so register its replacement first", row.SHA256)))
	}
	selfLockout := id.IssuerSHA256 != "" && id.IssuerSHA256 == row.SHA256
	if selfLockout && !req.Msg.GetIUnderstandSelfLockout() {
		return nil, failedPrecondition("your own certificate chains to operator CA %s, so retiring it signs you out; "+
			"sign in with a certificate from the active CA, or set i_understand_self_lockout to retire it anyway", row.SHA256)
	}

	if err := ot.SetOperatorCAState(ctx, row.SHA256, store.OperatorCARetired, retiredByAdmin, time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrOperatorCANotFound) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if c := s.revocations.OCSP(); c != nil {
		c.ClearAnchor(row.SHA256)
	}
	if err := s.applyTrustChange(ctx); err != nil {
		return nil, err
	}
	log.Printf("fleet: operator CA %s retired by %s; its certificates are refused from their next request", row.SHA256, id.CN)
	summary := fmt.Sprintf("Retired operator CA %s; certificates under it are no longer trusted", row.SHA256)
	if selfLockout {
		summary += " (the caller's own CA, retired with i_understand_self_lockout)"
	}
	s.audit(ctx, "operator-ca-retired", row.SHA256, summary)

	oc, err := s.rowProto(ctx, ot, row.SHA256)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&fleetv1.RetireOperatorCAResponse{OperatorCa: oc}), nil
}

// rowProto renders the stored row with the fingerprint, as it is now.
func (s *Service) rowProto(ctx context.Context, ot store.OperatorTrust, sha string) (*fleetv1.OperatorCA, error) {
	row, err := findRow(ctx, ot, sha)
	if err != nil {
		return nil, err
	}
	oc, err := s.rowToProto(row, s.storedCRLs(ctx, ot))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return oc, nil
}

// SetOperatorCACRLSource changes a trusted operator CA's CRL source to a
// URL, an uploaded CRL or none. A new URL or CRL must verify against the CA
// first, and none needs the NO_CRL acknowledgement (it also cuts off MCP
// under the CA). Admin-gated and audited.
func (s *Service) SetOperatorCACRLSource(ctx context.Context, req *connect.Request[fleetv1.SetOperatorCACRLSourceRequest]) (*connect.Response[fleetv1.SetOperatorCACRLSourceResponse], error) {
	id, ot, err := s.operatorCAWrite(ctx, "SetOperatorCACRLSource")
	if err != nil {
		return nil, err
	}
	m := req.Msg
	choice := operatorca.CRLChoice{Acknowledgements: acksOf(m.GetAcknowledgements())}
	switch src := m.GetCrlSource().(type) {
	case *fleetv1.SetOperatorCACRLSourceRequest_Url:
		choice.Source, choice.URL = store.CRLSourceURL, src.Url
	case *fleetv1.SetOperatorCACRLSourceRequest_CrlDer:
		choice.Source, choice.DER = store.CRLSourceUpload, src.CrlDer
	case *fleetv1.SetOperatorCACRLSourceRequest_None:
		choice.Source = store.CRLSourceNone
	default:
		return nil, invalidArg("crl_source is required: url, crl_der or none")
	}
	row, cert, err := trustedRow(ctx, ot, m.GetSha256())
	if err != nil {
		return nil, err
	}
	if err := s.uploadUnderHard(choice.Source); err != nil {
		return nil, err
	}
	now := time.Now()
	crl, err := operatorca.CheckCRLChoice(ctx, cert, choice, now, s.caAdmin.FetchCRL)
	if err != nil {
		return nil, caErr(err)
	}
	crlRow, decide := crlWrite(row.SHA256, choice.Source, crl, now.UTC())
	if err := ot.SetOperatorCACRLSource(ctx, row.SHA256, choice.Source, choice.URL, choice.Acknowledgements, crlRow, decide); err != nil {
		if errors.Is(err, store.ErrOperatorCANotFound) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, caErr(err)
	}
	if err := s.applyTrustChange(ctx); err != nil {
		return nil, err
	}
	log.Printf("fleet: operator CA %s CRL source changed from %s to %s by %s", row.SHA256, row.CRLSource, choice.Source, id.CN)
	s.audit(ctx, "operator-ca-crl-source-changed", row.SHA256, fmt.Sprintf(
		"Changed the CRL source of operator CA %s from %s%s to %s%s, acknowledgements [%s]",
		row.SHA256, row.CRLSource, prefixed(row.CRLURL), choice.Source, prefixed(choice.URL), strings.Join(choice.Acknowledgements, ", ")))

	oc, err := s.rowProto(ctx, ot, row.SHA256)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&fleetv1.SetOperatorCACRLSourceResponse{OperatorCa: oc}), nil
}

// UploadOperatorCRL stores a new CRL for an operator CA whose CRL source is
// upload. It must verify against the CA and be newer than the stored CRL;
// storing it moves the revocation epoch so every replica enforces it.
// Admin-gated and audited.
func (s *Service) UploadOperatorCRL(ctx context.Context, req *connect.Request[fleetv1.UploadOperatorCRLRequest]) (*connect.Response[fleetv1.UploadOperatorCRLResponse], error) {
	id, ot, err := s.operatorCAWrite(ctx, "UploadOperatorCRL")
	if err != nil {
		return nil, err
	}
	row, _, err := trustedRow(ctx, ot, req.Msg.GetSha256())
	if err != nil {
		return nil, err
	}
	if row.CRLSource != store.CRLSourceUpload {
		return nil, failedPrecondition("operator CA %s takes its CRL from %s, not by upload; switch its CRL source to upload first", row.SHA256, row.CRLSource)
	}
	stored, err := s.revocations.StoreCRL(ctx, row.SHA256, req.Msg.GetCrlDer(), store.CRLSourceUpload)
	if err != nil {
		if errors.Is(err, operatorca.ErrUnknownAnchor) {
			return nil, failedPrecondition("operator CA %s isn't trusted on this replica yet; try again", row.SHA256)
		}
		return nil, caErr(err)
	}
	if stored {
		v, _ := s.revocations.CRL(row.SHA256)
		log.Printf("fleet: CRL uploaded for operator CA %s by %s", row.SHA256, id.CN)
		s.audit(ctx, "operator-crl-uploaded", row.SHA256, fmt.Sprintf(
			"Uploaded a CRL for operator CA %s: number %v, %d revoked, next update %s",
			row.SHA256, v.Number, len(v.Revoked), v.List.NextUpdate.UTC().Format(time.RFC3339)))
	} else {
		log.Printf("fleet: CRL upload for operator CA %s by %s is the CRL already stored; nothing changed", row.SHA256, id.CN)
	}

	oc, err := s.rowProto(ctx, ot, row.SHA256)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&fleetv1.UploadOperatorCRLResponse{OperatorCa: oc}), nil
}

// SetOperatorCAOCSP changes a trusted operator CA's OCSP mode. Mode url
// must pass a probe of the responder first. The CA's cached OCSP answers are
// dropped here and on each replica as it takes the change. Admin-gated and
// audited.
func (s *Service) SetOperatorCAOCSP(ctx context.Context, req *connect.Request[fleetv1.SetOperatorCAOCSPRequest]) (*connect.Response[fleetv1.SetOperatorCAOCSPResponse], error) {
	id, ot, err := s.operatorCAWrite(ctx, "SetOperatorCAOCSP")
	if err != nil {
		return nil, err
	}
	m := req.Msg
	mode := ocspModeOf(m.GetOcspMode())
	if mode == store.OCSPModeURL && m.GetOcspUrl() == "" {
		return nil, invalidArg("ocsp_url is required for OCSP mode url")
	}
	row, cert, err := trustedRow(ctx, ot, m.GetSha256())
	if err != nil {
		return nil, err
	}
	probe, err := operatorca.CheckOCSPChoice(ctx, cert, mode, m.GetOcspUrl(), s.probe())
	if err != nil {
		if errors.Is(err, operatorca.ErrOCSPURL) {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return nil, caErr(err)
	}
	if err := ot.SetOperatorCAOCSP(ctx, row.SHA256, mode, m.GetOcspUrl()); err != nil {
		if errors.Is(err, store.ErrOperatorCANotFound) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if c := s.revocations.OCSP(); c != nil {
		c.ClearAnchor(row.SHA256)
	}
	if err := s.applyTrustChange(ctx); err != nil {
		return nil, err
	}
	log.Printf("fleet: operator CA %s OCSP mode changed from %s to %s by %s", row.SHA256, row.OCSPMode, mode, id.CN)
	s.audit(ctx, "operator-ca-ocsp-changed", row.SHA256, fmt.Sprintf(
		"Changed the OCSP mode of operator CA %s from %s%s to %s%s", row.SHA256, row.OCSPMode, prefixed(row.OCSPURL), mode, prefixed(m.GetOcspUrl())))

	oc, err := s.rowProto(ctx, ot, row.SHA256)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&fleetv1.SetOperatorCAOCSPResponse{OperatorCa: oc, OcspProbe: probeToProto(cert, probe)}), nil
}
