package bootstrap

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
	"strings"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// registeredBy is what a first-run registration records as its registrar.
const registeredBy = "first-run session"

const ackNoCRL = "NO_CRL"

// rejected gives a refusal the InvalidArgument transport code unless it
// already carries one.
func rejected(err error) error {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return err
	}
	return connect.NewError(connect.CodeInvalidArgument, err)
}

func caRejected(code connect.Code, reason fleetv1.ErrorReason, format string, args ...any) error {
	return connect.NewError(code, apperr.Reasoned(apperr.CodeOperatorCARejected, reason, fmt.Errorf("bootstrap: "+format, args...)))
}

// normalizeFingerprint accepts a SHA-256 in any case, with or without the
// colons openssl prints.
func normalizeFingerprint(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
}

// registration is an operator CA upload that passed every check.
type registration struct {
	cert      *x509.Certificate
	warnings  []string
	acks      []string
	crlSource string
	crlURL    string
	crl       *operatorca.VerifiedCRL
	ocspMode  string
	ocspURL   string
	probe     *fleetv1.OcspProbeResult
}

// RegisterOperatorCA previews, confirms or re-confirms the external operator
// CA. Session-gated and audited.
func (s *Service) RegisterOperatorCA(ctx context.Context, req *connect.Request[fleetv1.BootstrapServiceRegisterOperatorCARequest]) (*connect.Response[fleetv1.BootstrapServiceRegisterOperatorCAResponse], error) {
	if err := s.admit(ctx); err != nil {
		return nil, err
	}
	sessionHash, err := s.session(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	m := req.Msg
	if len(m.GetCaCertDer()) == 0 {
		return s.reconfirm(ctx, sessionHash, m.GetConfirmSha256())
	}

	reg, err := s.check(ctx, m)
	if err != nil {
		return nil, s.fail(ctx, rejected(err))
	}
	extfile, err := operatorca.ExtfileSection("admin")
	if err != nil {
		return nil, err
	}
	fp := operatorca.Fingerprint(reg.cert)
	resp := &fleetv1.BootstrapServiceRegisterOperatorCAResponse{
		OperatorCa:   s.previewOf(reg),
		AdminExtfile: extfile,
		OcspProbe:    reg.probe,
	}
	if m.GetConfirmSha256() == "" {
		return connect.NewResponse(resp), nil
	}
	if normalizeFingerprint(m.GetConfirmSha256()) != fp {
		return nil, s.fail(ctx, caRejected(connect.CodeInvalidArgument, fleetv1.ErrorReason_ERROR_REASON_NOT_CONFIRMED,
			"confirm_sha256 doesn't match the uploaded operator CA"))
	}

	now := s.now().UTC()
	row := store.OperatorCA{
		SHA256: fp, CertDER: reg.cert.Raw, State: store.OperatorCAActive,
		CRLSource: reg.crlSource, CRLURL: reg.crlURL, OCSPMode: reg.ocspMode, OCSPURL: reg.ocspURL,
		Acknowledgements: reg.acks, Warnings: reg.warnings, RegisteredAt: now, RegisteredBy: registeredBy,
	}
	var (
		crlRow *store.OperatorCRL
		decide store.DecideCRL
	)
	if v := reg.crl; v != nil {
		crlRow = &store.OperatorCRL{
			IssuerSHA256: fp, DER: v.DER, Number: v.Number, ThisUpdate: v.List.ThisUpdate, NextUpdate: v.List.NextUpdate,
			FetchedAt: now, Source: reg.crlSource,
		}
		decide = func(cur store.OperatorCRL, has bool) (bool, error) { return operatorca.AcceptNewer(cur, has, v) }
	}
	if err := s.st.RegisterFirstRunOperatorCA(ctx, row, sessionHash, crlRow, decide); err != nil {
		switch {
		case errors.Is(err, store.ErrBootstrapClosed):
			return nil, connect.NewError(connect.CodeFailedPrecondition, apperr.Coded(apperr.CodeFirstRunClosed, err))
		case isReasoned(err):
			return nil, s.fail(ctx, rejected(err))
		default:
			return nil, fmt.Errorf("bootstrap: store the operator CA: %w", err)
		}
	}
	if err := s.trust.Rebuild(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap: trust the new operator CA: %w", err)
	}
	if err := s.rev.Reload(ctx); err != nil {
		s.logf("bootstrap: can't reload revocation data after registering %s: %v", fp, err)
	}

	ip := clientIP(ctx)
	s.logf("manager: operator CA registered %s, SHA-256 %s, from %s", reg.cert.Subject, operatorca.ColonFingerprint(reg.cert.Raw), ip)
	for _, w := range reg.warnings {
		s.logf("manager: WARNING operator CA %s: %s", fp, w)
	}
	s.record(ctx, store.AuditEvent{
		Kind: KindOperatorCARegistered,
		Summary: fmt.Sprintf("Registered operator CA %s (SHA-256 %s) from %s: CRL source %s%s, OCSP mode %s%s, acknowledgements [%s], warnings [%s]",
			reg.cert.Subject, fp, ip, reg.crlSource, suffix(reg.crlURL), reg.ocspMode, suffix(reg.ocspURL),
			strings.Join(reg.acks, ", "), strings.Join(reg.warnings, "; ")),
		TargetKind: "operator-ca",
		TargetPath: "/operator-cas/" + fp,
	})

	resp.Confirmed = true
	resp.OperatorCa.State = fleetv1.OperatorCAState_OPERATOR_CA_STATE_ACTIVE
	resp.OperatorCa.RegisteredAt = now.Format(time.RFC3339)
	return connect.NewResponse(resp), nil
}

func suffix(s string) string {
	if s == "" {
		return ""
	}
	return " " + s
}

func isReasoned(err error) bool {
	_, ok := apperr.ReasonOf(err)
	return ok
}

// check runs every registration check, in order, fail-closed: the upload,
// the CRL source choice, the anchor rules, the CRL itself, and the OCSP
// settings.
func (s *Service) check(ctx context.Context, m *fleetv1.BootstrapServiceRegisterOperatorCARequest) (*registration, error) {
	cert, err := operatorca.ParseAnchorUpload(m.GetCaCertDer())
	if err != nil {
		return nil, err
	}
	reg := &registration{cert: cert, crlSource: store.CRLSourceNone}
	for _, a := range m.GetAcknowledgements() {
		if a != fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_UNSPECIFIED {
			reg.acks = append(reg.acks, strings.TrimPrefix(a.String(), "OPERATOR_CA_ACKNOWLEDGEMENT_"))
		}
	}
	var crlDER []byte
	switch src := m.GetCrlSource().(type) {
	case *fleetv1.BootstrapServiceRegisterOperatorCARequest_Url:
		reg.crlSource, reg.crlURL = store.CRLSourceURL, src.Url
	case *fleetv1.BootstrapServiceRegisterOperatorCARequest_CrlDer:
		reg.crlSource, crlDER = store.CRLSourceUpload, src.CrlDer
	}

	now := s.now()
	reg.warnings, err = operatorca.ValidateAnchor(cert, operatorca.AnchorOptions{
		Now: now, NodeCAs: s.nodeCAs(), CRLSource: reg.crlSource != store.CRLSourceNone,
	})
	if err != nil {
		return nil, err
	}
	if reg.crlSource == store.CRLSourceNone {
		acknowledged := false
		for _, a := range reg.acks {
			acknowledged = acknowledged || a == ackNoCRL
		}
		if !acknowledged {
			return nil, caRejected(connect.CodeInvalidArgument, fleetv1.ErrorReason_ERROR_REASON_NO_CRL_NOT_ACKNOWLEDGED,
				"no CRL source was chosen and NO_CRL wasn't acknowledged")
		}
	}

	if reg.crlSource == store.CRLSourceURL {
		if err := operatorca.ValidateFetchURL(reg.crlURL); err != nil {
			return nil, caRejected(connect.CodeInvalidArgument, fleetv1.ErrorReason_ERROR_REASON_CRL_UNREACHABLE, "CRL URL refused: %v", err)
		}
		crlDER, err = s.fetchCRL(ctx, reg.crlURL)
		if err != nil {
			if !isReasoned(err) {
				err = apperr.Reasoned(apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_UNREACHABLE, err)
			}
			return nil, err
		}
	}
	if crlDER != nil {
		reg.crl, err = operatorca.VerifyCRL(crlDER, cert, now)
		if err != nil {
			return nil, err
		}
	}

	switch m.GetOcspMode() {
	case fleetv1.OcspMode_OCSP_MODE_OFF:
		reg.ocspMode = store.OCSPModeOff
	case fleetv1.OcspMode_OCSP_MODE_URL:
		reg.ocspMode, reg.ocspURL = store.OCSPModeURL, m.GetOcspUrl()
		if err := operatorca.ValidateFetchURL(reg.ocspURL); err != nil {
			return nil, caRejected(connect.CodeInvalidArgument, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE, "OCSP URL refused: %v", err)
		}
		// The probe is nil only when the manager runs without an OCSP
		// client.
		if s.probe != nil {
			reg.probe, err = s.probe(ctx, cert, reg.ocspURL)
			if err != nil {
				return nil, err
			}
		}
	default:
		reg.ocspMode = store.OCSPModeAIA
	}
	return reg, nil
}

// previewOf is the operator CA a registration would store.
func (s *Service) previewOf(reg *registration) *fleetv1.OperatorCA {
	oc := describeCA(reg.cert, reg.warnings, reg.acks, reg.crlSource, reg.crlURL, reg.ocspMode, reg.ocspURL)
	if v := reg.crl; v != nil {
		oc.Crl = crlStatus(v, s.now(), s.now(), "")
	}
	return oc
}

// reconfirm previews the current registration for a new session, or records
// the new session's confirmation of it without changing anything. With
// nothing registered the preview is empty.
func (s *Service) reconfirm(ctx context.Context, sessionHash, confirm string) (*connect.Response[fleetv1.BootstrapServiceRegisterOperatorCAResponse], error) {
	row := s.activeCA(ctx)
	if row == nil {
		// A new session asks for the current registration first. Nothing
		// registered is an empty answer, not the caller's mistake.
		if confirm == "" {
			return connect.NewResponse(&fleetv1.BootstrapServiceRegisterOperatorCAResponse{}), nil
		}
		return nil, s.fail(ctx, caRejected(connect.CodeFailedPrecondition, fleetv1.ErrorReason_ERROR_REASON_NOT_CONFIRMED,
			"no operator CA is registered yet; upload one"))
	}
	cert, err := x509.ParseCertificate(row.CertDER)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: the registered operator CA %s doesn't parse: %w", row.SHA256, err)
	}
	extfile, err := operatorca.ExtfileSection("admin")
	if err != nil {
		return nil, err
	}
	oc := describeCA(cert, row.Warnings, row.Acknowledgements, row.CRLSource, row.CRLURL, row.OCSPMode, row.OCSPURL)
	oc.State = fleetv1.OperatorCAState_OPERATOR_CA_STATE_ACTIVE
	oc.RegisteredAt = row.RegisteredAt.UTC().Format(time.RFC3339)
	if v, ok := s.rev.CRL(row.SHA256); ok {
		oc.Crl = crlStatus(v, time.Time{}, s.now(), s.rev.Status(row.SHA256).LastError)
	}
	resp := &fleetv1.BootstrapServiceRegisterOperatorCAResponse{OperatorCa: oc, AdminExtfile: extfile}
	if confirm == "" {
		return connect.NewResponse(resp), nil
	}
	if normalizeFingerprint(confirm) != row.SHA256 {
		return nil, s.fail(ctx, caRejected(connect.CodeInvalidArgument, fleetv1.ErrorReason_ERROR_REASON_NOT_CONFIRMED,
			"confirm_sha256 doesn't match the registered operator CA"))
	}
	if err := s.st.ConfirmOperatorCA(ctx, row.SHA256, sessionHash); err != nil {
		return nil, fmt.Errorf("bootstrap: record the confirmation: %w", err)
	}
	s.logf("manager: operator CA %s confirmed again by a new first-run session from %s", row.SHA256, clientIP(ctx))
	resp.Confirmed = true
	return connect.NewResponse(resp), nil
}

func describeCA(cert *x509.Certificate, warnings, acks []string, crlSource, crlURL, ocspMode, ocspURL string) *fleetv1.OperatorCA {
	oc := &fleetv1.OperatorCA{
		Sha256:      operatorca.Fingerprint(cert),
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotAfter:    cert.NotAfter.UTC().Format(time.RFC3339),
		CrlSource:   crlSourceEnum(crlSource),
		CrlLocation: crlURL,
		OcspMode:    ocspModeEnum(ocspMode),
		OcspUrl:     ocspURL,
		Warnings:    warnings,
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
		LastError:    lastError,
		Stale:        !v.Fresh(now),
	}
	if v.Number != nil {
		st.CrlNumber = v.Number.String()
	}
	if !fetched.IsZero() {
		st.FetchedAt = fetched.UTC().Format(time.RFC3339)
	}
	return st
}

func crlSourceEnum(s string) fleetv1.CrlSource {
	switch s {
	case store.CRLSourceNone:
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
