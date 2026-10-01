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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/google/uuid"
)

// Credential requests replace issuing: the manager never signs an operator
// credential. An admin files a request from a CSR, the external operator CA
// signs it out of band, and an admin records the signed certificate.
const (
	requestLifetime = 30 * 24 * time.Hour
	maxCertSize     = 8 << 10
)

// credentialStore returns the store's credential request support. Both
// stores implement it; the in-memory one refuses with ErrDatabaseRequired.
func (s *Service) credentialStore() (store.OperatorCredentialStore, error) {
	cs, ok := s.store.(store.OperatorCredentialStore)
	if !ok {
		return nil, credStoreErr(store.ErrDatabaseRequired)
	}
	return cs, nil
}

// credStoreErr maps a credential store error to the code the UI branches on.
func credStoreErr(err error) error {
	switch {
	case errors.Is(err, store.ErrDatabaseRequired):
		return connect.NewError(connect.CodeFailedPrecondition, apperr.Reasoned(apperr.CodeUnavailable,
			fleetv1.ErrorReason_ERROR_REASON_DATABASE_REQUIRED, fmt.Errorf("fleet: credential requests and recording need Postgres: %w", err)))
	case errors.Is(err, store.ErrRequestNotFound):
		return connect.NewError(connect.CodeNotFound, apperr.Reasoned(apperr.CodeRequestInvalid,
			fleetv1.ErrorReason_ERROR_REASON_NOT_FOUND, errors.New("fleet: no such credential request")))
	case errors.Is(err, store.ErrCredentialRecorded):
		return connect.NewError(connect.CodeAlreadyExists, apperr.Reasoned(apperr.CodeCertRejected,
			fleetv1.ErrorReason_ERROR_REASON_DUPLICATE, errors.New("fleet: this operator certificate is already recorded")))
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// requestStateErr is the 1611 refusal for a request that can't be used.
func requestStateErr(r store.OperatorCredentialRequest) error {
	reason := fleetv1.ErrorReason_ERROR_REASON_NOT_PENDING
	if r.State == store.RequestExpired {
		reason = fleetv1.ErrorReason_ERROR_REASON_EXPIRED
	}
	return connect.NewError(connect.CodeFailedPrecondition, apperr.Reasoned(apperr.CodeRequestInvalid, reason,
		fmt.Errorf("fleet: credential request %s is %s, not pending", r.ID, r.State)))
}

func invalidArg(format string, args ...any) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("fleet: "+format, args...))
}

// CreateOperatorCredentialRequest stores a pending request for an operator
// credential from a CSR with subject CN=<email>, and returns what the CA
// operator needs to sign it: the CSR, the op_<level> extension section and
// the openssl ca command. Admin-gated and audited.
func (s *Service) CreateOperatorCredentialRequest(ctx context.Context, req *connect.Request[fleetv1.CreateOperatorCredentialRequestRequest]) (*connect.Response[fleetv1.CreateOperatorCredentialRequestResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	level := req.Msg.GetLevel()
	if _, err := authz.LevelFromToken(level); err != nil {
		return nil, invalidArg("level must be viewer, operator or admin")
	}
	if err := operatorca.ValidateFullName(req.Msg.GetFullName()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if !s.hasOperatorCA() {
		return nil, errOperatorCAUnconfigured("CreateOperatorCredentialRequest")
	}
	csr, err := operatorca.CheckCSR(req.Msg.GetCsrDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	email := strings.ToLower(req.Msg.GetEmail())
	if csr.Email != email {
		return nil, connect.NewError(connect.CodeInvalidArgument, apperr.Reasoned(apperr.CodeCSRRejected,
			fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH,
			fmt.Errorf("fleet: the CSR is for %s, not %s", csr.Email, email)))
	}
	section, err := operatorca.ExtfileSection(level)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	cs, err := s.credentialStore()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	r := store.OperatorCredentialRequest{
		ID: uuid.NewString(), Level: level, Email: email, FullName: req.Msg.GetFullName(),
		CSRDER: req.Msg.GetCsrDer(), State: store.RequestPending, CreatedByCN: id.CN,
		CreatedAt: now, ExpiresAt: now.Add(requestLifetime),
	}
	if err := cs.AddOperatorCredentialRequest(ctx, r); err != nil {
		return nil, credStoreErr(err)
	}
	log.Printf("fleet: %s requested a %s operator credential for %s (request %s)", id.CN, level, email, r.ID)
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         now.Format(time.RFC3339),
		Kind:       "operator-credential-requested",
		Summary:    fmt.Sprintf("Requested a %s operator credential for %s (request %s), to be signed by the operator CA", level, email, r.ID),
		TargetKind: "operator-credential-request",
		TargetPath: "/operators/requests/" + r.ID,
	})

	return connect.NewResponse(&fleetv1.CreateOperatorCredentialRequestResponse{
		RequestId:      r.ID,
		CsrPem:         csrPEM(r.CSRDER),
		ExtfileSection: section,
		OpensslCommand: operatorca.SignCommand(level, email),
		ExpiresAt:      r.ExpiresAt.Format(time.RFC3339),
	}), nil
}

// ListOperatorCredentialRequests returns credential requests, newest first,
// optionally filtered by state. Operator-readable.
func (s *Service) ListOperatorCredentialRequests(ctx context.Context, req *connect.Request[fleetv1.ListOperatorCredentialRequestsRequest]) (*connect.Response[fleetv1.ListOperatorCredentialRequestsResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}
	state := req.Msg.GetState()
	switch state {
	case "", store.RequestPending, store.RequestCompleted, store.RequestCancelled, store.RequestExpired:
	default:
		return nil, invalidArg("state must be pending, completed, cancelled or expired")
	}
	if !s.hasOperatorCA() {
		return nil, errOperatorCAUnconfigured("ListOperatorCredentialRequests")
	}
	cs, err := s.credentialStore()
	if err != nil {
		return nil, err
	}
	reqs, err := cs.OperatorCredentialRequests(ctx, state, time.Now().UTC())
	if err != nil {
		return nil, credStoreErr(err)
	}
	items := make([]*fleetv1.OperatorCredentialRequest, len(reqs))
	for i, r := range reqs {
		items[i] = requestToProto(r)
	}
	return connect.NewResponse(&fleetv1.ListOperatorCredentialRequestsResponse{Items: items}), nil
}

// CancelOperatorCredentialRequest cancels a pending request and drops its
// CSR. Admin-gated and audited.
func (s *Service) CancelOperatorCredentialRequest(ctx context.Context, req *connect.Request[fleetv1.CancelOperatorCredentialRequestRequest]) (*connect.Response[fleetv1.CancelOperatorCredentialRequestResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	cs, err := s.credentialStore()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	r, err := cs.CancelOperatorCredentialRequest(ctx, req.Msg.GetRequestId(), now)
	if errors.Is(err, store.ErrRequestNotPending) {
		return nil, requestStateErr(r)
	}
	if err != nil {
		return nil, credStoreErr(err)
	}
	log.Printf("fleet: %s cancelled operator credential request %s for %s", id.CN, r.ID, r.Email)
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         now.Format(time.RFC3339),
		Kind:       "operator-credential-request-cancelled",
		Summary:    fmt.Sprintf("Cancelled the %s operator credential request for %s (request %s)", r.Level, r.Email, r.ID),
		TargetKind: "operator-credential-request",
		TargetPath: "/operators/requests/" + r.ID,
	})
	return connect.NewResponse(&fleetv1.CancelOperatorCredentialRequestResponse{Request: requestToProto(r)}), nil
}

// RecordOperatorCredential checks and records an operator certificate the
// external operator CA signed. With request_id, the level, CN and public key
// must match the pending request, which is then completed; without it, a
// certificate made entirely out of band is imported and its level read from
// the extension. Either way it must pass the operator certificate profile,
// chain to the active operator CA, and not be recorded already. Admin-gated
// and audited.
func (s *Service) RecordOperatorCredential(ctx context.Context, req *connect.Request[fleetv1.RecordOperatorCredentialRequest]) (*connect.Response[fleetv1.RecordOperatorCredentialResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	der := req.Msg.GetCertDer()
	if len(der) == 0 || len(der) > maxCertSize {
		return nil, invalidArg("cert_der must be one DER certificate of at most %d bytes", maxCertSize)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, invalidArg("cert_der is not exactly one DER certificate: %v", err)
	}
	fullName := req.Msg.GetFullName()
	if fullName != "" {
		if err := operatorca.ValidateFullName(fullName); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	if !s.hasOperatorCA() {
		return nil, errOperatorCAUnconfigured("RecordOperatorCredential")
	}
	cs, err := s.credentialStore()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	check := operatorca.CertCheck{Now: now, Revoked: s.revocations.IsRevoked, CheckRevocation: s.revocations.CheckWebCert}
	var request store.OperatorCredentialRequest
	if rid := req.Msg.GetRequestId(); rid != "" {
		request, err = cs.OperatorCredentialRequest(ctx, rid, now)
		if err != nil {
			return nil, credStoreErr(err)
		}
		if request.State != store.RequestPending {
			return nil, requestStateErr(request)
		}
		csr, err := x509.ParseCertificateRequest(request.CSRDER)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: the stored CSR of request %s doesn't parse: %w", rid, err))
		}
		check.WantLevel, check.CSR = request.Level, csr
		if fullName == "" {
			fullName = request.FullName
		}
	}

	anchor, err := s.signingAnchor(cert)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if cn := strings.ToLower(cert.Subject.CommonName); request.ID != "" && cn != request.Email {
		return nil, connect.NewError(connect.CodeInvalidArgument, apperr.Reasoned(apperr.CodeCertRejected,
			fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH,
			fmt.Errorf("fleet: the certificate is for %q, but request %s is for %s", cn, request.ID, request.Email)))
	}
	res, err := operatorca.CheckOperatorCert(cert, anchor.Cert, check)
	if err != nil {
		// No fresh revocation data (1608) is the deployment's state, not a
		// problem with the certificate.
		if code, _ := apperr.Code(err); code == apperr.CodeNoRevocationSource {
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	kind := store.OperatorCredentialRecorded
	if request.ID != "" {
		kind = store.OperatorCredentialRequested
	}
	sum := sha256.Sum256(cert.Raw)
	cred := store.OperatorCredential{
		CommonName: res.Email, SerialHex: res.Serial, Level: res.Level.Token(),
		NotAfter: cert.NotAfter.UTC().Format(time.RFC3339), IssuerSHA256: anchor.SHA256, Kind: kind,
		Email: res.Email, FullName: fullName, LeafSHA256: hex.EncodeToString(sum[:]), RequestID: request.ID,
	}
	if err := cs.RecordOperatorCredential(ctx, cred, request.ID, now); err != nil {
		if errors.Is(err, store.ErrRequestNotPending) {
			current, _ := cs.OperatorCredentialRequest(ctx, request.ID, now)
			return nil, requestStateErr(current)
		}
		return nil, credStoreErr(err)
	}

	log.Printf("fleet: %s recorded %s operator credential %s for %s under operator CA %s", id.CN, cred.Level, cred.SerialHex, cred.Email, cred.IssuerSHA256)
	summary := fmt.Sprintf("Recorded %s operator credential %s for %s, signed by operator CA %s, expiring %s",
		cred.Level, cred.SerialHex, cred.Email, cred.IssuerSHA256, cred.NotAfter)
	if request.ID != "" {
		summary += fmt.Sprintf(", completing request %s", request.ID)
	}
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         now.Format(time.RFC3339),
		Kind:       "operator-credential-recorded",
		Summary:    summary,
		TargetKind: "operator-credential",
		TargetPath: "/operators/" + cred.SerialHex,
	})

	return connect.NewResponse(&fleetv1.RecordOperatorCredentialResponse{
		Credential: s.credentialToProto(cred),
		Warnings:   res.Warnings,
	}), nil
}

// signingAnchor finds the trusted operator CA that signed cert. New
// credentials must come from the active operator CA, so one signed by a
// retiring CA is refused with NOT_ACTIVE_ANCHOR. A certificate no trusted CA
// signed is left to CheckOperatorCert, against an active CA, to refuse as
// NOT_CHAINED.
func (s *Service) signingAnchor(cert *x509.Certificate) (operatorca.Anchor, error) {
	var active []operatorca.Anchor
	for _, a := range s.trust.Anchors() {
		if !bytes.Equal(cert.RawIssuer, a.Cert.RawSubject) || cert.CheckSignatureFrom(a.Cert) != nil {
			if a.State == store.OperatorCAActive {
				active = append(active, a)
			}
			continue
		}
		if a.State != store.OperatorCAActive {
			return operatorca.Anchor{}, apperr.Reasoned(apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_NOT_ACTIVE_ANCHOR,
				fmt.Errorf("fleet: the certificate was signed by the %s operator CA %s; record certificates from the active operator CA", a.State, a.Cert.Subject))
		}
		return a, nil
	}
	if len(active) == 0 {
		return operatorca.Anchor{}, apperr.Reasoned(apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_NOT_CHAINED,
			errors.New("fleet: no operator CA is active"))
	}
	return active[0], nil
}

func csrPEM(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func requestToProto(r store.OperatorCredentialRequest) *fleetv1.OperatorCredentialRequest {
	return &fleetv1.OperatorCredentialRequest{
		Id: r.ID, Level: r.Level, Email: r.Email, FullName: r.FullName, CsrPem: csrPEM(r.CSRDER),
		State: r.State, CreatedByCn: r.CreatedByCN, CreatedAt: rfc3339(r.CreatedAt), ExpiresAt: rfc3339(r.ExpiresAt),
		CompletedSerial: r.CompletedSerial,
	}
}

// rfc3339 formats t, or returns "" for the zero time.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
