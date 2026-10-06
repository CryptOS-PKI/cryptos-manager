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
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/google/uuid"
)

// certificateRequestLifetime is how long a pending certificate request can
// be decided before it reads as expired.
const certificateRequestLifetime = 30 * 24 * time.Hour

// CreateCertificateRequest files a request for a certificate under a
// requestable catalog profile, from a CSR a browser (or cryptosctl)
// generated. Viewer level and above. Audited.
func (s *Service) CreateCertificateRequest(ctx context.Context, req *connect.Request[fleetv1.CreateCertificateRequestRequest]) (*connect.Response[fleetv1.CreateCertificateRequestResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}

	profileName := req.Msg.GetProfileName()
	if profileName == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: profile_name is required"))
	}
	stored, ok := s.store.Profile(profileName)
	if !ok {
		return nil, apperr.Coded(apperr.CodeProfileNotFound,
			connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: profile %q not found", profileName)))
	}
	if !stored.Requestable {
		return nil, apperr.Coded(apperr.CodeProfileNotRequestable,
			connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("fleet: profile %q is not requestable", profileName)))
	}
	profile, err := unmarshalProfile(stored)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	csr, err := parseCertificateRequestCSR(req.Msg.GetCsrDer())
	if err != nil {
		return nil, err
	}
	if err := checkCSRAgainstProfile(csr, profile); err != nil {
		return nil, err
	}

	if s.approvals == nil {
		return nil, mcpDisabled()
	}

	now := time.Now().UTC()
	r := store.CertificateRequest{
		ID: uuid.NewString(), RequesterCN: id.CN, RequesterSerial: id.Serial,
		Profile: profileName, CSRDER: req.Msg.GetCsrDer(), Note: req.Msg.GetNote(),
		State: store.CertRequestPending, CreatedAt: now, ExpiresAt: now.Add(certificateRequestLifetime),
	}
	summary := fmt.Sprintf("Requested a %s certificate (request %s)", profileName, r.ID)
	approved := s.approvals.RequestCertificate(ctx, id, r.ID, summary, authz.LevelOperator)
	r.ApprovalID = approved.ID

	s.store.AddCertificateRequest(r)
	log.Printf("fleet: %s requested a %s certificate (request %s)", id.CN, profileName, r.ID)
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         now.Format(time.RFC3339),
		Kind:       "certificate-request-created",
		Summary:    summary,
		TargetKind: "certificate-request",
		TargetPath: "/certificate-requests/" + r.ID,
	})

	return connect.NewResponse(&fleetv1.CreateCertificateRequestResponse{Request: certRequestToProto(r)}), nil
}

// ListCertificateRequests returns certificate requests, newest first,
// optionally filtered by state. The requester sees only their own requests;
// an operator or admin sees every request.
func (s *Service) ListCertificateRequests(ctx context.Context, req *connect.Request[fleetv1.ListCertificateRequestsRequest]) (*connect.Response[fleetv1.ListCertificateRequestsResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}

	state := req.Msg.GetState()
	switch state {
	case "", store.CertRequestPending, store.CertRequestApproved, store.CertRequestIssued, store.CertRequestDenied,
		store.CertRequestCancelled, store.CertRequestExpired, store.CertRequestFailed:
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("fleet: state must be pending, approved, issued, denied, cancelled, expired or failed"))
	}

	mineOnly := req.Msg.GetMineOnly() || id.Level < authz.LevelOperator

	all := s.store.CertificateRequests(time.Now().UTC())
	items := make([]*fleetv1.CertificateRequest, 0, len(all))
	for _, r := range all {
		if state != "" && r.State != state {
			continue
		}
		if mineOnly && r.RequesterCN != id.CN {
			continue
		}
		items = append(items, certRequestToProto(r))
	}

	return connect.NewResponse(&fleetv1.ListCertificateRequestsResponse{Items: items}), nil
}

// GetCertificateRequestByID returns one certificate request's state, and its
// certificate once issued. Readable by the requester or by an operator and
// above; a read, so it is not audited.
func (s *Service) GetCertificateRequestByID(ctx context.Context, req *connect.Request[fleetv1.GetCertificateRequestByIDRequest]) (*connect.Response[fleetv1.GetCertificateRequestByIDResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}

	r, ok := s.store.CertificateRequest(req.Msg.GetId(), time.Now().UTC())
	if !ok {
		return nil, requestNotFoundErr(req.Msg.GetId())
	}
	if id.Level < authz.LevelOperator && r.RequesterCN != id.CN {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: not your certificate request"))
	}

	return connect.NewResponse(&fleetv1.GetCertificateRequestByIDResponse{Request: certRequestToProto(r)}), nil
}

// CancelCertificateRequest ends a pending certificate request. The requester
// may cancel their own; an admin may cancel any. Audited.
func (s *Service) CancelCertificateRequest(ctx context.Context, req *connect.Request[fleetv1.CancelCertificateRequestRequest]) (*connect.Response[fleetv1.CancelCertificateRequestResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	r, ok := s.store.CertificateRequest(req.Msg.GetId(), now)
	if !ok {
		return nil, requestNotFoundErr(req.Msg.GetId())
	}
	if id.Level < authz.LevelAdmin && r.RequesterCN != id.CN {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: only the requester or an admin can cancel this request"))
	}
	if r.State != store.CertRequestPending {
		return nil, requestNotPendingErr(r)
	}

	if err := s.store.UpdateCertificateRequest(r.ID, func(cr *store.CertificateRequest) {
		cr.State = store.CertRequestCancelled
		cr.DecidedAt = now
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: cancel certificate request: %w", err))
	}
	final, _ := s.store.CertificateRequest(r.ID, now)

	log.Printf("fleet: %s cancelled certificate request %s", id.CN, r.ID)
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         now.Format(time.RFC3339),
		Kind:       "certificate-request-cancelled",
		Summary:    fmt.Sprintf("Cancelled certificate request %s", r.ID),
		TargetKind: "certificate-request",
		TargetPath: "/certificate-requests/" + r.ID,
	})

	return connect.NewResponse(&fleetv1.CancelCertificateRequestResponse{Request: certRequestToProto(final)}), nil
}

// onCertificateRequestDecided runs after a CERTIFICATE_REQUEST approval is
// decided: a denial marks the request denied, and an approval marks it
// approved and then drives issuance. It is best-effort by design -- the
// approval itself has already been decided and DecideApproval must not fail
// the caller for a problem downstream of that decision; a failure here
// surfaces through the certificate request's own state instead.
func (s *Service) onCertificateRequestDecided(ctx context.Context, decided store.Approval) {
	now := time.Now().UTC()
	requestID := decided.RequestDigest
	r, ok := s.store.CertificateRequest(requestID, now)
	if !ok {
		log.Printf("fleet: certificate request %s (approval %s) vanished before its decision could be applied", requestID, decided.ID)
		return
	}

	if decided.Status != store.ApprovalApproved {
		if err := s.store.UpdateCertificateRequest(r.ID, func(cr *store.CertificateRequest) {
			cr.State = store.CertRequestDenied
			cr.DecidedAt = now
		}); err != nil {
			log.Printf("fleet: mark certificate request %s denied: %v", r.ID, err)
			return
		}
		auditlog.Record(ctx, s.store, store.AuditEvent{
			ID:         newAuditID(),
			At:         now.Format(time.RFC3339),
			Kind:       "certificate-request-denied",
			Summary:    fmt.Sprintf("Denied certificate request %s", r.ID),
			TargetKind: "certificate-request",
			TargetPath: "/certificate-requests/" + r.ID,
		})
		return
	}

	if err := s.store.UpdateCertificateRequest(r.ID, func(cr *store.CertificateRequest) {
		cr.State = store.CertRequestApproved
		cr.DecidedAt = now
	}); err != nil {
		log.Printf("fleet: mark certificate request %s approved: %v", r.ID, err)
		return
	}
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         now.Format(time.RFC3339),
		Kind:       "certificate-request-approved",
		Summary:    fmt.Sprintf("Approved certificate request %s", r.ID),
		TargetKind: "certificate-request",
		TargetPath: "/certificate-requests/" + r.ID,
	})

	s.issueCertificateRequest(ctx, r.ID)
}

// issueCertificateRequest finds the managed node currently serving the
// request's profile and calls its IssueLeaf. A node refusal, or no node
// serving the profile, moves the request to failed with the reason instead
// of returning an error: the approver has already acted, and the requester
// sees the failure on their own request.
func (s *Service) issueCertificateRequest(ctx context.Context, requestID string) {
	now := time.Now().UTC()
	r, ok := s.store.CertificateRequest(requestID, now)
	if !ok {
		log.Printf("fleet: certificate request %s vanished before issuance", requestID)
		return
	}

	node, err := s.resolveIssuingNodeForProfile(ctx, r.Profile)
	if err != nil {
		s.failCertificateRequest(ctx, r, err.Error())
		return
	}

	conn, err := s.dial(node)
	if err != nil {
		s.failCertificateRequest(ctx, r, fmt.Sprintf("dial %s: %v", node.Name, err))
		return
	}
	defer func() { _ = conn.Close() }()

	issued, err := conn.IssueLeaf(ctx, r.CSRDER, r.Profile)
	if err != nil {
		nerr := nodeError("issue leaf", err)
		reason, ok := apperr.NodeReasonOf(nerr)
		if !ok {
			reason = nerr.Error()
		}
		s.failCertificateRequest(ctx, r, reason)
		return
	}

	issuedAt := time.Now().UTC()
	if err := s.store.UpdateCertificateRequest(r.ID, func(cr *store.CertificateRequest) {
		cr.State = store.CertRequestIssued
		cr.CertDER = issued.GetCertDer()
		cr.IssuedAt = issuedAt
	}); err != nil {
		log.Printf("fleet: mark certificate request %s issued: %v", r.ID, err)
		return
	}
	log.Printf("fleet: issued a %s certificate for request %s on %s", r.Profile, r.ID, node.Name)
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         issuedAt.Format(time.RFC3339),
		Kind:       "certificate-request-issued",
		Summary:    fmt.Sprintf("Issued the certificate for request %s on %s", r.ID, node.Name),
		TargetKind: "certificate-request",
		TargetPath: "/certificate-requests/" + r.ID,
	})
}

// failCertificateRequest moves r to failed with reason and audits it.
func (s *Service) failCertificateRequest(ctx context.Context, r store.CertificateRequest, reason string) {
	at := time.Now().UTC()
	if err := s.store.UpdateCertificateRequest(r.ID, func(cr *store.CertificateRequest) {
		cr.State = store.CertRequestFailed
		cr.FailureReason = reason
	}); err != nil {
		log.Printf("fleet: mark certificate request %s failed: %v", r.ID, err)
		return
	}
	log.Printf("fleet: certificate request %s failed: %s", r.ID, reason)
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         at.Format(time.RFC3339),
		Kind:       "certificate-request-failed",
		Summary:    fmt.Sprintf("Certificate request %s failed: %s", r.ID, reason),
		TargetKind: "certificate-request",
		TargetPath: "/certificate-requests/" + r.ID,
	})
}

// resolveIssuingNodeForProfile finds the managed node whose current config
// carries profileName in pki.profiles[]. A node that cannot be dialled or
// read is skipped rather than failing the search. It errors if no managed
// node currently serves the profile.
func (s *Service) resolveIssuingNodeForProfile(ctx context.Context, profileName string) (store.Node, error) {
	for _, n := range s.store.Nodes() {
		conn, err := s.dial(n)
		if err != nil {
			continue
		}
		cfg, err := conn.GetConfig(ctx)
		_ = conn.Close()
		if err != nil {
			continue
		}
		for _, p := range cfg.GetConfig().GetPki().GetProfiles() {
			if p.GetName() == profileName {
				return n, nil
			}
		}
	}
	return store.Node{}, fmt.Errorf("no managed node currently serves profile %q", profileName)
}

// parseCertificateRequestCSR checks csrDER's size, parses it, and verifies
// its self-signature.
func parseCertificateRequestCSR(csrDER []byte) (*x509.CertificateRequest, error) {
	if len(csrDER) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: csr_der is required"))
	}
	if len(csrDER) > operatorca.MaxCSRSize {
		return nil, apperr.Coded(apperr.CodeCSRRejected, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("fleet: the CSR is %d bytes, more than %d", len(csrDER), operatorca.MaxCSRSize)))
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, apperr.Coded(apperr.CodeCSRRejected, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("fleet: the CSR doesn't parse: %w", err)))
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, apperr.Coded(apperr.CodeCSRRejected, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("fleet: the CSR signature doesn't verify: %w", err)))
	}
	return csr, nil
}

// checkCSRAgainstProfile checks a submitted CSR against the profile it is
// requested under. The node stamps the profile's own fixed subject common
// name and SANs over whatever the CSR carries, so a profile with no fixed
// common name needs the CSR to supply one, and a profile that doesn't allow
// request SANs should not receive a CSR that carries its own (they would
// silently be dropped). The CSR's key must be one the node will sign.
func checkCSRAgainstProfile(csr *x509.CertificateRequest, profile *nodev1.CertificateProfile) error {
	if profile.GetSubject().GetCommonName() == "" && csr.Subject.CommonName == "" {
		return csrProfileMismatch("subject", "the profile does not fix a subject common name, and the CSR has none")
	}
	if !profile.GetAllowRequestSans() && csrHasSANs(csr) {
		return csrProfileMismatch("sans", "the profile does not allow request SANs, but the CSR carries its own")
	}
	if !operatorca.LeafKeyAllowed(csr.PublicKey) {
		return csrProfileMismatch("key_type", "the CSR key must be ECDSA P-384 or RSA of 3072 bits or more")
	}
	return nil
}

// csrHasSANs reports whether csr carries any subject alternative name.
func csrHasSANs(csr *x509.CertificateRequest) bool {
	return len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0
}

func csrProfileMismatch(field, detail string) error {
	return apperr.Coded(apperr.CodeCsrProfileMismatch, connect.NewError(connect.CodeInvalidArgument,
		fmt.Errorf("fleet: the CSR's %s doesn't match the profile: %s", field, detail)))
}

func requestNotFoundErr(id string) error {
	return apperr.Coded(apperr.CodeRequestNotFound,
		connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: no such certificate request %s", id)))
}

func requestNotPendingErr(r store.CertificateRequest) error {
	return apperr.Coded(apperr.CodeRequestNotPending,
		connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("fleet: certificate request %s is %s, not pending", r.ID, r.State)))
}

func certPEM(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func certRequestToProto(r store.CertificateRequest) *fleetv1.CertificateRequest {
	return &fleetv1.CertificateRequest{
		Id: r.ID, ProfileName: r.Profile, CsrPem: csrPEM(r.CSRDER), Note: r.Note,
		RequestedByCn: r.RequesterCN, RequestedBySerial: r.RequesterSerial, State: r.State,
		ApprovalId: r.ApprovalID, CertificatePem: certPEM(r.CertDER), FailureReason: r.FailureReason,
		CreatedAt: rfc3339(r.CreatedAt), ExpiresAt: rfc3339(r.ExpiresAt),
		DecidedAt: rfc3339(r.DecidedAt), IssuedAt: rfc3339(r.IssuedAt),
	}
}
