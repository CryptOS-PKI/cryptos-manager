package fleet

/*
Apache License 2.0

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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// operatorLevel returns the authenticated operator identity carried by ctx.
// Every enrollment RPC needs at least one operator identity to authorize
// against, so callers reach for this before checking a specific Level.
func operatorLevel(ctx context.Context) (authz.Identity, error) {
	id, ok := authz.FromContext(ctx)
	if !ok {
		return authz.Identity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("fleet: no operator identity"))
	}
	return id, nil
}

// CreateEnrollment opens a new enrollment request. LINK dials the not-yet-
// inventoried node with the caller-supplied admin cert/key, runs the
// attestation challenge to TOFU-pin its identity, and records it as
// PENDING. SUBORDINATE just records the requested child/parent/profile as
// PENDING; the ferry itself runs at approval time. Both kinds require
// operator level or above.
func (s *Service) CreateEnrollment(ctx context.Context, req *connect.Request[fleetv1.CreateEnrollmentRequest]) (*connect.Response[fleetv1.CreateEnrollmentResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	switch req.Msg.GetKind() {
	case "LINK":
		return s.createLinkEnrollment(ctx, req.Msg)
	case "SUBORDINATE":
		return s.createSubordinateEnrollment(req.Msg)
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("fleet: unknown enrollment kind %q", req.Msg.GetKind()))
	}
}

// createLinkEnrollment dials the candidate node with the supplied admin
// material, attests it, and stores a PENDING LINK enrollment pinned to the
// attested identity's fingerprint.
func (s *Service) createLinkEnrollment(ctx context.Context, msg *fleetv1.CreateEnrollmentRequest) (*connect.Response[fleetv1.CreateEnrollmentResponse], error) {
	if s.dialPEM == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("fleet: enrollment not configured (no PEM dial seam)"))
	}
	conn, err := s.dialPEM(msg.GetNodeEndpoint(), msg.GetAdminCertPem(), msg.GetAdminKeyPem(), msg.GetCaPem())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	fp, err := verifyAttestation(ctx, conn)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("fleet: attestation: %w", err))
	}

	// The node's CN is display-only at this stage; tolerate a GetIdentity
	// failure rather than blocking the enrollment on it.
	cn := ""
	if idResp, ierr := conn.GetIdentity(ctx); ierr == nil {
		cn, _ = leafCNs(idResp.GetIdentity())
	}

	e := store.Enrollment{
		ID:              newEnrollmentID(),
		Kind:            "LINK",
		Status:          "PENDING",
		Address:         msg.GetNodeEndpoint(),
		ProposedName:    cn,
		PinnedKeySHA256: fp,
		AttestationOK:   true,
		RequestedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	s.store.AddEnrollment(e)

	return connect.NewResponse(&fleetv1.CreateEnrollmentResponse{Enrollment: enrollmentToProto(e)}), nil
}

// createSubordinateEnrollment records a PENDING SUBORDINATE enrollment for
// the given child node, parent CA, and issuing profile. No node is dialed
// here: the CSR/sign/submit ferry runs only once the request is approved.
func (s *Service) createSubordinateEnrollment(msg *fleetv1.CreateEnrollmentRequest) (*connect.Response[fleetv1.CreateEnrollmentResponse], error) {
	if msg.GetChildNode() == "" || msg.GetParentCn() == "" || msg.GetProfile() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: child_node, parent_cn, profile are required"))
	}

	e := store.Enrollment{
		ID:           newEnrollmentID(),
		Kind:         "SUBORDINATE",
		Status:       "PENDING",
		ProposedName: msg.GetChildNode(),
		ParentCN:     msg.GetParentCn(),
		Profile:      msg.GetProfile(),
		RequestedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	s.store.AddEnrollment(e)

	return connect.NewResponse(&fleetv1.CreateEnrollmentResponse{Enrollment: enrollmentToProto(e)}), nil
}

// ApproveEnrollment admits a PENDING enrollment. LINK approval requires
// admin level: it re-dials the node with freshly re-supplied admin material,
// re-attests, and rejects the approval outright if the node's identity
// fingerprint no longer matches the one pinned at CreateEnrollment (the node
// may have been re-provisioned, or the request may be targeting the wrong
// node entirely) — only then does it push managed-state via SetManagement.
// SUBORDINATE approval requires operator level: it resolves the parent node
// by CN against the inventory and runs the CSR/sign/submit ferry.
func (s *Service) ApproveEnrollment(ctx context.Context, req *connect.Request[fleetv1.ApproveEnrollmentRequest]) (*connect.Response[fleetv1.ApproveEnrollmentResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}

	e, ok := s.store.Enrollment(req.Msg.GetId())
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("fleet: enrollment not found"))
	}
	if e.Status != "PENDING" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("fleet: enrollment not pending"))
	}

	switch e.Kind {
	case "LINK":
		if err := s.approveLinkEnrollment(ctx, id, e, req.Msg); err != nil {
			return nil, err
		}
	case "SUBORDINATE":
		if err := s.approveSubordinateEnrollment(ctx, id, e); err != nil {
			return nil, err
		}
	default:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: enrollment %q has unknown kind %q", e.ID, e.Kind))
	}

	final, ok := s.store.Enrollment(e.ID)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: enrollment %q vanished after approval", e.ID))
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "enroll-approved",
		Summary:    fmt.Sprintf("Approved enrollment %s (%s)", final.ProposedName, final.Kind),
		TargetKind: "enrollment",
		TargetPath: "/enrollments/" + final.ID,
	})

	return connect.NewResponse(&fleetv1.ApproveEnrollmentResponse{Enrollment: enrollmentToProto(final)}), nil
}

// approveLinkEnrollment is the admin-gated LINK approval path: re-attest,
// pin-check, push managed-state, then mark the enrollment APPROVED.
func (s *Service) approveLinkEnrollment(ctx context.Context, id authz.Identity, e store.Enrollment, msg *fleetv1.ApproveEnrollmentRequest) error {
	if id.Level < authz.LevelAdmin {
		return connect.NewError(connect.CodePermissionDenied, errors.New("fleet: admin level required to approve a LINK"))
	}
	if msg.GetNodeEndpoint() == "" || msg.GetAdminKeyPem() == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: LINK approval must re-supply the node connection material"))
	}
	if s.dialPEM == nil {
		return connect.NewError(connect.CodeUnimplemented, errors.New("fleet: enrollment not configured (no PEM dial seam)"))
	}

	conn, err := s.dialPEM(msg.GetNodeEndpoint(), msg.GetAdminCertPem(), msg.GetAdminKeyPem(), msg.GetCaPem())
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	fp, err := verifyAttestation(ctx, conn)
	if err != nil {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("fleet: attestation: %w", err))
	}
	if fp != e.PinnedKeySHA256 {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("fleet: node identity changed since enrollment"))
	}

	if _, err := conn.SetManagement(ctx, &cryptosv1.Management{
		ManagerCn:               id.CN,
		TrustPem:                s.operatorCAPEM,
		OperatorSurfaceReadonly: true,
	}); err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: set management: %w", err))
	}

	if err := s.store.UpdateEnrollment(e.ID, func(en *store.Enrollment) {
		en.Status = "APPROVED"
		en.AdmittedNodeName = en.ProposedName
	}); err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: update enrollment: %w", err))
	}
	return nil
}

// approveSubordinateEnrollment is the operator-gated SUBORDINATE approval
// path: resolve the child (already inventoried) and parent (matched by CN)
// nodes, run the CSR/sign/submit ferry, then mark the enrollment APPROVED.
func (s *Service) approveSubordinateEnrollment(ctx context.Context, id authz.Identity, e store.Enrollment) error {
	if id.Level < authz.LevelOperator {
		return connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	child, ok := s.store.Node(e.ProposedName)
	if !ok {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("fleet: child node %q not in inventory", e.ProposedName))
	}

	parent, err := s.resolveParentByCN(ctx, e.ParentCN)
	if err != nil {
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}

	if err := s.runSubordinateFerry(ctx, child, parent, e.Profile); err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: subordinate ferry: %w", err))
	}

	if err := s.store.UpdateEnrollment(e.ID, func(en *store.Enrollment) {
		en.Status = "APPROVED"
		en.AdmittedNodeName = en.ProposedName
	}); err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: update enrollment: %w", err))
	}
	return nil
}

// resolveParentByCN dials each inventory node and matches the node's own
// identity leaf Subject CN against cn, returning the first match. The parent of
// a SUBORDINATE enrollment is named by CN rather than by inventory name because
// the operator identifies it the same way the topology labels a CA (its subject
// CN); the inventory has no separate CN-indexed lookup. A node that fails to
// dial or identify is skipped, so a transient failure on the real parent
// surfaces as "no match" — approval is a retriable no-op until the ferry runs.
func (s *Service) resolveParentByCN(ctx context.Context, cn string) (store.Node, error) {
	for _, n := range s.store.Nodes() {
		conn, err := s.dial(n)
		if err != nil {
			continue
		}
		idResp, err := conn.GetIdentity(ctx)
		_ = conn.Close()
		if err != nil {
			continue
		}
		if leaf, _ := leafCNs(idResp.GetIdentity()); leaf == cn {
			return n, nil
		}
	}
	return store.Node{}, fmt.Errorf("fleet: no inventory node with CA CN %q", cn)
}

// runSubordinateFerry drives the three-call subordinate-issuance sequence:
// the child hands over its own CSR, the parent signs it under profile, and
// the signed chain is delivered back to the child so it can adopt its new
// identity.
func (s *Service) runSubordinateFerry(ctx context.Context, child, parent store.Node, profile string) error {
	cc, err := s.dial(child)
	if err != nil {
		return fmt.Errorf("dial child %q: %w", child.Name, err)
	}
	defer func() { _ = cc.Close() }()

	csr, err := cc.GetSubordinateCSR(ctx)
	if err != nil {
		return fmt.Errorf("get subordinate csr from %q: %w", child.Name, err)
	}

	pc, err := s.dial(parent)
	if err != nil {
		return fmt.Errorf("dial parent %q: %w", parent.Name, err)
	}
	defer func() { _ = pc.Close() }()

	signed, err := pc.SignSubordinateCSR(ctx, csr.GetCsrDer(), profile)
	if err != nil {
		return fmt.Errorf("sign subordinate csr on %q: %w", parent.Name, err)
	}

	if _, err := cc.SubmitSubordinateCertificate(ctx, signed.GetChainDer(), signed.GetChainPem()); err != nil {
		return fmt.Errorf("submit subordinate certificate to %q: %w", child.Name, err)
	}
	return nil
}

// RejectEnrollment denies a PENDING enrollment, recording the operator's
// reason. Both LINK and SUBORDINATE rejection require only operator level:
// rejecting is strictly less privileged than approving, so it never needs
// admin.
func (s *Service) RejectEnrollment(ctx context.Context, req *connect.Request[fleetv1.RejectEnrollmentRequest]) (*connect.Response[fleetv1.RejectEnrollmentResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	e, ok := s.store.Enrollment(req.Msg.GetId())
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("fleet: enrollment not found"))
	}
	if e.Status != "PENDING" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("fleet: enrollment not pending"))
	}

	if err := s.store.UpdateEnrollment(e.ID, func(en *store.Enrollment) {
		en.Status = "REJECTED"
		en.RejectionReason = req.Msg.GetReason()
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: update enrollment: %w", err))
	}

	final, ok := s.store.Enrollment(e.ID)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: enrollment %q vanished after rejection", e.ID))
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "enroll-rejected",
		Summary:    fmt.Sprintf("Rejected enrollment %s (%s)", final.ProposedName, final.Kind),
		TargetKind: "enrollment",
		TargetPath: "/enrollments/" + final.ID,
	})

	return connect.NewResponse(&fleetv1.RejectEnrollmentResponse{Enrollment: enrollmentToProto(final)}), nil
}

// newEnrollmentID generates a unique enrollment identifier: an "enr-" prefix
// over 16 random bytes of hex, cheap collision odds that need no store
// round-trip to check.
func newEnrollmentID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is effectively unrecoverable; panic rather than
		// silently hand back a colliding/predictable ID.
		panic(fmt.Sprintf("fleet: newEnrollmentID: %v", err))
	}
	return "enr-" + hex.EncodeToString(b)
}

// newAuditID generates a unique audit-event identifier: an "aud-" prefix over
// 16 random bytes of hex. Same rationale as newEnrollmentID.
func newAuditID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("fleet: newAuditID: %v", err))
	}
	return "aud-" + hex.EncodeToString(b)
}
