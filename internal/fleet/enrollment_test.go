package fleet

/*
Apache License 2.0

Copyright 2026 Shane

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/nodeclient"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

const testOperatorCAPEM = "OPERATOR-CA-PEM"

// operatorCtx returns a context carrying an authenticated identity at the
// given level.
func operatorCtx(cn string, level authz.Level) context.Context {
	return authz.NewContext(context.Background(), authz.Identity{CN: cn, Level: level})
}

// dialPEMFakeFor returns a dialPEM seam that always hands back conn,
// ignoring the supplied connection material (tests only care what the
// Service does with the resulting NodeConn).
func dialPEMFakeFor(conn NodeConn) func(endpoint, certPEM, keyPEM, caPEM string) (NodeConn, error) {
	return func(string, string, string, string) (NodeConn, error) {
		return conn, nil
	}
}

// connErr is a connect error asserted for code.
func requireConnectCode(t *testing.T, err error, code connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want code %v", code)
	}
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if cerr.Code() != code {
		t.Fatalf("error code = %v, want %v (%v)", cerr.Code(), code, err)
	}
}

func TestCreateEnrollment_Link_Operator(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	conn := &fakeConn{attestKey: key}

	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(conn), testOperatorCAPEM)

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.CreateEnrollment(ctx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind:         "LINK",
		NodeEndpoint: "node.acme.com:4443",
		AdminCertPem: "cert",
		AdminKeyPem:  "key",
		CaPem:        "ca",
	}))
	if err != nil {
		t.Fatalf("CreateEnrollment(LINK) error = %v, want nil", err)
	}

	e := resp.Msg.GetEnrollment()
	if e == nil {
		t.Fatal("CreateEnrollment(LINK) returned nil enrollment")
	}
	if e.GetKind() != "LINK" {
		t.Errorf("Kind = %q, want LINK", e.GetKind())
	}
	if e.GetStatus() != "PENDING" {
		t.Errorf("Status = %q, want PENDING", e.GetStatus())
	}
	if e.GetPinnedKeySha256() == "" {
		t.Error("PinnedKeySha256 is empty, want a TOFU fingerprint")
	}
	if e.GetAddress() != "node.acme.com:4443" {
		t.Errorf("Address = %q, want node.acme.com:4443", e.GetAddress())
	}
	if !conn.closed {
		t.Error("dialPEM conn was not closed")
	}

	stored, ok := st.Enrollment(e.GetId())
	if !ok {
		t.Fatal("enrollment not persisted in store")
	}
	if !stored.AttestationOK {
		t.Error("stored.AttestationOK = false, want true")
	}
	if stored.PinnedKeySHA256 != e.GetPinnedKeySha256() {
		t.Errorf("stored.PinnedKeySHA256 = %q, want %q", stored.PinnedKeySHA256, e.GetPinnedKeySha256())
	}
}

func TestCreateEnrollment_Link_AttestationFails(t *testing.T) {
	conn := &fakeConn{err: errors.New("attest refused")}

	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(conn), testOperatorCAPEM)

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.CreateEnrollment(ctx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind:         "LINK",
		NodeEndpoint: "node.acme.com:4443",
		AdminCertPem: "cert",
		AdminKeyPem:  "key",
	}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
}

func TestCreateEnrollment_Subordinate_Operator(t *testing.T) {
	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.CreateEnrollment(ctx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind:      "SUBORDINATE",
		ChildNode: "child-1",
		ParentCn:  "ACME Intermediate CA",
		Profile:   "subordinate-ca",
	}))
	if err != nil {
		t.Fatalf("CreateEnrollment(SUBORDINATE) error = %v, want nil", err)
	}

	e := resp.Msg.GetEnrollment()
	if e.GetKind() != "SUBORDINATE" {
		t.Errorf("Kind = %q, want SUBORDINATE", e.GetKind())
	}
	if e.GetStatus() != "PENDING" {
		t.Errorf("Status = %q, want PENDING", e.GetStatus())
	}
	if e.GetProposedName() != "child-1" {
		t.Errorf("ProposedName = %q, want child-1", e.GetProposedName())
	}
	if e.GetParentCn() != "ACME Intermediate CA" {
		t.Errorf("ParentCn = %q, want ACME Intermediate CA", e.GetParentCn())
	}

	stored, ok := st.Enrollment(e.GetId())
	if !ok {
		t.Fatal("enrollment not persisted in store")
	}
	if stored.Profile != "subordinate-ca" {
		t.Errorf("stored.Profile = %q, want subordinate-ca", stored.Profile)
	}
}

func TestCreateEnrollment_Subordinate_MissingField(t *testing.T) {
	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.CreateEnrollment(ctx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind:      "SUBORDINATE",
		ChildNode: "child-1",
		// ParentCn and Profile omitted.
	}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestCreateEnrollment_Viewer_PermissionDenied(t *testing.T) {
	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.CreateEnrollment(ctx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind:      "SUBORDINATE",
		ChildNode: "child-1",
		ParentCn:  "ACME Intermediate CA",
		Profile:   "subordinate-ca",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func TestCreateEnrollment_NoIdentity_Unauthenticated(t *testing.T) {
	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	_, err := svc.CreateEnrollment(context.Background(), connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind:      "SUBORDINATE",
		ChildNode: "child-1",
		ParentCn:  "ACME Intermediate CA",
		Profile:   "subordinate-ca",
	}))
	requireConnectCode(t, err, connect.CodeUnauthenticated)
}

func TestApproveEnrollment_Link_OperatorDenied(t *testing.T) {
	st := memory.New(nil)
	st.AddEnrollment(store.Enrollment{ID: "enr-1", Kind: "LINK", Status: "PENDING"})
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.ApproveEnrollment(ctx, connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{Id: "enr-1"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func TestApproveEnrollment_Link_Admin(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	createConn := &fakeConn{attestKey: key}

	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(createConn), testOperatorCAPEM)

	createCtx := operatorCtx("op@acme.example", authz.LevelOperator)
	createResp, err := svc.CreateEnrollment(createCtx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind:         "LINK",
		NodeEndpoint: "node.acme.com:4443",
		AdminCertPem: "cert",
		AdminKeyPem:  "key",
		CaPem:        "ca",
	}))
	if err != nil {
		t.Fatalf("CreateEnrollment(LINK) error = %v, want nil", err)
	}
	id := createResp.Msg.GetEnrollment().GetId()

	approveConn := &fakeConn{attestKey: key}
	svc.dialPEM = dialPEMFakeFor(approveConn)

	adminCtx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	approveResp, err := svc.ApproveEnrollment(adminCtx, connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{
		Id:           id,
		NodeEndpoint: "node.acme.com:4443",
		AdminCertPem: "cert",
		AdminKeyPem:  "key",
		CaPem:        "ca",
	}))
	if err != nil {
		t.Fatalf("ApproveEnrollment(LINK) error = %v, want nil", err)
	}

	if approveResp.Msg.GetEnrollment().GetStatus() != "APPROVED" {
		t.Errorf("Status = %q, want APPROVED", approveResp.Msg.GetEnrollment().GetStatus())
	}

	if approveConn.gotManagement == nil {
		t.Fatal("SetManagement was not called on the approval conn")
	}
	if approveConn.gotManagement.GetManagerCn() != "admin@acme.example" {
		t.Errorf("Management.ManagerCn = %q, want admin@acme.example", approveConn.gotManagement.GetManagerCn())
	}
	if approveConn.gotManagement.GetTrustPem() != testOperatorCAPEM {
		t.Errorf("Management.TrustPem = %q, want %q", approveConn.gotManagement.GetTrustPem(), testOperatorCAPEM)
	}
	if !approveConn.gotManagement.GetOperatorSurfaceReadonly() {
		t.Error("Management.OperatorSurfaceReadonly = false, want true")
	}
	if !approveConn.closed {
		t.Error("approve conn was not closed")
	}
}

func TestApproveEnrollment_Link_PinMismatch_FailedPrecondition(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	createConn := &fakeConn{attestKey: key}

	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(createConn), testOperatorCAPEM)

	createCtx := operatorCtx("op@acme.example", authz.LevelOperator)
	createResp, err := svc.CreateEnrollment(createCtx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind:         "LINK",
		NodeEndpoint: "node.acme.com:4443",
		AdminCertPem: "cert",
		AdminKeyPem:  "key",
		CaPem:        "ca",
	}))
	if err != nil {
		t.Fatalf("CreateEnrollment(LINK) error = %v, want nil", err)
	}
	id := createResp.Msg.GetEnrollment().GetId()

	// The node's identity key changed since enrollment (e.g. re-provisioned):
	// re-attestation now produces a different fingerprint.
	approveConn := &fakeConn{attestKey: otherKey}
	svc.dialPEM = dialPEMFakeFor(approveConn)

	adminCtx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err = svc.ApproveEnrollment(adminCtx, connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{
		Id:           id,
		NodeEndpoint: "node.acme.com:4443",
		AdminCertPem: "cert",
		AdminKeyPem:  "key",
		CaPem:        "ca",
	}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)

	if approveConn.gotManagement != nil {
		t.Error("SetManagement was called despite a pin mismatch")
	}

	stored, ok := st.Enrollment(id)
	if !ok {
		t.Fatal("enrollment vanished from store")
	}
	if stored.Status != "PENDING" {
		t.Errorf("stored.Status = %q, want PENDING (unchanged on pin mismatch)", stored.Status)
	}
}

func TestApproveEnrollment_Subordinate_Operator(t *testing.T) {
	var calls []string
	childConn := &fakeConn{calls: &calls}
	parentConn := &fakeConn{
		calls: &calls,
		signSubordinateResp: &cryptosv1.SignSubordinateCSRResponse{
			ChainDer: [][]byte{[]byte("child-der"), []byte("parent-der")},
			ChainPem: "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
		},
	}

	st := memory.NewWithCatalog(
		[]store.Node{
			{Name: "child-1", Endpoint: "child.acme.com:4443"},
			{Name: "parent-1", Endpoint: "parent.acme.com:4443"},
		},
		nil, nil, nil,
		[]store.Enrollment{
			{ID: "enr-1", Kind: "SUBORDINATE", Status: "PENDING", ProposedName: "child-1", ParentCN: "ACME Intermediate CA", Profile: "subordinate-ca"},
		},
	)

	parentIdentityConn := &fakeConn{
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "ACME Intermediate CA", "ACME Root CA")}},
		},
	}
	childIdentityConn := &fakeConn{
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "child-1", "ACME Intermediate CA")}},
		},
	}

	// resolveParentByCN dials every inventory node via s.dial (not dialPEM) to
	// find the one whose leaf CN matches ParentCN; runSubordinateFerry then
	// dials the resolved child/parent nodes again via s.dial to run the
	// ferry. Route by node name: identity probes hand back a conn whose
	// GetIdentity works, while the ferry uses the same node name's conn for
	// GetSubordinateCSR/SignSubordinateCSR/SubmitSubordinateCertificate.
	dial := func(n store.Node) (NodeConn, error) {
		switch n.Name {
		case "child-1":
			return &routingConn{identity: childIdentityConn, ferry: childConn}, nil
		case "parent-1":
			return &routingConn{identity: parentIdentityConn, ferry: parentConn}, nil
		}
		return nil, errors.New("no fake conn for " + n.Name)
	}

	svc := New(st, dial).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.ApproveEnrollment(ctx, connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{Id: "enr-1"}))
	if err != nil {
		t.Fatalf("ApproveEnrollment(SUBORDINATE) error = %v, want nil", err)
	}

	if resp.Msg.GetEnrollment().GetStatus() != "APPROVED" {
		t.Errorf("Status = %q, want APPROVED", resp.Msg.GetEnrollment().GetStatus())
	}

	want := []string{"GetSubordinateCSR", "SignSubordinateCSR", "SubmitSubordinateCertificate"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("calls[%d] = %q, want %q (full: %v)", i, calls[i], want[i], calls)
		}
	}
	if parentConn.gotCSRProfile != "subordinate-ca" {
		t.Errorf("SignSubordinateCSR profile = %q, want subordinate-ca", parentConn.gotCSRProfile)
	}
}

func TestApproveEnrollment_NotPending_FailedPrecondition(t *testing.T) {
	st := memory.New(nil)
	st.AddEnrollment(store.Enrollment{ID: "enr-1", Kind: "LINK", Status: "APPROVED"})
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ApproveEnrollment(ctx, connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{Id: "enr-1"}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
}

func TestApproveEnrollment_UnknownID_NotFound(t *testing.T) {
	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ApproveEnrollment(ctx, connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{Id: "missing"}))
	requireConnectCode(t, err, connect.CodeNotFound)
}

func TestRejectEnrollment_Operator(t *testing.T) {
	st := memory.New(nil)
	st.AddEnrollment(store.Enrollment{ID: "enr-1", Kind: "LINK", Status: "PENDING"})
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.RejectEnrollment(ctx, connect.NewRequest(&fleetv1.RejectEnrollmentRequest{Id: "enr-1", Reason: "bad key"}))
	if err != nil {
		t.Fatalf("RejectEnrollment error = %v, want nil", err)
	}
	if resp.Msg.GetEnrollment().GetStatus() != "REJECTED" {
		t.Errorf("Status = %q, want REJECTED", resp.Msg.GetEnrollment().GetStatus())
	}
	if resp.Msg.GetEnrollment().GetRejectionReason() != "bad key" {
		t.Errorf("RejectionReason = %q, want %q", resp.Msg.GetEnrollment().GetRejectionReason(), "bad key")
	}
}

func TestRejectEnrollment_AppendsAuditEvent(t *testing.T) {
	st := memory.New(nil)
	st.AddEnrollment(store.Enrollment{ID: "enr-1", Kind: "LINK", Status: "PENDING", ProposedName: "node-1"})
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	before := len(st.Audit())
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	if _, err := svc.RejectEnrollment(ctx, connect.NewRequest(&fleetv1.RejectEnrollmentRequest{Id: "enr-1", Reason: "bad key"})); err != nil {
		t.Fatalf("RejectEnrollment error = %v, want nil", err)
	}

	audit := st.Audit()
	if len(audit) != before+1 {
		t.Fatalf("audit len = %d, want %d (one new event)", len(audit), before+1)
	}
	last := audit[len(audit)-1]
	if last.Kind != "enroll-rejected" {
		t.Errorf("Kind = %q, want enroll-rejected", last.Kind)
	}
	if last.Hash == "" {
		t.Error("audit event Hash is empty, want a chain hash")
	}
}

func TestApproveEnrollment_Link_AppendsAuditEvent(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	createConn := &fakeConn{attestKey: key}

	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(createConn), testOperatorCAPEM)

	createCtx := operatorCtx("op@acme.example", authz.LevelOperator)
	createResp, err := svc.CreateEnrollment(createCtx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind:         "LINK",
		NodeEndpoint: "node.acme.com:4443",
		AdminCertPem: "cert",
		AdminKeyPem:  "key",
		CaPem:        "ca",
	}))
	if err != nil {
		t.Fatalf("CreateEnrollment(LINK) error = %v, want nil", err)
	}
	id := createResp.Msg.GetEnrollment().GetId()

	svc.dialPEM = dialPEMFakeFor(&fakeConn{attestKey: key})
	before := len(st.Audit())
	adminCtx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	if _, err := svc.ApproveEnrollment(adminCtx, connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{
		Id:           id,
		NodeEndpoint: "node.acme.com:4443",
		AdminCertPem: "cert",
		AdminKeyPem:  "key",
		CaPem:        "ca",
	})); err != nil {
		t.Fatalf("ApproveEnrollment(LINK) error = %v, want nil", err)
	}

	audit := st.Audit()
	if len(audit) != before+1 {
		t.Fatalf("audit len = %d, want %d (one new event)", len(audit), before+1)
	}
	if audit[len(audit)-1].Kind != "enroll-approved" {
		t.Errorf("Kind = %q, want enroll-approved", audit[len(audit)-1].Kind)
	}
}

func TestRejectEnrollment_NotPending_FailedPrecondition(t *testing.T) {
	st := memory.New(nil)
	st.AddEnrollment(store.Enrollment{ID: "enr-1", Kind: "LINK", Status: "REJECTED"})
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.RejectEnrollment(ctx, connect.NewRequest(&fleetv1.RejectEnrollmentRequest{Id: "enr-1"}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
}

func TestRejectEnrollment_UnknownID_NotFound(t *testing.T) {
	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.RejectEnrollment(ctx, connect.NewRequest(&fleetv1.RejectEnrollmentRequest{Id: "missing"}))
	requireConnectCode(t, err, connect.CodeNotFound)
}

func TestRejectEnrollment_Viewer_PermissionDenied(t *testing.T) {
	st := memory.New(nil)
	st.AddEnrollment(store.Enrollment{ID: "enr-1", Kind: "LINK", Status: "PENDING"})
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{}), testOperatorCAPEM)

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.RejectEnrollment(ctx, connect.NewRequest(&fleetv1.RejectEnrollmentRequest{Id: "enr-1"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

// routingConn splits GetIdentity to identity's fake and every ferry-relevant
// method to ferry's fake, so a single dial func can serve both
// resolveParentByCN's identity probe and runSubordinateFerry's ferry calls
// against the same inventory node without them clobbering each other's
// canned responses.
type routingConn struct {
	identity NodeConn
	ferry    NodeConn
}

func (r *routingConn) GetStatus(ctx context.Context) (*cryptosv1.GetStatusResponse, error) {
	return r.ferry.GetStatus(ctx)
}

func (r *routingConn) ListInstallDisks(ctx context.Context) (*cryptosv1.ListInstallDisksResponse, error) {
	return r.ferry.ListInstallDisks(ctx)
}

func (r *routingConn) GetIdentity(ctx context.Context) (*cryptosv1.GetIdentityResponse, error) {
	return r.identity.GetIdentity(ctx)
}

func (r *routingConn) ListIssued(ctx context.Context) (*cryptosv1.ListIssuedResponse, error) {
	return r.ferry.ListIssued(ctx)
}

func (r *routingConn) ListRevocations(ctx context.Context) (*cryptosv1.ListRevocationsResponse, error) {
	return r.ferry.ListRevocations(ctx)
}

func (r *routingConn) Attest(ctx context.Context, nonce []byte) (*cryptosv1.AttestResponse, error) {
	return r.ferry.Attest(ctx, nonce)
}

func (r *routingConn) GetSubordinateCSR(ctx context.Context) (*cryptosv1.GetSubordinateCSRResponse, error) {
	return r.ferry.GetSubordinateCSR(ctx)
}

func (r *routingConn) SignSubordinateCSR(ctx context.Context, csrDER []byte, profile string) (*cryptosv1.SignSubordinateCSRResponse, error) {
	return r.ferry.SignSubordinateCSR(ctx, csrDER, profile)
}

func (r *routingConn) SubmitSubordinateCertificate(ctx context.Context, chainDER [][]byte, chainPEM string) (*cryptosv1.SubmitSubordinateCertificateResponse, error) {
	return r.ferry.SubmitSubordinateCertificate(ctx, chainDER, chainPEM)
}

func (r *routingConn) ApplyConfig(ctx context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error) {
	return r.ferry.ApplyConfig(ctx, cfg)
}

func (r *routingConn) GetConfig(ctx context.Context) (*cryptosv1.GetConfigResponse, error) {
	return r.ferry.GetConfig(ctx)
}

func (r *routingConn) SetManagement(ctx context.Context, m *cryptosv1.Management) (*cryptosv1.SetManagementResponse, error) {
	return r.ferry.SetManagement(ctx, m)
}

func (r *routingConn) RevokeCertificate(ctx context.Context, serialHex string, reasonCode int32) (*cryptosv1.RevokeCertificateResponse, error) {
	return r.ferry.RevokeCertificate(ctx, serialHex, reasonCode)
}

func (r *routingConn) IssueLeaf(ctx context.Context, csrDER []byte, profileName string) (*cryptosv1.IssueLeafResponse, error) {
	return r.ferry.IssueLeaf(ctx, csrDER, profileName)
}

func (r *routingConn) BeginKeyRotation(ctx context.Context) (*cryptosv1.BeginKeyRotationResponse, error) {
	return r.ferry.BeginKeyRotation(ctx)
}

func (r *routingConn) CompleteKeyRotation(ctx context.Context, chainDER [][]byte, chainPEM string) (*cryptosv1.CompleteKeyRotationResponse, error) {
	return r.ferry.CompleteKeyRotation(ctx, chainDER, chainPEM)
}

func (r *routingConn) ExportCAKey(ctx context.Context, passphrase []byte) (*cryptosv1.ExportCAKeyResponse, error) {
	return r.ferry.ExportCAKey(ctx, passphrase)
}

func (r *routingConn) ImportCAKey(ctx context.Context, envelope, passphrase []byte) (*cryptosv1.ImportCAKeyResponse, error) {
	return r.ferry.ImportCAKey(ctx, envelope, passphrase)
}

func (r *routingConn) RemoteReset(ctx context.Context, confirmCN string) (*cryptosv1.RemoteResetResponse, error) {
	return r.identity.RemoteReset(ctx, confirmCN)
}

func (r *routingConn) StartCeremony(ctx context.Context, kind cryptosv1.CeremonyKind, machineConfigYAML []byte) (nodeclient.CeremonyStream, error) {
	return r.identity.StartCeremony(ctx, kind, machineConfigYAML)
}

func (r *routingConn) Close() error {
	_ = r.ferry.Close()
	return r.identity.Close()
}

// issuedLeafDER builds subjectCN's DER certificate, issued by a freshly
// generated CA named issuerCN, for feeding leafCNs in resolveParentByCN
// tests (which only reads the leaf's Subject/Issuer names off a real chain).
// It reuses signCert (nodes_test.go) for both the issuer and the leaf.
func issuedLeafDER(t *testing.T, subjectCN, issuerCN string) []byte {
	t.Helper()
	_, issuerCert, issuerKey := signCert(t, issuerCN, nil, nil)
	leafDER, _, _ := signCert(t, subjectCN, issuerCert, issuerKey)
	return leafDER
}
