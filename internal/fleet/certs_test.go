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
	"errors"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func certsTestStore() store.Store {
	return memory.New([]store.Node{
		{Name: "A", Endpoint: "a.acme.com:4443", Role: "root"},
		{Name: "B", Endpoint: "b.acme.com:4444", Role: "intermediate"},
	})
}

func TestListCertificates_MergesIssuedAndRevoked_SkipsBadNode(t *testing.T) {
	now := time.Now()

	connA := &fakeConn{
		issued: &cryptosv1.ListIssuedResponse{
			Issued: []*cryptosv1.IssuedCert{
				{
					SerialHex:   "01",
					SubjectDn:   "CN=leaf.acme.com",
					NotBefore:   timestamppb.New(now.Add(-time.Hour)),
					NotAfter:    timestamppb.New(now.Add(time.Hour)),
					ProfileName: "leaf-tls",
					IssuedAt:    timestamppb.New(now.Add(-time.Hour)),
				},
				{
					SerialHex:   "02",
					SubjectDn:   "CN=expired.acme.com",
					NotBefore:   timestamppb.New(now.Add(-48 * time.Hour)),
					NotAfter:    timestamppb.New(now.Add(-24 * time.Hour)),
					ProfileName: "leaf-tls",
					IssuedAt:    timestamppb.New(now.Add(-48 * time.Hour)),
				},
				{
					SerialHex:   "03",
					SubjectDn:   "CN=sub.acme.com",
					NotBefore:   timestamppb.New(now.Add(-time.Hour)),
					NotAfter:    timestamppb.New(now.Add(time.Hour)),
					ProfileName: "sub-ca",
					IssuedAt:    timestamppb.New(now.Add(-time.Hour)),
				},
			},
		},
		revocations: &cryptosv1.ListRevocationsResponse{
			Revocations: []*cryptosv1.Revocation{
				{
					SerialHex:  "01",
					RevokedAt:  timestamppb.New(now.Add(-time.Minute)),
					ReasonCode: 1,
				},
			},
		},
	}
	connB := &fakeConn{err: errors.New("dial refused")}

	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA, "B": connB}))

	resp, err := svc.ListCertificates(context.Background(), connect.NewRequest(&fleetv1.ListCertificatesRequest{}))
	if err != nil {
		t.Fatalf("ListCertificates() error = %v, want nil", err)
	}

	certs := resp.Msg.GetCertificates()
	if len(certs) != 3 {
		t.Fatalf("len(certs) = %d, want 3 (node B skipped, not fatal)", len(certs))
	}

	bySerial := map[string]*fleetv1.Certificate{}
	for _, c := range certs {
		if c.GetIssuerNode() != "A" {
			t.Errorf("cert %s IssuerNode = %q, want A", c.GetSerial(), c.GetIssuerNode())
		}
		bySerial[c.GetSerial()] = c
	}

	revoked := bySerial["01"]
	if revoked == nil {
		t.Fatal("missing serial 01")
	}
	if revoked.GetStatus() != "REVOKED" {
		t.Errorf("serial 01 Status = %q, want REVOKED", revoked.GetStatus())
	}
	if revoked.GetRevokedAt() == "" {
		t.Error("serial 01 RevokedAt is empty, want RFC3339 timestamp")
	}
	if revoked.GetKind() != "leaf" {
		t.Errorf("serial 01 Kind = %q, want leaf", revoked.GetKind())
	}

	expired := bySerial["02"]
	if expired == nil {
		t.Fatal("missing serial 02")
	}
	if expired.GetStatus() != "EXPIRED" {
		t.Errorf("serial 02 Status = %q, want EXPIRED", expired.GetStatus())
	}
	if expired.GetKind() != "leaf" {
		t.Errorf("serial 02 Kind = %q, want leaf", expired.GetKind())
	}

	subCA := bySerial["03"]
	if subCA == nil {
		t.Fatal("missing serial 03")
	}
	if subCA.GetStatus() != "VALID" {
		t.Errorf("serial 03 Status = %q, want VALID", subCA.GetStatus())
	}
	if subCA.GetKind() != "subordinate-ca" {
		t.Errorf("serial 03 Kind = %q, want subordinate-ca", subCA.GetKind())
	}
	if subCA.GetSubjectCn() != "CN=sub.acme.com" {
		t.Errorf("serial 03 SubjectCn = %q, want CN=sub.acme.com", subCA.GetSubjectCn())
	}
}

func TestListCertificates_ScopedToOneNode(t *testing.T) {
	connA := &fakeConn{
		issued: &cryptosv1.ListIssuedResponse{
			Issued: []*cryptosv1.IssuedCert{
				{SerialHex: "01", NotBefore: timestamppb.Now(), NotAfter: timestamppb.New(time.Now().Add(time.Hour))},
			},
		},
	}

	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	resp, err := svc.ListCertificates(context.Background(), connect.NewRequest(&fleetv1.ListCertificatesRequest{Node: "A"}))
	if err != nil {
		t.Fatalf("ListCertificates(node=A) error = %v, want nil", err)
	}

	certs := resp.Msg.GetCertificates()
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
	if certs[0].GetIssuerNode() != "A" {
		t.Errorf("IssuerNode = %q, want A", certs[0].GetIssuerNode())
	}
}

func TestListCertificates_ScopedToUnknownNode_NotFound(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{}))

	_, err := svc.ListCertificates(context.Background(), connect.NewRequest(&fleetv1.ListCertificatesRequest{Node: "missing"}))
	if err == nil {
		t.Fatal("ListCertificates(node=missing) error = nil, want NotFound")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("ListCertificates(node=missing) error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeNotFound {
		t.Errorf("ListCertificates(node=missing) error code = %v, want CodeNotFound", connectErr.Code())
	}
}

func TestRevokeCertificate_ViewerDenied_NoDialNoAudit(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.RevokeCertificate(ctx, connect.NewRequest(&fleetv1.RevokeCertificateRequest{
		NodeName:   "A",
		SerialHex:  "01",
		ReasonCode: 1,
	}))
	if err == nil {
		t.Fatal("RevokeCertificate(viewer) error = nil, want PermissionDenied")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodePermissionDenied {
		t.Errorf("code = %v, want CodePermissionDenied", connectErr.Code())
	}
	if connA.gotRevokeSerial != "" {
		t.Errorf("node was dialed and revoked (serial %q), want no call", connA.gotRevokeSerial)
	}
	if connA.closed {
		t.Error("node connection was opened, want no dial")
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event on denial)", len(st.Audit()), before)
	}
}

func TestRevokeCertificate_UnknownNode_NotFound(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{}))

	before := len(st.Audit())
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.RevokeCertificate(ctx, connect.NewRequest(&fleetv1.RevokeCertificateRequest{
		NodeName:   "missing",
		SerialHex:  "01",
		ReasonCode: 1,
	}))
	if err == nil {
		t.Fatal("RevokeCertificate(unknown node) error = nil, want NotFound")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeNotFound {
		t.Errorf("code = %v, want CodeNotFound", connectErr.Code())
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event when node unknown)", len(st.Audit()), before)
	}
}

func TestRevokeCertificate_Operator_RevokesAndAudits(t *testing.T) {
	now := time.Now().UTC()
	st := certsTestStore()
	connA := &fakeConn{
		revokeResp: &cryptosv1.RevokeCertificateResponse{
			Revocation: &cryptosv1.Revocation{
				SerialHex:  "0a1b",
				RevokedAt:  timestamppb.New(now),
				ReasonCode: 4,
			},
		},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.RevokeCertificate(ctx, connect.NewRequest(&fleetv1.RevokeCertificateRequest{
		NodeName:   "A",
		SerialHex:  "0a1b",
		ReasonCode: 4,
	}))
	if err != nil {
		t.Fatalf("RevokeCertificate(operator) error = %v, want nil", err)
	}

	if connA.gotRevokeSerial != "0a1b" {
		t.Errorf("node revoke serial = %q, want 0a1b", connA.gotRevokeSerial)
	}
	if connA.gotRevokeReason != 4 {
		t.Errorf("node revoke reason = %d, want 4", connA.gotRevokeReason)
	}
	if !connA.closed {
		t.Error("node connection was not closed")
	}

	msg := resp.Msg
	if msg.GetSerialHex() != "0a1b" {
		t.Errorf("response serial = %q, want 0a1b", msg.GetSerialHex())
	}
	if msg.GetReasonCode() != 4 {
		t.Errorf("response reason = %d, want 4", msg.GetReasonCode())
	}
	if msg.GetRevokedAt() != now.Format(time.RFC3339) {
		t.Errorf("response revokedAt = %q, want %q", msg.GetRevokedAt(), now.Format(time.RFC3339))
	}

	audit := st.Audit()
	if len(audit) != before+1 {
		t.Fatalf("audit len = %d, want %d (one new event)", len(audit), before+1)
	}
	last := audit[len(audit)-1]
	if last.Kind != "revoked" {
		t.Errorf("audit Kind = %q, want revoked", last.Kind)
	}
	if !strings.Contains(last.Summary, "0a1b") || !strings.Contains(last.Summary, "A") {
		t.Errorf("audit Summary = %q, want it to name the serial and node", last.Summary)
	}
	if last.TargetKind != "cert" {
		t.Errorf("audit TargetKind = %q, want cert", last.TargetKind)
	}
}

func TestIssueLeaf_ViewerDenied_NoDialNoAudit(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.IssueLeaf(ctx, connect.NewRequest(&fleetv1.IssueLeafRequest{
		NodeName:    "A",
		CsrDer:      []byte("csr"),
		ProfileName: "TLS Server",
	}))
	if err == nil {
		t.Fatal("IssueLeaf(viewer) error = nil, want PermissionDenied")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodePermissionDenied {
		t.Errorf("code = %v, want CodePermissionDenied", connectErr.Code())
	}
	if connA.gotIssueCSR != nil {
		t.Errorf("node was dialed and signed (csr %q), want no call", connA.gotIssueCSR)
	}
	if connA.closed {
		t.Error("node connection was opened, want no dial")
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event on denial)", len(st.Audit()), before)
	}
}

func TestIssueLeaf_EmptyCSR_InvalidArgument(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.IssueLeaf(ctx, connect.NewRequest(&fleetv1.IssueLeafRequest{
		NodeName:    "A",
		CsrDer:      nil,
		ProfileName: "TLS Server",
	}))
	if err == nil {
		t.Fatal("IssueLeaf(empty CSR) error = nil, want InvalidArgument")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want CodeInvalidArgument", connectErr.Code())
	}
	if connA.gotIssueCSR != nil {
		t.Error("node was dialed and signed, want no call on empty CSR")
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event on invalid argument)", len(st.Audit()), before)
	}
}

func TestIssueLeaf_UnknownNode_NotFound(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{}))

	before := len(st.Audit())
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.IssueLeaf(ctx, connect.NewRequest(&fleetv1.IssueLeafRequest{
		NodeName:    "missing",
		CsrDer:      []byte("csr"),
		ProfileName: "TLS Server",
	}))
	if err == nil {
		t.Fatal("IssueLeaf(unknown node) error = nil, want NotFound")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeNotFound {
		t.Errorf("code = %v, want CodeNotFound", connectErr.Code())
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event when node unknown)", len(st.Audit()), before)
	}
}

func TestIssueLeaf_Operator_SignsAndAudits(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{
		issueResp: &cryptosv1.IssueLeafResponse{CertDer: []byte("signed-leaf-der")},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.IssueLeaf(ctx, connect.NewRequest(&fleetv1.IssueLeafRequest{
		NodeName:    "A",
		CsrDer:      []byte("csr-der"),
		ProfileName: "TLS Server",
	}))
	if err != nil {
		t.Fatalf("IssueLeaf(operator) error = %v, want nil", err)
	}

	if string(connA.gotIssueCSR) != "csr-der" {
		t.Errorf("node issue CSR = %q, want csr-der", connA.gotIssueCSR)
	}
	if connA.gotIssueProfile != "TLS Server" {
		t.Errorf("node issue profile = %q, want TLS Server", connA.gotIssueProfile)
	}
	if !connA.closed {
		t.Error("node connection was not closed")
	}

	if string(resp.Msg.GetCertDer()) != "signed-leaf-der" {
		t.Errorf("response cert = %q, want signed-leaf-der", resp.Msg.GetCertDer())
	}

	audit := st.Audit()
	if len(audit) != before+1 {
		t.Fatalf("audit len = %d, want %d (one new event)", len(audit), before+1)
	}
	last := audit[len(audit)-1]
	if last.Kind != "issued" {
		t.Errorf("audit Kind = %q, want issued", last.Kind)
	}
	if !strings.Contains(last.Summary, "TLS Server") || !strings.Contains(last.Summary, "A") {
		t.Errorf("audit Summary = %q, want it to name the profile and node", last.Summary)
	}
	if last.TargetKind != "cert" {
		t.Errorf("audit TargetKind = %q, want cert", last.TargetKind)
	}
}

func TestIssueLeaf_NodeError_MappedNoAudit(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{err: errors.New("node refused")}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.IssueLeaf(ctx, connect.NewRequest(&fleetv1.IssueLeafRequest{
		NodeName:    "A",
		CsrDer:      []byte("csr"),
		ProfileName: "TLS Server",
	}))
	if err == nil {
		t.Fatal("IssueLeaf(node error) error = nil, want a Connect error")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event when node fails)", len(st.Audit()), before)
	}
}

func TestRevokeCertificate_NodeError_MappedNoAudit(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{err: errors.New("node refused")}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.RevokeCertificate(ctx, connect.NewRequest(&fleetv1.RevokeCertificateRequest{
		NodeName:   "A",
		SerialHex:  "01",
		ReasonCode: 1,
	}))
	if err == nil {
		t.Fatal("RevokeCertificate(node error) error = nil, want a Connect error")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event when node fails)", len(st.Audit()), before)
	}
}
