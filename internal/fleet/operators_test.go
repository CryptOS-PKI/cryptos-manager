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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// operatorCertDER builds a self-signed DER cert with the given serial and
// not_after, standing in for what the operator-CA node returns from IssueLeaf.
func operatorCertDER(t *testing.T, serial *big.Int, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "op@acme.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func operatorsStore() store.Store {
	return memory.New([]store.Node{
		{Name: "opca", Endpoint: "opca.acme.com:4443", Role: "root"},
	})
}

func TestIssueOperatorCredential_ViewerDenied_NoDialNoStore(t *testing.T) {
	st := operatorsStore()
	conn := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"opca": conn})).WithOperatorCA("opca")

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.IssueOperatorCredential(ctx, connect.NewRequest(&fleetv1.IssueOperatorCredentialRequest{
		CommonName: "new@acme.example", Level: "operator", CsrDer: []byte("csr"),
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if conn.gotIssueCSR != nil {
		t.Error("operator CA was dialed on a denied request")
	}
	if len(st.OperatorCredentials()) != 0 || len(st.Audit()) != 0 {
		t.Error("denied request wrote a credential or audit event")
	}
}

func TestIssueOperatorCredential_UnknownLevel_InvalidArgument(t *testing.T) {
	svc := New(operatorsStore(), dialFor(map[string]*fakeConn{"opca": {}})).WithOperatorCA("opca")
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.IssueOperatorCredential(ctx, connect.NewRequest(&fleetv1.IssueOperatorCredentialRequest{
		CommonName: "x", Level: "superuser", CsrDer: []byte("csr"),
	}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestIssueOperatorCredential_NoOperatorCAConfigured_FailedPrecondition(t *testing.T) {
	svc := New(operatorsStore(), dialFor(map[string]*fakeConn{"opca": {}})) // no WithOperatorCA
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.IssueOperatorCredential(ctx, connect.NewRequest(&fleetv1.IssueOperatorCredentialRequest{
		CommonName: "x", Level: "admin", CsrDer: []byte("csr"),
	}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
}

func TestIssueOperatorCredential_Admin_RoutesToLevelProfile_RecordsAndAudits(t *testing.T) {
	st := operatorsStore()
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	der := operatorCertDER(t, big.NewInt(0x0a1b), notAfter)
	conn := &fakeConn{issueResp: &cryptosv1.IssueLeafResponse{CertDer: der}}
	svc := New(st, dialFor(map[string]*fakeConn{"opca": conn})).WithOperatorCA("opca")

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.IssueOperatorCredential(ctx, connect.NewRequest(&fleetv1.IssueOperatorCredentialRequest{
		CommonName: "new@acme.example", Level: "admin", CsrDer: []byte("csr-der"),
	}))
	if err != nil {
		t.Fatalf("IssueOperatorCredential(admin) error = %v", err)
	}

	if conn.gotIssueProfile != "operator-admin" {
		t.Errorf("routed to profile %q, want operator-admin", conn.gotIssueProfile)
	}
	if string(conn.gotIssueCSR) != "csr-der" {
		t.Errorf("forwarded CSR %q, want csr-der", conn.gotIssueCSR)
	}
	if !conn.closed {
		t.Error("operator CA connection not closed")
	}

	wantSerial := fmt.Sprintf("%x", big.NewInt(0x0a1b))
	if resp.Msg.GetSerialHex() != wantSerial {
		t.Errorf("response serial = %q, want %q", resp.Msg.GetSerialHex(), wantSerial)
	}
	if string(resp.Msg.GetCertDer()) != string(der) {
		t.Error("response cert der does not match the issued cert")
	}

	creds := st.OperatorCredentials()
	if len(creds) != 1 {
		t.Fatalf("store has %d credentials, want 1", len(creds))
	}
	c := creds[0]
	if c.CommonName != "new@acme.example" || c.Level != "admin" || c.SerialHex != wantSerial || c.Revoked {
		t.Errorf("stored credential = %+v, want CN new@acme.example level admin serial %s not revoked", c, wantSerial)
	}

	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "operator-issued" {
		t.Fatalf("audit = %+v, want one operator-issued event", audit)
	}
	// The audit must name the serial but never leak the CSR/cert bytes.
	if !strings.Contains(audit[0].Summary, wantSerial) {
		t.Errorf("audit summary %q does not name the serial", audit[0].Summary)
	}
	if strings.Contains(audit[0].Summary, "csr-der") || strings.Contains(audit[0].Summary, string(der)) {
		t.Error("audit summary leaks CSR or cert bytes")
	}
}

func TestRevokeOperatorCredential_Admin_RevokesMarksAndAudits(t *testing.T) {
	st := operatorsStore()
	st.AddOperatorCredential(store.OperatorCredential{CommonName: "op@acme.example", SerialHex: "0a1b", Level: "operator", NotAfter: "later"})
	now := time.Now().UTC()
	conn := &fakeConn{revokeResp: &cryptosv1.RevokeCertificateResponse{
		Revocation: &cryptosv1.Revocation{SerialHex: "0a1b", RevokedAt: timestamppb.New(now), ReasonCode: 4},
	}}
	svc := New(st, dialFor(map[string]*fakeConn{"opca": conn})).WithOperatorCA("opca")

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.RevokeOperatorCredential(ctx, connect.NewRequest(&fleetv1.RevokeOperatorCredentialRequest{
		SerialHex: "0a1b", ReasonCode: 4,
	}))
	if err != nil {
		t.Fatalf("RevokeOperatorCredential(admin) error = %v", err)
	}
	if conn.gotRevokeSerial != "0a1b" || conn.gotRevokeReason != 4 {
		t.Errorf("node revoke = (%q,%d), want (0a1b,4)", conn.gotRevokeSerial, conn.gotRevokeReason)
	}
	if resp.Msg.GetRevokedAt() != now.Format(time.RFC3339) {
		t.Errorf("revokedAt = %q, want %q", resp.Msg.GetRevokedAt(), now.Format(time.RFC3339))
	}

	creds := st.OperatorCredentials()
	if len(creds) != 1 || !creds[0].Revoked {
		t.Errorf("store credential not marked revoked: %+v", creds)
	}
	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "operator-revoked" {
		t.Fatalf("audit = %+v, want one operator-revoked event", audit)
	}
}

func TestRevokeOperatorCredential_ViewerDenied(t *testing.T) {
	svc := New(operatorsStore(), dialFor(map[string]*fakeConn{"opca": {}})).WithOperatorCA("opca")
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.RevokeOperatorCredential(ctx, connect.NewRequest(&fleetv1.RevokeOperatorCredentialRequest{SerialHex: "0a1b"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func TestListOperatorCredentials_OperatorReadable(t *testing.T) {
	st := operatorsStore()
	st.AddOperatorCredential(store.OperatorCredential{CommonName: "a", SerialHex: "01", Level: "viewer", NotAfter: "t"})
	st.AddOperatorCredential(store.OperatorCredential{CommonName: "b", SerialHex: "02", Level: "admin", NotAfter: "t", Revoked: true})
	svc := New(st, dialFor(map[string]*fakeConn{})).WithOperatorCA("opca")

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.ListOperatorCredentials(ctx, connect.NewRequest(&fleetv1.ListOperatorCredentialsRequest{}))
	if err != nil {
		t.Fatalf("ListOperatorCredentials(operator) error = %v", err)
	}
	if len(resp.Msg.GetItems()) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(resp.Msg.GetItems()))
	}
}

// An empty list with no operator CA read as "this fleet has no operators" while
// an operator was signed in: the manager can neither list, issue nor revoke
// without one, so it must say so with the stable code the UI branches on,
// even when the store still holds rows from an earlier configuration.
func TestListOperatorCredentials_NoOperatorCA_FailedPreconditionCoded(t *testing.T) {
	st := operatorsStore()
	st.AddOperatorCredential(store.OperatorCredential{CommonName: "a", SerialHex: "01", Level: "viewer", NotAfter: "t"})
	svc := New(st, dialFor(map[string]*fakeConn{}))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.ListOperatorCredentials(ctx, connect.NewRequest(&fleetv1.ListOperatorCredentialsRequest{}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
	if resp != nil {
		t.Errorf("resp = %v, want nil alongside the error", resp)
	}
	if code, ok := apperr.Code(err); !ok || code != apperr.CodeOperatorCAUnconfigured {
		t.Errorf("apperr code = %d (ok=%v), want %d", code, ok, apperr.CodeOperatorCAUnconfigured)
	}
}

// A configured operator-CA name that is missing from the inventory still
// lists: the rows are the manager's own, and reading them dials nothing.
func TestListOperatorCredentials_OperatorCANotInInventory_StillLists(t *testing.T) {
	st := operatorsStore()
	st.AddOperatorCredential(store.OperatorCredential{CommonName: "a", SerialHex: "01", Level: "viewer", NotAfter: "t"})
	svc := New(st, dialFor(map[string]*fakeConn{})).WithOperatorCA("gone")

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.ListOperatorCredentials(ctx, connect.NewRequest(&fleetv1.ListOperatorCredentialsRequest{}))
	if err != nil {
		t.Fatalf("ListOperatorCredentials error = %v", err)
	}
	if len(resp.Msg.GetItems()) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(resp.Msg.GetItems()))
	}
}

func TestListOperatorCredentials_ViewerDenied(t *testing.T) {
	svc := New(operatorsStore(), dialFor(map[string]*fakeConn{}))
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.ListOperatorCredentials(ctx, connect.NewRequest(&fleetv1.ListOperatorCredentialsRequest{}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func TestOperatorProfiles_CarryLevelExtension(t *testing.T) {
	profiles, err := OperatorProfiles()
	if err != nil {
		t.Fatalf("OperatorProfiles() error = %v", err)
	}
	if len(profiles) != 3 {
		t.Fatalf("got %d operator profiles, want 3", len(profiles))
	}
	byName := map[string]store.Profile{}
	for _, p := range profiles {
		byName[p.Name] = p
	}
	for _, level := range []string{"viewer", "operator", "admin"} {
		p, ok := byName["operator-"+level]
		if !ok {
			t.Fatalf("missing profile operator-%s", level)
		}
		cp := &cryptosv1.CertificateProfile{}
		if err := proto.Unmarshal(p.Spec, cp); err != nil {
			t.Fatalf("unmarshal operator-%s: %v", level, err)
		}
		wantOID, wantDER, _ := authz.MarshalLevelExtension(level)
		exts := cp.GetExtraExtensions()
		if len(exts) != 1 || exts[0].GetOid() != wantOID || string(exts[0].GetValue()) != string(wantDER) {
			t.Errorf("operator-%s extension = %+v, want oid %s with the level DER", level, exts, wantOID)
		}
	}
}
