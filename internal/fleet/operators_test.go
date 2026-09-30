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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/operatorca"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

func operatorsStore() store.Store {
	return memory.New([]store.Node{
		{Name: "opca", Endpoint: "opca.acme.com:4443", Role: "root"},
	})
}

// denylistStore is the in-memory store with a working denylist, standing in
// for Postgres.
type denylistStore struct {
	*memory.Store
	entries []store.DenylistEntry
}

func (d *denylistStore) OperatorDenylist(context.Context) ([]store.DenylistEntry, error) {
	return d.entries, nil
}

func (d *denylistStore) AddOperatorDenylistEntry(_ context.Context, e store.DenylistEntry) (bool, error) {
	d.entries = append(d.entries, e)
	return true, nil
}

func testOperatorCA(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Operator CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return ca
}

// withOperatorTrust wires a config-file operator CA over ot into svc.
func withOperatorTrust(t *testing.T, svc *Service, ot store.OperatorTrust, kind operatorca.Kind, ca *x509.Certificate) *Service {
	t.Helper()
	var anchors []operatorca.Anchor
	if ca != nil {
		anchors = []operatorca.Anchor{{Cert: ca, SHA256: operatorca.Fingerprint(ca), State: store.OperatorCAActive, FromConfig: true, CRLSource: store.CRLSourceNone}}
	}
	rev := operatorca.NewRevocations(operatorca.RevocationOptions{Store: ot})
	trust, err := operatorca.NewTrustStore(context.Background(), operatorca.Source{Kind: kind, File: anchors}, ot, rev, &tls.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rev.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	return svc.WithOperatorTrust(trust, rev)
}

func noDial(t *testing.T) func(store.Node) (NodeConn, error) {
	return func(n store.Node) (NodeConn, error) {
		t.Errorf("dialled node %s", n.Name)
		return nil, errors.New("no dial")
	}
}

// Revoking puts the serial on the manager's denylist under the operator CA,
// dials no node, warns that the CA itself isn't revoked, and audits.
func TestRevokeOperatorCredential_WritesTheDenylist(t *testing.T) {
	ds := &denylistStore{Store: memory.New(nil)}
	ca := testOperatorCA(t)
	svc := withOperatorTrust(t, New(ds, noDial(t)), ds, operatorca.KindFile, ca)

	resp, err := svc.RevokeOperatorCredential(operatorCtx("admin@example.org", authz.LevelAdmin),
		connect.NewRequest(&fleetv1.RevokeOperatorCredentialRequest{SerialHex: "0A:1B", ReasonCode: 4, Note: "left"}))
	if err != nil {
		t.Fatalf("RevokeOperatorCredential = %v", err)
	}
	fp := operatorca.Fingerprint(ca)
	if len(ds.entries) != 1 || ds.entries[0].IssuerSHA256 != fp || ds.entries[0].SerialHex != "a1b" ||
		ds.entries[0].Reason != 4 || ds.entries[0].Note != "left" || ds.entries[0].RevokedByCN != "admin@example.org" {
		t.Fatalf("denylist = %+v", ds.entries)
	}
	if resp.Msg.GetIssuerSha256() != fp || resp.Msg.GetSerialHex() != "a1b" || len(resp.Msg.GetWarnings()) != 1 || resp.Msg.GetRevokedAt() == "" {
		t.Fatalf("response = %+v", resp.Msg)
	}
	audit := ds.Audit()
	if len(audit) != 1 || audit[0].Kind != "operator-revoked" {
		t.Fatalf("audit = %+v", audit)
	}
}

func TestRevokeOperatorCredential_NeedsPostgres(t *testing.T) {
	st := memory.New(nil)
	svc := withOperatorTrust(t, New(st, noDial(t)), st, operatorca.KindFile, testOperatorCA(t))
	_, err := svc.RevokeOperatorCredential(operatorCtx("admin@example.org", authz.LevelAdmin),
		connect.NewRequest(&fleetv1.RevokeOperatorCredentialRequest{SerialHex: "0a1b"}))
	if code, _ := apperr.Code(err); code != apperr.CodeUnavailable {
		t.Fatalf("error = %v, want 1603", err)
	}
}

func TestRevokeOperatorCredential_NoOperatorCA(t *testing.T) {
	svc := New(operatorsStore(), noDial(t))
	_, err := svc.RevokeOperatorCredential(operatorCtx("admin@example.org", authz.LevelAdmin),
		connect.NewRequest(&fleetv1.RevokeOperatorCredentialRequest{SerialHex: "0a1b"}))
	if code, _ := apperr.Code(err); code != apperr.CodeOperatorCAUnconfigured {
		t.Fatalf("error = %v, want 1400", err)
	}
}

func TestRevokeOperatorCredential_ViewerDenied(t *testing.T) {
	svc := New(operatorsStore(), noDial(t))
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.RevokeOperatorCredential(ctx, connect.NewRequest(&fleetv1.RevokeOperatorCredentialRequest{SerialHex: "0a1b"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

// Listing works with any operator CA source, with no operator_ca_node, and
// reports the denylist.
func TestListOperatorCredentials_OperatorReadable(t *testing.T) {
	ds := &denylistStore{Store: memory.New(nil)}
	ca := testOperatorCA(t)
	fp := operatorca.Fingerprint(ca)
	ds.AddOperatorCredential(store.OperatorCredential{CommonName: "a@example.org", SerialHex: "1", Level: "viewer", NotAfter: "t", IssuerSHA256: fp, Kind: store.OperatorCredentialRecorded, Email: "a@example.org"})
	ds.AddOperatorCredential(store.OperatorCredential{CommonName: "b@example.org", SerialHex: "2", Level: "admin", NotAfter: "t", Kind: store.OperatorCredentialLegacyNode})
	svc := withOperatorTrust(t, New(ds, noDial(t)), ds, operatorca.KindFile, ca)
	if _, err := svc.RevokeOperatorCredential(operatorCtx("admin@example.org", authz.LevelAdmin),
		connect.NewRequest(&fleetv1.RevokeOperatorCredentialRequest{SerialHex: "1"})); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.ListOperatorCredentials(operatorCtx("op@example.org", authz.LevelOperator), connect.NewRequest(&fleetv1.ListOperatorCredentialsRequest{}))
	if err != nil {
		t.Fatalf("ListOperatorCredentials = %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 2 {
		t.Fatalf("items = %+v", items)
	}
	if a := items[0]; !a.GetDenylisted() || !a.GetRevoked() || a.GetIssuerSha256() != fp || a.GetKind() != store.OperatorCredentialRecorded || a.GetEmail() != "a@example.org" {
		t.Fatalf("first item = %+v", a)
	}
	if b := items[1]; b.GetKind() != store.OperatorCredentialLegacyNode || b.GetDenylisted() {
		t.Fatalf("legacy item = %+v", b)
	}
}

// With no operator CA source at all the manager says so with the stable code
// the UI branches on, even when the store still holds rows.
func TestListOperatorCredentials_NoOperatorCA_FailedPreconditionCoded(t *testing.T) {
	st := memory.New(nil)
	st.AddOperatorCredential(store.OperatorCredential{CommonName: "a", SerialHex: "01", Level: "viewer", NotAfter: "t"})
	for name, svc := range map[string]*Service{
		"not wired":   New(st, noDial(t)),
		"source none": withOperatorTrust(t, New(st, noDial(t)), st, operatorca.KindNone, nil),
	} {
		resp, err := svc.ListOperatorCredentials(operatorCtx("op@acme.example", authz.LevelOperator), connect.NewRequest(&fleetv1.ListOperatorCredentialsRequest{}))
		requireConnectCode(t, err, connect.CodeFailedPrecondition)
		if resp != nil {
			t.Errorf("%s: resp = %v, want nil alongside the error", name, resp)
		}
		if code, ok := apperr.Code(err); !ok || code != apperr.CodeOperatorCAUnconfigured {
			t.Errorf("%s: apperr code = %d (ok=%v), want %d", name, code, ok, apperr.CodeOperatorCAUnconfigured)
		}
	}
}

func TestListOperatorCredentials_ViewerDenied(t *testing.T) {
	svc := New(operatorsStore(), dialFor(map[string]*fakeConn{}))
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.ListOperatorCredentials(ctx, connect.NewRequest(&fleetv1.ListOperatorCredentialsRequest{}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}
