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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

func adminIdentity(cert *x509.Certificate, ca testCA) authz.Identity {
	id, err := authz.IdentityFromCertificate(cert)
	if err != nil {
		panic(err)
	}
	id.IssuerSHA256 = operatorca.Fingerprint(ca.cert)
	id.Via = authz.ViaWeb
	return id
}

// serveAs sends one request through the real client-certificate middleware
// with the latch hook, as the certificate's holder.
func serveAs(h *harness, cert *x509.Certificate) int {
	mw := authz.ClientCertMiddlewareWith(operatorca.PeerAuthorizer{Trust: h.trust, Rev: h.rev}, h.svc.Latch().Observe)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest(http.MethodPost, "/cryptos.fleet.v1.FleetService/WhoAmI", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)
	return rec.Code
}

func TestLatch_FirstAdminRequestClosesFirstRun(t *testing.T) {
	h, secret, ca := registered(t)
	_ = secret
	admin := ca.leaf(t, leafOpts{cn: "Admin@Example.org"})
	if code := serveAs(h, admin); code != http.StatusOK {
		t.Fatalf("the admin request got %d", code)
	}
	st, _ := h.st.BootstrapState(h.ctx)
	if !st.Closed() || st.ClosedBySerial != operatorca.SerialKey(admin.SerialNumber) || st.ClosedByCN != "Admin@Example.org" ||
		st.ClosedByIssuerSHA256 != operatorca.Fingerprint(ca.cert) {
		t.Fatalf("latch = %+v", st)
	}
	if len(h.st.tokenHashes()) != 0 {
		t.Fatal("tokens survived")
	}
	creds, _ := h.st.FirstAdminCredentials(h.ctx)
	if len(creds) != 1 || creds[0].SerialHex != operatorca.SerialKey(admin.SerialNumber) || creds[0].Email != "admin@example.org" {
		t.Fatalf("path B without a pre-flight wasn't recorded as first_admin: %+v", creds)
	}
	if h.logs.count("first run CLOSED by Admin@Example.org") != 1 {
		t.Error("the latch closing wasn't logged")
	}
	rows := h.auditKinds(KindBootstrapClosed)
	if len(rows) != 1 || rows[0].ActorKind != authz.ActorCert || rows[0].ActorCN != "Admin@Example.org" {
		t.Fatalf("latch audit = %+v", rows)
	}
	if h.state().GetState() != fleetv1.BootstrapState_BOOTSTRAP_STATE_CLOSED {
		t.Fatal("GetBootstrapState isn't CLOSED")
	}
}

func TestLatch_PreflightRecordIsKept(t *testing.T) {
	h, secret, ca := registered(t)
	admin := ca.leaf(t, leafOpts{})
	if _, err := h.submit(secret, &fleetv1.SubmitFirstAdminCertificateRequest{CertDer: admin.Raw, FullName: "Ada Example"}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	serveAs(h, admin)
	creds, _ := h.st.FirstAdminCredentials(h.ctx)
	if len(creds) != 1 || creds[0].FullName != "Ada Example" {
		t.Fatalf("the latch overwrote the pre-flight record: %+v", creds)
	}
}

func TestLatch_ViewerOperatorAndDenylistedAdminDontCloseIt(t *testing.T) {
	h, _, ca := registered(t)
	for _, level := range []string{"viewer", "operator"} {
		if code := serveAs(h, ca.leaf(t, leafOpts{level: level})); code != http.StatusOK {
			t.Fatalf("%s request got %d", level, code)
		}
	}
	denied := ca.leaf(t, leafOpts{})
	if err := h.rev.Deny(h.ctx, store.DenylistEntry{IssuerSHA256: operatorca.Fingerprint(ca.cert), SerialHex: operatorca.SerialKey(denied.SerialNumber)}); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if code := serveAs(h, denied); code != http.StatusForbidden {
		t.Fatalf("a denylisted admin got %d, want 403", code)
	}
	if st, _ := h.st.BootstrapState(h.ctx); st.Closed() {
		t.Fatalf("the latch closed: %+v", st)
	}
}

func TestLatch_StaysClosedWhenEveryAdminIsDeniedOrTheCARetired(t *testing.T) {
	h, _, ca := registered(t)
	admin := ca.leaf(t, leafOpts{})
	serveAs(h, admin)
	if err := h.rev.Deny(h.ctx, store.DenylistEntry{IssuerSHA256: operatorca.Fingerprint(ca.cert), SerialHex: operatorca.SerialKey(admin.SerialNumber)}); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if err := h.st.SetOperatorCAState(h.ctx, operatorca.Fingerprint(ca.cert), store.OperatorCARetired, "test", testNow); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if err := h.trust.Rebuild(h.ctx); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	restarted, err := New(h.ctx, Options{Store: h.st, Audit: h.audit, Trust: h.trust, Rev: h.rev, Now: h.clock.Now, Logf: h.logs.Logf,
		PrintBanner: func([]string) { t.Error("a banner was printed after the latch closed") }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := restarted.Start(h.ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if st, _ := h.st.BootstrapState(h.ctx); !st.Closed() {
		t.Fatal("the latch reopened")
	}
	if h.logs.count("no operator CA is trusted and first run is closed") == 0 {
		t.Error("a closed first run with nothing trusted wasn't logged")
	}
}

func TestLatch_FileSourceClosesItToo(t *testing.T) {
	st := newFakeStore()
	ca := newCA(t, "Example Operator CA")
	rev := operatorca.NewRevocations(operatorca.RevocationOptions{Store: st})
	trust, err := operatorca.NewTrustStore(t.Context(), operatorca.Source{Kind: operatorca.KindFile,
		File: []operatorca.Anchor{{Cert: ca.cert, SHA256: operatorca.Fingerprint(ca.cert), State: store.OperatorCAActive, FromConfig: true}}},
		st, rev, &tls.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(o *Options) { o.Store, o.Trust, o.Rev = st, trust, rev })
	h.st, h.trust, h.rev = st, trust, rev
	serveAs(h, ca.leaf(t, leafOpts{}))
	if s, _ := st.BootstrapState(h.ctx); !s.Closed() {
		t.Fatal("the first admin request in the file source didn't close the latch")
	}
	if h.bannerCount() != 0 {
		t.Fatal("the file source printed a banner")
	}
}

func TestLatch_NilIsANoOp(t *testing.T) {
	var l *Latch
	l.Observe(t.Context(), authz.Identity{Level: authz.LevelAdmin}, nil)
}
