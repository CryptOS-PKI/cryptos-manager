package operatorca

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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/config"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// serverTLS is a base TLS config with a server certificate for 127.0.0.1,
// and a pool that trusts it.
func serverTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	ca := newCA(t, caOpts{cn: "Example Server CA", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(24 * time.Hour)})
	key := newKey(t, keyP256)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}, pool
}

// liveCA is an operator CA valid around the real clock, for handshakes.
func liveCA(t *testing.T, cn string) testCA {
	t.Helper()
	return newCA(t, caOpts{cn: cn, notBefore: time.Now().Add(-time.Hour)})
}

func liveLeaf(t *testing.T, ca testCA, o leafOpts) tls.Certificate {
	t.Helper()
	key := newKey(t, keyP384)
	o.key = key
	o.notBefore = time.Now().Add(-time.Hour)
	o.notAfter = time.Now().Add(24 * time.Hour)
	cert := ca.leaf(t, o)
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
}

func registeredRow(ca testCA, state string) store.OperatorCA {
	return store.OperatorCA{SHA256: Fingerprint(ca.cert), CertDER: ca.cert.Raw, State: state, CRLSource: store.CRLSourceNone, OCSPMode: store.OCSPModeOff}
}

type trustFixture struct {
	st    *fakeTrust
	logs  *logSink
	rev   *Revocations
	trust *TrustStore
	srv   *httptest.Server
	roots *x509.CertPool
}

func newTrustFixture(t *testing.T, st *fakeTrust, src Source) trustFixture {
	t.Helper()
	f := trustFixture{st: st, logs: &logSink{}}
	f.rev = NewRevocations(RevocationOptions{Store: st, Policy: PolicySoft, Logf: f.logs.Logf})
	base, roots := serverTLS(t)
	f.roots = roots
	trust, err := NewTrustStore(context.Background(), src, st, f.rev, base, f.logs.Logf)
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}
	f.trust = trust
	if err := f.rev.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	h := authz.ClientCertMiddlewareWith(PeerAuthorizer{Trust: trust, Rev: f.rev})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := authz.FromContext(r.Context())
		_, _ = io.WriteString(w, id.CN+" "+id.IssuerSHA256)
	}))
	f.srv = httptest.NewUnstartedServer(h)
	f.srv.EnableHTTP2 = true
	f.srv.TLS = &tls.Config{GetConfigForClient: trust.GetConfigForClient}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f trustFixture) client(cert *tls.Certificate, cache tls.ClientSessionCache, keepAlive bool) *http.Client {
	cfg := &tls.Config{RootCAs: f.roots, ClientSessionCache: cache, MinVersion: tls.VersionTLS12}
	if cert != nil {
		// Always offer the certificate, as a browser does once the user
		// picks one, even when the server's list of acceptable CAs doesn't
		// name its issuer.
		c := *cert
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &c, nil }
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true, DisableKeepAlives: !keepAlive}}
}

func registered() Source { return Source{Kind: KindRegistered, Policy: PolicySoft} }

func get(t *testing.T, c *http.Client, url string, reused *bool) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if reused != nil {
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { *reused = info.Reused },
		}))
	}
	resp, err := c.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return resp, err
}

// Registering an operator CA makes its certificates work on the next
// handshake, with no restart.
func TestTrustStore_RegistrationIsTrustedWithoutARestart(t *testing.T) {
	st := newFakeTrust()
	f := newTrustFixture(t, st, registered())
	ca := liveCA(t, "Example Operator CA")
	leaf := liveLeaf(t, ca, leafOpts{})

	if _, err := get(t, f.client(&leaf, nil, false), f.srv.URL, nil); err == nil {
		t.Fatal("a certificate from an unregistered CA completed the handshake")
	}
	if err := st.AddOperatorCA(context.Background(), registeredRow(ca, store.OperatorCAActive)); err != nil {
		t.Fatal(err)
	}
	if err := f.trust.Rebuild(context.Background()); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	resp, err := get(t, f.client(&leaf, nil, false), f.srv.URL, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("after registering: %v, %v", resp, err)
	}
	if f.logs.count(ColonFingerprint(ca.cert.Raw)) == 0 {
		t.Fatal("the new anchor's fingerprint was not logged")
	}
}

// A certificate from an unknown CA fails the handshake, and so does one
// with the level extension marked critical: Go's verifier refuses any
// unhandled critical extension, which is why the level must be non-critical.
func TestTrustStore_HandshakeRefusals(t *testing.T) {
	st := newFakeTrust()
	ca := liveCA(t, "Example Operator CA")
	if err := st.AddOperatorCA(context.Background(), registeredRow(ca, store.OperatorCAActive)); err != nil {
		t.Fatal(err)
	}
	f := newTrustFixture(t, st, registered())

	good := liveLeaf(t, ca, leafOpts{})
	if resp, err := get(t, f.client(&good, nil, false), f.srv.URL, nil); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("good certificate: %v, %v", resp, err)
	}
	unknown := liveLeaf(t, liveCA(t, "Example Unknown CA"), leafOpts{})
	if _, err := get(t, f.client(&unknown, nil, false), f.srv.URL, nil); err == nil {
		t.Fatal("a certificate from an unknown CA completed the handshake")
	}
	critical := liveLeaf(t, ca, leafOpts{levelCritical: true})
	if _, err := get(t, f.client(&critical, nil, false), f.srv.URL, nil); err == nil {
		t.Fatal("a certificate with a critical level extension completed the handshake")
	}
}

// An HTTP/2 connection that authenticated under a CA is refused on its next
// request once that CA is retired: trust is re-checked per request, not per
// handshake.
func TestTrustStore_RetiredCAIsRefusedOnTheNextRequest(t *testing.T) {
	st := newFakeTrust()
	x := liveCA(t, "Example Operator CA X")
	y := liveCA(t, "Example Operator CA Y")
	ctx := context.Background()
	if err := st.AddOperatorCA(ctx, registeredRow(y, store.OperatorCAActive)); err != nil {
		t.Fatal(err)
	}
	if err := st.AddOperatorCA(ctx, registeredRow(x, store.OperatorCARetiring)); err != nil {
		t.Fatal(err)
	}
	f := newTrustFixture(t, st, registered())
	leaf := liveLeaf(t, x, leafOpts{})
	c := f.client(&leaf, nil, true)

	var reused bool
	resp, err := get(t, c, f.srv.URL, &reused)
	if err != nil || resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("first request: %v, %v", resp, err)
	}
	if err := st.SetOperatorCAState(ctx, Fingerprint(x.cert), store.OperatorCARetired, "retired", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.trust.Rebuild(ctx); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	resp, err = get(t, c, f.srv.URL, &reused)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if !reused {
		t.Fatal("the second request used a new connection; the test needs the same one")
	}
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("x-cryptos-error-reason") != "NOT_CHAINED" {
		t.Fatalf("second request = %d %s, want 403 NOT_CHAINED", resp.StatusCode, resp.Header.Get("x-cryptos-error-reason"))
	}
}

// A session ticket from one trust generation doesn't resume under the next,
// so a trust change also invalidates resumption.
func TestTrustStore_TicketsDontResumeAcrossGenerations(t *testing.T) {
	st := newFakeTrust()
	ca := liveCA(t, "Example Operator CA")
	ctx := context.Background()
	if err := st.AddOperatorCA(ctx, registeredRow(ca, store.OperatorCAActive)); err != nil {
		t.Fatal(err)
	}
	f := newTrustFixture(t, st, registered())
	leaf := liveLeaf(t, ca, leafOpts{})
	c := f.client(&leaf, tls.NewLRUClientSessionCache(8), false)

	resumed := func() bool {
		t.Helper()
		resp, err := get(t, c, f.srv.URL, nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("request: %v, %v", resp, err)
		}
		return resp.TLS.DidResume
	}
	if resumed() {
		t.Fatal("the first connection resumed")
	}
	if !resumed() {
		t.Fatal("the second connection in the same generation didn't resume; the test can't tell anything")
	}
	if err := st.AddOperatorCA(ctx, registeredRow(liveCA(t, "Example Operator CA 2"), store.OperatorCARetiring)); err != nil {
		t.Fatal(err)
	}
	if err := f.trust.Rebuild(ctx); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if resumed() {
		t.Fatal("a ticket from the previous generation resumed")
	}
}

// A denylist entry refuses the certificate on its next request over the
// same connection.
func TestPeerAuthorizer_DenylistRefusesTheNextRequest(t *testing.T) {
	st := newFakeTrust()
	ca := liveCA(t, "Example Operator CA")
	ctx := context.Background()
	if err := st.AddOperatorCA(ctx, registeredRow(ca, store.OperatorCAActive)); err != nil {
		t.Fatal(err)
	}
	f := newTrustFixture(t, st, registered())
	leaf := liveLeaf(t, ca, leafOpts{})
	c := f.client(&leaf, nil, true)
	if resp, err := get(t, c, f.srv.URL, nil); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("first request: %v, %v", resp, err)
	}
	if err := f.rev.Deny(ctx, store.DenylistEntry{IssuerSHA256: Fingerprint(ca.cert), SerialHex: SerialKey(leaf.Leaf.SerialNumber)}); err != nil {
		t.Fatal(err)
	}
	resp, err := get(t, c, f.srv.URL, nil)
	if err != nil || resp.StatusCode != http.StatusForbidden || resp.Header.Get("x-cryptos-error-reason") != "REVOKED" {
		t.Fatalf("after denying: %v, %v", resp, err)
	}
}

func TestVerifyPeer_CachesPerLeafAndGeneration(t *testing.T) {
	st := newFakeTrust()
	ca := newCA(t, caOpts{notBefore: time.Now().Add(-time.Hour)})
	ctx := context.Background()
	if err := st.AddOperatorCA(ctx, registeredRow(ca, store.OperatorCAActive)); err != nil {
		t.Fatal(err)
	}
	rev := NewRevocations(RevocationOptions{Store: st})
	base, _ := serverTLS(t)
	trust, err := NewTrustStore(ctx, registered(), st, rev, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf := liveLeaf(t, ca, leafOpts{}).Leaf
	for range 3 {
		a, err := trust.VerifyPeer(leaf, nil)
		if err != nil || a.SHA256 != Fingerprint(ca.cert) {
			t.Fatalf("VerifyPeer = %+v, %v", a, err)
		}
	}
	if got := trust.verifications.Load(); got != 1 {
		t.Fatalf("%d chain verifications for one leaf, want 1", got)
	}
	if err := st.AddOperatorCA(ctx, registeredRow(newCA(t, caOpts{cn: "Example Other CA"}), store.OperatorCARetiring)); err != nil {
		t.Fatal(err)
	}
	if err := trust.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.VerifyPeer(leaf, nil); err != nil {
		t.Fatal(err)
	}
	if got := trust.verifications.Load(); got != 2 {
		t.Fatalf("%d verifications after a new generation, want 2", got)
	}
}

func writePEM(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	var b []byte
	for _, c := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	path := filepath.Join(t.TempDir(), "operator-ca.pem")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolve_Kinds(t *testing.T) {
	ctx := context.Background()
	ca := newCA(t, caOpts{})
	path := writePEM(t, ca.cert)
	cases := map[string]struct {
		cfg  config.Config
		want Kind
	}{
		"bare with Postgres is registered": {config.Config{DatabaseURL: "postgres://db/manager", FirstRun: config.FirstRunAuto}, KindRegistered},
		"no Postgres is none":              {config.Config{FirstRun: config.FirstRunAuto}, KindNone},
		"first run disabled is none":       {config.Config{DatabaseURL: "postgres://db/manager", FirstRun: config.FirstRunDisabled}, KindNone},
		"authBypass is dev":                {config.Config{AuthBypass: true, OperatorCAPath: path}, KindDev},
		"operatorCAPath is file":           {config.Config{OperatorCAPath: path, FirstRun: config.FirstRunDisabled}, KindFile},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			src, err := Resolve(ctx, c.cfg, newFakeTrust(), nil, nil)
			if err != nil || src.Kind != c.want {
				t.Fatalf("Resolve = %v, %v; want %v", src.Kind, err, c.want)
			}
		})
	}
}

// The config file wins over the database: registered rows are ignored while
// operatorCAPath is set, and that is logged once.
func TestResolve_FileWinsOverRegisteredRows(t *testing.T) {
	ctx := context.Background()
	fileCA, rowCA := newCA(t, caOpts{cn: "Example File CA"}), newCA(t, caOpts{cn: "Example Row CA"})
	st := newFakeTrust()
	if err := st.AddOperatorCA(ctx, registeredRow(rowCA, store.OperatorCAActive)); err != nil {
		t.Fatal(err)
	}
	path := writePEM(t, fileCA.cert)
	logs := &logSink{}
	cfg := config.Config{OperatorCAPath: path, DatabaseURL: "postgres://db/manager", OperatorOCSP: config.OCSPConfig{Mode: config.OCSPModeURL, URL: "http://ocsp.example.org/"},
		OperatorCRL: []config.CRLSource{{URL: "http://pki.example.org/op.crl"}}}
	src, err := Resolve(ctx, cfg, st, nil, logs.Logf)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if src.Kind != KindFile || len(src.File) != 1 || src.File[0].SHA256 != Fingerprint(fileCA.cert) {
		t.Fatalf("source = %+v, want the file CA only", src)
	}
	if a := src.File[0]; !a.FromConfig || !a.HasCRL() || a.OCSPMode != store.OCSPModeURL || a.OCSPURL != "http://ocsp.example.org/" {
		t.Fatalf("file anchor = %+v", a)
	}
	if len(src.CRLTargets) != 1 || src.CRLTargets[0].Location != "http://pki.example.org/op.crl" {
		t.Fatalf("CRL targets = %+v", src.CRLTargets)
	}
	if n := logs.count("1 registered operator CA(s) in the database are ignored while operatorCAPath is set"); n != 1 {
		t.Fatalf("precedence logged %d times, want once: %q", n, logs.lines)
	}

	f := newTrustFixture(t, st, src)
	if anchors := f.trust.Anchors(); len(anchors) != 1 || anchors[0].SHA256 != Fingerprint(fileCA.cert) {
		t.Fatalf("trusted anchors = %+v, want the file CA only", anchors)
	}
}

// The config file can't name a CryptOS node's CA, by certificate or key.
func TestResolve_FileRefusesANodeCA(t *testing.T) {
	node := newCA(t, caOpts{cn: "Example Workload Intermediate"})
	sameKey := newCA(t, caOpts{cn: "Example Workload Intermediate G2", key: node.key})
	for name, anchor := range map[string]*x509.Certificate{"same cert": node.cert, "same key": sameKey.cert} {
		_, err := Resolve(context.Background(), config.Config{OperatorCAPath: writePEM(t, anchor)}, newFakeTrust(), []*x509.Certificate{node.cert}, nil)
		if err == nil || !strings.Contains(err.Error(), "CryptOS node") {
			t.Fatalf("%s: Resolve = %v, want the node CA refusal", name, err)
		}
	}
}

func TestResolve_FileWithoutCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(path, []byte("nothing here"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(context.Background(), config.Config{OperatorCAPath: path}, newFakeTrust(), nil, nil); err == nil {
		t.Fatal("Resolve accepted an operatorCAPath with no certificates")
	}
}

// hard can't be used with an upload CRL source: an expired upload would lock
// out the only admins able to upload the next one.
func TestResolve_HardRefusesAnUploadRow(t *testing.T) {
	ctx := context.Background()
	st := newFakeTrust()
	row := registeredRow(newCA(t, caOpts{}), store.OperatorCAActive)
	row.CRLSource = store.CRLSourceUpload
	if err := st.AddOperatorCA(ctx, row); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DatabaseURL: "postgres://db/manager", FirstRun: config.FirstRunAuto, OperatorRevocationPolicy: config.RevocationPolicyHard}
	if _, err := Resolve(ctx, cfg, st, nil, nil); err == nil || !strings.Contains(err.Error(), "upload") {
		t.Fatalf("Resolve = %v, want the hard-with-upload refusal", err)
	}
	cfg.OperatorRevocationPolicy = config.RevocationPolicySoft
	if _, err := Resolve(ctx, cfg, st, nil, nil); err != nil {
		t.Fatalf("Resolve (soft) = %v", err)
	}
}

// Every start logs each trusted anchor's subject and fingerprint.
func TestTrustStore_LogsTheAnchorsAtStart(t *testing.T) {
	ca := newCA(t, caOpts{})
	st := newFakeTrust()
	logs := &logSink{}
	src := Source{Kind: KindFile, File: []Anchor{{Cert: ca.cert, SHA256: Fingerprint(ca.cert), FromConfig: true, State: store.OperatorCAActive}}}
	base, _ := serverTLS(t)
	if _, err := NewTrustStore(context.Background(), src, st, NewRevocations(RevocationOptions{Store: st}), base, logs.Logf); err != nil {
		t.Fatal(err)
	}
	if logs.count("Example Operator CA") == 0 || logs.count(ColonFingerprint(ca.cert.Raw)) == 0 {
		t.Fatalf("logs = %q, want the anchor's subject and SHA-256", logs.lines)
	}

	none := &logSink{}
	if _, err := NewTrustStore(context.Background(), Source{Kind: KindNone}, st, NewRevocations(RevocationOptions{Store: st}), base, none.Logf); err != nil {
		t.Fatal(err)
	}
	if none.count("no operator CA is trusted") == 0 {
		t.Fatalf("logs = %q, want the no-anchor warning", none.lines)
	}
}
