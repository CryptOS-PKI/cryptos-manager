package main

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/config"
)

// writeSelfSigned writes a self-signed cert + EC key to dir and returns paths.
func writeSelfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "manager.acme.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatal(err)
	}
	if err := keyOut.Close(); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestWithRecover_PanicBecomes500(t *testing.T) {
	h := withRecover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("store: query failed")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/cryptos.fleet.v1.FleetService/ListNodes", nil)

	// The recover must contain the panic so the request does not crash the server.
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestWithRecover_PassesThroughWhenNoPanic(t *testing.T) {
	h := withRecover(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

// TestBuildTLSConfig_RequestsButDoesNotRequireAClientCert is the core of #68:
// requiring the certificate during the handshake meant a browser without one
// got no response at all -- no landing page, not even a health surface -- so an
// operator could not tell a live service from a dead one before importing a
// certificate. The certificate is still requested and still verified against
// the operator CA when presented; what changed is that its absence is now the
// API's answer to give, not the handshake's.
func TestBuildTLSConfig_RequestsButDoesNotRequireAClientCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir)
	cfg := config.Config{TLSCert: certPath, TLSKey: keyPath, OperatorCAPath: certPath}
	tc, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if tc.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", tc.ClientAuth)
	}
	if tc.ClientCAs == nil {
		t.Error("ClientCAs is nil, want the operator CA pool")
	}
	if len(tc.Certificates) != 1 {
		t.Errorf("Certificates = %d, want 1", len(tc.Certificates))
	}
}

func TestBuildTLSConfig_BadOperatorCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir)
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{TLSCert: certPath, TLSKey: keyPath, OperatorCAPath: junk}
	if _, err := buildTLSConfig(cfg); err == nil {
		t.Fatal("buildTLSConfig with junk CA = nil error, want error")
	}
}

// stubHandler answers with a fixed status and body so routing can be asserted
// without the real SPA or Connect handler.
func stubHandler(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

// TestRootHandler_SPAIsAnonymousAndAPIIsNot pins the split #68 asks for: the web
// surface answers a client with no certificate, and the API does not. The auth
// middleware used to wrap the whole mux, which is why softening the TLS mode on
// its own would have exposed the API to anonymous callers.
func TestRootHandler_SPAIsAnonymousAndAPIIsNot(t *testing.T) {
	h := newRootHandler(
		"/cryptos.fleet.v1.FleetService/",
		stubHandler(http.StatusOK, "api"),
		stubHandler(http.StatusOK, "spa"),
		authz.ClientCertMiddleware,
		nil,
	)

	for _, tc := range []struct {
		name     string
		target   string
		want     int
		wantBody string
	}{
		{"spa root", "/", http.StatusOK, "spa"},
		{"spa deep link", "/nodes/pki-root-01", http.StatusOK, "spa"},
		{"api", "/cryptos.fleet.v1.FleetService/WhoAmI", http.StatusUnauthorized, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			// No TLS on the request: a client that presented no certificate.
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.target, nil))

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.want, rec.Body.String())
			}
			if tc.wantBody != "" && rec.Body.String() != tc.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

// TestHTTPSRedirectHandler covers the port 80 listener (#70). The redirect
// target is the *public* HTTPS port, which is not the port the manager listens
// on: the container serves 8443 internally and is published on 443, so
// redirecting to the listener's own port would send the browser somewhere it
// cannot reach.
func TestHTTPSRedirectHandler(t *testing.T) {
	for _, tc := range []struct {
		name       string
		publicPort string
		method     string
		host       string
		target     string
		want       string
	}{
		{"bare host", "", http.MethodGet, "fm.acme.example", "/", "https://fm.acme.example/"},
		{"strips the http port", "", http.MethodGet, "fm.acme.example:80", "/", "https://fm.acme.example/"},
		{
			"container published on 80 redirects to 443, not 8443",
			"", http.MethodGet, "fm.acme.example", "/nodes", "https://fm.acme.example/nodes",
		},
		{
			"preserves path and query",
			"", http.MethodGet, "fm.acme.example", "/nodes?role=root&page=2",
			"https://fm.acme.example/nodes?role=root&page=2",
		},
		{
			"honours a non-standard public port",
			"8443", http.MethodGet, "fm.acme.example:8080", "/", "https://fm.acme.example:8443/",
		},
		{
			"explicit 443 is left implicit",
			"443", http.MethodGet, "fm.acme.example", "/", "https://fm.acme.example/",
		},
		{"non-GET is redirected too", "", http.MethodPost, "fm.acme.example", "/api", "https://fm.acme.example/api"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()

			httpsRedirectHandler(tc.publicPort).ServeHTTP(rec, req)

			// Temporary rather than permanent: a browser caches a 301 or 308
			// for the origin more or less forever, and that is painful to undo
			// if the deployment ever needs to serve something on 80.
			if rec.Code != http.StatusTemporaryRedirect {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusTemporaryRedirect)
			}
			if got := rec.Header().Get("Location"); got != tc.want {
				t.Errorf("Location = %q, want %q", got, tc.want)
			}
		})
	}
}

// A request with no Host header has nowhere to redirect to, and guessing would
// send the client somewhere arbitrary.
func TestHTTPSRedirectHandler_NoHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = ""
	rec := httptest.NewRecorder()

	httpsRedirectHandler("").ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
