package main

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
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos-manager/internal/config"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/memory"
)

func TestWithCORS_AllowsTheBootstrapSessionHeader(t *testing.T) {
	h := withCORS([]string{"https://ui.example.org"}, stubHandler(http.StatusOK, "x"))
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://ui.example.org")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), bootstrap.SessionHeader) {
		t.Fatalf("Access-Control-Allow-Headers = %q, want %s", rec.Header().Get("Access-Control-Allow-Headers"), bootstrap.SessionHeader)
	}
}

// testBootstrap builds the first-run service the way main does, over the
// in-memory store (no Postgres, so first run is unavailable).
func testBootstrap(t *testing.T) (*bootstrap.Service, func(*http.ServeMux)) {
	t.Helper()
	st := memory.New(nil)
	base, err := buildTLSConfig(context.Background(), config.Config{}, nil, t.Logf)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	trust, err := setupOperatorTrust(context.Background(), config.Config{}, st, st, base, t.Logf)
	if err != nil {
		t.Fatalf("setupOperatorTrust: %v", err)
	}
	svc, mount, err := setupBootstrap(context.Background(), config.Config{}, st, nil, trust, base, t.Logf)
	if err != nil {
		t.Fatalf("setupBootstrap: %v", err)
	}
	return svc, mount
}

// BootstrapService is mounted outside the certificate middleware, answers
// over TLS without a client certificate, and refuses plaintext.
func TestBootstrapMount_TLSOnlyAndOutsideTheCertificateMiddleware(t *testing.T) {
	_, mount := testBootstrap(t)
	h := newRootHandler("/cryptos.fleet.v1.FleetService/", stubHandler(http.StatusOK, "api"), stubHandler(http.StatusOK, "spa"),
		authz.ClientCertMiddleware, nil, mount)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, fleetv1connect.BootstrapServiceGetBootstrapStateProcedure, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{HandshakeComplete: true}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "BOOTSTRAP_STATE_UNAVAILABLE") {
		t.Fatalf("GetBootstrapState over TLS with no client certificate = %d %s", rec.Code, rec.Body)
	}

	req = httptest.NewRequest(http.MethodPost, fleetv1connect.BootstrapServiceGetBootstrapStateProcedure, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get(apperr.MetadataKey) != "1603" {
		t.Fatalf("GetBootstrapState over plaintext = %d (code %q), want 403 with 1603", rec.Code, rec.Header().Get(apperr.MetadataKey))
	}
}

// A bootstrap session secret is not a credential anywhere else: the API, the
// MCP endpoint and the OAuth consent all still want a certificate or a key.
func TestSessionSecretOpensNothingElse(t *testing.T) {
	_, boot := testBootstrap(t)
	mcp, err := testMCPMount(t, livePool, noRevocations{})
	if err != nil {
		t.Fatalf("mcpMount: %v", err)
	}
	h := newRootHandler("/cryptos.fleet.v1.FleetService/", stubHandler(http.StatusOK, "api"), stubHandler(http.StatusOK, "spa"),
		authz.ClientCertMiddleware, nil, mcp, boot)
	for _, target := range []string{"/cryptos.fleet.v1.FleetService/CreateMcpKey", "/mcp", "/oauth2/consent/some-id"} {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{}`))
		req.Header.Set(bootstrap.SessionHeader, "fos_bsess_ABCDEFGHJKMNPQRSTVWXYZ0123456789ABCDEFGHJKMNPQRSTV")
		req.TLS = &tls.ConnectionState{HandshakeComplete: true}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with only a session secret = %d, want 401", target, rec.Code)
		}
	}
}

// Registration probes a url-mode OCSP responder through the running
// revocation engine's OCSP client; a responder that doesn't answer is 1605
// OCSP_UNREACHABLE.
func TestOCSPProbe_UsesTheRevocationEnginesClient(t *testing.T) {
	if ocspProbe(operatorca.NewRevocations(operatorca.RevocationOptions{Store: memory.New(nil)})) != nil {
		t.Fatal("a probe was built without an OCSP client")
	}
	probe := ocspProbe(operatorca.NewRevocations(operatorca.RevocationOptions{Store: memory.New(nil), OCSPFetcher: operatorca.NewOCSPFetcher()}))
	if probe == nil {
		t.Fatal("no probe with an OCSP client")
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	_, ca, _ := writeOperatorCA(t, t.TempDir())
	_, err := probe(context.Background(), ca, dead.URL)
	if r, ok := apperr.ReasonOf(err); !ok || r != fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE {
		t.Fatalf("probe of a dead responder = %v, want 1605 OCSP_UNREACHABLE", err)
	}
}

// BootstrapService never joins the plaintext listener authBypass serves,
// even if a mount for it were built; on the TLS server it is there.
func TestRootMounts_BootstrapOnlyOnTheTLSServer(t *testing.T) {
	_, boot := testBootstrap(t)
	serve := func(bypass bool) string {
		mounts := rootMounts(config.Config{AuthBypass: bypass}, nil, boot)
		h := newRootHandler("/cryptos.fleet.v1.FleetService/", stubHandler(http.StatusOK, "api"), stubHandler(http.StatusOK, "spa"),
			authz.BypassMiddleware, nil, mounts...)
		req := httptest.NewRequest(http.MethodPost, fleetv1connect.BootstrapServiceGetBootstrapStateProcedure, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	if got := serve(true); got != "spa" {
		t.Fatalf("under authBypass the bootstrap path reached %q, want the SPA", got)
	}
	if got := serve(false); got == "spa" {
		t.Fatal("on the TLS server the bootstrap path didn't reach BootstrapService")
	}
}

// The HTTP redirect listener, the only other plaintext server, never
// reaches BootstrapService: a POST gets 405 and nothing else is served.
func TestRedirectListener_NeverServesBootstrap(t *testing.T) {
	h := httpsRedirectHandler("443")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://fleet.example.org"+fleetv1connect.BootstrapServiceStartBootstrapSessionProcedure, strings.NewReader(`{"token":"x"}`)))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST to the redirect listener = %d, want 405", rec.Code)
	}
}
