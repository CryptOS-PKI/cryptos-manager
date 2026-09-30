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

	"github.com/CryptOS-PKI/api/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/bootstrap"
	"github.com/CryptOS-PKI/manager/internal/config"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
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
