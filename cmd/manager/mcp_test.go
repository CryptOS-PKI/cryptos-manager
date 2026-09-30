package main

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
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/manager/internal/approval"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/fleet"
	"github.com/CryptOS-PKI/manager/internal/mcpauth"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

type noRevocations struct{}

func (noRevocations) RevokedSerials() ([]string, error) { return nil, nil }

func testMCPMount(t *testing.T, roots *x509.CertPool, cache *authz.RevocationCache) (func(*http.ServeMux), error) {
	t.Helper()
	st := memory.New(nil)
	svc := fleet.New(st, nil)
	return mcpMount("https://fleetos.example.org", svc, st, &mcpauth.Keys{Store: st}, &approval.Service{Store: st}, roots, cache, authz.ClientCertMiddleware, "test")
}

// The endpoint is refused outright rather than served without the live
// certificate checks.
func TestMCPMount_RefusesWithoutTheOperatorCAOrRevocation(t *testing.T) {
	if _, err := testMCPMount(t, x509.NewCertPool(), nil); err == nil {
		t.Error("mounted without a revocation cache")
	}
	if _, err := testMCPMount(t, nil, authz.NewRevocationCache(noRevocations{})); err == nil {
		t.Error("mounted without an operator CA pool")
	}
}

func TestRootHandler_MountsMCPAndLogin(t *testing.T) {
	mount, err := testMCPMount(t, x509.NewCertPool(), authz.NewRevocationCache(noRevocations{}))
	if err != nil {
		t.Fatalf("mcpMount: %v", err)
	}
	h := newRootHandler("/cryptos.fleet.v1.FleetService/", stubHandler(http.StatusOK, "api"), stubHandler(http.StatusOK, "spa"),
		authz.ClientCertMiddleware, nil, mount)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/mcp without a key: %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer resource_metadata="https://fleetos.example.org/.well-known/oauth-protected-resource/mcp"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"resource":"https://fleetos.example.org/mcp"`) {
		t.Fatalf("resource metadata: %d %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/consent/some-id", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("consent without a certificate: %d", rec.Code)
	}

	// The SPA still owns the consent page route itself.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/consent?req=x", nil))
	if rec.Body.String() != "spa" {
		t.Fatalf("consent page = %q, want the SPA", rec.Body.String())
	}
}

func TestRootHandler_NoMCPWhenDisabled(t *testing.T) {
	h := newRootHandler("/cryptos.fleet.v1.FleetService/", stubHandler(http.StatusOK, "api"), stubHandler(http.StatusOK, "spa"),
		authz.ClientCertMiddleware, nil)
	for _, target := range []string{"/mcp", "/.well-known/oauth-authorization-server"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Body.String() != "spa" {
			t.Errorf("%s = %d %q, want the SPA", target, rec.Code, rec.Body.String())
		}
	}
}
