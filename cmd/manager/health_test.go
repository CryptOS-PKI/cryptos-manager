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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/config"
)

func TestHealthHandler_OKWithoutAStoreCheck(t *testing.T) {
	rec := httptest.NewRecorder()
	healthHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, healthPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
	}
	if got["status"] != "ok" {
		t.Errorf("status field = %q, want ok", got["status"])
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestHealthHandler_OKWhenTheStoreAnswers(t *testing.T) {
	called := false
	rec := httptest.NewRecorder()
	healthHandler(func(context.Context) error { called = true; return nil }).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, healthPath, nil))

	if !called {
		t.Fatal("store check was not called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// A database that cannot be reached is the failure worth reporting, and the
// endpoint is anonymous, so the driver's error (which names the host) stays in
// the log rather than the response.
func TestHealthHandler_503WhenTheStoreIsUnreachable(t *testing.T) {
	rec := httptest.NewRecorder()
	healthHandler(func(context.Context) error { return errors.New("dial tcp db.internal:5432: connection refused") }).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, healthPath, nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "db.internal") {
		t.Errorf("body %q leaks the store error", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "unavailable") {
		t.Errorf("body %q does not say the service is unavailable", rec.Body.String())
	}
}

func TestHealthHandler_Head(t *testing.T) {
	rec := httptest.NewRecorder()
	healthHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodHead, healthPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD body = %q, want empty", rec.Body.String())
	}
}

func TestHealthHandler_RejectsWrites(t *testing.T) {
	rec := httptest.NewRecorder()
	healthHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, healthPath, nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// The web handler answers every path with the SPA and a 200, which is why it
// cannot stand in for a health check: this pins that /healthz is served by the
// manager itself, without a client certificate.
func TestRootHandler_HealthIsAnonymousAndNotTheSPA(t *testing.T) {
	h := newRootHandler(
		"/cryptos.fleet.v1.FleetService/",
		stubHandler(http.StatusOK, "api"),
		stubHandler(http.StatusOK, "spa"),
		authz.ClientCertMiddleware,
		nil,
		healthMount(func(context.Context) error { return errors.New("down") }),
	)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, healthPath, nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d (body %q), want the health handler's 503", rec.Code, rec.Body.String())
	}
}

func TestHealthProbeURL(t *testing.T) {
	for _, tc := range []struct {
		name   string
		listen string
		bypass bool
		want   string
	}{
		{"all interfaces", "0.0.0.0:8443", false, "https://127.0.0.1:8443/healthz"},
		{"empty host", ":8443", false, "https://127.0.0.1:8443/healthz"},
		{"ipv6 any", "[::]:8443", false, "https://127.0.0.1:8443/healthz"},
		{"specific host", "10.0.0.5:9443", false, "https://10.0.0.5:9443/healthz"},
		{"dev bypass is plaintext", "0.0.0.0:8080", true, "http://127.0.0.1:8080/healthz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := healthProbeURL(config.Config{Listen: tc.listen, AuthBypass: tc.bypass})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("url = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHealthProbeURL_BadListen(t *testing.T) {
	if _, err := healthProbeURL(config.Config{Listen: "8443"}); err == nil {
		t.Fatal("want an error for a listen address with no port")
	}
}

// The probe talks to the manager's own TLS listener, whose certificate names
// the public hostname rather than 127.0.0.1, so it has to succeed against a
// certificate it cannot verify.
func TestProbeHealth(t *testing.T) {
	ok := httptest.NewTLSServer(healthHandler(nil))
	defer ok.Close()
	if err := probeHealth(ok.URL + healthPath); err != nil {
		t.Errorf("healthy server: %v", err)
	}

	down := httptest.NewTLSServer(healthHandler(func(context.Context) error { return errors.New("down") }))
	defer down.Close()
	if err := probeHealth(down.URL + healthPath); err == nil {
		t.Error("unhealthy server: want an error")
	}

	if err := probeHealth("https://127.0.0.1:1" + healthPath); err == nil {
		t.Error("nothing listening: want an error")
	}
}
