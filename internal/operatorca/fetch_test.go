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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
)

const secretBody = "SECRET-BODY-DO-NOT-ECHO"

func TestFetch_ReturnsTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("crl-bytes")) }))
	defer srv.Close()
	got, err := NewFetcher(FetchLimits{Timeout: time.Second, MaxBytes: MaxCRLSize}).Fetch(context.Background(), srv.URL)
	if err != nil || string(got) != "crl-bytes" {
		t.Fatalf("Fetch = %q, %v", got, err)
	}
}

func TestFetch_Limits(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 1025)))
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	mux.HandleFunc("/to-file", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	})
	mux.HandleFunc("/hop/", func(w http.ResponseWriter, r *http.Request) {
		n := len(strings.TrimPrefix(r.URL.Path, "/hop/"))
		http.Redirect(w, r, "/hop/"+strings.Repeat("x", n+1), http.StatusFound)
	})
	mux.HandleFunc("/three-hops/", func(w http.ResponseWriter, r *http.Request) {
		n := len(strings.TrimPrefix(r.URL.Path, "/three-hops/"))
		if n == 3 {
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.Redirect(w, r, "/three-hops/"+strings.Repeat("x", n+1), http.StatusFound)
	})
	mux.HandleFunc("/error", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(secretBody))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	f := NewFetcher(FetchLimits{Timeout: 200 * time.Millisecond, MaxBytes: 1024})
	if got, err := f.Fetch(context.Background(), srv.URL+"/three-hops/"); err != nil || string(got) != "ok" {
		t.Fatalf("three redirects = %q, %v; want followed", got, err)
	}
	for name, url := range map[string]string{
		"non-http scheme":       "ftp://pki.example.org/op.crl",
		"file scheme":           "file:///etc/passwd",
		"redirect to file://":   srv.URL + "/to-file",
		"more than 3 redirects": srv.URL + "/hop/",
		"body over the cap":     srv.URL + "/big",
		"timeout":               srv.URL + "/slow",
		"server error":          srv.URL + "/error",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.Fetch(context.Background(), url)
			wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_UNREACHABLE)
			if strings.Contains(err.Error(), secretBody) || strings.Contains(err.Error(), "xxxx") {
				t.Fatalf("error echoes the body: %v", err)
			}
		})
	}
}

// Proxy settings in the environment don't redirect the manager's fetches.
func TestFetch_IgnoresProxyEnvironment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("direct")) }))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	got, err := NewFetcher(FetchLimits{Timeout: time.Second, MaxBytes: 1024}).Fetch(context.Background(), srv.URL)
	if err != nil || string(got) != "direct" {
		t.Fatalf("Fetch = %q, %v; want the direct answer", got, err)
	}
}

func TestValidateFetchURL(t *testing.T) {
	for _, ok := range []string{"http://pki.example.org/op.crl", "https://pki.example.org/op.crl"} {
		if err := ValidateFetchURL(ok); err != nil {
			t.Errorf("ValidateFetchURL(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ftp://pki.example.org/op.crl", "file:///etc/op.crl", "http://", "pki.example.org/op.crl", "http://pki.example.org/" + strings.Repeat("a", 2048)} {
		if err := ValidateFetchURL(bad); err == nil {
			t.Errorf("ValidateFetchURL(%q) accepted", bad)
		}
	}
}
