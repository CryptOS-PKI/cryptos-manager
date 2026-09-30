package authz

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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// staticRevoked is a RevocationSource returning a fixed set of serials, or an
// error to exercise the fail-safe (keep-last-good) refresh behavior.
type staticRevoked struct {
	serials []string
	err     error
	calls   int
}

func (s *staticRevoked) RevokedSerials() ([]string, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.serials, nil
}

func TestRevocationCache_NormalizesAndMatchesMiddlewareSerial(t *testing.T) {
	// The cache is seeded with the node's hex serial (0abc); the middleware
	// derives its own serial string from the cert (00:0A:BC via formatSerial).
	// A revoked serial must be denied regardless of separator/case.
	src := &staticRevoked{serials: []string{"0abc"}}
	cache := NewRevocationCache(src)
	if err := cache.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	cert := leafCert(t, LevelOperator) // serial 0x0abc
	serial := formatSerial(cert.SerialNumber)
	if !cache.IsRevoked(serial) {
		t.Fatalf("IsRevoked(%q) = false, want true (normalized match on 0abc)", serial)
	}
	if cache.IsRevoked("00:11:22") {
		t.Fatal("IsRevoked of an unrelated serial = true, want false")
	}
}

func TestRevocationCache_KeepsLastGoodOnError(t *testing.T) {
	src := &staticRevoked{serials: []string{"0abc"}}
	cache := NewRevocationCache(src)
	if err := cache.Refresh(); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}

	// The next fetch fails: the cache must keep the last-good set rather than
	// clearing it (which would fail-open) or locking everyone out.
	src.serials = nil
	src.err = errors.New("crl unreachable")
	if err := cache.Refresh(); err == nil {
		t.Fatal("Refresh with failing source returned nil error, want the fetch error surfaced")
	}

	cert := leafCert(t, LevelOperator)
	if !cache.IsRevoked(formatSerial(cert.SerialNumber)) {
		t.Fatal("after a failed refresh IsRevoked = false, want the last-good revoked set retained")
	}
}

func TestClientCertMiddleware_DeniesRevokedSerial(t *testing.T) {
	src := &staticRevoked{serials: []string{"0abc"}} // matches leafCert serial
	cache := NewRevocationCache(src)
	if err := cache.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rpc", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafCert(t, LevelOperator)}}
	ClientCertMiddlewareWithRevocation(cache, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("next must not be called for a revoked client certificate")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a revoked serial", rec.Code)
	}
}

func TestClientCertMiddleware_AllowsValidSerial(t *testing.T) {
	src := &staticRevoked{serials: []string{"deadbeef"}} // does NOT match leafCert
	cache := NewRevocationCache(src)
	if err := cache.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	var passed bool
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rpc", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafCert(t, LevelOperator)}}
	ClientCertMiddlewareWithRevocation(cache, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		passed = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if !passed || rec.Code != http.StatusOK {
		t.Fatalf("valid serial was not allowed: passed=%v status=%d", passed, rec.Code)
	}
}

func TestClientCertMiddleware_NilRevocationCacheAllows(t *testing.T) {
	// A nil cache (revocation enforcement not wired, e.g. no operator_ca_node)
	// must not deny anyone: it degrades to the plain client-cert middleware.
	var passed bool
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rpc", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafCert(t, LevelOperator)}}
	ClientCertMiddlewareWithRevocation(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		passed = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if !passed || rec.Code != http.StatusOK {
		t.Fatalf("nil cache denied a valid client: passed=%v status=%d", passed, rec.Code)
	}
}
