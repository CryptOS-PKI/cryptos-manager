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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/config"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// fakeCertStore stands in for the Postgres bootstrap_server_cert row.
type fakeCertStore struct {
	mu      sync.Mutex
	row     *store.ServerCert
	locks   []string
	deleted int
}

func (f *fakeCertStore) WithAdvisoryLock(ctx context.Context, name string, fn func(context.Context) error) error {
	f.mu.Lock()
	f.locks = append(f.locks, name)
	f.mu.Unlock()
	return fn(ctx)
}

func (f *fakeCertStore) BootstrapServerCert(context.Context) (store.ServerCert, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.row == nil {
		return store.ServerCert{}, false, nil
	}
	return *f.row, true, nil
}

func (f *fakeCertStore) PutBootstrapServerCert(_ context.Context, c store.ServerCert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.row = &c
	return nil
}

func (f *fakeCertStore) DeleteBootstrapServerCert(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.row = nil
	f.deleted++
	return nil
}

func leafOf(t *testing.T, c *tls.Config) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// The self-signed certificate is kept in Postgres, so every restart and
// every replica serves the same fingerprint, under the advisory lock.
func TestBuildTLSConfig_ReusesThePersistedCertificate(t *testing.T) {
	cs := &fakeCertStore{}
	cfg := config.Config{Listen: "0.0.0.0:8443"}
	first, err := buildTLSConfig(context.Background(), cfg, cs, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildTLSConfig(context.Background(), cfg, cs, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if !leafOf(t, first).Equal(leafOf(t, second)) {
		t.Fatal("a restart generated a new certificate instead of reusing the stored one")
	}
	if len(cs.locks) != 2 || cs.locks[0] != "fleetos.bootstrap_cert" {
		t.Fatalf("locks = %v, want fleetos.bootstrap_cert each time", cs.locks)
	}
}

func TestBuildTLSConfig_RegeneratesWithinSevenDaysOfExpiry(t *testing.T) {
	cs := &fakeCertStore{}
	cfg := config.Config{Listen: "0.0.0.0:8443"}
	first, err := buildTLSConfig(context.Background(), cfg, cs, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	cs.row.NotAfter = time.Now().Add(6 * 24 * time.Hour)
	second, err := buildTLSConfig(context.Background(), cfg, cs, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if leafOf(t, first).Equal(leafOf(t, second)) {
		t.Fatal("a certificate within 7 days of expiry was reused")
	}
}

func TestBuildTLSConfig_DeletesThePersistedCertificateOnceTLSIsConfigured(t *testing.T) {
	cs := &fakeCertStore{row: &store.ServerCert{CertDER: []byte("old")}}
	certPath, keyPath := writeSelfSigned(t, t.TempDir())
	if _, err := buildTLSConfig(context.Background(), config.Config{TLSCert: certPath, TLSKey: keyPath}, cs, t.Logf); err != nil {
		t.Fatal(err)
	}
	if cs.row != nil || cs.deleted != 1 {
		t.Fatalf("row = %v, deleted %d; want the stored certificate gone", cs.row, cs.deleted)
	}
}

// Every start logs the self-signed certificate's SHA-256, the value the
// browser shows, so the operator can compare it before trusting the page.
func TestBuildTLSConfig_LogsTheFingerprint(t *testing.T) {
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	tc, err := buildTLSConfig(context.Background(), config.Config{Listen: "0.0.0.0:8443"}, &fakeCertStore{}, logf)
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafOf(t, tc)
	sum := sha256.Sum256(leaf.Raw)
	var want []string
	for _, b := range sum {
		want = append(want, fmt.Sprintf("%02X", b))
	}
	fp := strings.Join(want, ":")
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "SELF-SIGNED bootstrap certificate, SHA-256 "+fp+", valid until "+leaf.NotAfter.UTC().Format("2006-01-02")) {
		t.Fatalf("log = %q, want the fingerprint line for %s", joined, fp)
	}
}
