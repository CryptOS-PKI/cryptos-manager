package postgres

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
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/storetest"
)

func TestOperatorTrust(t *testing.T) {
	storetest.OperatorTrust(t, func(t *testing.T) store.OperatorTrust { return testStore(t) })
}

// A database that recorded node-issued operator credentials keeps them
// through v7, marked legacy_node with no issuer, and the key becomes
// (issuer, serial) so serials from different operator CAs can't collide.
func TestMigrateV7_KeepsLegacyOperatorCredentials(t *testing.T) {
	pool := freshSchemaPool(t)
	ctx := context.Background()

	if err := migrateSteps(ctx, pool, migrations[:6]); err != nil {
		t.Fatalf("migrate to v6: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO operator_credentials (serial_hex, common_name, level, not_after, revoked)
		 VALUES ('1f', 'op@example.org', 'admin', '2027-01-01T00:00:00Z', false)`); err != nil {
		t.Fatalf("insert legacy credential: %v", err)
	}
	if err := migrate(ctx, pool); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	if err := migrate(ctx, pool); err != nil {
		t.Fatalf("migrate again: %v", err)
	}

	s := &Store{pool: pool}
	creds := s.OperatorCredentials()
	if len(creds) != 1 {
		t.Fatalf("OperatorCredentials() = %+v, want the legacy row", creds)
	}
	if c := creds[0]; c.Kind != store.OperatorCredentialLegacyNode || c.IssuerSHA256 != "" || c.SerialHex != "1f" || c.CommonName != "op@example.org" {
		t.Fatalf("legacy row after v7 = %+v", c)
	}

	s.AddOperatorCredential(store.OperatorCredential{
		IssuerSHA256: "aa", SerialHex: "1f", CommonName: "op@example.org", Level: "admin",
		NotAfter: "2027-01-01T00:00:00Z", Kind: "first_admin", Email: "op@example.org", FullName: "Op Example", LeafSHA256: "cc",
	})
	creds = s.OperatorCredentials()
	if len(creds) != 2 {
		t.Fatalf("the same serial under an issuer was refused: %+v", creds)
	}
	for _, c := range creds {
		if c.IssuerSHA256 == "aa" && (c.Kind != "first_admin" || c.Email != "op@example.org" || c.FullName != "Op Example" || c.LeafSHA256 != "cc") {
			t.Fatalf("new row = %+v", c)
		}
	}
}

// Every table the day-zero design keeps in Postgres exists after v7, and the
// singletons are seeded.
func TestMigrateV7_CreatesTheBootstrapAndTrustTables(t *testing.T) {
	pool := freshSchemaPool(t)
	ctx := context.Background()
	if err := migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, table := range []string{
		"operator_cas", "operator_crls", "operator_denylist", "operator_credential_requests",
		"operator_revocation_epoch", "bootstrap_state", "bootstrap_tokens", "bootstrap_sessions", "bootstrap_server_cert",
	} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables
			WHERE table_schema = current_schema() AND table_name = $1)`, table).Scan(&exists); err != nil {
			t.Fatalf("look up %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s missing after v7", table)
		}
	}
	for _, singleton := range []string{"operator_revocation_epoch", "bootstrap_state"} {
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+singleton).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s has %d rows (%v), want the one singleton", singleton, n, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO operator_credential_requests
		(id, level, email, full_name, state, created_by_cn, created_at, expires_at)
		VALUES (gen_random_uuid(), 'viewer', 'v@example.org', 'V', 'lost', 'a', now(), now())`); err == nil {
		t.Error("a credential request with an unknown state was stored")
	}
}

func TestBootstrapServerCert_RoundTripAndDelete(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if _, ok, err := s.BootstrapServerCert(ctx); err != nil || ok {
		t.Fatalf("BootstrapServerCert() on an empty store = %v, %v", ok, err)
	}
	notAfter := time.Date(2026, 12, 29, 0, 0, 0, 0, time.UTC)
	in := store.ServerCert{CertDER: []byte("cert"), KeyDER: []byte("key"), NotAfter: notAfter}
	if err := s.PutBootstrapServerCert(ctx, in); err != nil {
		t.Fatalf("PutBootstrapServerCert: %v", err)
	}
	in.CertDER = []byte("cert-2")
	if err := s.PutBootstrapServerCert(ctx, in); err != nil {
		t.Fatalf("PutBootstrapServerCert (replace): %v", err)
	}
	got, ok, err := s.BootstrapServerCert(ctx)
	if err != nil || !ok || string(got.CertDER) != "cert-2" || string(got.KeyDER) != "key" || !got.NotAfter.Equal(notAfter) {
		t.Fatalf("BootstrapServerCert() = %+v, %v, %v", got, ok, err)
	}
	if err := s.DeleteBootstrapServerCert(ctx); err != nil {
		t.Fatalf("DeleteBootstrapServerCert: %v", err)
	}
	if _, ok, _ := s.BootstrapServerCert(ctx); ok {
		t.Fatal("the server cert survived a delete")
	}
}

// Two callers under the same advisory lock run one at a time.
func TestWithAdvisoryLock_Serialises(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.WithAdvisoryLock(ctx, "fleetos.bootstrap_cert", func(context.Context) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	second := make(chan struct{})
	go func() {
		_ = s.WithAdvisoryLock(ctx, "fleetos.bootstrap_cert", func(context.Context) error {
			close(second)
			return nil
		})
	}()
	select {
	case <-second:
		t.Fatal("the second holder ran while the first held the lock")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first WithAdvisoryLock: %v", err)
	}
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Fatal("the second holder never ran")
	}
}
