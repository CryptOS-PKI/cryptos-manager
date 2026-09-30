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
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testDSNEnv is the env var that gates the Postgres integration tests. When it
// is unset every test that needs a database skips, so the package stays green
// without a running Postgres.
const testDSNEnv = "MANAGER_TEST_DATABASE_URL"

// testPool returns a migrated connection pool against MANAGER_TEST_DATABASE_URL,
// with every table truncated for per-test isolation. It skips the test when the
// env var is unset. The pool is closed at test cleanup.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv(testDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping Postgres integration test", testDSNEnv)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", testDSNEnv, err)
	}
	t.Cleanup(pool.Close)

	if err := migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	truncateAll(t, pool)

	return pool
}

// testStore returns a Store wrapping a freshly-truncated migrated pool, gated
// on MANAGER_TEST_DATABASE_URL the same way as testPool.
func testStore(t *testing.T) *Store {
	t.Helper()
	return &Store{pool: testPool(t)}
}

// truncateAll empties every data table so each test starts from a known state.
// The audit_events sequence is restarted so hash-chain ordering is predictable.
func truncateAll(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`TRUNCATE nodes, node_names, profiles, adapters, audit_events, enrollments, operator_credentials, mcp_keys, oauth_requests, oauth_codes, approvals RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}
