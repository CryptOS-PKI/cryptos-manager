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
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/storetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNodeIDs(t *testing.T) {
	storetest.NodeIDs(t, func(t *testing.T) store.Store { return testStore(t) })
}

// freshSchemaPool returns a pool whose search_path is a new, empty schema, so a
// test can build the database up migration by migration without touching the
// shared tables. The schema is dropped at cleanup.
func freshSchemaPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv(testDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping Postgres integration test", testDSNEnv)
	}
	ctx := context.Background()
	schema := fmt.Sprintf("mig_%d", time.Now().UnixNano())

	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(admin.Close)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect to schema: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestMigrateBackfillsNodeIDs(t *testing.T) {
	pool := freshSchemaPool(t)
	ctx := context.Background()

	// Build a database as it stood before node IDs, with live rows in it.
	if err := migrateSteps(ctx, pool, migrations[:5]); err != nil {
		t.Fatalf("migrate to v5: %v", err)
	}
	for _, name := range []string{"pki-root", "pki-inter"} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO nodes (name, endpoint, role, admin_cert, admin_key, ca_cert) VALUES ($1, $1, 'root', '', '', '')`,
			name); err != nil {
			t.Fatalf("insert legacy node: %v", err)
		}
	}
	legacyEnrollmentInsert(t, pool, "enr-1", "pki-inter")
	legacyEnrollmentInsert(t, pool, "enr-2", "gone")
	legacyEnrollmentInsert(t, pool, "enr-3", "")

	if err := migrate(ctx, pool); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	s := &Store{pool: pool}
	nodes := s.Nodes()
	if len(nodes) != 2 {
		t.Fatalf("Nodes() after migration = %+v, want the two legacy nodes", nodes)
	}
	ids := map[string]string{}
	for _, n := range nodes {
		u, err := uuid.Parse(n.ID)
		if err != nil || u.Version() != 7 {
			t.Fatalf("node %s backfilled with %q, want a UUIDv7", n.Name, n.ID)
		}
		ids[n.Name] = n.ID
	}
	if ids["pki-root"] == ids["pki-inter"] {
		t.Fatal("backfill gave two nodes the same ID")
	}

	var nullable, unique bool
	if err := pool.QueryRow(ctx, `SELECT is_nullable = 'YES' FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'nodes' AND column_name = 'id'`).Scan(&nullable); err != nil {
		t.Fatalf("read nodes.id nullability: %v", err)
	}
	if nullable {
		t.Error("nodes.id is nullable after the migration, want NOT NULL")
	}
	if err := pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
		WHERE c.relname = 'nodes' AND c.relnamespace = current_schema()::regnamespace
		  AND i.indisunique AND i.indnatts = 1 AND a.attname = 'id')`).Scan(&unique); err != nil {
		t.Fatalf("read nodes.id uniqueness: %v", err)
	}
	if !unique {
		t.Error("nodes.id has no unique index after the migration")
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO nodes (id, name, endpoint, role, admin_cert, admin_key, ca_cert) VALUES ($1, 'dup', '', '', '', '', '')`,
		ids["pki-root"]); err == nil {
		t.Error("inserting a second node with an existing ID succeeded, want a unique violation")
	}

	for id, want := range map[string]string{"enr-1": ids["pki-inter"], "enr-2": "", "enr-3": ""} {
		got, _ := s.Enrollment(id)
		if got.AdmittedNodeID != want {
			t.Errorf("enrollment %s admitted_node_id = %q, want %q", id, got.AdmittedNodeID, want)
		}
	}

	hist := s.NodeNames()
	if len(hist) != 2 {
		t.Fatalf("NodeNames() after migration = %+v, want one span per node", hist)
	}
	for _, h := range hist {
		if ids[h.Name] != h.NodeID || !h.From.IsZero() || !h.Until.IsZero() {
			t.Errorf("seeded span %+v, want the node's current name, open at both ends", h)
		}
	}

	if err := migrate(ctx, pool); err != nil {
		t.Fatalf("re-running migrate: %v", err)
	}
	for _, n := range s.Nodes() {
		if n.ID != ids[n.Name] {
			t.Errorf("re-running migrate changed %s's ID from %s to %s", n.Name, ids[n.Name], n.ID)
		}
	}
}

// legacyEnrollmentInsert writes an enrollment row with only the columns that
// existed before node IDs.
func legacyEnrollmentInsert(t *testing.T, pool *pgxpool.Pool, id, admitted string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO enrollments (
		id, proposed_name, role, parent_cn, address, status, attestation_summary, attestation_node_id,
		csr_key_type, csr_subject_cn, requested_at, rejection_reason, admitted_node_name, kind,
		pinned_key_sha256, attestation_ok, profile
	) VALUES ($1, $2, '', '', '', 'APPROVED', '', '', '', '', 't0', '', $2, 'LINK', '', false, '')`, id, admitted); err != nil {
		t.Fatalf("insert legacy enrollment %s: %v", id, err)
	}
}

func TestSeedIfEmptyMintsNodeIDs(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	nodes := []store.Node{
		{Name: "n1", Endpoint: "n1:443", Role: "root"},
		{Name: "n2", Endpoint: "n2:443", Role: "issuing"},
	}
	if err := s.SeedIfEmpty(ctx, nodes, nil, nil, nil, nil); err != nil {
		t.Fatalf("SeedIfEmpty: %v", err)
	}
	for _, n := range s.Nodes() {
		if !store.IsNodeID(n.ID) {
			t.Fatalf("seeded node %s has ID %q, want a node ID", n.Name, n.ID)
		}
	}
	if hist := s.NodeNames(); len(hist) != 2 {
		t.Fatalf("NodeNames() after seed = %+v, want one span per node", hist)
	}
}

// A manager restart re-runs SeedIfEmpty with the names from config.yaml. A
// rename made since must survive it: the config is bootstrap-only.
func TestRenameSurvivesARestartSeed(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	fromConfig := []store.Node{{Name: "pki-root", Endpoint: "root:443", Role: "root"}}
	if err := s.SeedIfEmpty(ctx, fromConfig, nil, nil, nil, nil); err != nil {
		t.Fatalf("first SeedIfEmpty: %v", err)
	}
	n, _ := s.Node("pki-root")
	if _, err := s.RenameNode(n.ID, "root-east", time.Now()); err != nil {
		t.Fatalf("RenameNode: %v", err)
	}

	if err := s.SeedIfEmpty(ctx, fromConfig, nil, nil, nil, nil); err != nil {
		t.Fatalf("restart SeedIfEmpty: %v", err)
	}
	all := s.Nodes()
	if len(all) != 1 || all[0].ID != n.ID || all[0].Name != "root-east" {
		t.Fatalf("Nodes() after restart = %+v, want the one node %s still named root-east", all, n.ID)
	}
}
