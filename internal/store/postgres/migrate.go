// Package postgres implements store.Store against a hand-rolled Postgres
// backend using raw SQL over pgx. No ORM, no query builder.
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
	_ "embed"
	"fmt"
	"log"

	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// schemaSQL is the base DDL for the manager's tables (every table created
// IF NOT EXISTS), applied as the v1 migration.
//
//go:embed schema.sql
var schemaSQL string

// v2ProfilesSQL widens the profiles table to hold the full marshaled
// cryptos.v1.CertificateProfile (name + spec bytes) rather than the flat
// projection v1 shipped. A database that first migrates at v2 already has the
// new table shape from schema.sql, so this DROPs and recreates it to bring an
// existing v1 database to the same shape. Profiles are seeded (not
// operator-critical pre-GA), so dropping and reseeding is acceptable.
const v2ProfilesSQL = `DROP TABLE IF EXISTS profiles;
CREATE TABLE profiles (name text PRIMARY KEY, spec bytea NOT NULL);`

// v3OperatorCredentialsSQL adds the operator_credentials table backing the S9
// Operators surface: the durable metadata of every operator client cert the
// manager issued via the operator-CA node (the manager never holds the key).
const v3OperatorCredentialsSQL = `CREATE TABLE IF NOT EXISTS operator_credentials (
  serial_hex text PRIMARY KEY, common_name text NOT NULL, level text NOT NULL,
  not_after text NOT NULL, revoked boolean NOT NULL DEFAULT false,
  issued_at timestamptz NOT NULL DEFAULT now()
);`

// v4McpSQL records who acted on every audit row, versions the audit hash
// chain so rows hashed before the actor fields keep verifying, and adds the
// MCP agent key table plus the short-lived OAuth login state. The OAuth state
// is in the database rather than in memory because a login's browser leg and
// token leg can land on different replicas.
const v4McpSQL = `ALTER TABLE audit_events
  ADD COLUMN IF NOT EXISTS actor_kind text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS actor_cn text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS actor_serial text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS key_id text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS via text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS tool text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS request_digest text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS outcome text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS approval_id text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS approver_serial text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS chain_version integer NOT NULL DEFAULT 1;
CREATE TABLE IF NOT EXISTS mcp_keys (
  id text PRIMARY KEY, token_hash text UNIQUE NOT NULL, label text NOT NULL,
  client_name text NOT NULL, operator_serial text NOT NULL, operator_cn text NOT NULL,
  operator_cert_der bytea NOT NULL, level_ceiling text NOT NULL,
  created_at timestamptz NOT NULL, last_used_at timestamptz, revoked_at timestamptz,
  expires_at timestamptz
);
CREATE TABLE IF NOT EXISTS oauth_requests (
  id text PRIMARY KEY, client_id text NOT NULL, client_name text NOT NULL,
  redirect_uri text NOT NULL, state text NOT NULL, code_challenge text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash text PRIMARY KEY, client_id text NOT NULL, client_name text NOT NULL,
  redirect_uri text NOT NULL, code_challenge text NOT NULL, operator_cn text NOT NULL,
  operator_serial text NOT NULL, operator_cert_der bytea NOT NULL,
  level_ceiling text NOT NULL, label text NOT NULL, expires_at timestamptz NOT NULL
);`

// v5ApprovalsSQL adds the step-up approvals raised by MCP tool calls. They
// are in the database so an agent's request, the operator's decision in the
// browser and the agent's re-call can each land on a different replica.
const v5ApprovalsSQL = `CREATE TABLE IF NOT EXISTS approvals (
  id text PRIMARY KEY, tool text NOT NULL, summary text NOT NULL, request_digest text NOT NULL,
  requested_by_cn text NOT NULL, requested_by_serial text NOT NULL, key_id text NOT NULL,
  required_level text NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
  status text NOT NULL, decided_by_cn text NOT NULL DEFAULT '', decided_by_serial text NOT NULL DEFAULT '',
  decided_by_level text NOT NULL DEFAULT '', decided_at timestamptz, used_at timestamptz
);
CREATE INDEX IF NOT EXISTS approvals_created_at ON approvals (created_at DESC);`

// v6NodeIDsSQL gives every node a stable ID separate from its editable name,
// points enrollments at the node they admitted by that ID, and keeps each
// node's name history so audit entries and links recorded under an old name
// still find the node. The ID column starts nullable: backfillNodeIDs fills it
// with UUIDv7s minted in Go (Postgres only gained uuidv7() in 18), and
// v6NodeIDsFinishSQL then makes it NOT NULL and UNIQUE. name keeps its primary
// key, so two nodes still cannot share a name.
const v6NodeIDsSQL = `ALTER TABLE nodes ADD COLUMN IF NOT EXISTS id uuid;
ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS admitted_node_id text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS node_names (
  seq bigserial PRIMARY KEY, node_id uuid NOT NULL, name text NOT NULL,
  valid_from timestamptz, valid_until timestamptz
);
CREATE INDEX IF NOT EXISTS node_names_name ON node_names (name);`

// v6NodeIDsFinishSQL runs after the backfill. Each existing node's history
// starts with its current name, open at both ends, because nothing recorded
// when it got that name.
const v6NodeIDsFinishSQL = `ALTER TABLE nodes ALTER COLUMN id SET NOT NULL;
ALTER TABLE nodes ADD CONSTRAINT nodes_id_key UNIQUE (id);
UPDATE enrollments e SET admitted_node_id = n.id::text
  FROM nodes n WHERE e.admitted_node_name <> '' AND e.admitted_node_name = n.name AND e.admitted_node_id = '';
INSERT INTO node_names (node_id, name) SELECT id, name FROM nodes ORDER BY name;`

// backfillNodeIDs mints a UUIDv7 for every node that has no ID yet.
func backfillNodeIDs(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `SELECT name FROM nodes WHERE id IS NULL ORDER BY name`)
	if err != nil {
		return fmt.Errorf("list nodes without an id: %w", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("read nodes without an id: %w", err)
	}
	log.Printf("postgres: migration v6: backfilling ids for %d node(s)", len(names))
	for _, name := range names {
		id := store.NewNodeID()
		if _, err := tx.Exec(ctx, `UPDATE nodes SET id = $1 WHERE name = $2`, id, name); err != nil {
			return fmt.Errorf("set id for node %q: %w", name, err)
		}
		log.Printf("postgres: migration v6: node %s gets id %s", name, id)
	}
	if _, err := tx.Exec(ctx, v6NodeIDsFinishSQL); err != nil {
		return fmt.Errorf("finish node ids: %w", err)
	}
	return nil
}

// migration is one ordered, idempotently-tracked schema step: its SQL, then
// its Go step when a step needs values SQL cannot produce.
type migration struct {
	version string
	sql     string
	apply   func(ctx context.Context, tx pgx.Tx) error
}

// migrations is the ordered list of schema steps. Each runs at most once,
// tracked in schema_migrations; appending a new step is how the schema evolves.
var migrations = []migration{
	{version: "v1", sql: schemaSQL},
	{version: "v2", sql: v2ProfilesSQL},
	{version: "v3", sql: v3OperatorCredentialsSQL},
	{version: "v4", sql: v4McpSQL},
	{version: "v5", sql: v5ApprovalsSQL},
	{version: "v6", sql: v6NodeIDsSQL, apply: backfillNodeIDs},
}

// migrate applies every not-yet-applied migration in order, each tracked in a
// schema_migrations table, and is safe to run on every startup. Running it
// against an already-migrated database is a no-op.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return migrateSteps(ctx, pool, migrations)
}

// migrateSteps applies the not-yet-applied steps of steps, in order, in one
// transaction.
func migrateSteps(ctx context.Context, pool *pgxpool.Pool, steps []migration) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
  version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return fmt.Errorf("postgres: create schema_migrations: %w", err)
	}

	for _, m := range steps {
		var applied bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
			m.version).Scan(&applied); err != nil {
			return fmt.Errorf("postgres: check migration %s: %w", m.version, err)
		}
		if applied {
			continue
		}

		log.Printf("postgres: applying migration %s", m.version)
		if _, err := tx.Exec(ctx, m.sql); err != nil {
			return fmt.Errorf("postgres: apply schema %s: %w", m.version, err)
		}
		if m.apply != nil {
			if err := m.apply(ctx, tx); err != nil {
				return fmt.Errorf("postgres: apply migration %s: %w", m.version, err)
			}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`, m.version); err != nil {
			return fmt.Errorf("postgres: record migration %s: %w", m.version, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit migration: %w", err)
	}
	return nil
}
