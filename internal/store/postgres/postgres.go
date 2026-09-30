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
	"errors"
	"fmt"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is a store.Store backed by Postgres. State is durable: pending
// enrollments and the audit chain survive a restart.
type Store struct {
	pool *pgxpool.Pool
}

// auditChainLockKey is the fixed key for the transaction-scoped advisory lock
// that serializes audit-chain appends (see AddAuditEvent). The value is
// arbitrary but reserved for this one purpose so that no two appends read the
// same prev_hash concurrently and fork the chain.
const auditChainLockKey int64 = 0x6175646974636861 // "auditcha"

// compile-time proof that Store satisfies the store.Store interface.
var _ store.Store = (*Store)(nil)

// New opens a connection pool to dsn, applies the schema migration, and
// returns a ready Store. The caller owns the Store and must Close it.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// bg is the context used by the interface methods, which are context-free to
// match store.Store; Postgres calls always need one.
func bg() context.Context { return context.Background() }

// Nodes returns every node in the inventory.
func (s *Store) Nodes() []store.Node {
	rows, err := s.pool.Query(bg(),
		`SELECT name, endpoint, role, admin_cert, admin_key, ca_cert FROM nodes ORDER BY name`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query nodes: %v", err))
	}
	defer rows.Close()

	out := make([]store.Node, 0)
	for rows.Next() {
		var n store.Node
		if err := rows.Scan(&n.Name, &n.Endpoint, &n.Role, &n.AdminCert, &n.AdminKey, &n.CACert); err != nil {
			panic(fmt.Sprintf("postgres: scan node: %v", err))
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate nodes: %v", err))
	}
	return out
}

// Node returns the node with the given name, and whether it was found.
func (s *Store) Node(name string) (store.Node, bool) {
	var n store.Node
	err := s.pool.QueryRow(bg(),
		`SELECT name, endpoint, role, admin_cert, admin_key, ca_cert FROM nodes WHERE name = $1`, name).
		Scan(&n.Name, &n.Endpoint, &n.Role, &n.AdminCert, &n.AdminKey, &n.CACert)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Node{}, false
	}
	if err != nil {
		panic(fmt.Sprintf("postgres: query node %q: %v", name, err))
	}
	return n, true
}

// AddNode inserts n into the inventory, replacing any node with the same name
// (an adopted node re-registering keeps the latest endpoint/role).
func (s *Store) AddNode(n store.Node) {
	if _, err := s.pool.Exec(bg(),
		`INSERT INTO nodes (name, endpoint, role, admin_cert, admin_key, ca_cert)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (name) DO UPDATE SET
		   endpoint = EXCLUDED.endpoint, role = EXCLUDED.role,
		   admin_cert = EXCLUDED.admin_cert, admin_key = EXCLUDED.admin_key,
		   ca_cert = EXCLUDED.ca_cert`,
		n.Name, n.Endpoint, n.Role, n.AdminCert, n.AdminKey, n.CACert); err != nil {
		panic(fmt.Sprintf("postgres: insert node %q: %v", n.Name, err))
	}
}

// Profiles returns every certificate issuance profile.
func (s *Store) Profiles() []store.Profile {
	rows, err := s.pool.Query(bg(),
		`SELECT name, spec FROM profiles ORDER BY name`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query profiles: %v", err))
	}
	defer rows.Close()

	out := make([]store.Profile, 0)
	for rows.Next() {
		var p store.Profile
		if err := rows.Scan(&p.Name, &p.Spec); err != nil {
			panic(fmt.Sprintf("postgres: scan profile: %v", err))
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate profiles: %v", err))
	}
	return out
}

// Profile returns the profile with the given name, and whether it was found.
func (s *Store) Profile(name string) (store.Profile, bool) {
	var p store.Profile
	err := s.pool.QueryRow(bg(),
		`SELECT name, spec FROM profiles WHERE name = $1`, name).Scan(&p.Name, &p.Spec)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Profile{}, false
	}
	if err != nil {
		panic(fmt.Sprintf("postgres: query profile %q: %v", name, err))
	}
	return p, true
}

// CreateProfile inserts p into the catalog. It returns an error if a profile
// with the same name already exists (the primary-key conflict).
func (s *Store) CreateProfile(p store.Profile) error {
	tag, err := s.pool.Exec(bg(),
		`INSERT INTO profiles (name, spec) VALUES ($1, $2)
		 ON CONFLICT (name) DO NOTHING`, p.Name, p.Spec)
	if err != nil {
		return fmt.Errorf("postgres: insert profile %q: %w", p.Name, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: profile %q already exists", p.Name)
	}
	return nil
}

// UpdateProfile replaces the spec of the profile named p.Name. It returns an
// error if no profile has that name.
func (s *Store) UpdateProfile(p store.Profile) error {
	tag, err := s.pool.Exec(bg(),
		`UPDATE profiles SET spec = $2 WHERE name = $1`, p.Name, p.Spec)
	if err != nil {
		return fmt.Errorf("postgres: update profile %q: %w", p.Name, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: profile %q not found", p.Name)
	}
	return nil
}

// DeleteProfile removes the profile with the given name. It returns an error
// if no profile has that name.
func (s *Store) DeleteProfile(name string) error {
	tag, err := s.pool.Exec(bg(), `DELETE FROM profiles WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("postgres: delete profile %q: %w", name, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: profile %q not found", name)
	}
	return nil
}

// Adapters returns every enrollment protocol adapter.
func (s *Store) Adapters() []store.Adapter {
	rows, err := s.pool.Query(bg(),
		`SELECT name, kind, endpoint, profile, enabled, challenges, gpo_template
		 FROM adapters ORDER BY name`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query adapters: %v", err))
	}
	defer rows.Close()

	out := make([]store.Adapter, 0)
	for rows.Next() {
		var a store.Adapter
		if err := rows.Scan(&a.Name, &a.Kind, &a.Endpoint, &a.Profile, &a.Enabled, &a.Challenges, &a.GPOTemplate); err != nil {
			panic(fmt.Sprintf("postgres: scan adapter: %v", err))
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate adapters: %v", err))
	}
	return out
}

// SetAdapterEnabled sets the enabled state of the adapter with the given name
// and returns the updated adapter. It returns an error if no adapter has that
// name.
func (s *Store) SetAdapterEnabled(name string, enabled bool) (store.Adapter, error) {
	var a store.Adapter
	err := s.pool.QueryRow(bg(),
		`UPDATE adapters SET enabled = $2 WHERE name = $1
		 RETURNING name, kind, endpoint, profile, enabled, challenges, gpo_template`,
		name, enabled).
		Scan(&a.Name, &a.Kind, &a.Endpoint, &a.Profile, &a.Enabled, &a.Challenges, &a.GPOTemplate)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Adapter{}, fmt.Errorf("postgres: adapter %q not found", name)
	}
	if err != nil {
		return store.Adapter{}, fmt.Errorf("postgres: set adapter %q enabled: %w", name, err)
	}
	return a, nil
}

// Audit returns every audit event ordered by append sequence.
func (s *Store) Audit() []store.AuditEvent {
	rows, err := s.pool.Query(bg(),
		`SELECT id, at, kind, summary, target_kind, target_path, actor_kind, actor_cn,
		        actor_serial, key_id, via, tool, request_digest, outcome, approval_id,
		        approver_serial, chain_version, prev_hash, hash
		 FROM audit_events ORDER BY seq`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query audit_events: %v", err))
	}
	defer rows.Close()

	out := make([]store.AuditEvent, 0)
	for rows.Next() {
		var e store.AuditEvent
		if err := rows.Scan(&e.ID, &e.At, &e.Kind, &e.Summary, &e.TargetKind, &e.TargetPath,
			&e.ActorKind, &e.ActorCN, &e.ActorSerial, &e.KeyID, &e.Via, &e.Tool, &e.RequestDigest,
			&e.Outcome, &e.ApprovalID, &e.ApproverSerial, &e.ChainVersion, &e.PrevHash, &e.Hash); err != nil {
			panic(fmt.Sprintf("postgres: scan audit event: %v", err))
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate audit_events: %v", err))
	}
	return out
}

// Enrollments returns every enrollment request.
func (s *Store) Enrollments() []store.Enrollment {
	rows, err := s.pool.Query(bg(), selectEnrollment+` ORDER BY requested_at, id`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query enrollments: %v", err))
	}
	defer rows.Close()

	out := make([]store.Enrollment, 0)
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			panic(fmt.Sprintf("postgres: scan enrollment: %v", err))
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate enrollments: %v", err))
	}
	return out
}

// Enrollment returns the enrollment request with the given ID, and whether it
// was found.
func (s *Store) Enrollment(id string) (store.Enrollment, bool) {
	row := s.pool.QueryRow(bg(), selectEnrollment+` WHERE id = $1`, id)
	e, err := scanEnrollment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Enrollment{}, false
	}
	if err != nil {
		panic(fmt.Sprintf("postgres: query enrollment %q: %v", id, err))
	}
	return e, true
}

// AddEnrollment appends a new enrollment request.
func (s *Store) AddEnrollment(e store.Enrollment) {
	if _, err := s.pool.Exec(bg(), insertEnrollment, enrollmentArgs(e)...); err != nil {
		panic(fmt.Sprintf("postgres: insert enrollment %q: %v", e.ID, err))
	}
}

// UpdateEnrollment reads the enrollment with the given ID, applies mutate to it
// in Go, and writes every column back, all in one transaction. It returns an
// error if no enrollment has that ID.
func (s *Store) UpdateEnrollment(id string, mutate func(*store.Enrollment)) error {
	ctx := bg()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin enrollment update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, selectEnrollment+` WHERE id = $1`, id)
	e, err := scanEnrollment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: enrollment %q not found", id)
	}
	if err != nil {
		return fmt.Errorf("postgres: load enrollment %q: %w", id, err)
	}

	mutate(&e)

	if _, err := tx.Exec(ctx, updateEnrollment, updateEnrollmentArgs(e)...); err != nil {
		return fmt.Errorf("postgres: update enrollment %q: %w", id, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit enrollment update: %w", err)
	}
	return nil
}

// AddAuditEvent appends e to the hash-chained audit log: it reads the most
// recent event's hash as prev_hash (empty for the first event), computes the
// new hash, persists the row, and returns the stored event. The read and insert
// run in one transaction that first takes a transaction-scoped advisory lock on
// the audit chain, so concurrent appends serialize on that lock instead of both
// reading the same prev_hash and forking the chain; the lock releases
// automatically on commit or rollback.
func (s *Store) AddAuditEvent(e store.AuditEvent) store.AuditEvent {
	ctx := bg()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		panic(fmt.Sprintf("postgres: begin audit append: %v", err))
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditChainLockKey); err != nil {
		panic(fmt.Sprintf("postgres: lock audit chain: %v", err))
	}

	var prev string
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		panic(fmt.Sprintf("postgres: read last audit hash: %v", err))
	}

	e.ChainVersion = store.AuditChainVersion
	e.PrevHash = prev
	e.Hash = store.HashEvent(prev, e)

	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_events (id, at, kind, summary, target_kind, target_path, actor_kind,
		   actor_cn, actor_serial, key_id, via, tool, request_digest, outcome, approval_id,
		   approver_serial, chain_version, prev_hash, hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
		e.ID, e.At, e.Kind, e.Summary, e.TargetKind, e.TargetPath, e.ActorKind, e.ActorCN,
		e.ActorSerial, e.KeyID, e.Via, e.Tool, e.RequestDigest, e.Outcome, e.ApprovalID,
		e.ApproverSerial, e.ChainVersion, e.PrevHash, e.Hash); err != nil {
		panic(fmt.Sprintf("postgres: insert audit event %q: %v", e.ID, err))
	}
	if err := tx.Commit(ctx); err != nil {
		panic(fmt.Sprintf("postgres: commit audit append: %v", err))
	}
	return e
}

// OperatorCredentials returns every issued operator credential, oldest first.
func (s *Store) OperatorCredentials() []store.OperatorCredential {
	rows, err := s.pool.Query(bg(),
		`SELECT common_name, serial_hex, level, not_after, revoked
		 FROM operator_credentials ORDER BY issued_at, serial_hex`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query operator_credentials: %v", err))
	}
	defer rows.Close()

	out := make([]store.OperatorCredential, 0)
	for rows.Next() {
		var c store.OperatorCredential
		if err := rows.Scan(&c.CommonName, &c.SerialHex, &c.Level, &c.NotAfter, &c.Revoked); err != nil {
			panic(fmt.Sprintf("postgres: scan operator credential: %v", err))
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate operator_credentials: %v", err))
	}
	return out
}

// AddOperatorCredential records a newly issued operator credential. A serial
// collision is a hard error (serials are unique per operator CA), surfaced via
// the store's panic-on-error contract.
func (s *Store) AddOperatorCredential(c store.OperatorCredential) {
	if _, err := s.pool.Exec(bg(),
		`INSERT INTO operator_credentials (serial_hex, common_name, level, not_after, revoked)
		 VALUES ($1, $2, $3, $4, $5)`,
		c.SerialHex, c.CommonName, c.Level, c.NotAfter, c.Revoked); err != nil {
		panic(fmt.Sprintf("postgres: insert operator credential %q: %v", c.SerialHex, err))
	}
}

// MarkOperatorCredentialRevoked flags the credential with the given hex serial
// as revoked. It returns an error if no credential has that serial.
func (s *Store) MarkOperatorCredentialRevoked(serialHex string) error {
	tag, err := s.pool.Exec(bg(),
		`UPDATE operator_credentials SET revoked = true WHERE serial_hex = $1`, serialHex)
	if err != nil {
		return fmt.Errorf("postgres: revoke operator credential %q: %w", serialHex, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: operator credential %q not found", serialHex)
	}
	return nil
}

// SeedIfEmpty inserts the given catalog only when every target table is empty,
// so restarts never duplicate or clobber live data. The check and the inserts
// run in one transaction.
func (s *Store) SeedIfEmpty(ctx context.Context, nodes []store.Node, profiles []store.Profile, adapters []store.Adapter, audit []store.AuditEvent, enrollments []store.Enrollment) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin seed: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	empty, err := allTablesEmpty(ctx, tx)
	if err != nil {
		return err
	}
	if !empty {
		return tx.Commit(ctx)
	}

	for _, n := range nodes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO nodes (name, endpoint, role, admin_cert, admin_key, ca_cert)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			n.Name, n.Endpoint, n.Role, n.AdminCert, n.AdminKey, n.CACert); err != nil {
			return fmt.Errorf("postgres: seed node %q: %w", n.Name, err)
		}
	}
	for _, p := range profiles {
		if _, err := tx.Exec(ctx,
			`INSERT INTO profiles (name, spec) VALUES ($1, $2)`,
			p.Name, p.Spec); err != nil {
			return fmt.Errorf("postgres: seed profile %q: %w", p.Name, err)
		}
	}
	for _, a := range adapters {
		if _, err := tx.Exec(ctx,
			`INSERT INTO adapters (name, kind, endpoint, profile, enabled, challenges, gpo_template)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			a.Name, a.Kind, a.Endpoint, a.Profile, a.Enabled, nonNil(a.Challenges), a.GPOTemplate); err != nil {
			return fmt.Errorf("postgres: seed adapter %q: %w", a.Name, err)
		}
	}
	for _, ev := range audit {
		if _, err := tx.Exec(ctx,
			`INSERT INTO audit_events (id, at, kind, summary, target_kind, target_path, prev_hash, hash)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			ev.ID, ev.At, ev.Kind, ev.Summary, ev.TargetKind, ev.TargetPath, ev.PrevHash, ev.Hash); err != nil {
			return fmt.Errorf("postgres: seed audit event %q: %w", ev.ID, err)
		}
	}
	for _, en := range enrollments {
		if _, err := tx.Exec(ctx, insertEnrollment, enrollmentArgs(en)...); err != nil {
			return fmt.Errorf("postgres: seed enrollment %q: %w", en.ID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit seed: %w", err)
	}
	return nil
}

// allTablesEmpty reports whether every seedable table has zero rows.
func allTablesEmpty(ctx context.Context, tx pgx.Tx) (bool, error) {
	var total int
	err := tx.QueryRow(ctx,
		`SELECT (SELECT count(*) FROM nodes)
		      + (SELECT count(*) FROM profiles)
		      + (SELECT count(*) FROM adapters)
		      + (SELECT count(*) FROM audit_events)
		      + (SELECT count(*) FROM enrollments)`).Scan(&total)
	if err != nil {
		return false, fmt.Errorf("postgres: count for seed guard: %w", err)
	}
	return total == 0, nil
}

// nonNil replaces a nil slice with an empty one so a NOT NULL text[] column
// never receives NULL (the store's zero value for an absent list is nil).
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// selectEnrollment is the shared column list for reading an enrollment; append
// a WHERE/ORDER BY clause as needed.
const selectEnrollment = `SELECT id, proposed_name, role, parent_cn, address, status,
	attestation_summary, attestation_node_id, csr_key_type, csr_subject_cn,
	requested_at, rejection_reason, admitted_node_name, kind, pinned_key_sha256,
	attestation_ok, profile FROM enrollments`

const insertEnrollment = `INSERT INTO enrollments (
	id, proposed_name, role, parent_cn, address, status,
	attestation_summary, attestation_node_id, csr_key_type, csr_subject_cn,
	requested_at, rejection_reason, admitted_node_name, kind, pinned_key_sha256,
	attestation_ok, profile
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`

const updateEnrollment = `UPDATE enrollments SET
	proposed_name=$2, role=$3, parent_cn=$4, address=$5, status=$6,
	attestation_summary=$7, attestation_node_id=$8, csr_key_type=$9, csr_subject_cn=$10,
	requested_at=$11, rejection_reason=$12, admitted_node_name=$13, kind=$14,
	pinned_key_sha256=$15, attestation_ok=$16, profile=$17
WHERE id=$1`

// enrollmentArgs lays out an Enrollment in the column order used by both the
// insert and update statements.
func enrollmentArgs(e store.Enrollment) []any {
	return []any{
		e.ID, e.ProposedName, e.Role, e.ParentCN, e.Address, e.Status,
		e.AttestationSummary, e.AttestationNodeID, e.CSRKeyType, e.CSRSubjectCN,
		e.RequestedAt, e.RejectionReason, e.AdmittedNodeName, e.Kind, e.PinnedKeySHA256,
		e.AttestationOK, e.Profile,
	}
}

// updateEnrollmentArgs mirrors enrollmentArgs; the id stays $1 as the WHERE key
// while the remaining columns are rewritten.
func updateEnrollmentArgs(e store.Enrollment) []any {
	return enrollmentArgs(e)
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows, letting scanEnrollment
// serve the single-row and iterating callers.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanEnrollment reads one enrollment row in the selectEnrollment column order.
func scanEnrollment(r rowScanner) (store.Enrollment, error) {
	var e store.Enrollment
	err := r.Scan(
		&e.ID, &e.ProposedName, &e.Role, &e.ParentCN, &e.Address, &e.Status,
		&e.AttestationSummary, &e.AttestationNodeID, &e.CSRKeyType, &e.CSRSubjectCN,
		&e.RequestedAt, &e.RejectionReason, &e.AdmittedNodeName, &e.Kind, &e.PinnedKeySHA256,
		&e.AttestationOK, &e.Profile,
	)
	return e, err
}

const selectMcpKey = `SELECT id, token_hash, label, client_name, operator_serial, operator_cn,
  operator_cert_der, level_ceiling, created_at, last_used_at, revoked_at, expires_at FROM mcp_keys`

func scanMcpKey(row pgx.Row) (store.McpKey, error) {
	var (
		k                          store.McpKey
		lastUsed, revoked, expires *time.Time
	)
	if err := row.Scan(&k.ID, &k.TokenHash, &k.Label, &k.ClientName, &k.OperatorSerial, &k.OperatorCN,
		&k.OperatorCertDER, &k.LevelCeiling, &k.CreatedAt, &lastUsed, &revoked, &expires); err != nil {
		return store.McpKey{}, err
	}
	k.CreatedAt = k.CreatedAt.UTC()
	k.LastUsedAt = timeOrZero(lastUsed)
	k.RevokedAt = timeOrZero(revoked)
	k.ExpiresAt = timeOrZero(expires)
	return k, nil
}

func timeOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// AddMcpKey records a newly minted MCP key. A duplicate id or token hash is a
// hard error, surfaced via the store's panic-on-error contract.
func (s *Store) AddMcpKey(k store.McpKey) {
	if _, err := s.pool.Exec(bg(),
		`INSERT INTO mcp_keys (id, token_hash, label, client_name, operator_serial, operator_cn,
		   operator_cert_der, level_ceiling, created_at, last_used_at, revoked_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		k.ID, k.TokenHash, k.Label, k.ClientName, k.OperatorSerial, k.OperatorCN, k.OperatorCertDER,
		k.LevelCeiling, k.CreatedAt, nullTime(k.LastUsedAt), nullTime(k.RevokedAt), nullTime(k.ExpiresAt)); err != nil {
		panic(fmt.Sprintf("postgres: insert mcp key %q: %v", k.ID, err))
	}
}

// McpKeyByHash returns the key whose token_hash is hash, and whether it was
// found.
func (s *Store) McpKeyByHash(hash string) (store.McpKey, bool) {
	return s.oneMcpKey(selectMcpKey+` WHERE token_hash = $1`, hash)
}

// McpKey returns the key with the given ID, and whether it was found.
func (s *Store) McpKey(id string) (store.McpKey, bool) {
	return s.oneMcpKey(selectMcpKey+` WHERE id = $1`, id)
}

func (s *Store) oneMcpKey(query, arg string) (store.McpKey, bool) {
	k, err := scanMcpKey(s.pool.QueryRow(bg(), query, arg))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.McpKey{}, false
	}
	if err != nil {
		panic(fmt.Sprintf("postgres: query mcp key: %v", err))
	}
	return k, true
}

// McpKeys returns every MCP key, newest first.
func (s *Store) McpKeys() []store.McpKey {
	rows, err := s.pool.Query(bg(), selectMcpKey+` ORDER BY created_at DESC, id`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query mcp_keys: %v", err))
	}
	defer rows.Close()

	out := make([]store.McpKey, 0)
	for rows.Next() {
		k, err := scanMcpKey(rows)
		if err != nil {
			panic(fmt.Sprintf("postgres: scan mcp key: %v", err))
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate mcp_keys: %v", err))
	}
	return out
}

// RevokeMcpKey stamps revoked_at on the key, keeping the first revocation
// time of an already revoked key.
func (s *Store) RevokeMcpKey(id string, at time.Time) (store.McpKey, error) {
	k, err := scanMcpKey(s.pool.QueryRow(bg(),
		`UPDATE mcp_keys SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1
		 RETURNING id, token_hash, label, client_name, operator_serial, operator_cn,
		   operator_cert_der, level_ceiling, created_at, last_used_at, revoked_at, expires_at`, id, at))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.McpKey{}, fmt.Errorf("postgres: mcp key %q not found", id)
	}
	if err != nil {
		return store.McpKey{}, fmt.Errorf("postgres: revoke mcp key %q: %w", id, err)
	}
	return k, nil
}

// TouchMcpKey sets last_used_at on the key and reports whether it was the
// key's first use. The previous value is read in the same statement, so two
// concurrent first requests cannot both report first use.
func (s *Store) TouchMcpKey(id string, at time.Time) bool {
	var prev *time.Time
	err := s.pool.QueryRow(bg(),
		`UPDATE mcp_keys k SET last_used_at = $2 FROM (SELECT id, last_used_at FROM mcp_keys WHERE id = $1 FOR UPDATE) old
		 WHERE k.id = old.id RETURNING old.last_used_at`, id, at).Scan(&prev)
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	if err != nil {
		panic(fmt.Sprintf("postgres: touch mcp key %q: %v", id, err))
	}
	return prev == nil
}

// AddOAuthRequest records a pending authorization request and drops expired
// OAuth state, so abandoned logins do not accumulate.
func (s *Store) AddOAuthRequest(r store.OAuthRequest) {
	ctx := bg()
	if _, err := s.pool.Exec(ctx, `DELETE FROM oauth_requests WHERE expires_at < now()`); err != nil {
		panic(fmt.Sprintf("postgres: purge oauth_requests: %v", err))
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM oauth_codes WHERE expires_at < now()`); err != nil {
		panic(fmt.Sprintf("postgres: purge oauth_codes: %v", err))
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO oauth_requests (id, client_id, client_name, redirect_uri, state, code_challenge, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		r.ID, r.ClientID, r.ClientName, r.RedirectURI, r.State, r.CodeChallenge, r.ExpiresAt); err != nil {
		panic(fmt.Sprintf("postgres: insert oauth request: %v", err))
	}
}

const oauthRequestCols = `id, client_id, client_name, redirect_uri, state, code_challenge, expires_at`

func (s *Store) oauthRequest(query, id string) (store.OAuthRequest, bool) {
	var r store.OAuthRequest
	err := s.pool.QueryRow(bg(), query, id).
		Scan(&r.ID, &r.ClientID, &r.ClientName, &r.RedirectURI, &r.State, &r.CodeChallenge, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.OAuthRequest{}, false
	}
	if err != nil {
		panic(fmt.Sprintf("postgres: query oauth request: %v", err))
	}
	r.ExpiresAt = r.ExpiresAt.UTC()
	return r, true
}

// OAuthRequest returns the pending request with the given ID.
func (s *Store) OAuthRequest(id string) (store.OAuthRequest, bool) {
	return s.oauthRequest(`SELECT `+oauthRequestCols+` FROM oauth_requests WHERE id = $1`, id)
}

// TakeOAuthRequest deletes and returns the pending request with the given ID
// in one statement, so consent can be given at most once.
func (s *Store) TakeOAuthRequest(id string) (store.OAuthRequest, bool) {
	return s.oauthRequest(`DELETE FROM oauth_requests WHERE id = $1 RETURNING `+oauthRequestCols, id)
}

// AddOAuthCode records an approved authorization code.
func (s *Store) AddOAuthCode(c store.OAuthCode) {
	if _, err := s.pool.Exec(bg(),
		`INSERT INTO oauth_codes (code_hash, client_id, client_name, redirect_uri, code_challenge,
		   operator_cn, operator_serial, operator_cert_der, level_ceiling, label, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		c.CodeHash, c.ClientID, c.ClientName, c.RedirectURI, c.CodeChallenge, c.OperatorCN,
		c.OperatorSerial, c.OperatorCertDER, c.LevelCeiling, c.Label, c.ExpiresAt); err != nil {
		panic(fmt.Sprintf("postgres: insert oauth code: %v", err))
	}
}

// TakeOAuthCode deletes and returns the code with the given hash in one
// statement, so a code can be redeemed at most once.
func (s *Store) TakeOAuthCode(hash string) (store.OAuthCode, bool) {
	var c store.OAuthCode
	err := s.pool.QueryRow(bg(),
		`DELETE FROM oauth_codes WHERE code_hash = $1 RETURNING code_hash, client_id, client_name,
		   redirect_uri, code_challenge, operator_cn, operator_serial, operator_cert_der,
		   level_ceiling, label, expires_at`, hash).
		Scan(&c.CodeHash, &c.ClientID, &c.ClientName, &c.RedirectURI, &c.CodeChallenge, &c.OperatorCN,
			&c.OperatorSerial, &c.OperatorCertDER, &c.LevelCeiling, &c.Label, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.OAuthCode{}, false
	}
	if err != nil {
		panic(fmt.Sprintf("postgres: take oauth code: %v", err))
	}
	c.ExpiresAt = c.ExpiresAt.UTC()
	return c, true
}

const approvalCols = `id, tool, summary, request_digest, requested_by_cn, requested_by_serial, key_id,
  required_level, created_at, expires_at, status, decided_by_cn, decided_by_serial, decided_by_level,
  decided_at, used_at`

func scanApproval(row pgx.Row) (store.Approval, error) {
	var (
		a            store.Approval
		decided, use *time.Time
	)
	if err := row.Scan(&a.ID, &a.Tool, &a.Summary, &a.RequestDigest, &a.RequestedByCN, &a.RequestedBySerial,
		&a.KeyID, &a.RequiredLevel, &a.CreatedAt, &a.ExpiresAt, &a.Status, &a.DecidedByCN, &a.DecidedBySerial,
		&a.DecidedByLevel, &decided, &use); err != nil {
		return store.Approval{}, err
	}
	a.CreatedAt = a.CreatedAt.UTC()
	a.ExpiresAt = a.ExpiresAt.UTC()
	a.DecidedAt = timeOrZero(decided)
	a.UsedAt = timeOrZero(use)
	return a, nil
}

// AddApproval records a newly raised approval.
func (s *Store) AddApproval(a store.Approval) {
	if _, err := s.pool.Exec(bg(),
		`INSERT INTO approvals (`+approvalCols+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		a.ID, a.Tool, a.Summary, a.RequestDigest, a.RequestedByCN, a.RequestedBySerial, a.KeyID, a.RequiredLevel,
		a.CreatedAt, a.ExpiresAt, a.Status, a.DecidedByCN, a.DecidedBySerial, a.DecidedByLevel,
		nullTime(a.DecidedAt), nullTime(a.UsedAt)); err != nil {
		panic(fmt.Sprintf("postgres: insert approval %q: %v", a.ID, err))
	}
}

// oneApproval runs a query returning at most one approval row. No row means
// the approval is missing or the statement's condition did not hold.
func (s *Store) oneApproval(query string, args ...any) (store.Approval, bool) {
	a, err := scanApproval(s.pool.QueryRow(bg(), query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Approval{}, false
	}
	if err != nil {
		panic(fmt.Sprintf("postgres: approval: %v", err))
	}
	return a, true
}

// Approval returns the approval with the given ID, and whether it was found.
func (s *Store) Approval(id string) (store.Approval, bool) {
	return s.oneApproval(`SELECT `+approvalCols+` FROM approvals WHERE id = $1`, id)
}

// Approvals returns every approval, newest first.
func (s *Store) Approvals() []store.Approval {
	rows, err := s.pool.Query(bg(), `SELECT `+approvalCols+` FROM approvals ORDER BY created_at DESC, id`)
	if err != nil {
		panic(fmt.Sprintf("postgres: query approvals: %v", err))
	}
	defer rows.Close()

	out := make([]store.Approval, 0)
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			panic(fmt.Sprintf("postgres: scan approval: %v", err))
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		panic(fmt.Sprintf("postgres: iterate approvals: %v", err))
	}
	return out
}

// DecideApproval records the decision on a pending, unexpired approval in a
// single conditional UPDATE.
func (s *Store) DecideApproval(id, status, deciderCN, deciderSerial, deciderLevel string, at time.Time) (store.Approval, bool) {
	return s.oneApproval(
		`UPDATE approvals SET status = $2, decided_by_cn = $3, decided_by_serial = $4, decided_by_level = $5, decided_at = $6
		 WHERE id = $1 AND status = 'pending' AND expires_at > $6 RETURNING `+approvalCols,
		id, status, deciderCN, deciderSerial, deciderLevel, at)
}

// UseApproval marks an approved, unexpired approval used in a single
// conditional UPDATE.
func (s *Store) UseApproval(id string, at time.Time) (store.Approval, bool) {
	return s.oneApproval(
		`UPDATE approvals SET status = 'used', used_at = $2
		 WHERE id = $1 AND status = 'approved' AND expires_at > $2 RETURNING `+approvalCols,
		id, at)
}
