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

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/jackc/pgx/v5"
)

var _ store.Bootstrap = (*Store)(nil)

// BootstrapState returns the first-run latch.
func (s *Store) BootstrapState(ctx context.Context) (store.BootstrapState, error) {
	var (
		st     store.BootstrapState
		closed *time.Time
	)
	err := s.pool.QueryRow(ctx, `SELECT closed_at, closed_by_serial, closed_by_cn, closed_by_issuer_sha256 FROM bootstrap_state WHERE id`).
		Scan(&closed, &st.ClosedBySerial, &st.ClosedByCN, &st.ClosedByIssuerSHA256)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.BootstrapState{}, nil
	}
	if err != nil {
		return store.BootstrapState{}, fmt.Errorf("postgres: read bootstrap state: %w", err)
	}
	st.ClosedAt = timeOrZero(closed)
	return st, nil
}

// CloseBootstrap closes the latch if it is open, and in the same
// transaction ends every session and deletes every token.
func (s *Store) CloseBootstrap(ctx context.Context, by store.BootstrapState) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("postgres: begin closing first run: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `INSERT INTO bootstrap_state (id, closed_at, closed_by_serial, closed_by_cn, closed_by_issuer_sha256)
		VALUES (true, $1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET closed_at = excluded.closed_at, closed_by_serial = excluded.closed_by_serial,
		  closed_by_cn = excluded.closed_by_cn, closed_by_issuer_sha256 = excluded.closed_by_issuer_sha256
		WHERE bootstrap_state.closed_at IS NULL`,
		by.ClosedAt, by.ClosedBySerial, by.ClosedByCN, by.ClosedByIssuerSHA256)
	if err != nil {
		return false, fmt.Errorf("postgres: close first run: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE bootstrap_sessions SET ended_at = $1, ended_reason = $2 WHERE ended_at IS NULL`,
		by.ClosedAt, store.SessionEndedClosed); err != nil {
		return false, fmt.Errorf("postgres: end bootstrap sessions: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM bootstrap_tokens`); err != nil {
		return false, fmt.Errorf("postgres: delete bootstrap tokens: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("postgres: commit closing first run: %w", err)
	}
	return true, nil
}

// lockOpen locks the latch row for the transaction and returns
// ErrBootstrapClosed when first run is closed, so a first-run write and the
// latch closing can't interleave.
func lockOpen(ctx context.Context, tx pgx.Tx) error {
	var closed *time.Time
	err := tx.QueryRow(ctx, `SELECT closed_at FROM bootstrap_state WHERE id FOR UPDATE`).Scan(&closed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("postgres: read bootstrap state: %w", err)
	}
	if closed != nil {
		return store.ErrBootstrapClosed
	}
	return nil
}

// IssueBootstrapToken stores t and marks every other unused token used.
func (s *Store) IssueBootstrapToken(ctx context.Context, t store.BootstrapToken) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin token issue: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockOpen(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE bootstrap_tokens SET used_at = $1 WHERE used_at IS NULL`, t.CreatedAt); err != nil {
		return fmt.Errorf("postgres: retire earlier bootstrap tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bootstrap_tokens (token_hash, created_at, expires_at) VALUES ($1, $2, $3)`,
		t.Hash, t.CreatedAt, t.ExpiresAt); err != nil {
		return fmt.Errorf("postgres: store bootstrap token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit bootstrap token: %w", err)
	}
	return nil
}

// LiveBootstrapToken returns the newest unused, unexpired token.
func (s *Store) LiveBootstrapToken(ctx context.Context, now time.Time) (store.BootstrapToken, bool, error) {
	var t store.BootstrapToken
	err := s.pool.QueryRow(ctx, `SELECT token_hash, created_at, expires_at FROM bootstrap_tokens
		WHERE used_at IS NULL AND expires_at > $1 ORDER BY id DESC LIMIT 1`, now).Scan(&t.Hash, &t.CreatedAt, &t.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.BootstrapToken{}, false, nil
	}
	if err != nil {
		return store.BootstrapToken{}, false, fmt.Errorf("postgres: read bootstrap token: %w", err)
	}
	t.CreatedAt, t.ExpiresAt = t.CreatedAt.UTC(), t.ExpiresAt.UTC()
	return t, true, nil
}

// StartBootstrapSession consumes the token and starts the session in one
// transaction. The conditional UPDATE takes the token row's lock, so of two
// concurrent starts exactly one sees the token unused.
func (s *Store) StartBootstrapSession(ctx context.Context, tokenHash string, bs store.BootstrapSession, now time.Time) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("postgres: begin session start: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockOpen(ctx, tx); err != nil {
		if errors.Is(err, store.ErrBootstrapClosed) {
			return false, nil
		}
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE bootstrap_tokens SET used_at = $2
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2`, tokenHash, now)
	if err != nil {
		return false, fmt.Errorf("postgres: consume bootstrap token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE bootstrap_sessions SET ended_at = $1, ended_reason = $2 WHERE ended_at IS NULL`,
		now, store.SessionEndedSuperseded); err != nil {
		return false, fmt.Errorf("postgres: end earlier bootstrap sessions: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bootstrap_sessions (session_hash, created_at, last_used_at, expires_at) VALUES ($1, $2, $3, $4)`,
		bs.Hash, bs.CreatedAt, bs.LastUsedAt, bs.ExpiresAt); err != nil {
		return false, fmt.Errorf("postgres: store bootstrap session: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("postgres: commit bootstrap session: %w", err)
	}
	return true, nil
}

// BootstrapSession returns the session with the given hash.
func (s *Store) BootstrapSession(ctx context.Context, hash string) (store.BootstrapSession, bool, error) {
	var (
		bs    store.BootstrapSession
		ended *time.Time
	)
	err := s.pool.QueryRow(ctx, `SELECT session_hash, created_at, last_used_at, expires_at, ended_at, ended_reason
		FROM bootstrap_sessions WHERE session_hash = $1`, hash).
		Scan(&bs.Hash, &bs.CreatedAt, &bs.LastUsedAt, &bs.ExpiresAt, &ended, &bs.EndedReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.BootstrapSession{}, false, nil
	}
	if err != nil {
		return store.BootstrapSession{}, false, fmt.Errorf("postgres: read bootstrap session: %w", err)
	}
	bs.CreatedAt, bs.LastUsedAt, bs.ExpiresAt = bs.CreatedAt.UTC(), bs.LastUsedAt.UTC(), bs.ExpiresAt.UTC()
	bs.EndedAt = timeOrZero(ended)
	return bs, true, nil
}

// TouchBootstrapSession records a use of a live session.
func (s *Store) TouchBootstrapSession(ctx context.Context, hash string, at time.Time) error {
	if _, err := s.pool.Exec(ctx, `UPDATE bootstrap_sessions SET last_used_at = $2 WHERE session_hash = $1 AND ended_at IS NULL`, hash, at); err != nil {
		return fmt.Errorf("postgres: touch bootstrap session: %w", err)
	}
	return nil
}

// EndBootstrapSession ends one session, keeping the first end.
func (s *Store) EndBootstrapSession(ctx context.Context, hash, reason string, at time.Time) error {
	if _, err := s.pool.Exec(ctx, `UPDATE bootstrap_sessions SET ended_at = $2, ended_reason = $3
		WHERE session_hash = $1 AND ended_at IS NULL`, hash, at, reason); err != nil {
		return fmt.Errorf("postgres: end bootstrap session: %w", err)
	}
	return nil
}

// EndBootstrapSessions ends every session not yet ended.
func (s *Store) EndBootstrapSessions(ctx context.Context, reason string, at time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE bootstrap_sessions SET ended_at = $1, ended_reason = $2 WHERE ended_at IS NULL`, at, reason)
	if err != nil {
		return 0, fmt.Errorf("postgres: end bootstrap sessions: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// HasLiveBootstrapSession reports whether a session is live at now.
func (s *Store) HasLiveBootstrapSession(ctx context.Context, now time.Time, idle time.Duration) (bool, error) {
	var live bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM bootstrap_sessions
		WHERE ended_at IS NULL AND expires_at > $1 AND last_used_at > $2)`, now, now.Add(-idle)).Scan(&live); err != nil {
		return false, fmt.Errorf("postgres: look for a live bootstrap session: %w", err)
	}
	return live, nil
}

// RegisterFirstRunOperatorCA retires the earlier registration, stores ca as
// active, stores its CRL and moves the trust version, in one transaction.
func (s *Store) RegisterFirstRunOperatorCA(ctx context.Context, ca store.OperatorCA, sessionHash string, crl *store.OperatorCRL, decide store.DecideCRL) error {
	mode := ca.OCSPMode
	if mode == "" {
		mode = store.OCSPModeAIA
	}
	registered := ca.RegisteredAt
	if registered.IsZero() {
		registered = time.Now().UTC()
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin operator CA registration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockOpen(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE operator_cas SET state = 'retired', retired_at = $2, retired_reason = $3, updated_at = clock_timestamp()
		WHERE state IN ('active', 'retiring') AND sha256 <> $1`, ca.SHA256, registered, store.RetiredSuperseded); err != nil {
		return fmt.Errorf("postgres: retire the earlier operator CA: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO operator_cas
		(cert_der, sha256, state, crl_source, crl_url, ocsp_mode, ocsp_url, acknowledgements, warnings,
		 registered_at, registered_by, confirmed_session_hash)
		VALUES ($1, $2, 'active', $3, $4, $5, nullif($6, ''), $7, $8, $9, $10, $11)
		ON CONFLICT (sha256) DO UPDATE SET cert_der = excluded.cert_der, state = 'active',
		  crl_source = excluded.crl_source, crl_url = excluded.crl_url, ocsp_mode = excluded.ocsp_mode, ocsp_url = excluded.ocsp_url,
		  acknowledgements = excluded.acknowledgements, warnings = excluded.warnings, registered_at = excluded.registered_at,
		  registered_by = excluded.registered_by, confirmed_session_hash = excluded.confirmed_session_hash,
		  retired_at = NULL, retired_reason = '', updated_at = clock_timestamp()`,
		ca.CertDER, ca.SHA256, ca.CRLSource, ca.CRLURL, mode, ca.OCSPURL,
		nonNil(ca.Acknowledgements), nonNil(ca.Warnings), registered, ca.RegisteredBy, sessionHash); err != nil {
		return fmt.Errorf("postgres: store operator CA %s: %w", ca.SHA256, err)
	}
	if crl != nil {
		if _, err := putCRLTx(ctx, tx, *crl, decide); err != nil {
			return err
		}
	}
	if err := bumpEpoch(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit operator CA registration: %w", err)
	}
	return nil
}

// ConfirmOperatorCA records the session that confirmed the operator CA.
func (s *Store) ConfirmOperatorCA(ctx context.Context, sha256, sessionHash string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE operator_cas SET confirmed_session_hash = $2 WHERE sha256 = $1`, sha256, sessionHash)
	if err != nil {
		return fmt.Errorf("postgres: confirm operator CA %s: %w", sha256, err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrOperatorCANotFound
	}
	return nil
}

// OperatorCAConfirmedBy returns the session hash that last confirmed the
// operator CA.
func (s *Store) OperatorCAConfirmedBy(ctx context.Context, sha256 string) (string, error) {
	var by *string
	err := s.pool.QueryRow(ctx, `SELECT confirmed_session_hash FROM operator_cas WHERE sha256 = $1`, sha256).Scan(&by)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", store.ErrOperatorCANotFound
	}
	if err != nil {
		return "", fmt.Errorf("postgres: read operator CA confirmation: %w", err)
	}
	if by == nil {
		return "", nil
	}
	return *by, nil
}

// RecordFirstAdmin upserts the first admin's credential.
func (s *Store) RecordFirstAdmin(ctx context.Context, c store.OperatorCredential, at time.Time) error {
	if _, err := s.pool.Exec(ctx, `INSERT INTO operator_credentials (serial_hex, common_name, level, not_after, revoked,
		  issuer_sha256, kind, email, full_name, leaf_sha256, first_seen_at)
		VALUES ($1, $2, $3, $4, false, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (issuer_sha256, serial_hex) DO UPDATE SET kind = excluded.kind, full_name = excluded.full_name,
		  email = excluded.email, common_name = excluded.common_name, level = excluded.level,
		  not_after = excluded.not_after, leaf_sha256 = excluded.leaf_sha256`,
		c.SerialHex, c.CommonName, c.Level, c.NotAfter, c.IssuerSHA256, store.OperatorCredentialFirstAdmin,
		c.Email, c.FullName, c.LeafSHA256, nullTime(at)); err != nil {
		return fmt.Errorf("postgres: record first admin %s/%s: %w", c.IssuerSHA256, c.SerialHex, err)
	}
	return nil
}

// RecordFirstUse stores c as first_admin unless it is already recorded.
func (s *Store) RecordFirstUse(ctx context.Context, c store.OperatorCredential, at time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `INSERT INTO operator_credentials (serial_hex, common_name, level, not_after, revoked,
		  issuer_sha256, kind, email, full_name, leaf_sha256, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, $4, false, $5, $6, $7, $8, $9, $10, $10)
		ON CONFLICT (issuer_sha256, serial_hex) DO NOTHING`,
		c.SerialHex, c.CommonName, c.Level, c.NotAfter, c.IssuerSHA256, store.OperatorCredentialFirstAdmin,
		c.Email, c.FullName, c.LeafSHA256, nullTime(at))
	if err != nil {
		return false, fmt.Errorf("postgres: record first use of %s/%s: %w", c.IssuerSHA256, c.SerialHex, err)
	}
	return tag.RowsAffected() == 1, nil
}

// FirstAdminCredentials returns every first_admin credential, oldest first.
func (s *Store) FirstAdminCredentials(ctx context.Context) ([]store.OperatorCredential, error) {
	rows, err := s.pool.Query(ctx, `SELECT common_name, serial_hex, level, not_after, revoked, issuer_sha256, kind, email, full_name, leaf_sha256
		FROM operator_credentials WHERE kind = $1 ORDER BY issued_at, issuer_sha256, serial_hex`, store.OperatorCredentialFirstAdmin)
	if err != nil {
		return nil, fmt.Errorf("postgres: query first admin credentials: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.OperatorCredential, error) {
		var c store.OperatorCredential
		err := row.Scan(&c.CommonName, &c.SerialHex, &c.Level, &c.NotAfter, &c.Revoked, &c.IssuerSHA256, &c.Kind, &c.Email, &c.FullName, &c.LeafSHA256)
		return c, err
	})
	if err != nil {
		return nil, fmt.Errorf("postgres: read first admin credentials: %w", err)
	}
	return out, nil
}

// ResetFirstRun clears the latch, deletes the sessions and tokens and
// retires every operator CA row, in one transaction. The denylist and
// operator_crls are left as they are.
func (s *Store) ResetFirstRun(ctx context.Context, at time.Time) (store.FirstRunReset, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.FirstRunReset{}, fmt.Errorf("postgres: begin first-run reset: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		r      store.FirstRunReset
		closed *time.Time
	)
	err = tx.QueryRow(ctx, `SELECT closed_at, closed_by_serial, closed_by_cn, closed_by_issuer_sha256 FROM bootstrap_state WHERE id FOR UPDATE`).
		Scan(&closed, &r.Previous.ClosedBySerial, &r.Previous.ClosedByCN, &r.Previous.ClosedByIssuerSHA256)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return store.FirstRunReset{}, fmt.Errorf("postgres: read bootstrap state: %w", err)
	}
	r.Previous.ClosedAt = timeOrZero(closed)
	if _, err := tx.Exec(ctx, `INSERT INTO bootstrap_state (id) VALUES (true)
		ON CONFLICT (id) DO UPDATE SET closed_at = NULL, closed_by_serial = '', closed_by_cn = '', closed_by_issuer_sha256 = ''`); err != nil {
		return store.FirstRunReset{}, fmt.Errorf("postgres: clear the first-run latch: %w", err)
	}
	tag, err := tx.Exec(ctx, `DELETE FROM bootstrap_sessions`)
	if err != nil {
		return store.FirstRunReset{}, fmt.Errorf("postgres: delete bootstrap sessions: %w", err)
	}
	r.Sessions = int(tag.RowsAffected())
	if tag, err = tx.Exec(ctx, `DELETE FROM bootstrap_tokens`); err != nil {
		return store.FirstRunReset{}, fmt.Errorf("postgres: delete bootstrap tokens: %w", err)
	}
	r.Tokens = int(tag.RowsAffected())
	if tag, err = tx.Exec(ctx, `UPDATE operator_cas SET state = 'retired', retired_at = $1, retired_reason = $2, updated_at = clock_timestamp()
		WHERE state <> 'retired'`, at, store.RetiredReset); err != nil {
		return store.FirstRunReset{}, fmt.Errorf("postgres: retire operator CAs: %w", err)
	}
	r.RetiredCAs = int(tag.RowsAffected())
	if err := tx.Commit(ctx); err != nil {
		return store.FirstRunReset{}, fmt.Errorf("postgres: commit first-run reset: %w", err)
	}
	return r, nil
}
