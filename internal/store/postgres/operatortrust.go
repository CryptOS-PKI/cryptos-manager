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
	"math/big"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var _ store.OperatorTrust = (*Store)(nil)

const selectOperatorCA = `SELECT sha256, cert_der, state, crl_source, crl_url, ocsp_mode, coalesce(ocsp_url, ''),
  acknowledgements, warnings, registered_at, registered_by, retired_at, retired_reason, updated_at FROM operator_cas`

// OperatorCAs returns every registered operator CA, oldest first.
func (s *Store) OperatorCAs(ctx context.Context) ([]store.OperatorCA, error) {
	rows, err := s.pool.Query(ctx, selectOperatorCA+` ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: query operator_cas: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.OperatorCA, error) {
		var (
			ca      store.OperatorCA
			retired *time.Time
		)
		if err := row.Scan(&ca.SHA256, &ca.CertDER, &ca.State, &ca.CRLSource, &ca.CRLURL, &ca.OCSPMode, &ca.OCSPURL,
			&ca.Acknowledgements, &ca.Warnings, &ca.RegisteredAt, &ca.RegisteredBy, &retired, &ca.RetiredReason, &ca.UpdatedAt); err != nil {
			return store.OperatorCA{}, err
		}
		ca.RetiredAt = timeOrZero(retired)
		ca.RegisteredAt = ca.RegisteredAt.UTC()
		ca.UpdatedAt = ca.UpdatedAt.UTC()
		return ca, nil
	})
	if err != nil {
		return nil, fmt.Errorf("postgres: read operator_cas: %w", err)
	}
	return out, nil
}

// AddOperatorCA stores a new operator CA row. The table's constraints refuse
// a second active or retiring row and an OCSP url mode with no URL.
func (s *Store) AddOperatorCA(ctx context.Context, ca store.OperatorCA) error {
	mode := ca.OCSPMode
	if mode == "" {
		mode = store.OCSPModeAIA
	}
	registered := ca.RegisteredAt
	if registered.IsZero() {
		registered = time.Now().UTC()
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO operator_cas
		(cert_der, sha256, state, crl_source, crl_url, ocsp_mode, ocsp_url, acknowledgements, warnings,
		 registered_at, registered_by, retired_at, retired_reason)
		VALUES ($1, $2, $3, $4, $5, $6, nullif($7, ''), $8, $9, $10, $11, $12, $13)`,
		ca.CertDER, ca.SHA256, ca.State, ca.CRLSource, ca.CRLURL, mode, ca.OCSPURL,
		nonNil(ca.Acknowledgements), nonNil(ca.Warnings), registered, ca.RegisteredBy,
		nullTime(ca.RetiredAt), ca.RetiredReason); err != nil {
		return fmt.Errorf("postgres: insert operator CA %s: %w", ca.SHA256, err)
	}
	return nil
}

// SetOperatorCAState moves an operator CA row to state. updated_at moves with
// it, which is what other replicas' trust poll notices.
func (s *Store) SetOperatorCAState(ctx context.Context, sha256, state, reason string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE operator_cas SET state = $2,
		retired_at = CASE WHEN $2 = 'retired' THEN $3::timestamptz ELSE retired_at END,
		retired_reason = CASE WHEN $2 = 'retired' THEN $4 ELSE retired_reason END,
		updated_at = clock_timestamp()
		WHERE sha256 = $1`, sha256, state, at, reason)
	if err != nil {
		return fmt.Errorf("postgres: set operator CA %s to %s: %w", sha256, state, err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrOperatorCANotFound
	}
	return nil
}

// OperatorCRLs returns every stored CRL and last attempt.
func (s *Store) OperatorCRLs(ctx context.Context) ([]store.OperatorCRL, error) {
	rows, err := s.pool.Query(ctx, `SELECT issuer_sha256, crl_der, crl_number::text, this_update, next_update,
		fetched_at, source, last_error, last_attempt_at FROM operator_crls ORDER BY issuer_sha256`)
	if err != nil {
		return nil, fmt.Errorf("postgres: query operator_crls: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanOperatorCRL)
	if err != nil {
		return nil, fmt.Errorf("postgres: read operator_crls: %w", err)
	}
	return out, nil
}

func scanOperatorCRL(row pgx.CollectableRow) (store.OperatorCRL, error) {
	var (
		c                                          store.OperatorCRL
		number                                     pgtype.Text
		thisUpdate, nextUpdate, fetched, attempted *time.Time
	)
	if err := row.Scan(&c.IssuerSHA256, &c.DER, &number, &thisUpdate, &nextUpdate, &fetched, &c.Source, &c.LastError, &attempted); err != nil {
		return store.OperatorCRL{}, err
	}
	if number.Valid {
		n, ok := new(big.Int).SetString(number.String, 10)
		if !ok {
			return store.OperatorCRL{}, fmt.Errorf("crl_number %q is not an integer", number.String)
		}
		c.Number = n
	}
	c.ThisUpdate, c.NextUpdate = timeOrZero(thisUpdate), timeOrZero(nextUpdate)
	c.FetchedAt, c.LastAttemptAt = timeOrZero(fetched), timeOrZero(attempted)
	return c, nil
}

// PutOperatorCRL stores c when decide accepts it. The stored row is locked
// for the decision, so the anti-rollback check and the write are one step.
func (s *Store) PutOperatorCRL(ctx context.Context, c store.OperatorCRL, decide store.DecideCRL) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("postgres: begin CRL write: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ok, err := putCRLTx(ctx, tx, c, decide)
	if err != nil || !ok {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("postgres: commit CRL for %s: %w", c.IssuerSHA256, err)
	}
	return true, nil
}

// putCRLTx is PutOperatorCRL inside tx: it locks the stored row, asks
// decide, and on acceptance writes c and bumps the revocation epoch.
func putCRLTx(ctx context.Context, tx pgx.Tx, c store.OperatorCRL, decide store.DecideCRL) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT issuer_sha256, crl_der, crl_number::text, this_update, next_update,
		fetched_at, source, last_error, last_attempt_at FROM operator_crls WHERE issuer_sha256 = $1 FOR UPDATE`, c.IssuerSHA256)
	if err != nil {
		return false, fmt.Errorf("postgres: read CRL for %s: %w", c.IssuerSHA256, err)
	}
	current, err := pgx.CollectRows(rows, scanOperatorCRL)
	if err != nil {
		return false, fmt.Errorf("postgres: read CRL for %s: %w", c.IssuerSHA256, err)
	}
	has := len(current) == 1 && current[0].DER != nil
	var cur store.OperatorCRL
	if len(current) == 1 {
		cur = current[0]
	}
	ok, err := decide(cur, has)
	if err != nil || !ok {
		return false, err
	}

	var number any
	if c.Number != nil {
		number = c.Number.String()
	}
	if _, err := tx.Exec(ctx, `INSERT INTO operator_crls
		(issuer_sha256, crl_der, crl_number, this_update, next_update, fetched_at, source, last_error, last_attempt_at)
		VALUES ($1, $2, $3::numeric, $4, $5, $6, $7, '', $6)
		ON CONFLICT (issuer_sha256) DO UPDATE SET crl_der = excluded.crl_der, crl_number = excluded.crl_number,
		  this_update = excluded.this_update, next_update = excluded.next_update, fetched_at = excluded.fetched_at,
		  source = excluded.source, last_error = '', last_attempt_at = excluded.last_attempt_at`,
		c.IssuerSHA256, c.DER, number, c.ThisUpdate, c.NextUpdate, nullTime(c.FetchedAt), c.Source); err != nil {
		return false, fmt.Errorf("postgres: store CRL for %s: %w", c.IssuerSHA256, err)
	}
	if err := bumpEpoch(ctx, tx); err != nil {
		return false, err
	}
	return true, nil
}

// RecordOperatorCRLAttempt records a failed refresh. The stored CRL, if any,
// stays the last good one.
func (s *Store) RecordOperatorCRLAttempt(ctx context.Context, issuerSHA256, lastError string, at time.Time) error {
	if _, err := s.pool.Exec(ctx, `INSERT INTO operator_crls (issuer_sha256, last_error, last_attempt_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (issuer_sha256) DO UPDATE SET last_error = excluded.last_error, last_attempt_at = excluded.last_attempt_at`,
		issuerSHA256, lastError, at); err != nil {
		return fmt.Errorf("postgres: record CRL attempt for %s: %w", issuerSHA256, err)
	}
	return nil
}

// OperatorDenylist returns every denylist entry.
func (s *Store) OperatorDenylist(ctx context.Context) ([]store.DenylistEntry, error) {
	rows, err := s.pool.Query(ctx, `SELECT issuer_sha256, serial_hex, reason, revoked_at, revoked_by_cn, revoked_by_serial, note
		FROM operator_denylist ORDER BY revoked_at, issuer_sha256, serial_hex`)
	if err != nil {
		return nil, fmt.Errorf("postgres: query operator_denylist: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.DenylistEntry, error) {
		var e store.DenylistEntry
		err := row.Scan(&e.IssuerSHA256, &e.SerialHex, &e.Reason, &e.RevokedAt, &e.RevokedByCN, &e.RevokedBySerial, &e.Note)
		e.RevokedAt = e.RevokedAt.UTC()
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("postgres: read operator_denylist: %w", err)
	}
	return out, nil
}

// AddOperatorDenylistEntry adds e and bumps the revocation epoch in the same
// transaction, so a replica that sees the new epoch also sees the entry.
func (s *Store) AddOperatorDenylistEntry(ctx context.Context, e store.DenylistEntry) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("postgres: begin denylist write: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	at := e.RevokedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	tag, err := tx.Exec(ctx, `INSERT INTO operator_denylist
		(issuer_sha256, serial_hex, reason, revoked_at, revoked_by_cn, revoked_by_serial, note)
		VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`,
		e.IssuerSHA256, e.SerialHex, e.Reason, at, e.RevokedByCN, e.RevokedBySerial, e.Note)
	if err != nil {
		return false, fmt.Errorf("postgres: insert denylist entry %s/%s: %w", e.IssuerSHA256, e.SerialHex, err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if err := bumpEpoch(ctx, tx); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("postgres: commit denylist entry: %w", err)
	}
	return true, nil
}

// OperatorTrustVersion reads the operator CA row count and newest change,
// and the revocation epoch, in one query.
func (s *Store) OperatorTrustVersion(ctx context.Context) (store.TrustVersion, error) {
	var v store.TrustVersion
	if err := s.pool.QueryRow(ctx, `SELECT
		(SELECT count(*)::text || ':' || coalesce(to_char(max(updated_at) AT TIME ZONE 'UTC', 'YYYYMMDDHH24MISSUS'), '') FROM operator_cas),
		coalesce((SELECT epoch FROM operator_revocation_epoch WHERE id), 0)`).Scan(&v.CAs, &v.Epoch); err != nil {
		return store.TrustVersion{}, fmt.Errorf("postgres: read trust version: %w", err)
	}
	return v, nil
}

// TryAdvisoryLock takes a session-level advisory lock on a connection held
// out of the pool until release, so the lock lives exactly as long as the
// holder wants it.
func (s *Store) TryAdvisoryLock(ctx context.Context, name string) (func(), bool, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("postgres: acquire connection for lock %s: %w", name, err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, name).Scan(&ok); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("postgres: try lock %s: %w", name, err)
	}
	if !ok {
		conn.Release()
		return nil, false, nil
	}
	return func() {
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext($1))`, name); err != nil {
			// Closing the connection drops the lock with it.
			_ = conn.Conn().Close(context.Background())
		}
		conn.Release()
	}, true, nil
}

// WithAdvisoryLock runs fn while holding the named lock, waiting for it if
// another replica holds it.
func (s *Store) WithAdvisoryLock(ctx context.Context, name string, fn func(context.Context) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres: acquire connection for lock %s: %w", name, err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext($1))`, name); err != nil {
		return fmt.Errorf("postgres: lock %s: %w", name, err)
	}
	defer func() {
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext($1))`, name); err != nil {
			_ = conn.Conn().Close(context.Background())
		}
	}()
	return fn(ctx)
}

// BootstrapServerCert returns the stored self-signed server certificate.
func (s *Store) BootstrapServerCert(ctx context.Context) (store.ServerCert, bool, error) {
	var c store.ServerCert
	err := s.pool.QueryRow(ctx, `SELECT cert_der, key_der, not_after FROM bootstrap_server_cert WHERE id`).
		Scan(&c.CertDER, &c.KeyDER, &c.NotAfter)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ServerCert{}, false, nil
	}
	if err != nil {
		return store.ServerCert{}, false, fmt.Errorf("postgres: read bootstrap server cert: %w", err)
	}
	c.NotAfter = c.NotAfter.UTC()
	return c, true, nil
}

// PutBootstrapServerCert stores c, replacing any earlier certificate.
func (s *Store) PutBootstrapServerCert(ctx context.Context, c store.ServerCert) error {
	if _, err := s.pool.Exec(ctx, `INSERT INTO bootstrap_server_cert (id, cert_der, key_der, not_after, created_at)
		VALUES (true, $1, $2, $3, now())
		ON CONFLICT (id) DO UPDATE SET cert_der = excluded.cert_der, key_der = excluded.key_der,
		  not_after = excluded.not_after, created_at = excluded.created_at`,
		c.CertDER, c.KeyDER, c.NotAfter); err != nil {
		return fmt.Errorf("postgres: store bootstrap server cert: %w", err)
	}
	return nil
}

// DeleteBootstrapServerCert removes the stored certificate once real TLS
// material is configured.
func (s *Store) DeleteBootstrapServerCert(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM bootstrap_server_cert`); err != nil {
		return fmt.Errorf("postgres: delete bootstrap server cert: %w", err)
	}
	return nil
}

func bumpEpoch(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `INSERT INTO operator_revocation_epoch (id, epoch) VALUES (true, 1)
		ON CONFLICT (id) DO UPDATE SET epoch = operator_revocation_epoch.epoch + 1`); err != nil {
		return fmt.Errorf("postgres: bump revocation epoch: %w", err)
	}
	return nil
}
