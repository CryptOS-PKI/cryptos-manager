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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var _ store.OperatorCredentialStore = (*Store)(nil)

const selectCredentialRequest = `SELECT id::text, level, email, full_name, csr_der, state, created_by_cn,
  created_at, expires_at, completed_serial FROM operator_credential_requests`

// expireRequests marks every pending request past its expiry as expired and
// drops its CSR.
func expireRequests(ctx context.Context, tx pgx.Tx, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE operator_credential_requests SET state = 'expired', csr_der = NULL
		WHERE state = 'pending' AND expires_at <= $1`, now); err != nil {
		return fmt.Errorf("postgres: expire operator credential requests: %w", err)
	}
	return nil
}

func scanCredentialRequest(row pgx.CollectableRow) (store.OperatorCredentialRequest, error) {
	var r store.OperatorCredentialRequest
	if err := row.Scan(&r.ID, &r.Level, &r.Email, &r.FullName, &r.CSRDER, &r.State, &r.CreatedByCN,
		&r.CreatedAt, &r.ExpiresAt, &r.CompletedSerial); err != nil {
		return store.OperatorCredentialRequest{}, err
	}
	r.CreatedAt, r.ExpiresAt = r.CreatedAt.UTC(), r.ExpiresAt.UTC()
	return r, nil
}

// inTx runs fn in a transaction, committing when it returns nil.
func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}

// requestByID reads one request, locking it for the rest of tx when lock is
// set. An ID that isn't a UUID can't name a request.
func requestByID(ctx context.Context, tx pgx.Tx, id string, lock bool) (store.OperatorCredentialRequest, error) {
	if _, err := uuid.Parse(id); err != nil {
		return store.OperatorCredentialRequest{}, store.ErrRequestNotFound
	}
	q := selectCredentialRequest + ` WHERE id = $1`
	if lock {
		q += ` FOR UPDATE`
	}
	rows, err := tx.Query(ctx, q, id)
	if err != nil {
		return store.OperatorCredentialRequest{}, fmt.Errorf("postgres: query operator credential request %s: %w", id, err)
	}
	r, err := pgx.CollectExactlyOneRow(rows, scanCredentialRequest)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.OperatorCredentialRequest{}, store.ErrRequestNotFound
	}
	if err != nil {
		return store.OperatorCredentialRequest{}, fmt.Errorf("postgres: read operator credential request %s: %w", id, err)
	}
	return r, nil
}

// AddOperatorCredentialRequest stores a new request.
func (s *Store) AddOperatorCredentialRequest(ctx context.Context, r store.OperatorCredentialRequest) error {
	if _, err := s.pool.Exec(ctx, `INSERT INTO operator_credential_requests
		(id, level, email, full_name, csr_der, state, created_by_cn, created_at, expires_at, completed_serial)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		r.ID, r.Level, r.Email, r.FullName, r.CSRDER, r.State, r.CreatedByCN, r.CreatedAt, r.ExpiresAt, r.CompletedSerial); err != nil {
		return fmt.Errorf("postgres: insert operator credential request %s: %w", r.ID, err)
	}
	return nil
}

// OperatorCredentialRequests returns requests newest first, only those in
// state when it isn't empty.
func (s *Store) OperatorCredentialRequests(ctx context.Context, state string, now time.Time) ([]store.OperatorCredentialRequest, error) {
	var out []store.OperatorCredentialRequest
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := expireRequests(ctx, tx, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, selectCredentialRequest+` WHERE $1 = '' OR state = $1 ORDER BY created_at DESC, id`, state)
		if err != nil {
			return fmt.Errorf("postgres: query operator credential requests: %w", err)
		}
		out, err = pgx.CollectRows(rows, scanCredentialRequest)
		if err != nil {
			return fmt.Errorf("postgres: read operator credential requests: %w", err)
		}
		return nil
	})
	return out, err
}

// OperatorCredentialRequest returns the request with the ID.
func (s *Store) OperatorCredentialRequest(ctx context.Context, id string, now time.Time) (store.OperatorCredentialRequest, error) {
	var r store.OperatorCredentialRequest
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := expireRequests(ctx, tx, now); err != nil {
			return err
		}
		var err error
		r, err = requestByID(ctx, tx, id, false)
		return err
	})
	return r, err
}

// CancelOperatorCredentialRequest cancels a pending request and drops its
// CSR.
func (s *Store) CancelOperatorCredentialRequest(ctx context.Context, id string, now time.Time) (store.OperatorCredentialRequest, error) {
	var r store.OperatorCredentialRequest
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := expireRequests(ctx, tx, now); err != nil {
			return err
		}
		var err error
		if r, err = requestByID(ctx, tx, id, true); err != nil {
			return err
		}
		if r.State != store.RequestPending {
			return store.ErrRequestNotPending
		}
		if _, err := tx.Exec(ctx, `UPDATE operator_credential_requests SET state = 'cancelled', csr_der = NULL WHERE id = $1`, id); err != nil {
			return fmt.Errorf("postgres: cancel operator credential request %s: %w", id, err)
		}
		r.State, r.CSRDER = store.RequestCancelled, nil
		return nil
	})
	return r, err
}

// RecordOperatorCredential stores c and completes requestID, if set, in one
// transaction. A row the manager only observed is upgraded in place, keeping
// its first and last seen times.
func (s *Store) RecordOperatorCredential(ctx context.Context, c store.OperatorCredential, requestID string, now time.Time) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := expireRequests(ctx, tx, now); err != nil {
			return err
		}
		if requestID != "" {
			r, err := requestByID(ctx, tx, requestID, true)
			if err != nil {
				return err
			}
			if r.State != store.RequestPending {
				return store.ErrRequestNotPending
			}
		}
		tag, err := tx.Exec(ctx, `INSERT INTO operator_credentials (serial_hex, common_name, level, not_after, revoked,
			  issuer_sha256, kind, email, full_name, leaf_sha256, request_id)
			VALUES ($1, $2, $3, $4, false, $5, $6, $7, $8, $9, nullif($10, '')::uuid)
			ON CONFLICT (issuer_sha256, serial_hex) DO UPDATE SET
			  common_name = EXCLUDED.common_name, level = EXCLUDED.level, not_after = EXCLUDED.not_after,
			  kind = EXCLUDED.kind, email = EXCLUDED.email, full_name = EXCLUDED.full_name,
			  leaf_sha256 = EXCLUDED.leaf_sha256, request_id = EXCLUDED.request_id
			WHERE operator_credentials.kind = 'observed'`,
			c.SerialHex, c.CommonName, c.Level, c.NotAfter, c.IssuerSHA256, c.Kind, c.Email, c.FullName, c.LeafSHA256, requestID)
		if err != nil {
			return fmt.Errorf("postgres: record operator credential %s/%s: %w", c.IssuerSHA256, c.SerialHex, err)
		}
		if tag.RowsAffected() == 0 {
			return store.ErrCredentialRecorded
		}
		if requestID != "" {
			if _, err := tx.Exec(ctx, `UPDATE operator_credential_requests SET state = 'completed', csr_der = NULL, completed_serial = $2
				WHERE id = $1`, requestID, c.SerialHex); err != nil {
				return fmt.Errorf("postgres: complete operator credential request %s: %w", requestID, err)
			}
		}
		return nil
	})
}

// ObserveOperatorCredential inserts an observed row for a credential the
// manager doesn't know, or updates the seen times of one it does.
func (s *Store) ObserveOperatorCredential(ctx context.Context, c store.OperatorCredential, at time.Time) error {
	if _, err := s.pool.Exec(ctx, `INSERT INTO operator_credentials (serial_hex, common_name, level, not_after, revoked,
		  issuer_sha256, kind, email, leaf_sha256, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, $4, false, $5, 'observed', $6, $7, $8, $8)
		ON CONFLICT (issuer_sha256, serial_hex) DO UPDATE SET
		  first_seen_at = coalesce(operator_credentials.first_seen_at, EXCLUDED.first_seen_at),
		  last_seen_at = greatest(operator_credentials.last_seen_at, EXCLUDED.last_seen_at)`,
		c.SerialHex, c.CommonName, c.Level, c.NotAfter, c.IssuerSHA256, c.Email, c.LeafSHA256, at); err != nil {
		return fmt.Errorf("postgres: observe operator credential %s/%s: %w", c.IssuerSHA256, c.SerialHex, err)
	}
	return nil
}
