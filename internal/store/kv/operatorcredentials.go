package kv

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
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

var _ store.OperatorCredentialStore = (*Store)(nil)

// expireRequests marks every pending request past its expiry as expired,
// drops its CSR, and returns the requests as they then stand.
func (x *txn) expireRequests(now time.Time) ([]store.OperatorCredentialRequest, error) {
	rows, err := readAll[store.OperatorCredentialRequest](x.ctx, x.t, x.s, keyRequests)
	if err != nil {
		return nil, err
	}
	for i, r := range rows {
		if r.State == store.RequestPending && !r.ExpiresAt.After(now) {
			rows[i].State, rows[i].CSRDER = store.RequestExpired, nil
			if err := x.put(keyRequests, r.ID, rows[i]); err != nil {
				return nil, err
			}
		}
	}
	return rows, nil
}

func requestNamed(rows []store.OperatorCredentialRequest, id string) (store.OperatorCredentialRequest, error) {
	if i := slices.IndexFunc(rows, func(r store.OperatorCredentialRequest) bool { return r.ID == id }); i >= 0 {
		return rows[i], nil
	}
	return store.OperatorCredentialRequest{}, store.ErrRequestNotFound
}

// AddOperatorCredentialRequest stores a new request.
func (s *Store) AddOperatorCredentialRequest(ctx context.Context, r store.OperatorCredentialRequest) error {
	return s.update(ctx, func(x *txn) error { return x.put(keyRequests, r.ID, r) })
}

// OperatorCredentialRequests returns requests newest first, only those in
// state when it isn't empty.
func (s *Store) OperatorCredentialRequests(ctx context.Context, state string, now time.Time) ([]store.OperatorCredentialRequest, error) {
	var out []store.OperatorCredentialRequest
	err := s.update(ctx, func(x *txn) error {
		rows, err := x.expireRequests(now)
		if err != nil {
			return err
		}
		out = out[:0]
		for _, r := range rows {
			if state == "" || r.State == state {
				out = append(out, r)
			}
		}
		return nil
	}, keyRequests)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b store.OperatorCredentialRequest) int {
		return cmp.Or(b.CreatedAt.Compare(a.CreatedAt), cmp.Compare(a.ID, b.ID))
	})
	return out, nil
}

// OperatorCredentialRequest returns the request with the ID.
func (s *Store) OperatorCredentialRequest(ctx context.Context, id string, now time.Time) (store.OperatorCredentialRequest, error) {
	var r store.OperatorCredentialRequest
	err := s.update(ctx, func(x *txn) error {
		rows, err := x.expireRequests(now)
		if err != nil {
			return err
		}
		r, err = requestNamed(rows, id)
		return err
	}, keyRequests)
	return r, err
}

// CancelOperatorCredentialRequest cancels a pending request and drops its CSR.
func (s *Store) CancelOperatorCredentialRequest(ctx context.Context, id string, now time.Time) (store.OperatorCredentialRequest, error) {
	var r store.OperatorCredentialRequest
	err := s.update(ctx, func(x *txn) error {
		rows, err := x.expireRequests(now)
		if err != nil {
			return err
		}
		if r, err = requestNamed(rows, id); err != nil {
			return err
		}
		if r.State != store.RequestPending {
			return store.ErrRequestNotPending
		}
		r.State, r.CSRDER = store.RequestCancelled, nil
		return x.put(keyRequests, id, r)
	}, keyRequests)
	return r, err
}

// RecordOperatorCredential stores c and completes requestID, if set, in one
// step. A row the manager only observed is upgraded in place, keeping its
// first and last seen times.
func (s *Store) RecordOperatorCredential(ctx context.Context, c store.OperatorCredential, requestID string, now time.Time) error {
	field := credentialField(c.IssuerSHA256, c.SerialHex)
	return s.update(ctx, func(x *txn) error {
		rows, err := x.expireRequests(now)
		if err != nil {
			return err
		}
		var req store.OperatorCredentialRequest
		if requestID != "" {
			if req, err = requestNamed(rows, requestID); err != nil {
				return err
			}
			if req.State != store.RequestPending {
				return store.ErrRequestNotPending
			}
		}

		row := c
		row.Revoked, row.RequestID = false, requestID
		cur, ok, err := readOne[seqRow[store.OperatorCredential]](ctx, x.t, s, keyCredentials, field)
		if err != nil {
			return err
		}
		switch {
		case !ok:
			if err := x.putNewCredential(row); err != nil {
				return err
			}
		case cur.Row.Kind != store.OperatorCredentialObserved:
			return store.ErrCredentialRecorded
		default:
			row.Revoked, row.FirstSeenAt, row.LastSeenAt = cur.Row.Revoked, cur.Row.FirstSeenAt, cur.Row.LastSeenAt
			cur.Row = row
			if err := x.put(keyCredentials, field, cur); err != nil {
				return err
			}
		}

		if requestID != "" {
			req.State, req.CSRDER, req.CompletedSerial = store.RequestCompleted, nil, c.SerialHex
			return x.put(keyRequests, requestID, req)
		}
		return nil
	}, keyRequests, keyCredentials)
}

// ObserveOperatorCredential inserts an observed row for a credential the
// manager doesn't know, or updates the seen times of one it does.
func (s *Store) ObserveOperatorCredential(ctx context.Context, c store.OperatorCredential, at time.Time) error {
	field := credentialField(c.IssuerSHA256, c.SerialHex)
	return s.update(ctx, func(x *txn) error {
		cur, ok, err := readOne[seqRow[store.OperatorCredential]](ctx, x.t, s, keyCredentials, field)
		if err != nil {
			return err
		}
		if !ok {
			row := c
			row.Kind, row.Revoked, row.FullName, row.RequestID = store.OperatorCredentialObserved, false, "", ""
			row.FirstSeenAt, row.LastSeenAt = at, at
			return x.putNewCredential(row)
		}
		if cur.Row.FirstSeenAt.IsZero() {
			cur.Row.FirstSeenAt = at
		}
		if at.After(cur.Row.LastSeenAt) {
			cur.Row.LastSeenAt = at
		}
		return x.put(keyCredentials, field, cur)
	}, keyCredentials)
}
