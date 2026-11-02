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
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

var _ store.Bootstrap = (*Store)(nil)

// tokenRow is a bootstrap token plus when it was used up.
type tokenRow struct {
	store.BootstrapToken
	UsedAt time.Time
}

// BootstrapState returns the first-run latch.
func (s *Store) BootstrapState(ctx context.Context) (store.BootstrapState, error) {
	st, _, err := readValue[store.BootstrapState](ctx, s.rdb, s, keyLatch)
	return st, err
}

// requireOpen fails when first run is closed. Every first-run write watches
// the latch, so it and the latch closing can't interleave.
func (x *txn) requireOpen() error {
	st, _, err := readValue[store.BootstrapState](x.ctx, x.t, x.s, keyLatch)
	if err != nil {
		return err
	}
	if st.Closed() {
		return store.ErrBootstrapClosed
	}
	return nil
}

// endSessions ends every session not ended yet and returns how many.
func (x *txn) endSessions(reason string, at time.Time) (int, error) {
	rows, err := readAll[store.BootstrapSession](x.ctx, x.t, x.s, keySessions)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rows {
		if !r.EndedAt.IsZero() {
			continue
		}
		r.EndedAt, r.EndedReason = at, reason
		if err := x.put(keySessions, r.Hash, r); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

// deleteAll removes every row of the hash and returns how many there were.
func (x *txn) deleteAll(name string) (int, error) {
	fields, err := x.t.HKeys(x.ctx, x.s.key(name)).Result()
	if err != nil {
		return 0, fmt.Errorf("kv: list %s: %w", name, err)
	}
	for _, f := range fields {
		x.del(name, f)
	}
	return len(fields), nil
}

// CloseBootstrap closes the latch if it is open, ending every session and
// deleting every token in the same step.
func (s *Store) CloseBootstrap(ctx context.Context, by store.BootstrapState) (bool, error) {
	closed := false
	err := s.update(ctx, func(x *txn) error {
		err := x.requireOpen()
		closed = err == nil
		if errors.Is(err, store.ErrBootstrapClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := x.putValue(keyLatch, by); err != nil {
			return err
		}
		if _, err := x.endSessions(store.SessionEndedClosed, by.ClosedAt); err != nil {
			return err
		}
		_, err = x.deleteAll(keyTokens)
		return err
	}, keyLatch, keySessions, keyTokens)
	if err != nil {
		return false, err
	}
	return closed, nil
}

// IssueBootstrapToken stores t and marks every other unused token used.
func (s *Store) IssueBootstrapToken(ctx context.Context, t store.BootstrapToken) error {
	return s.update(ctx, func(x *txn) error {
		if err := x.requireOpen(); err != nil {
			return err
		}
		rows, err := readAll[seqRow[tokenRow]](ctx, x.t, s, keyTokens)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.Row.UsedAt.IsZero() {
				r.Row.UsedAt = t.CreatedAt
				if err := x.put(keyTokens, r.Row.Hash, r); err != nil {
					return err
				}
			}
		}
		seq, err := x.seq()
		if err != nil {
			return err
		}
		return x.put(keyTokens, t.Hash, seqRow[tokenRow]{Seq: seq, Row: tokenRow{BootstrapToken: t}})
	}, keyLatch, keyTokens)
}

// LiveBootstrapToken returns the newest unused, unexpired token.
func (s *Store) LiveBootstrapToken(ctx context.Context, now time.Time) (store.BootstrapToken, bool, error) {
	rows, err := readAll[seqRow[tokenRow]](ctx, s.rdb, s, keyTokens)
	if err != nil {
		return store.BootstrapToken{}, false, err
	}
	rows = bySeq(rows)
	for i := len(rows) - 1; i >= 0; i-- {
		if r := rows[i].Row; r.UsedAt.IsZero() && r.ExpiresAt.After(now) {
			return r.BootstrapToken, true, nil
		}
	}
	return store.BootstrapToken{}, false, nil
}

// StartBootstrapSession consumes the token and starts the session in one
// step: of two concurrent starts, the second sees the token used.
func (s *Store) StartBootstrapSession(ctx context.Context, tokenHash string, bs store.BootstrapSession, now time.Time) (bool, error) {
	started := false
	err := s.update(ctx, func(x *txn) error {
		started = false
		if err := x.requireOpen(); err != nil {
			if errors.Is(err, store.ErrBootstrapClosed) {
				return nil
			}
			return err
		}
		r, ok, err := readOne[seqRow[tokenRow]](ctx, x.t, s, keyTokens, tokenHash)
		if err != nil {
			return err
		}
		if !ok || !r.Row.UsedAt.IsZero() || !r.Row.ExpiresAt.After(now) {
			return nil
		}
		r.Row.UsedAt = now
		if err := x.put(keyTokens, tokenHash, r); err != nil {
			return err
		}
		if _, err := x.endSessions(store.SessionEndedSuperseded, now); err != nil {
			return err
		}
		bs.EndedAt, bs.EndedReason = time.Time{}, ""
		started = true
		return x.put(keySessions, bs.Hash, bs)
	}, keyLatch, keyTokens, keySessions)
	if err != nil {
		return false, err
	}
	return started, nil
}

// BootstrapSession returns the session with the given hash.
func (s *Store) BootstrapSession(ctx context.Context, hash string) (store.BootstrapSession, bool, error) {
	return readOne[store.BootstrapSession](ctx, s.rdb, s, keySessions, hash)
}

// changeLiveSession applies change to a session not yet ended.
func (s *Store) changeLiveSession(ctx context.Context, hash string, change func(*store.BootstrapSession)) error {
	return s.update(ctx, func(x *txn) error {
		r, ok, err := readOne[store.BootstrapSession](ctx, x.t, s, keySessions, hash)
		if err != nil || !ok || !r.EndedAt.IsZero() {
			return err
		}
		change(&r)
		return x.put(keySessions, hash, r)
	}, keySessions)
}

// TouchBootstrapSession records a use of a live session.
func (s *Store) TouchBootstrapSession(ctx context.Context, hash string, at time.Time) error {
	return s.changeLiveSession(ctx, hash, func(r *store.BootstrapSession) { r.LastUsedAt = at })
}

// EndBootstrapSession ends one session, keeping the first end.
func (s *Store) EndBootstrapSession(ctx context.Context, hash, reason string, at time.Time) error {
	return s.changeLiveSession(ctx, hash, func(r *store.BootstrapSession) { r.EndedAt, r.EndedReason = at, reason })
}

// EndBootstrapSessions ends every session not yet ended.
func (s *Store) EndBootstrapSessions(ctx context.Context, reason string, at time.Time) (int, error) {
	var n int
	err := s.update(ctx, func(x *txn) error {
		var err error
		n, err = x.endSessions(reason, at)
		return err
	}, keySessions)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// HasLiveBootstrapSession reports whether a session is live at now.
func (s *Store) HasLiveBootstrapSession(ctx context.Context, now time.Time, idle time.Duration) (bool, error) {
	rows, err := readAll[store.BootstrapSession](ctx, s.rdb, s, keySessions)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.EndedAt.IsZero() && r.ExpiresAt.After(now) && r.LastUsedAt.After(now.Add(-idle)) {
			return true, nil
		}
	}
	return false, nil
}

// RegisterFirstRunOperatorCA retires the earlier registration, stores ca as
// active, stores its CRL and moves the trust version, in one step.
func (s *Store) RegisterFirstRunOperatorCA(ctx context.Context, ca store.OperatorCA, sessionHash string, crl *store.OperatorCRL, decide store.DecideCRL) error {
	if ca.RegisteredAt.IsZero() {
		ca.RegisteredAt = time.Now().UTC()
	}
	return s.update(ctx, func(x *txn) error {
		if err := x.requireOpen(); err != nil {
			return err
		}
		rows, err := x.operatorCAs()
		if err != nil {
			return err
		}
		for _, r := range rows {
			if trusted(r.Row.State) && r.Row.SHA256 != ca.SHA256 {
				r.Row.State = store.OperatorCARetired
				r.Row.RetiredAt, r.Row.RetiredReason = ca.RegisteredAt, store.RetiredSuperseded
				if err := x.putCA(r); err != nil {
					return err
				}
			}
		}
		if err := x.activate(rows, ca, sessionHash); err != nil {
			return err
		}
		if crl != nil {
			if _, err := x.putCRL(*crl, decide); err != nil {
				return err
			}
		}
		x.bump(keyEpoch)
		return nil
	}, keyLatch, keyOperatorCAs, keyOperatorCRLs)
}

// ConfirmOperatorCA records the session that confirmed the operator CA.
func (s *Store) ConfirmOperatorCA(ctx context.Context, sha256, sessionHash string) error {
	return s.update(ctx, func(x *txn) error {
		r, ok, err := readOne[seqRow[caRow]](ctx, x.t, s, keyOperatorCAs, sha256)
		if err != nil {
			return err
		}
		if !ok {
			return store.ErrOperatorCANotFound
		}
		r.Row.ConfirmedBy = sessionHash
		return x.put(keyOperatorCAs, sha256, r)
	}, keyOperatorCAs)
}

// OperatorCAConfirmedBy returns the session hash that last confirmed the CA.
func (s *Store) OperatorCAConfirmedBy(ctx context.Context, sha256 string) (string, error) {
	r, ok, err := readOne[seqRow[caRow]](ctx, s.rdb, s, keyOperatorCAs, sha256)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", store.ErrOperatorCANotFound
	}
	return r.Row.ConfirmedBy, nil
}

// RecordFirstAdmin upserts the first admin's credential.
func (s *Store) RecordFirstAdmin(ctx context.Context, c store.OperatorCredential, at time.Time) error {
	field := credentialField(c.IssuerSHA256, c.SerialHex)
	return s.update(ctx, func(x *txn) error {
		r, ok, err := readOne[seqRow[store.OperatorCredential]](ctx, x.t, s, keyCredentials, field)
		if err != nil {
			return err
		}
		row := c
		row.Kind = store.OperatorCredentialFirstAdmin
		if !ok {
			row.Revoked, row.FirstSeenAt, row.LastSeenAt = false, at, time.Time{}
			return x.putNewCredential(row)
		}
		row.Revoked, row.FirstSeenAt, row.LastSeenAt = r.Row.Revoked, r.Row.FirstSeenAt, r.Row.LastSeenAt
		r.Row = row
		return x.put(keyCredentials, field, r)
	}, keyCredentials)
}

// RecordFirstUse stores c as first_admin unless it is already recorded.
func (s *Store) RecordFirstUse(ctx context.Context, c store.OperatorCredential, at time.Time) (bool, error) {
	field := credentialField(c.IssuerSHA256, c.SerialHex)
	stored := false
	err := s.update(ctx, func(x *txn) error {
		_, ok, err := readOne[seqRow[store.OperatorCredential]](ctx, x.t, s, keyCredentials, field)
		if err != nil {
			return err
		}
		stored = !ok
		if ok {
			return nil
		}
		row := c
		row.Kind, row.Revoked, row.FirstSeenAt, row.LastSeenAt = store.OperatorCredentialFirstAdmin, false, at, at
		return x.putNewCredential(row)
	}, keyCredentials)
	if err != nil {
		return false, err
	}
	return stored, nil
}

// FirstAdminCredentials returns every first_admin credential, oldest first.
func (s *Store) FirstAdminCredentials(ctx context.Context) ([]store.OperatorCredential, error) {
	rows, err := readAll[seqRow[store.OperatorCredential]](ctx, s.rdb, s, keyCredentials)
	if err != nil {
		return nil, err
	}
	var out []store.OperatorCredential
	for _, r := range bySeq(rows) {
		if r.Row.Kind == store.OperatorCredentialFirstAdmin {
			out = append(out, r.Row)
		}
	}
	return out, nil
}

// ResetFirstRun clears the latch, deletes the sessions and tokens and retires
// every operator CA row, in one step. The denylist and CRLs stay.
func (s *Store) ResetFirstRun(ctx context.Context, at time.Time) (store.FirstRunReset, error) {
	var r store.FirstRunReset
	err := s.update(ctx, func(x *txn) error {
		var err error
		r = store.FirstRunReset{}
		if r.Previous, _, err = readValue[store.BootstrapState](ctx, x.t, s, keyLatch); err != nil {
			return err
		}
		if err := x.putValue(keyLatch, store.BootstrapState{}); err != nil {
			return err
		}
		if r.Sessions, err = x.deleteAll(keySessions); err != nil {
			return err
		}
		if r.Tokens, err = x.deleteAll(keyTokens); err != nil {
			return err
		}
		rows, err := x.operatorCAs()
		if err != nil {
			return err
		}
		for _, c := range rows {
			if c.Row.State == store.OperatorCARetired {
				continue
			}
			c.Row.State, c.Row.RetiredAt, c.Row.RetiredReason = store.OperatorCARetired, at, store.RetiredReset
			if err := x.putCA(c); err != nil {
				return err
			}
			r.RetiredCAs++
		}
		return nil
	}, keyLatch, keySessions, keyTokens, keyOperatorCAs)
	if err != nil {
		return store.FirstRunReset{}, err
	}
	return r, nil
}
