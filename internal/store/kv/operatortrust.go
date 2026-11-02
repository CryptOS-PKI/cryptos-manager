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
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"
	"time"

	"github.com/Bugs5382/go-redis/lock"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

var _ store.OperatorTrust = (*Store)(nil)

// lockTTL is how long a lock survives its holder dying; a live holder keeps
// extending it.
const lockTTL = 30 * time.Second

// lockWait stands in for "as long as it takes" while the caller's context
// bounds the wait.
const lockWait = 24 * time.Hour

// caRow is an operator CA plus the session that confirmed it.
type caRow struct {
	store.OperatorCA
	ConfirmedBy string
}

func (x *txn) operatorCAs() ([]seqRow[caRow], error) {
	return readAll[seqRow[caRow]](x.ctx, x.t, x.s, keyOperatorCAs)
}

// putCA queues r and moves the version the trust poll compares.
func (x *txn) putCA(r seqRow[caRow]) error {
	r.Row.UpdatedAt = time.Now().UTC()
	x.bump(keyCAVersion)
	return x.put(keyOperatorCAs, r.Row.SHA256, r)
}

// activate stores ca as the active row, reviving a row with the same
// fingerprint if there is one.
func (x *txn) activate(rows []seqRow[caRow], ca store.OperatorCA, confirmedBy string) error {
	if ca.OCSPMode == "" {
		ca.OCSPMode = store.OCSPModeAIA
	}
	if ca.RegisteredAt.IsZero() {
		ca.RegisteredAt = time.Now().UTC()
	}
	ca.State = store.OperatorCAActive
	ca.RetiredAt, ca.RetiredReason = time.Time{}, ""
	row := seqRow[caRow]{Row: caRow{OperatorCA: ca, ConfirmedBy: confirmedBy}}
	if i := slices.IndexFunc(rows, func(r seqRow[caRow]) bool { return r.Row.SHA256 == ca.SHA256 }); i >= 0 {
		row.Seq = rows[i].Seq
	} else {
		seq, err := x.seq()
		if err != nil {
			return err
		}
		row.Seq = seq
	}
	return x.putCA(row)
}

func trusted(state string) bool {
	return state == store.OperatorCAActive || state == store.OperatorCARetiring
}

// OperatorCAs returns every registered operator CA, oldest first.
func (s *Store) OperatorCAs(ctx context.Context) ([]store.OperatorCA, error) {
	rows, err := readAll[seqRow[caRow]](ctx, s.rdb, s, keyOperatorCAs)
	if err != nil {
		return nil, err
	}
	out := make([]store.OperatorCA, 0, len(rows))
	for _, r := range bySeq(rows) {
		out = append(out, r.Row.OperatorCA)
	}
	return out, nil
}

// AddOperatorCA stores a new row, holding to the rules the Postgres table's
// constraints enforce: one row per fingerprint, at most one active and one
// retiring, and an OCSP or CRL URL when the mode says there is one.
func (s *Store) AddOperatorCA(ctx context.Context, ca store.OperatorCA) error {
	if ca.OCSPMode == "" {
		ca.OCSPMode = store.OCSPModeAIA
	}
	if ca.RegisteredAt.IsZero() {
		ca.RegisteredAt = time.Now().UTC()
	}
	if ca.OCSPMode == store.OCSPModeURL && ca.OCSPURL == "" {
		return fmt.Errorf("kv: operator CA %s: OCSP mode url needs a URL", ca.SHA256)
	}
	if ca.CRLSource == store.CRLSourceURL && ca.CRLURL == "" {
		return fmt.Errorf("kv: operator CA %s: CRL source url needs a URL", ca.SHA256)
	}
	return s.update(ctx, func(x *txn) error {
		rows, err := x.operatorCAs()
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.Row.SHA256 == ca.SHA256 {
				return fmt.Errorf("kv: operator CA %s already exists", ca.SHA256)
			}
			if trusted(ca.State) && r.Row.State == ca.State {
				return fmt.Errorf("kv: operator CA %s: there is already a %s operator CA", ca.SHA256, ca.State)
			}
		}
		seq, err := x.seq()
		if err != nil {
			return err
		}
		return x.putCA(seqRow[caRow]{Seq: seq, Row: caRow{OperatorCA: ca}})
	}, keyOperatorCAs)
}

// SetOperatorCAState moves the row to state.
func (s *Store) SetOperatorCAState(ctx context.Context, sha256, state, reason string, at time.Time) error {
	return s.update(ctx, func(x *txn) error {
		r, ok, err := readOne[seqRow[caRow]](ctx, x.t, s, keyOperatorCAs, sha256)
		if err != nil {
			return err
		}
		if !ok {
			return store.ErrOperatorCANotFound
		}
		r.Row.State = state
		if state == store.OperatorCARetired {
			r.Row.RetiredAt, r.Row.RetiredReason = at, reason
		}
		return x.putCA(r)
	}, keyOperatorCAs)
}

// RotateOperatorCA makes ca active and moves the current active row to
// retiring, in one step.
func (s *Store) RotateOperatorCA(ctx context.Context, ca store.OperatorCA, crl *store.OperatorCRL, decide store.DecideCRL) error {
	return s.update(ctx, func(x *txn) error {
		rows, err := x.operatorCAs()
		if err != nil {
			return err
		}
		for _, r := range rows {
			if trusted(r.Row.State) && r.Row.SHA256 == ca.SHA256 {
				return store.ErrOperatorCATrusted
			}
		}
		for _, r := range rows {
			if r.Row.State == store.OperatorCARetiring {
				return store.ErrRotationInProgress
			}
		}
		for _, r := range rows {
			if r.Row.State == store.OperatorCAActive {
				r.Row.State = store.OperatorCARetiring
				if err := x.putCA(r); err != nil {
					return err
				}
			}
		}
		if err := x.activate(rows, ca, ""); err != nil {
			return err
		}
		if crl != nil {
			if _, err := x.putCRL(*crl, decide); err != nil {
				return err
			}
		}
		x.bump(keyEpoch)
		return nil
	}, keyOperatorCAs, keyOperatorCRLs)
}

// changeTrusted applies change to an active or retiring row.
func (x *txn) changeTrusted(sha256 string, change func(*caRow)) error {
	r, ok, err := readOne[seqRow[caRow]](x.ctx, x.t, x.s, keyOperatorCAs, sha256)
	if err != nil {
		return err
	}
	if !ok || !trusted(r.Row.State) {
		return store.ErrOperatorCANotFound
	}
	change(&r.Row)
	return x.putCA(r)
}

// SetOperatorCACRLSource changes a trusted row's CRL source and stores its new
// CRL, in one step.
func (s *Store) SetOperatorCACRLSource(ctx context.Context, sha256, source, url string, acks []string, crl *store.OperatorCRL, decide store.DecideCRL) error {
	return s.update(ctx, func(x *txn) error {
		err := x.changeTrusted(sha256, func(r *caRow) {
			r.CRLSource, r.CRLURL, r.Acknowledgements = source, url, acks
		})
		if err != nil {
			return err
		}
		if crl != nil {
			if _, err := x.putCRL(*crl, decide); err != nil {
				return err
			}
		}
		x.bump(keyEpoch)
		return nil
	}, keyOperatorCAs, keyOperatorCRLs)
}

// SetOperatorCAOCSP changes a trusted row's OCSP mode and URL.
func (s *Store) SetOperatorCAOCSP(ctx context.Context, sha256, mode, url string) error {
	if mode == store.OCSPModeURL && url == "" {
		return fmt.Errorf("kv: operator CA %s: OCSP mode url needs a URL", sha256)
	}
	return s.update(ctx, func(x *txn) error {
		return x.changeTrusted(sha256, func(r *caRow) { r.OCSPMode, r.OCSPURL = mode, url })
	}, keyOperatorCAs)
}

// OperatorCRLs returns every stored CRL and last attempt.
func (s *Store) OperatorCRLs(ctx context.Context) ([]store.OperatorCRL, error) {
	out, err := readAll[store.OperatorCRL](ctx, s.rdb, s, keyOperatorCRLs)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b store.OperatorCRL) int { return cmp.Compare(a.IssuerSHA256, b.IssuerSHA256) })
	return out, nil
}

// putCRL decides on and queues c, inside an update watching keyOperatorCRLs,
// so the anti-rollback check and the write are one step.
func (x *txn) putCRL(c store.OperatorCRL, decide store.DecideCRL) (bool, error) {
	cur, ok, err := readOne[store.OperatorCRL](x.ctx, x.t, x.s, keyOperatorCRLs, c.IssuerSHA256)
	if err != nil {
		return false, err
	}
	accept, err := decide(cur, ok && cur.DER != nil)
	if err != nil || !accept {
		return false, err
	}
	c.LastError, c.LastAttemptAt = "", c.FetchedAt
	if err := x.put(keyOperatorCRLs, c.IssuerSHA256, c); err != nil {
		return false, err
	}
	x.bump(keyEpoch)
	return true, nil
}

// PutOperatorCRL stores c if decide accepts it.
func (s *Store) PutOperatorCRL(ctx context.Context, c store.OperatorCRL, decide store.DecideCRL) (bool, error) {
	var stored bool
	err := s.update(ctx, func(x *txn) error {
		var err error
		stored, err = x.putCRL(c, decide)
		return err
	}, keyOperatorCRLs)
	if err != nil {
		return false, err
	}
	return stored, nil
}

// RecordOperatorCRLAttempt records a failed refresh, keeping the stored CRL.
func (s *Store) RecordOperatorCRLAttempt(ctx context.Context, issuerSHA256, lastError string, at time.Time) error {
	return s.update(ctx, func(x *txn) error {
		c, _, err := readOne[store.OperatorCRL](ctx, x.t, s, keyOperatorCRLs, issuerSHA256)
		if err != nil {
			return err
		}
		c.IssuerSHA256, c.LastError, c.LastAttemptAt = issuerSHA256, lastError, at
		return x.put(keyOperatorCRLs, issuerSHA256, c)
	}, keyOperatorCRLs)
}

// OperatorDenylist returns every denylist entry, oldest first.
func (s *Store) OperatorDenylist(ctx context.Context) ([]store.DenylistEntry, error) {
	out, err := readAll[store.DenylistEntry](ctx, s.rdb, s, keyDenylist)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b store.DenylistEntry) int {
		return cmp.Or(a.RevokedAt.Compare(b.RevokedAt), cmp.Compare(a.IssuerSHA256, b.IssuerSHA256), cmp.Compare(a.SerialHex, b.SerialHex))
	})
	return out, nil
}

// AddOperatorDenylistEntry adds e and bumps the revocation epoch in the same
// step, so a replica that sees the new epoch also sees the entry.
func (s *Store) AddOperatorDenylistEntry(ctx context.Context, e store.DenylistEntry) (bool, error) {
	if e.RevokedAt.IsZero() {
		e.RevokedAt = time.Now().UTC()
	}
	field := credentialField(e.IssuerSHA256, e.SerialHex)
	added := false
	err := s.update(ctx, func(x *txn) error {
		_, exists, err := readOne[store.DenylistEntry](ctx, x.t, s, keyDenylist, field)
		if err != nil {
			return err
		}
		added = !exists
		if exists {
			return nil
		}
		x.bump(keyEpoch)
		return x.put(keyDenylist, field, e)
	}, keyDenylist)
	if err != nil {
		return false, err
	}
	return added, nil
}

// OperatorTrustVersion reads both counters in one command.
func (s *Store) OperatorTrustVersion(ctx context.Context) (store.TrustVersion, error) {
	vals, err := s.rdb.MGet(ctx, s.key(keyCAVersion), s.key(keyEpoch)).Result()
	if err != nil {
		return store.TrustVersion{}, fmt.Errorf("kv: read trust version: %w", err)
	}
	var v store.TrustVersion
	if ca, ok := vals[0].(string); ok {
		v.CAs = ca
	}
	if epoch, ok := vals[1].(string); ok {
		if v.Epoch, err = strconv.ParseInt(epoch, 10, 64); err != nil {
			return store.TrustVersion{}, fmt.Errorf("kv: decode the revocation epoch: %w", err)
		}
	}
	return v, nil
}

func (s *Store) lockKey(name string) string { return s.key("lock:" + name) }

// release gives up l. A lock that has already gone expires by itself, so a
// failure here only logs.
func release(l *lock.Lock) {
	if err := l.Release(bg()); err != nil && !errors.Is(err, lock.ErrNotHeld) {
		log.Printf("kv: WARNING release lock %s: %v", l.Key(), err)
	}
}

// TryAdvisoryLock takes the named lock if no replica holds it. Everything the
// manager guards this way is work a second replica would only duplicate.
func (s *Store) TryAdvisoryLock(ctx context.Context, name string) (func(), bool, error) {
	l, err := lock.Acquire(ctx, s.client, s.lockKey(name), lockTTL, lock.WithAutoExtend(lockTTL/3))
	if errors.Is(err, lock.ErrNotAcquired) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("kv: try lock %s: %w", name, err)
	}
	return func() { release(l) }, true, nil
}

// WithAdvisoryLock runs fn while holding the named lock, waiting for it if
// another replica holds it.
func (s *Store) WithAdvisoryLock(ctx context.Context, name string, fn func(context.Context) error) error {
	l, err := lock.Acquire(ctx, s.client, s.lockKey(name), lockTTL, lock.WithWait(lockWait), lock.WithAutoExtend(lockTTL/3))
	if err != nil {
		return fmt.Errorf("kv: lock %s: %w", name, err)
	}
	defer release(l)
	return fn(ctx)
}

// BootstrapServerCert returns the stored self-signed server certificate.
func (s *Store) BootstrapServerCert(ctx context.Context) (store.ServerCert, bool, error) {
	return readValue[store.ServerCert](ctx, s.rdb, s, keyServerCert)
}

// PutBootstrapServerCert stores c, replacing any earlier certificate.
func (s *Store) PutBootstrapServerCert(ctx context.Context, c store.ServerCert) error {
	return s.update(ctx, func(x *txn) error { return x.putValue(keyServerCert, c) })
}

// DeleteBootstrapServerCert removes the stored certificate.
func (s *Store) DeleteBootstrapServerCert(ctx context.Context) error {
	if err := s.rdb.Del(ctx, s.key(keyServerCert)).Err(); err != nil {
		return fmt.Errorf("kv: delete bootstrap server cert: %w", err)
	}
	return nil
}
