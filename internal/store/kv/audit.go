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
	"encoding/json"
	"errors"
	"fmt"
	"log"

	redis "github.com/Bugs5382/go-redis"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	upstream "github.com/redis/go-redis/v9"
)

// ErrAuditChainBroken is returned when the audit stream doesn't verify: an
// entry was changed or removed.
var ErrAuditChainBroken = errors.New("kv: the audit hash chain is broken")

// Fields of a stream entry. prev_hash and hash sit next to the event so the
// stream can be followed with nothing but a client and SHA-256.
const (
	fieldPrevHash = "prev_hash"
	fieldHash     = "hash"
	fieldEvent    = "event"
)

// auditKey names the stream. It sits outside the state prefix so the ACL can
// grant it less.
func (s *Store) auditKey() string { return "{" + s.ns + "}:audit" }

// AddAuditEvent appends e to the chain. Replicas share one chain, so the
// chain head is a watched key: the entry is hashed from the head, and it and
// the new head commit together or not at all. A replica that loses the race
// rehashes from the new head, which keeps one line of history however many
// replicas write, and keeps stream order and chain order the same.
func (s *Store) AddAuditEvent(e store.AuditEvent) store.AuditEvent {
	ctx := bg()
	e.ChainVersion = store.AuditChainVersion
	err := s.update(ctx, func(x *txn) error {
		prev, _, err := readValue[string](ctx, x.t, s, keyAuditHead)
		if err != nil {
			return err
		}
		e.PrevHash = prev
		e.Hash = store.HashEvent(prev, e)
		b, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("kv: encode audit event: %w", err)
		}
		x.writes = append(x.writes, func(p upstream.Pipeliner) {
			p.XAdd(ctx, &upstream.XAddArgs{
				Stream: s.auditKey(),
				ID:     "*",
				Values: map[string]any{fieldPrevHash: prev, fieldHash: e.Hash, fieldEvent: b},
			})
		})
		return x.putValue(keyAuditHead, e.Hash)
	}, keyAuditHead)
	must(err, "append audit event")
	return e
}

// readChain reads the stream and the head in one step, so a concurrent append
// can't look like a break.
func (s *Store) readChain(ctx context.Context) ([]upstream.XMessage, string, error) {
	var (
		msgs *upstream.XMessageSliceCmd
		head *upstream.StringCmd
	)
	_, err := s.rdb.TxPipelined(ctx, func(p upstream.Pipeliner) error {
		msgs = p.XRange(ctx, s.auditKey(), "-", "+")
		head = p.Get(ctx, s.key(keyAuditHead))
		return nil
	})
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, "", fmt.Errorf("kv: read the audit stream: %w", err)
	}
	if err := msgs.Err(); err != nil {
		return nil, "", fmt.Errorf("kv: read the audit stream: %w", err)
	}
	var want string
	if raw, err := head.Result(); err == nil {
		if err := json.Unmarshal([]byte(raw), &want); err != nil {
			return nil, "", fmt.Errorf("kv: decode the audit chain head: %w", err)
		}
	} else if !errors.Is(err, redis.Nil) {
		return nil, "", fmt.Errorf("kv: read the audit chain head: %w", err)
	}
	return msgs.Val(), want, nil
}

func text(m upstream.XMessage, field string) string {
	v, _ := m.Values[field].(string)
	return v
}

// verifyChain walks the entries. It returns every event it could decode, and
// ErrAuditChainBroken, naming the first entry that fails, if the chain doesn't
// hold from the first entry through to the head.
func verifyChain(msgs []upstream.XMessage, head string) ([]store.AuditEvent, error) {
	out := make([]store.AuditEvent, 0, len(msgs))
	var broken error
	fail := func(id, why string) {
		if broken == nil {
			broken = fmt.Errorf("%w at entry %s: %s", ErrAuditChainBroken, id, why)
		}
	}

	prev := ""
	for _, m := range msgs {
		var e store.AuditEvent
		if err := json.Unmarshal([]byte(text(m, fieldEvent)), &e); err != nil {
			fail(m.ID, "its event can't be decoded")
			continue
		}
		out = append(out, e)
		switch {
		case text(m, fieldPrevHash) != prev || e.PrevHash != prev:
			fail(m.ID, "it doesn't follow the entry before it")
		case text(m, fieldHash) != store.HashEvent(prev, e) || e.Hash != text(m, fieldHash):
			fail(m.ID, "its hash doesn't match its contents")
		}
		prev = text(m, fieldHash)
	}
	if prev != head {
		fail("(end)", "the last entry isn't the chain head, so entries are missing")
	}
	return out, broken
}

// noteChain remembers the latest verdict for health and logs a break.
func (s *Store) noteChain(err error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	s.chainErr = err
	if err != nil {
		log.Printf("kv: ERROR %v", err)
	}
}

// VerifyAudit walks the whole chain, at startup and on demand.
func (s *Store) VerifyAudit(ctx context.Context) error {
	msgs, head, err := s.readChain(ctx)
	if err != nil {
		return err
	}
	_, err = verifyChain(msgs, head)
	s.noteChain(err)
	if err == nil {
		log.Printf("kv: audit chain verified, %d entries", len(msgs))
	}
	return err
}

// AuditChainError returns the latest verification's break, nil if it held.
func (s *Store) AuditChainError() error {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	return s.chainErr
}

// Audit returns every audit event in append order, verifying the chain as it
// reads. A broken chain is reported, not hidden: what is left of the log is
// still what an investigator needs, so it is returned anyway.
func (s *Store) Audit() []store.AuditEvent {
	msgs, head, err := s.readChain(bg())
	must(err, "read audit")
	out, err := verifyChain(msgs, head)
	s.noteChain(err)
	return out
}
