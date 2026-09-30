package bootstrap

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
	"strings"
	"sync"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
)

// fakeStore is an in-memory store.OperatorTrust and store.Bootstrap that
// behaves like the Postgres store, and counts token and session lookups so a
// test can prove a closed first run never reads them.
type fakeStore struct {
	mu sync.Mutex

	cas       []store.OperatorCA
	confirmed map[string]string
	crls      map[string]store.OperatorCRL
	denylist  map[string]store.DenylistEntry
	epoch     int64
	caChange  int
	locks     map[string]bool

	latch    store.BootstrapState
	tokens   []fakeToken
	sessions map[string]store.BootstrapSession
	creds    map[string]store.OperatorCredential

	tokenLookups   int
	sessionLookups int
}

type fakeToken struct {
	store.BootstrapToken
	used bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		confirmed: map[string]string{}, crls: map[string]store.OperatorCRL{}, denylist: map[string]store.DenylistEntry{},
		locks: map[string]bool{}, sessions: map[string]store.BootstrapSession{}, creds: map[string]store.OperatorCredential{},
	}
}

func (f *fakeStore) lookups() (tokens, sessions int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenLookups, f.sessionLookups
}

func (f *fakeStore) tokenHashes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, t := range f.tokens {
		out = append(out, t.Hash)
	}
	return out
}

func (f *fakeStore) sessionHashes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for h := range f.sessions {
		out = append(out, h)
	}
	return out
}

// OperatorTrust

func (f *fakeStore) OperatorCAs(context.Context) ([]store.OperatorCA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.OperatorCA(nil), f.cas...), nil
}

func (f *fakeStore) AddOperatorCA(_ context.Context, ca store.OperatorCA) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cas = append(f.cas, ca)
	f.caChange++
	return nil
}

func (f *fakeStore) SetOperatorCAState(_ context.Context, sha, state, reason string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.cas {
		if f.cas[i].SHA256 == sha {
			f.cas[i].State, f.cas[i].RetiredReason, f.cas[i].RetiredAt = state, reason, at
			f.caChange++
			return nil
		}
	}
	return store.ErrOperatorCANotFound
}

func (f *fakeStore) OperatorCRLs(context.Context) ([]store.OperatorCRL, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.OperatorCRL
	for _, c := range f.crls {
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeStore) PutOperatorCRL(_ context.Context, c store.OperatorCRL, decide store.DecideCRL) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.putCRLLocked(c, decide)
}

func (f *fakeStore) putCRLLocked(c store.OperatorCRL, decide store.DecideCRL) (bool, error) {
	cur, ok := f.crls[c.IssuerSHA256]
	accept, err := decide(cur, ok && cur.DER != nil)
	if err != nil || !accept {
		return false, err
	}
	f.crls[c.IssuerSHA256] = c
	f.epoch++
	return true, nil
}

func (f *fakeStore) RecordOperatorCRLAttempt(_ context.Context, issuer, lastError string, at time.Time) error {
	return nil
}

func (f *fakeStore) OperatorDenylist(context.Context) ([]store.DenylistEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.DenylistEntry
	for _, e := range f.denylist {
		out = append(out, e)
	}
	return out, nil
}

func (f *fakeStore) AddOperatorDenylistEntry(_ context.Context, e store.DenylistEntry) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := e.IssuerSHA256 + "/" + e.SerialHex
	if _, ok := f.denylist[k]; ok {
		return false, nil
	}
	f.denylist[k] = e
	f.epoch++
	return true, nil
}

func (f *fakeStore) OperatorTrustVersion(context.Context) (store.TrustVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return store.TrustVersion{CAs: fmt.Sprintf("%d:%d", len(f.cas), f.caChange), Epoch: f.epoch}, nil
}

func (f *fakeStore) TryAdvisoryLock(_ context.Context, name string) (func(), bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.locks[name] {
		return nil, false, nil
	}
	f.locks[name] = true
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.locks, name)
	}, true, nil
}

// Bootstrap

func (f *fakeStore) BootstrapState(context.Context) (store.BootstrapState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.latch, nil
}

func (f *fakeStore) CloseBootstrap(_ context.Context, by store.BootstrapState) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.latch.Closed() {
		return false, nil
	}
	f.latch = by
	for h, s := range f.sessions {
		if s.EndedAt.IsZero() {
			s.EndedAt, s.EndedReason = by.ClosedAt, store.SessionEndedClosed
			f.sessions[h] = s
		}
	}
	f.tokens = nil
	return true, nil
}

func (f *fakeStore) IssueBootstrapToken(_ context.Context, t store.BootstrapToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.latch.Closed() {
		return store.ErrBootstrapClosed
	}
	for i := range f.tokens {
		f.tokens[i].used = true
	}
	f.tokens = append(f.tokens, fakeToken{BootstrapToken: t})
	return nil
}

func (f *fakeStore) LiveBootstrapToken(_ context.Context, now time.Time) (store.BootstrapToken, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenLookups++
	for i := len(f.tokens) - 1; i >= 0; i-- {
		if t := f.tokens[i]; !t.used && t.ExpiresAt.After(now) {
			return t.BootstrapToken, true, nil
		}
	}
	return store.BootstrapToken{}, false, nil
}

func (f *fakeStore) StartBootstrapSession(_ context.Context, tokenHash string, s store.BootstrapSession, now time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenLookups++
	if f.latch.Closed() {
		return false, nil
	}
	for i := range f.tokens {
		t := &f.tokens[i]
		if t.Hash == tokenHash && !t.used && t.ExpiresAt.After(now) {
			t.used = true
			for h, old := range f.sessions {
				if old.EndedAt.IsZero() {
					old.EndedAt, old.EndedReason = now, store.SessionEndedSuperseded
					f.sessions[h] = old
				}
			}
			f.sessions[s.Hash] = s
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) BootstrapSession(_ context.Context, hash string) (store.BootstrapSession, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessionLookups++
	s, ok := f.sessions[hash]
	return s, ok, nil
}

func (f *fakeStore) TouchBootstrapSession(_ context.Context, hash string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sessions[hash]; ok && s.EndedAt.IsZero() {
		s.LastUsedAt = at
		f.sessions[hash] = s
	}
	return nil
}

func (f *fakeStore) EndBootstrapSession(_ context.Context, hash, reason string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sessions[hash]; ok && s.EndedAt.IsZero() {
		s.EndedAt, s.EndedReason = at, reason
		f.sessions[hash] = s
	}
	return nil
}

func (f *fakeStore) EndBootstrapSessions(_ context.Context, reason string, at time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for h, s := range f.sessions {
		if s.EndedAt.IsZero() {
			s.EndedAt, s.EndedReason = at, reason
			f.sessions[h] = s
			n++
		}
	}
	return n, nil
}

func (f *fakeStore) HasLiveBootstrapSession(_ context.Context, now time.Time, idle time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions {
		if s.EndedAt.IsZero() && s.ExpiresAt.After(now) && s.LastUsedAt.After(now.Add(-idle)) {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) RegisterFirstRunOperatorCA(_ context.Context, ca store.OperatorCA, sessionHash string, crl *store.OperatorCRL, decide store.DecideCRL) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.latch.Closed() {
		return store.ErrBootstrapClosed
	}
	if crl != nil {
		cur, ok := f.crls[crl.IssuerSHA256]
		accept, err := decide(cur, ok && cur.DER != nil)
		if err != nil {
			return err
		}
		if accept {
			f.crls[crl.IssuerSHA256] = *crl
		}
	}
	if ca.OCSPMode == "" {
		ca.OCSPMode = store.OCSPModeAIA
	}
	found := false
	for i := range f.cas {
		switch {
		case f.cas[i].SHA256 == ca.SHA256:
			ca.State = store.OperatorCAActive
			f.cas[i] = ca
			found = true
		case f.cas[i].State == store.OperatorCAActive || f.cas[i].State == store.OperatorCARetiring:
			f.cas[i].State, f.cas[i].RetiredReason, f.cas[i].RetiredAt = store.OperatorCARetired, store.RetiredSuperseded, ca.RegisteredAt
		}
	}
	if !found {
		ca.State = store.OperatorCAActive
		f.cas = append(f.cas, ca)
	}
	f.confirmed[ca.SHA256] = sessionHash
	f.caChange++
	f.epoch++
	return nil
}

func (f *fakeStore) ConfirmOperatorCA(_ context.Context, sha, sessionHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cas {
		if c.SHA256 == sha {
			f.confirmed[sha] = sessionHash
			return nil
		}
	}
	return store.ErrOperatorCANotFound
}

func (f *fakeStore) OperatorCAConfirmedBy(_ context.Context, sha string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.confirmed[sha], nil
}

func (f *fakeStore) RecordFirstAdmin(_ context.Context, c store.OperatorCredential, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c.Kind = store.OperatorCredentialFirstAdmin
	f.creds[c.IssuerSHA256+"/"+c.SerialHex] = c
	return nil
}

func (f *fakeStore) RecordFirstUse(_ context.Context, c store.OperatorCredential, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := c.IssuerSHA256 + "/" + c.SerialHex
	if _, ok := f.creds[k]; ok {
		return false, nil
	}
	c.Kind = store.OperatorCredentialFirstAdmin
	f.creds[k] = c
	return true, nil
}

func (f *fakeStore) FirstAdminCredentials(context.Context) ([]store.OperatorCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.OperatorCredential
	for _, c := range f.creds {
		if c.Kind == store.OperatorCredentialFirstAdmin {
			out = append(out, c)
		}
	}
	return out, nil
}

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// logSink captures log lines.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) Logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logSink) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *logSink) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, sub) {
			n++
		}
	}
	return n
}
