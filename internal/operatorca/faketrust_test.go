package operatorca

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
	"strings"
	"sync"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
)

// fakeTrust is an in-memory store.OperatorTrust that behaves like the
// Postgres store, including exclusive advisory locks, so two "replicas" can
// share one.
type fakeTrust struct {
	mu       sync.Mutex
	cas      []store.OperatorCA
	crls     map[string]store.OperatorCRL
	denylist map[string]store.DenylistEntry
	epoch    int64
	caChange int
	locks    map[string]bool
	failPoll bool
	noDB     bool
}

func newFakeTrust() *fakeTrust {
	return &fakeTrust{crls: map[string]store.OperatorCRL{}, denylist: map[string]store.DenylistEntry{}, locks: map[string]bool{}}
}

func (f *fakeTrust) OperatorCAs(context.Context) ([]store.OperatorCA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.OperatorCA(nil), f.cas...), nil
}

func (f *fakeTrust) AddOperatorCA(_ context.Context, ca store.OperatorCA) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noDB {
		return store.ErrDatabaseRequired
	}
	for _, c := range f.cas {
		if c.SHA256 == ca.SHA256 || (ca.State != store.OperatorCARetired && c.State == ca.State) {
			return fmt.Errorf("fake: duplicate %s/%s", ca.SHA256, ca.State)
		}
	}
	if ca.OCSPMode == "" {
		ca.OCSPMode = store.OCSPModeAIA
	}
	f.cas = append(f.cas, ca)
	f.caChange++
	return nil
}

func (f *fakeTrust) SetOperatorCAState(_ context.Context, sha, state, reason string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.cas {
		if f.cas[i].SHA256 == sha {
			f.cas[i].State = state
			if state == store.OperatorCARetired {
				f.cas[i].RetiredAt, f.cas[i].RetiredReason = at, reason
			}
			f.caChange++
			return nil
		}
	}
	return store.ErrOperatorCANotFound
}

func (f *fakeTrust) OperatorCRLs(context.Context) ([]store.OperatorCRL, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.OperatorCRL
	for _, c := range f.crls {
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeTrust) PutOperatorCRL(_ context.Context, c store.OperatorCRL, decide store.DecideCRL) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.crls[c.IssuerSHA256]
	accept, err := decide(cur, ok && cur.DER != nil)
	if err != nil || !accept {
		return false, err
	}
	c.LastError = ""
	c.LastAttemptAt = c.FetchedAt
	f.crls[c.IssuerSHA256] = c
	f.epoch++
	return true, nil
}

func (f *fakeTrust) RecordOperatorCRLAttempt(_ context.Context, issuer, lastError string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.crls[issuer]
	c.IssuerSHA256, c.LastError, c.LastAttemptAt = issuer, lastError, at
	f.crls[issuer] = c
	return nil
}

func (f *fakeTrust) OperatorDenylist(context.Context) ([]store.DenylistEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.DenylistEntry
	for _, e := range f.denylist {
		out = append(out, e)
	}
	return out, nil
}

func (f *fakeTrust) AddOperatorDenylistEntry(_ context.Context, e store.DenylistEntry) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noDB {
		return false, store.ErrDatabaseRequired
	}
	k := e.IssuerSHA256 + "/" + e.SerialHex
	if _, ok := f.denylist[k]; ok {
		return false, nil
	}
	f.denylist[k] = e
	f.epoch++
	return true, nil
}

func (f *fakeTrust) OperatorTrustVersion(context.Context) (store.TrustVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPoll {
		return store.TrustVersion{}, errors.New("fake: database down")
	}
	return store.TrustVersion{CAs: fmt.Sprintf("%d:%d", len(f.cas), f.caChange), Epoch: f.epoch}, nil
}

func (f *fakeTrust) TryAdvisoryLock(_ context.Context, name string) (func(), bool, error) {
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

// tamperCRL overwrites a stored CRL's bytes, as a database writer could.
func (f *fakeTrust) tamperCRL(issuer string, der []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.crls[issuer]
	c.DER = der
	f.crls[issuer] = c
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

// auditSink captures audit events.
type auditSink struct {
	mu     sync.Mutex
	events []store.AuditEvent
}

func (a *auditSink) Record(e store.AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
}

func (a *auditSink) kinds(kind string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}
