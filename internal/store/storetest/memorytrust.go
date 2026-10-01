package storetest

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
	"slices"
	"sync"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
)

var _ store.OperatorTrust = (*MemoryTrust)(nil)

// MemoryTrust is an in-memory store.OperatorTrust that behaves like the
// Postgres store, registered operator CAs and the denylist included, so tests
// in other packages can run the registered source without a database. Two
// trust stores sharing one MemoryTrust stand in for two replicas sharing one
// database. OperatorTrust checks it against the same contract as Postgres.
type MemoryTrust struct {
	mu       sync.Mutex
	cas      []store.OperatorCA
	crls     map[string]store.OperatorCRL
	denylist []store.DenylistEntry
	epoch    int64
	changes  int
	locks    map[string]bool
}

// NewMemoryTrust returns an empty MemoryTrust.
func NewMemoryTrust() *MemoryTrust {
	return &MemoryTrust{crls: map[string]store.OperatorCRL{}, locks: map[string]bool{}}
}

// OperatorCAs returns every row, oldest first.
func (m *MemoryTrust) OperatorCAs(context.Context) ([]store.OperatorCA, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.OperatorCA, len(m.cas))
	for i, c := range m.cas {
		c.Acknowledgements = slices.Clone(c.Acknowledgements)
		c.Warnings = slices.Clone(c.Warnings)
		out[i] = c
	}
	return out, nil
}

func (m *MemoryTrust) checkLocked(next []store.OperatorCA) error {
	seen := map[string]bool{}
	var active, retiring int
	for _, c := range next {
		if seen[c.SHA256] {
			return fmt.Errorf("storetest: duplicate operator CA %s", c.SHA256)
		}
		seen[c.SHA256] = true
		switch c.State {
		case store.OperatorCAActive:
			active++
		case store.OperatorCARetiring:
			retiring++
		}
		if c.OCSPMode == store.OCSPModeURL && c.OCSPURL == "" {
			return fmt.Errorf("storetest: operator CA %s is in OCSP url mode with no URL", c.SHA256)
		}
		if c.CRLSource == store.CRLSourceURL && c.CRLURL == "" {
			return fmt.Errorf("storetest: operator CA %s has a CRL url source with no URL", c.SHA256)
		}
	}
	if active > 1 || retiring > 1 {
		return errors.New("storetest: more than one active or retiring operator CA")
	}
	return nil
}

func (m *MemoryTrust) commitLocked(next []store.OperatorCA) error {
	if err := m.checkLocked(next); err != nil {
		return err
	}
	m.cas = next
	m.changes++
	return nil
}

func normalized(ca store.OperatorCA) store.OperatorCA {
	if ca.OCSPMode == "" {
		ca.OCSPMode = store.OCSPModeAIA
	}
	if ca.RegisteredAt.IsZero() {
		ca.RegisteredAt = time.Now().UTC()
	}
	ca.Acknowledgements = slices.Clone(ca.Acknowledgements)
	ca.Warnings = slices.Clone(ca.Warnings)
	ca.UpdatedAt = time.Now().UTC()
	return ca
}

// AddOperatorCA stores a new row.
func (m *MemoryTrust) AddOperatorCA(_ context.Context, ca store.OperatorCA) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.commitLocked(append(slices.Clone(m.cas), normalized(ca)))
}

// SetOperatorCAState moves a row to state.
func (m *MemoryTrust) SetOperatorCAState(_ context.Context, sha256, state, reason string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := slices.Clone(m.cas)
	i := slices.IndexFunc(next, func(c store.OperatorCA) bool { return c.SHA256 == sha256 })
	if i < 0 {
		return store.ErrOperatorCANotFound
	}
	next[i].State, next[i].UpdatedAt = state, time.Now().UTC()
	if state == store.OperatorCARetired {
		next[i].RetiredAt, next[i].RetiredReason = at, reason
	}
	return m.commitLocked(next)
}

// RotateOperatorCA is the rotation step, all or nothing.
func (m *MemoryTrust) RotateOperatorCA(_ context.Context, ca store.OperatorCA, crl *store.OperatorCRL, decide store.DecideCRL) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := slices.Clone(m.cas)
	for _, c := range next {
		if c.SHA256 == ca.SHA256 && c.State != store.OperatorCARetired {
			return store.ErrOperatorCATrusted
		}
		if c.State == store.OperatorCARetiring {
			return store.ErrRotationInProgress
		}
	}
	now := time.Now().UTC()
	for i := range next {
		if next[i].State == store.OperatorCAActive {
			next[i].State, next[i].UpdatedAt = store.OperatorCARetiring, now
		}
	}
	ca = normalized(ca)
	ca.State, ca.RetiredAt, ca.RetiredReason = store.OperatorCAActive, time.Time{}, ""
	if i := slices.IndexFunc(next, func(c store.OperatorCA) bool { return c.SHA256 == ca.SHA256 }); i >= 0 {
		next[i] = ca
	} else {
		next = append(next, ca)
	}
	if err := m.checkLocked(next); err != nil {
		return err
	}
	if crl != nil {
		if _, err := m.putCRLLocked(*crl, decide); err != nil {
			return err
		}
	}
	m.cas = next
	m.changes++
	m.epoch++
	return nil
}

func (m *MemoryTrust) trustedLocked(sha256 string) int {
	return slices.IndexFunc(m.cas, func(c store.OperatorCA) bool {
		return c.SHA256 == sha256 && c.State != store.OperatorCARetired
	})
}

// SetOperatorCACRLSource changes a trusted row's CRL source.
func (m *MemoryTrust) SetOperatorCACRLSource(_ context.Context, sha256, source, url string, acks []string, crl *store.OperatorCRL, decide store.DecideCRL) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.trustedLocked(sha256)
	if i < 0 {
		return store.ErrOperatorCANotFound
	}
	next := slices.Clone(m.cas)
	next[i].CRLSource, next[i].CRLURL, next[i].Acknowledgements = source, url, slices.Clone(acks)
	next[i].UpdatedAt = time.Now().UTC()
	if err := m.checkLocked(next); err != nil {
		return err
	}
	if crl != nil {
		if _, err := m.putCRLLocked(*crl, decide); err != nil {
			return err
		}
	}
	m.cas = next
	m.changes++
	m.epoch++
	return nil
}

// SetOperatorCAOCSP changes a trusted row's OCSP settings.
func (m *MemoryTrust) SetOperatorCAOCSP(_ context.Context, sha256, mode, url string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.trustedLocked(sha256)
	if i < 0 {
		return store.ErrOperatorCANotFound
	}
	next := slices.Clone(m.cas)
	next[i].OCSPMode, next[i].OCSPURL, next[i].UpdatedAt = mode, url, time.Now().UTC()
	return m.commitLocked(next)
}

// OperatorCRLs returns every stored CRL and last attempt.
func (m *MemoryTrust) OperatorCRLs(context.Context) ([]store.OperatorCRL, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.OperatorCRL, 0, len(m.crls))
	for _, c := range m.crls {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b store.OperatorCRL) int {
		switch {
		case a.IssuerSHA256 < b.IssuerSHA256:
			return -1
		case a.IssuerSHA256 > b.IssuerSHA256:
			return 1
		}
		return 0
	})
	return out, nil
}

func (m *MemoryTrust) putCRLLocked(c store.OperatorCRL, decide store.DecideCRL) (bool, error) {
	cur, ok := m.crls[c.IssuerSHA256]
	accept, err := decide(cur, ok && cur.DER != nil)
	if err != nil || !accept {
		return false, err
	}
	c.LastError, c.LastAttemptAt = "", c.FetchedAt
	m.crls[c.IssuerSHA256] = c
	return true, nil
}

// PutOperatorCRL stores c when decide accepts it and bumps the epoch.
func (m *MemoryTrust) PutOperatorCRL(_ context.Context, c store.OperatorCRL, decide store.DecideCRL) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ok, err := m.putCRLLocked(c, decide)
	if ok {
		m.epoch++
	}
	return ok, err
}

// RecordOperatorCRLAttempt records a failed refresh.
func (m *MemoryTrust) RecordOperatorCRLAttempt(_ context.Context, issuerSHA256, lastError string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.crls[issuerSHA256]
	c.IssuerSHA256, c.LastError, c.LastAttemptAt = issuerSHA256, lastError, at
	m.crls[issuerSHA256] = c
	return nil
}

// OperatorDenylist returns every entry.
func (m *MemoryTrust) OperatorDenylist(context.Context) ([]store.DenylistEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.denylist), nil
}

// AddOperatorDenylistEntry adds e unless it exists, bumping the epoch.
func (m *MemoryTrust) AddOperatorDenylistEntry(_ context.Context, e store.DenylistEntry) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, have := range m.denylist {
		if have.IssuerSHA256 == e.IssuerSHA256 && have.SerialHex == e.SerialHex {
			return false, nil
		}
	}
	m.denylist = append(m.denylist, e)
	m.epoch++
	return true, nil
}

// OperatorTrustVersion is the row count with a change counter, and the
// epoch.
func (m *MemoryTrust) OperatorTrustVersion(context.Context) (store.TrustVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return store.TrustVersion{CAs: fmt.Sprintf("%d:%d", len(m.cas), m.changes), Epoch: m.epoch}, nil
}

// TryAdvisoryLock takes the named lock if it is free.
func (m *MemoryTrust) TryAdvisoryLock(_ context.Context, name string) (func(), bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locks[name] {
		return nil, false, nil
	}
	m.locks[name] = true
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.locks, name)
	}, true, nil
}
