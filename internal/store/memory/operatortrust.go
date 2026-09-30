package memory

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
	"sync"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
)

var _ store.OperatorTrust = (*Store)(nil)

// trustState is the operator trust data the in-memory store keeps. Registered
// operator CAs and the denylist need Postgres, so only CRLs live here, per
// process, which is how a config-file operator CA without Postgres works.
type trustState struct {
	mu    sync.Mutex
	crls  map[string]store.OperatorCRL
	epoch int64
}

// OperatorCAs returns no rows: registered operator CAs need Postgres.
func (s *Store) OperatorCAs(context.Context) ([]store.OperatorCA, error) {
	return nil, nil
}

// AddOperatorCA refuses: registered operator CAs need Postgres.
func (s *Store) AddOperatorCA(context.Context, store.OperatorCA) error {
	return store.ErrDatabaseRequired
}

// SetOperatorCAState finds nothing to change.
func (s *Store) SetOperatorCAState(context.Context, string, string, string, time.Time) error {
	return store.ErrOperatorCANotFound
}

// OperatorCRLs returns the CRLs this process stored.
func (s *Store) OperatorCRLs(context.Context) ([]store.OperatorCRL, error) {
	s.trust.mu.Lock()
	defer s.trust.mu.Unlock()
	out := make([]store.OperatorCRL, 0, len(s.trust.crls))
	for _, c := range s.trust.crls {
		out = append(out, c)
	}
	return out, nil
}

// PutOperatorCRL stores c if decide accepts it.
func (s *Store) PutOperatorCRL(_ context.Context, c store.OperatorCRL, decide store.DecideCRL) (bool, error) {
	s.trust.mu.Lock()
	defer s.trust.mu.Unlock()
	cur, ok := s.trust.crls[c.IssuerSHA256]
	accept, err := decide(cur, ok && cur.DER != nil)
	if err != nil || !accept {
		return false, err
	}
	if s.trust.crls == nil {
		s.trust.crls = map[string]store.OperatorCRL{}
	}
	c.LastError = ""
	c.LastAttemptAt = c.FetchedAt
	s.trust.crls[c.IssuerSHA256] = c
	s.trust.epoch++
	return true, nil
}

// RecordOperatorCRLAttempt records a failed refresh, keeping the stored CRL.
func (s *Store) RecordOperatorCRLAttempt(_ context.Context, issuerSHA256, lastError string, at time.Time) error {
	s.trust.mu.Lock()
	defer s.trust.mu.Unlock()
	if s.trust.crls == nil {
		s.trust.crls = map[string]store.OperatorCRL{}
	}
	c := s.trust.crls[issuerSHA256]
	c.IssuerSHA256 = issuerSHA256
	c.LastError = lastError
	c.LastAttemptAt = at
	s.trust.crls[issuerSHA256] = c
	return nil
}

// OperatorDenylist returns no entries: the denylist needs Postgres.
func (s *Store) OperatorDenylist(context.Context) ([]store.DenylistEntry, error) {
	return nil, nil
}

// AddOperatorDenylistEntry refuses: the denylist needs Postgres.
func (s *Store) AddOperatorDenylistEntry(context.Context, store.DenylistEntry) (bool, error) {
	return false, store.ErrDatabaseRequired
}

// OperatorTrustVersion reports the per-process epoch. There are never any
// operator CA rows.
func (s *Store) OperatorTrustVersion(context.Context) (store.TrustVersion, error) {
	s.trust.mu.Lock()
	defer s.trust.mu.Unlock()
	return store.TrustVersion{Epoch: s.trust.epoch}, nil
}

// TryAdvisoryLock always succeeds: one process is the only replica.
func (s *Store) TryAdvisoryLock(context.Context, string) (func(), bool, error) {
	return func() {}, true, nil
}
