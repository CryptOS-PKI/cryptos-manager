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
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
)

var _ store.OperatorCredentialStore = (*Store)(nil)

// Credential requests, recording and observed credentials need Postgres, so
// the in-memory store refuses them all with ErrDatabaseRequired.

// AddOperatorCredentialRequest refuses: requests need Postgres.
func (s *Store) AddOperatorCredentialRequest(context.Context, store.OperatorCredentialRequest) error {
	return store.ErrDatabaseRequired
}

// OperatorCredentialRequests refuses: requests need Postgres.
func (s *Store) OperatorCredentialRequests(context.Context, string, time.Time) ([]store.OperatorCredentialRequest, error) {
	return nil, store.ErrDatabaseRequired
}

// OperatorCredentialRequest refuses: requests need Postgres.
func (s *Store) OperatorCredentialRequest(context.Context, string, time.Time) (store.OperatorCredentialRequest, error) {
	return store.OperatorCredentialRequest{}, store.ErrDatabaseRequired
}

// CancelOperatorCredentialRequest refuses: requests need Postgres.
func (s *Store) CancelOperatorCredentialRequest(context.Context, string, time.Time) (store.OperatorCredentialRequest, error) {
	return store.OperatorCredentialRequest{}, store.ErrDatabaseRequired
}

// RecordOperatorCredential refuses: recording needs Postgres.
func (s *Store) RecordOperatorCredential(context.Context, store.OperatorCredential, string, time.Time) error {
	return store.ErrDatabaseRequired
}

// ObserveOperatorCredential refuses: observed credentials need Postgres.
func (s *Store) ObserveOperatorCredential(context.Context, store.OperatorCredential, time.Time) error {
	return store.ErrDatabaseRequired
}
