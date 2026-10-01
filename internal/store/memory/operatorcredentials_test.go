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
	"errors"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// Credential requests, recording and observed credentials need Postgres.
func TestOperatorCredentialStore_NeedsPostgres(t *testing.T) {
	ctx, now, s := context.Background(), time.Now(), New(nil)
	_, listErr := s.OperatorCredentialRequests(ctx, "", now)
	_, getErr := s.OperatorCredentialRequest(ctx, "id", now)
	_, cancelErr := s.CancelOperatorCredentialRequest(ctx, "id", now)
	for name, err := range map[string]error{
		"add":     s.AddOperatorCredentialRequest(ctx, store.OperatorCredentialRequest{}),
		"list":    listErr,
		"get":     getErr,
		"cancel":  cancelErr,
		"record":  s.RecordOperatorCredential(ctx, store.OperatorCredential{}, "", now),
		"observe": s.ObserveOperatorCredential(ctx, store.OperatorCredential{}, now),
	} {
		if !errors.Is(err, store.ErrDatabaseRequired) {
			t.Errorf("%s: error = %v, want ErrDatabaseRequired", name, err)
		}
	}
}
