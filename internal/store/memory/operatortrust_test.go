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

	"github.com/CryptOS-PKI/manager/internal/store"
)

// The in-memory store backs only the file source: no registered operator
// CAs and no denylist, which both need Postgres. CRLs are kept per process.
func TestOperatorTrust_MemoryNeedsPostgresForRowsAndDenylist(t *testing.T) {
	st := New(nil)
	ctx := context.Background()

	if err := st.AddOperatorCA(ctx, store.OperatorCA{SHA256: "aa", State: store.OperatorCAActive}); !errors.Is(err, store.ErrDatabaseRequired) {
		t.Fatalf("AddOperatorCA error = %v, want ErrDatabaseRequired", err)
	}
	if cas, err := st.OperatorCAs(ctx); err != nil || len(cas) != 0 {
		t.Fatalf("OperatorCAs() = %+v, %v; want none", cas, err)
	}
	if _, err := st.AddOperatorDenylistEntry(ctx, store.DenylistEntry{IssuerSHA256: "aa", SerialHex: "1"}); !errors.Is(err, store.ErrDatabaseRequired) {
		t.Fatalf("AddOperatorDenylistEntry error = %v, want ErrDatabaseRequired", err)
	}
	if list, err := st.OperatorDenylist(ctx); err != nil || len(list) != 0 {
		t.Fatalf("OperatorDenylist() = %+v, %v; want none", list, err)
	}
}

func TestOperatorTrust_MemoryKeepsCRLsAndLocks(t *testing.T) {
	st := New(nil)
	ctx := context.Background()
	at := time.Now().UTC()

	before, _ := st.OperatorTrustVersion(ctx)
	c := store.OperatorCRL{IssuerSHA256: "aa", DER: []byte("crl"), ThisUpdate: at, NextUpdate: at.Add(time.Hour)}
	if stored, err := st.PutOperatorCRL(ctx, c, func(store.OperatorCRL, bool) (bool, error) { return true, nil }); err != nil || !stored {
		t.Fatalf("PutOperatorCRL = %v, %v", stored, err)
	}
	if after, _ := st.OperatorTrustVersion(ctx); after.Epoch != before.Epoch+1 {
		t.Fatalf("epoch = %d, want %d", after.Epoch, before.Epoch+1)
	}
	if err := st.RecordOperatorCRLAttempt(ctx, "aa", "CRL_UNREACHABLE", at); err != nil {
		t.Fatalf("RecordOperatorCRLAttempt: %v", err)
	}
	crls, err := st.OperatorCRLs(ctx)
	if err != nil || len(crls) != 1 || string(crls[0].DER) != "crl" || crls[0].LastError != "CRL_UNREACHABLE" {
		t.Fatalf("OperatorCRLs() = %+v, %v", crls, err)
	}

	release, ok, err := st.TryAdvisoryLock(ctx, "fleetos.crl.aa")
	if err != nil || !ok {
		t.Fatalf("TryAdvisoryLock = %v, %v", ok, err)
	}
	release()
}
