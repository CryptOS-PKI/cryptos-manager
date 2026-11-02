package main

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
	"testing"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store/kv"
)

type fakeKVChecks struct {
	persistence kv.Persistence
	persistErr  error
	aclErr      error
	verifyErr   error
}

func (f fakeKVChecks) CheckPersistence(context.Context) (kv.Persistence, error) {
	return f.persistence, f.persistErr
}
func (f fakeKVChecks) CheckAuditACL(context.Context) error { return f.aclErr }
func (f fakeKVChecks) VerifyAudit(context.Context) error   { return f.verifyErr }

func TestCheckKV(t *testing.T) {
	ctx := context.Background()
	logged := func(buf *strings.Builder) func(string, ...any) {
		return func(f string, a ...any) { fmt.Fprintf(buf, f+"\n", a...) }
	}

	t.Run("AHealthyServerPasses", func(t *testing.T) {
		var b strings.Builder
		if err := checkKV(ctx, fakeKVChecks{persistence: kv.PersistenceAOF}, logged(&b)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("NoPersistenceRefuses", func(t *testing.T) {
		var b strings.Builder
		err := checkKV(ctx, fakeKVChecks{persistence: kv.PersistenceNone, persistErr: kv.ErrNoPersistence}, logged(&b))
		if !errors.Is(err, kv.ErrNoPersistence) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("AnAccountThatCanTrimRefuses", func(t *testing.T) {
		var b strings.Builder
		err := checkKV(ctx, fakeKVChecks{persistence: kv.PersistenceAOF, aclErr: kv.ErrAuditACL}, logged(&b))
		if !errors.Is(err, kv.ErrAuditACL) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("ABrokenChainIsReportedAndStarts", func(t *testing.T) {
		var b strings.Builder
		err := checkKV(ctx, fakeKVChecks{persistence: kv.PersistenceAOF, verifyErr: kv.ErrAuditChainBroken}, logged(&b))
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if !strings.Contains(b.String(), "ERROR") {
			t.Fatalf("log = %q, want an error", b.String())
		}
	})
	t.Run("AnUnreadableChainRefuses", func(t *testing.T) {
		var b strings.Builder
		boom := errors.New("connection reset")
		if err := checkKV(ctx, fakeKVChecks{persistence: kv.PersistenceAOF, verifyErr: boom}, logged(&b)); !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestKVDetail(t *testing.T) {
	for name, tc := range map[string]struct {
		p        kv.Persistence
		chainErr error
		want     storageDetail
	}{
		"aof":        {p: kv.PersistenceAOF, want: storageDetail{Persistence: "aof", AuditChain: auditChainOK}},
		"rdb only":   {p: kv.PersistenceRDBOnly, want: storageDetail{Persistence: "rdb-only", AuditChain: auditChainOK, Degraded: true}},
		"turned off": {p: kv.PersistenceNone, want: storageDetail{Persistence: "none", AuditChain: auditChainOK, Degraded: true}},
		"unknown":    {p: kv.PersistenceUnknown, want: storageDetail{Persistence: "unknown", AuditChain: auditChainOK, Degraded: true}},
		"broken":     {p: kv.PersistenceAOF, chainErr: kv.ErrAuditChainBroken, want: storageDetail{Persistence: "aof", AuditChain: auditChainBroken, Degraded: true}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := kvDetail(tc.p, tc.chainErr); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
