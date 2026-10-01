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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

// closedFirstRun is a store after a normal day zero: an active and a
// retiring operator CA, a denylist entry, a stored CRL, and a closed latch
// with an ended session.
func closedFirstRun(t *testing.T) *fakeStore {
	t.Helper()
	ctx := context.Background()
	st := newFakeStore()
	for _, ca := range []store.OperatorCA{
		{SHA256: "aa", CertDER: []byte{1}, State: store.OperatorCAActive, CRLSource: store.CRLSourceUpload, RegisteredAt: testNow},
		{SHA256: "bb", CertDER: []byte{2}, State: store.OperatorCARetiring, CRLSource: store.CRLSourceNone, RegisteredAt: testNow},
	} {
		if err := st.AddOperatorCA(ctx, ca); err != nil {
			t.Fatalf("AddOperatorCA: %v", err)
		}
	}
	if _, err := st.AddOperatorDenylistEntry(ctx, store.DenylistEntry{IssuerSHA256: "aa", SerialHex: "1f", RevokedAt: testNow}); err != nil {
		t.Fatalf("AddOperatorDenylistEntry: %v", err)
	}
	if _, err := st.PutOperatorCRL(ctx, store.OperatorCRL{IssuerSHA256: "aa", DER: []byte{9}, ThisUpdate: testNow, NextUpdate: testNow.Add(time.Hour)},
		func(store.OperatorCRL, bool) (bool, error) { return true, nil }); err != nil {
		t.Fatalf("PutOperatorCRL: %v", err)
	}
	st.sessions["s1"] = store.BootstrapSession{Hash: "s1", CreatedAt: testNow, EndedAt: testNow, EndedReason: store.SessionEndedClosed}
	st.latch = store.BootstrapState{ClosedAt: testNow, ClosedBySerial: "1f", ClosedByCN: "admin@example.org", ClosedByIssuerSHA256: "aa"}
	return st
}

func resetOptions(st *fakeStore, audit *memory.Store, out *strings.Builder) ResetOptions {
	return ResetOptions{
		Store: st, Audit: audit, Out: out, Host: "fm-host",
		Live: func(context.Context) bool { return false },
		Now:  func() time.Time { return testNow.Add(time.Hour) },
	}
}

func auditKinds(a *memory.Store) []string {
	var kinds []string
	for _, e := range a.Audit() {
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

func TestReset_ReopensFirstRun(t *testing.T) {
	st, audit, out := closedFirstRun(t), memory.New(nil), &strings.Builder{}
	if err := Reset(context.Background(), resetOptions(st, audit, out)); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	if st.latch.Closed() {
		t.Errorf("latch = %+v, want open", st.latch)
	}
	if len(st.sessions) != 0 || len(st.tokens) != 0 {
		t.Errorf("sessions %v, tokens %v; want none", st.sessions, st.tokens)
	}
	if len(st.cas) != 2 {
		t.Fatalf("operator CAs = %+v, want both rows kept", st.cas)
	}
	for _, ca := range st.cas {
		if ca.State != store.OperatorCARetired || ca.RetiredReason != store.RetiredReset {
			t.Errorf("%s = %s (%q), want retired by the reset", ca.SHA256, ca.State, ca.RetiredReason)
		}
	}
	if len(st.denylist) != 1 || len(st.crls) != 1 {
		t.Errorf("denylist %v, CRLs %v; want both kept", st.denylist, st.crls)
	}
	if st.locks[TokenLockName] {
		t.Error("the token lock is still held after the reset")
	}

	text := out.String()
	for _, want := range []string{
		"admin@example.org",
		"2 operator CA(s) retired",
		"denylist and stored CRLs are kept",
		"The FM never held your operator CA key. If you believe the CA itself is compromised, create a new operator CA before registering again. Otherwise you may register the same CA again.",
		"Revoke at your CA any credential you no longer trust, and publish a new CRL.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "WARNING") {
		t.Errorf("unexpected warning:\n%s", text)
	}

	events := audit.Audit()
	if len(events) != 1 || events[0].Kind != KindBootstrapReset {
		t.Fatalf("audit = %v, want one %s", auditKinds(audit), KindBootstrapReset)
	}
	e := events[0]
	if e.ActorKind != ActorHost || e.ActorCN != "fm-host" || e.Via != ViaCLI || !strings.Contains(e.Summary, "2 operator CA(s) retired") {
		t.Errorf("audit event = %+v", e)
	}
}

func TestReset_RefusesWhileATokenLockIsHeld(t *testing.T) {
	st, audit, out := closedFirstRun(t), memory.New(nil), &strings.Builder{}
	st.locks[TokenLockName] = true
	o := resetOptions(st, audit, out)
	probed := false
	o.Live = func(context.Context) bool { probed = true; return false }

	err := Reset(context.Background(), o)
	if !errors.Is(err, ErrManagerRunning) {
		t.Fatalf("Reset() = %v, want ErrManagerRunning", err)
	}
	if probed {
		t.Error("probed /healthz after the lock was refused")
	}
	if !st.latch.Closed() || st.cas[0].State != store.OperatorCAActive {
		t.Error("the reset changed the store while a manager held the lock")
	}
	if len(audit.Audit()) != 0 {
		t.Errorf("audit = %v, want nothing", auditKinds(audit))
	}
}

func TestReset_RefusesWhileHealthzAnswers(t *testing.T) {
	st, audit, out := closedFirstRun(t), memory.New(nil), &strings.Builder{}
	o := resetOptions(st, audit, out)
	o.Live = func(context.Context) bool { return true }

	err := Reset(context.Background(), o)
	if !errors.Is(err, ErrManagerRunning) {
		t.Fatalf("Reset() = %v, want ErrManagerRunning", err)
	}
	if !st.latch.Closed() || st.cas[0].State != store.OperatorCAActive {
		t.Error("the reset changed the store while the manager answered")
	}
	if st.locks[TokenLockName] {
		t.Error("the token lock is still held after the refusal")
	}
	if len(audit.Audit()) != 0 {
		t.Errorf("audit = %v, want nothing", auditKinds(audit))
	}
}

func TestReset_WarnsWhenFirstRunStaysShut(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*ResetOptions)
		want string
	}{
		"operatorCAPath":    {func(o *ResetOptions) { o.FileSource = true }, "first run stays NOT_APPLICABLE"},
		"firstRun disabled": {func(o *ResetOptions) { o.FirstRunDisabled = true }, "firstRun is disabled"},
	} {
		t.Run(name, func(t *testing.T) {
			st, audit, out := closedFirstRun(t), memory.New(nil), &strings.Builder{}
			o := resetOptions(st, audit, out)
			tc.set(&o)
			if err := Reset(context.Background(), o); err != nil {
				t.Fatalf("Reset: %v", err)
			}
			if !strings.Contains(out.String(), "WARNING") || !strings.Contains(out.String(), tc.want) {
				t.Errorf("output lacks the %q warning:\n%s", tc.want, out.String())
			}
			if st.latch.Closed() {
				t.Error("the warning stopped the reset")
			}
		})
	}
}
