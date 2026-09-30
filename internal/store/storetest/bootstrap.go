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
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
)

// BootstrapStore is what first run needs from a store.
type BootstrapStore interface {
	store.OperatorTrust
	store.Bootstrap
}

// Bootstrap runs the conformance suite for store.Bootstrap. newStore must
// return an empty store with first run open.
func Bootstrap(t *testing.T, newStore func(t *testing.T) BootstrapStore) {
	ctx := context.Background()
	at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	session := func(hash string) store.BootstrapSession {
		return store.BootstrapSession{Hash: hash, CreatedAt: at, LastUsedAt: at, ExpiresAt: at.Add(time.Hour)}
	}
	issue := func(t *testing.T, st BootstrapStore, hash string, expires time.Time) {
		t.Helper()
		if err := st.IssueBootstrapToken(ctx, store.BootstrapToken{Hash: hash, CreatedAt: at, ExpiresAt: expires}); err != nil {
			t.Fatalf("IssueBootstrapToken(%s): %v", hash, err)
		}
	}
	start := func(t *testing.T, st BootstrapStore, token, sess string) bool {
		t.Helper()
		ok, err := st.StartBootstrapSession(ctx, token, session(sess), at)
		if err != nil {
			t.Fatalf("StartBootstrapSession: %v", err)
		}
		return ok
	}

	t.Run("LatchStartsOpenAndClosesOnce", func(t *testing.T) {
		st := newStore(t)
		s, err := st.BootstrapState(ctx)
		if err != nil || s.Closed() {
			t.Fatalf("BootstrapState() = %+v, %v; want open", s, err)
		}
		issue(t, st, "t1", at.Add(time.Hour))
		if !start(t, st, "t1", "s1") {
			t.Fatal("the session didn't start")
		}
		issue(t, st, "t2", at.Add(time.Hour))

		by := store.BootstrapState{ClosedAt: at, ClosedBySerial: "1f", ClosedByCN: "admin@example.org", ClosedByIssuerSHA256: "aa"}
		closed, err := st.CloseBootstrap(ctx, by)
		if err != nil || !closed {
			t.Fatalf("CloseBootstrap() = %v, %v; want true", closed, err)
		}
		again, err := st.CloseBootstrap(ctx, store.BootstrapState{ClosedAt: at.Add(time.Hour), ClosedByCN: "other@example.org"})
		if err != nil || again {
			t.Fatalf("second CloseBootstrap() = %v, %v; want false", again, err)
		}
		s, err = st.BootstrapState(ctx)
		if err != nil || !s.ClosedAt.Equal(at) || s.ClosedBySerial != "1f" || s.ClosedByCN != "admin@example.org" || s.ClosedByIssuerSHA256 != "aa" {
			t.Fatalf("BootstrapState() = %+v, %v; want the first closer", s, err)
		}
		if _, ok, _ := st.LiveBootstrapToken(ctx, at); ok {
			t.Error("a token is still live after the latch closed")
		}
		sess, ok, err := st.BootstrapSession(ctx, "s1")
		if err != nil {
			t.Fatalf("BootstrapSession: %v", err)
		}
		if ok && sess.EndedAt.IsZero() {
			t.Error("the session wasn't ended when the latch closed")
		}
		if err := st.IssueBootstrapToken(ctx, store.BootstrapToken{Hash: "t3", CreatedAt: at, ExpiresAt: at.Add(time.Hour)}); !errors.Is(err, store.ErrBootstrapClosed) {
			t.Errorf("IssueBootstrapToken after close = %v, want ErrBootstrapClosed", err)
		}
	})

	t.Run("OneLiveToken", func(t *testing.T) {
		st := newStore(t)
		if _, ok, err := st.LiveBootstrapToken(ctx, at); err != nil || ok {
			t.Fatalf("LiveBootstrapToken() on an empty store = %v, %v", ok, err)
		}
		issue(t, st, "t1", at.Add(time.Hour))
		issue(t, st, "t2", at.Add(time.Hour))
		tok, ok, err := st.LiveBootstrapToken(ctx, at)
		if err != nil || !ok || tok.Hash != "t2" || !tok.ExpiresAt.Equal(at.Add(time.Hour)) {
			t.Fatalf("LiveBootstrapToken() = %+v, %v, %v; want t2", tok, ok, err)
		}
		if start(t, st, "t1", "s1") {
			t.Fatal("an older token still started a session after a new one was issued")
		}
		if _, ok, _ := st.LiveBootstrapToken(ctx, at.Add(2*time.Hour)); ok {
			t.Error("an expired token is reported live")
		}
	})

	t.Run("TokenIsSingleUseAndExpires", func(t *testing.T) {
		st := newStore(t)
		issue(t, st, "t1", at.Add(time.Hour))
		if start(t, st, "wrong", "s0") {
			t.Fatal("an unknown token started a session")
		}
		if !start(t, st, "t1", "s1") {
			t.Fatal("a good token didn't start a session")
		}
		if start(t, st, "t1", "s2") {
			t.Fatal("a used token started a second session")
		}
		issue(t, st, "t2", at.Add(-time.Minute))
		if start(t, st, "t2", "s3") {
			t.Fatal("an expired token started a session")
		}
		if _, ok, _ := st.BootstrapSession(ctx, "s2"); ok {
			t.Error("a refused start stored a session")
		}
	})

	t.Run("ConcurrentDoubleConsumeStartsOneSession", func(t *testing.T) {
		st := newStore(t)
		issue(t, st, "t1", at.Add(time.Hour))
		var (
			wg      sync.WaitGroup
			started atomic.Int32
		)
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				ok, err := st.StartBootstrapSession(ctx, "t1", session(string(rune('a'+i))), at)
				if err != nil {
					t.Errorf("StartBootstrapSession: %v", err)
				}
				if ok {
					started.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if n := started.Load(); n != 1 {
			t.Fatalf("%d sessions started from one token, want exactly 1", n)
		}
	})

	t.Run("NewSessionSupersedesTheOld", func(t *testing.T) {
		st := newStore(t)
		issue(t, st, "t1", at.Add(time.Hour))
		start(t, st, "t1", "s1")
		issue(t, st, "t2", at.Add(time.Hour))
		start(t, st, "t2", "s2")
		old, ok, err := st.BootstrapSession(ctx, "s1")
		if err != nil || !ok || old.EndedAt.IsZero() || old.EndedReason != store.SessionEndedSuperseded {
			t.Fatalf("the first session = %+v, %v, %v; want ended as superseded", old, ok, err)
		}
		cur, ok, err := st.BootstrapSession(ctx, "s2")
		if err != nil || !ok || !cur.EndedAt.IsZero() || !cur.ExpiresAt.Equal(at.Add(time.Hour)) {
			t.Fatalf("the second session = %+v, %v, %v; want live", cur, ok, err)
		}
	})

	t.Run("SessionTouchEndAndLiveness", func(t *testing.T) {
		st := newStore(t)
		idle := 15 * time.Minute
		if live, err := st.HasLiveBootstrapSession(ctx, at, idle); err != nil || live {
			t.Fatalf("HasLiveBootstrapSession() on an empty store = %v, %v", live, err)
		}
		issue(t, st, "t1", at.Add(time.Hour))
		start(t, st, "t1", "s1")
		if live, _ := st.HasLiveBootstrapSession(ctx, at.Add(time.Minute), idle); !live {
			t.Fatal("a fresh session isn't live")
		}
		if live, _ := st.HasLiveBootstrapSession(ctx, at.Add(16*time.Minute), idle); live {
			t.Fatal("an idle session is live")
		}
		if err := st.TouchBootstrapSession(ctx, "s1", at.Add(10*time.Minute)); err != nil {
			t.Fatalf("TouchBootstrapSession: %v", err)
		}
		s, _, _ := st.BootstrapSession(ctx, "s1")
		if !s.LastUsedAt.Equal(at.Add(10 * time.Minute)) {
			t.Fatalf("LastUsedAt = %v after a touch", s.LastUsedAt)
		}
		if live, _ := st.HasLiveBootstrapSession(ctx, at.Add(16*time.Minute), idle); !live {
			t.Fatal("a touched session isn't live")
		}
		if live, _ := st.HasLiveBootstrapSession(ctx, at.Add(61*time.Minute), time.Hour); live {
			t.Fatal("a session past its absolute expiry is live")
		}
		if err := st.EndBootstrapSession(ctx, "s1", store.SessionEndedExpired, at.Add(11*time.Minute)); err != nil {
			t.Fatalf("EndBootstrapSession: %v", err)
		}
		s, _, _ = st.BootstrapSession(ctx, "s1")
		if s.EndedReason != store.SessionEndedExpired || !s.EndedAt.Equal(at.Add(11*time.Minute)) {
			t.Fatalf("ended session = %+v", s)
		}
		if live, _ := st.HasLiveBootstrapSession(ctx, at.Add(12*time.Minute), idle); live {
			t.Fatal("an ended session is live")
		}

		issue(t, st, "t2", at.Add(time.Hour))
		start(t, st, "t2", "s2")
		n, err := st.EndBootstrapSessions(ctx, store.SessionEndedRateLimited, at.Add(13*time.Minute))
		if err != nil || n != 1 {
			t.Fatalf("EndBootstrapSessions() = %d, %v; want 1", n, err)
		}
	})

	t.Run("StartRefusedOnceClosed", func(t *testing.T) {
		st := newStore(t)
		issue(t, st, "t1", at.Add(time.Hour))
		if _, err := st.CloseBootstrap(ctx, store.BootstrapState{ClosedAt: at, ClosedByCN: "admin@example.org"}); err != nil {
			t.Fatalf("CloseBootstrap: %v", err)
		}
		if start(t, st, "t1", "s1") {
			t.Fatal("a session started after the latch closed")
		}
	})

	t.Run("RegisterFirstRunOperatorCA", func(t *testing.T) {
		st := newStore(t)
		before := trustVersion(t, st)
		first := store.OperatorCA{SHA256: "aa", CertDER: []byte{1}, State: store.OperatorCAActive, CRLSource: store.CRLSourceNone,
			OCSPMode: store.OCSPModeOff, Acknowledgements: []string{"NO_CRL"}, RegisteredAt: at, RegisteredBy: "bootstrap"}
		if err := st.RegisterFirstRunOperatorCA(ctx, first, "s1", nil, nil); err != nil {
			t.Fatalf("RegisterFirstRunOperatorCA: %v", err)
		}
		if by, err := st.OperatorCAConfirmedBy(ctx, "aa"); err != nil || by != "s1" {
			t.Fatalf("OperatorCAConfirmedBy() = %q, %v; want s1", by, err)
		}
		if after := trustVersion(t, st); after.CAs == before.CAs || after.Epoch == before.Epoch {
			t.Fatalf("trust version %+v -> %+v; want both the CAs and the epoch to move", before, after)
		}

		second := store.OperatorCA{SHA256: "bb", CertDER: []byte{2}, State: store.OperatorCAActive, CRLSource: store.CRLSourceURL,
			CRLURL: "http://pki.example.org/op.crl", OCSPMode: store.OCSPModeURL, OCSPURL: "http://ocsp.example.org/", RegisteredAt: at}
		crl := &store.OperatorCRL{IssuerSHA256: "bb", DER: []byte{9}, Number: big.NewInt(7), ThisUpdate: at, NextUpdate: at.Add(time.Hour), FetchedAt: at, Source: store.CRLSourceURL}
		if err := st.RegisterFirstRunOperatorCA(ctx, second, "s2", crl, acceptAll); err != nil {
			t.Fatalf("RegisterFirstRunOperatorCA(second): %v", err)
		}
		cas, err := st.OperatorCAs(ctx)
		if err != nil {
			t.Fatalf("OperatorCAs: %v", err)
		}
		states := map[string]store.OperatorCA{}
		for _, c := range cas {
			states[c.SHA256] = c
		}
		if a := states["aa"]; a.State != store.OperatorCARetired || a.RetiredReason != store.RetiredSuperseded {
			t.Fatalf("the earlier registration = %+v; want retired as superseded", a)
		}
		if b := states["bb"]; b.State != store.OperatorCAActive || b.OCSPMode != store.OCSPModeURL || b.OCSPURL != "http://ocsp.example.org/" || b.CRLURL != second.CRLURL {
			t.Fatalf("the new registration = %+v", b)
		}
		crls, err := st.OperatorCRLs(ctx)
		if err != nil || len(crls) != 1 || crls[0].IssuerSHA256 != "bb" || crls[0].Number.Int64() != 7 {
			t.Fatalf("OperatorCRLs() = %+v, %v; want the registered CRL", crls, err)
		}

		// Registering the first CA again brings its row back.
		if err := st.RegisterFirstRunOperatorCA(ctx, first, "s3", nil, nil); err != nil {
			t.Fatalf("RegisterFirstRunOperatorCA(again): %v", err)
		}
		cas, _ = st.OperatorCAs(ctx)
		for _, c := range cas {
			want := store.OperatorCARetired
			if c.SHA256 == "aa" {
				want = store.OperatorCAActive
			}
			if c.State != want {
				t.Errorf("%s is %s, want %s", c.SHA256, c.State, want)
			}
		}
		if by, _ := st.OperatorCAConfirmedBy(ctx, "aa"); by != "s3" {
			t.Errorf("OperatorCAConfirmedBy(aa) = %q, want s3", by)
		}
	})

	t.Run("RegisterRefusesARolledBackCRL", func(t *testing.T) {
		st := newStore(t)
		ca := store.OperatorCA{SHA256: "aa", CertDER: []byte{1}, State: store.OperatorCAActive, CRLSource: store.CRLSourceUpload, RegisteredAt: at}
		refuse := errors.New("older CRL")
		err := st.RegisterFirstRunOperatorCA(ctx, ca, "s1", &store.OperatorCRL{IssuerSHA256: "aa", DER: []byte{1}, ThisUpdate: at, NextUpdate: at.Add(time.Hour)},
			func(store.OperatorCRL, bool) (bool, error) { return false, refuse })
		if !errors.Is(err, refuse) {
			t.Fatalf("RegisterFirstRunOperatorCA with a refused CRL = %v, want the decision's error", err)
		}
		if cas, _ := st.OperatorCAs(ctx); len(cas) != 0 {
			t.Fatalf("a registration whose CRL was refused stored %+v", cas)
		}
	})

	t.Run("RegisterRefusedOnceClosed", func(t *testing.T) {
		st := newStore(t)
		if _, err := st.CloseBootstrap(ctx, store.BootstrapState{ClosedAt: at}); err != nil {
			t.Fatalf("CloseBootstrap: %v", err)
		}
		err := st.RegisterFirstRunOperatorCA(ctx, store.OperatorCA{SHA256: "aa", CertDER: []byte{1}, State: store.OperatorCAActive, CRLSource: store.CRLSourceNone}, "s1", nil, nil)
		if !errors.Is(err, store.ErrBootstrapClosed) {
			t.Fatalf("RegisterFirstRunOperatorCA after close = %v, want ErrBootstrapClosed", err)
		}
	})

	t.Run("ConfirmOperatorCA", func(t *testing.T) {
		st := newStore(t)
		if err := st.RegisterFirstRunOperatorCA(ctx, store.OperatorCA{SHA256: "aa", CertDER: []byte{1}, State: store.OperatorCAActive, CRLSource: store.CRLSourceNone}, "s1", nil, nil); err != nil {
			t.Fatalf("RegisterFirstRunOperatorCA: %v", err)
		}
		if err := st.ConfirmOperatorCA(ctx, "aa", "s2"); err != nil {
			t.Fatalf("ConfirmOperatorCA: %v", err)
		}
		if by, _ := st.OperatorCAConfirmedBy(ctx, "aa"); by != "s2" {
			t.Fatalf("OperatorCAConfirmedBy() = %q, want s2", by)
		}
		if err := st.ConfirmOperatorCA(ctx, "zz", "s2"); !errors.Is(err, store.ErrOperatorCANotFound) {
			t.Fatalf("ConfirmOperatorCA(unknown) = %v, want ErrOperatorCANotFound", err)
		}
	})

	t.Run("FirstAdminRecords", func(t *testing.T) {
		st := newStore(t)
		c := store.OperatorCredential{IssuerSHA256: "aa", SerialHex: "1f", CommonName: "admin@example.org", Level: "admin",
			NotAfter: "2027-09-30T12:00:00Z", Email: "admin@example.org", FullName: "Ada Example", LeafSHA256: "cc"}
		if err := st.RecordFirstAdmin(ctx, c, at); err != nil {
			t.Fatalf("RecordFirstAdmin: %v", err)
		}
		c.FullName = "Ada B. Example"
		if err := st.RecordFirstAdmin(ctx, c, at); err != nil {
			t.Fatalf("RecordFirstAdmin again: %v", err)
		}
		got, err := st.FirstAdminCredentials(ctx)
		if err != nil || len(got) != 1 || got[0].FullName != "Ada B. Example" || got[0].Kind != store.OperatorCredentialFirstAdmin ||
			got[0].IssuerSHA256 != "aa" || got[0].SerialHex != "1f" || got[0].Email != "admin@example.org" || got[0].LeafSHA256 != "cc" {
			t.Fatalf("FirstAdminCredentials() = %+v, %v", got, err)
		}

		stored, err := st.RecordFirstUse(ctx, c, at)
		if err != nil || stored {
			t.Fatalf("RecordFirstUse of a recorded credential = %v, %v; want false", stored, err)
		}
		other := c
		other.SerialHex, other.FullName = "20", ""
		stored, err = st.RecordFirstUse(ctx, other, at)
		if err != nil || !stored {
			t.Fatalf("RecordFirstUse of a new credential = %v, %v; want true", stored, err)
		}
		got, _ = st.FirstAdminCredentials(ctx)
		if len(got) != 2 {
			t.Fatalf("FirstAdminCredentials() = %+v, want both", got)
		}
	})
}
