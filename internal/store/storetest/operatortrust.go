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
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// OperatorTrust runs the operator CA, CRL, denylist and trust-version checks
// against stores built by newStore, which must return an empty store each
// time it is called. It covers the store that backs the registered operator
// CA source, so the store must support every method.
func OperatorTrust(t *testing.T, newStore func(t *testing.T) store.OperatorTrust) {
	ctx := context.Background()
	at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	t.Run("AddAndListOperatorCAs", func(t *testing.T) {
		st := newStore(t)
		in := store.OperatorCA{
			SHA256: "aa", CertDER: []byte{1, 2, 3}, State: store.OperatorCAActive,
			CRLSource: store.CRLSourceURL, CRLURL: "http://pki.example.org/op.crl",
			Acknowledgements: []string{}, Warnings: []string{"issued by a fleet CA"},
			RegisteredAt: at, RegisteredBy: "bootstrap",
		}
		if err := st.AddOperatorCA(ctx, in); err != nil {
			t.Fatalf("AddOperatorCA: %v", err)
		}
		cas, err := st.OperatorCAs(ctx)
		if err != nil || len(cas) != 1 {
			t.Fatalf("OperatorCAs() = %+v, %v; want one row", cas, err)
		}
		got := cas[0]
		if got.SHA256 != "aa" || !bytes.Equal(got.CertDER, in.CertDER) || got.State != store.OperatorCAActive ||
			got.CRLSource != store.CRLSourceURL || got.CRLURL != in.CRLURL || got.RegisteredBy != "bootstrap" ||
			!got.RegisteredAt.Equal(at) || len(got.Warnings) != 1 || got.Warnings[0] != in.Warnings[0] {
			t.Fatalf("OperatorCAs()[0] = %+v, want %+v", got, in)
		}
		if got.OCSPMode != store.OCSPModeAIA {
			t.Errorf("OCSPMode = %q, want the default %q", got.OCSPMode, store.OCSPModeAIA)
		}
		if got.UpdatedAt.IsZero() {
			t.Error("UpdatedAt is zero")
		}
	})

	t.Run("OneActiveAndOneRetiringAtMost", func(t *testing.T) {
		st := newStore(t)
		mustAddCA(t, st, "a1", store.OperatorCAActive)
		if err := st.AddOperatorCA(ctx, ca("a2", store.OperatorCAActive)); err == nil {
			t.Fatal("a second active operator CA was stored")
		}
		mustAddCA(t, st, "r1", store.OperatorCARetiring)
		if err := st.AddOperatorCA(ctx, ca("r2", store.OperatorCARetiring)); err == nil {
			t.Fatal("a second retiring operator CA was stored")
		}
		mustAddCA(t, st, "x1", store.OperatorCARetired)
		mustAddCA(t, st, "x2", store.OperatorCARetired)
	})

	t.Run("URLModeNeedsAnOCSPURL", func(t *testing.T) {
		st := newStore(t)
		c := ca("u1", store.OperatorCAActive)
		c.OCSPMode = store.OCSPModeURL
		if err := st.AddOperatorCA(ctx, c); err == nil {
			t.Fatal("an operator CA in OCSP url mode with no URL was stored")
		}
		c.OCSPURL = "http://ocsp.example.org/"
		if err := st.AddOperatorCA(ctx, c); err != nil {
			t.Fatalf("AddOperatorCA with an OCSP URL: %v", err)
		}
	})

	t.Run("SetOperatorCAStateRetiresAndChangesTheTrustVersion", func(t *testing.T) {
		st := newStore(t)
		mustAddCA(t, st, "a1", store.OperatorCAActive)
		before := trustVersion(t, st)

		if err := st.SetOperatorCAState(ctx, "a1", store.OperatorCARetired, "superseded", at); err != nil {
			t.Fatalf("SetOperatorCAState: %v", err)
		}
		cas, _ := st.OperatorCAs(ctx)
		if cas[0].State != store.OperatorCARetired || cas[0].RetiredReason != "superseded" || !cas[0].RetiredAt.Equal(at) {
			t.Fatalf("after retiring: %+v", cas[0])
		}
		if after := trustVersion(t, st); after.CAs == before.CAs {
			t.Fatalf("trust version unchanged after a state change: %+v", after)
		}
		if err := st.SetOperatorCAState(ctx, "missing", store.OperatorCARetired, "", at); !errors.Is(err, store.ErrOperatorCANotFound) {
			t.Fatalf("SetOperatorCAState(missing) error = %v, want ErrOperatorCANotFound", err)
		}
	})

	t.Run("AddingACAChangesTheTrustVersion", func(t *testing.T) {
		st := newStore(t)
		before := trustVersion(t, st)
		mustAddCA(t, st, "a1", store.OperatorCAActive)
		if after := trustVersion(t, st); after.CAs == before.CAs {
			t.Fatal("trust version unchanged after adding a CA")
		}
	})

	t.Run("DenylistIsKeyedByIssuerAndBumpsTheEpoch", func(t *testing.T) {
		st := newStore(t)
		before := trustVersion(t, st)

		added, err := st.AddOperatorDenylistEntry(ctx, store.DenylistEntry{
			IssuerSHA256: "aa", SerialHex: "1f", Reason: 4, RevokedAt: at, RevokedByCN: "admin@example.org", Note: "left",
		})
		if err != nil || !added {
			t.Fatalf("AddOperatorDenylistEntry = %v, %v; want added", added, err)
		}
		if _, err := st.AddOperatorDenylistEntry(ctx, store.DenylistEntry{IssuerSHA256: "bb", SerialHex: "1f", RevokedAt: at}); err != nil {
			t.Fatalf("same serial under another issuer: %v", err)
		}
		mid := trustVersion(t, st)
		if mid.Epoch != before.Epoch+2 {
			t.Fatalf("epoch = %d, want %d after two new entries", mid.Epoch, before.Epoch+2)
		}

		again, err := st.AddOperatorDenylistEntry(ctx, store.DenylistEntry{IssuerSHA256: "aa", SerialHex: "1f", Reason: 1, RevokedAt: at.Add(time.Hour)})
		if err != nil || again {
			t.Fatalf("re-adding an entry = %v, %v; want not added", again, err)
		}
		if after := trustVersion(t, st); after.Epoch != mid.Epoch {
			t.Fatalf("epoch moved on a no-op denylist write: %d -> %d", mid.Epoch, after.Epoch)
		}

		list, err := st.OperatorDenylist(ctx)
		if err != nil || len(list) != 2 {
			t.Fatalf("OperatorDenylist() = %+v, %v; want two entries", list, err)
		}
		for _, e := range list {
			if e.IssuerSHA256 == "aa" && (e.Reason != 4 || e.Note != "left" || e.RevokedByCN != "admin@example.org" || !e.RevokedAt.Equal(at)) {
				t.Fatalf("first entry was overwritten: %+v", e)
			}
		}
	})

	t.Run("PutOperatorCRLStoresOnlyWhatDecideAccepts", func(t *testing.T) {
		st := newStore(t)
		before := trustVersion(t, st)
		first := store.OperatorCRL{
			IssuerSHA256: "aa", DER: []byte("crl-1"), Number: big.NewInt(1000),
			ThisUpdate: at, NextUpdate: at.Add(7 * 24 * time.Hour), FetchedAt: at, Source: store.CRLSourceURL,
		}
		stored, err := st.PutOperatorCRL(ctx, first, func(_ store.OperatorCRL, has bool) (bool, error) {
			if has {
				t.Error("decide saw a stored CRL in an empty store")
			}
			return true, nil
		})
		if err != nil || !stored {
			t.Fatalf("PutOperatorCRL(first) = %v, %v", stored, err)
		}
		if got := trustVersion(t, st); got.Epoch != before.Epoch+1 {
			t.Fatalf("epoch = %d after a stored CRL, want %d", got.Epoch, before.Epoch+1)
		}

		second := first
		second.DER = []byte("crl-0")
		second.Number = big.NewInt(999)
		stored, err = st.PutOperatorCRL(ctx, second, func(cur store.OperatorCRL, has bool) (bool, error) {
			if !has || string(cur.DER) != "crl-1" || cur.Number.Cmp(big.NewInt(1000)) != 0 {
				t.Errorf("decide saw %+v (has %v), want the stored crl-1", cur, has)
			}
			return false, nil
		})
		if err != nil || stored {
			t.Fatalf("PutOperatorCRL(refused) = %v, %v; want not stored", stored, err)
		}
		refuse := errors.New("rollback")
		if _, err := st.PutOperatorCRL(ctx, second, func(store.OperatorCRL, bool) (bool, error) { return false, refuse }); !errors.Is(err, refuse) {
			t.Fatalf("PutOperatorCRL error = %v, want the decide error", err)
		}

		crls, err := st.OperatorCRLs(ctx)
		if err != nil || len(crls) != 1 || string(crls[0].DER) != "crl-1" || crls[0].Number.Cmp(big.NewInt(1000)) != 0 ||
			!crls[0].NextUpdate.Equal(first.NextUpdate) || crls[0].Source != store.CRLSourceURL {
			t.Fatalf("OperatorCRLs() = %+v, %v; want crl-1 only", crls, err)
		}
		if got := trustVersion(t, st); got.Epoch != before.Epoch+1 {
			t.Fatalf("epoch moved on a refused CRL: %d", got.Epoch)
		}
	})

	t.Run("ACRLWithoutANumberRoundTrips", func(t *testing.T) {
		st := newStore(t)
		c := store.OperatorCRL{IssuerSHA256: "aa", DER: []byte("crl"), ThisUpdate: at, NextUpdate: at.Add(time.Hour), FetchedAt: at}
		if _, err := st.PutOperatorCRL(ctx, c, acceptAll); err != nil {
			t.Fatalf("PutOperatorCRL: %v", err)
		}
		crls, _ := st.OperatorCRLs(ctx)
		if len(crls) != 1 || crls[0].Number != nil {
			t.Fatalf("OperatorCRLs() = %+v, want one CRL with no number", crls)
		}
	})

	t.Run("AFailedAttemptKeepsTheLastGoodCRL", func(t *testing.T) {
		st := newStore(t)
		good := store.OperatorCRL{IssuerSHA256: "aa", DER: []byte("good"), ThisUpdate: at, NextUpdate: at.Add(time.Hour), FetchedAt: at}
		if _, err := st.PutOperatorCRL(ctx, good, acceptAll); err != nil {
			t.Fatalf("PutOperatorCRL: %v", err)
		}
		if err := st.RecordOperatorCRLAttempt(ctx, "aa", "CRL_UNREACHABLE: connection refused", at.Add(time.Minute)); err != nil {
			t.Fatalf("RecordOperatorCRLAttempt: %v", err)
		}
		if err := st.RecordOperatorCRLAttempt(ctx, "bb", "CRL_INVALID: bad signature", at); err != nil {
			t.Fatalf("RecordOperatorCRLAttempt with no CRL: %v", err)
		}
		crls, _ := st.OperatorCRLs(ctx)
		byIssuer := map[string]store.OperatorCRL{}
		for _, c := range crls {
			byIssuer[c.IssuerSHA256] = c
		}
		if a := byIssuer["aa"]; string(a.DER) != "good" || a.LastError == "" || !a.LastAttemptAt.Equal(at.Add(time.Minute)) {
			t.Fatalf("aa after a failed attempt = %+v", a)
		}
		if b := byIssuer["bb"]; b.DER != nil || b.LastError != "CRL_INVALID: bad signature" {
			t.Fatalf("bb = %+v, want an error with no CRL", b)
		}
		if _, err := st.PutOperatorCRL(ctx, good, acceptAll); err != nil {
			t.Fatalf("PutOperatorCRL: %v", err)
		}
		crls, _ = st.OperatorCRLs(ctx)
		for _, c := range crls {
			if c.IssuerSHA256 == "aa" && c.LastError != "" {
				t.Fatalf("a stored CRL kept the old error: %+v", c)
			}
		}
	})

	t.Run("RotateMovesTheActiveCAToRetiring", func(t *testing.T) {
		st := newStore(t)
		mustAddCA(t, st, "a1", store.OperatorCAActive)
		mustAddCA(t, st, "x1", store.OperatorCARetired)
		before := trustVersion(t, st)

		next := ca("a2", store.OperatorCAActive)
		next.CRLSource, next.CRLURL, next.Acknowledgements = store.CRLSourceURL, "http://pki.example.org/g2.crl", []string{}
		next.OCSPMode, next.OCSPURL = store.OCSPModeURL, "http://ocsp.example.org/"
		next.RegisteredBy = "admin@example.org"
		crl := &store.OperatorCRL{IssuerSHA256: "a2", DER: []byte("crl-a2"), Number: big.NewInt(5), ThisUpdate: at, NextUpdate: at.Add(time.Hour), FetchedAt: at, Source: store.CRLSourceURL}
		if err := st.RotateOperatorCA(ctx, next, crl, acceptAll); err != nil {
			t.Fatalf("RotateOperatorCA: %v", err)
		}
		states := caStates(t, st)
		if states["a1"] != store.OperatorCARetiring || states["a2"] != store.OperatorCAActive || states["x1"] != store.OperatorCARetired {
			t.Fatalf("states after a rotation = %v", states)
		}
		got := caRow(t, st, "a2")
		if got.CRLSource != store.CRLSourceURL || got.CRLURL != next.CRLURL || got.OCSPMode != store.OCSPModeURL ||
			got.OCSPURL != next.OCSPURL || got.RegisteredBy != "admin@example.org" {
			t.Fatalf("the new row = %+v", got)
		}
		crls, _ := st.OperatorCRLs(ctx)
		if len(crls) != 1 || string(crls[0].DER) != "crl-a2" {
			t.Fatalf("OperatorCRLs() = %+v, want the new CA's CRL", crls)
		}
		after := trustVersion(t, st)
		if after.CAs == before.CAs || after.Epoch <= before.Epoch {
			t.Fatalf("trust version %+v -> %+v, want both parts moved", before, after)
		}
	})

	t.Run("RotateRefusesWhileACAIsRetiring", func(t *testing.T) {
		st := newStore(t)
		mustAddCA(t, st, "a1", store.OperatorCAActive)
		mustAddCA(t, st, "r1", store.OperatorCARetiring)
		before := trustVersion(t, st)
		err := st.RotateOperatorCA(ctx, ca("a2", store.OperatorCAActive), nil, nil)
		if !errors.Is(err, store.ErrRotationInProgress) {
			t.Fatalf("RotateOperatorCA error = %v, want ErrRotationInProgress", err)
		}
		if states := caStates(t, st); len(states) != 2 || states["a1"] != store.OperatorCAActive || states["r1"] != store.OperatorCARetiring {
			t.Fatalf("states after a refused rotation = %v", states)
		}
		if after := trustVersion(t, st); after != before {
			t.Fatalf("trust version moved on a refused rotation: %+v -> %+v", before, after)
		}
	})

	t.Run("RotateRefusesACAThatIsAlreadyTrusted", func(t *testing.T) {
		st := newStore(t)
		mustAddCA(t, st, "a1", store.OperatorCAActive)
		if err := st.RotateOperatorCA(ctx, ca("a1", store.OperatorCAActive), nil, nil); !errors.Is(err, store.ErrOperatorCATrusted) {
			t.Fatalf("RotateOperatorCA(the active CA) error = %v, want ErrOperatorCATrusted", err)
		}
		if states := caStates(t, st); states["a1"] != store.OperatorCAActive {
			t.Fatalf("states = %v", states)
		}
	})

	t.Run("RotateBringsBackARetiredCA", func(t *testing.T) {
		st := newStore(t)
		mustAddCA(t, st, "x1", store.OperatorCARetired)
		if err := st.SetOperatorCAState(ctx, "x1", store.OperatorCARetired, "retired", at); err != nil {
			t.Fatal(err)
		}
		mustAddCA(t, st, "a1", store.OperatorCAActive)
		if err := st.RotateOperatorCA(ctx, ca("x1", store.OperatorCAActive), nil, nil); err != nil {
			t.Fatalf("RotateOperatorCA(a retired CA): %v", err)
		}
		got := caRow(t, st, "x1")
		if got.State != store.OperatorCAActive || !got.RetiredAt.IsZero() || got.RetiredReason != "" {
			t.Fatalf("the CA brought back = %+v", got)
		}
		if states := caStates(t, st); states["a1"] != store.OperatorCARetiring {
			t.Fatalf("states = %v", states)
		}
	})

	t.Run("RotateWithARefusedCRLWritesNothing", func(t *testing.T) {
		st := newStore(t)
		mustAddCA(t, st, "a1", store.OperatorCAActive)
		refuse := errors.New("rollback")
		crl := &store.OperatorCRL{IssuerSHA256: "a2", DER: []byte("crl"), ThisUpdate: at, NextUpdate: at.Add(time.Hour), FetchedAt: at}
		err := st.RotateOperatorCA(ctx, ca("a2", store.OperatorCAActive), crl, func(store.OperatorCRL, bool) (bool, error) { return false, refuse })
		if !errors.Is(err, refuse) {
			t.Fatalf("RotateOperatorCA error = %v, want the decide error", err)
		}
		if states := caStates(t, st); len(states) != 1 || states["a1"] != store.OperatorCAActive {
			t.Fatalf("states after a refused CRL = %v", states)
		}
	})

	t.Run("SetOperatorCACRLSourceChangesATrustedCA", func(t *testing.T) {
		st := newStore(t)
		mustAddCA(t, st, "a1", store.OperatorCAActive)
		mustAddCA(t, st, "x1", store.OperatorCARetired)
		before := trustVersion(t, st)

		crl := &store.OperatorCRL{IssuerSHA256: "a1", DER: []byte("crl-a1"), ThisUpdate: at, NextUpdate: at.Add(time.Hour), FetchedAt: at, Source: store.CRLSourceURL}
		if err := st.SetOperatorCACRLSource(ctx, "a1", store.CRLSourceURL, "http://pki.example.org/a1.crl", []string{}, crl, acceptAll); err != nil {
			t.Fatalf("SetOperatorCACRLSource: %v", err)
		}
		got := caRow(t, st, "a1")
		if got.CRLSource != store.CRLSourceURL || got.CRLURL != "http://pki.example.org/a1.crl" || len(got.Acknowledgements) != 0 {
			t.Fatalf("row after the change = %+v", got)
		}
		crls, _ := st.OperatorCRLs(ctx)
		if len(crls) != 1 || string(crls[0].DER) != "crl-a1" {
			t.Fatalf("OperatorCRLs() = %+v", crls)
		}
		after := trustVersion(t, st)
		if after.CAs == before.CAs || after.Epoch <= before.Epoch {
			t.Fatalf("trust version %+v -> %+v, want both parts moved", before, after)
		}

		if err := st.SetOperatorCACRLSource(ctx, "a1", store.CRLSourceNone, "", []string{"NO_CRL"}, nil, nil); err != nil {
			t.Fatalf("SetOperatorCACRLSource(none): %v", err)
		}
		if got := caRow(t, st, "a1"); got.CRLSource != store.CRLSourceNone || got.CRLURL != "" || len(got.Acknowledgements) != 1 {
			t.Fatalf("row after switching to none = %+v", got)
		}
		if err := st.SetOperatorCACRLSource(ctx, "x1", store.CRLSourceNone, "", []string{"NO_CRL"}, nil, nil); !errors.Is(err, store.ErrOperatorCANotFound) {
			t.Fatalf("SetOperatorCACRLSource(retired) error = %v, want ErrOperatorCANotFound", err)
		}
	})

	t.Run("SetOperatorCAOCSPChangesATrustedCA", func(t *testing.T) {
		st := newStore(t)
		mustAddCA(t, st, "a1", store.OperatorCAActive)
		mustAddCA(t, st, "x1", store.OperatorCARetired)
		before := trustVersion(t, st)
		if err := st.SetOperatorCAOCSP(ctx, "a1", store.OCSPModeURL, "http://ocsp.example.org/"); err != nil {
			t.Fatalf("SetOperatorCAOCSP: %v", err)
		}
		if got := caRow(t, st, "a1"); got.OCSPMode != store.OCSPModeURL || got.OCSPURL != "http://ocsp.example.org/" {
			t.Fatalf("row = %+v", got)
		}
		if after := trustVersion(t, st); after.CAs == before.CAs {
			t.Fatal("trust version unchanged after an OCSP change")
		}
		if err := st.SetOperatorCAOCSP(ctx, "a1", store.OCSPModeOff, ""); err != nil {
			t.Fatalf("SetOperatorCAOCSP(off): %v", err)
		}
		if got := caRow(t, st, "a1"); got.OCSPMode != store.OCSPModeOff || got.OCSPURL != "" {
			t.Fatalf("row after off = %+v", got)
		}
		if err := st.SetOperatorCAOCSP(ctx, "a1", store.OCSPModeURL, ""); err == nil {
			t.Fatal("url mode with no URL was stored")
		}
		if err := st.SetOperatorCAOCSP(ctx, "x1", store.OCSPModeOff, ""); !errors.Is(err, store.ErrOperatorCANotFound) {
			t.Fatalf("SetOperatorCAOCSP(retired) error = %v, want ErrOperatorCANotFound", err)
		}
	})

	t.Run("TryAdvisoryLockIsExclusive", func(t *testing.T) {
		st := newStore(t)
		release, ok, err := st.TryAdvisoryLock(ctx, "fleetos.crl.test")
		if err != nil || !ok {
			t.Fatalf("first TryAdvisoryLock = %v, %v", ok, err)
		}
		if _, ok, err := st.TryAdvisoryLock(ctx, "fleetos.crl.test"); err != nil || ok {
			t.Fatalf("second TryAdvisoryLock = %v, %v; want not acquired", ok, err)
		}
		other, ok, err := st.TryAdvisoryLock(ctx, "fleetos.crl.other")
		if err != nil || !ok {
			t.Fatalf("TryAdvisoryLock on another name = %v, %v", ok, err)
		}
		other()
		release()
		again, ok, err := st.TryAdvisoryLock(ctx, "fleetos.crl.test")
		if err != nil || !ok {
			t.Fatalf("TryAdvisoryLock after release = %v, %v", ok, err)
		}
		again()
	})
}

func acceptAll(store.OperatorCRL, bool) (bool, error) { return true, nil }

func ca(sha, state string) store.OperatorCA {
	return store.OperatorCA{SHA256: sha, CertDER: []byte(sha), State: state, CRLSource: store.CRLSourceNone,
		Acknowledgements: []string{"NO_CRL"}, RegisteredAt: time.Now().UTC()}
}

func mustAddCA(t *testing.T, st store.OperatorTrust, sha, state string) {
	t.Helper()
	if err := st.AddOperatorCA(context.Background(), ca(sha, state)); err != nil {
		t.Fatalf("AddOperatorCA(%s, %s): %v", sha, state, err)
	}
}

func caStates(t *testing.T, st store.OperatorTrust) map[string]string {
	t.Helper()
	cas, err := st.OperatorCAs(context.Background())
	if err != nil {
		t.Fatalf("OperatorCAs: %v", err)
	}
	out := map[string]string{}
	for _, c := range cas {
		out[c.SHA256] = c.State
	}
	return out
}

func caRow(t *testing.T, st store.OperatorTrust, sha string) store.OperatorCA {
	t.Helper()
	cas, err := st.OperatorCAs(context.Background())
	if err != nil {
		t.Fatalf("OperatorCAs: %v", err)
	}
	for _, c := range cas {
		if c.SHA256 == sha {
			return c
		}
	}
	t.Fatalf("no operator CA %s", sha)
	return store.OperatorCA{}
}

func trustVersion(t *testing.T, st store.OperatorTrust) store.TrustVersion {
	t.Helper()
	v, err := st.OperatorTrustVersion(context.Background())
	if err != nil {
		t.Fatalf("OperatorTrustVersion: %v", err)
	}
	return v
}
