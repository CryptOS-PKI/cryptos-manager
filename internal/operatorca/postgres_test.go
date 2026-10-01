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
	"fmt"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/postgres"
	"github.com/jackc/pgx/v5"
)

// pgStores returns n stores on one fresh, migrated database, standing in for
// n replicas. It skips when MANAGER_TEST_DATABASE_URL is unset.
func pgStores(t *testing.T, n int) ([]*postgres.Store, string) {
	t.Helper()
	dsn := os.Getenv("MANAGER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MANAGER_TEST_DATABASE_URL not set; skipping Postgres integration test")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	name := fmt.Sprintf("opca_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + name
	var out []*postgres.Store
	for range n {
		s, err := postgres.New(ctx, u.String())
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		t.Cleanup(s.Close)
		out = append(out, s)
	}
	return out, u.String()
}

// A second replica picks up a registration another replica made within one
// poll, and enforces a denylist entry the same way.
func TestPostgres_SecondReplicaFollowsWithinOnePoll(t *testing.T) {
	stores, _ := pgStores(t, 2)
	ctx := context.Background()
	base, _ := serverTLS(t)

	type replica struct {
		rev   *Revocations
		trust *TrustStore
		poll  *Poller
	}
	var reps []replica
	for _, st := range stores {
		rev := NewRevocations(RevocationOptions{Store: st})
		trust, err := NewTrustStore(ctx, registered(), st, rev, base, nil)
		if err != nil {
			t.Fatal(err)
		}
		poll := NewPoller(st, trust, rev, nil)
		if err := poll.PollOnce(ctx); err != nil {
			t.Fatal(err)
		}
		reps = append(reps, replica{rev, trust, poll})
	}

	ca := newCA(t, caOpts{notBefore: time.Now().Add(-time.Hour)})
	if err := stores[0].AddOperatorCA(ctx, registeredRow(ca, store.OperatorCAActive)); err != nil {
		t.Fatal(err)
	}
	if err := reps[0].trust.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	leaf := liveLeaf(t, ca, leafOpts{}).Leaf
	if _, err := reps[1].trust.VerifyPeer(leaf, nil); err == nil {
		t.Fatal("the second replica trusted the CA before polling")
	}
	if err := reps[1].poll.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := reps[1].trust.VerifyPeer(leaf, nil); err != nil {
		t.Fatalf("the second replica doesn't trust the CA after one poll: %v", err)
	}

	sha := Fingerprint(ca.cert)
	if err := reps[0].rev.Deny(ctx, store.DenylistEntry{IssuerSHA256: sha, SerialHex: SerialKey(leaf.SerialNumber)}); err != nil {
		t.Fatal(err)
	}
	if err := reps[1].poll.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if !reps[1].rev.IsRevoked(sha, SerialKey(leaf.SerialNumber)) {
		t.Fatal("the second replica doesn't enforce the denylist entry after one poll")
	}
}

// Exactly one replica fetches a CRL URL per cycle, under the advisory lock;
// the other loads it from Postgres and re-verifies it, and refuses a
// tampered copy.
func TestPostgres_OneFetchPerCycleAndTamperedCRLsAreRefused(t *testing.T) {
	stores, dsn := pgStores(t, 2)
	ctx := context.Background()
	ca := newCA(t, caOpts{})
	crl := ca.crl(t, crlOpts{number: big.NewInt(1), revoked: []*big.Int{big.NewInt(0x42)}})
	srv, hits := crlServer(t, func() []byte { return crl })
	a := anchorFor(ca, store.CRLSourceURL, "")
	a.CRLLocation = srv.URL

	clock := &fakeClock{t: testNow}
	var revs []*Revocations
	for _, st := range stores {
		rev := NewRevocations(RevocationOptions{Store: st, Now: clock.Now})
		rev.SetAnchors([]Anchor{a})
		revs = append(revs, rev)
	}
	target := CRLTarget{Source: store.CRLSourceURL, Location: srv.URL, AnchorSHA256: a.SHA256}
	done := make(chan error, 2)
	for i, st := range stores {
		r := &CRLRefresher{Rev: revs[i], Store: st, Fetch: NewFetcher(FetchLimits{Timeout: time.Second, MaxBytes: MaxCRLSize}), Now: clock.Now}
		go func() { _, err := r.RefreshOnce(ctx, target); done <- err }()
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("RefreshOnce: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("fetched %d times, want 1", got)
	}
	if err := revs[1].Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if !revs[1].IsRevoked(a.SHA256, "42") {
		t.Fatal("the other replica didn't load the stored CRL")
	}

	rogue := newCA(t, caOpts{cn: "Example Operator CA"})
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `UPDATE operator_crls SET crl_der = $1 WHERE issuer_sha256 = $2`,
		ca.crl(t, crlOpts{number: big.NewInt(2), signer: &rogue}), a.SHA256); err != nil {
		t.Fatal(err)
	}
	fresh := NewRevocations(RevocationOptions{Store: stores[1], Now: clock.Now})
	fresh.SetAnchors([]Anchor{a})
	if err := fresh.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if st := fresh.Status(a.SHA256); st.CRLLoaded {
		t.Fatal("a replica loaded a tampered CRL from the database")
	}
}
