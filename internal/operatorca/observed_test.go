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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// observeStore records what the recorder writes. Writes block while gate is
// set and not yet closed.
type observeStore struct {
	store.OperatorCredentialStore
	mu     sync.Mutex
	writes []store.OperatorCredential
	at     []time.Time
	err    error
	wrote  chan struct{}
}

func newObserveStore() *observeStore { return &observeStore{wrote: make(chan struct{}, 64)} }

func (s *observeStore) ObserveOperatorCredential(_ context.Context, c store.OperatorCredential, at time.Time) error {
	s.mu.Lock()
	s.writes = append(s.writes, c)
	s.at = append(s.at, at)
	err := s.err
	s.mu.Unlock()
	s.wrote <- struct{}{}
	return err
}

func (s *observeStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.writes)
}

func waitWrite(t *testing.T, s *observeStore) {
	t.Helper()
	select {
	case <-s.wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("the recorder never wrote")
	}
}

// runRecorder starts rec's worker and returns a func that stops it and waits
// for it to return.
func runRecorder(rec *ObservedRecorder) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rec.Run(ctx)
		close(done)
	}()
	return func() {
		cancel()
		<-done
	}
}

type fakeAuthorizer struct {
	issuer string
	err    error
}

func (f fakeAuthorizer) AuthorizePeer(*x509.Certificate, []*x509.Certificate) (string, error) {
	return f.issuer, f.err
}

// The first authenticated request from a certificate writes one observed
// row carrying the serial, issuer, CN, level and notAfter.
func TestObservedRecorder_FirstSightWritesOneRow(t *testing.T) {
	ca := newCA(t, caOpts{})
	leaf := ca.leaf(t, leafOpts{cn: "Alice@Example.org", level: "operator"})
	st := newObserveStore()
	rec := NewObservedRecorder(ObservedOptions{Store: st, Now: func() time.Time { return testNow }})
	stop := runRecorder(rec)

	auth := rec.Authorizer(fakeAuthorizer{issuer: Fingerprint(ca.cert)})
	for range 5 {
		if _, err := auth.AuthorizePeer(leaf, nil); err != nil {
			t.Fatalf("AuthorizePeer: %v", err)
		}
	}
	waitWrite(t, st)
	stop()

	if n := st.count(); n != 1 {
		t.Fatalf("writes = %d, want 1 for repeated requests", n)
	}
	sum := sha256.Sum256(leaf.Raw)
	want := store.OperatorCredential{
		IssuerSHA256: Fingerprint(ca.cert), SerialHex: SerialKey(leaf.SerialNumber), CommonName: "Alice@Example.org",
		Email: "alice@example.org", Level: "operator", NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
		Kind: store.OperatorCredentialObserved, LeafSHA256: hex.EncodeToString(sum[:]),
	}
	if got := st.writes[0]; got.IssuerSHA256 != want.IssuerSHA256 || got.SerialHex != want.SerialHex || got.CommonName != want.CommonName ||
		got.Email != want.Email || got.Level != want.Level || got.NotAfter != want.NotAfter || got.Kind != want.Kind || got.LeafSHA256 != want.LeafSHA256 {
		t.Fatalf("observed row = %+v, want %+v", got, want)
	}
	if !st.at[0].Equal(testNow) {
		t.Fatalf("observed at %v, want %v", st.at[0], testNow)
	}
}

// A certificate seen again within the hour doesn't write; after an hour it
// writes once more, so last_seen_at moves at most hourly.
func TestObservedRecorder_RepeatsAreCached(t *testing.T) {
	ca := newCA(t, caOpts{})
	leaf := ca.leaf(t, leafOpts{})
	now := testNow
	rec := NewObservedRecorder(ObservedOptions{Store: newObserveStore(), Now: func() time.Time { return now }})
	fp := Fingerprint(ca.cert)

	for range 10 {
		rec.Observe(leaf, fp)
	}
	now = now.Add(59 * time.Minute)
	rec.Observe(leaf, fp)
	if n := len(rec.queue); n != 1 {
		t.Fatalf("queued = %d within the hour, want 1", n)
	}
	now = now.Add(2 * time.Minute)
	rec.Observe(leaf, fp)
	if n := len(rec.queue); n != 2 {
		t.Fatalf("queued = %d after an hour, want 2", n)
	}
}

// A full queue drops the sighting at once rather than blocking the request,
// and a dropped certificate is tried again on its next request.
func TestObservedRecorder_OverflowDropsWithoutBlocking(t *testing.T) {
	ca := newCA(t, caOpts{})
	a, b := ca.leaf(t, leafOpts{}), ca.leaf(t, leafOpts{})
	rec := NewObservedRecorder(ObservedOptions{Store: newObserveStore(), QueueSize: 1, Now: func() time.Time { return testNow }})
	fp := Fingerprint(ca.cert)

	done := make(chan struct{})
	go func() {
		rec.Observe(a, fp)
		rec.Observe(b, fp)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe blocked on a full queue")
	}
	if rec.Dropped() != 1 {
		t.Fatalf("Dropped() = %d, want 1", rec.Dropped())
	}
	<-rec.queue
	rec.Observe(b, fp)
	if len(rec.queue) != 1 {
		t.Fatal("a dropped certificate wasn't queued on its next request")
	}
}

// A refused request is not observed, and the refusal passes through.
func TestObservedRecorder_RefusedRequestsAreNotObserved(t *testing.T) {
	ca := newCA(t, caOpts{})
	rec := NewObservedRecorder(ObservedOptions{Store: newObserveStore(), Now: func() time.Time { return testNow }})
	refusal := errors.New("refused")
	if _, err := rec.Authorizer(fakeAuthorizer{err: refusal}).AuthorizePeer(ca.leaf(t, leafOpts{}), nil); !errors.Is(err, refusal) {
		t.Fatalf("AuthorizePeer error = %v, want the refusal", err)
	}
	if len(rec.queue) != 0 {
		t.Fatal("a refused request was observed")
	}
}

// A failed write is logged and the worker keeps going.
func TestObservedRecorder_WriteErrorsDontStopTheWorker(t *testing.T) {
	ca := newCA(t, caOpts{})
	st := newObserveStore()
	st.err = errors.New("database down")
	var logged []string
	var mu sync.Mutex
	rec := NewObservedRecorder(ObservedOptions{Store: st, Now: func() time.Time { return testNow }, Logf: func(f string, _ ...any) {
		mu.Lock()
		logged = append(logged, f)
		mu.Unlock()
	}})
	stop := runRecorder(rec)
	fp := Fingerprint(ca.cert)
	first := ca.leaf(t, leafOpts{})
	rec.Observe(first, fp)
	waitWrite(t, st)
	rec.Observe(ca.leaf(t, leafOpts{}), fp)
	waitWrite(t, st)
	stop()
	mu.Lock()
	n := len(logged)
	mu.Unlock()
	if n == 0 {
		t.Fatal("a failed write wasn't logged")
	}
	rec.Observe(first, fp)
	if len(rec.queue) != 1 {
		t.Fatal("a certificate whose write failed wasn't queued again on its next request")
	}
}
