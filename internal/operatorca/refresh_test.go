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
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
)

func crlServer(t *testing.T, body func() []byte) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		b := body()
		if b == nil {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func (f revFixture) refresher(rev *Revocations, fileTargets ...CRLTarget) *CRLRefresher {
	return &CRLRefresher{
		Rev: rev, Store: f.st, Fetch: NewFetcher(FetchLimits{Timeout: time.Second, MaxBytes: MaxCRLSize}),
		ReadFile: os.ReadFile, Now: f.clock.Now, Logf: f.logs.Logf, Interval: 15 * time.Minute, FileTargets: fileTargets,
	}
}

// One replica per anchor fetches in a cycle, under the advisory lock; the
// others find the fresh CRL in the store and load it on their next poll.
func TestRefresh_OneReplicaFetchesPerCycle(t *testing.T) {
	x := newCA(t, caOpts{})
	crl := x.crl(t, crlOpts{number: big.NewInt(1), revoked: []*big.Int{big.NewInt(0x42)}})
	srv, hits := crlServer(t, func() []byte { return crl })
	ax := anchorFor(x, store.CRLSourceURL, "")
	ax.CRLLocation = srv.URL
	f := newRevFixture(t, PolicySoft, ax)
	other := f.replica(t, PolicySoft, ax)

	target := CRLTarget{Source: store.CRLSourceURL, Location: srv.URL, AnchorSHA256: ax.SHA256}
	var wg sync.WaitGroup
	for _, rev := range []*Revocations{f.rev, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.refresher(rev).RefreshOnce(context.Background(), target); err != nil {
				t.Errorf("RefreshOnce: %v", err)
			}
		}()
	}
	wg.Wait()
	if _, err := f.refresher(other).RefreshOnce(context.Background(), target); err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("the CRL URL was fetched %d times in one cycle, want 1", got)
	}
	for i, rev := range []*Revocations{f.rev, other} {
		if err := NewPoller(f.st, nil, rev, nil).PollOnce(context.Background()); err != nil {
			t.Fatalf("PollOnce: %v", err)
		}
		if !rev.IsRevoked(ax.SHA256, "42") {
			t.Fatalf("replica %d doesn't enforce the fetched CRL", i)
		}
	}

	f.clock.Add(16 * time.Minute)
	if _, err := f.refresher(other).RefreshOnce(context.Background(), target); err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("the next cycle fetched %d times in total, want 2", got)
	}
}

func TestRefresh_FailureKeepsTheLastGoodCRLAndRecordsTheError(t *testing.T) {
	x := newCA(t, caOpts{})
	var mu sync.Mutex
	body := x.crl(t, crlOpts{number: big.NewInt(1), revoked: []*big.Int{big.NewInt(0x42)}})
	srv, _ := crlServer(t, func() []byte { mu.Lock(); defer mu.Unlock(); return body })
	ax := anchorFor(x, store.CRLSourceURL, "")
	f := newRevFixture(t, PolicySoft, ax)
	target := CRLTarget{Source: store.CRLSourceURL, Location: srv.URL, AnchorSHA256: ax.SHA256}

	if _, err := f.refresher(f.rev).RefreshOnce(context.Background(), target); err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	mu.Lock()
	body = nil
	mu.Unlock()
	f.clock.Add(16 * time.Minute)
	if _, err := f.refresher(f.rev).RefreshOnce(context.Background(), target); err == nil {
		t.Fatal("RefreshOnce against a failing URL succeeded")
	}
	if !f.rev.IsRevoked(ax.SHA256, "42") {
		t.Fatal("a failed refresh dropped the last good CRL")
	}
	if st := f.rev.Status(ax.SHA256); st.LastError == "" {
		t.Fatal("the refresh error isn't in the status")
	}
	crls, _ := f.st.OperatorCRLs(context.Background())
	if len(crls) != 1 || crls[0].LastError == "" || crls[0].DER == nil {
		t.Fatalf("stored = %+v, want the old CRL and the error", crls)
	}
}

// A config-file CRL entry is matched to the anchor that signed it.
func TestRefresh_ConfigEntriesMatchTheirAnchor(t *testing.T) {
	a := newCA(t, caOpts{cn: "Example Operator CA A"})
	b := newCA(t, caOpts{cn: "Example Operator CA B"})
	crlB := b.crl(t, crlOpts{number: big.NewInt(3), revoked: []*big.Int{big.NewInt(0xbb)}})
	srv, _ := crlServer(t, func() []byte { return crlB })

	dir := t.TempDir()
	path := filepath.Join(dir, "a.crl")
	if err := os.WriteFile(path, a.crl(t, crlOpts{number: big.NewInt(1), revoked: []*big.Int{big.NewInt(0xaa)}}), 0o600); err != nil {
		t.Fatal(err)
	}

	aa, ab := anchorFor(a, store.CRLSourcePath, ""), anchorFor(b, store.CRLSourceURL, "")
	aa.FromConfig, ab.FromConfig = true, true
	f := newRevFixture(t, PolicySoft, aa, ab)
	targets := []CRLTarget{{Source: store.CRLSourceURL, Location: srv.URL}, {Source: store.CRLSourcePath, Location: path}}
	r := f.refresher(f.rev, targets...)
	for _, tg := range targets {
		if _, err := r.RefreshOnce(context.Background(), tg); err != nil {
			t.Fatalf("RefreshOnce(%s): %v", tg.Location, err)
		}
	}
	if !f.rev.IsRevoked(ab.SHA256, "bb") || f.rev.IsRevoked(aa.SHA256, "bb") {
		t.Fatal("the URL CRL wasn't matched to CA B only")
	}
	if !f.rev.IsRevoked(aa.SHA256, "aa") || f.rev.IsRevoked(ab.SHA256, "aa") {
		t.Fatal("the path CRL wasn't matched to CA A only")
	}

	c := newCA(t, caOpts{cn: "Example Unrelated CA"})
	if err := os.WriteFile(path, c.crl(t, crlOpts{number: big.NewInt(1)}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RefreshOnce(context.Background(), targets[1]); err == nil {
		t.Fatal("a CRL signed by none of the operator CAs was accepted")
	}
}

func TestRefresh_Targets(t *testing.T) {
	x := newCA(t, caOpts{})
	y := newCA(t, caOpts{cn: "Example Upload CA"})
	ax, ay := anchorFor(x, store.CRLSourceURL, ""), anchorFor(y, store.CRLSourceUpload, "")
	ax.CRLLocation = "http://pki.example.org/x.crl"
	f := newRevFixture(t, PolicySoft, ax, ay)
	file := CRLTarget{Source: store.CRLSourcePath, Location: "/etc/fleet/op.crl"}
	got := f.refresher(f.rev, file).Targets()
	if len(got) != 2 {
		t.Fatalf("Targets() = %+v, want the URL row and the config entry", got)
	}
}

func TestNextRefresh(t *testing.T) {
	interval := 15 * time.Minute
	now := testNow

	due, backoff := nextRefresh(now, nil, time.Time{}, 0, interval, 0.5)
	if !due.Equal(now.Add(interval)) || backoff != 0 {
		t.Fatalf("success with no CRL deadline = %s, %s", due, backoff)
	}
	due, _ = nextRefresh(now, nil, time.Time{}, 0, interval, 0)
	if want := now.Add(time.Duration(float64(interval) * 0.9)); !due.Equal(want) {
		t.Fatalf("low jitter = %s, want %s", due, want)
	}
	due, _ = nextRefresh(now, nil, time.Time{}, 0, interval, 1)
	if want := now.Add(time.Duration(float64(interval) * 1.1)); !due.Equal(want) {
		t.Fatalf("high jitter = %s, want %s", due, want)
	}
	due, _ = nextRefresh(now, nil, now.Add(5*time.Minute), 0, interval, 0.5)
	if !due.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("a nearer nextUpdate = %s, want it", due)
	}

	fail := errors.New("down")
	var steps []time.Duration
	backoff = 0
	for range 6 {
		due, backoff = nextRefresh(now, fail, time.Time{}, backoff, interval, 0.5)
		steps = append(steps, due.Sub(now))
	}
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for i := range want {
		if steps[i] != want[i] {
			t.Fatalf("backoff steps = %v, want %v", steps, want)
		}
	}
	// A CRL already past nextUpdate is retried like a failure.
	due, backoff = nextRefresh(now, nil, now.Add(-time.Minute), 0, interval, 0.5)
	if due.Sub(now) != time.Minute || backoff != time.Minute {
		t.Fatalf("stale CRL = %s, %s; want a one-minute retry", due.Sub(now), backoff)
	}
}
