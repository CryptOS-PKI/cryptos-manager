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
	"net/mail"
	"strings"
	"sync/atomic"
	"time"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// Defaults for the observed-credential recorder.
const (
	DefaultObservedQueueSize = 256
	DefaultObservedCacheSize = 4096
	// observedRefresh is how often a certificate in use has its last seen
	// time written again.
	observedRefresh = time.Hour
	dropLogInterval = time.Minute
	observeTimeout  = 10 * time.Second
)

// ObservedOptions configures an ObservedRecorder. Zero sizes take the
// defaults; a nil Now is time.Now.
type ObservedOptions struct {
	Store     store.OperatorCredentialStore
	QueueSize int
	CacheSize int
	Now       func() time.Time
	Logf      func(string, ...any)
}

type observation struct {
	cred store.OperatorCredential
	sum  [sha256.Size]byte
	at   time.Time
}

// ObservedRecorder writes an observed row for every operator certificate
// the manager sees authenticate, so the Operators page lists everyone who
// can sign in, including certificates the external CA signed that were never
// recorded. It never slows a request: sightings go through an LRU, so a
// certificate is written at most hourly, and a bounded queue that drops a
// sighting when full. A dropped sighting is tried again on the certificate's
// next request.
type ObservedRecorder struct {
	st    store.OperatorCredentialStore
	queue chan observation
	seen  *lru[[sha256.Size]byte, time.Time]
	now   func() time.Time
	logf  func(string, ...any)

	dropped     atomic.Int64
	lastDropLog atomic.Int64
}

// NewObservedRecorder builds a recorder. Start its worker with Run.
func NewObservedRecorder(o ObservedOptions) *ObservedRecorder {
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultObservedQueueSize
	}
	if o.CacheSize <= 0 {
		o.CacheSize = DefaultObservedCacheSize
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return &ObservedRecorder{
		st: o.Store, queue: make(chan observation, o.QueueSize),
		seen: newLRU[[sha256.Size]byte, time.Time](o.CacheSize), now: o.Now, logf: o.Logf,
	}
}

// Observe notes that leaf authenticated under the operator CA issuerSHA256.
// It returns at once.
func (r *ObservedRecorder) Observe(leaf *x509.Certificate, issuerSHA256 string) {
	now := r.now()
	sum := sha256.Sum256(leaf.Raw)
	if last, ok := r.seen.get(sum); ok && now.Sub(last) < observedRefresh {
		return
	}
	select {
	case r.queue <- observation{cred: observedCredential(leaf, issuerSHA256, sum), sum: sum, at: now}:
		r.seen.put(sum, now)
	default:
		n := r.dropped.Add(1)
		last := r.lastDropLog.Load()
		if now.UnixNano()-last >= int64(dropLogInterval) && r.lastDropLog.CompareAndSwap(last, now.UnixNano()) {
			r.logf("operatorca: WARNING the observed-credential queue is full; dropped %d sighting(s) so far, each is retried on its next request", n)
		}
	}
}

// Dropped returns how many sightings a full queue has dropped.
func (r *ObservedRecorder) Dropped() int64 { return r.dropped.Load() }

// Run writes queued sightings until ctx is done. A failed write is logged
// and the certificate is written again on a later request.
func (r *ObservedRecorder) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case o := <-r.queue:
			wctx, cancel := context.WithTimeout(ctx, observeTimeout)
			err := r.st.ObserveOperatorCredential(wctx, o.cred, o.at)
			cancel()
			if err != nil {
				r.seen.remove(func(k [sha256.Size]byte) bool { return k == o.sum })
				r.logf("operatorca: recording operator certificate %s under %s as seen failed: %v", o.cred.SerialHex, o.cred.IssuerSHA256, err)
				continue
			}
			r.logf("operatorca: operator certificate %s (%s) under %s seen in use", o.cred.SerialHex, o.cred.CommonName, o.cred.IssuerSHA256)
		}
	}
}

// Authorizer wraps inner so every certificate it accepts is observed.
func (r *ObservedRecorder) Authorizer(inner authz.PeerAuthorizer) authz.PeerAuthorizer {
	return observingAuthorizer{inner: inner, rec: r}
}

type observingAuthorizer struct {
	inner authz.PeerAuthorizer
	rec   *ObservedRecorder
}

func (a observingAuthorizer) AuthorizePeer(leaf *x509.Certificate, intermediates []*x509.Certificate) (string, error) {
	issuer, err := a.inner.AuthorizePeer(leaf, intermediates)
	if err != nil {
		return "", err
	}
	a.rec.Observe(leaf, issuer)
	return issuer, nil
}

// observedCredential is the row for a certificate seen in use. The handshake
// and AuthorizePeer already verified it, so it is read, not checked.
func observedCredential(leaf *x509.Certificate, issuerSHA256 string, sum [sha256.Size]byte) store.OperatorCredential {
	c := store.OperatorCredential{
		IssuerSHA256: issuerSHA256, SerialHex: SerialKey(leaf.SerialNumber), CommonName: leaf.Subject.CommonName,
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339), Kind: store.OperatorCredentialObserved,
		LeafSHA256: hex.EncodeToString(sum[:]),
	}
	if level, err := authz.LevelFromCertificate(leaf); err == nil {
		c.Level = level.Token()
	}
	if addr, err := mail.ParseAddress(c.CommonName); err == nil && addr.Name == "" && addr.Address == c.CommonName {
		c.Email = strings.ToLower(c.CommonName)
	}
	return c
}
