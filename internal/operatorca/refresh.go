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
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// The CRL refresh schedule.
const (
	DefaultCRLInterval = 15 * time.Minute
	minCRLRetry        = time.Minute
	crlJitter          = 0.1
	refreshTick        = 15 * time.Second
)

// CRLTarget is one place a CRL comes from: a registered operator CA's URL,
// or an operatorCRL entry from the config file, whose CRL is matched to the
// anchor that signed it.
type CRLTarget struct {
	Source   string // url or path
	Location string
	// AnchorSHA256 names the operator CA the CRL belongs to; empty for a
	// config-file entry.
	AnchorSHA256 string
}

func (t CRLTarget) key() string {
	if t.AnchorSHA256 != "" {
		return t.AnchorSHA256
	}
	sum := sha256.Sum256([]byte(t.Source + ":" + t.Location))
	return hex.EncodeToString(sum[:])
}

// CRLRefresher keeps each anchor's CRL current. For a URL, one replica per
// anchor fetches under an advisory lock and stores a newer CRL, which bumps
// the revocation epoch; the others load it on their next poll. A path is
// re-read by every replica, since each has its own mount.
type CRLRefresher struct {
	Rev         *Revocations
	Store       store.OperatorTrust
	Fetch       *Fetcher
	ReadFile    func(string) ([]byte, error)
	Now         func() time.Time
	Logf        func(string, ...any)
	Interval    time.Duration
	FileTargets []CRLTarget
}

func (r *CRLRefresher) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *CRLRefresher) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *CRLRefresher) interval() time.Duration {
	if r.Interval > 0 {
		return r.Interval
	}
	return DefaultCRLInterval
}

// Targets lists what to refresh: every registered anchor with a URL source,
// and the config-file entries.
func (r *CRLRefresher) Targets() []CRLTarget {
	var out []CRLTarget
	for _, a := range r.Rev.Anchors() {
		if !a.FromConfig && a.CRLSource == store.CRLSourceURL && a.CRLLocation != "" {
			out = append(out, CRLTarget{Source: store.CRLSourceURL, Location: a.CRLLocation, AnchorSHA256: a.SHA256})
		}
	}
	return append(out, r.FileTargets...)
}

// RefreshOnce fetches or reads one target's CRL, verifies it and stores it
// if it is newer. It returns the nextUpdate of the anchor's CRL, zero when
// there is none. A URL another replica holds the lock for, or refreshed
// within the last half interval, is left alone.
func (r *CRLRefresher) RefreshOnce(ctx context.Context, t CRLTarget) (time.Time, error) {
	if t.Source == store.CRLSourceURL {
		release, ok, err := r.Store.TryAdvisoryLock(ctx, "fleetos.crl."+t.key())
		if err != nil {
			return time.Time{}, fmt.Errorf("operatorca: CRL lock: %w", err)
		}
		if !ok {
			return r.nextUpdate(t.AnchorSHA256), nil
		}
		defer release()
		if r.recentlyRefreshed(ctx, t) {
			return r.nextUpdate(t.AnchorSHA256), nil
		}
	}

	var (
		b   []byte
		err error
	)
	switch t.Source {
	case store.CRLSourceURL:
		b, err = r.Fetch.Fetch(ctx, t.Location)
	case store.CRLSourcePath:
		b, err = r.ReadFile(t.Location)
		if err != nil {
			err = apperr.Reasoned(apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_UNREACHABLE,
				fmt.Errorf("operatorca: read CRL file %s: %w", t.Location, err))
		}
	default:
		return time.Time{}, fmt.Errorf("operatorca: no refresh for CRL source %q", t.Source)
	}
	if err != nil {
		r.fail(ctx, t, err)
		return r.nextUpdate(t.AnchorSHA256), err
	}

	anchor := t.AnchorSHA256
	if anchor == "" {
		anchor, err = r.matchAnchor(b)
		if err != nil {
			r.fail(ctx, t, err)
			return time.Time{}, err
		}
	}
	stored, err := r.Rev.StoreCRL(ctx, anchor, b, t.Source)
	if err != nil {
		t.AnchorSHA256 = anchor
		r.fail(ctx, t, err)
		return r.nextUpdate(anchor), err
	}
	if !stored {
		if err := r.Store.RecordOperatorCRLAttempt(ctx, anchor, "", r.now().UTC()); err != nil {
			r.logf("operatorca: record CRL attempt for %s: %v", anchor, err)
		}
		r.Rev.RecordCRLError(anchor, "")
	}
	return r.nextUpdate(anchor), nil
}

func (r *CRLRefresher) recentlyRefreshed(ctx context.Context, t CRLTarget) bool {
	if t.AnchorSHA256 == "" {
		return false
	}
	crls, err := r.Store.OperatorCRLs(ctx)
	if err != nil {
		return false
	}
	now := r.now()
	for _, c := range crls {
		if c.IssuerSHA256 == t.AnchorSHA256 {
			return c.DER != nil && c.LastError == "" && now.Before(c.NextUpdate) &&
				now.Sub(c.LastAttemptAt) < r.interval()/2
		}
	}
	return false
}

func (r *CRLRefresher) matchAnchor(der []byte) (string, error) {
	now := r.now()
	for _, a := range r.Rev.Anchors() {
		if !a.FromConfig {
			continue
		}
		if _, err := VerifyCRL(der, a.Cert, now); err == nil {
			return a.SHA256, nil
		}
	}
	return "", crlInvalid("is signed by none of the operator CAs in operatorCAPath")
}

func (r *CRLRefresher) fail(ctx context.Context, t CRLTarget, err error) {
	msg := errorClass(err) + ": " + err.Error()
	r.logf("operatorca: CRL refresh from %s %s failed: %s", t.Source, redact(t.Location), msg)
	if t.AnchorSHA256 == "" {
		return
	}
	r.Rev.RecordCRLError(t.AnchorSHA256, msg)
	if err := r.Store.RecordOperatorCRLAttempt(ctx, t.AnchorSHA256, msg, r.now().UTC()); err != nil {
		r.logf("operatorca: record CRL attempt for %s: %v", t.AnchorSHA256, err)
	}
}

func (r *CRLRefresher) nextUpdate(anchor string) time.Time {
	if anchor == "" {
		return time.Time{}
	}
	if v, ok := r.Rev.CRL(anchor); ok {
		return v.List.NextUpdate
	}
	return time.Time{}
}

func errorClass(err error) string {
	if reason, ok := apperr.ReasonOf(err); ok {
		return apperr.ReasonName(reason)
	}
	if errors.Is(err, ErrUnknownAnchor) {
		return "UNKNOWN_ANCHOR"
	}
	return "ERROR"
}

// nextRefresh schedules a target's next refresh. After a success it is the
// interval with jitter (jitter in [0,1] maps to plus or minus 10%), or the
// CRL's nextUpdate if that comes first. After a failure, or when the CRL is
// already past nextUpdate, it retries after a backoff that starts at a
// minute and doubles up to the interval.
func nextRefresh(now time.Time, err error, nextUpdate time.Time, backoff, interval time.Duration, jitter float64) (time.Time, time.Duration) {
	if err != nil || (!nextUpdate.IsZero() && !now.Before(nextUpdate)) {
		backoff = min(max(backoff*2, minCRLRetry), interval)
		return now.Add(backoff), backoff
	}
	due := now.Add(time.Duration(float64(interval) * (1 - crlJitter + 2*crlJitter*jitter)))
	if !nextUpdate.IsZero() && nextUpdate.Before(due) {
		due = nextUpdate
	}
	return due, 0
}

// Run refreshes every target on its schedule until ctx ends. Targets are
// re-read on every tick, so a newly registered operator CA is picked up.
func (r *CRLRefresher) Run(ctx context.Context) {
	type sched struct {
		due     time.Time
		backoff time.Duration
	}
	state := map[string]*sched{}
	t := time.NewTicker(refreshTick)
	defer t.Stop()
	for {
		now := r.now()
		for _, target := range r.Targets() {
			s, ok := state[target.key()]
			if !ok {
				s = &sched{}
				state[target.key()] = s
			}
			if now.Before(s.due) {
				continue
			}
			next, err := r.RefreshOnce(ctx, target)
			s.due, s.backoff = nextRefresh(r.now(), err, next, s.backoff, r.interval(), rand.Float64())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
