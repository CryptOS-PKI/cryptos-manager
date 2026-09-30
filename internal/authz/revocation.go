package authz

/*
Apache License 2.0

Copyright 2026 Shane

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
	"log"
	"strings"
	"sync"
	"time"
)

// RevocationSource yields the operator-CA node's currently revoked serials, in
// whatever hex form the node reports them. The manager caches them and enforces
// revocation at the middleware. A source that fails (the operator-CA node is
// unreachable) returns an error, and the cache keeps its last-good set.
type RevocationSource interface {
	RevokedSerials() ([]string, error)
}

// RevocationCache holds the operator-CA's revoked serials, refreshed
// periodically from a RevocationSource. IsRevoked answers the middleware. It is
// fail-safe: a failed refresh keeps the last-good set instead of clearing it
// (which would fail-open) or locking every operator out.
type RevocationCache struct {
	src RevocationSource

	mu      sync.RWMutex
	revoked map[string]struct{}
}

// NewRevocationCache builds an empty cache over src. Until the first successful
// Refresh it reports nothing revoked.
func NewRevocationCache(src RevocationSource) *RevocationCache {
	return &RevocationCache{src: src, revoked: map[string]struct{}{}}
}

// Refresh fetches the current revoked set from the source and, on success,
// atomically replaces the cached set with the normalized serials. On a source
// error it leaves the cached set untouched and returns the error (the caller
// logs it); the last-good set stays in force.
func (c *RevocationCache) Refresh() error {
	serials, err := c.src.RevokedSerials()
	if err != nil {
		return err
	}
	next := make(map[string]struct{}, len(serials))
	for _, s := range serials {
		next[normalizeSerial(s)] = struct{}{}
	}
	c.mu.Lock()
	c.revoked = next
	c.mu.Unlock()
	return nil
}

// IsRevoked reports whether serial (in the middleware's colon-separated form or
// any hex form) is in the cached revoked set. Serials are compared normalized
// so the node's hex form and the middleware's formatSerial output match.
func (c *RevocationCache) IsRevoked(serial string) bool {
	key := normalizeSerial(serial)
	c.mu.RLock()
	_, ok := c.revoked[key]
	c.mu.RUnlock()
	return ok
}

// Prime performs a single synchronous refresh. Call it before the server starts
// serving so revocation is enforced on the very first request rather than after
// the background loop's first tick; a cold, unprimed cache reports nothing
// revoked. It returns the refresh error (fail-safe: the caller treats a prime
// failure as non-fatal but should warn that enforcement is not yet active).
func (c *RevocationCache) Prime() error {
	return c.Refresh()
}

// Run refreshes the cache on every interval tick until ctx is cancelled. The
// caller should Prime once before serving; Run itself does not do an initial
// refresh. A tick refresh error is logged (not fatal): the last-good set stays
// in force so a transient operator-CA outage never locks everyone out. Intended
// to run in its own goroutine.
func (c *RevocationCache) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Refresh(); err != nil {
				log.Printf("authz: revocation refresh failed (keeping last-good set): %v", err)
			}
		}
	}
}

// normalizeSerial folds a serial to a comparable key: lowercase hex with every
// colon and surrounding whitespace stripped, and any leading zero bytes
// dropped. This lets the middleware's colon-separated uppercase form
// (formatSerial) match the node's compact hex form regardless of zero padding.
func normalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}
