// Package ratelimit holds the manager's failure limiters: per client, where
// only failures spend tokens, and a global rolling window.
package ratelimit

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
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// maxTrackedClients bounds the per-client map. Forgetting every client at
// once only restores their bursts.
const maxTrackedClients = 10000

// Failures allows each client a burst of failures that refills slowly. Only
// failures spend tokens, so a client that keeps succeeding is never slowed
// down.
type Failures struct {
	mu      sync.Mutex
	burst   int
	refill  time.Duration
	clients map[string]*rate.Limiter
	now     func() time.Time
}

// NewFailures builds a limiter that allows burst failures per client and
// gives one back every refill.
func NewFailures(burst int, refill time.Duration) *Failures {
	return &Failures{burst: burst, refill: refill, clients: map[string]*rate.Limiter{}, now: time.Now}
}

func (f *Failures) limiter(client string) *rate.Limiter {
	l, ok := f.clients[client]
	if !ok {
		if len(f.clients) >= maxTrackedClients {
			f.clients = map[string]*rate.Limiter{}
		}
		l = rate.NewLimiter(rate.Every(f.refill), f.burst)
		f.clients[client] = l
	}
	return l
}

// Fail spends one of the client's tokens.
func (f *Failures) Fail(client string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.limiter(client).AllowN(f.now(), 1)
}

// Blocked reports whether the client has no failures left.
func (f *Failures) Blocked(client string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.clients[client]
	return ok && l.TokensAt(f.now()) < 1
}

// Window counts failures from every client in a rolling window and trips
// when limit of them fall inside it. A trip starts the count over.
type Window struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	times  []time.Time
	now    func() time.Time
}

// NewWindow builds a window that trips at limit failures within window.
func NewWindow(limit int, window time.Duration) *Window {
	return &Window{limit: limit, window: window, now: time.Now}
}

// Fail records a failure and reports whether it tripped the limit.
func (w *Window) Fail() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	cutoff := now.Add(-w.window)
	kept := w.times[:0]
	for _, t := range w.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	w.times = append(kept, now)
	if len(w.times) >= w.limit {
		w.times = nil
		return true
	}
	return false
}

// ClientIP is the peer address of the request, without the port.
// X-Forwarded-For is never trusted: behind a proxy every client shares the
// proxy's address, and a global limit is the real control.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
