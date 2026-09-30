package mcpauth

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
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"golang.org/x/time/rate"
)

const identityExtra = "fleetos.identity"

// Middleware requires a valid MCP key on every request and puts the resolved
// identity on the request context. Any client certificate on the connection
// is ignored: the key alone authenticates. Every refusal is the same 401 with
// a WWW-Authenticate header pointing at resourceMetadataURL (RFC 9728), and
// the reason goes only to the log. A client that keeps presenting bad keys is
// throttled with 429.
func Middleware(r *Resolver, resourceMetadataURL string) func(http.Handler) http.Handler {
	limiter := newFailureLimiter()
	verify := func(ctx context.Context, token string, req *http.Request) (*auth.TokenInfo, error) {
		id, err := r.Resolve(ctx, token)
		if err != nil {
			limiter.fail(clientIP(req))
			log.Printf("mcpauth: refused %s %q from %s: %v", req.Method, req.URL.Path, req.RemoteAddr, err)
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: id.KeyID, Extra: map[string]any{identityExtra: id}}, nil
	}
	bearer := auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetadataURL,
		// Keys are long-lived by design; liveness comes from the per-request
		// certificate and revocation checks, not an expiry claim.
		AllowMissingExpiration: true,
	})

	return func(next http.Handler) http.Handler {
		withIdentity := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			id := auth.TokenInfoFromContext(req.Context()).Extra[identityExtra].(authz.Identity)
			next.ServeHTTP(w, req.WithContext(authz.NewContext(req.Context(), id)))
		})
		guarded := bearer(withIdentity)

		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if limiter.blocked(clientIP(req)) {
				http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
				return
			}
			guarded.ServeHTTP(w, req)
		})
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// failureLimiter allows each client a burst of failed keys that refills
// slowly. Only failures spend tokens, so a client with a good key is never
// slowed down.
type failureLimiter struct {
	mu      sync.Mutex
	clients map[string]*rate.Limiter
}

const (
	failureBurst     = 10
	failureRefill    = 6 * time.Second
	maxTrackedClient = 10000
)

func newFailureLimiter() *failureLimiter {
	return &failureLimiter{clients: map[string]*rate.Limiter{}}
}

func (f *failureLimiter) limiter(ip string) *rate.Limiter {
	l, ok := f.clients[ip]
	if !ok {
		// A bounded map is enough: forgetting every client at once only
		// restores their burst.
		if len(f.clients) >= maxTrackedClient {
			f.clients = map[string]*rate.Limiter{}
		}
		l = rate.NewLimiter(rate.Every(failureRefill), failureBurst)
		f.clients[ip] = l
	}
	return l
}

func (f *failureLimiter) fail(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.limiter(ip).Allow()
}

func (f *failureLimiter) blocked(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.clients[ip]
	return ok && l.Tokens() < 1
}

// IdentityFromTokenInfo returns the identity Middleware resolved for the
// request that carried ti. MCP tool handlers read it from the request's
// TokenInfo.
func IdentityFromTokenInfo(ti *auth.TokenInfo) (authz.Identity, bool) {
	if ti == nil {
		return authz.Identity{}, false
	}
	id, ok := ti.Extra[identityExtra].(authz.Identity)
	return id, ok
}
