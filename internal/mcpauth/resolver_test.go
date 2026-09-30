package mcpauth

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
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

// mintFor stores a key bound to cert with the given ceiling and returns the
// plaintext.
func mintFor(t *testing.T, st store.Store, cert *x509.Certificate, ceiling string) (string, store.McpKey) {
	t.Helper()
	owner, err := authz.IdentityFromCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	owner.Via = authz.ViaWeb
	plain, key, err := (&Keys{Store: st}).Mint(context.Background(), owner, cert.Raw, "laptop", "agent", ceiling)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return plain, key
}

func TestResolve_ValidKeyYieldsLiveIdentity(t *testing.T) {
	ca := newTestCA(t, "Operator CA")
	st := memory.New(nil)
	cert := ca.validOperator(t, 0x0abc, authz.LevelOperator)
	plain, key := mintFor(t, st, cert, "")
	r := &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{}}

	id, err := r.Resolve(context.Background(), plain)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := authz.Identity{CN: "operator@example.org", Serial: "0A:BC", Level: authz.LevelOperator, Via: authz.ViaMCP, KeyID: key.ID}
	if id != want {
		t.Fatalf("identity = %+v, want %+v", id, want)
	}
	if k, _ := st.McpKey(key.ID); k.LastUsedAt.IsZero() {
		t.Fatal("last_used_at not stamped")
	}
}

func TestResolve_CeilingCapsTheCertLevel(t *testing.T) {
	ca := newTestCA(t, "Operator CA")
	cases := []struct {
		certLevel authz.Level
		ceiling   string
		want      authz.Level
	}{
		{authz.LevelAdmin, "viewer", authz.LevelViewer},
		{authz.LevelAdmin, "operator", authz.LevelOperator},
		{authz.LevelAdmin, "", authz.LevelAdmin},
		{authz.LevelOperator, "operator", authz.LevelOperator},
	}
	for i, c := range cases {
		st := memory.New(nil)
		plain, _ := mintFor(t, st, ca.validOperator(t, int64(100+i), c.certLevel), c.ceiling)
		r := &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{}}
		id, err := r.Resolve(context.Background(), plain)
		if err != nil || id.Level != c.want {
			t.Errorf("cert %v ceiling %q: level %v err %v, want %v", c.certLevel, c.ceiling, id.Level, err, c.want)
		}
	}
}

// A ceiling stored above the certificate's level (the cert was re-issued at a
// lower level under the same serial is impossible, but a stored row must never
// widen what the cert grants) still resolves to the certificate's level.
func TestResolve_CeilingNeverRaisesTheCertLevel(t *testing.T) {
	ca := newTestCA(t, "Operator CA")
	st := memory.New(nil)
	cert := ca.validOperator(t, 7, authz.LevelViewer)
	plain, _ := NewKey()
	st.AddMcpKey(store.McpKey{ID: "k", TokenHash: HashKey(plain), OperatorSerial: "07", OperatorCN: "operator@example.org",
		OperatorCertDER: cert.Raw, LevelCeiling: "admin", CreatedAt: time.Now()})
	r := &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{}}
	id, err := r.Resolve(context.Background(), plain)
	if err != nil || id.Level != authz.LevelViewer {
		t.Fatalf("level %v err %v, want viewer", id.Level, err)
	}
}

func TestResolve_Rejections(t *testing.T) {
	ca := newTestCA(t, "Operator CA")
	other := newTestCA(t, "Some Other CA")

	cases := map[string]struct {
		setup func(t *testing.T, st store.Store) (plain string, r *Resolver)
		want  error
	}{
		"malformed": {func(t *testing.T, st store.Store) (string, *Resolver) {
			return "not-a-key", &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{}}
		}, ErrMalformed},
		"unknown": {func(t *testing.T, st store.Store) (string, *Resolver) {
			k, _ := NewKey()
			return k, &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{}}
		}, ErrUnknownKey},
		"revoked key": {func(t *testing.T, st store.Store) (string, *Resolver) {
			plain, key := mintFor(t, st, ca.validOperator(t, 1, authz.LevelOperator), "")
			_, _ = st.RevokeMcpKey(key.ID, time.Now())
			return plain, &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{}}
		}, ErrKeyRevoked},
		"revoked cert": {func(t *testing.T, st store.Store) (string, *Resolver) {
			plain, _ := mintFor(t, st, ca.validOperator(t, 0x0abc, authz.LevelOperator), "")
			return plain, &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{"0A:BC": true}}
		}, ErrCertRevoked},
		"expired cert": {func(t *testing.T, st store.Store) (string, *Resolver) {
			cert := ca.operatorCert(t, 2, authz.LevelOperator, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
			plain, _ := mintFor(t, st, cert, "")
			return plain, &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{}}
		}, ErrCertExpired},
		"not yet valid cert": {func(t *testing.T, st store.Store) (string, *Resolver) {
			cert := ca.operatorCert(t, 3, authz.LevelOperator, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
			plain, _ := mintFor(t, st, cert, "")
			return plain, &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{}}
		}, ErrCertExpired},
		"wrong CA": {func(t *testing.T, st store.Store) (string, *Resolver) {
			plain, _ := mintFor(t, st, other.validOperator(t, 4, authz.LevelAdmin), "")
			return plain, &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{}}
		}, ErrCertUntrusted},
		"operator CA removed from the pool": {func(t *testing.T, st store.Store) (string, *Resolver) {
			plain, _ := mintFor(t, st, ca.validOperator(t, 5, authz.LevelAdmin), "")
			return plain, &Resolver{Store: st, Roots: other.pool(), Revoked: revokedSet{}}
		}, ErrCertUntrusted},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			st := memory.New(nil)
			plain, r := c.setup(t, st)
			if _, err := r.Resolve(context.Background(), plain); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestResolve_AuditsFirstUseAndKnownKeyRejections(t *testing.T) {
	ca := newTestCA(t, "Operator CA")
	st := memory.New(nil)
	plain, key := mintFor(t, st, ca.validOperator(t, 9, authz.LevelOperator), "")
	r := &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{}}

	_, _ = r.Resolve(context.Background(), plain)
	_, _ = r.Resolve(context.Background(), plain)
	_, _ = st.RevokeMcpKey(key.ID, time.Now())
	_, _ = r.Resolve(context.Background(), plain)
	unknown, _ := NewKey()
	_, _ = r.Resolve(context.Background(), unknown)

	var kinds []string
	for _, e := range st.Audit() {
		kinds = append(kinds, e.Kind)
		if e.Kind == "mcp-key-first-used" || e.Kind == "mcp-key-rejected" {
			if e.TargetKind != "mcp-key" || e.KeyID != key.ID || e.ActorKind != "mcp_key" || e.Via != "mcp" {
				t.Errorf("%s row = %+v", e.Kind, e)
			}
		}
		if e.Kind == "mcp-key-rejected" && e.Outcome != "denied" {
			t.Errorf("rejection outcome = %q", e.Outcome)
		}
	}
	want := []string{"mcp-key-created", "mcp-key-first-used", "mcp-key-rejected"}
	if len(kinds) != len(want) {
		t.Fatalf("audit kinds = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("audit kinds = %v, want %v", kinds, want)
		}
	}
}

func TestMiddleware_Uniform401AndIdentityOnSuccess(t *testing.T) {
	ca := newTestCA(t, "Operator CA")
	st := memory.New(nil)
	good, _ := mintFor(t, st, ca.validOperator(t, 11, authz.LevelOperator), "")
	revokedPlain, revokedKey := mintFor(t, st, ca.validOperator(t, 12, authz.LevelOperator), "")
	_, _ = st.RevokeMcpKey(revokedKey.ID, time.Now())
	expiredPlain, _ := mintFor(t, st, ca.operatorCert(t, 13, authz.LevelOperator, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)), "")
	other := newTestCA(t, "Other CA")
	wrongCAPlain, _ := mintFor(t, st, other.validOperator(t, 14, authz.LevelOperator), "")
	certRevokedPlain, _ := mintFor(t, st, ca.validOperator(t, 15, authz.LevelOperator), "")

	r := &Resolver{Store: st, Roots: ca.pool(), Revoked: revokedSet{"0F": true}}
	var got authz.Identity
	h := Middleware(r, "https://fleetos.example.org/.well-known/oauth-protected-resource/mcp")(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got, _ = authz.FromContext(req.Context())
	}))

	call := func(bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.RemoteAddr = "192.0.2.10:5000"
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	var bodies []string
	for name, bearer := range map[string]string{
		"none": "", "garbage": "garbage", "revoked key": revokedPlain, "expired cert": expiredPlain,
		"wrong CA": wrongCAPlain, "revoked cert": certRevokedPlain,
	} {
		rec := call(bearer)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
		if w := rec.Header().Get("WWW-Authenticate"); w != `Bearer resource_metadata="https://fleetos.example.org/.well-known/oauth-protected-resource/mcp"` {
			t.Errorf("%s: WWW-Authenticate = %q", name, w)
		}
		if bearer != "" && bearer != "garbage" {
			bodies = append(bodies, rec.Body.String())
		}
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("rejection bodies differ: %q vs %q", b, bodies[0])
		}
	}

	if rec := call(good); rec.Code != http.StatusOK || got.Via != authz.ViaMCP || got.Level != authz.LevelOperator {
		t.Fatalf("good key: status %d identity %+v", rec.Code, got)
	}
}

func TestMiddleware_ThrottlesRepeatedFailuresPerClient(t *testing.T) {
	ca := newTestCA(t, "Operator CA")
	r := &Resolver{Store: memory.New(nil), Roots: ca.pool(), Revoked: revokedSet{}}
	h := Middleware(r, "")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	throttled := false
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.RemoteAddr = "203.0.113.7:4000"
		req.Header.Set("Authorization", "Bearer fos_mcp_wrong")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatal("50 failed keys from one client were never throttled")
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.RemoteAddr = "203.0.113.8:4000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("another client got %d, want 401", rec.Code)
	}
}
