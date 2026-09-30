package oauth

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/mcpauth"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

const publicURL = "https://fleetos.example.org"

type fixture struct {
	t      *testing.T
	st     *memory.Store
	srv    *Server
	mux    *http.ServeMux
	now    time.Time
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPool *x509.CertPool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, st: memory.New(nil), now: time.Now()}
	f.srv = &Server{Store: f.st, Keys: &mcpauth.Keys{Store: f.st}, PublicURL: publicURL, Now: func() time.Time { return f.now }}
	f.mux = http.NewServeMux()
	f.srv.Routes(f.mux, authz.ClientCertMiddleware)

	f.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Operator CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &f.caKey.PublicKey, f.caKey)
	f.ca, _ = x509.ParseCertificate(der)
	f.caPool = x509.NewCertPool()
	f.caPool.AddCert(f.ca)
	return f
}

func (f *fixture) operatorCert(serial int64, level authz.Level) *x509.Certificate {
	value, _ := asn1.Marshal(level.Token())
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "operator@example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 1}, Value: value}},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, f.ca, &key.PublicKey, f.caKey)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func (f *fixture) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) register(redirects ...string) (*httptest.ResponseRecorder, map[string]any) {
	body, _ := json.Marshal(map[string]any{
		"client_name": "agent-cli", "redirect_uris": redirects,
		"grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none",
	})
	rec := f.do(httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(body)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func pkce() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *fixture) authorize(q url.Values) *httptest.ResponseRecorder {
	return f.do(httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil))
}

func authorizeQuery(clientID, redirect, challenge string) url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"xyz"},
		"resource": {publicURL + "/mcp"},
	}
}

// consentRequest builds a consent call as the browser makes it; cert may be
// nil for a browser without one.
func consentRequest(method, id string, cert *x509.Certificate, body any) *http.Request {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/oauth2/consent/"+id, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	return req
}

// login drives the flow to a consent request id.
func (f *fixture) pendingRequest(redirect string) (clientID, verifier, reqID string) {
	f.t.Helper()
	_, reg := f.register(redirect)
	clientID = reg["client_id"].(string)
	verifier, challenge := pkce()
	rec := f.authorize(authorizeQuery(clientID, redirect, challenge))
	if rec.Code != http.StatusFound {
		f.t.Fatalf("authorize status %d: %s", rec.Code, rec.Body)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/oauth/consent" {
		f.t.Fatalf("authorize redirected to %s", loc)
	}
	return clientID, verifier, loc.Query().Get("req")
}

func (f *fixture) approve(reqID string, cert *x509.Certificate, ceiling string) *url.URL {
	f.t.Helper()
	rec := f.do(consentRequest(http.MethodPost, reqID, cert, map[string]any{"approve": true, "label": "laptop", "level_ceiling": ceiling}))
	if rec.Code != http.StatusOK {
		f.t.Fatalf("approve status %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		RedirectTo string `json:"redirect_to"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	u, _ := url.Parse(out.RedirectTo)
	return u
}

func (f *fixture) token(form url.Values) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestMetadata(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		rec := f.do(httptest.NewRequest(http.MethodGet, path, nil))
		var prm map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &prm)
		if rec.Code != 200 || prm["resource"] != publicURL+"/mcp" || prm["authorization_servers"].([]any)[0] != publicURL {
			t.Fatalf("%s = %d %v", path, rec.Code, prm)
		}
	}
	rec := f.do(httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	var asm map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &asm)
	if asm["issuer"] != publicURL || asm["authorization_endpoint"] != publicURL+"/oauth2/authorize" ||
		asm["token_endpoint"] != publicURL+"/oauth2/token" || asm["registration_endpoint"] != publicURL+"/oauth2/register" {
		t.Fatalf("authorization server metadata = %v", asm)
	}
	if m := asm["code_challenge_methods_supported"].([]any); len(m) != 1 || m[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported = %v", m)
	}
	if _, ok := asm["jwks_uri"]; ok {
		t.Fatal("metadata advertises an empty jwks_uri")
	}
}

func TestRegister_LoopbackRedirectsOnly(t *testing.T) {
	f := newFixture(t)
	for _, ok := range []string{"http://127.0.0.1:33418/callback", "http://[::1]/cb", "http://localhost:5555/callback"} {
		rec, out := f.register(ok)
		if rec.Code != http.StatusCreated || out["client_id"] == "" {
			t.Errorf("%s: status %d %v", ok, rec.Code, out)
		}
		if g := out["grant_types"].([]any); len(g) != 1 || g[0] != "authorization_code" {
			t.Errorf("%s: grant_types = %v, want authorization_code only", ok, g)
		}
	}
	for _, bad := range []string{"https://example.org/cb", "http://192.0.2.1/cb", "https://127.0.0.1/cb", "http://127.0.0.1/cb#frag", "fleetos://cb", "http://localhost.example.org/cb"} {
		rec, out := f.register(bad)
		if rec.Code != http.StatusBadRequest || out["error"] != "invalid_redirect_uri" {
			t.Errorf("%s: status %d %v", bad, rec.Code, out)
		}
	}
	if rec, _ := f.register(); rec.Code != http.StatusBadRequest {
		t.Errorf("no redirect_uris: status %d", rec.Code)
	}
}

func TestAuthorize_Validation(t *testing.T) {
	f := newFixture(t)
	redirect := "http://127.0.0.1:33418/callback"
	_, reg := f.register(redirect)
	clientID := reg["client_id"].(string)
	_, challenge := pkce()

	// Errors the client cannot be trusted with are answered in place.
	for name, q := range map[string]url.Values{
		"unknown client":    authorizeQuery("fos-client-bogus", redirect, challenge),
		"redirect mismatch": authorizeQuery(clientID, "http://127.0.0.1:33418/other", challenge),
	} {
		if rec := f.authorize(q); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Errorf("%s: status %d location %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}

	// A loopback redirect may use any port (RFC 8252 7.3).
	if rec := f.authorize(authorizeQuery(clientID, "http://127.0.0.1:40000/callback", challenge)); rec.Code != http.StatusFound {
		t.Errorf("other loopback port: status %d", rec.Code)
	}

	withErr := func(mut func(url.Values)) string {
		q := authorizeQuery(clientID, redirect, challenge)
		mut(q)
		rec := f.authorize(q)
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if loc.Query().Get("state") != "xyz" {
			t.Errorf("error redirect lost state: %s", loc)
		}
		return loc.Query().Get("error")
	}
	if e := withErr(func(q url.Values) { q.Del("code_challenge") }); e != "invalid_request" {
		t.Errorf("no PKCE: error %q", e)
	}
	if e := withErr(func(q url.Values) { q.Set("code_challenge_method", "plain") }); e != "invalid_request" {
		t.Errorf("plain PKCE: error %q", e)
	}
	if e := withErr(func(q url.Values) { q.Set("response_type", "token") }); e != "unsupported_response_type" {
		t.Errorf("implicit: error %q", e)
	}
	if e := withErr(func(q url.Values) { q.Set("resource", "https://other.example.org/mcp") }); e != "invalid_target" {
		t.Errorf("other resource: error %q", e)
	}
}

func TestConsent_RequiresACertificate(t *testing.T) {
	f := newFixture(t)
	_, _, reqID := f.pendingRequest("http://127.0.0.1:33418/callback")

	if rec := f.do(consentRequest(http.MethodGet, reqID, nil, nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET without cert: %d", rec.Code)
	}
	if rec := f.do(consentRequest(http.MethodPost, reqID, nil, map[string]any{"approve": true})); rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST without cert: %d", rec.Code)
	}
	// The refused attempts did not consume the request.
	if rec := f.do(consentRequest(http.MethodGet, reqID, f.operatorCert(5, authz.LevelOperator), nil)); rec.Code != http.StatusOK {
		t.Fatalf("GET with cert after refusals: %d", rec.Code)
	}
}

func TestConsent_ShowsTheRequestAndOperator(t *testing.T) {
	f := newFixture(t)
	_, _, reqID := f.pendingRequest("http://127.0.0.1:33418/callback")

	rec := f.do(consentRequest(http.MethodGet, reqID, f.operatorCert(0x0abc, authz.LevelOperator), nil))
	var got struct {
		ClientName   string `json:"client_name"`
		RedirectHost string `json:"redirect_host"`
		Operator     struct {
			CN, Serial, Level string
		} `json:"operator"`
		AllowedCeilings []string `json:"allowed_ceilings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != 200 {
		t.Fatalf("consent GET %d: %s", rec.Code, rec.Body)
	}
	if got.ClientName != "agent-cli" || got.RedirectHost != "127.0.0.1:33418" || got.Operator.CN != "operator@example.org" ||
		got.Operator.Serial != "0A:BC" || got.Operator.Level != "operator" || strings.Join(got.AllowedCeilings, ",") != "viewer,operator" {
		t.Fatalf("consent = %+v", got)
	}

	if rec := f.do(consentRequest(http.MethodGet, "nope", f.operatorCert(1, authz.LevelAdmin), nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown request: %d", rec.Code)
	}
	f.now = f.now.Add(11 * time.Minute)
	if rec := f.do(consentRequest(http.MethodGet, reqID, f.operatorCert(1, authz.LevelAdmin), nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("expired request: %d", rec.Code)
	}
}

func TestConsent_DenyAndCeilingRules(t *testing.T) {
	f := newFixture(t)
	cert := f.operatorCert(3, authz.LevelOperator)

	_, _, reqID := f.pendingRequest("http://127.0.0.1:33418/callback")
	rec := f.do(consentRequest(http.MethodPost, reqID, cert, map[string]any{"approve": false}))
	var out struct {
		RedirectTo string `json:"redirect_to"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	u, _ := url.Parse(out.RedirectTo)
	if u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "xyz" || u.Query().Get("code") != "" || u.Host != "127.0.0.1:33418" {
		t.Fatalf("deny redirect = %s", out.RedirectTo)
	}
	if rec := f.do(consentRequest(http.MethodPost, reqID, cert, map[string]any{"approve": true})); rec.Code != http.StatusNotFound {
		t.Fatalf("second decision: %d", rec.Code)
	}

	_, _, reqID = f.pendingRequest("http://127.0.0.1:33418/callback")
	if rec := f.do(consentRequest(http.MethodPost, reqID, cert, map[string]any{"approve": true, "level_ceiling": "admin"})); rec.Code != http.StatusBadRequest {
		t.Fatalf("ceiling above level: %d", rec.Code)
	}

	// A form post from another site cannot carry JSON.
	_, _, reqID = f.pendingRequest("http://127.0.0.1:33418/callback")
	req := consentRequest(http.MethodPost, reqID, cert, map[string]any{"approve": true})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := f.do(req); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("form-encoded consent: %d", rec.Code)
	}
}

func TestToken_FullFlowMintsABoundKey(t *testing.T) {
	f := newFixture(t)
	redirect := "http://127.0.0.1:33418/callback"
	clientID, verifier, reqID := f.pendingRequest(redirect)
	cert := f.operatorCert(0x0abc, authz.LevelAdmin)
	back := f.approve(reqID, cert, "operator")
	if back.Query().Get("state") != "xyz" || back.Query().Get("code") == "" {
		t.Fatalf("approve redirect = %s", back)
	}

	form := url.Values{"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")},
		"redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {verifier}}
	rec, out := f.token(form)
	if rec.Code != http.StatusOK {
		t.Fatalf("token %d: %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	key, _ := out["access_token"].(string)
	if !mcpauth.WellFormed(key) || out["token_type"] != "Bearer" {
		t.Fatalf("token response = %v", out)
	}
	for _, absent := range []string{"expires_in", "refresh_token"} {
		if _, ok := out[absent]; ok {
			t.Fatalf("token response carries %s", absent)
		}
	}

	r := &mcpauth.Resolver{Store: f.st, Roots: func() *x509.CertPool { return f.caPool }, Revoked: revokedNone{}}
	id, err := r.Resolve(context.Background(), key)
	if err != nil || id.Serial != "0A:BC" || id.Level != authz.LevelOperator {
		t.Fatalf("minted key resolves to %+v, %v", id, err)
	}
	stored, _ := f.st.McpKeyByHash(mcpauth.HashKey(key))
	if stored.ClientName != "agent-cli" || stored.Label != "laptop" {
		t.Fatalf("stored key = %+v", stored)
	}
	created := f.st.Audit()[0]
	if created.Kind != "mcp-key-created" || created.ActorSerial != "0A:BC" || created.ActorKind != "cert" {
		t.Fatalf("mint audit = %+v", created)
	}

	if rec, out := f.token(form); rec.Code != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("code reuse: %d %v", rec.Code, out)
	}
}

func TestToken_Refusals(t *testing.T) {
	redirect := "http://127.0.0.1:33418/callback"
	cases := map[string]func(f *fixture, form url.Values){
		"wrong verifier":    func(_ *fixture, form url.Values) { v, _ := pkce(); form.Set("code_verifier", v) },
		"missing verifier":  func(_ *fixture, form url.Values) { form.Del("code_verifier") },
		"redirect mismatch": func(_ *fixture, form url.Values) { form.Set("redirect_uri", "http://127.0.0.1:1/callback") },
		"other client": func(f *fixture, form url.Values) {
			_, reg := f.register("http://127.0.0.1:1/elsewhere")
			form.Set("client_id", reg["client_id"].(string))
		},
		"expired code":     func(f *fixture, _ url.Values) { f.now = f.now.Add(61 * time.Second) },
		"unknown code":     func(_ *fixture, form url.Values) { form.Set("code", "nope") },
		"wrong grant type": func(_ *fixture, form url.Values) { form.Set("grant_type", "refresh_token") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			clientID, verifier, reqID := f.pendingRequest(redirect)
			back := f.approve(reqID, f.operatorCert(9, authz.LevelOperator), "")
			form := url.Values{"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")},
				"redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {verifier}}
			mutate(f, form)
			rec, out := f.token(form)
			if rec.Code != http.StatusBadRequest || out["access_token"] != nil {
				t.Fatalf("status %d body %v", rec.Code, out)
			}
			if len(f.st.McpKeys()) != 0 {
				t.Fatal("a key was minted")
			}
		})
	}
}

type revokedNone struct{}

func (revokedNone) CheckMCP(string, string) error { return nil }
