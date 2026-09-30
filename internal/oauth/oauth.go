// Package oauth is the one-time MCP login: an OAuth 2.0 native-app flow
// (RFC 8252 loopback redirect, PKCE S256, RFC 7591 registration, RFC 8414 and
// RFC 9728 metadata) whose consent step is authenticated by the operator's
// client certificate and whose token is a long-lived MCP key.
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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/mcpauth"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// Lifetimes of the login state. A pending request waits for a person to find
// the consent page; a code is redeemed by the client within moments.
const (
	requestTTL = 10 * time.Minute
	codeTTL    = time.Minute
)

// Routes the login mounts, relative to the public URL.
const (
	ResourceMetadataPath = "/.well-known/oauth-protected-resource"
	authServerMetaPath   = "/.well-known/oauth-authorization-server"
	registerPath         = "/oauth2/register"
	authorizePath        = "/oauth2/authorize"
	tokenPath            = "/oauth2/token"
	consentAPIPath       = "/oauth2/consent/"
	// consentPagePath is the web UI route that renders the consent screen.
	consentPagePath = "/oauth/consent"
)

// Server serves the login endpoints.
type Server struct {
	Store store.Store
	Keys  *mcpauth.Keys
	// PublicURL is the manager's external origin, for example
	// https://fleetos.example.org. It is the issuer, and PublicURL + "/mcp"
	// is the protected resource.
	PublicURL string
	// Now defaults to time.Now.
	Now func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) resource() string { return s.PublicURL + "/mcp" }

// ResourceMetadataURL is the RFC 9728 metadata location for the MCP resource,
// for the WWW-Authenticate header on a refused MCP request.
func (s *Server) ResourceMetadataURL() string {
	return s.PublicURL + ResourceMetadataPath + "/mcp"
}

// Routes mounts the login on mux. certMW is the client-certificate
// middleware the API uses; the consent endpoints sit behind it, so the
// certificate the browser presents is the login.
func (s *Server) Routes(mux *http.ServeMux, certMW func(http.Handler) http.Handler) {
	prm := auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               s.resource(),
		AuthorizationServers:   []string{s.PublicURL},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "FleetOS Fleet Manager",
	})
	mux.Handle("GET "+ResourceMetadataPath, prm)
	mux.Handle("GET "+ResourceMetadataPath+"/mcp", prm)
	mux.HandleFunc("GET "+authServerMetaPath, s.authServerMetadata)
	mux.HandleFunc("POST "+registerPath, s.register)
	mux.HandleFunc("GET "+authorizePath, s.authorize)
	mux.HandleFunc("POST "+tokenPath, s.token)
	mux.Handle("GET "+consentAPIPath+"{id}", certMW(http.HandlerFunc(s.consentInfo)))
	mux.Handle("POST "+consentAPIPath+"{id}", http.NewCrossOriginProtection().Handler(certMW(http.HandlerFunc(s.consentDecide))))
}

// authServerMeta is the RFC 8414 document. It is declared here rather than
// taken from oauthex so no empty jwks_uri is advertised: there are no signed
// tokens to verify.
type authServerMeta struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

func (s *Server) authServerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, authServerMeta{
		Issuer:                            s.PublicURL,
		AuthorizationEndpoint:             s.PublicURL + authorizePath,
		TokenEndpoint:                     s.PublicURL + tokenPath,
		RegistrationEndpoint:              s.PublicURL + registerPath,
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
	})
}

// client is what a registration records. It is carried inside the client_id
// itself, so registration needs no storage and every replica can read it.
// Nothing in it is secret or trusted beyond display: redirect URIs are
// loopback only and PKCE binds the code to the client that asked for it.
type client struct {
	Name         string   `json:"n"`
	RedirectURIs []string `json:"r"`
}

const (
	clientIDPrefix  = "fos-client-"
	maxClientName   = 200
	maxRedirectURIs = 10
	maxRedirectLen  = 512
	maxLabel        = 200
)

func encodeClientID(c client) string {
	b, _ := json.Marshal(c) // a struct of strings always marshals
	return clientIDPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func decodeClientID(id string) (client, bool) {
	body, ok := strings.CutPrefix(id, clientIDPrefix)
	if !ok {
		return client{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return client{}, false
	}
	var c client
	if json.Unmarshal(b, &c) != nil || len(c.RedirectURIs) == 0 {
		return client{}, false
	}
	for _, r := range c.RedirectURIs {
		if _, ok := loopback(r); !ok {
			return client{}, false
		}
	}
	return c, true
}

// loopback parses a redirect URI and accepts it only as an RFC 8252 loopback
// redirect: plain http to 127.0.0.1, [::1] or localhost, with no fragment.
// An MCP client is a native app on the operator's machine, so no other
// redirect can be legitimate, and refusing them means a code can never be
// sent to a remote site.
func loopback(raw string) (*url.URL, bool) {
	if len(raw) > maxRedirectLen {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Fragment != "" || u.User != nil {
		return nil, false
	}
	switch u.Hostname() {
	case "localhost":
		return u, true
	default:
		ip := net.ParseIP(u.Hostname())
		return u, ip != nil && ip.IsLoopback()
	}
}

// sameLoopback reports whether a matches registered, ignoring the port: a
// native app picks a free port at run time (RFC 8252 section 7.3).
func sameLoopback(registered, a *url.URL) bool {
	return registered.Hostname() == a.Hostname() && registered.Path == a.Path && registered.RawQuery == a.RawQuery
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var meta oauthex.ClientRegistrationMetadata
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&meta); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the body is not client metadata JSON")
		return
	}
	if len(meta.RedirectURIs) == 0 || len(meta.RedirectURIs) > maxRedirectURIs {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "between 1 and 10 loopback redirect_uris are required")
		return
	}
	for _, ru := range meta.RedirectURIs {
		if _, ok := loopback(ru); !ok {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "only http loopback redirect URIs (127.0.0.1, [::1], localhost) are accepted")
			return
		}
	}
	name := meta.ClientName
	if len(name) > maxClientName {
		name = name[:maxClientName]
	}

	c := client{Name: name, RedirectURIs: meta.RedirectURIs}
	log.Printf("oauth: registered MCP client %q from %s", name, r.RemoteAddr)
	// The server decides what is registered (RFC 7591 section 3.2.1): a
	// public client using the code grant, with no refresh tokens.
	writeJSON(w, http.StatusCreated, &oauthex.ClientRegistrationResponse{
		ClientRegistrationMetadata: oauthex.ClientRegistrationMetadata{
			RedirectURIs:            c.RedirectURIs,
			ClientName:              name,
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
		},
		ClientID:         encodeClientID(c),
		ClientIDIssuedAt: s.now(),
	})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, ok := decodeClientID(q.Get("client_id"))
	if !ok {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	redirect, ok := loopback(q.Get("redirect_uri"))
	registered := false
	for _, ru := range c.RedirectURIs {
		reg, _ := loopback(ru)
		if ok && sameLoopback(reg, redirect) {
			registered = true
		}
	}
	if !registered {
		// Never redirect to an unverified URI (RFC 6749 section 4.1.2.1).
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}

	state := q.Get("state")
	fail := func(code, desc string) {
		http.Redirect(w, r, withParams(redirect, url.Values{"error": {code}, "error_description": {desc}, "state": {state}}), http.StatusFound)
	}
	switch {
	case q.Get("response_type") != "code":
		fail("unsupported_response_type", "only the authorization code flow is supported")
		return
	case q.Get("code_challenge_method") != "S256" || !validPKCE(q.Get("code_challenge")):
		fail("invalid_request", "PKCE with code_challenge_method S256 is required")
		return
	case q.Get("resource") != "" && q.Get("resource") != s.resource():
		fail("invalid_target", "the only resource here is "+s.resource())
		return
	}

	req := store.OAuthRequest{
		ID:            randomToken(),
		ClientID:      q.Get("client_id"),
		ClientName:    c.Name,
		RedirectURI:   redirect.String(),
		State:         state,
		CodeChallenge: q.Get("code_challenge"),
		ExpiresAt:     s.now().Add(requestTTL),
	}
	s.Store.AddOAuthRequest(req)
	log.Printf("oauth: login request %s for client %q waiting for consent", req.ID, c.Name)
	http.Redirect(w, r, consentPagePath+"?req="+url.QueryEscape(req.ID), http.StatusFound)
}

// validPKCE checks a code challenge or verifier: 43 to 128 unreserved
// characters (RFC 7636 section 4.1).
func validPKCE(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !unreserved(c) {
			return false
		}
	}
	return true
}

func unreserved(c rune) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)
}

type consentOperator struct {
	CN     string `json:"cn"`
	Serial string `json:"serial"`
	Level  string `json:"level"`
}

type consentView struct {
	ClientName      string          `json:"client_name"`
	RedirectHost    string          `json:"redirect_host"`
	Operator        consentOperator `json:"operator"`
	AllowedCeilings []string        `json:"allowed_ceilings"`
}

// pending returns the unexpired request named in the path, answering 404
// otherwise.
func (s *Server) pending(w http.ResponseWriter, r *http.Request, take bool) (store.OAuthRequest, bool) {
	id := r.PathValue("id")
	var (
		req store.OAuthRequest
		ok  bool
	)
	if take {
		req, ok = s.Store.TakeOAuthRequest(id)
	} else {
		req, ok = s.Store.OAuthRequest(id)
	}
	if !ok || !s.now().Before(req.ExpiresAt) {
		http.Error(w, "unknown or expired login request", http.StatusNotFound)
		return store.OAuthRequest{}, false
	}
	return req, true
}

// operator returns the certificate identity the middleware verified, and the
// certificate itself.
func operator(w http.ResponseWriter, r *http.Request) (authz.Identity, *x509.Certificate, bool) {
	id, _ := authz.FromContext(r.Context())
	cert, ok := authz.PeerCertFromContext(r.Context())
	if !ok || id.KeyID != "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return authz.Identity{}, nil, false
	}
	return id, cert, true
}

func (s *Server) consentInfo(w http.ResponseWriter, r *http.Request) {
	id, _, ok := operator(w, r)
	if !ok {
		return
	}
	req, ok := s.pending(w, r, false)
	if !ok {
		return
	}
	redirect, _ := url.Parse(req.RedirectURI)

	var ceilings []string
	for l := authz.LevelViewer; l <= id.Level; l++ {
		ceilings = append(ceilings, l.Token())
	}
	writeJSON(w, http.StatusOK, consentView{
		ClientName:      req.ClientName,
		RedirectHost:    redirect.Host,
		Operator:        consentOperator{CN: id.CN, Serial: id.Serial, Level: id.Level.Token()},
		AllowedCeilings: ceilings,
	})
}

type consentDecision struct {
	Approve      bool   `json:"approve"`
	Label        string `json:"label"`
	LevelCeiling string `json:"level_ceiling"`
}

func (s *Server) consentDecide(w http.ResponseWriter, r *http.Request) {
	id, cert, ok := operator(w, r)
	if !ok {
		return
	}
	// JSON only: a cross-site form cannot send it without a CORS preflight.
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		http.Error(w, "the consent decision must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var d consentDecision
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&d); err != nil {
		http.Error(w, "the body is not a consent decision", http.StatusBadRequest)
		return
	}
	if d.LevelCeiling != "" {
		l, err := authz.LevelFromToken(d.LevelCeiling)
		if err != nil || l > id.Level {
			http.Error(w, "level_ceiling must be viewer, operator or admin, and not above your own level", http.StatusBadRequest)
			return
		}
	}
	if len(d.Label) > maxLabel {
		http.Error(w, "label is too long", http.StatusBadRequest)
		return
	}

	req, ok := s.pending(w, r, true)
	if !ok {
		return
	}
	redirect, _ := url.Parse(req.RedirectURI)

	if !d.Approve {
		log.Printf("oauth: login request %s denied by %s (%s)", req.ID, id.CN, id.Serial)
		writeJSON(w, http.StatusOK, map[string]string{
			"redirect_to": withParams(redirect, url.Values{"error": {"access_denied"}, "state": {req.State}}),
		})
		return
	}

	code := randomToken()
	label := d.Label
	if label == "" {
		label = req.ClientName
	}
	s.Store.AddOAuthCode(store.OAuthCode{
		CodeHash:        hashToken(code),
		ClientID:        req.ClientID,
		ClientName:      req.ClientName,
		RedirectURI:     req.RedirectURI,
		CodeChallenge:   req.CodeChallenge,
		OperatorCN:      id.CN,
		OperatorSerial:  id.Serial,
		OperatorCertDER: cert.Raw,
		LevelCeiling:    d.LevelCeiling,
		Label:           label,
		ExpiresAt:       s.now().Add(codeTTL),
	})
	log.Printf("oauth: login request %s approved by %s (%s)", req.ID, id.CN, id.Serial)
	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_to": withParams(redirect, url.Values{"code": {code}, "state": {req.State}}),
	})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body is not a form")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	code, ok := s.Store.TakeOAuthCode(hashToken(r.PostForm.Get("code")))
	switch {
	case !ok, !s.now().Before(code.ExpiresAt):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the code is unknown, used or expired")
		return
	case r.PostForm.Get("client_id") != code.ClientID:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the code was issued to another client")
		return
	case r.PostForm.Get("redirect_uri") != code.RedirectURI:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	case !verifierMatches(r.PostForm.Get("code_verifier"), code.CodeChallenge):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match the code challenge")
		return
	}

	cert, err := x509.ParseCertificate(code.OperatorCertDER)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "the stored operator certificate does not parse")
		return
	}
	owner, err := authz.IdentityFromCertificate(cert)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the operator certificate carries no access level")
		return
	}
	owner.Via = authz.ViaWeb

	plain, key, err := s.Keys.Mint(r.Context(), owner, code.OperatorCertDER, code.Label, code.ClientName, code.LevelCeiling)
	if errors.Is(err, mcpauth.ErrBadCeiling) || errors.Is(err, mcpauth.ErrCeilingTooHigh) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the level ceiling is no longer allowed")
		return
	}
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "the key could not be minted")
		return
	}
	log.Printf("oauth: minted MCP key %s for %s (%s) via client %q", key.ID, owner.CN, owner.Serial, code.ClientName)

	// No expires_in and no refresh token: the key lives until it or its
	// operator certificate is revoked or the certificate expires.
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]string{"access_token": plain, "token_type": "Bearer"})
}

func verifierMatches(verifier, challenge string) bool {
	if !validPKCE(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

func withParams(u *url.URL, params url.Values) string {
	out := *u
	q := out.Query()
	for k, v := range params {
		if len(v) > 0 && v[0] != "" {
			q[k] = v
		}
	}
	out.RawQuery = q.Encode()
	return out.String()
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
