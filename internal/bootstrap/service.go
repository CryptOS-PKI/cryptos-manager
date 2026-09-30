// Package bootstrap is the Fleet Manager's first run: before any operator CA
// is trusted, the holder of a one-time token from the manager's log registers
// the external operator CA's certificate and checks the first admin
// certificate that CA signed. The manager signs nothing here. First run
// closes for good the first time an admin certificate authenticates.
//
// BootstrapService is served over HTTPS only, outside the client-certificate
// middleware. Tokens and session secrets are kept only as SHA-256 hashes in
// Postgres; without Postgres first run is unavailable.
package bootstrap

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
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/api/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/operatorca"
	"github.com/CryptOS-PKI/manager/internal/ratelimit"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// ActorBootstrapSession is the audit actor kind of whatever a bootstrap
// session did.
const ActorBootstrapSession = "bootstrap_session"

// Audit kinds written by first run.
const (
	KindSessionStarted       = "bootstrap-session-started"
	KindOperatorCARegistered = "operator-ca-registered"
	KindFirstAdminRecorded   = "operator-first-admin-recorded"
	KindFirstAdminSuperseded = "operator-first-admin-superseded"
	KindBootstrapClosed      = "bootstrap-closed"
	KindTokenRotated         = "bootstrap-token-rotated"
)

// Failure limits: per client, a burst of 5 that refills one a minute;
// across every client, 50 in an hour rotate the token and end the session.
const (
	perClientBurst  = 5
	perClientRefill = time.Minute
	globalFailures  = 50
	globalWindow    = time.Hour
	tokenTick       = 30 * time.Second
)

// Request body limits: the session procedures carry at most a certificate,
// a CSR and a name; RegisterOperatorCA can carry a CRL.
const (
	maxSessionBody  = 16 << 10
	maxRegisterBody = operatorca.MaxCRLSize + 64<<10
)

// Store is what first run needs from the database.
type Store interface {
	store.OperatorTrust
	store.Bootstrap
}

// OCSPProbe checks, at registration, that an OCSP responder set in url mode
// answers for the anchor with a validly signed response. A failure carries
// 1605 OCSP_UNREACHABLE or OCSP_INVALID.
type OCSPProbe func(ctx context.Context, anchor *x509.Certificate, url string) (*fleetv1.OcspProbeResult, error)

// ServerInfo is the server certificate the banner tells the operator to
// check in the browser.
type ServerInfo struct {
	SHA256   string
	NotAfter time.Time
}

// Options configures a Service.
type Options struct {
	// Store is nil without Postgres, which makes first run unavailable.
	Store Store
	// Audit is the audit chain.
	Audit store.Store
	Trust *operatorca.TrustStore
	Rev   *operatorca.Revocations
	// FirstRunDisabled is firstRun: disabled.
	FirstRunDisabled bool
	// NodeCAs returns the CryptOS node CA certificates the manager knows, so
	// a node's CA is refused as the operator CA.
	NodeCAs func() []*x509.Certificate
	// FetchCRL fetches a CRL URL with the manager's fetch limits.
	FetchCRL func(ctx context.Context, url string) ([]byte, error)
	// OCSPProbe checks a url-mode OCSP responder at registration. It is nil
	// only without an OCSP client; the mode and URL are then stored
	// unprobed.
	OCSPProbe OCSPProbe
	// TrustedOrigins are extra origins allowed to POST cross-origin (the
	// configured CORS origins).
	TrustedOrigins []string
	Server         ServerInfo
	Now            func() time.Time
	Rand           io.Reader
	Logf           func(string, ...any)
	// PrintBanner prints a token banner. It defaults to the process log.
	PrintBanner func(lines []string)
}

// Service is BootstrapService.
type Service struct {
	fleetv1connect.UnimplementedBootstrapServiceHandler

	st       Store
	audit    store.Store
	trust    *operatorca.TrustStore
	rev      *operatorca.Revocations
	disabled bool
	nodeCAs  func() []*x509.Certificate
	fetchCRL func(ctx context.Context, url string) ([]byte, error)
	probe    OCSPProbe
	origins  []string
	now      func() time.Time
	rand     io.Reader
	logf     func(string, ...any)

	tokens    *tokens
	latch     *Latch
	perClient *ratelimit.Failures
	global    *ratelimit.Window
}

// New builds the service and reads the latch.
func New(ctx context.Context, o Options) (*Service, error) {
	s := &Service{
		st: o.Store, audit: o.Audit, trust: o.Trust, rev: o.Rev, disabled: o.FirstRunDisabled,
		nodeCAs: o.NodeCAs, fetchCRL: o.FetchCRL, probe: o.OCSPProbe, origins: o.TrustedOrigins,
		now: o.Now, rand: o.Rand, logf: o.Logf,
		perClient: ratelimit.NewFailures(perClientBurst, perClientRefill),
		global:    ratelimit.NewWindow(globalFailures, globalWindow),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.rand == nil {
		s.rand = rand.Reader
	}
	if s.logf == nil {
		s.logf = log.Printf
	}
	if s.nodeCAs == nil {
		s.nodeCAs = func() []*x509.Certificate { return nil }
	}
	printBanner := o.PrintBanner
	if printBanner == nil {
		printBanner = func(lines []string) {
			for _, l := range lines {
				log.Print(l)
			}
		}
	}
	var bs store.Bootstrap
	if s.st != nil {
		bs = s.st
		s.tokens = &tokens{st: s.st, lock: s.st.TryAdvisoryLock, now: s.now, rand: s.rand, print: printBanner, server: o.Server, logf: s.logf}
	}
	latch, err := NewLatch(ctx, LatchOptions{Store: bs, Audit: s.audit, Now: s.now, Logf: s.logf, OnClose: s.onClose})
	if err != nil {
		return nil, err
	}
	s.latch = latch
	return s, nil
}

// Latch is the first-run latch, to hook into the client-certificate
// middleware.
func (s *Service) Latch() *Latch { return s.latch }

func (s *Service) onClose() {
	if s.tokens != nil {
		s.tokens.stop()
	}
}

// firstRunApplies reports whether this deployment has a first run at all:
// the registered source with Postgres and firstRun not disabled.
func (s *Service) firstRunApplies() bool {
	return s.st != nil && !s.disabled && s.trust != nil && s.trust.Source().Kind == operatorca.KindRegistered
}

// Start prints the first token when first run is open and this replica
// holds the token lock, then keeps a token live until first run closes. A
// closed first run that trusts nothing is logged, so the operator knows why
// every caller is refused.
func (s *Service) Start(ctx context.Context) error {
	if !s.firstRunApplies() {
		return nil
	}
	closed, err := s.closed(ctx)
	if err != nil {
		return err
	}
	if closed {
		if len(s.trust.Anchors()) == 0 {
			s.logf("manager: WARNING no operator CA is trusted and first run is closed, so every API caller is refused; " +
				"restore operatorCAPath, or reopen first run with the break-glass reset")
		}
		return nil
	}
	s.tokens.ensure(ctx, true)
	go func() {
		t := time.NewTicker(tokenTick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if s.latch.Closed() {
					return
				}
				s.TickTokens(ctx)
			}
		}
	}()
	return nil
}

// TickTokens issues a new token when the live one expired and this replica
// holds the token lock. It does nothing once first run is closed.
func (s *Service) TickTokens(ctx context.Context) {
	if !s.firstRunApplies() || s.latch.Closed() {
		return
	}
	if closed, err := s.closed(ctx); err != nil || closed {
		return
	}
	s.tokens.ensure(ctx, false)
}

func (s *Service) closed(ctx context.Context) (bool, error) {
	if s.latch.Closed() {
		return true, nil
	}
	st, err := s.st.BootstrapState(ctx)
	if err != nil {
		return false, fmt.Errorf("bootstrap: read the first-run latch: %w", err)
	}
	if st.Closed() {
		s.latch.markClosed()
	}
	return st.Closed(), nil
}

// state computes the first-run state.
func (s *Service) state(ctx context.Context) (fleetv1.BootstrapState, fleetv1.ErrorReason, error) {
	switch {
	case s.trust != nil && s.trust.Source().Kind == operatorca.KindFile:
		return fleetv1.BootstrapState_BOOTSTRAP_STATE_NOT_APPLICABLE, 0, nil
	case s.st == nil:
		return fleetv1.BootstrapState_BOOTSTRAP_STATE_UNAVAILABLE, fleetv1.ErrorReason_ERROR_REASON_DATABASE_REQUIRED, nil
	case s.disabled:
		return fleetv1.BootstrapState_BOOTSTRAP_STATE_UNAVAILABLE, fleetv1.ErrorReason_ERROR_REASON_FIRST_RUN_DISABLED, nil
	}
	closed, err := s.closed(ctx)
	if err != nil {
		return 0, 0, err
	}
	if closed {
		return fleetv1.BootstrapState_BOOTSTRAP_STATE_CLOSED, 0, nil
	}
	live, err := s.st.HasLiveBootstrapSession(ctx, s.now(), SessionIdle)
	if err != nil {
		return 0, 0, fmt.Errorf("bootstrap: look for a live session: %w", err)
	}
	if live || s.activeCA(ctx) != nil {
		return fleetv1.BootstrapState_BOOTSTRAP_STATE_OPEN_IN_PROGRESS, 0, nil
	}
	return fleetv1.BootstrapState_BOOTSTRAP_STATE_OPEN, 0, nil
}

// activeCA returns the active registered operator CA row, if any.
func (s *Service) activeCA(ctx context.Context) *store.OperatorCA {
	rows, err := s.st.OperatorCAs(ctx)
	if err != nil {
		s.logf("bootstrap: can't read operator CAs: %v", err)
		return nil
	}
	for _, r := range rows {
		if r.State == store.OperatorCAActive {
			return &r
		}
	}
	return nil
}

// gate refuses a session procedure unless first run is open. It reads
// neither the token nor the session, so a closed deployment is no oracle.
func (s *Service) gate(ctx context.Context) error {
	st, reason, err := s.state(ctx)
	if err != nil {
		return err
	}
	switch st {
	case fleetv1.BootstrapState_BOOTSTRAP_STATE_OPEN, fleetv1.BootstrapState_BOOTSTRAP_STATE_OPEN_IN_PROGRESS:
		return nil
	case fleetv1.BootstrapState_BOOTSTRAP_STATE_UNAVAILABLE:
		return connect.NewError(connect.CodeFailedPrecondition, apperr.Reasoned(apperr.CodeUnavailable, reason,
			errors.New("bootstrap: first run is unavailable")))
	default:
		return connect.NewError(connect.CodeFailedPrecondition, apperr.Coded(apperr.CodeFirstRunClosed,
			errors.New("bootstrap: first run is closed")))
	}
}

// admit is the start of every session procedure: first run open, then the
// client's failure budget.
func (s *Service) admit(ctx context.Context) error {
	if err := s.gate(ctx); err != nil {
		return err
	}
	if s.perClient.Blocked(clientIP(ctx)) {
		s.logf("bootstrap: refused %s from %s: rate limited", procedure(ctx), clientIP(ctx))
		return connect.NewError(connect.CodeResourceExhausted, apperr.Coded(apperr.CodeRateLimited,
			errors.New("bootstrap: too many failures from this client")))
	}
	return nil
}

// fail counts a refusal against the client and the global cap, logs it by
// class, and returns it. Tripping the global cap rotates the token and ends
// the live session.
func (s *Service) fail(ctx context.Context, err error) error {
	ip := clientIP(ctx)
	s.logf("bootstrap: refused %s from %s: %s", procedure(ctx), ip, errorClass(err))
	s.perClient.Fail(ip)
	if s.global.Fail() {
		s.rotateAfterFailures(ctx)
	}
	return err
}

func (s *Service) rotateAfterFailures(ctx context.Context) {
	now := s.now().UTC()
	s.logf("manager: WARNING %d failed first-run requests within an hour; rotating the bootstrap token and ending the live session", globalFailures)
	if _, err := s.st.EndBootstrapSessions(ctx, store.SessionEndedRateLimited, now); err != nil {
		s.logf("bootstrap: can't end the live session: %v", err)
	}
	if err := s.tokens.issue(ctx, fmt.Sprintf("%d failed first-run requests within an hour", globalFailures)); err != nil {
		s.logf("bootstrap: can't rotate the bootstrap token: %v", err)
	}
	s.record(ctx, store.AuditEvent{
		Kind:    KindTokenRotated,
		Summary: fmt.Sprintf("Rotated the bootstrap token and ended the live session after %d failed first-run requests within an hour", globalFailures),
	})
}

// errorClass names a refusal for the log by its code and sub-reason, never
// by its message.
func errorClass(err error) string {
	code, _ := apperr.Code(err)
	class := fmt.Sprintf("%d", code)
	if r, ok := apperr.ReasonOf(err); ok {
		class += " " + apperr.ReasonName(r)
	}
	return class
}

func invalidToken() error {
	return connect.NewError(connect.CodeUnauthenticated, apperr.Coded(apperr.CodeTokenInvalid,
		errors.New("bootstrap: the bootstrap token is wrong, expired or used")))
}

func invalidSession() error {
	return connect.NewError(connect.CodeUnauthenticated, apperr.Coded(apperr.CodeSessionInvalid,
		errors.New("bootstrap: the bootstrap session is unknown, expired or ended")))
}

// session checks the session header and records the use. It returns the
// session's hash.
func (s *Service) session(ctx context.Context, h http.Header) (string, error) {
	secret := h.Get(SessionHeader)
	if len(secret) <= len(SessionPrefix) || secret[:len(SessionPrefix)] != SessionPrefix {
		return "", s.fail(ctx, invalidSession())
	}
	hash := HashSecret(secret)
	sess, ok, err := s.st.BootstrapSession(ctx, hash)
	if err != nil {
		return "", fmt.Errorf("bootstrap: read the session: %w", err)
	}
	now := s.now().UTC()
	if !ok || !sess.EndedAt.IsZero() {
		return "", s.fail(ctx, invalidSession())
	}
	if !now.Before(sess.ExpiresAt) || now.Sub(sess.LastUsedAt) >= SessionIdle {
		if err := s.st.EndBootstrapSession(ctx, hash, store.SessionEndedExpired, now); err != nil {
			s.logf("bootstrap: can't end an expired session: %v", err)
		}
		return "", s.fail(ctx, invalidSession())
	}
	if err := s.st.TouchBootstrapSession(ctx, hash, now); err != nil {
		return "", fmt.Errorf("bootstrap: touch the session: %w", err)
	}
	return hash, nil
}

// record writes an audit row for something a bootstrap session did.
func (s *Service) record(ctx context.Context, e store.AuditEvent) {
	if s.audit == nil {
		return
	}
	if _, ok := authz.FromContext(ctx); !ok {
		e.ActorKind = ActorBootstrapSession
		e.Via = authz.ViaWeb
	}
	auditlog.Record(ctx, s.audit, e)
}

// GetBootstrapState reports whether first run is open. Anonymous.
func (s *Service) GetBootstrapState(ctx context.Context, _ *connect.Request[fleetv1.GetBootstrapStateRequest]) (*connect.Response[fleetv1.GetBootstrapStateResponse], error) {
	st, reason, err := s.state(ctx)
	if err != nil {
		return nil, err
	}
	resp := &fleetv1.GetBootstrapStateResponse{State: st, ReasonCode: reason}
	if st == fleetv1.BootstrapState_BOOTSTRAP_STATE_OPEN || st == fleetv1.BootstrapState_BOOTSTRAP_STATE_OPEN_IN_PROGRESS {
		if tok, ok, err := s.st.LiveBootstrapToken(ctx, s.now()); err == nil && ok {
			resp.TokenExpiresAt = tok.ExpiresAt.UTC().Format(time.RFC3339)
		}
	}
	return connect.NewResponse(resp), nil
}

// StartBootstrapSession consumes the token and starts the one live session.
func (s *Service) StartBootstrapSession(ctx context.Context, req *connect.Request[fleetv1.StartBootstrapSessionRequest]) (*connect.Response[fleetv1.StartBootstrapSessionResponse], error) {
	if err := s.admit(ctx); err != nil {
		return nil, err
	}
	canon, ok := CanonicalToken(req.Msg.GetToken())
	if !ok {
		return nil, s.fail(ctx, invalidToken())
	}
	secret, err := newSessionSecret(s.rand)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	sess := store.BootstrapSession{Hash: HashSecret(secret), CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(SessionMax)}
	started, err := s.st.StartBootstrapSession(ctx, HashSecret(canon), sess, now)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: start the session: %w", err)
	}
	if !started {
		return nil, s.fail(ctx, invalidToken())
	}
	if err := s.tokens.issue(ctx, "the previous token started a session"); err != nil {
		s.logf("bootstrap: can't issue the next bootstrap token: %v", err)
	}
	s.logf("manager: bootstrap session started from %s", clientIP(ctx))
	s.record(ctx, store.AuditEvent{
		Kind:    KindSessionStarted,
		Summary: fmt.Sprintf("Started a first-run session from %s; any earlier session was ended", clientIP(ctx)),
	})
	return connect.NewResponse(&fleetv1.StartBootstrapSessionResponse{
		SessionSecret: secret,
		ExpiresAt:     sess.ExpiresAt.Format(time.RFC3339),
	}), nil
}

type requestInfoKey struct{}

type requestInfo struct {
	ip        string
	procedure string
}

func clientIP(ctx context.Context) string {
	if ri, ok := ctx.Value(requestInfoKey{}).(requestInfo); ok {
		return ri.ip
	}
	return ""
}

func procedure(ctx context.Context) string {
	if ri, ok := ctx.Value(requestInfoKey{}).(requestInfo); ok {
		return ri.procedure
	}
	return ""
}

// Handler returns BootstrapService's path and handler. The handler refuses
// any request that didn't arrive over TLS, refuses cross-origin writes,
// bounds request bodies, and gives every refusal a numeric code.
func (s *Service) Handler() (string, http.Handler) {
	path, h := fleetv1connect.NewBootstrapServiceHandler(s,
		connect.WithInterceptors(apperr.Interceptor()),
		connect.WithReadMaxBytes(maxRegisterBody),
	)
	cop := http.NewCrossOriginProtection()
	for _, o := range s.origins {
		if err := cop.AddTrustedOrigin(o); err != nil {
			s.logf("bootstrap: WARNING ignoring CORS origin %q for first run: %v", o, err)
		}
	}
	return path, cop.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			s.logf("bootstrap: refused %s from %s: not over TLS", r.URL.Path, ratelimit.ClientIP(r))
			apperr.WriteHTTP(w, http.StatusForbidden, apperr.Coded(apperr.CodeUnavailable,
				errors.New("bootstrap: first run is served over HTTPS only")))
			return
		}
		limit := int64(maxSessionBody)
		if r.URL.Path == fleetv1connect.BootstrapServiceRegisterOperatorCAProcedure {
			limit = maxRegisterBody
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		ctx := context.WithValue(r.Context(), requestInfoKey{}, requestInfo{ip: ratelimit.ClientIP(r), procedure: r.URL.Path})
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
}
