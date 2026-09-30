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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/api/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/operatorca"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

var tokenPattern = regexp.MustCompile(`fos_boot_[0-9A-Z-]+`)

// harness is a BootstrapService wired to fakes and served in process: a
// client's requests go straight to the handler with the remote address and
// TLS state the test picks.
type harness struct {
	t      *testing.T
	ctx    context.Context
	clock  *fakeClock
	st     *fakeStore
	audit  *memory.Store
	trust  *operatorca.TrustStore
	rev    *operatorca.Revocations
	svc    *Service
	h      http.Handler
	logs   *logSink
	nodeCA []testCA

	mu      sync.Mutex
	banners [][]string
}

type harnessOpt func(*Options)

func newHarness(t *testing.T, opts ...harnessOpt) *harness {
	t.Helper()
	ctx := context.Background()
	h := &harness{t: t, ctx: ctx, clock: &fakeClock{t: testNow}, st: newFakeStore(), audit: memory.New(nil), logs: &logSink{}}
	h.rev = operatorca.NewRevocations(operatorca.RevocationOptions{Store: h.st, Now: h.clock.Now, Logf: h.logs.Logf,
		OCSPFetcher: operatorca.NewOCSPFetcher()})
	var err error
	h.trust, err = operatorca.NewTrustStore(ctx, operatorca.Source{Kind: operatorca.KindRegistered}, h.st, h.rev, &tls.Config{}, h.logs.Logf)
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}
	o := Options{
		Store: h.st, Audit: h.audit, Trust: h.trust, Rev: h.rev,
		FetchCRL: operatorca.NewFetcher(operatorca.FetchLimits{Timeout: operatorca.DefaultFetchTimeout, MaxBytes: operatorca.MaxCRLSize}).Fetch,
		Server:   ServerInfo{SHA256: "AB:CD", NotAfter: testNow.Add(90 * 24 * time.Hour)},
		Now:      h.clock.Now,
		Logf:     h.logs.Logf,
		PrintBanner: func(lines []string) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.banners = append(h.banners, lines)
		},
		NodeCAs: func() []*x509.Certificate {
			var out []*x509.Certificate
			for _, n := range h.nodeCA {
				out = append(out, n.cert)
			}
			return out
		},
	}
	for _, fn := range opts {
		fn(&o)
	}
	h.svc, err = New(ctx, o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := h.svc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, h.h = h.svc.Handler()
	return h
}

// token is the newest token printed in a banner.
func (h *harness) token() string {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.banners) - 1; i >= 0; i-- {
		for _, line := range h.banners[i] {
			if m := tokenPattern.FindString(line); m != "" {
				return m
			}
		}
	}
	h.t.Fatal("no token was printed")
	return ""
}

func (h *harness) bannerCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.banners)
}

func (h *harness) bannerText() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var b strings.Builder
	for _, lines := range h.banners {
		b.WriteString(strings.Join(lines, "\n"))
		b.WriteString("\n")
	}
	return b.String()
}

type inProcess struct {
	h      http.Handler
	remote string
	tls    bool
}

func (p inProcess) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.RemoteAddr = p.remote
	if p.tls {
		r.TLS = &tls.ConnectionState{HandshakeComplete: true}
	}
	if r.Body == nil {
		r.Body = http.NoBody
	}
	rec := httptest.NewRecorder()
	p.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

func (h *harness) clientFrom(remote string, withTLS bool) fleetv1connect.BootstrapServiceClient {
	return fleetv1connect.NewBootstrapServiceClient(&http.Client{Transport: inProcess{h: h.h, remote: remote, tls: withTLS}}, "https://fm.example.org")
}

func (h *harness) client() fleetv1connect.BootstrapServiceClient {
	return h.clientFrom("192.0.2.10:40000", true)
}

func (h *harness) state() *fleetv1.GetBootstrapStateResponse {
	h.t.Helper()
	resp, err := h.client().GetBootstrapState(h.ctx, connect.NewRequest(&fleetv1.GetBootstrapStateRequest{}))
	if err != nil {
		h.t.Fatalf("GetBootstrapState: %v", err)
	}
	return resp.Msg
}

// startSession starts a session with the newest token and returns its
// secret.
func (h *harness) startSession() string {
	h.t.Helper()
	resp, err := h.client().StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: h.token()}))
	if err != nil {
		h.t.Fatalf("StartBootstrapSession: %v", err)
	}
	return resp.Msg.GetSessionSecret()
}

func withSession[T any](secret string, msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set(SessionHeader, secret)
	return req
}

func (h *harness) register(secret string, msg *fleetv1.BootstrapServiceRegisterOperatorCARequest) (*fleetv1.BootstrapServiceRegisterOperatorCAResponse, error) {
	resp, err := h.client().RegisterOperatorCA(h.ctx, withSession(secret, msg))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// registerCA previews and confirms ca with no CRL and OCSP off.
func (h *harness) registerCA(secret string, ca testCA) {
	h.t.Helper()
	msg := &fleetv1.BootstrapServiceRegisterOperatorCARequest{
		CaCertDer:        ca.cert.Raw,
		CrlSource:        &fleetv1.BootstrapServiceRegisterOperatorCARequest_None{None: true},
		OcspMode:         fleetv1.OcspMode_OCSP_MODE_OFF,
		Acknowledgements: []fleetv1.OperatorCAAcknowledgement{fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_NO_CRL},
	}
	preview, err := h.register(secret, msg)
	if err != nil {
		h.t.Fatalf("RegisterOperatorCA preview: %v", err)
	}
	msg.ConfirmSha256 = preview.GetOperatorCa().GetSha256()
	if _, err := h.register(secret, msg); err != nil {
		h.t.Fatalf("RegisterOperatorCA confirm: %v", err)
	}
}

func (h *harness) submit(secret string, msg *fleetv1.SubmitFirstAdminCertificateRequest) (*fleetv1.SubmitFirstAdminCertificateResponse, error) {
	resp, err := h.client().SubmitFirstAdminCertificate(h.ctx, withSession(secret, msg))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (h *harness) auditKinds(kind string) []store.AuditEvent {
	var out []store.AuditEvent
	for _, e := range h.audit.Audit() {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// codeOf returns the numeric code and sub-reason a refusal carries.
func codeOf(t *testing.T, err error) (int, string) {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a Connect error", err)
	}
	n, convErr := strconv.Atoi(ce.Meta().Get(apperr.MetadataKey))
	if convErr != nil {
		t.Fatalf("error %v has no numeric code (%q)", err, ce.Meta().Get(apperr.MetadataKey))
	}
	return n, ce.Meta().Get(apperr.ReasonKey)
}

func wantCode(t *testing.T, err error, code int, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want %d %s", code, reason)
	}
	gotCode, gotReason := codeOf(t, err)
	if gotCode != code || gotReason != reason {
		t.Fatalf("got %d %q (%v), want %d %q", gotCode, gotReason, err, code, reason)
	}
}
