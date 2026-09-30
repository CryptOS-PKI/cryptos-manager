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
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/api/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/operatorca"
	"github.com/CryptOS-PKI/manager/internal/store"
)

func TestGetBootstrapState_PerSourceAndState(t *testing.T) {
	t.Run("open, then in progress", func(t *testing.T) {
		h := newHarness(t)
		st := h.state()
		if st.GetState() != fleetv1.BootstrapState_BOOTSTRAP_STATE_OPEN || st.GetTokenExpiresAt() == "" {
			t.Fatalf("fresh state = %+v; want OPEN with the token expiry", st)
		}
		h.startSession()
		if got := h.state().GetState(); got != fleetv1.BootstrapState_BOOTSTRAP_STATE_OPEN_IN_PROGRESS {
			t.Fatalf("state with a live session = %v, want OPEN_IN_PROGRESS", got)
		}
		h.clock.Add(16 * time.Minute)
		if got := h.state().GetState(); got != fleetv1.BootstrapState_BOOTSTRAP_STATE_OPEN {
			t.Fatalf("state after the session idled out = %v, want OPEN", got)
		}
	})
	t.Run("closed", func(t *testing.T) {
		h := newHarness(t)
		ca := newCA(t, "Example Operator CA")
		admin := ca.leaf(t, leafOpts{})
		h.svc.Latch().Observe(h.ctx, adminIdentity(admin, ca), admin)
		st := h.state()
		if st.GetState() != fleetv1.BootstrapState_BOOTSTRAP_STATE_CLOSED || st.GetTokenExpiresAt() != "" {
			t.Fatalf("state = %+v; want CLOSED and no token expiry", st)
		}
	})
	t.Run("file source", func(t *testing.T) {
		h := newHarness(t, func(o *Options) {
			rev := operatorca.NewRevocations(operatorca.RevocationOptions{Store: newFakeStore()})
			ts, err := operatorca.NewTrustStore(t.Context(), operatorca.Source{Kind: operatorca.KindFile}, newFakeStore(), rev, &tls.Config{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			o.Trust, o.Rev = ts, rev
		})
		if got := h.state().GetState(); got != fleetv1.BootstrapState_BOOTSTRAP_STATE_NOT_APPLICABLE {
			t.Fatalf("file source state = %v, want NOT_APPLICABLE", got)
		}
		if h.bannerCount() != 0 {
			t.Fatal("the file source printed a banner")
		}
		if len(h.st.tokenHashes()) != 0 {
			t.Fatal("the file source wrote a token")
		}
		_, err := h.client().StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: "fos_boot_x"}))
		wantCode(t, err, apperr.CodeFirstRunClosed, "")
	})
	t.Run("no database", func(t *testing.T) {
		h := newHarness(t, func(o *Options) { o.Store = nil })
		st := h.state()
		if st.GetState() != fleetv1.BootstrapState_BOOTSTRAP_STATE_UNAVAILABLE || st.GetReasonCode() != fleetv1.ErrorReason_ERROR_REASON_DATABASE_REQUIRED {
			t.Fatalf("state without Postgres = %+v", st)
		}
		_, err := h.client().StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: "fos_boot_x"}))
		wantCode(t, err, apperr.CodeUnavailable, "DATABASE_REQUIRED")
	})
	t.Run("first run disabled", func(t *testing.T) {
		h := newHarness(t, func(o *Options) { o.FirstRunDisabled = true })
		st := h.state()
		if st.GetState() != fleetv1.BootstrapState_BOOTSTRAP_STATE_UNAVAILABLE || st.GetReasonCode() != fleetv1.ErrorReason_ERROR_REASON_FIRST_RUN_DISABLED {
			t.Fatalf("state with firstRun disabled = %+v", st)
		}
		if h.bannerCount() != 0 {
			t.Fatal("a banner was printed with firstRun disabled")
		}
	})
}

func TestClosed_SessionRPCsReturn1601WithoutLookingAnythingUp(t *testing.T) {
	h := newHarness(t)
	secret := h.startSession()
	tok := h.token()
	ca := newCA(t, "Example Operator CA")
	admin := ca.leaf(t, leafOpts{})
	h.svc.Latch().Observe(h.ctx, adminIdentity(admin, ca), admin)

	tokens, sessions := h.st.lookups()
	_, err := h.client().StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: tok}))
	wantCode(t, err, apperr.CodeFirstRunClosed, "")
	_, err = h.register(secret, noCRL(ca))
	wantCode(t, err, apperr.CodeFirstRunClosed, "")
	_, err = h.submit(secret, &fleetv1.SubmitFirstAdminCertificateRequest{CertDer: admin.Raw, FullName: "Ada Example"})
	wantCode(t, err, apperr.CodeFirstRunClosed, "")
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("Connect code %v, want FailedPrecondition", connect.CodeOf(err))
	}
	if t2, s2 := h.st.lookups(); t2 != tokens || s2 != sessions {
		t.Fatalf("a closed first run looked up tokens (%d -> %d) or sessions (%d -> %d)", tokens, t2, sessions, s2)
	}
}

func TestRateLimit_PerClient(t *testing.T) {
	h := newHarness(t)
	c := h.clientFrom("203.0.113.7:5000", true)
	bad, _ := NewToken(rand.Reader)
	for i := 0; i < 5; i++ {
		_, err := c.StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: bad}))
		wantCode(t, err, apperr.CodeTokenInvalid, "")
	}
	_, err := c.StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: h.token()}))
	wantCode(t, err, apperr.CodeRateLimited, "")
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("Connect code %v, want ResourceExhausted", connect.CodeOf(err))
	}
	// A bad session counts too, and another client is unaffected.
	if _, err := h.clientFrom("203.0.113.8:5000", true).StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: h.token()})); err != nil {
		t.Fatalf("another client was throttled: %v", err)
	}
	h.clock.Add(61 * time.Second)
	if h.logs.count("203.0.113.7") == 0 {
		t.Error("refusals weren't logged with the client address")
	}
}

func TestRateLimit_GlobalCapRotatesTheTokenAndEndsTheSession(t *testing.T) {
	h := newHarness(t)
	secret := h.startSession()
	tok := h.token()
	bad, _ := NewToken(rand.Reader)
	for i := 0; i < 50; i++ {
		c := h.clientFrom("198.51.100."+strconv.Itoa(i)+":1", true)
		_, _ = c.StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: bad}))
	}
	if h.token() == tok {
		t.Fatal("50 failures in an hour didn't rotate the token")
	}
	if !strings.Contains(h.bannerText(), "failed") {
		t.Error("the new banner doesn't say why the token was rotated")
	}
	_, err := h.clientFrom("192.0.2.200:1", true).RegisterOperatorCA(h.ctx, withSession(secret, noCRL(newCA(t, "Example Operator CA"))))
	wantCode(t, err, apperr.CodeSessionInvalid, "")
	_, err = h.clientFrom("192.0.2.201:1", true).StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: tok}))
	wantCode(t, err, apperr.CodeTokenInvalid, "")
	if len(h.auditKinds(KindTokenRotated)) != 1 {
		t.Error("the failure-driven rotation wasn't audited")
	}
}

func TestEveryProcedureRefusesPlaintext(t *testing.T) {
	h := newHarness(t)
	c := h.clientFrom("192.0.2.10:1", false)
	checks := map[string]func() error{
		"GetBootstrapState": func() error {
			_, err := c.GetBootstrapState(h.ctx, connect.NewRequest(&fleetv1.GetBootstrapStateRequest{}))
			return err
		},
		"StartBootstrapSession": func() error {
			_, err := c.StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: h.token()}))
			return err
		},
		"RegisterOperatorCA": func() error {
			_, err := c.RegisterOperatorCA(h.ctx, connect.NewRequest(&fleetv1.BootstrapServiceRegisterOperatorCARequest{}))
			return err
		},
		"SubmitFirstAdminCertificate": func() error {
			_, err := c.SubmitFirstAdminCertificate(h.ctx, connect.NewRequest(&fleetv1.SubmitFirstAdminCertificateRequest{}))
			return err
		},
	}
	for name, call := range checks {
		if err := call(); err == nil {
			t.Errorf("%s answered a request that didn't come over TLS", name)
		}
	}
	if len(h.st.sessionHashes()) != 0 {
		t.Fatal("a plaintext request started a session")
	}
}

func TestHandler_BodyLimits(t *testing.T) {
	h := newHarness(t)
	path, _ := h.svc.Handler()
	if path != "/"+fleetv1connect.BootstrapServiceName+"/" {
		t.Fatalf("path = %q", path)
	}
	big := bytes.Repeat([]byte("a"), 17<<10)
	req := httptest.NewRequest(http.MethodPost, fleetv1connect.BootstrapServiceStartBootstrapSessionProcedure, bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("a 17 KiB StartBootstrapSession body was accepted")
	}
	if len(h.st.sessionHashes()) != 0 {
		t.Fatal("an oversized request started a session")
	}
}

func TestHandler_CrossOriginWritesRefused(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodPost, fleetv1connect.BootstrapServiceStartBootstrapSessionProcedure, strings.NewReader(`{"token":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://evil.example.net")
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a cross-site POST got %d, want 403", rec.Code)
	}
}

var _ = store.SessionEndedClosed
