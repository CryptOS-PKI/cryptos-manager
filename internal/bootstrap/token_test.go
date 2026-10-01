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
	"crypto/rand"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/store"
)

const wantAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func TestNewToken_FormatAndEntropy(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		tok, err := NewToken(rand.Reader)
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if !strings.HasPrefix(tok, TokenPrefix) {
			t.Fatalf("token %q lacks the %s prefix", tok, TokenPrefix)
		}
		groups := strings.Split(strings.TrimPrefix(tok, TokenPrefix), "-")
		body := strings.Join(groups, "")
		// 256 bits in base32 is 52 characters (5 bits each), grouped in fours.
		if len(body) != 52 {
			t.Fatalf("token body has %d characters, want 52 for 256 bits", len(body))
		}
		for i, g := range groups {
			if len(g) != 4 {
				t.Fatalf("group %d of %q has %d characters, want 4", i, tok, len(g))
			}
		}
		for _, c := range body {
			if !strings.ContainsRune(wantAlphabet, c) {
				t.Fatalf("token %q has %q, outside the Crockford base32 alphabet", tok, c)
			}
		}
		if seen[tok] {
			t.Fatalf("token %q repeated", tok)
		}
		seen[tok] = true
	}
}

func TestCanonicalToken_ForgivesReadingMistakes(t *testing.T) {
	tok, err := NewToken(rand.Reader)
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	want, ok := CanonicalToken(tok)
	if !ok {
		t.Fatalf("CanonicalToken(%q) refused a fresh token", tok)
	}
	for _, typed := range []string{
		"  " + tok + "\n",
		strings.ToLower(tok),
		strings.ReplaceAll(tok, "-", ""),
	} {
		got, ok := CanonicalToken(typed)
		if !ok || got != want {
			t.Errorf("CanonicalToken(%q) = %q, %v; want %q", typed, got, ok, want)
		}
	}
	for _, bad := range []string{"", "fos_boot_", "fos_bsess_" + strings.TrimPrefix(tok, TokenPrefix), tok + "U", tok[:len(tok)-1]} {
		if _, ok := CanonicalToken(bad); ok {
			t.Errorf("CanonicalToken(%q) accepted a malformed token", bad)
		}
	}
}

func TestStartSession_OnlyHashesAreStored(t *testing.T) {
	h := newHarness(t)
	tok := h.token()
	secret := h.startSession()
	if !strings.HasPrefix(secret, SessionPrefix) {
		t.Fatalf("session secret %q lacks the %s prefix", secret, SessionPrefix)
	}
	canon, _ := CanonicalToken(tok)
	for _, hash := range h.st.tokenHashes() {
		if strings.Contains(hash, strings.TrimPrefix(canon, TokenPrefix)) || hash == tok {
			t.Fatalf("the store holds the token itself: %q", hash)
		}
		if len(hash) != 64 {
			t.Fatalf("stored token hash %q is not a hex SHA-256", hash)
		}
	}
	found := false
	for _, hash := range h.st.sessionHashes() {
		if strings.Contains(hash, strings.TrimPrefix(secret, SessionPrefix)) {
			t.Fatalf("the store holds the session secret itself: %q", hash)
		}
		if hash == HashSecret(secret) {
			found = true
		}
	}
	if !found {
		t.Fatal("the session's SHA-256 wasn't stored")
	}
}

func TestStartSession_WrongExpiredOrUsedTokenGiveTheSame1600(t *testing.T) {
	h := newHarness(t)
	first := h.token()
	if _, err := h.client().StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: first})); err != nil {
		t.Fatalf("a good token: %v", err)
	}

	wrong, _ := NewToken(rand.Reader)
	cases := map[string]string{"wrong": wrong, "used": first, "malformed": "fos_boot_nope"}
	var messages []string
	for name, tok := range cases {
		_, err := h.clientFrom("198.51.100."+name[:1]+":1", true).StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: tok}))
		wantCode(t, err, apperr.CodeTokenInvalid, "")
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s token: Connect code %v, want Unauthenticated", name, connect.CodeOf(err))
		}
		messages = append(messages, err.Error())
	}

	// Expired: the token printed after the session start, an hour later.
	next := h.token()
	h.clock.Add(61 * time.Minute)
	_, err := h.clientFrom("198.51.100.99:1", true).StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: next}))
	wantCode(t, err, apperr.CodeTokenInvalid, "")
	messages = append(messages, err.Error())
	for _, m := range messages[1:] {
		if m != messages[0] {
			t.Fatalf("refusals differ, which tells a caller why: %q vs %q", m, messages[0])
		}
	}
}

func TestStartSession_PrintsANewTokenAtOnce(t *testing.T) {
	h := newHarness(t)
	if n := h.bannerCount(); n != 1 {
		t.Fatalf("%d banners at start, want 1", n)
	}
	first := h.token()
	h.startSession()
	if n := h.bannerCount(); n != 2 {
		t.Fatalf("%d banners after the session started, want 2", n)
	}
	if next := h.token(); next == first {
		t.Fatal("the session start printed the same token again")
	}
}

func TestTokenExpiry_PrintsANewToken(t *testing.T) {
	h := newHarness(t)
	first := h.token()
	h.clock.Add(30 * time.Minute)
	h.svc.TickTokens(h.ctx)
	if h.bannerCount() != 1 {
		t.Fatal("a live token was replaced before it expired")
	}
	h.clock.Add(31 * time.Minute)
	h.svc.TickTokens(h.ctx)
	if h.bannerCount() != 2 || h.token() == first {
		t.Fatal("no new token was printed after the first expired")
	}
	if got := h.state().GetTokenExpiresAt(); got != h.clock.Now().Add(TokenTTL).Format(time.RFC3339) {
		t.Errorf("token_expires_at = %q, want the new token's expiry", got)
	}
}

func TestTokens_OnlyTheLockHolderPrintsOnStartAndExpiry(t *testing.T) {
	h := newHarness(t)
	second, err := New(h.ctx, Options{Store: h.st, Audit: h.audit, Trust: h.trust, Rev: h.rev, Now: h.clock.Now, Logf: h.logs.Logf,
		PrintBanner: func([]string) { t.Error("a second replica printed a banner while the first holds the token lock") }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := second.Start(h.ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	h.clock.Add(61 * time.Minute)
	second.TickTokens(h.ctx)
}

func TestNewSessionEndsThePrevious(t *testing.T) {
	h := newHarness(t)
	ca := newCA(t, "Example Operator CA")
	first := h.startSession()
	second := h.startSession()
	_, err := h.register(first, &fleetv1.BootstrapServiceRegisterOperatorCARequest{CaCertDer: ca.cert.Raw,
		CrlSource:        &fleetv1.BootstrapServiceRegisterOperatorCARequest_None{None: true},
		Acknowledgements: []fleetv1.OperatorCAAcknowledgement{fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_NO_CRL}})
	wantCode(t, err, apperr.CodeSessionInvalid, "")
	if _, err := h.register(second, &fleetv1.BootstrapServiceRegisterOperatorCARequest{CaCertDer: ca.cert.Raw,
		CrlSource:        &fleetv1.BootstrapServiceRegisterOperatorCARequest_None{None: true},
		Acknowledgements: []fleetv1.OperatorCAAcknowledgement{fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_NO_CRL}}); err != nil {
		t.Fatalf("the newest session was refused: %v", err)
	}
}

func TestSession_IdleAndAbsoluteExpiry(t *testing.T) {
	h := newHarness(t)
	ca := newCA(t, "Example Operator CA")
	preview := func(secret string) error {
		_, err := h.register(secret, &fleetv1.BootstrapServiceRegisterOperatorCARequest{CaCertDer: ca.cert.Raw,
			CrlSource:        &fleetv1.BootstrapServiceRegisterOperatorCARequest_None{None: true},
			Acknowledgements: []fleetv1.OperatorCAAcknowledgement{fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_NO_CRL}})
		return err
	}

	idle := h.startSession()
	h.clock.Add(16 * time.Minute)
	wantCode(t, preview(idle), apperr.CodeSessionInvalid, "")

	busy := h.startSession()
	for i := 0; i < 5; i++ {
		h.clock.Add(10 * time.Minute)
		if err := preview(busy); err != nil {
			t.Fatalf("a session in use was refused after %d minutes: %v", (i+1)*10, err)
		}
	}
	h.clock.Add(10 * time.Minute)
	wantCode(t, preview(busy), apperr.CodeSessionInvalid, "")

	if err := preview("fos_bsess_unknown"); err == nil {
		t.Fatal("an unknown session was accepted")
	} else {
		wantCode(t, err, apperr.CodeSessionInvalid, "")
	}
	if err := preview(""); err == nil {
		t.Fatal("a call with no session header was accepted")
	} else {
		wantCode(t, err, apperr.CodeSessionInvalid, "")
	}
}

func TestAfterTheLatch_NoTokensSessionsOrBanner(t *testing.T) {
	h := newHarness(t)
	h.startSession()
	ca := newCA(t, "Example Operator CA")
	admin := ca.leaf(t, leafOpts{})
	h.svc.Latch().Observe(h.ctx, adminIdentity(admin, ca), admin)

	if len(h.st.tokenHashes()) != 0 {
		t.Fatal("tokens survived the latch closing")
	}
	for _, hash := range h.st.sessionHashes() {
		s, _, _ := h.st.BootstrapSession(h.ctx, hash)
		if s.EndedAt.IsZero() {
			t.Fatal("a session survived the latch closing")
		}
	}
	before := h.bannerCount()
	h.clock.Add(2 * time.Hour)
	h.svc.TickTokens(h.ctx)
	if h.bannerCount() != before {
		t.Fatal("a banner was printed after the latch closed")
	}

	restarted, err := New(h.ctx, Options{Store: h.st, Audit: h.audit, Trust: h.trust, Rev: h.rev, Now: h.clock.Now, Logf: h.logs.Logf,
		PrintBanner: func([]string) { t.Error("a restart printed a banner after the latch closed") }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := restarted.Start(h.ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

func TestSecretsNeverInErrorsAuditOrLogs(t *testing.T) {
	h := newHarness(t)
	tok := h.token()
	secret := h.startSession()
	usedTok := tok
	nextTok := h.token()

	// Drive refusals that could echo what was sent.
	_, err1 := h.client().StartBootstrapSession(h.ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: usedTok}))
	_, err2 := h.register(secret+"x", &fleetv1.BootstrapServiceRegisterOperatorCARequest{})
	ca := newCA(t, "Example Operator CA")
	h.registerCA(secret, ca)
	_, err3 := h.submit(secret, &fleetv1.SubmitFirstAdminCertificateRequest{CertDer: []byte("junk"), FullName: "Ada Example"})

	secrets := []string{usedTok, nextTok, secret, strings.TrimPrefix(secret, SessionPrefix)}
	for _, tk := range []string{usedTok, nextTok} {
		c, _ := CanonicalToken(tk)
		secrets = append(secrets, c, strings.TrimPrefix(c, TokenPrefix))
	}
	var haystack strings.Builder
	for _, err := range []error{err1, err2, err3} {
		if err != nil {
			haystack.WriteString(err.Error())
		}
	}
	for _, e := range h.audit.Audit() {
		haystack.WriteString(strings.Join([]string{e.Summary, e.ActorCN, e.ActorSerial, e.KeyID, e.TargetPath, e.RequestDigest}, "|"))
	}
	haystack.WriteString(h.logs.all())
	for _, s := range secrets {
		if strings.Contains(haystack.String(), s) {
			t.Fatalf("a token or session secret leaked into an error, audit row or log line: %q", s)
		}
	}
	// The one place a token may appear is its own banner.
	if !strings.Contains(h.bannerText(), nextTok) {
		t.Fatal("the banner doesn't carry the token")
	}
	if strings.Contains(h.bannerText(), secret) {
		t.Fatal("a banner carries the session secret")
	}
}

func TestStartSession_AuditedWithTheClientAddress(t *testing.T) {
	h := newHarness(t)
	h.startSession()
	rows := h.auditKinds(KindSessionStarted)
	if len(rows) != 1 {
		t.Fatalf("%d %s rows, want 1", len(rows), KindSessionStarted)
	}
	if rows[0].ActorKind != ActorBootstrapSession || !strings.Contains(rows[0].Summary, "192.0.2.10") {
		t.Fatalf("audit row = %+v; want actor %s and the client address", rows[0], ActorBootstrapSession)
	}
	if h.logs.count("bootstrap session started from 192.0.2.10") != 1 {
		t.Error("the session start wasn't logged with the client address")
	}
}

var _ = store.SessionEndedClosed
