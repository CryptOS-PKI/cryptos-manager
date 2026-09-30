package operatorca

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
	"math/big"
	"sync"
	"testing"
	"time"

	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/store"
	"golang.org/x/crypto/ocsp"
)

func allowed(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s = %v, want allowed", what, err)
	}
}

// OCSP revoked and unknown refuse; unknown is audited once per cache
// period; good never overrides the denylist or the CRL.
func TestCheckWebCert_OCSPStatus(t *testing.T) {
	ca := newCA(t, caOpts{})
	f := newOCSPFixture(t, PolicySoft, nil)
	clock := f.clock
	r := newTestResponder(t, ca, clock.Now)
	a := ocspAnchor(ca, store.CRLSourceURL, store.OCSPModeURL, r.URL())
	f.rev.SetAnchors([]Anchor{a})
	mustStoreCRL(t, f.rev, a, ca.crl(t, crlOpts{revoked: []*big.Int{big.NewInt(0x66)}}))

	revokedLeaf := ca.leaf(t, leafOpts{serial: big.NewInt(0x100)})
	unknownLeaf := ca.leaf(t, leafOpts{serial: big.NewInt(0x101)})
	goodLeaf := ca.leaf(t, leafOpts{serial: big.NewInt(0x102)})
	crlListed := ca.leaf(t, leafOpts{serial: big.NewInt(0x66)})
	r.set(func(r *testResponder) {
		r.status["100"] = ocsp.Revoked
		r.status["101"] = ocsp.Unknown
	})

	wantReason(t, f.rev.CheckWebCert(a.SHA256, revokedLeaf), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED_OCSP)
	wantReason(t, f.rev.CheckWebCert(a.SHA256, unknownLeaf), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNKNOWN)
	wantReason(t, f.rev.CheckWebCert(a.SHA256, unknownLeaf), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNKNOWN)
	if n := f.audit.kinds(KindOCSPUnknown); n != 1 {
		t.Fatalf("%s audited %d times in one cache period, want 1", KindOCSPUnknown, n)
	}
	clock.Add(31 * time.Minute)
	wantReason(t, f.rev.CheckWebCert(a.SHA256, unknownLeaf), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNKNOWN)
	if n := f.audit.kinds(KindOCSPUnknown); n != 2 {
		t.Fatalf("%s audited %d times over two cache periods, want 2", KindOCSPUnknown, n)
	}

	allowed(t, f.rev.CheckWebCert(a.SHA256, goodLeaf), "good")
	if err := f.rev.Deny(context.Background(), store.DenylistEntry{IssuerSHA256: a.SHA256, SerialHex: "102"}); err != nil {
		t.Fatal(err)
	}
	wantReason(t, f.rev.CheckWebCert(a.SHA256, goodLeaf), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED)
	wantReason(t, f.rev.CheckWebCert(a.SHA256, crlListed), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED)
}

// The responder comes from the anchor's mode: aia reads the leaf, url the
// anchor, off nothing.
func TestCheckWebCert_ResponderSource(t *testing.T) {
	ca := newCA(t, caOpts{})
	clock := &fakeClock{t: testNow}
	aiaResp := newTestResponder(t, ca, clock.Now)
	urlResp := newTestResponder(t, ca, clock.Now)
	withAIA := ca.leaf(t, leafOpts{ocspServer: []string{aiaResp.URL()}})
	noAIA := ca.leaf(t, leafOpts{})

	f := newOCSPFixture(t, PolicyHard, nil, ocspAnchor(ca, store.CRLSourceNone, store.OCSPModeAIA, ""))
	sha := Fingerprint(ca.cert)
	allowed(t, f.rev.CheckWebCert(sha, withAIA), "aia with a URI")
	if aiaResp.count() != 1 {
		t.Fatalf("aia: the leaf's responder got %d requests, want 1", aiaResp.count())
	}
	allowed(t, f.rev.CheckWebCert(sha, noAIA), "aia leaf without a URI")
	if aiaResp.count() != 1 || urlResp.count() != 0 {
		t.Fatalf("aia leaf without a URI sent a request")
	}

	f = newOCSPFixture(t, PolicyHard, nil, ocspAnchor(ca, store.CRLSourceNone, store.OCSPModeURL, urlResp.URL()))
	allowed(t, f.rev.CheckWebCert(sha, withAIA), "url")
	if urlResp.count() != 1 || aiaResp.count() != 1 {
		t.Fatalf("url: anchor responder %d, leaf responder %d requests; want 1 and unchanged", urlResp.count(), aiaResp.count())
	}

	f = newOCSPFixture(t, PolicyHard, nil, ocspAnchor(ca, store.CRLSourceNone, store.OCSPModeOff, urlResp.URL()))
	allowed(t, f.rev.CheckWebCert(sha, withAIA), "off")
	if urlResp.count() != 1 || aiaResp.count() != 1 {
		t.Fatal("off sent a request")
	}
}

// The AIA URI is read only after the leaf chains to a trusted anchor.
func TestPeerAuthorizer_NoAIAFromAnUnchainedLeaf(t *testing.T) {
	st := newFakeTrust()
	ca := liveCA(t, "Example Operator CA")
	rogue := liveCA(t, "Example Rogue CA")
	resp := newTestResponder(t, ca, time.Now)
	row := registeredRow(ca, store.OperatorCAActive)
	row.OCSPMode = store.OCSPModeAIA
	if err := st.AddOperatorCA(t.Context(), row); err != nil {
		t.Fatal(err)
	}
	rev := NewRevocations(RevocationOptions{Store: st, Policy: PolicySoft, OCSPFetcher: NewOCSPFetcher()})
	base, _ := serverTLS(t)
	trust, err := NewTrustStore(t.Context(), registered(), st, rev, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth := PeerAuthorizer{Trust: trust, Rev: rev}

	bad := liveLeaf(t, rogue, leafOpts{ocspServer: []string{resp.URL()}})
	if _, err := auth.AuthorizePeer(bad.Leaf, nil); err == nil {
		t.Fatal("a leaf from an untrusted CA was authorized")
	}
	if resp.count() != 0 {
		t.Fatalf("the AIA URI of an unchained leaf got %d requests", resp.count())
	}
	good := liveLeaf(t, ca, leafOpts{ocspServer: []string{resp.URL()}})
	if _, err := auth.AuthorizePeer(good.Leaf, nil); err != nil {
		t.Fatalf("AuthorizePeer = %v", err)
	}
	if resp.count() != 1 {
		t.Fatalf("the trusted leaf's AIA responder got %d requests, want 1", resp.count())
	}
}

// No fresh OCSP response falls back to a fresh CRL, whatever the policy.
func TestCheckWebCert_FallbackToTheCRL(t *testing.T) {
	ca := newCA(t, caOpts{})
	other := newCA(t, caOpts{cn: "Example Other CA"})
	for name, broken := range map[string]func(r *testResponder){
		"unreachable": func(r *testResponder) { r.down = true },
		"invalid":     func(r *testResponder) { r.wrongKey = &other },
	} {
		t.Run(name, func(t *testing.T) {
			r := newTestResponder(t, ca, func() time.Time { return testNow })
			r.set(broken)
			a := ocspAnchor(ca, store.CRLSourceURL, store.OCSPModeURL, r.URL())
			f := newOCSPFixture(t, PolicyHard, nil, a)
			mustStoreCRL(t, f.rev, a, ca.crl(t, crlOpts{revoked: []*big.Int{big.NewInt(0x66)}}))
			allowed(t, f.rev.CheckWebCert(a.SHA256, ca.leaf(t, leafOpts{serial: big.NewInt(0x200)})), "fresh CRL, no OCSP")
			wantReason(t, f.rev.CheckWebCert(a.SHA256, ca.leaf(t, leafOpts{serial: big.NewInt(0x66)})), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED)
		})
	}
}

// No fresh OCSP response and no CRL: soft allows with a banner, an hourly
// log line and one audit row per outage; hard refuses with STALE_OCSP.
func TestCheckWebCert_NoOCSPNoCRL(t *testing.T) {
	ca := newCA(t, caOpts{})
	leaf := ca.leaf(t, leafOpts{serial: big.NewInt(0x300)})

	t.Run("soft", func(t *testing.T) {
		f := newOCSPFixture(t, PolicySoft, nil)
		r := newTestResponder(t, ca, f.clock.Now)
		a := ocspAnchor(ca, store.CRLSourceNone, store.OCSPModeURL, r.URL())
		f.rev.SetAnchors([]Anchor{a})
		r.set(func(r *testResponder) { r.down = true })

		allowed(t, f.rev.CheckWebCert(a.SHA256, leaf), "soft, responder down")
		if st := f.rev.Status(a.SHA256); st.OCSPBanner == "" {
			t.Fatal("no OCSP banner during the outage")
		}
		for range 3 {
			f.clock.Add(time.Minute)
			allowed(t, f.rev.CheckWebCert(a.SHA256, leaf), "soft, responder down")
		}
		if n := f.logs.count("OCSP responder unreachable"); n != 1 {
			t.Fatalf("outage logged %d times within the hour, want 1", n)
		}
		if n := f.audit.kinds(KindOCSPUnavailable); n != 1 {
			t.Fatalf("%s audited %d times in one outage, want 1", KindOCSPUnavailable, n)
		}
		f.clock.Add(time.Hour)
		allowed(t, f.rev.CheckWebCert(a.SHA256, leaf), "soft, responder down")
		if n := f.logs.count("OCSP responder unreachable"); n != 2 {
			t.Fatalf("outage logged %d times over an hour, want 2", n)
		}

		r.set(func(r *testResponder) { r.down = false })
		f.clock.Add(time.Minute)
		allowed(t, f.rev.CheckWebCert(a.SHA256, leaf), "responder back")
		if st := f.rev.Status(a.SHA256); st.OCSPBanner != "" {
			t.Fatalf("banner %q after the responder came back", st.OCSPBanner)
		}
		r.set(func(r *testResponder) { r.down = true })
		f.clock.Add(2 * time.Hour)
		allowed(t, f.rev.CheckWebCert(a.SHA256, leaf), "second outage")
		if n := f.audit.kinds(KindOCSPUnavailable); n != 2 {
			t.Fatalf("%s audited %d times over two outages, want 2", KindOCSPUnavailable, n)
		}
	})
	t.Run("hard", func(t *testing.T) {
		r := newTestResponder(t, ca, func() time.Time { return testNow })
		r.set(func(r *testResponder) { r.down = true })
		a := ocspAnchor(ca, store.CRLSourceNone, store.OCSPModeURL, r.URL())
		f := newOCSPFixture(t, PolicyHard, nil, a)
		wantReason(t, f.rev.CheckWebCert(a.SHA256, leaf), apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_STALE_OCSP)
	})
}

// Hard with a stale CRL: a fresh OCSP good is current revocation data.
func TestCheckWebCert_HardWithAStaleCRL(t *testing.T) {
	ca := newCA(t, caOpts{})
	f := newOCSPFixture(t, PolicyHard, nil)
	r := newTestResponder(t, ca, f.clock.Now)
	a := ocspAnchor(ca, store.CRLSourceURL, store.OCSPModeAIA, "")
	f.rev.SetAnchors([]Anchor{a})
	mustStoreCRL(t, f.rev, a, ca.crl(t, crlOpts{}))
	f.clock.Add(8 * 24 * time.Hour)

	allowed(t, f.rev.CheckWebCert(a.SHA256, ca.leaf(t, leafOpts{ocspServer: []string{r.URL()}})), "fresh OCSP good")

	down := newTestResponder(t, ca, f.clock.Now)
	down.set(func(r *testResponder) { r.down = true })
	wantReason(t, f.rev.CheckWebCert(a.SHA256, ca.leaf(t, leafOpts{ocspServer: []string{down.URL()}})),
		apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_STALE_OCSP)
	wantReason(t, f.rev.CheckWebCert(a.SHA256, ca.leaf(t, leafOpts{})),
		apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_STALE_CRL)
}

// A denylist write wins over a cached good.
func TestCheckWebCert_DenylistBeatsACachedGood(t *testing.T) {
	ca := newCA(t, caOpts{})
	r := newTestResponder(t, ca, func() time.Time { return testNow })
	a := ocspAnchor(ca, store.CRLSourceNone, store.OCSPModeURL, r.URL())
	f := newOCSPFixture(t, PolicySoft, nil, a)
	leaf := ca.leaf(t, leafOpts{})
	allowed(t, f.rev.CheckWebCert(a.SHA256, leaf), "good")
	if err := f.rev.Deny(context.Background(), store.DenylistEntry{IssuerSHA256: a.SHA256, SerialHex: SerialKey(leaf.SerialNumber)}); err != nil {
		t.Fatal(err)
	}
	wantReason(t, f.rev.CheckWebCert(a.SHA256, leaf), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED)
	if r.count() != 1 {
		t.Fatalf("responder got %d requests, want 1 (cached)", r.count())
	}
}

// MCP needs a fresh CRL; OCSP can only add a refusal there.
func TestCheckMCPCert_OCSP(t *testing.T) {
	ca := newCA(t, caOpts{})
	other := newCA(t, caOpts{cn: "Example Other CA"})
	setup := func(t *testing.T, crl bool, mutate func(r *testResponder)) (ocspFixture, Anchor) {
		t.Helper()
		r := newTestResponder(t, ca, func() time.Time { return testNow })
		if mutate != nil {
			r.set(mutate)
		}
		src := store.CRLSourceNone
		if crl {
			src = store.CRLSourceURL
		}
		a := ocspAnchor(ca, src, store.OCSPModeURL, r.URL())
		f := newOCSPFixture(t, PolicySoft, nil, a)
		if crl {
			mustStoreCRL(t, f.rev, a, ca.crl(t, crlOpts{}))
		}
		return f, a
	}
	leaf := ca.leaf(t, leafOpts{serial: big.NewInt(0x400)})

	for name, mutate := range map[string]func(r *testResponder){
		"responder down":   func(r *testResponder) { r.down = true },
		"invalid response": func(r *testResponder) { r.wrongKey = &other },
		"good":             nil,
	} {
		f, a := setup(t, true, mutate)
		allowed(t, f.rev.CheckMCPCert(a.SHA256, leaf), "fresh CRL, "+name)
	}
	f, a := setup(t, true, func(r *testResponder) { r.status["400"] = ocsp.Revoked })
	wantReason(t, f.rev.CheckMCPCert(a.SHA256, leaf), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED_OCSP)
	f, a = setup(t, true, func(r *testResponder) { r.status["400"] = ocsp.Unknown })
	wantReason(t, f.rev.CheckMCPCert(a.SHA256, leaf), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNKNOWN)

	f, a = setup(t, false, nil)
	wantReason(t, f.rev.CheckMCPCert(a.SHA256, leaf), apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_NO_CRL)

	f, a = setup(t, true, nil)
	f.clock.Add(8 * 24 * time.Hour)
	_ = f.rev.Reload(t.Context())
	wantReason(t, f.rev.CheckMCPCert(a.SHA256, leaf), apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_STALE_CRL)
}

// The cache lives min(nextUpdate, 1 h), 5 minutes without nextUpdate, and
// 30 s for a failure; an entry in use is refreshed at half its life.
func TestOCSPCache_TTL(t *testing.T) {
	ca := newCA(t, caOpts{})
	a := anchorFor(ca, store.CRLSourceNone, store.OCSPModeURL)
	clock := &fakeClock{t: testNow}
	r := newTestResponder(t, ca, clock.Now)
	bg := &bgRunner{}
	c := NewOCSPClient(OCSPOptions{Fetch: NewOCSPFetcher(), Now: clock.Now, Background: bg.Go})

	for name, tc := range map[string]struct {
		set  func(r *testResponder)
		want time.Duration
	}{
		"nextUpdate in 30 min": {func(r *testResponder) { r.next, r.noNext = 30*time.Minute, false }, 30 * time.Minute},
		"nextUpdate in 3 h":    {func(r *testResponder) { r.next, r.noNext = 3*time.Hour, false }, time.Hour},
		"no nextUpdate":        {func(r *testResponder) { r.noNext = true }, 5 * time.Minute},
	} {
		r.set(tc.set)
		serial := nextSerial()
		if _, err := c.Check(a, serial, r.URL(), notRevoked); err != nil {
			t.Fatalf("%s: Check = %v", name, err)
		}
		e, ok := c.cached(a.SHA256, serial)
		if !ok {
			t.Fatalf("%s: nothing cached", name)
		}
		if got := e.expires.Sub(clock.Now()); got < tc.want-time.Second || got > tc.want+time.Second {
			t.Fatalf("%s: cached for %s, want %s", name, got, tc.want)
		}
	}

	r.set(func(r *testResponder) { r.next, r.noNext = 30*time.Minute+time.Minute, false })
	serial := nextSerial()
	if _, err := c.Check(a, serial, r.URL(), notRevoked); err != nil {
		t.Fatal(err)
	}
	base := r.count()
	clock.Add(14 * time.Minute)
	if _, err := c.Check(a, serial, r.URL(), notRevoked); err != nil {
		t.Fatal(err)
	}
	bg.wait()
	if r.count() != base {
		t.Fatalf("refreshed before half the TTL")
	}
	clock.Add(2 * time.Minute)
	if _, err := c.Check(a, serial, r.URL(), notRevoked); err != nil {
		t.Fatal(err)
	}
	bg.wait()
	if r.count() != base+1 {
		t.Fatalf("an entry in use past half its TTL: %d requests, want %d", r.count(), base+1)
	}
	clock.Add(2 * time.Hour)
	if r.count() != base+1 {
		t.Fatal("an idle entry was fetched")
	}
	if _, ok := c.cached(a.SHA256, serial); ok {
		t.Fatal("an idle entry outlived its TTL")
	}

	r.set(func(r *testResponder) { r.down = true })
	serial = nextSerial()
	_, err := c.Check(a, serial, r.URL(), notRevoked)
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE)
	base = r.count()
	clock.Add(29 * time.Second)
	_, err = c.Check(a, serial, r.URL(), notRevoked)
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE)
	if r.count() != base {
		t.Fatal("a failed fetch was retried within 30 s")
	}
	clock.Add(2 * time.Second)
	_, _ = c.Check(a, serial, r.URL(), notRevoked)
	if r.count() != base+1 {
		t.Fatal("a failed fetch wasn't retried after 30 s")
	}
}

// Concurrent requests for one uncached certificate share one fetch.
func TestOCSPCache_SingleFlight(t *testing.T) {
	ca := newCA(t, caOpts{})
	a := anchorFor(ca, store.CRLSourceNone, store.OCSPModeURL)
	r := newTestResponder(t, ca, func() time.Time { return testNow })
	gate := make(chan struct{})
	r.set(func(r *testResponder) { r.gate = gate })
	c := NewOCSPClient(OCSPOptions{Fetch: NewOCSPFetcher(), Now: func() time.Time { return testNow }})

	run := func(serials ...*big.Int) {
		var wg sync.WaitGroup
		started := make(chan struct{}, 50)
		for i := range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				started <- struct{}{}
				if _, err := c.Check(a, serials[i%len(serials)], r.URL(), notRevoked); err != nil {
					t.Errorf("Check = %v", err)
				}
			}()
		}
		for range 50 {
			<-started
		}
		time.Sleep(100 * time.Millisecond)
		close(gate)
		wg.Wait()
	}
	run(big.NewInt(0x500))
	if r.count() != 1 {
		t.Fatalf("50 concurrent checks of one cert made %d requests, want 1", r.count())
	}
	gate = make(chan struct{})
	r.set(func(r *testResponder) { r.gate = gate })
	run(big.NewInt(0x501), big.NewInt(0x502))
	if r.count() != 3 {
		t.Fatalf("two serials made %d more requests, want 2", r.count()-1)
	}
}
