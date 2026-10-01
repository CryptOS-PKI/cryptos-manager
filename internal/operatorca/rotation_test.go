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
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"golang.org/x/crypto/ocsp"
)

// The registration probe reports who signed the answer, so the Operator CAs
// page can show the responder certificate an admin is about to rely on.
func TestOCSPProbeResult_ReportsTheSigner(t *testing.T) {
	ca := newCA(t, caOpts{})
	clock := &fakeClock{t: testNow}
	c := NewOCSPClient(OCSPOptions{Fetch: NewOCSPFetcher(), Now: clock.Now})
	r := newTestResponder(t, ca, clock.Now)
	r.set(func(r *testResponder) { r.defaultStatus = ocsp.Unknown })

	res, err := c.ProbeResult(t.Context(), ca.cert, r.URL())
	if err != nil {
		t.Fatalf("ProbeResult = %v", err)
	}
	if res.Status != OCSPUnknown || res.Signer == nil || !res.Signer.Equal(ca.cert) {
		t.Fatalf("ProbeResult = %+v, want unknown signed by the CA", res)
	}

	delegate := ca.delegated(t, delegatedOpts{noCheck: true})
	r.set(func(r *testResponder) { r.delegate = &delegate })
	res, err = c.ProbeResult(t.Context(), ca.cert, r.URL())
	if err != nil {
		t.Fatalf("ProbeResult with a delegated signer = %v", err)
	}
	if res.Signer == nil || !res.Signer.Equal(delegate.cert) {
		t.Fatalf("signer = %v, want the delegated responder", res.Signer)
	}
}

// Each replica remembers the last OCSP failure per operator CA for the
// Operator CAs page, and forgets it once the responder answers again or the
// CA's OCSP settings are cleared.
func TestOCSPClient_LastErrorPerAnchor(t *testing.T) {
	ca := newCA(t, caOpts{})
	clock := &fakeClock{t: testNow}
	c := NewOCSPClient(OCSPOptions{Fetch: NewOCSPFetcher(), Now: clock.Now})
	r := newTestResponder(t, ca, clock.Now)
	a := ocspAnchor(ca, store.CRLSourceNone, store.OCSPModeURL, r.URL())

	r.set(func(r *testResponder) { r.down = true })
	if _, err := c.Check(a, big.NewInt(7), r.URL(), notRevoked); err == nil {
		t.Fatal("Check against a down responder succeeded")
	}
	if got := c.LastError(a.SHA256); !strings.Contains(got, "OCSP_UNREACHABLE") {
		t.Fatalf("LastError = %q, want the OCSP_UNREACHABLE class", got)
	}
	if got := c.LastError("other"); got != "" {
		t.Fatalf("LastError(other) = %q, want empty", got)
	}

	r.set(func(r *testResponder) { r.down = false })
	if _, err := c.Check(a, big.NewInt(8), r.URL(), notRevoked); err != nil {
		t.Fatalf("Check = %v", err)
	}
	if got := c.LastError(a.SHA256); got != "" {
		t.Fatalf("LastError after a good answer = %q, want empty", got)
	}

	r.set(func(r *testResponder) { r.down = true })
	_, _ = c.Check(a, big.NewInt(9), r.URL(), notRevoked)
	c.ClearAnchor(a.SHA256)
	if got := c.LastError(a.SHA256); got != "" {
		t.Fatalf("LastError after ClearAnchor = %q, want empty", got)
	}
}

// When an operator CA's OCSP settings change, every replica drops the
// answers it cached for that CA as soon as it installs the new settings, so
// the old responder's answers aren't used for up to an hour.
func TestSetAnchors_ClearsCachedOCSPWhenTheSettingsChange(t *testing.T) {
	ca := newCA(t, caOpts{})
	other := newCA(t, caOpts{cn: "Example Other Operator CA"})
	r := newTestResponder(t, ca, func() time.Time { return testNow })
	r2 := newTestResponder(t, other, func() time.Time { return testNow })
	a := ocspAnchor(ca, store.CRLSourceNone, store.OCSPModeURL, r.URL())
	b := ocspAnchor(other, store.CRLSourceNone, store.OCSPModeURL, r2.URL())
	f := newOCSPFixture(t, PolicySoft, nil, a, b)
	leaf := ca.leaf(t, leafOpts{})
	otherLeaf := other.leaf(t, leafOpts{})

	check := func() {
		t.Helper()
		if err := f.rev.CheckWebCert(a.SHA256, leaf); err != nil {
			t.Fatalf("CheckWebCert = %v", err)
		}
		if err := f.rev.CheckWebCert(b.SHA256, otherLeaf); err != nil {
			t.Fatalf("CheckWebCert(other) = %v", err)
		}
	}
	check()
	if r.count() != 1 || r2.count() != 1 {
		t.Fatalf("requests = %d, %d; want one each", r.count(), r2.count())
	}

	f.rev.SetAnchors([]Anchor{a, b})
	check()
	if r.count() != 1 || r2.count() != 1 {
		t.Fatalf("requests after unchanged settings = %d, %d; want the cache used", r.count(), r2.count())
	}

	moved := a
	moved.OCSPURL = r.URL() + "/"
	f.rev.SetAnchors([]Anchor{moved, b})
	if err := f.rev.CheckWebCert(a.SHA256, leaf); err != nil {
		t.Fatalf("CheckWebCert after the change = %v", err)
	}
	if err := f.rev.CheckWebCert(b.SHA256, otherLeaf); err != nil {
		t.Fatalf("CheckWebCert(other) after the change = %v", err)
	}
	if r.count() != 2 {
		t.Fatalf("requests to the changed CA's responder = %d, want a fresh fetch", r.count())
	}
	if r2.count() != 1 {
		t.Fatalf("requests to the unchanged CA's responder = %d, want its cache kept", r2.count())
	}
}
