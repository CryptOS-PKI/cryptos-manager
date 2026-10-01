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
	"errors"
	"math/big"
	"testing"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

func anchorFor(ca testCA, crlSource, ocspMode string) Anchor {
	if ocspMode == "" {
		ocspMode = store.OCSPModeOff
	}
	return Anchor{Cert: ca.cert, SHA256: Fingerprint(ca.cert), CRLSource: crlSource, OCSPMode: ocspMode, State: store.OperatorCAActive}
}

type revFixture struct {
	st    *fakeTrust
	clock *fakeClock
	logs  *logSink
	audit *auditSink
	rev   *Revocations
}

func newRevFixture(t *testing.T, policy string, anchors ...Anchor) revFixture {
	t.Helper()
	f := revFixture{st: newFakeTrust(), clock: &fakeClock{t: testNow}, logs: &logSink{}, audit: &auditSink{}}
	f.rev = f.replica(t, policy, anchors...)
	return f
}

// replica is another manager process sharing the fixture's store and clock.
func (f revFixture) replica(t *testing.T, policy string, anchors ...Anchor) *Revocations {
	t.Helper()
	rev := NewRevocations(RevocationOptions{Store: f.st, Policy: policy, Now: f.clock.Now, Logf: f.logs.Logf, Audit: f.audit.Record})
	rev.SetAnchors(anchors)
	if err := rev.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return rev
}

func mustStoreCRL(t *testing.T, rev *Revocations, a Anchor, der []byte) {
	t.Helper()
	if stored, err := rev.StoreCRL(context.Background(), a.SHA256, der, store.CRLSourceUpload); err != nil || !stored {
		t.Fatalf("StoreCRL = %v, %v", stored, err)
	}
}

func TestIsRevoked_IsPerAnchorAndUnionsDenylistAndCRL(t *testing.T) {
	x := newCA(t, caOpts{cn: "Example Operator CA X"})
	y := newCA(t, caOpts{cn: "Example Operator CA Y"})
	ax, ay := anchorFor(x, store.CRLSourceUpload, ""), anchorFor(y, store.CRLSourceNone, "")
	f := newRevFixture(t, PolicySoft, ax, ay)

	if err := f.rev.Deny(context.Background(), store.DenylistEntry{IssuerSHA256: ax.SHA256, SerialHex: "0A:0B", Reason: 4}); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	mustStoreCRL(t, f.rev, ax, x.crl(t, crlOpts{number: big.NewInt(1), revoked: []*big.Int{big.NewInt(0xc0)}}))

	for _, c := range []struct {
		anchor, serial string
		want           bool
	}{
		{ax.SHA256, "a0b", true},  // denylist
		{ax.SHA256, "c0", true},   // CRL
		{ax.SHA256, "d0", false},  // neither
		{ay.SHA256, "a0b", false}, // same serial, other issuer
		{ay.SHA256, "c0", false},
	} {
		if got := f.rev.IsRevoked(c.anchor, c.serial); got != c.want {
			t.Errorf("IsRevoked(%s…, %s) = %v, want %v", c.anchor[:8], c.serial, got, c.want)
		}
	}
}

// A denylist write is enforced on the writing replica at once, bumps the
// epoch, and reaches another replica on its next poll.
func TestDeny_SynchronousHereAndOnePollElsewhere(t *testing.T) {
	x := newCA(t, caOpts{})
	ax := anchorFor(x, store.CRLSourceNone, "")
	f := newRevFixture(t, PolicySoft, ax)
	other := f.replica(t, PolicySoft, ax)
	before, _ := f.st.OperatorTrustVersion(context.Background())

	if err := f.rev.Deny(context.Background(), store.DenylistEntry{IssuerSHA256: ax.SHA256, SerialHex: "1f"}); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if !f.rev.IsRevoked(ax.SHA256, "1f") {
		t.Fatal("the writing replica doesn't enforce its own denylist write")
	}
	after, _ := f.st.OperatorTrustVersion(context.Background())
	if after.Epoch != before.Epoch+1 {
		t.Fatalf("epoch %d -> %d, want a bump", before.Epoch, after.Epoch)
	}
	if other.IsRevoked(ax.SHA256, "1f") {
		t.Fatal("the other replica saw the entry before polling")
	}
	poller := NewPoller(f.st, nil, other, f.logs.Logf)
	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if !other.IsRevoked(ax.SHA256, "1f") {
		t.Fatal("the other replica doesn't enforce the entry after one poll")
	}
}

func TestDeny_NeedsPostgres(t *testing.T) {
	x := newCA(t, caOpts{})
	ax := anchorFor(x, store.CRLSourceNone, "")
	f := newRevFixture(t, PolicySoft, ax)
	f.st.noDB = true
	err := f.rev.Deny(context.Background(), store.DenylistEntry{IssuerSHA256: ax.SHA256, SerialHex: "1f"})
	wantReason(t, err, apperr.CodeUnavailable, fleetv1.ErrorReason_ERROR_REASON_DATABASE_REQUIRED)
}

// Every replica re-verifies stored CRLs against their anchor on load, so a
// database writer can't slip in a CRL the CA didn't sign.
func TestReload_RefusesATamperedStoredCRL(t *testing.T) {
	x := newCA(t, caOpts{})
	rogue := newCA(t, caOpts{cn: "Example Operator CA"})
	ax := anchorFor(x, store.CRLSourceUpload, "")
	f := newRevFixture(t, PolicySoft, ax)
	mustStoreCRL(t, f.rev, ax, x.crl(t, crlOpts{number: big.NewInt(1), revoked: []*big.Int{big.NewInt(0x77)}}))

	f.st.tamperCRL(ax.SHA256, x.crl(t, crlOpts{number: big.NewInt(2), signer: &rogue}))
	other := f.replica(t, PolicySoft, ax)
	if other.IsRevoked(ax.SHA256, "77") {
		t.Fatal("a replica loaded entries from a CRL it should have refused")
	}
	if st := other.Status(ax.SHA256); st.CRLLoaded {
		t.Fatalf("status = %+v, want no CRL loaded", st)
	}
	if f.logs.count("refused the stored CRL") == 0 {
		t.Fatal("the refused CRL was not logged")
	}
}

func TestCheckWeb_StaleCRL(t *testing.T) {
	x := newCA(t, caOpts{})
	crl := x.crl(t, crlOpts{number: big.NewInt(1), revoked: []*big.Int{big.NewInt(0x66)}, nextUpdate: testNow.Add(time.Hour)})

	t.Run("soft keeps the last good CRL, banners, and audits once", func(t *testing.T) {
		ax := anchorFor(x, store.CRLSourceURL, "")
		f := newRevFixture(t, PolicySoft, ax)
		mustStoreCRL(t, f.rev, ax, crl)
		f.clock.Add(2 * time.Hour)

		if err := f.rev.CheckWeb(ax.SHA256, "1"); err != nil {
			t.Fatalf("CheckWeb(good serial) = %v, want allowed in soft mode", err)
		}
		wantReason(t, f.rev.CheckWeb(ax.SHA256, "66"), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED)
		_ = f.rev.CheckWeb(ax.SHA256, "1")
		if got := f.audit.kinds(KindCRLExpired); got != 1 {
			t.Fatalf("operator-crl-expired audited %d times, want once", got)
		}
		if st := f.rev.Status(ax.SHA256); st.Banner == "" || st.CRLFresh {
			t.Fatalf("status = %+v, want a banner and a stale CRL", st)
		}
		if n := f.logs.count("past nextUpdate"); n != 1 {
			t.Fatalf("stale CRL logged %d times in the same hour, want 1", n)
		}
		f.clock.Add(61 * time.Minute)
		_ = f.rev.CheckWeb(ax.SHA256, "1")
		if n := f.logs.count("past nextUpdate"); n != 2 {
			t.Fatalf("stale CRL logged %d times after an hour, want 2", n)
		}
	})

	t.Run("hard refuses the anchor", func(t *testing.T) {
		ax := anchorFor(x, store.CRLSourceURL, "")
		f := newRevFixture(t, PolicyHard, ax)
		mustStoreCRL(t, f.rev, ax, crl)
		if err := f.rev.CheckWeb(ax.SHA256, "1"); err != nil {
			t.Fatalf("CheckWeb with a fresh CRL = %v", err)
		}
		f.clock.Add(2 * time.Hour)
		wantReason(t, f.rev.CheckWeb(ax.SHA256, "1"), apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_STALE_CRL)
	})
}

// A CRL source that has never produced a CRL, for example an unreachable URL
// at start-up, is enforced like an expired one.
func TestCheckWeb_CRLNotYetLoaded(t *testing.T) {
	x := newCA(t, caOpts{})
	ax := anchorFor(x, store.CRLSourceURL, "")

	soft := newRevFixture(t, PolicySoft, ax)
	if err := soft.rev.CheckWeb(ax.SHA256, "1"); err != nil {
		t.Fatalf("soft: CheckWeb = %v, want the denylist only", err)
	}
	if soft.logs.count("CRL NOT YET ENFORCED") == 0 {
		t.Fatal("soft: no NOT YET ENFORCED warning")
	}

	hard := newRevFixture(t, PolicyHard, ax)
	wantReason(t, hard.rev.CheckWeb(ax.SHA256, "1"), apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_STALE_CRL)
}

func TestCheckWeb_NoCRLSource(t *testing.T) {
	x := newCA(t, caOpts{})
	for _, c := range []struct {
		ocsp, badge string
	}{
		{store.OCSPModeOff, BadgeNotObserved},
		{store.OCSPModeAIA, BadgeOCSPOnly},
		{store.OCSPModeURL, BadgeOCSPOnly},
	} {
		ax := anchorFor(x, store.CRLSourceNone, c.ocsp)
		f := newRevFixture(t, PolicyHard, ax)
		if err := f.rev.Deny(context.Background(), store.DenylistEntry{IssuerSHA256: ax.SHA256, SerialHex: "5"}); err != nil {
			t.Fatalf("Deny: %v", err)
		}
		if err := f.rev.CheckWeb(ax.SHA256, "1"); err != nil {
			t.Fatalf("ocsp %s: CheckWeb = %v, want allowed even in hard mode", c.ocsp, err)
		}
		wantReason(t, f.rev.CheckWeb(ax.SHA256, "5"), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED)
		if st := f.rev.Status(ax.SHA256); st.Badge != c.badge {
			t.Fatalf("ocsp %s: badge = %q, want %q", c.ocsp, st.Badge, c.badge)
		}
	}
}

func TestCheckMCP_Freshness(t *testing.T) {
	x := newCA(t, caOpts{})
	crl := x.crl(t, crlOpts{number: big.NewInt(1), revoked: []*big.Int{big.NewInt(0x66)}, nextUpdate: testNow.Add(time.Hour)})

	t.Run("fresh CRL and poll", func(t *testing.T) {
		ax := anchorFor(x, store.CRLSourceURL, "")
		f := newRevFixture(t, PolicySoft, ax)
		mustStoreCRL(t, f.rev, ax, crl)
		if err := f.rev.CheckMCP(ax.SHA256, "1"); err != nil {
			t.Fatalf("CheckMCP = %v", err)
		}
		wantReason(t, f.rev.CheckMCP(ax.SHA256, "66"), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED)
	})
	t.Run("stale CRL fails closed even in soft mode", func(t *testing.T) {
		ax := anchorFor(x, store.CRLSourceURL, "")
		f := newRevFixture(t, PolicySoft, ax)
		mustStoreCRL(t, f.rev, ax, crl)
		f.clock.Add(2 * time.Hour)
		poll := NewPoller(f.st, nil, f.rev, f.logs.Logf)
		_ = poll.PollOnce(context.Background())
		wantReason(t, f.rev.CheckMCP(ax.SHA256, "1"), apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_STALE_CRL)
		if err := f.rev.CheckWeb(ax.SHA256, "1"); err != nil {
			t.Fatalf("the web path in soft mode = %v, want allowed", err)
		}
	})
	t.Run("no CRL source", func(t *testing.T) {
		ax := anchorFor(x, store.CRLSourceNone, store.OCSPModeURL)
		f := newRevFixture(t, PolicySoft, ax)
		wantReason(t, f.rev.CheckMCP(ax.SHA256, "1"), apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_NO_CRL)
	})
	t.Run("denylist poll older than 5 minutes", func(t *testing.T) {
		ax := anchorFor(x, store.CRLSourceURL, "")
		f := newRevFixture(t, PolicySoft, ax)
		mustStoreCRL(t, f.rev, ax, x.crl(t, crlOpts{number: big.NewInt(1)}))
		f.st.failPoll = true
		poll := NewPoller(f.st, nil, f.rev, f.logs.Logf)
		f.clock.Add(4 * time.Minute)
		if err := poll.PollOnce(context.Background()); err == nil {
			t.Fatal("PollOnce succeeded against a failing store")
		}
		if err := f.rev.CheckMCP(ax.SHA256, "1"); err != nil {
			t.Fatalf("CheckMCP 4 minutes after the last good poll = %v", err)
		}
		f.clock.Add(2 * time.Minute)
		wantReason(t, f.rev.CheckMCP(ax.SHA256, "1"), apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_STALE_DENYLIST)
		f.st.failPoll = false
		if err := poll.PollOnce(context.Background()); err != nil {
			t.Fatalf("PollOnce: %v", err)
		}
		if err := f.rev.CheckMCP(ax.SHA256, "1"); err != nil {
			t.Fatalf("CheckMCP after a good poll = %v", err)
		}
	})
	t.Run("unknown anchor", func(t *testing.T) {
		f := newRevFixture(t, PolicySoft)
		if err := f.rev.CheckMCP("nope", "1"); err == nil {
			t.Fatal("CheckMCP for an anchor the manager doesn't trust passed")
		}
	})
}

func TestStoreCRL_AntiRollbackAndVerification(t *testing.T) {
	x := newCA(t, caOpts{})
	other := newCA(t, caOpts{cn: "Example Other CA"})
	ax := anchorFor(x, store.CRLSourceUpload, "")
	f := newRevFixture(t, PolicySoft, ax)
	ctx := context.Background()

	mustStoreCRL(t, f.rev, ax, x.crl(t, crlOpts{number: big.NewInt(5)}))
	_, err := f.rev.StoreCRL(ctx, ax.SHA256, x.crl(t, crlOpts{number: big.NewInt(4)}), store.CRLSourceUpload)
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_ROLLBACK)
	_, err = f.rev.StoreCRL(ctx, ax.SHA256, other.crl(t, crlOpts{number: big.NewInt(9)}), store.CRLSourceUpload)
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_INVALID)
	if _, err := f.rev.StoreCRL(ctx, "unknown", x.crl(t, crlOpts{number: big.NewInt(9)}), store.CRLSourceUpload); !errors.Is(err, ErrUnknownAnchor) {
		t.Fatalf("StoreCRL(unknown anchor) = %v, want ErrUnknownAnchor", err)
	}
}
