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
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"golang.org/x/crypto/ocsp"
)

// The shared acceptance check asks the live revocation decision, OCSP
// included, about a certificate it is shown, so first-admin submission and
// credential recording both refuse what the CA's responder says is revoked
// or unknown.
func TestCheckOperatorCert_AsksTheLiveRevocationDecision(t *testing.T) {
	ca := newCA(t, caOpts{})
	resp := newTestResponder(t, ca, func() time.Time { return testNow })
	f := newOCSPFixture(t, PolicySoft, nil, ocspAnchor(ca, store.CRLSourceNone, store.OCSPModeURL, resp.URL()))

	good := ca.leaf(t, leafOpts{})
	revoked := ca.leaf(t, leafOpts{})
	unknown := ca.leaf(t, leafOpts{})
	resp.set(func(r *testResponder) {
		r.status[SerialKey(revoked.SerialNumber)] = ocsp.Revoked
		r.status[SerialKey(unknown.SerialNumber)] = ocsp.Unknown
	})
	check := CertCheck{Now: testNow, WantLevel: "admin", Revoked: f.rev.IsRevoked, CheckRevocation: f.rev.CheckWebCert}

	if _, err := CheckOperatorCert(good, ca.cert, check); err != nil {
		t.Fatalf("a certificate the responder says is good was refused: %v", err)
	}
	for name, tc := range map[string]struct {
		cert   *x509.Certificate
		reason string
	}{"revoked": {revoked, "REVOKED_OCSP"}, "unknown": {unknown, "OCSP_UNKNOWN"}} {
		_, err := CheckOperatorCert(tc.cert, ca.cert, check)
		code, _ := apperr.Code(err)
		r, _ := apperr.ReasonOf(err)
		if code != apperr.CodeCertRejected || apperr.ReasonName(r) != tc.reason {
			t.Errorf("%s: got %v, want 1610 %s", name, err, tc.reason)
		}
	}
}

func TestCheckOperatorCert_CheckRevocationGetsTheLeafAndAnchor(t *testing.T) {
	ca := newCA(t, caOpts{})
	leaf := ca.leaf(t, leafOpts{})
	refusal := errors.New("refused")
	var gotAnchor string
	var gotLeaf *x509.Certificate
	_, err := CheckOperatorCert(leaf, ca.cert, CertCheck{Now: testNow, CheckRevocation: func(anchor string, l *x509.Certificate) error {
		gotAnchor, gotLeaf = anchor, l
		return refusal
	}})
	if !errors.Is(err, refusal) {
		t.Fatalf("err = %v, want the revocation decision's error as is", err)
	}
	if gotAnchor != Fingerprint(ca.cert) || gotLeaf != leaf {
		t.Fatalf("CheckRevocation got anchor %q and leaf %v", gotAnchor, gotLeaf)
	}
}
