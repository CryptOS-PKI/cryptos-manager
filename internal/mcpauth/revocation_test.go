package mcpauth

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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/memory"
)

// fakeChecker answers CheckMCP from a table keyed by anchor fingerprint.
type fakeChecker struct {
	errs       map[string]error
	gotAnchor  string
	gotSerial  string
	callsCount int
}

func (f *fakeChecker) CheckMCP(anchor, serial string) error {
	f.gotAnchor, f.gotSerial = anchor, serial
	f.callsCount++
	return f.errs[anchor]
}

func fp(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// The resolver re-validates against the pool trusted now, so a key minted
// under a CA registered after start works without a restart.
func TestResolve_UsesTheLivePool(t *testing.T) {
	first, second := newTestCA(t, "Operator CA One"), newTestCA(t, "Operator CA Two")
	st := memory.New(nil)
	current := first.pool()
	r := &Resolver{Store: st, Roots: func() *x509.CertPool { return current }, Revoked: &fakeChecker{}}

	plain, _ := mintFor(t, st, second.validOperator(t, 0x42, authz.LevelOperator), "")
	if _, err := r.Resolve(context.Background(), plain); !errors.Is(err, ErrCertUntrusted) {
		t.Fatalf("Resolve before the CA is trusted = %v, want ErrCertUntrusted", err)
	}
	current = second.pool()
	if _, err := r.Resolve(context.Background(), plain); err != nil {
		t.Fatalf("Resolve after the CA is trusted = %v", err)
	}
}

// Every call runs the MCP revocation rules for the bound certificate's
// operator CA: a revoked certificate, and stale or missing revocation data,
// each refuse the key.
func TestResolve_RunsTheMCPRevocationRules(t *testing.T) {
	ca := newTestCA(t, "Operator CA")
	cases := map[string]struct {
		err  error
		want error
	}{
		"denylisted":     {apperr.Reasoned(apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED, errors.New("denylisted")), ErrCertRevoked},
		"stale CRL":      {apperr.Reasoned(apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_STALE_CRL, errors.New("stale")), ErrRevocationStale},
		"stale denylist": {apperr.Reasoned(apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_STALE_DENYLIST, errors.New("stale")), ErrRevocationStale},
		"no CRL":         {apperr.Reasoned(apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_NO_CRL, errors.New("no CRL")), ErrRevocationStale},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			st := memory.New(nil)
			cert := ca.validOperator(t, 0x0abc, authz.LevelOperator)
			plain, _ := mintFor(t, st, cert, "")
			checker := &fakeChecker{errs: map[string]error{fp(ca.cert): c.err}}
			r := &Resolver{Store: st, Roots: ca.pool, Revoked: checker}

			_, err := r.Resolve(context.Background(), plain)
			if !errors.Is(err, c.want) {
				t.Fatalf("Resolve = %v, want %v", err, c.want)
			}
			if checker.gotAnchor != fp(ca.cert) || checker.gotSerial != "abc" {
				t.Fatalf("checked anchor %q serial %q, want the CA's fingerprint and abc", checker.gotAnchor, checker.gotSerial)
			}
			if reason, ok := apperr.ReasonOf(err); !ok || reason == fleetv1.ErrorReason_ERROR_REASON_UNSPECIFIED {
				t.Fatalf("the refusal lost its sub-reason: %v", err)
			}
		})
	}
}

// A certificate that can't hold an MCP key is refused before a key exists,
// rather than minting a key that can never be used.
func TestMint_RefusesACertificateTheAdmissionCheckRefuses(t *testing.T) {
	ca := newTestCA(t, "Operator CA")
	st := memory.New(nil)
	cert := ca.validOperator(t, 9, authz.LevelOperator)
	owner, _ := authz.IdentityFromCertificate(cert)
	noCRL := apperr.Reasoned(apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_NO_CRL, errors.New("no CRL source"))
	keys := &Keys{Store: st, Admit: func(der []byte) error {
		if string(der) != string(cert.Raw) {
			t.Error("Admit got another certificate")
		}
		return noCRL
	}}

	_, _, err := keys.Mint(context.Background(), owner, cert.Raw, "laptop", "", "")
	if !errors.Is(err, ErrNotAdmitted) {
		t.Fatalf("Mint = %v, want ErrNotAdmitted", err)
	}
	if code, _ := apperr.Code(err); code != apperr.CodeNoRevocationSource {
		t.Fatalf("code = %d, want 1608", code)
	}
	if len(st.McpKeys()) != 0 {
		t.Fatal("a key was stored for a refused certificate")
	}
}

// certChecker also takes the whole certificate, which the OCSP check needs
// for the responder URI in the certificate's authorityInfoAccess.
type certChecker struct {
	fakeChecker
	gotCert *x509.Certificate
}

func (c *certChecker) CheckMCPCert(anchor string, cert *x509.Certificate) error {
	c.gotAnchor, c.gotCert = anchor, cert
	c.callsCount++
	return c.errs[anchor]
}

// A checker that takes the certificate gets the bound certificate itself.
func TestResolve_PassesTheCertificateToACertChecker(t *testing.T) {
	ca := newTestCA(t, "Operator CA")
	st := memory.New(nil)
	cert := ca.validOperator(t, 0x0abd, authz.LevelOperator)
	plain, _ := mintFor(t, st, cert, "")
	revokedOCSP := apperr.Reasoned(apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED_OCSP, errors.New("revoked"))
	checker := &certChecker{fakeChecker: fakeChecker{errs: map[string]error{fp(ca.cert): revokedOCSP}}}
	r := &Resolver{Store: st, Roots: ca.pool, Revoked: checker}

	_, err := r.Resolve(context.Background(), plain)
	if !errors.Is(err, ErrCertRevoked) {
		t.Fatalf("Resolve = %v, want ErrCertRevoked", err)
	}
	if checker.gotCert == nil || !checker.gotCert.Equal(cert) || checker.gotAnchor != fp(ca.cert) {
		t.Fatalf("CheckMCPCert got anchor %q cert %v, want the bound certificate", checker.gotAnchor, checker.gotCert)
	}
	if checker.gotSerial != "" {
		t.Fatal("the serial-only CheckMCP was called as well")
	}
}
