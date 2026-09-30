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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/store"
)

func TestVerifyCRL_AcceptsACRLTheAnchorSigned(t *testing.T) {
	ca := newCA(t, caOpts{})
	der := ca.crl(t, crlOpts{revoked: []*big.Int{big.NewInt(0x1f), big.NewInt(0x2a)}, number: big.NewInt(7)})
	pemCRL := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})

	for name, in := range map[string][]byte{"DER": der, "PEM": pemCRL} {
		v, err := VerifyCRL(in, ca.cert, testNow)
		if err != nil {
			t.Fatalf("%s: VerifyCRL = %v", name, err)
		}
		if !v.IsRevoked("1f") || !v.IsRevoked("2a") || v.IsRevoked("3b") {
			t.Fatalf("%s: revoked set = %v", name, v.Revoked)
		}
		if v.Number == nil || v.Number.Int64() != 7 || string(v.DER) != string(der) {
			t.Fatalf("%s: number %v, DER kept %v", name, v.Number, string(v.DER) == string(der))
		}
	}
}

// A CRL the documented OpenSSL recipe publishes verifies, and lists the
// certificate it revoked.
func TestVerifyCRL_OpenSSLRecipe(t *testing.T) {
	ca := readFixtureCert(t, "ca.crt")
	viewer := readFixtureCert(t, "viewer.crt")
	b, err := os.ReadFile(filepath.Join("testdata", "openssl", "operator.crl.pem"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	v, err := VerifyCRL(b, ca, viewer.NotBefore.Add(time.Hour))
	if err != nil {
		t.Fatalf("VerifyCRL(OpenSSL) = %v", err)
	}
	if !v.IsRevoked(SerialKey(viewer.SerialNumber)) {
		t.Fatal("the revoked viewer certificate is not in the verified set")
	}
}

func TestVerifyCRL_Rejections(t *testing.T) {
	ca := newCA(t, caOpts{})
	other := newCA(t, caOpts{cn: "Example Other CA"})
	otherName := pkix.Name{CommonName: "Example Somebody Else"}
	caOnly := idpExtension(t, true, issuingDistributionPoint{OnlyContainsCACerts: true})
	someReasons := idpExtension(t, true, issuingDistributionPoint{OnlySomeReasons: asn1.BitString{Bytes: []byte{0x40}, BitLength: 2}})
	indirectIDP := idpExtension(t, true, issuingDistributionPoint{IndirectCRL: true})
	certIssuer := pkix.Extension{Id: oidCertIssuer, Critical: true, Value: []byte{0x30, 0x00}}
	openSSLCAOnly, err := os.ReadFile(filepath.Join("testdata", "openssl", "ca-only.crl.pem"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	fixtureCA := readFixtureCert(t, "ca.crt")

	cases := map[string]struct {
		der    []byte
		anchor *testCA
		now    time.Time
	}{
		"wrong signer":             {der: ca.crl(t, crlOpts{signer: &other})},
		"issuer name mismatch":     {der: ca.crl(t, crlOpts{issuerName: &otherName})},
		"no nextUpdate":            {der: ca.crl(t, crlOpts{noNext: true})},
		"thisUpdate in the future": {der: ca.crl(t, crlOpts{thisUpdate: testNow.Add(10 * time.Minute)})},
		"delta CRL": {der: ca.crl(t, crlOpts{extensions: []pkix.Extension{
			{Id: oidDeltaCRL, Critical: true, Value: []byte{0x02, 0x01, 0x05}},
		}})},
		"indirect CRL entry":         {der: ca.crl(t, crlOpts{revoked: []*big.Int{big.NewInt(1)}, entryExt: []pkix.Extension{certIssuer}})},
		"indirect CRL IDP":           {der: ca.crl(t, crlOpts{extensions: []pkix.Extension{indirectIDP}})},
		"IDP limited to CA certs":    {der: ca.crl(t, crlOpts{extensions: []pkix.Extension{caOnly}})},
		"IDP limited to reasons":     {der: ca.crl(t, crlOpts{extensions: []pkix.Extension{someReasons}})},
		"unknown critical ext":       {der: ca.crl(t, crlOpts{extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0x00}}}})},
		"unknown critical entry ext": {der: ca.crl(t, crlOpts{revoked: []*big.Int{big.NewInt(1)}, entryExt: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0x00}}}})},
		"garbage":                    {der: []byte("not a CRL")},
		"over 4 MiB":                 {der: make([]byte, MaxCRLSize+1)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyCRL(c.der, ca.cert, testNow)
			wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_INVALID)
		})
	}
	t.Run("OpenSSL IDP limited to CA certs", func(t *testing.T) {
		_, err := VerifyCRL(openSSLCAOnly, fixtureCA, fixtureCA.NotBefore.Add(time.Hour))
		if err == nil || !strings.Contains(err.Error(), "only CA") {
			t.Fatalf("VerifyCRL(OpenSSL CA-only) = %v, want the IDP scope refusal", err)
		}
		wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_INVALID)
	})
}

// An IDP that only names where the CRL lives, or limits it to end-entity
// certificates, is fine: operator certificates are end-entity certificates.
func TestVerifyCRL_AcceptsAUserCertIDP(t *testing.T) {
	ca := newCA(t, caOpts{})
	der := ca.crl(t, crlOpts{extensions: []pkix.Extension{idpExtension(t, true, issuingDistributionPoint{OnlyContainsUserCerts: true})}})
	if _, err := VerifyCRL(der, ca.cert, testNow); err != nil {
		t.Fatalf("VerifyCRL = %v", err)
	}
}

func TestAcceptNewer_AntiRollback(t *testing.T) {
	ca := newCA(t, caOpts{})
	verify := func(o crlOpts) *VerifiedCRL {
		t.Helper()
		v, err := VerifyCRL(ca.crl(t, o), ca.cert, testNow)
		if err != nil {
			t.Fatalf("VerifyCRL: %v", err)
		}
		return v
	}
	asStored := func(v *VerifiedCRL) store.OperatorCRL {
		return store.OperatorCRL{DER: v.DER, Number: v.Number, ThisUpdate: v.List.ThisUpdate}
	}

	n5 := verify(crlOpts{number: big.NewInt(5)})
	n6 := verify(crlOpts{number: big.NewInt(6)})
	n4 := verify(crlOpts{number: big.NewInt(4)})
	n5other := verify(crlOpts{number: big.NewInt(5), revoked: []*big.Int{big.NewInt(9)}})

	if ok, err := AcceptNewer(store.OperatorCRL{}, false, n5); !ok || err != nil {
		t.Fatalf("first CRL = %v, %v; want stored", ok, err)
	}
	if ok, err := AcceptNewer(asStored(n5), true, n6); !ok || err != nil {
		t.Fatalf("higher number = %v, %v; want stored", ok, err)
	}
	if ok, err := AcceptNewer(asStored(n5), true, n5); ok || err != nil {
		t.Fatalf("same number, same bytes = %v, %v; want a no-op", ok, err)
	}
	_, err := AcceptNewer(asStored(n5), true, n4)
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_ROLLBACK)
	_, err = AcceptNewer(asStored(n5), true, n5other)
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_ROLLBACK)

	older := verify(crlOpts{thisUpdate: testNow.Add(-2 * time.Hour)})
	newer := verify(crlOpts{thisUpdate: testNow.Add(-time.Hour)})
	if ok, err := AcceptNewer(asStored(older), true, newer); !ok || err != nil {
		t.Fatalf("no number, newer thisUpdate = %v, %v; want stored", ok, err)
	}
	if ok, err := AcceptNewer(asStored(newer), true, newer); ok || err != nil {
		t.Fatalf("no number, same bytes = %v, %v; want a no-op", ok, err)
	}
	sameTime := verify(crlOpts{thisUpdate: testNow.Add(-time.Hour), revoked: []*big.Int{big.NewInt(3)}})
	_, err = AcceptNewer(asStored(newer), true, sameTime)
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_ROLLBACK)
	_, err = AcceptNewer(asStored(newer), true, older)
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_ROLLBACK)
}
