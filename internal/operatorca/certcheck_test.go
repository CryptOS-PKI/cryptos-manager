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
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
)

func TestCheckOperatorCert_AcceptsTheProfile(t *testing.T) {
	ca := newCA(t, caOpts{})
	for name, kind := range map[string]keyKind{"P-384": keyP384, "RSA-3072": keyRSA3072} {
		t.Run(name, func(t *testing.T) {
			key := newKey(t, kind)
			leaf := ca.leaf(t, leafOpts{cn: "Admin@Example.org", key: key})
			res, err := CheckOperatorCert(leaf, ca.cert, CertCheck{
				Now: testNow, WantLevel: "admin", CSR: csrFor(t, key, "Admin@Example.org", false),
			})
			if err != nil {
				t.Fatalf("CheckOperatorCert = %v", err)
			}
			if res.Level != authz.LevelAdmin || res.Email != "admin@example.org" || len(res.Warnings) != 0 {
				t.Fatalf("result = %+v", res)
			}
		})
	}
}

func TestCheckOperatorCert_Rejections(t *testing.T) {
	ca := newCA(t, caOpts{})
	other := newCA(t, caOpts{cn: "Example Other CA"})
	csrKey := newKey(t, keyP384)
	revokedSerial := big.NewInt(0xdead)

	cases := map[string]struct {
		leaf   *x509.Certificate
		check  CertCheck
		reason fleetv1.ErrorReason
	}{
		"signed by another CA": {
			leaf:   other.leaf(t, leafOpts{}),
			reason: fleetv1.ErrorReason_ERROR_REASON_NOT_CHAINED,
		},
		"expired": {
			leaf:   ca.leaf(t, leafOpts{notBefore: testNow.Add(-48 * time.Hour), notAfter: testNow.Add(-time.Hour)}),
			reason: fleetv1.ErrorReason_ERROR_REASON_NOT_CHAINED,
		},
		"critical level extension": {
			leaf:   ca.leaf(t, leafOpts{levelCritical: true}),
			reason: fleetv1.ErrorReason_ERROR_REASON_LEVEL_EXT_CRITICAL,
		},
		"wrong level": {
			leaf:   ca.leaf(t, leafOpts{level: "viewer"}),
			reason: fleetv1.ErrorReason_ERROR_REASON_WRONG_LEVEL,
		},
		"no level extension": {
			leaf:   ca.leaf(t, leafOpts{level: "-"}),
			reason: fleetv1.ErrorReason_ERROR_REASON_WRONG_LEVEL,
		},
		"no EKU": {
			leaf:   ca.leaf(t, leafOpts{noEKU: true}),
			reason: fleetv1.ErrorReason_ERROR_REASON_EKU,
		},
		"extra EKU": {
			leaf:   ca.leaf(t, leafOpts{eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}),
			reason: fleetv1.ErrorReason_ERROR_REASON_EKU,
		},
		"key usage with keyCertSign": {
			leaf:   ca.leaf(t, leafOpts{keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}),
			reason: fleetv1.ErrorReason_ERROR_REASON_KEY_USAGE,
		},
		"key usage without digitalSignature": {
			leaf:   ca.leaf(t, leafOpts{keyUsage: x509.KeyUsageKeyEncipherment}),
			reason: fleetv1.ErrorReason_ERROR_REASON_KEY_USAGE,
		},
		"basicConstraints absent": {
			leaf:   ca.leaf(t, leafOpts{noBC: true}),
			reason: fleetv1.ErrorReason_ERROR_REASON_BASIC_CONSTRAINTS,
		},
		"CA:TRUE": {
			leaf:   ca.leaf(t, leafOpts{isCA: true, keyUsage: x509.KeyUsageDigitalSignature}),
			reason: fleetv1.ErrorReason_ERROR_REASON_BASIC_CONSTRAINTS,
		},
		"subject with an extra RDN": {
			leaf:   ca.leaf(t, leafOpts{extraRDN: true}),
			reason: fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH,
		},
		"CN that isn't an email": {
			leaf:   ca.leaf(t, leafOpts{cn: "Admin User"}),
			reason: fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH,
		},
		"CN with a display name": {
			leaf:   ca.leaf(t, leafOpts{cn: "Admin <admin@example.org>"}),
			reason: fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH,
		},
		"P-256 key": {
			leaf:   ca.leaf(t, leafOpts{keyKind: keyP256}),
			reason: fleetv1.ErrorReason_ERROR_REASON_KEY_TYPE,
		},
		"key differs from the CSR": {
			leaf:   ca.leaf(t, leafOpts{}),
			check:  CertCheck{CSR: csrFor(t, csrKey, "admin@example.org", false)},
			reason: fleetv1.ErrorReason_ERROR_REASON_KEY_MISMATCH,
		},
		"under a day left": {
			leaf:   ca.leaf(t, leafOpts{notAfter: testNow.Add(23 * time.Hour)}),
			reason: fleetv1.ErrorReason_ERROR_REASON_EXPIRING,
		},
		"denylisted or in the CRL": {
			leaf: ca.leaf(t, leafOpts{serial: revokedSerial}),
			check: CertCheck{Revoked: func(anchor, serial string) bool {
				return anchor == Fingerprint(ca.cert) && serial == "dead"
			}},
			reason: fleetv1.ErrorReason_ERROR_REASON_REVOKED,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			c.check.Now = testNow
			c.check.WantLevel = "admin"
			_, err := CheckOperatorCert(c.leaf, ca.cert, c.check)
			wantReason(t, err, apperr.CodeCertRejected, c.reason)
		})
	}
}

func TestCheckOperatorCert_WarnsOverFourHundredDays(t *testing.T) {
	ca := newCA(t, caOpts{})
	leaf := ca.leaf(t, leafOpts{notAfter: testNow.Add(401 * 24 * time.Hour)})
	res, err := CheckOperatorCert(leaf, ca.cert, CertCheck{Now: testNow, WantLevel: "admin"})
	if err != nil {
		t.Fatalf("CheckOperatorCert = %v", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "400 days") {
		t.Fatalf("warnings = %q, want one about the 400-day validity", res.Warnings)
	}
}

// With no wanted level the check reads the level from the certificate.
func TestCheckOperatorCert_ReadsTheLevelWhenNoneIsWanted(t *testing.T) {
	ca := newCA(t, caOpts{})
	res, err := CheckOperatorCert(ca.leaf(t, leafOpts{level: "operator"}), ca.cert, CertCheck{Now: testNow})
	if err != nil || res.Level != authz.LevelOperator {
		t.Fatalf("CheckOperatorCert = %+v, %v; want level operator", res, err)
	}
}

func TestCheckCSR(t *testing.T) {
	good := newKey(t, keyP384)
	if res, err := CheckCSR(csrFor(t, good, "Holder@Example.org", false).Raw); err != nil || res.Email != "holder@example.org" {
		t.Fatalf("CheckCSR(good) = %+v, %v", res, err)
	}

	tampered := csrFor(t, good, "holder@example.org", false)
	raw := append([]byte{}, tampered.Raw...)
	raw[len(raw)-3] ^= 0xff

	cases := map[string]struct {
		der    []byte
		reason fleetv1.ErrorReason
	}{
		"over 4 KiB":    {der: make([]byte, 4<<10+1), reason: fleetv1.ErrorReason_ERROR_REASON_SIZE},
		"bad signature": {der: raw, reason: fleetv1.ErrorReason_ERROR_REASON_SIGNATURE},
		"extra RDN":     {der: csrFor(t, good, "holder@example.org", true).Raw, reason: fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH},
		"not an email":  {der: csrFor(t, good, "holder", false).Raw, reason: fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH},
		"P-256":         {der: csrFor(t, newKey(t, keyP256), "holder@example.org", false).Raw, reason: fleetv1.ErrorReason_ERROR_REASON_KEY_TYPE},
		"RSA-2048":      {der: csrFor(t, newKey(t, keyRSA2048), "holder@example.org", false).Raw, reason: fleetv1.ErrorReason_ERROR_REASON_KEY_TYPE},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := CheckCSR(c.der)
			wantReason(t, err, apperr.CodeCSRRejected, c.reason)
		})
	}
}

func TestEmailFromCN_Bounds(t *testing.T) {
	long := strings.Repeat("a", 250) + "@example.org"
	if _, err := emailFromSubject(pkix.Name{CommonName: long}.ToRDNSequence()); err == nil {
		t.Fatal("a 262-character email was accepted")
	}
}

// Certificates made with the documented OpenSSL recipe carry exactly the
// level encoding the manager reads, and pass the full profile check.
func TestOpenSSLRecipe_MatchesTheLevelEncoding(t *testing.T) {
	ca := readFixtureCert(t, "ca.crt")
	for _, level := range []string{"admin", "operator", "viewer"} {
		t.Run(level, func(t *testing.T) {
			leaf := readFixtureCert(t, level+".crt")
			_, want, err := authz.MarshalLevelExtension(level)
			if err != nil {
				t.Fatalf("MarshalLevelExtension: %v", err)
			}
			var found bool
			for _, ext := range leaf.Extensions {
				if ext.Id.Equal(oidLevel) {
					found = true
					if ext.Critical || string(ext.Value) != string(want) {
						t.Fatalf("level extension = %x (critical %v), want %x non-critical", ext.Value, ext.Critical, want)
					}
				}
			}
			if !found {
				t.Fatal("no level extension in the OpenSSL fixture")
			}
			if _, err := CheckOperatorCert(leaf, ca, CertCheck{Now: leaf.NotBefore.Add(time.Hour), WantLevel: level}); err != nil {
				t.Fatalf("CheckOperatorCert(OpenSSL %s) = %v", level, err)
			}
		})
	}
}

func readFixtureCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "openssl", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("fixture %s is not PEM", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return cert
}
