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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
)

// The test PKI. Every name is a fake: example.org, "Example Operator CA".

var (
	oidLevel = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 1}
	testNow  = time.Now().UTC().Truncate(time.Second)

	serialMu      sync.Mutex
	serialCounter = big.NewInt(0x5000)
)

func nextSerial() *big.Int {
	serialMu.Lock()
	defer serialMu.Unlock()
	serialCounter = new(big.Int).Add(serialCounter, big.NewInt(1))
	return new(big.Int).Set(serialCounter)
}

func p384(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func p256(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newCA(t *testing.T, cn string) testCA {
	t.Helper()
	return newCAWith(t, cn, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, nil)
}

func newCAWith(t *testing.T, cn string, ku x509.KeyUsage, parent *testCA) testCA {
	t.Helper()
	key := p384(t)
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	ski := sha256.Sum256(spki)
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{Organization: []string{"Example"}, CommonName: cn},
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              testNow.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              ku,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski[:20],
	}
	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return testCA{cert: cert, key: key}
}

type leafOpts struct {
	cn       string
	level    string
	key      crypto.Signer
	notAfter time.Time
	critical bool
	ocsp     []string
}

func (ca testCA) leaf(t *testing.T, o leafOpts) *x509.Certificate {
	t.Helper()
	if o.cn == "" {
		o.cn = "admin@example.org"
	}
	if o.level == "" {
		o.level = "admin"
	}
	if o.key == nil {
		o.key = p384(t)
	}
	if o.notAfter.IsZero() {
		o.notAfter = testNow.Add(365 * 24 * time.Hour)
	}
	_, lvl, err := authz.MarshalLevelExtension(o.level)
	if err != nil {
		t.Fatalf("level extension: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: o.cn},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              o.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: oidLevel, Critical: o.critical, Value: lvl}},
		OCSPServer:            o.ocsp,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, o.key.Public(), ca.key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

func csrDER(t *testing.T, key crypto.Signer, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der
}

func (ca testCA) crl(t *testing.T, number int64, revoked ...*big.Int) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: testNow.Add(-time.Hour)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                testNow.Add(-time.Hour),
		NextUpdate:                testNow.Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, ca.cert, ca.key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return der
}
