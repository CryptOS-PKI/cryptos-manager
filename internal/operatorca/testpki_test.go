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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/authz"
)

// The test PKI. Every name is a fake: example.org, "Example Operator CA".

var (
	oidLevel          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 1}
	testNow           = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	testSerialCounter = big.NewInt(0x1000)
)

type keyKind int

const (
	keyP384 keyKind = iota
	keyP256
	keyRSA3072
	keyRSA2048
)

func newKey(t *testing.T, k keyKind) crypto.Signer {
	t.Helper()
	var (
		key crypto.Signer
		err error
	)
	switch k {
	case keyP384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case keyP256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case keyRSA3072:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case keyRSA2048:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func nextSerial() *big.Int {
	testSerialCounter = new(big.Int).Add(testSerialCounter, big.NewInt(1))
	return new(big.Int).Set(testSerialCounter)
}

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

type caOpts struct {
	cn        string
	keyUsage  x509.KeyUsage
	notAfter  time.Time
	notBefore time.Time
	key       crypto.Signer
	keyKind   keyKind
	parent    *testCA
	notCA     bool
}

func newCA(t *testing.T, o caOpts) testCA {
	t.Helper()
	if o.cn == "" {
		o.cn = "Example Operator CA"
	}
	if o.keyUsage == 0 {
		o.keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if o.notBefore.IsZero() {
		o.notBefore = testNow.Add(-24 * time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = testNow.Add(10 * 365 * 24 * time.Hour)
	}
	key := o.key
	if key == nil {
		key = newKey(t, o.keyKind)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	ski := sha256.Sum256(spki)
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{Organization: []string{"Example"}, CommonName: o.cn},
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		KeyUsage:              o.keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  !o.notCA,
		MaxPathLenZero:        !o.notCA,
		SubjectKeyId:          ski[:20],
	}
	parentCert, parentKey := tmpl, key
	if o.parent != nil {
		parentCert, parentKey = o.parent.cert, o.parent.key
		tmpl.MaxPathLenZero = false
		tmpl.MaxPathLen = 0
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("create CA %q: %v", o.cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return testCA{cert: cert, key: key}
}

type leafOpts struct {
	cn             string
	extraRDN       bool
	level          string // "" means admin; "-" means no level extension
	levelCritical  bool
	eku            []x509.ExtKeyUsage
	noEKU          bool
	keyUsage       x509.KeyUsage
	noBC           bool
	isCA           bool
	key            crypto.Signer
	keyKind        keyKind
	notBefore      time.Time
	notAfter       time.Time
	serial         *big.Int
	ocspServer     []string
	extraExtension *pkix.Extension
}

func (ca testCA) leaf(t *testing.T, o leafOpts) *x509.Certificate {
	t.Helper()
	if o.cn == "" {
		o.cn = "admin@example.org"
	}
	if o.level == "" {
		o.level = "admin"
	}
	if o.keyUsage == 0 {
		o.keyUsage = x509.KeyUsageDigitalSignature
	}
	if o.eku == nil && !o.noEKU {
		o.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if o.notBefore.IsZero() {
		o.notBefore = testNow.Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = testNow.Add(365 * 24 * time.Hour)
	}
	if o.serial == nil {
		o.serial = nextSerial()
	}
	key := o.key
	if key == nil {
		key = newKey(t, o.keyKind)
	}
	subject := pkix.Name{CommonName: o.cn}
	if o.extraRDN {
		subject.Organization = []string{"Example"}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          o.serial,
		Subject:               subject,
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		KeyUsage:              o.keyUsage,
		ExtKeyUsage:           o.eku,
		BasicConstraintsValid: !o.noBC,
		IsCA:                  o.isCA,
		OCSPServer:            o.ocspServer,
	}
	if o.level != "-" {
		_, der, err := authz.MarshalLevelExtension(o.level)
		if err != nil {
			t.Fatalf("level extension: %v", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidLevel, Critical: o.levelCritical, Value: der})
	}
	if o.extraExtension != nil {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, *o.extraExtension)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

// csrFor builds a CSR for key with the given subject CN.
func csrFor(t *testing.T, key crypto.Signer, cn string, extraRDN bool) *x509.CertificateRequest {
	t.Helper()
	subject := pkix.Name{CommonName: cn}
	if extraRDN {
		subject.Organization = []string{"Example"}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}
