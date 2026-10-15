package main

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
)

// This script holds its own operator CA entirely in memory, for the one run:
// no trust any other party relies on is involved, so there is nothing to
// escrow or hand off. The private key never touches disk; the certificates it
// signs do, briefly, under the run's tmpfs work directory, alongside the
// node admin keys the lab gate already issued.

// generateCA creates a throwaway ECDSA P-384 operator CA, self-signed, valid
// for the run. It is this script's own external operator CA: the manager
// never generates or holds it, matching how a real deployment's operator CA
// always starts outside the manager.
func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating operator CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "cryptos-manager e2e operator CA"},
		NotBefore:    time.Now().Add(-time.Minute),
		// The manager refuses to register an operator CA (1605 EXPIRING) with
		// under 30 days left, even though this script only needs it for the
		// run's own lifetime, so this is comfortably past that floor.
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("self-signing operator CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing operator CA: %w", err)
	}
	return cert, key, nil
}

// generateCSR builds a PKCS#10 request for a fresh ECDSA P-384 key, subject
// CN=commonName, as the manager's operator-credential CSR rules require. It
// returns the request's DER bytes and the private key, which the caller pairs
// with the certificate signCredential later returns.
func generateCSR(commonName string) (csrDER []byte, key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating credential key: %w", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CSR: %w", err)
	}
	return csrDER, key, nil
}

// signCredential signs csrDER under ca/caKey, stamping the access-level
// extension the manager's authz package reads off every operator
// certificate (internal/authz.LevelFromCertificate). level is
// "viewer"|"operator"|"admin". This is this script acting as the holder of
// the operator CA it registered, the same role a real deployment's CA
// operator plays when they sign a requested credential out of band.
func signCredential(ca *x509.Certificate, caKey *ecdsa.PrivateKey, csrDER []byte, level string, validity time.Duration) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	oid, value, err := authz.MarshalLevelExtension(level)
	if err != nil {
		return nil, fmt.Errorf("access-level extension: %w", err)
	}
	levelOID, err := parseOID(oid)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		// The manager refuses an operator certificate (1610 BASIC_CONSTRAINTS)
		// unless basicConstraints is present with CA:FALSE, not merely absent.
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions:       []pkix.Extension{{Id: levelOID, Value: value}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("signing credential: %w", err)
	}
	return der, nil
}

// randomSerial returns a positive 128-bit random certificate serial.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}
	return serial, nil
}

// parseOID parses a dotted-decimal OID string, as authz.AccessLevelOID
// gives it, into an asn1.ObjectIdentifier.
func parseOID(dotted string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(dotted, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("parsing OID %q: %w", dotted, err)
		}
		oid[i] = n
	}
	return oid, nil
}
