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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
)

// Bounds on an operator certificate and its CSR.
const (
	MaxCSRSize          = 4 << 10
	maxEmailLength      = 254
	minLeafValidity     = 24 * time.Hour
	warnLeafValidity    = 400 * 24 * time.Hour
	accessLevelOIDValue = authz.AccessLevelOID
)

var (
	oidCommonName  = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidAccessLevel = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 1}
)

// CertCheck is what CheckOperatorCert checks a certificate against.
type CertCheck struct {
	Now time.Time
	// WantLevel is the level the certificate must carry; empty accepts any
	// level and reports it.
	WantLevel string
	// CSR, when set, must carry the certificate's public key.
	CSR *x509.CertificateRequest
	// Revoked reports whether the anchor's denylist or CRL lists the serial.
	Revoked func(anchorSHA256, serial string) bool
	// CheckRevocation, when set, is the live revocation decision for the
	// certificate (Revocations.CheckWebCert): the denylist and CRL, the CA's
	// OCSP responder where one is configured, and operatorRevocationPolicy.
	// Its refusal is returned as is.
	CheckRevocation func(anchorSHA256 string, leaf *x509.Certificate) error
}

// CertResult is what a certificate that passed the check carries.
type CertResult struct {
	Level    authz.Level
	Email    string
	Serial   string
	Warnings []string
}

func rejectCert(reason fleetv1.ErrorReason, format string, args ...any) error {
	return apperr.Reasoned(apperr.CodeCertRejected, reason, fmt.Errorf("operatorca: "+format, args...))
}

// CheckOperatorCert is the one check of the operator certificate profile,
// used wherever the manager accepts an operator certificate it is shown
// rather than one a TLS handshake verified. The certificate must verify
// against anchor alone for client auth, carry the level extension
// non-critical, have EKU exactly clientAuth, key usage digitalSignature
// without certificate or CRL signing, basicConstraints CA:FALSE, subject
// exactly CN=<email>, a P-384 or RSA 3072+ key, at least a day left, and not
// be revoked: by the denylist or CRL through Revoked, and by the live
// decision, OCSP included, through CheckRevocation. More than 400 days of
// validity is a warning.
func CheckOperatorCert(cert, anchor *x509.Certificate, c CertCheck) (CertResult, error) {
	levelExt, hasLevel := findExtension(cert, oidAccessLevel)
	if hasLevel && levelExt.Critical {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_LEVEL_EXT_CRITICAL,
			"the level extension %s is marked critical, so TLS verification would refuse the certificate", accessLevelOIDValue)
	}

	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: c.Now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_NOT_CHAINED,
			"the certificate doesn't verify against %s for client authentication: %v", anchor.Subject, err)
	}

	if !hasLevel {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_WRONG_LEVEL, "the certificate has no level extension")
	}
	level, err := authz.LevelFromCertificate(cert)
	if err != nil {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_WRONG_LEVEL, "the level extension doesn't decode: %v", err)
	}
	if c.WantLevel != "" && level.Token() != c.WantLevel {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_WRONG_LEVEL,
			"the certificate carries level %s, want %s", level.Token(), c.WantLevel)
	}

	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_EKU, "extended key usage must be exactly clientAuth")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_KEY_USAGE,
			"key usage must include digitalSignature and exclude keyCertSign and cRLSign")
	}
	if !cert.BasicConstraintsValid || cert.IsCA {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_BASIC_CONSTRAINTS, "basicConstraints must be present with CA:FALSE")
	}

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(cert.RawSubject, &subject); err != nil {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH, "the subject doesn't decode: %v", err)
	}
	email, err := emailFromSubject(subject)
	if err != nil {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH, "%v", err)
	}

	if !leafKeyAllowed(cert.PublicKey) {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_KEY_TYPE,
			"the certificate has a %s key; operator certificates need P-384 or RSA of 3072 bits or more", describeKey(cert))
	}
	if c.CSR != nil && !bytes.Equal(c.CSR.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_KEY_MISMATCH, "the certificate's public key isn't the CSR's")
	}
	if cert.NotAfter.Sub(c.Now) < minLeafValidity {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_EXPIRING,
			"the certificate expires %s, less than a day away", cert.NotAfter.UTC().Format(time.RFC3339))
	}

	serial := SerialKey(cert.SerialNumber)
	if c.Revoked != nil && c.Revoked(Fingerprint(anchor), serial) {
		return CertResult{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_REVOKED,
			"serial %s under %s is on the denylist or in the CRL", serial, anchor.Subject)
	}
	if c.CheckRevocation != nil {
		if err := c.CheckRevocation(Fingerprint(anchor), cert); err != nil {
			return CertResult{}, err
		}
	}

	res := CertResult{Level: level, Email: email, Serial: serial}
	if cert.NotAfter.Sub(cert.NotBefore) > warnLeafValidity {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"the certificate is valid for %d days, more than the recommended 400 days",
			int(cert.NotAfter.Sub(cert.NotBefore).Hours()/24)))
	}
	return res, nil
}

// CSRResult is what a CSR that passed CheckCSR carries.
type CSRResult struct {
	CSR   *x509.CertificateRequest
	Email string
}

func rejectCSR(reason fleetv1.ErrorReason, format string, args ...any) error {
	return apperr.Reasoned(apperr.CodeCSRRejected, reason, fmt.Errorf("operatorca: "+format, args...))
}

// CheckCSR checks a CSR for an operator credential: at most 4 KiB, a valid
// signature, subject exactly CN=<email>, and a P-384 or RSA 3072+ key.
func CheckCSR(der []byte) (CSRResult, error) {
	if len(der) > MaxCSRSize {
		return CSRResult{}, rejectCSR(fleetv1.ErrorReason_ERROR_REASON_SIZE, "the CSR is %d bytes, more than %d", len(der), MaxCSRSize)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return CSRResult{}, rejectCSR(fleetv1.ErrorReason_ERROR_REASON_SIGNATURE, "the CSR doesn't parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return CSRResult{}, rejectCSR(fleetv1.ErrorReason_ERROR_REASON_SIGNATURE, "the CSR signature doesn't verify: %v", err)
	}
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(csr.RawSubject, &subject); err != nil {
		return CSRResult{}, rejectCSR(fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH, "the subject doesn't decode: %v", err)
	}
	email, err := emailFromSubject(subject)
	if err != nil {
		return CSRResult{}, rejectCSR(fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH, "%v", err)
	}
	if !leafKeyAllowed(csr.PublicKey) {
		return CSRResult{}, rejectCSR(fleetv1.ErrorReason_ERROR_REASON_KEY_TYPE, "the CSR key must be P-384 or RSA of 3072 bits or more")
	}
	return CSRResult{CSR: csr, Email: email}, nil
}

// emailFromSubject requires a subject of exactly one RDN, CN=<email>, and
// returns the email lower-cased.
func emailFromSubject(subject pkix.RDNSequence) (string, error) {
	if len(subject) != 1 || len(subject[0]) != 1 || !subject[0][0].Type.Equal(oidCommonName) {
		return "", fmt.Errorf("the subject must be exactly CN=<email>, got %s", subject.String())
	}
	cn, ok := subject[0][0].Value.(string)
	if !ok {
		return "", fmt.Errorf("the CN is not a string")
	}
	if len(cn) > maxEmailLength {
		return "", fmt.Errorf("the CN is %d characters, more than %d", len(cn), maxEmailLength)
	}
	addr, err := mail.ParseAddress(cn)
	if err != nil || addr.Name != "" || addr.Address != cn {
		return "", fmt.Errorf("the CN %q is not a bare email address", cn)
	}
	return strings.ToLower(cn), nil
}

func leafKeyAllowed(pub any) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P384()
	case *rsa.PublicKey:
		return k.N.BitLen() >= minRSABits
	default:
		return false
	}
}

func findExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext, true
		}
	}
	return pkix.Extension{}, false
}

// SerialKey is the form serials are compared and stored in: lowercase hex
// with no separators or leading zeros.
func SerialKey(n *big.Int) string {
	return fmt.Sprintf("%x", n)
}

// NormalizeSerial brings a serial written in any of the usual hex forms
// (upper or lower case, colon-separated, zero-padded) to SerialKey's form.
func NormalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}
