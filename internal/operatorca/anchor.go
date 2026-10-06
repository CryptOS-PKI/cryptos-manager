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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
)

// Bounds on what an operator CA upload may be.
const (
	MaxCertSize       = 8 << 10
	minAnchorValidity = 30 * 24 * time.Hour
	minRSABits        = 3072
)

// Fingerprint is how the manager names a certificate everywhere: the
// lowercase hex SHA-256 of its DER, with no separators.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// ColonFingerprint is the SHA-256 in the upper-case, colon-separated form
// browsers and openssl show, for log lines an operator compares by eye.
func ColonFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	const digits = "0123456789ABCDEF"
	out := make([]byte, 0, len(sum)*3)
	for i, b := range sum {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

// AnchorOptions carries what ValidateAnchor checks an operator CA against.
type AnchorOptions struct {
	Now time.Time
	// NodeCAs are the CryptOS node CA certificates the manager knows: the
	// inventory's CA certificates and the chains nodes report.
	NodeCAs []*x509.Certificate
	// CRLSource is set when a CRL will be verified against the anchor, which
	// then needs cRLSign.
	CRLSource bool
}

func rejectAnchor(reason fleetv1.ErrorReason, format string, args ...any) error {
	return apperr.Reasoned(apperr.CodeOperatorCARejected, reason, fmt.Errorf("operatorca: "+format, args...))
}

// ParseAnchorUpload reads an uploaded operator CA certificate: DER or PEM,
// at most MaxCertSize bytes, exactly one certificate.
func ParseAnchorUpload(b []byte) (*x509.Certificate, error) {
	cert, err := parseSingleCert(b)
	if err != nil {
		return nil, apperr.Coded(apperr.CodeOperatorCARejected, err)
	}
	return cert, nil
}

func parseSingleCert(b []byte) (*x509.Certificate, error) {
	if len(b) == 0 {
		return nil, errors.New("operatorca: no certificate")
	}
	if len(b) > MaxCertSize {
		return nil, fmt.Errorf("operatorca: the upload is %d bytes, more than the %d allowed", len(b), MaxCertSize)
	}
	der := b
	if block, rest := pem.Decode(b); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("operatorca: PEM block is %q, not CERTIFICATE", block.Type)
		}
		if next, _ := pem.Decode(rest); next != nil {
			return nil, errors.New("operatorca: more than one PEM block; upload exactly one certificate")
		}
		der = block.Bytes
	}
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, fmt.Errorf("operatorca: parse certificate: %w", err)
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("operatorca: %d certificates; upload exactly one", len(certs))
	}
	return certs[0], nil
}

// ValidateAnchor checks that cert may be an operator CA: a CA with
// keyCertSign, at least 30 days left, a P-384, P-256 or RSA 3072+ key, not a
// CryptOS node's CA (by certificate or public key), and cRLSign when a CRL
// will be verified against it. It returns warnings for an anchor that is
// allowed but weakens separation, such as one issued by a node's CA.
func ValidateAnchor(cert *x509.Certificate, opts AnchorOptions) ([]string, error) {
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, rejectAnchor(fleetv1.ErrorReason_ERROR_REASON_NOT_A_CA,
			"%s is not a CA certificate with keyCertSign", cert.Subject)
	}
	if cert.NotAfter.Sub(opts.Now) < minAnchorValidity {
		return nil, rejectAnchor(fleetv1.ErrorReason_ERROR_REASON_EXPIRING,
			"%s expires %s, less than 30 days away", cert.Subject, cert.NotAfter.UTC().Format(time.RFC3339))
	}
	if !anchorKeyAllowed(cert) {
		return nil, rejectAnchor(fleetv1.ErrorReason_ERROR_REASON_KEY_TYPE,
			"%s has a %s key; use P-384, P-256 or RSA of 3072 bits or more", cert.Subject, describeKey(cert))
	}
	if node := matchingNodeCA(cert, opts.NodeCAs); node != nil {
		return nil, rejectAnchor(fleetv1.ErrorReason_ERROR_REASON_IS_NODE_CA,
			"%s is the CryptOS node CA %s (same certificate or key); a CryptOS node can't be the operator CA", cert.Subject, node.Subject)
	}
	if opts.CRLSource && cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, rejectAnchor(fleetv1.ErrorReason_ERROR_REASON_CRL_SIGN_MISSING,
			"%s has no cRLSign key usage, so no CRL can be verified against it", cert.Subject)
	}

	var warnings []string
	for _, node := range opts.NodeCAs {
		if cert.CheckSignatureFrom(node) == nil {
			warnings = append(warnings, fmt.Sprintf(
				"the operator CA was issued by the CryptOS node CA %s: relying parties that trust that CA for client authentication would also accept operator certificates",
				node.Subject))
		}
	}
	return warnings, nil
}

// CheckNotNodeCA refuses any config-file anchor that is a CryptOS node's CA,
// by certificate or public key. It is the start-up check for the file source.
func CheckNotNodeCA(anchors, nodeCAs []*x509.Certificate) error {
	for _, a := range anchors {
		if node := matchingNodeCA(a, nodeCAs); node != nil {
			return rejectAnchor(fleetv1.ErrorReason_ERROR_REASON_IS_NODE_CA,
				"operator CA %s (SHA-256 %s) is the CryptOS node CA %s (same certificate or key); a CryptOS node can't be the operator CA",
				a.Subject, Fingerprint(a), node.Subject)
		}
	}
	return nil
}

// NodeCAWarning reports a registered operator CA that now matches a CryptOS
// node's CA, by certificate or key -- something ValidateAnchor and
// CheckNotNodeCA only catch at registration time, before a matching node
// existed or was linked. Empty when there's no match.
func NodeCAWarning(cert *x509.Certificate, nodeCAs []*x509.Certificate) string {
	node := matchingNodeCA(cert, nodeCAs)
	if node == nil {
		return ""
	}
	return fmt.Sprintf(
		"this operator CA is the CryptOS node CA %s (same certificate or key); a CryptOS node can't be the operator CA",
		node.Subject)
}

func matchingNodeCA(cert *x509.Certificate, nodeCAs []*x509.Certificate) *x509.Certificate {
	for _, n := range nodeCAs {
		if bytes.Equal(n.Raw, cert.Raw) || bytes.Equal(n.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
			return n
		}
	}
	return nil
}

func anchorKeyAllowed(cert *x509.Certificate) bool {
	switch k := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P384() || k.Curve == elliptic.P256()
	case *rsa.PublicKey:
		return k.N.BitLen() >= minRSABits
	default:
		return false
	}
}

func describeKey(cert *x509.Certificate) string {
	switch k := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}
