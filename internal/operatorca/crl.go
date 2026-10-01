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
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// Bounds on a CRL.
const (
	MaxCRLSize   = 4 << 20
	maxClockSkew = 5 * time.Minute
)

var (
	oidExtAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtCRLNumber      = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtDeltaCRL       = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidExtIDP            = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidExtReasonCode     = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidExtInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}
	oidExtCertIssuer     = asn1.ObjectIdentifier{2, 5, 29, 29}
)

// issuingDistributionPoint is the RFC 5280 section 5.2.5 extension.
type issuingDistributionPoint struct {
	DistributionPoint          asn1.RawValue  `asn1:"optional,tag:0"`
	OnlyContainsUserCerts      bool           `asn1:"optional,tag:1"`
	OnlyContainsCACerts        bool           `asn1:"optional,tag:2"`
	OnlySomeReasons            asn1.BitString `asn1:"optional,tag:3"`
	IndirectCRL                bool           `asn1:"optional,tag:4"`
	OnlyContainsAttributeCerts bool           `asn1:"optional,tag:5"`
}

// VerifiedCRL is a CRL that verified against its anchor, with its revoked
// serials in SerialKey form. Every entry counts, certificateHold included,
// for as long as it is listed.
type VerifiedCRL struct {
	List    *x509.RevocationList
	DER     []byte
	Number  *big.Int
	Revoked map[string]struct{}
}

// IsRevoked reports whether serial (SerialKey form) is listed.
func (v *VerifiedCRL) IsRevoked(serial string) bool {
	_, ok := v.Revoked[serial]
	return ok
}

// Fresh reports whether the CRL is still within its nextUpdate at now.
func (v *VerifiedCRL) Fresh(now time.Time) bool {
	return now.Before(v.List.NextUpdate)
}

func crlInvalid(format string, args ...any) error {
	return apperr.Reasoned(apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_INVALID,
		fmt.Errorf("operatorca: CRL "+format, args...))
}

func crlRollback(format string, args ...any) error {
	return apperr.Reasoned(apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_ROLLBACK,
		fmt.Errorf("operatorca: CRL "+format, args...))
}

// VerifyCRL parses a CRL, PEM or DER and at most MaxCRLSize bytes, and
// verifies it against anchor with the standard library, within the RFC 5280
// section 6.3 scope the manager supports: a complete, direct CRL for
// end-entity certificates, signed by the anchor itself. It refuses a CRL
// with the wrong signer or issuer, no nextUpdate, a thisUpdate more than 5
// minutes ahead, a delta or indirect CRL, an issuing distribution point that
// excludes end-entity certificates or limits reasons, and any unknown
// critical extension.
func VerifyCRL(b []byte, anchor *x509.Certificate, now time.Time) (*VerifiedCRL, error) {
	if len(b) > MaxCRLSize {
		return nil, crlInvalid("is %d bytes, more than %d", len(b), MaxCRLSize)
	}
	der := b
	if block, _ := pem.Decode(b); block != nil {
		if block.Type != "X509 CRL" {
			return nil, crlInvalid("PEM block is %q, not X509 CRL", block.Type)
		}
		der = block.Bytes
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, crlInvalid("doesn't parse: %v", err)
	}
	if err := list.CheckSignatureFrom(anchor); err != nil {
		return nil, crlInvalid("isn't signed by %s: %v", anchor.Subject, err)
	}
	if !bytes.Equal(list.RawIssuer, anchor.RawSubject) {
		return nil, crlInvalid("issuer %s isn't %s", list.Issuer, anchor.Subject)
	}
	if len(list.AuthorityKeyId) > 0 && len(anchor.SubjectKeyId) > 0 && !bytes.Equal(list.AuthorityKeyId, anchor.SubjectKeyId) {
		return nil, crlInvalid("authority key identifier doesn't match %s", anchor.Subject)
	}
	if list.NextUpdate.IsZero() {
		return nil, crlInvalid("has no nextUpdate")
	}
	if list.ThisUpdate.After(now.Add(maxClockSkew)) {
		return nil, crlInvalid("thisUpdate %s is in the future", list.ThisUpdate.UTC().Format(time.RFC3339))
	}
	if err := checkCRLExtensions(list); err != nil {
		return nil, err
	}

	revoked := make(map[string]struct{}, len(list.RevokedCertificateEntries))
	for _, e := range list.RevokedCertificateEntries {
		for _, ext := range e.Extensions {
			if ext.Id.Equal(oidExtCertIssuer) {
				return nil, crlInvalid("is indirect (an entry names a certificate issuer)")
			}
			if ext.Critical && !ext.Id.Equal(oidExtReasonCode) && !ext.Id.Equal(oidExtInvalidityDate) {
				return nil, crlInvalid("entry %s has an unknown critical extension %s", SerialKey(e.SerialNumber), ext.Id)
			}
		}
		revoked[SerialKey(e.SerialNumber)] = struct{}{}
	}

	return &VerifiedCRL{List: list, DER: der, Number: list.Number, Revoked: revoked}, nil
}

func checkCRLExtensions(list *x509.RevocationList) error {
	for _, ext := range list.Extensions {
		switch {
		case ext.Id.Equal(oidExtDeltaCRL):
			return crlInvalid("is a delta CRL")
		case ext.Id.Equal(oidExtIDP):
			var idp issuingDistributionPoint
			rest, err := asn1.Unmarshal(ext.Value, &idp)
			if err != nil || len(rest) != 0 {
				return crlInvalid("issuing distribution point doesn't decode")
			}
			switch {
			case idp.IndirectCRL:
				return crlInvalid("is indirect")
			case idp.OnlyContainsCACerts, idp.OnlyContainsAttributeCerts:
				return crlInvalid("covers only CA or attribute certificates")
			case idp.OnlySomeReasons.BitLength > 0:
				return crlInvalid("covers only some revocation reasons")
			}
		case ext.Id.Equal(oidExtAuthorityKeyID), ext.Id.Equal(oidExtCRLNumber):
		default:
			if ext.Critical {
				return crlInvalid("has an unknown critical extension %s", ext.Id)
			}
		}
	}
	return nil
}

// AcceptNewer is the anti-rollback rule for storing next over the stored
// CRL: a higher cRLNumber is stored; the same number with identical bytes is
// a no-op; anything lower, or the same number with different bytes, is a
// rollback. When either CRL has no cRLNumber, next must have a strictly
// newer thisUpdate instead.
func AcceptNewer(stored store.OperatorCRL, has bool, next *VerifiedCRL) (bool, error) {
	if !has {
		return true, nil
	}
	if bytes.Equal(stored.DER, next.DER) {
		return false, nil
	}
	if stored.Number != nil && next.Number != nil {
		if next.Number.Cmp(stored.Number) > 0 {
			return true, nil
		}
		return false, crlRollback("number %s isn't greater than the stored %s", next.Number, stored.Number)
	}
	if next.List.ThisUpdate.After(stored.ThisUpdate) {
		return true, nil
	}
	return false, crlRollback("thisUpdate %s isn't newer than the stored %s",
		next.List.ThisUpdate.UTC().Format(time.RFC3339), stored.ThisUpdate.UTC().Format(time.RFC3339))
}
