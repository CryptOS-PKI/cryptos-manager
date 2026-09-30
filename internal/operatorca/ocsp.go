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
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6960 CertIDs and key-hash ResponderIDs use SHA-1 as names, not signatures.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"golang.org/x/crypto/ocsp"
)

// Limits and sizes for OCSP (RFC 6960, RFC 8954).
const (
	// MaxOCSPSize caps an OCSP response body.
	MaxOCSPSize   = 64 << 10
	ocspNonceSize = 32
)

var (
	oidOCSPNonce   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	oidOCSPBasic   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidSHA1        = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

// The ASN.1 of RFC 6960 section 4, as far as the manager reads or writes
// it. golang.org/x/crypto/ocsp can't add a request nonce and doesn't expose
// responseExtensions, the CertID issuer hashes or every embedded
// certificate, so those parts are read here with encoding/asn1.

type ocspCertID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type ocspSingleRequest struct {
	Cert ocspCertID
}

type ocspTBSRequest struct {
	Version     int `asn1:"explicit,tag:0,default:0,optional"`
	RequestList []ocspSingleRequest
	Extensions  []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

type ocspRequestASN1 struct {
	TBSRequest ocspTBSRequest
}

type ocspResponseASN1 struct {
	Status   asn1.Enumerated
	Response ocspResponseBytes `asn1:"explicit,tag:0,optional"`
}

type ocspResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspBasicResponse struct {
	TBSResponseData    ocspResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type ocspResponseData struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID     asn1.RawValue
	ProducedAt         time.Time `asn1:"generalized"`
	Responses          []ocspSingleResponse
	ResponseExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type ocspSingleResponse struct {
	CertID           ocspCertID
	CertStatus       asn1.RawValue
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

// OCSPStatus is a certificate status from a validated OCSP response.
type OCSPStatus int

// Certificate statuses.
const (
	OCSPGood OCSPStatus = iota
	OCSPRevoked
	OCSPUnknown
)

func (s OCSPStatus) String() string {
	switch s {
	case OCSPGood:
		return "good"
	case OCSPRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// OCSPResult is a validated response for one certificate.
type OCSPResult struct {
	Status                 OCSPStatus
	ThisUpdate, NextUpdate time.Time
}

func ocspInvalid(format string, args ...any) error {
	return apperr.Reasoned(apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_INVALID,
		fmt.Errorf("operatorca: OCSP response refused: "+format, args...))
}

func ocspUnreachable(format string, args ...any) error {
	return apperr.Reasoned(apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE,
		fmt.Errorf("operatorca: OCSP responder "+format, args...))
}

// ocspQuery is one request for one certificate under an anchor: the DER
// request, carrying a fresh nonce, and what the response must match.
type ocspQuery struct {
	anchor   *x509.Certificate
	serial   *big.Int
	nameHash []byte
	keyHash  []byte
	// nonce is the nonce extension's extnValue as sent.
	nonce []byte
	der   []byte
}

func spkiKeyBytes(c *x509.Certificate) ([]byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("operatorca: parse the public key of %s: %w", c.Subject, err)
	}
	return spki.PublicKey.RightAlign(), nil
}

// newOCSPQuery builds a request for serial under anchor with a SHA-1
// CertID, the hash every responder supports, and a 32-byte nonce
// (RFC 8954).
func newOCSPQuery(anchor *x509.Certificate, serial *big.Int) (*ocspQuery, error) {
	key, err := spkiKeyBytes(anchor)
	if err != nil {
		return nil, err
	}
	nameHash := sha1.Sum(anchor.RawSubject) //nolint:gosec // CertID name hash
	keyHash := sha1.Sum(key)                //nolint:gosec // CertID key hash
	raw := make([]byte, ocspNonceSize)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("operatorca: OCSP nonce: %w", err)
	}
	nonce, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("operatorca: OCSP nonce: %w", err)
	}
	q := &ocspQuery{anchor: anchor, serial: serial, nameHash: nameHash[:], keyHash: keyHash[:], nonce: nonce}
	q.der, err = asn1.Marshal(ocspRequestASN1{TBSRequest: ocspTBSRequest{
		RequestList: []ocspSingleRequest{{Cert: ocspCertID{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA1, Parameters: asn1.NullRawValue},
			NameHash:      q.nameHash, IssuerKeyHash: q.keyHash, SerialNumber: serial,
		}}},
		Extensions: []pkix.Extension{{Id: oidOCSPNonce, Value: nonce}},
	}})
	if err != nil {
		return nil, fmt.Errorf("operatorca: marshal OCSP request: %w", err)
	}
	return q, nil
}

func (q *ocspQuery) matches(id ocspCertID) bool {
	return id.HashAlgorithm.Algorithm.Equal(oidSHA1) && id.SerialNumber != nil && id.SerialNumber.Cmp(q.serial) == 0 &&
		bytes.Equal(id.NameHash, q.nameHash) && bytes.Equal(id.IssuerKeyHash, q.keyHash)
}

// validate checks a response against the query (RFC 6960 sections 3.2 and
// 4.2.2.2): a successful basic response; a signer that is the anchor, or a
// delegated responder issued directly by the anchor with id-kp-OCSPSigning,
// valid now and named by the ResponderID; a single response whose CertID
// matches the request; a thisUpdate at most 5 minutes ahead and a
// nextUpdate not passed; a nonce, if echoed, equal to the one sent; no
// unknown critical extension. A delegated responder without
// id-pkix-ocsp-nocheck must not be revoked by isRevoked (the anchor's
// denylist and CRL; never OCSP, so there is no recursion). Errors never
// carry the response body.
func (q *ocspQuery) validate(der []byte, now time.Time, isRevoked func(serial string) bool) (OCSPResult, error) {
	var outer ocspResponseASN1
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) > 0 {
		return OCSPResult{}, ocspInvalid("the response isn't a DER OCSPResponse")
	}
	if st := ocsp.ResponseStatus(outer.Status); st != ocsp.Success {
		return OCSPResult{}, ocspInvalid("response status %s", st)
	}
	if !outer.Response.ResponseType.Equal(oidOCSPBasic) {
		return OCSPResult{}, ocspInvalid("response type %v isn't id-pkix-ocsp-basic", outer.Response.ResponseType)
	}
	var basic ocspBasicResponse
	if rest, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil || len(rest) > 0 {
		return OCSPResult{}, ocspInvalid("the BasicOCSPResponse doesn't parse")
	}
	tbs := basic.TBSResponseData

	var single *ocspSingleResponse
	for i := range tbs.Responses {
		if q.matches(tbs.Responses[i].CertID) {
			single = &tbs.Responses[i]
			break
		}
	}
	if single == nil {
		return OCSPResult{}, ocspInvalid("no single response matches the requested CertID (hash algorithm, issuer name and key hashes, serial)")
	}
	for _, e := range single.SingleExtensions {
		if e.Critical {
			return OCSPResult{}, ocspInvalid("unknown critical single extension %v", e.Id)
		}
	}
	for _, e := range tbs.ResponseExtensions {
		switch {
		case e.Id.Equal(oidOCSPNonce):
			if !bytes.Equal(e.Value, q.nonce) {
				return OCSPResult{}, ocspInvalid("the echoed nonce doesn't match the request")
			}
		case e.Critical:
			return OCSPResult{}, ocspInvalid("unknown critical response extension %v", e.Id)
		}
	}

	signer, err := q.signer(tbs.RawResponderID, basic.Certificates, now, isRevoked)
	if err != nil {
		return OCSPResult{}, err
	}
	resp, err := ocsp.ParseResponseForCert(der, &x509.Certificate{SerialNumber: q.serial}, nil)
	if err != nil {
		return OCSPResult{}, ocspInvalid("parse: %v", parseErrorClass(err))
	}
	if err := resp.CheckSignatureFrom(signer); err != nil {
		return OCSPResult{}, ocspInvalid("bad signature from %s", signer.Subject)
	}

	if single.ThisUpdate.After(now.Add(maxClockSkew)) {
		return OCSPResult{}, ocspInvalid("thisUpdate %s is more than 5 minutes ahead", single.ThisUpdate.UTC().Format(time.RFC3339))
	}
	if !single.NextUpdate.IsZero() && !now.Before(single.NextUpdate) {
		return OCSPResult{}, ocspInvalid("stale: nextUpdate %s has passed", single.NextUpdate.UTC().Format(time.RFC3339))
	}
	res := OCSPResult{ThisUpdate: single.ThisUpdate, NextUpdate: single.NextUpdate}
	switch resp.Status {
	case ocsp.Good:
		res.Status = OCSPGood
	case ocsp.Revoked:
		res.Status = OCSPRevoked
	default:
		res.Status = OCSPUnknown
	}
	return res, nil
}

// parseErrorClass keeps an error from x/crypto/ocsp short: a ResponseError
// or ParseError says what was wrong without quoting the body.
func parseErrorClass(err error) error {
	var pe ocsp.ParseError
	var re ocsp.ResponseError
	switch {
	case errors.As(err, &pe), errors.As(err, &re):
		return err
	default:
		return errors.New("malformed response")
	}
}

// signer picks the certificate that must have signed the response: the
// anchor when the ResponderID names it, otherwise an embedded delegated
// responder the ResponderID names.
func (q *ocspQuery) signer(rid asn1.RawValue, embedded []asn1.RawValue, now time.Time, isRevoked func(string) bool) (*x509.Certificate, error) {
	names, err := responderIDMatcher(rid)
	if err != nil {
		return nil, err
	}
	if names(q.anchor) {
		return q.anchor, nil
	}
	for _, raw := range embedded {
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, ocspInvalid("an embedded certificate doesn't parse")
		}
		if !names(c) {
			continue
		}
		if err := q.checkDelegated(c, now, isRevoked); err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, ocspInvalid("the ResponderID names neither the operator CA nor an embedded responder certificate")
}

func (q *ocspQuery) checkDelegated(c *x509.Certificate, now time.Time, isRevoked func(string) bool) error {
	if !bytes.Equal(c.RawIssuer, q.anchor.RawSubject) || c.CheckSignatureFrom(q.anchor) != nil {
		return ocspInvalid("the responder certificate %s isn't issued directly by the operator CA", c.Subject)
	}
	ok := false
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageOCSPSigning {
			ok = true
		}
	}
	if !ok {
		return ocspInvalid("the responder certificate %s lacks id-kp-OCSPSigning", c.Subject)
	}
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return ocspInvalid("the responder certificate %s isn't valid now (%s to %s)", c.Subject,
			c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
	}
	for _, e := range c.Extensions {
		if e.Id.Equal(oidOCSPNoCheck) {
			return nil
		}
	}
	if isRevoked != nil && isRevoked(SerialKey(c.SerialNumber)) {
		return ocspInvalid("the responder certificate %s (serial %s) is revoked", c.Subject, SerialKey(c.SerialNumber))
	}
	return nil
}

// responderIDMatcher returns a test for whether a certificate is the one a
// ResponderID names: byName ([1]) compares the subject DER, byKey ([2]) the
// SHA-1 of the public key.
func responderIDMatcher(rid asn1.RawValue) (func(*x509.Certificate) bool, error) {
	if rid.Class != asn1.ClassContextSpecific {
		return nil, ocspInvalid("bad ResponderID")
	}
	switch rid.Tag {
	case 1:
		var name asn1.RawValue
		if rest, err := asn1.Unmarshal(rid.Bytes, &name); err != nil || len(rest) > 0 {
			return nil, ocspInvalid("bad ResponderID name")
		}
		return func(c *x509.Certificate) bool { return bytes.Equal(c.RawSubject, name.FullBytes) }, nil
	case 2:
		var hash []byte
		if rest, err := asn1.Unmarshal(rid.Bytes, &hash); err != nil || len(rest) > 0 {
			return nil, ocspInvalid("bad ResponderID key hash")
		}
		return func(c *x509.Certificate) bool {
			key, err := spkiKeyBytes(c)
			if err != nil {
				return false
			}
			sum := sha1.Sum(key) //nolint:gosec // RFC 6960 KeyHash
			return bytes.Equal(sum[:], hash)
		}, nil
	default:
		return nil, ocspInvalid("bad ResponderID tag %d", rid.Tag)
	}
}
