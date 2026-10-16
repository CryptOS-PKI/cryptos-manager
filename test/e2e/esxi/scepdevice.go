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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"
)

// scepGlobalsOnce makes a real RFC 8894 interop choice once per process: the
// node's SCEP server (cryptos-node internal/cms) accepts only AES content
// encryption and SHA-256/SHA-512 signatures, and refuses DES/3DES and SHA-1.
// github.com/smallstep/scep builds every message through
// github.com/smallstep/pkcs7, whose own defaults are DES-CBC content
// encryption and a SHA-1 signature digest (both process-wide package
// variables, not per-message settings) - a PKCSReq built without this call
// would be refused by the node with BadAlg, not succeed. AES-CBC, not GCM:
// the node's envelope decryption only implements CBC.
var scepGlobalsOnce sync.Once

func scepSetGlobals() {
	scepGlobalsOnce.Do(func() {
		pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
		_ = pkcs7.SetDefaultDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	})
}

// These are the well-known RFC 8894 pkiMessage attribute OIDs (the Verisign
// arc every SCEP implementation, including this node's own server, uses).
// scep.NewCSRRequest already signs a PKCSReq with them, but it has no
// constructor for CertPoll (RFC 8894 section 3.3.3): newCertPoll below builds
// one with the same github.com/smallstep/pkcs7 primitives NewCSRRequest uses
// internally, so it needs the same OID values.
var (
	oidSCEPmessageType   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPsenderNonce   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPtransactionID = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// scepDeviceKeyBits is the device identity's RSA key size: large enough to
// clear a node's default Scep.profiles min_rsa_key_bits (3072) when, as is
// usual for a SCEP device, the same keypair is both the CSR's subject key and
// the self-signed identity the request is signed with.
const scepDeviceKeyBits = 3072

// scepDevice is a minimal RFC 8894 client: just enough of the protocol to
// drive one initial enrolment (PKCSReq, authorized by a one-time challenge)
// through to a certificate, including a CertPoll wait when the profile
// queues it for approval. It is not a general-purpose SCEP client: renewal,
// GetCert and GetCRL are not implemented, because no e2e step needs them.
//
// Each scepDevice is single-use: Enroll generates a fresh throwaway device
// identity, the way a real device would for a one-time challenge, and a
// later PollCert reuses that same identity and transactionID, as the node's
// CertPoll handler requires (the poll must be signed by the key that made
// the original request).
type scepDevice struct {
	baseURL    string
	httpClient *http.Client

	ca *x509.Certificate // filled by GetCACert
	ra *x509.Certificate // filled by GetCACert

	key           *rsa.PrivateKey // filled by Enroll
	self          *x509.Certificate
	transactionID scep.TransactionID
}

// newSCEPDevice builds a client for the node's SCEP listener at baseURL
// (http://host:port/cgi-bin/pkiclient.exe or /scep; see internal/scep's
// PathPKIClient/PathSCEP). httpClient is the caller's: the listener is plain
// HTTP by design (RFC 8894's CMS envelope carries confidentiality and
// integrity on its own), so no TLS pinning is needed here, unlike the
// mTLS-admin nodeclient.Dial other steps use.
func newSCEPDevice(baseURL string, httpClient *http.Client) *scepDevice {
	scepSetGlobals()
	return &scepDevice{baseURL: baseURL, httpClient: httpClient}
}

// GetCACert fetches the node's CA and RA certificates (RFC 8894 section
// 3.2.1.2's degenerate PKCS#7 reply), needed to encrypt a request and verify
// a reply. It must be called before Enroll.
func (d *scepDevice) GetCACert(ctx context.Context) error {
	body, err := d.get(ctx, "GetCACert", "")
	if err != nil {
		return fmt.Errorf("GetCACert: %w", err)
	}
	certs, err := scep.CACerts(body)
	if err != nil {
		return fmt.Errorf("GetCACert: parsing the degenerate PKCS#7: %w", err)
	}
	for _, c := range certs {
		switch {
		case c.IsCA:
			d.ca = c
		default:
			d.ra = c
		}
	}
	if d.ca == nil || d.ra == nil {
		return fmt.Errorf("GetCACert: expected a CA certificate and an RA certificate, got %d certificate(s)", len(certs))
	}
	return nil
}

// Enroll drives one initial enrolment (RFC 8894 section 3.2): a fresh
// self-signed RSA device identity, embedding challenge as the PKCS#10
// challengePassword attribute, sent as a PKCSReq. A PENDING result (the
// profile's require_approval is set) leaves the device identity on d for a
// later PollCert; the caller is expected to call PollCert once an operator
// has approved or rejected the enrolment. A FAILURE result carries failInfo
// and no certificate.
func (d *scepDevice) Enroll(ctx context.Context, subject pkix.Name, challenge string) (scep.PKIStatus, *x509.Certificate, scep.FailInfo, error) {
	if d.ra == nil || d.ca == nil {
		return "", nil, "", errors.New("Enroll: call GetCACert first")
	}

	key, self, err := newDeviceIdentity(subject)
	if err != nil {
		return "", nil, "", fmt.Errorf("Enroll: generating the device identity: %w", err)
	}

	csrDER, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{Subject: subject},
		ChallengePassword:  challenge,
	}, key)
	if err != nil {
		return "", nil, "", fmt.Errorf("Enroll: building the CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return "", nil, "", fmt.Errorf("Enroll: parsing the CSR back: %w", err)
	}

	msg, err := scep.NewCSRRequest(csr, &scep.PKIMessage{
		MessageType: scep.PKCSReq,
		Recipients:  []*x509.Certificate{d.ra},
		SignerCert:  self,
		SignerKey:   key,
	})
	if err != nil {
		return "", nil, "", fmt.Errorf("Enroll: building the PKCSReq: %w", err)
	}

	respDER, err := d.post(ctx, msg.Raw)
	if err != nil {
		return "", nil, "", fmt.Errorf("Enroll: PKIOperation: %w", err)
	}
	status, cert, failInfo, err := d.parseCertRep(respDER, self, key)
	if err != nil {
		return "", nil, "", err
	}
	// Kept for a later PollCert regardless of status: a FAILURE still lets
	// the caller poll again to double-check nothing was left pending.
	d.key, d.self, d.transactionID = key, self, msg.TransactionID
	return status, cert, failInfo, nil
}

// TransactionID returns the RFC 8894 transactionID Enroll used, once Enroll
// has been called. A step matches this against
// NodeScepEnrollment.transaction_id from ListNodeScepEnrollments to find
// which queued enrolment to approve or reject.
func (d *scepDevice) TransactionID() string {
	return string(d.transactionID)
}

// PollCert sends CertPoll (RFC 8894 section 3.3.3, formerly GetCertInitial)
// for the enrolment Enroll started, reusing its device identity and
// transactionID.
func (d *scepDevice) PollCert(ctx context.Context) (scep.PKIStatus, *x509.Certificate, scep.FailInfo, error) {
	if d.key == nil || d.self == nil || d.transactionID == "" {
		return "", nil, "", errors.New("PollCert: no enrolment from Enroll to poll for")
	}
	raw, err := d.newCertPoll()
	if err != nil {
		return "", nil, "", fmt.Errorf("PollCert: building CertPoll: %w", err)
	}
	respDER, err := d.post(ctx, raw)
	if err != nil {
		return "", nil, "", fmt.Errorf("PollCert: PKIOperation: %w", err)
	}
	return d.parseCertRep(respDER, d.self, d.key)
}

// newCertPoll builds a CertPoll PKIMessage with the same pkcs7 primitives
// scep.NewCSRRequest uses internally (it only builds PKCSReq/UpdateReq).
// RFC 8894 says CertPoll's encrypted content is an IssuerAndSubject; this
// node's CertPoll handler (cryptos-node internal/scep) looks up the pending
// transaction by TransactionID and checks only that the poll is signed by
// the same key that made the original request, so any content that encrypts
// cleanly to the current RA is accepted. A general-purpose client talking to
// a stricter server would need the real IssuerAndSubject structure.
func (d *scepDevice) newCertPoll() ([]byte, error) {
	enveloped, err := pkcs7.Encrypt([]byte{0x30, 0x00}, []*x509.Certificate{d.ra}) // empty ASN.1 SEQUENCE
	if err != nil {
		return nil, err
	}
	signedData, err := pkcs7.NewSignedData(enveloped)
	if err != nil {
		return nil, err
	}
	sn := make([]byte, 16)
	if _, err := rand.Read(sn); err != nil {
		return nil, err
	}
	cfg := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: oidSCEPtransactionID, Value: d.transactionID},
			{Type: oidSCEPmessageType, Value: scep.CertPoll},
			{Type: oidSCEPsenderNonce, Value: sn},
		},
	}
	if err := signedData.AddSigner(d.self, d.key, cfg); err != nil {
		return nil, err
	}
	return signedData.Finish()
}

// parseCertRep decodes a CertRep (RFC 8894 section 3.3) shared by Enroll and
// PollCert: SUCCESS decrypts and returns the issued certificate, PENDING
// returns no certificate or error, and anything else is a failure carrying
// failInfo.
func (d *scepDevice) parseCertRep(der []byte, self *x509.Certificate, key crypto.PrivateKey) (scep.PKIStatus, *x509.Certificate, scep.FailInfo, error) {
	msg, err := scep.ParsePKIMessage(der, scep.WithCACerts([]*x509.Certificate{d.ca, d.ra}))
	if err != nil {
		return "", nil, "", fmt.Errorf("parsing the CertRep: %w", err)
	}
	if msg.CertRepMessage == nil {
		return "", nil, "", fmt.Errorf("the response is not a CertRep (messageType %s)", msg.MessageType)
	}
	switch msg.PKIStatus {
	case scep.SUCCESS:
		if err := msg.DecryptPKIEnvelope(self, key); err != nil {
			return "", nil, "", fmt.Errorf("decrypting the issued certificate: %w", err)
		}
		return msg.PKIStatus, msg.Certificate, "", nil
	case scep.PENDING:
		return msg.PKIStatus, nil, "", nil
	default:
		return msg.PKIStatus, nil, msg.FailInfo, nil
	}
}

// newDeviceIdentity generates the throwaway RSA key and self-signed
// certificate a device presenting a one-time challenge has to offer: it has
// no certificate from this CA yet, so it can only vouch for itself. The same
// keypair signs the CSR it carries (the usual SCEP device pattern), so its
// subject matches the CSR's subject.
func newDeviceIdentity(subject pkix.Name) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, scepDeviceKeyBits)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

// get issues a SCEP GET operation (GetCACaps, GetCACert, or PKIOperation over
// GET for a server that does not advertise POSTPKIOperation).
func (d *scepDevice) get(ctx context.Context, operation, message string) ([]byte, error) {
	u, err := url.Parse(d.baseURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("operation", operation)
	if message != "" {
		q.Set("message", message)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	return d.do(req)
}

// post issues a PKIOperation over POST: this node always advertises
// POSTPKIOperation (internal/scep.Capabilities), so this client never falls
// back to the GET form.
func (d *scepDevice) post(ctx context.Context, raw []byte) ([]byte, error) {
	u, err := url.Parse(d.baseURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("operation", "PKIOperation")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-pki-message")
	return d.do(req)
}

func (d *scepDevice) do(req *http.Request) ([]byte, error) {
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Path, resp.Status, bytes.TrimSpace(body))
	}
	return body, nil
}
