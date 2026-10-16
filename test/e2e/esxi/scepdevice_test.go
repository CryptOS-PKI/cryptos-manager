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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

// Two more well-known RFC 8894 attribute OIDs, needed only to build the
// PENDING/FAILURE CertRep replies fakeSCEPServer sends: scep.PKIMessage.Fail
// already builds a FAILURE reply, but there is no equivalent for PENDING, so
// fakeSCEPServer builds that one by hand (see pendingReply).
var (
	oidSCEPpkiStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPrecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
)

// fakeSCEPServer is a minimal RFC 8894 server built from the same
// github.com/smallstep/scep and github.com/smallstep/pkcs7 primitives
// scepDevice uses, so these tests check scepDevice's wire format against an
// independent construction of a reply, not against itself replaying its own
// assumptions. It is not a stand-in for cryptos-node's internal/scep (no
// transaction storage, renewal, revocation or RA rotation): the live run
// run against a real node is still what proves the node's own behaviour; see
// docs/e2e-esxi.md.
type fakeSCEPServer struct {
	caCert, raCert  *x509.Certificate
	caKey, raKey    crypto.Signer
	requireApproval bool

	mu            sync.Mutex
	challenge     string
	challengeUsed bool
	pending       map[scep.TransactionID]*scep.PKIMessage
	decision      map[scep.TransactionID]string // "" (still pending), "approve" or "reject"
}

func newFakeSCEPServer(t *testing.T, challenge string, requireApproval bool) *fakeSCEPServer {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the fake CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake-scep-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("self-signing the fake CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing the fake CA: %v", err)
	}

	raKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the fake RA key: %v", err)
	}
	raTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "fake-scep-ra"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	raDER, err := x509.CreateCertificate(rand.Reader, raTmpl, caCert, &raKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("issuing the fake RA cert: %v", err)
	}
	raCert, err := x509.ParseCertificate(raDER)
	if err != nil {
		t.Fatalf("parsing the fake RA cert: %v", err)
	}

	return &fakeSCEPServer{
		caCert: caCert, raCert: raCert, caKey: caKey, raKey: raKey,
		requireApproval: requireApproval,
		challenge:       challenge,
		pending:         map[scep.TransactionID]*scep.PKIMessage{},
		decision:        map[scep.TransactionID]string{},
	}
}

func (f *fakeSCEPServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeSCEPServer) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("operation") {
	case "GetCACert":
		deg, err := scep.DegenerateCertificates([]*x509.Certificate{f.caCert, f.raCert})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(deg)
	case "PKIOperation":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := f.pkiOperation(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write(resp)
	default:
		http.Error(w, "fake scep server: unsupported operation", http.StatusBadRequest)
	}
}

// pkiOperation dispatches PKCSReq and CertPoll. scep.ParsePKIMessage refuses
// to parse a CertPoll request body at all (it returns errNotImplemented for
// that message type), so the message type is read directly off the PKCS#7
// signed attributes first.
func (f *fakeSCEPServer) pkiOperation(body []byte) ([]byte, error) {
	p7, err := pkcs7.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("fake scep server: parsing the request: %w", err)
	}
	if err := p7.Verify(); err != nil {
		return nil, fmt.Errorf("fake scep server: the request does not verify: %w", err)
	}
	var msgType scep.MessageType
	if err := p7.UnmarshalSignedAttribute(oidSCEPmessageType, &msgType); err != nil {
		return nil, fmt.Errorf("fake scep server: reading messageType: %w", err)
	}
	var tID scep.TransactionID
	if err := p7.UnmarshalSignedAttribute(oidSCEPtransactionID, &tID); err != nil {
		return nil, fmt.Errorf("fake scep server: reading transactionID: %w", err)
	}

	switch msgType {
	case scep.PKCSReq:
		return f.handlePKCSReq(body, tID)
	case scep.CertPoll:
		return f.handleCertPoll(tID)
	default:
		return nil, fmt.Errorf("fake scep server: messageType %s is not handled", msgType)
	}
}

func (f *fakeSCEPServer) handlePKCSReq(body []byte, tID scep.TransactionID) ([]byte, error) {
	msg, err := scep.ParsePKIMessage(body)
	if err != nil {
		return nil, fmt.Errorf("fake scep server: parsing the PKCSReq: %w", err)
	}
	if err := msg.DecryptPKIEnvelope(f.raCert, f.raKey); err != nil {
		return nil, fmt.Errorf("fake scep server: decrypting the PKCSReq: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.challengeUsed || msg.ChallengePassword != f.challenge {
		rep, err := msg.Fail(f.raCert, f.raKey, scep.BadRequest)
		if err != nil {
			return nil, err
		}
		return rep.Raw, nil
	}
	f.challengeUsed = true

	if f.requireApproval {
		f.pending[tID] = msg
		f.decision[tID] = ""
		return f.pendingReply(msg)
	}

	cert, err := f.issue(msg.CSR)
	if err != nil {
		return nil, err
	}
	rep, err := msg.Success(f.raCert, f.raKey, cert)
	if err != nil {
		return nil, err
	}
	return rep.Raw, nil
}

func (f *fakeSCEPServer) handleCertPoll(tID scep.TransactionID) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	msg, ok := f.pending[tID]
	if !ok {
		return nil, fmt.Errorf("fake scep server: no pending transaction %s", tID)
	}
	switch f.decision[tID] {
	case "approve":
		cert, err := f.issue(msg.CSR)
		if err != nil {
			return nil, err
		}
		rep, err := msg.Success(f.raCert, f.raKey, cert)
		if err != nil {
			return nil, err
		}
		return rep.Raw, nil
	case "reject":
		rep, err := msg.Fail(f.raCert, f.raKey, scep.BadRequest)
		if err != nil {
			return nil, err
		}
		return rep.Raw, nil
	default:
		return f.pendingReply(msg)
	}
}

// approve and reject stand in for ApproveNodeScepEnrollment and
// RejectNodeScepEnrollment: the real step calls those over the fleet API
// instead, against the enrolment whose transaction_id matches
// scepDevice.TransactionID(), and then calls scepDevice.PollCert the same
// way these tests call it after approve/reject.
func (f *fakeSCEPServer) approve(tID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decision[scep.TransactionID(tID)] = "approve"
}

func (f *fakeSCEPServer) reject(tID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decision[scep.TransactionID(tID)] = "reject"
}

// pendingReply builds a PENDING CertRep by hand: scep.PKIMessage has Fail
// (FAILURE) and Success (SUCCESS) but no third helper for PENDING.
func (f *fakeSCEPServer) pendingReply(msg *scep.PKIMessage) ([]byte, error) {
	sd, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return nil, err
	}
	cfg := pkcs7.SignerInfoConfig{ExtraSignedAttributes: []pkcs7.Attribute{
		{Type: oidSCEPtransactionID, Value: msg.TransactionID},
		{Type: oidSCEPpkiStatus, Value: scep.PENDING},
		{Type: oidSCEPmessageType, Value: scep.CertRep},
		{Type: oidSCEPsenderNonce, Value: msg.SenderNonce},
		{Type: oidSCEPrecipientNonce, Value: msg.SenderNonce},
	}}
	if err := sd.AddSigner(f.raCert, f.raKey, cfg); err != nil {
		return nil, err
	}
	return sd.Finish()
}

func (f *fakeSCEPServer) issue(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func devURL(srv *httptest.Server) string { return srv.URL + "/cgi-bin/pkiclient.exe" }

func TestScepDeviceEnrollIssuesImmediatelyWithoutApproval(t *testing.T) {
	fake := newFakeSCEPServer(t, "the-challenge", false)
	srv := fake.start(t)
	dev := newSCEPDevice(devURL(srv), srv.Client())
	ctx := context.Background()

	if err := dev.GetCACert(ctx); err != nil {
		t.Fatalf("GetCACert: %v", err)
	}
	status, cert, failInfo, err := dev.Enroll(ctx, pkix.Name{CommonName: "e2e-device"}, "the-challenge")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if status != scep.SUCCESS {
		t.Fatalf("status = %s (failInfo %s), want SUCCESS", status, failInfo)
	}
	if cert == nil {
		t.Fatal("Enroll returned no certificate on SUCCESS")
	}
	if cert.Subject.CommonName != "e2e-device" {
		t.Errorf("issued cert CN = %q, want %q", cert.Subject.CommonName, "e2e-device")
	}
	if err := cert.CheckSignatureFrom(fake.caCert); err != nil {
		t.Errorf("issued cert does not chain to the CA: %v", err)
	}
}

func TestScepDeviceEnrollWrongChallengeFails(t *testing.T) {
	fake := newFakeSCEPServer(t, "the-challenge", false)
	srv := fake.start(t)
	dev := newSCEPDevice(devURL(srv), srv.Client())
	ctx := context.Background()

	if err := dev.GetCACert(ctx); err != nil {
		t.Fatalf("GetCACert: %v", err)
	}
	status, cert, failInfo, err := dev.Enroll(ctx, pkix.Name{CommonName: "e2e-device"}, "wrong")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if status != scep.FAILURE {
		t.Fatalf("status = %s, want FAILURE", status)
	}
	if cert != nil {
		t.Error("Enroll returned a certificate on FAILURE")
	}
	if failInfo != scep.BadRequest {
		t.Errorf("failInfo = %s, want BadRequest", failInfo)
	}
}

func TestScepDeviceEnrollPendingThenApproved(t *testing.T) {
	fake := newFakeSCEPServer(t, "the-challenge", true)
	srv := fake.start(t)
	dev := newSCEPDevice(devURL(srv), srv.Client())
	ctx := context.Background()

	if err := dev.GetCACert(ctx); err != nil {
		t.Fatalf("GetCACert: %v", err)
	}
	status, cert, _, err := dev.Enroll(ctx, pkix.Name{CommonName: "e2e-device"}, "the-challenge")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if status != scep.PENDING {
		t.Fatalf("status = %s, want PENDING", status)
	}
	if cert != nil {
		t.Error("Enroll returned a certificate while PENDING")
	}

	status, _, _, err = dev.PollCert(ctx)
	if err != nil {
		t.Fatalf("PollCert (before a decision): %v", err)
	}
	if status != scep.PENDING {
		t.Fatalf("status before approval = %s, want PENDING", status)
	}

	fake.approve(dev.TransactionID())

	status, cert, failInfo, err := dev.PollCert(ctx)
	if err != nil {
		t.Fatalf("PollCert (after approval): %v", err)
	}
	if status != scep.SUCCESS {
		t.Fatalf("status after approval = %s (failInfo %s), want SUCCESS", status, failInfo)
	}
	if cert == nil {
		t.Fatal("PollCert returned no certificate on SUCCESS")
	}
	if err := cert.CheckSignatureFrom(fake.caCert); err != nil {
		t.Errorf("issued cert does not chain to the CA: %v", err)
	}
}

func TestScepDeviceEnrollPendingThenRejected(t *testing.T) {
	fake := newFakeSCEPServer(t, "the-challenge", true)
	srv := fake.start(t)
	dev := newSCEPDevice(devURL(srv), srv.Client())
	ctx := context.Background()

	if err := dev.GetCACert(ctx); err != nil {
		t.Fatalf("GetCACert: %v", err)
	}
	status, _, _, err := dev.Enroll(ctx, pkix.Name{CommonName: "e2e-device"}, "the-challenge")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if status != scep.PENDING {
		t.Fatalf("status = %s, want PENDING", status)
	}

	fake.reject(dev.TransactionID())

	status, cert, failInfo, err := dev.PollCert(ctx)
	if err != nil {
		t.Fatalf("PollCert (after rejection): %v", err)
	}
	if status != scep.FAILURE {
		t.Fatalf("status after rejection = %s, want FAILURE", status)
	}
	if cert != nil {
		t.Error("PollCert returned a certificate after rejection")
	}
	if failInfo != scep.BadRequest {
		t.Errorf("failInfo = %s, want BadRequest", failInfo)
	}
}

func TestScepDeviceEnrollWithoutGetCACertFails(t *testing.T) {
	dev := newSCEPDevice("http://127.0.0.1:0/cgi-bin/pkiclient.exe", http.DefaultClient)
	_, _, _, err := dev.Enroll(context.Background(), pkix.Name{CommonName: "e2e-device"}, "x")
	if err == nil {
		t.Fatal("Enroll without GetCACert should fail")
	}
}
