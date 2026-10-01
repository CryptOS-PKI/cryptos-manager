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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// The in-test OCSP responder. Responses are signed with
// golang.org/x/crypto/ocsp; a response that needs responseExtensions (the
// nonce echo) or several embedded certificates, which that package can't
// produce, is re-encoded and re-signed by resign.

type delegatedOpts struct {
	noEKU     bool
	noCheck   bool
	notBefore time.Time
	notAfter  time.Time
}

// delegated issues an OCSP signing certificate from ca.
func (ca testCA) delegated(t *testing.T, o delegatedOpts) testCA {
	t.Helper()
	if o.notBefore.IsZero() {
		o.notBefore = testNow.Add(-24 * time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = testNow.Add(30 * 24 * time.Hour)
	}
	key := newKey(t, keyP384)
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	if o.noEKU {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: "Example Operator OCSP"},
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
	}
	if o.noCheck {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidOCSPNoCheck, Value: asn1.NullBytes}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatalf("create delegated OCSP signer: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse delegated OCSP signer: %v", err)
	}
	return testCA{cert: cert, key: key}
}

type respOpts struct {
	status     int
	serial     *big.Int
	thisUpdate time.Time
	nextUpdate time.Time
	noNext     bool
	// signer signs the response; the anchor when nil.
	signer *testCA
	// responderID is the certificate the ResponderID names; the signer's
	// when nil.
	responderID *x509.Certificate
	// embed is the certificates carried in the response; the signer's
	// certificate when the signer isn't the anchor and embed is nil.
	embed []*x509.Certificate
	// certIDIssuer is the issuer the CertID hashes; the anchor when nil.
	certIDIssuer *x509.Certificate
	nonce        []byte
	singleExt    []pkix.Extension
	responseExt  []pkix.Extension
	hash         crypto.Hash
}

// ocspResponse builds a response for ca, the anchor.
func (ca testCA) ocspResponse(t *testing.T, o respOpts) []byte {
	t.Helper()
	signer := ca
	if o.signer != nil {
		signer = *o.signer
	}
	if o.responderID == nil {
		o.responderID = signer.cert
	}
	if o.embed == nil && o.signer != nil && o.signer.cert != ca.cert {
		o.embed = []*x509.Certificate{signer.cert}
	}
	if o.certIDIssuer == nil {
		o.certIDIssuer = ca.cert
	}
	if o.thisUpdate.IsZero() {
		o.thisUpdate = testNow.Add(-time.Minute)
	}
	if o.nextUpdate.IsZero() && !o.noNext {
		o.nextUpdate = o.thisUpdate.Add(30 * time.Minute)
	}
	if o.noNext {
		o.nextUpdate = time.Time{}
	}
	if o.hash == 0 {
		o.hash = crypto.SHA1
	}
	tmpl := ocsp.Response{
		Status: o.status, SerialNumber: o.serial, ThisUpdate: o.thisUpdate, NextUpdate: o.nextUpdate,
		IssuerHash: o.hash, ExtraExtensions: o.singleExt,
	}
	if o.status == ocsp.Revoked {
		tmpl.RevokedAt = o.thisUpdate.Add(-time.Hour)
	}
	if len(o.embed) > 0 {
		tmpl.Certificate = o.embed[0]
	}
	der, err := ocsp.CreateResponse(o.certIDIssuer, o.responderID, tmpl, signer.key)
	if err != nil {
		t.Fatalf("create OCSP response: %v", err)
	}
	if o.nonce != nil || o.responseExt != nil || len(o.embed) > 1 {
		exts := append([]pkix.Extension(nil), o.responseExt...)
		if o.nonce != nil {
			exts = append(exts, pkix.Extension{Id: oidOCSPNonce, Value: o.nonce})
		}
		der = resign(t, der, signer.key, exts, o.embed)
	}
	return der
}

// resign re-encodes a response with responseExtensions and the embedded
// certificates, and signs it again with key (a P-384 key, so SHA-384).
func resign(t *testing.T, der []byte, key crypto.Signer, exts []pkix.Extension, embed []*x509.Certificate) []byte {
	t.Helper()
	var outer ocspResponseASN1
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatalf("resign: outer: %v", err)
	}
	var basic ocspBasicResponse
	if _, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil {
		t.Fatalf("resign: basic: %v", err)
	}
	basic.TBSResponseData.Raw = nil
	basic.TBSResponseData.ResponseExtensions = exts
	tbs, err := asn1.Marshal(basic.TBSResponseData)
	if err != nil {
		t.Fatalf("resign: tbs: %v", err)
	}
	h := crypto.SHA384.New()
	h.Write(tbs)
	sig, err := key.Sign(rand.Reader, h.Sum(nil), crypto.SHA384)
	if err != nil {
		t.Fatalf("resign: sign: %v", err)
	}
	basic.TBSResponseData.Raw = tbs
	basic.SignatureAlgorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}}
	basic.Signature = asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}
	basic.Certificates = nil
	for _, c := range embed {
		basic.Certificates = append(basic.Certificates, asn1.RawValue{FullBytes: c.Raw})
	}
	basicDER, err := asn1.Marshal(basic)
	if err != nil {
		t.Fatalf("resign: basic marshal: %v", err)
	}
	outer.Response.Response = basicDER
	out, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("resign: outer marshal: %v", err)
	}
	return out
}

// parsedRequest is what the test responder read from a request.
type parsedRequest struct {
	method string
	serial *big.Int
	hash   asn1.ObjectIdentifier
	nonce  []byte // the nonce extension's extnValue
	size   int
}

func parseTestRequest(t *testing.T, der []byte) parsedRequest {
	t.Helper()
	var req ocspRequestASN1
	if rest, err := asn1.Unmarshal(der, &req); err != nil || len(rest) > 0 {
		t.Errorf("test responder: bad request: %v", err)
		return parsedRequest{}
	}
	if len(req.TBSRequest.RequestList) != 1 {
		t.Errorf("test responder: %d requests, want 1", len(req.TBSRequest.RequestList))
		return parsedRequest{}
	}
	p := parsedRequest{
		serial: req.TBSRequest.RequestList[0].Cert.SerialNumber,
		hash:   req.TBSRequest.RequestList[0].Cert.HashAlgorithm.Algorithm,
		size:   len(der),
	}
	for _, e := range req.TBSRequest.Extensions {
		if e.Id.Equal(oidOCSPNonce) {
			p.nonce = e.Value
		}
	}
	return p
}

// testResponder is an httptest OCSP responder for one anchor. By default it
// answers good for every serial, echoes the nonce and signs with the
// anchor.
type testResponder struct {
	t      *testing.T
	ca     testCA
	now    func() time.Time
	srv    *httptest.Server
	mu     sync.Mutex
	status map[string]int
	// defaultStatus answers serials missing from status.
	defaultStatus int
	// down makes the responder answer HTTP 500.
	down bool
	// wrongKey signs with a key that isn't the anchor's.
	wrongKey *testCA
	// delegate signs as a delegated responder the anchor issued.
	delegate *testCA
	noNonce  bool
	noPOST   bool
	next     time.Duration
	noNext   bool
	gate     chan struct{}
	requests atomic.Int64
	seen     []parsedRequest
}

func newTestResponder(t *testing.T, ca testCA, now func() time.Time) *testResponder {
	t.Helper()
	r := &testResponder{t: t, ca: ca, now: now, status: map[string]int{}, next: 30 * time.Minute}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *testResponder) URL() string { return r.srv.URL + "/ocsp" }

func (r *testResponder) set(f func(r *testResponder)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r)
}

func (r *testResponder) count() int { return int(r.requests.Load()) }

func (r *testResponder) last() parsedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) == 0 {
		return parsedRequest{}
	}
	return r.seen[len(r.seen)-1]
}

func (r *testResponder) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	gate, noPOST := r.gate, r.noPOST
	r.mu.Unlock()
	var der []byte
	switch req.Method {
	case http.MethodPost:
		if noPOST {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if req.Header.Get("Content-Type") != "application/ocsp-request" {
			r.t.Errorf("test responder: Content-Type %q", req.Header.Get("Content-Type"))
		}
		der, _ = io.ReadAll(req.Body)
	case http.MethodGet:
		enc := strings.TrimPrefix(req.URL.EscapedPath(), "/ocsp/")
		s, err := url.PathUnescape(enc)
		if err == nil {
			der, err = base64.StdEncoding.DecodeString(s)
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	r.requests.Add(1)
	if gate != nil {
		<-gate
	}
	p := parseTestRequest(r.t, der)
	p.method = req.Method
	r.mu.Lock()
	r.seen = append(r.seen, p)
	down, wrong, delegate, noNonce, next, noNext := r.down, r.wrongKey, r.delegate, r.noNonce, r.next, r.noNext
	status, ok := r.status[SerialKey(p.serial)]
	if !ok {
		status = r.defaultStatus
	}
	r.mu.Unlock()
	if down || p.serial == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	now := r.now()
	o := respOpts{status: status, serial: p.serial, thisUpdate: now.Add(-time.Minute), nextUpdate: now.Add(next), noNext: noNext}
	if !noNonce {
		o.nonce = p.nonce
	}
	if delegate != nil {
		o.signer = delegate
	}
	if wrong != nil {
		o.signer = wrong
		o.responderID = r.ca.cert
		o.embed = []*x509.Certificate{}
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(r.ca.ocspResponse(r.t, o))
}

// bgRunner runs background refreshes on goroutines the test can wait for.
type bgRunner struct{ wg sync.WaitGroup }

func (b *bgRunner) Go(f func()) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		f()
	}()
}

func (b *bgRunner) wait() { b.wg.Wait() }

// ocspFixture is a Revocations with OCSP on, sharing a fake clock with its
// responder.
type ocspFixture struct {
	revFixture
	bg *bgRunner
}

func newOCSPFixture(t *testing.T, policy string, fetch *Fetcher, anchors ...Anchor) ocspFixture {
	t.Helper()
	f := ocspFixture{revFixture: revFixture{st: newFakeTrust(), clock: &fakeClock{t: testNow}, logs: &logSink{}, audit: &auditSink{}}, bg: &bgRunner{}}
	if fetch == nil {
		fetch = NewOCSPFetcher()
	}
	f.rev = NewRevocations(RevocationOptions{
		Store: f.st, Policy: policy, Now: f.clock.Now, Logf: f.logs.Logf, Audit: f.audit.Record,
		OCSPFetcher: fetch, OCSPBackground: f.bg.Go,
	})
	f.rev.SetAnchors(anchors)
	if err := f.rev.Reload(t.Context()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return f
}

func ocspAnchor(ca testCA, crlSource, mode, responderURL string) Anchor {
	a := anchorFor(ca, crlSource, mode)
	a.OCSPURL = responderURL
	return a
}
