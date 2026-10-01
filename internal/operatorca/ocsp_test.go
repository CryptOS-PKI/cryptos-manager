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
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"golang.org/x/crypto/ocsp"
)

func mustQuery(t *testing.T, ca testCA, serial *big.Int) *ocspQuery {
	t.Helper()
	q, err := newOCSPQuery(ca.cert, serial)
	if err != nil {
		t.Fatalf("newOCSPQuery: %v", err)
	}
	return q
}

func notRevoked(string) bool { return false }

func wantInvalid(t *testing.T, err error) {
	t.Helper()
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_INVALID)
}

func TestOCSPValidate_Accepted(t *testing.T) {
	ca := newCA(t, caOpts{})
	serial := big.NewInt(0x77)
	signer := ca.delegated(t, delegatedOpts{noCheck: true})
	for name, o := range map[string]respOpts{
		"signed by the anchor":       {},
		"signed by a delegated cert": {signer: &signer},
	} {
		t.Run(name, func(t *testing.T) {
			q := mustQuery(t, ca, serial)
			o.serial = serial
			o.nonce = q.nonce
			res, err := q.validate(ca.ocspResponse(t, o), testNow, notRevoked)
			if err != nil {
				t.Fatalf("validate = %v", err)
			}
			if res.Status != OCSPGood || !res.NextUpdate.Equal(testNow.Add(29*time.Minute).Truncate(time.Second)) {
				t.Fatalf("result = %+v", res)
			}
		})
	}
}

func TestOCSPValidate_Refused(t *testing.T) {
	ca := newCA(t, caOpts{})
	other := newCA(t, caOpts{cn: "Example Other CA"})
	serial := big.NewInt(0x77)
	delegated := ca.delegated(t, delegatedOpts{noCheck: true})
	noEKU := ca.delegated(t, delegatedOpts{noEKU: true, noCheck: true})
	foreign := other.delegated(t, delegatedOpts{noCheck: true})
	expired := ca.delegated(t, delegatedOpts{noCheck: true, notAfter: testNow.Add(-time.Minute)})
	sameKeyOtherName := newCA(t, caOpts{cn: "Example Renamed CA", key: ca.key})
	sameNameOtherKey := newCA(t, caOpts{})

	for name, o := range map[string]respOpts{
		"wrong signer":                     {signer: &other, responderID: ca.cert, embed: []*x509.Certificate{}},
		"delegated without OCSPSigning":    {signer: &noEKU},
		"delegated issued by another CA":   {signer: &foreign},
		"expired delegated cert":           {signer: &expired},
		"ResponderID not the signer":       {signer: &delegated, responderID: ca.cert},
		"CertID serial":                    {serial: big.NewInt(0x78)},
		"CertID issuer name hash":          {certIDIssuer: sameKeyOtherName.cert},
		"CertID issuer key hash":           {certIDIssuer: sameNameOtherKey.cert},
		"thisUpdate more than 5 min ahead": {thisUpdate: testNow.Add(6 * time.Minute)},
		"stale (nextUpdate passed)":        {thisUpdate: testNow.Add(-2 * time.Hour), nextUpdate: testNow.Add(-time.Minute)},
		"unknown critical single ext":      {singleExt: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: asn1.NullBytes}}},
		"unknown critical response ext":    {responseExt: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: asn1.NullBytes}}},
	} {
		t.Run(name, func(t *testing.T) {
			q := mustQuery(t, ca, serial)
			if o.serial == nil {
				o.serial = serial
			}
			_, err := q.validate(ca.ocspResponse(t, o), testNow, notRevoked)
			wantInvalid(t, err)
		})
	}

	t.Run("a non-successful response status", func(t *testing.T) {
		q := mustQuery(t, ca, serial)
		for _, body := range [][]byte{ocsp.TryLaterErrorResponse, ocsp.UnauthorizedErrorResponse, ocsp.MalformedRequestErrorResponse} {
			_, err := q.validate(body, testNow, notRevoked)
			wantInvalid(t, err)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		q := mustQuery(t, ca, serial)
		_, err := q.validate([]byte("SECRET-BODY-DO-NOT-ECHO"), testNow, notRevoked)
		wantInvalid(t, err)
		if strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("error echoes the body: %v", err)
		}
	})
}

func TestOCSPValidate_NoCheck(t *testing.T) {
	ca := newCA(t, caOpts{})
	serial := big.NewInt(0x77)
	withNoCheck := ca.delegated(t, delegatedOpts{noCheck: true})
	without := ca.delegated(t, delegatedOpts{})

	q := mustQuery(t, ca, serial)
	called := false
	spy := func(string) bool { called = true; return true }
	if _, err := q.validate(ca.ocspResponse(t, respOpts{serial: serial, signer: &withNoCheck}), testNow, spy); err != nil {
		t.Fatalf("noCheck signer: %v", err)
	}
	if called {
		t.Fatal("a delegated signer with noCheck was revocation-checked")
	}

	q = mustQuery(t, ca, serial)
	if _, err := q.validate(ca.ocspResponse(t, respOpts{serial: serial, signer: &without}), testNow, notRevoked); err != nil {
		t.Fatalf("delegated signer without noCheck, not revoked: %v", err)
	}
	revokedSigner := func(s string) bool { return s == SerialKey(without.cert.SerialNumber) }
	_, err := q.validate(ca.ocspResponse(t, respOpts{serial: serial, signer: &without}), testNow, revokedSigner)
	wantInvalid(t, err)
}

func TestOCSPRequest_Nonce(t *testing.T) {
	ca := newCA(t, caOpts{})
	serial := big.NewInt(0x77)
	q := mustQuery(t, ca, serial)
	p := parseTestRequest(t, q.der)
	var nonce []byte
	if rest, err := asn1.Unmarshal(p.nonce, &nonce); err != nil || len(rest) > 0 {
		t.Fatalf("the nonce extension isn't an OCTET STRING: %v", err)
	}
	if len(nonce) != 32 {
		t.Fatalf("nonce is %d bytes, want 32", len(nonce))
	}
	if p.serial.Cmp(serial) != 0 {
		t.Fatalf("request serial = %v", p.serial)
	}
	if q2 := mustQuery(t, ca, serial); bytes.Equal(q2.nonce, q.nonce) {
		t.Fatal("two requests carry the same nonce")
	}

	if _, err := q.validate(ca.ocspResponse(t, respOpts{serial: serial, nonce: q.nonce}), testNow, notRevoked); err != nil {
		t.Fatalf("matching nonce: %v", err)
	}
	if _, err := q.validate(ca.ocspResponse(t, respOpts{serial: serial}), testNow, notRevoked); err != nil {
		t.Fatalf("no nonce in the response: %v", err)
	}
	other := mustQuery(t, ca, serial)
	_, err := q.validate(ca.ocspResponse(t, respOpts{serial: serial, nonce: other.nonce}), testNow, notRevoked)
	wantInvalid(t, err)
}

func TestOCSPValidate_Statuses(t *testing.T) {
	ca := newCA(t, caOpts{})
	serial := big.NewInt(0x77)
	for status, want := range map[int]OCSPStatus{ocsp.Good: OCSPGood, ocsp.Revoked: OCSPRevoked, ocsp.Unknown: OCSPUnknown} {
		q := mustQuery(t, ca, serial)
		res, err := q.validate(ca.ocspResponse(t, respOpts{serial: serial, status: status}), testNow, notRevoked)
		if err != nil || res.Status != want {
			t.Fatalf("status %d: %+v, %v", status, res, err)
		}
	}
}

func TestOCSPTransport(t *testing.T) {
	ca := newCA(t, caOpts{})
	a := anchorFor(ca, "none", "url")
	clock := &fakeClock{t: testNow}
	newClient := func(f *Fetcher) *OCSPClient {
		return NewOCSPClient(OCSPOptions{Fetch: f, Now: clock.Now})
	}

	t.Run("POST by default", func(t *testing.T) {
		r := newTestResponder(t, ca, clock.Now)
		res, err := newClient(NewOCSPFetcher()).Check(a, big.NewInt(0x10), r.URL(), notRevoked)
		if err != nil || res.Status != OCSPGood {
			t.Fatalf("Check = %+v, %v", res, err)
		}
		if got := r.last().method; got != http.MethodPost {
			t.Fatalf("method = %s, want POST", got)
		}
	})
	t.Run("GET after a 405 for a small request", func(t *testing.T) {
		r := newTestResponder(t, ca, clock.Now)
		r.set(func(r *testResponder) { r.noPOST = true })
		res, err := newClient(NewOCSPFetcher()).Check(a, big.NewInt(0x11), r.URL(), notRevoked)
		if err != nil || res.Status != OCSPGood {
			t.Fatalf("Check = %+v, %v", res, err)
		}
		if got := r.last().method; got != http.MethodGet {
			t.Fatalf("method = %s, want GET", got)
		}
	})
	t.Run("no GET for a large request", func(t *testing.T) {
		r := newTestResponder(t, ca, clock.Now)
		r.set(func(r *testResponder) { r.noPOST = true })
		huge := new(big.Int).Lsh(big.NewInt(1), 8*200)
		_, err := newClient(NewOCSPFetcher()).Check(a, huge, r.URL(), notRevoked)
		wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE)
		if r.count() != 0 {
			t.Fatalf("the responder answered %d requests, want none (no GET fallback)", r.count())
		}
	})
	t.Run("no GET after other errors", func(t *testing.T) {
		r := newTestResponder(t, ca, clock.Now)
		r.set(func(r *testResponder) { r.down = true })
		_, err := newClient(NewOCSPFetcher()).Check(a, big.NewInt(0x12), r.URL(), notRevoked)
		wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE)
		if r.last().method != http.MethodPost || r.count() != 1 {
			t.Fatalf("requests = %d, last %s; want one POST", r.count(), r.last().method)
		}
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), MaxOCSPSize+1))
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	mux.HandleFunc("/to-file", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	})
	mux.HandleFunc("/hop/", func(w http.ResponseWriter, r *http.Request) {
		n := len(strings.TrimPrefix(r.URL.Path, "/hop/"))
		http.Redirect(w, r, "/hop/"+strings.Repeat("x", n+1), http.StatusTemporaryRedirect)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	short := NewFetcher(FetchLimits{Timeout: 200 * time.Millisecond, MaxBytes: MaxOCSPSize})
	for name, c := range map[string]struct {
		url    string
		reason fleetv1.ErrorReason
	}{
		"non-http URL":          {"ldap://ocsp.example.org/", fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE},
		"redirect to file://":   {srv.URL + "/to-file", fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE},
		"more than 3 redirects": {srv.URL + "/hop/", fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE},
		"timeout":               {srv.URL + "/slow", fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE},
		"body over 64 KiB":      {srv.URL + "/big", fleetv1.ErrorReason_ERROR_REASON_OCSP_INVALID},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newClient(short).Check(a, big.NewInt(0x13), c.url, notRevoked)
			wantReason(t, err, apperr.CodeOperatorCARejected, c.reason)
			if strings.Contains(err.Error(), "xxxx") {
				t.Fatalf("error echoes the body: %v", err)
			}
		})
	}
}

func TestOCSPProbe(t *testing.T) {
	ca := newCA(t, caOpts{})
	other := newCA(t, caOpts{cn: "Example Other CA"})
	clock := &fakeClock{t: testNow}
	c := NewOCSPClient(OCSPOptions{Fetch: NewOCSPFetcher(), Now: clock.Now})

	r := newTestResponder(t, ca, clock.Now)
	r.set(func(r *testResponder) { r.defaultStatus = ocsp.Unknown })
	if err := c.Probe(t.Context(), ca.cert, r.URL()); err != nil {
		t.Fatalf("Probe with a signed unknown = %v", err)
	}
	first := r.last().serial
	if err := c.Probe(t.Context(), ca.cert, r.URL()); err != nil {
		t.Fatalf("second Probe = %v", err)
	}
	if first == nil || first.Cmp(r.last().serial) == 0 || first.Sign() <= 0 {
		t.Fatalf("probe serials %v and %v: want two different random positive serials", first, r.last().serial)
	}

	r.set(func(r *testResponder) { r.wrongKey = &other })
	err := c.Probe(t.Context(), ca.cert, r.URL())
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_INVALID)

	unsigned := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(ocsp.UnauthorizedErrorResponse)
	}))
	defer unsigned.Close()
	err = c.Probe(t.Context(), ca.cert, unsigned.URL)
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_INVALID)

	r.set(func(r *testResponder) { r.down = true })
	err = c.Probe(t.Context(), ca.cert, r.URL())
	wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE)
}
