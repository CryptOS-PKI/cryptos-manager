package bootstrap

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
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"golang.org/x/crypto/ocsp"
)

// ocspResponder answers OCSP requests for ca, signed by ca, with the status
// set per serial (good by default).
type ocspResponder struct {
	t      *testing.T
	ca     testCA
	srv    *httptest.Server
	mu     sync.Mutex
	status map[string]int
}

func newOCSPResponder(t *testing.T, ca testCA) *ocspResponder {
	t.Helper()
	r := &ocspResponder{t: t, ca: ca, status: map[string]int{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		q, err := ocsp.ParseRequest(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		st, ok := r.status[operatorca.SerialKey(q.SerialNumber)]
		r.mu.Unlock()
		if !ok {
			st = ocsp.Good
		}
		tmpl := ocsp.Response{Status: st, SerialNumber: q.SerialNumber, IssuerHash: q.HashAlgorithm,
			ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(30 * time.Minute)}
		if st == ocsp.Revoked {
			tmpl.RevokedAt = time.Now().Add(-time.Hour)
		}
		der, err := ocsp.CreateResponse(r.ca.cert, r.ca.cert, tmpl, r.ca.key)
		if err != nil {
			r.t.Errorf("responder: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(der)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *ocspResponder) set(serial string, status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status[serial] = status
}

// A first-admin certificate the CA's OCSP responder says is revoked, or
// doesn't know, is refused, like one on the denylist.
func TestSubmit_RefusesWhatTheOCSPResponderRevokes(t *testing.T) {
	ca := newCA(t, "Example Operator CA")
	resp := newOCSPResponder(t, ca)
	h := newHarness(t)
	secret := h.startSession()
	// aia: each certificate names its own responder, which only the
	// certificate itself can tell the check.
	msg := noCRL(ca)
	msg.OcspMode = fleetv1.OcspMode_OCSP_MODE_AIA
	preview, err := h.register(secret, msg)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	msg.ConfirmSha256 = preview.GetOperatorCa().GetSha256()
	if _, err := h.register(secret, msg); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	aia := []string{resp.srv.URL}
	revoked := ca.leaf(t, leafOpts{ocsp: aia})
	unknown := ca.leaf(t, leafOpts{ocsp: aia})
	resp.set(operatorca.SerialKey(revoked.SerialNumber), ocsp.Revoked)
	resp.set(operatorca.SerialKey(unknown.SerialNumber), ocsp.Unknown)

	_, err = h.clientFrom("192.0.2.71:1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
		&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: revoked.Raw, FullName: "Ada Example"}))
	wantCode(t, err, apperr.CodeCertRejected, "REVOKED_OCSP")
	_, err = h.clientFrom("192.0.2.72:1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
		&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: unknown.Raw, FullName: "Ada Example"}))
	wantCode(t, err, apperr.CodeCertRejected, "OCSP_UNKNOWN")
	if _, err := h.submit(secret, &fleetv1.SubmitFirstAdminCertificateRequest{CertDer: ca.leaf(t, leafOpts{ocsp: aia}).Raw, FullName: "Ada Example"}); err != nil {
		t.Fatalf("a certificate the responder says is good was refused: %v", err)
	}
}
