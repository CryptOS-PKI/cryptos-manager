package authz

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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
)

type fakeAuthorizer struct {
	gotLeaf          *x509.Certificate
	gotIntermediates []*x509.Certificate
	anchor           string
	err              error
}

func (f *fakeAuthorizer) AuthorizePeer(leaf *x509.Certificate, intermediates []*x509.Certificate) (string, error) {
	f.gotLeaf, f.gotIntermediates = leaf, intermediates
	return f.anchor, f.err
}

// Every request is re-checked by the authorizer with the leaf and the
// intermediates the peer sent, and the identity names the operator CA the
// certificate chains to.
func TestClientCertMiddlewareWith_RechecksEveryRequest(t *testing.T) {
	leaf, inter := leafCert(t, LevelAdmin), leafCert(t, LevelViewer)
	auth := &fakeAuthorizer{anchor: "ab12"}
	var got Identity
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = FromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodPost, "/rpc", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, inter}}
	rec := httptest.NewRecorder()
	ClientCertMiddlewareWith(auth)(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if auth.gotLeaf != leaf || len(auth.gotIntermediates) != 1 || auth.gotIntermediates[0] != inter {
		t.Fatal("the authorizer didn't get the peer's leaf and intermediates")
	}
	if got.IssuerSHA256 != "ab12" || got.Level != LevelAdmin {
		t.Fatalf("identity = %+v, want level admin under ab12", got)
	}
}

// A refusal answers 403 with the refusal's code and reason and never runs
// the handler.
func TestClientCertMiddlewareWith_RefusalCarriesTheCode(t *testing.T) {
	auth := &fakeAuthorizer{err: apperr.Reasoned(apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED, errors.New("denylisted"))}
	ran := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true })

	req := httptest.NewRequest(http.MethodPost, "/rpc", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafCert(t, LevelAdmin)}}
	rec := httptest.NewRecorder()
	ClientCertMiddlewareWith(auth)(next).ServeHTTP(rec, req)

	if ran {
		t.Fatal("the handler ran for a refused certificate")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if rec.Header().Get(apperr.MetadataKey) != "1610" || rec.Header().Get(apperr.ReasonKey) != "REVOKED" {
		t.Fatalf("headers = %v, want 1610/REVOKED", rec.Header())
	}
}
