package fleet

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
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"golang.org/x/crypto/ocsp"
)

// Recording asks the CA's OCSP responder too: a certificate it says is
// revoked, or doesn't know, isn't recorded.
func TestRecordOperatorCredential_RefusesWhatTheOCSPResponderRevokes(t *testing.T) {
	ca := newTestCA(t, "Example Operator CA")
	statuses := map[string]int{"a1": ocsp.Revoked, "a2": ocsp.Unknown}
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q, err := ocsp.ParseRequest(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		st, ok := statuses[operatorca.SerialKey(q.SerialNumber)]
		if !ok {
			st = ocsp.Good
		}
		tmpl := ocsp.Response{Status: st, SerialNumber: q.SerialNumber, IssuerHash: q.HashAlgorithm,
			ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(30 * time.Minute), RevokedAt: time.Now().Add(-time.Hour)}
		der, err := ocsp.CreateResponse(ca.cert, ca.cert, tmpl, ca.key)
		if err != nil {
			t.Errorf("responder: %v", err)
			return
		}
		_, _ = w.Write(der)
	}))
	defer responder.Close()

	st := newCredStore()
	anchor := ca.anchor(store.OperatorCAActive)
	anchor.OCSPMode, anchor.OCSPURL = store.OCSPModeURL, responder.URL
	rev := operatorca.NewRevocations(operatorca.RevocationOptions{Store: st, OCSPFetcher: operatorca.NewOCSPFetcher()})
	trust, err := operatorca.NewTrustStore(context.Background(), operatorca.Source{Kind: operatorca.KindFile, File: []operatorca.Anchor{anchor}}, st, rev, &tls.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rev.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc := New(st, noDial(t)).WithOperatorTrust(trust, rev)

	_, key := newCSR(t, "erin@example.org", false)
	record := func(serial int64) error {
		cert := ca.leaf(t, &key.PublicKey, "erin@example.org", "operator", serial)
		_, err := svc.RecordOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{CertDer: cert.Raw, FullName: "Erin Example"}))
		return err
	}
	requireReason(t, record(0xa1), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED_OCSP)
	requireReason(t, record(0xa2), apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNKNOWN)
	if err := record(0xa3); err != nil {
		t.Fatalf("a certificate the responder says is good was refused: %v", err)
	}
}
