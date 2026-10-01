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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/memory"
)

var oidLevel = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 1}

// testCA is an operator CA made for a test: the manager only ever sees its
// certificate; the key stays here to sign test leaves.
type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

var caSerial struct {
	sync.Mutex
	n int64
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSerial.Lock()
	caSerial.n++
	serial := caSerial.n
	caSerial.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key}
}

func (ca testCA) anchor(state string) operatorca.Anchor {
	return operatorca.Anchor{Cert: ca.cert, SHA256: operatorca.Fingerprint(ca.cert), State: state, FromConfig: true, CRLSource: store.CRLSourceNone}
}

// leaf signs an operator certificate for pub with the 4.2 profile: subject
// CN=<cn>, the level extension non-critical, EKU clientAuth, KU
// digitalSignature and CA:FALSE.
func (ca testCA) leaf(t *testing.T, pub crypto.PublicKey, cn, level string, serial int64) *x509.Certificate {
	t.Helper()
	_, value, err := authz.MarshalLevelExtension(level)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{Id: oidLevel, Value: value}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// newCSR makes a P-384 key (or P-256 when weak) and a CSR with subject
// CN=<cn>.
func newCSR(t *testing.T, cn string, weak bool) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	curve := elliptic.P384()
	if weak {
		curve = elliptic.P256()
	}
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

// credStore is the in-memory store with a working denylist and working
// credential requests, standing in for Postgres.
type credStore struct {
	*denylistStore
	mu       sync.Mutex
	requests map[string]store.OperatorCredentialRequest
	observed []store.OperatorCredential
}

func newCredStore() *credStore {
	return &credStore{denylistStore: &denylistStore{Store: memory.New(nil)}, requests: map[string]store.OperatorCredentialRequest{}}
}

func (c *credStore) expireLocked(now time.Time) {
	for id, r := range c.requests {
		if r.State == store.RequestPending && !now.Before(r.ExpiresAt) {
			r.State, r.CSRDER = store.RequestExpired, nil
			c.requests[id] = r
		}
	}
}

func (c *credStore) AddOperatorCredentialRequest(_ context.Context, r store.OperatorCredentialRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests[r.ID] = r
	return nil
}

func (c *credStore) OperatorCredentialRequests(_ context.Context, state string, now time.Time) ([]store.OperatorCredentialRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	var out []store.OperatorCredentialRequest
	for _, r := range c.requests {
		if state == "" || r.State == state {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (c *credStore) OperatorCredentialRequest(_ context.Context, id string, now time.Time) (store.OperatorCredentialRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	r, ok := c.requests[id]
	if !ok {
		return store.OperatorCredentialRequest{}, store.ErrRequestNotFound
	}
	return r, nil
}

func (c *credStore) CancelOperatorCredentialRequest(_ context.Context, id string, now time.Time) (store.OperatorCredentialRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	r, ok := c.requests[id]
	if !ok {
		return store.OperatorCredentialRequest{}, store.ErrRequestNotFound
	}
	if r.State != store.RequestPending {
		return r, store.ErrRequestNotPending
	}
	r.State, r.CSRDER = store.RequestCancelled, nil
	c.requests[id] = r
	return r, nil
}

func (c *credStore) RecordOperatorCredential(_ context.Context, cred store.OperatorCredential, requestID string, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	for _, have := range c.OperatorCredentials() {
		if have.IssuerSHA256 == cred.IssuerSHA256 && have.SerialHex == cred.SerialHex && have.Kind != store.OperatorCredentialObserved {
			return store.ErrCredentialRecorded
		}
	}
	if requestID != "" {
		r, ok := c.requests[requestID]
		if !ok {
			return store.ErrRequestNotFound
		}
		if r.State != store.RequestPending {
			return store.ErrRequestNotPending
		}
		r.State, r.CSRDER, r.CompletedSerial = store.RequestCompleted, nil, cred.SerialHex
		c.requests[requestID] = r
	}
	c.AddOperatorCredential(cred)
	return nil
}

func (c *credStore) ObserveOperatorCredential(_ context.Context, cred store.OperatorCredential, _ time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observed = append(c.observed, cred)
	return nil
}

// withAnchors wires a config-file operator CA source holding anchors over st.
func withAnchors(t *testing.T, svc *Service, st store.OperatorTrust, anchors ...operatorca.Anchor) (*Service, operatorca.PeerAuthorizer) {
	t.Helper()
	rev := operatorca.NewRevocations(operatorca.RevocationOptions{Store: st})
	trust, err := operatorca.NewTrustStore(context.Background(), operatorca.Source{Kind: operatorca.KindFile, File: anchors}, st, rev, &tls.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rev.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	return svc.WithOperatorTrust(trust, rev), operatorca.PeerAuthorizer{Trust: trust, Rev: rev}
}
