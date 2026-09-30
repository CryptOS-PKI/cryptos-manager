package mcpserver

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/approval"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/fleet"
	"github.com/CryptOS-PKI/manager/internal/mcpauth"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
)

// fakeNode is a CA node that answers the calls the phase-one tools make.
// Anything else hits the nil embedded interface and panics, which fails the
// test loudly.
type fakeNode struct {
	fleet.NodeConn

	role     string
	profiles []*cryptosv1.CertificateProfile

	mu      sync.Mutex
	issued  int
	revoked int
	applied int
}

func (f *fakeNode) GetConfig(context.Context) (*cryptosv1.GetConfigResponse, error) {
	return &cryptosv1.GetConfigResponse{Config: &cryptosv1.MachineConfig{
		Role: &cryptosv1.Role{Kind: f.role},
		Pki:  &cryptosv1.Pki{Profiles: f.profiles},
	}}, nil
}

func (f *fakeNode) IssueLeaf(_ context.Context, csrDER []byte, _ string) (*cryptosv1.IssueLeafResponse, error) {
	f.mu.Lock()
	f.issued++
	f.mu.Unlock()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: csr.Subject, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &cryptosv1.IssueLeafResponse{CertDer: der}, nil
}

func (f *fakeNode) RevokeCertificate(context.Context, string, int32) (*cryptosv1.RevokeCertificateResponse, error) {
	f.mu.Lock()
	f.revoked++
	f.mu.Unlock()
	return &cryptosv1.RevokeCertificateResponse{}, nil
}

func (f *fakeNode) ApplyConfig(context.Context, *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error) {
	f.mu.Lock()
	f.applied++
	f.mu.Unlock()
	return &cryptosv1.ApplyConfigResponse{Generation: 2}, nil
}

// changes counts every signing or configuration change the node was asked
// to make.
func (f *fakeNode) changes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issued + f.revoked + f.applied
}

func (f *fakeNode) issuedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issued
}

func (f *fakeNode) ListIssued(context.Context) (*cryptosv1.ListIssuedResponse, error) {
	return &cryptosv1.ListIssuedResponse{}, nil
}

func (f *fakeNode) ListRevocations(context.Context) (*cryptosv1.ListRevocationsResponse, error) {
	return &cryptosv1.ListRevocationsResponse{}, nil
}

func (f *fakeNode) GetStatus(context.Context) (*cryptosv1.GetStatusResponse, error) {
	return nil, errors.New("offline in tests")
}

func (f *fakeNode) GetIdentity(context.Context) (*cryptosv1.GetIdentityResponse, error) {
	return nil, errors.New("offline in tests")
}

func (f *fakeNode) Close() error { return nil }

var (
	leafProfile = &cryptosv1.CertificateProfile{Name: "tls-server", BasicConstraints: &cryptosv1.BasicConstraints{IsCa: false}}
	caProfile   = &cryptosv1.CertificateProfile{Name: "sub-ca", BasicConstraints: &cryptosv1.BasicConstraints{IsCa: true}}
)

// harness is a manager with the MCP endpoint mounted behind the key
// middleware on a real HTTP server, plus the operator CA that signs the
// operator certificates keys are bound to.
type harness struct {
	t         *testing.T
	st        *memory.Store
	nodes     map[string]*fakeNode
	caKey     *ecdsa.PrivateKey
	ca        *x509.Certificate
	srv       *httptest.Server
	approvals *approval.Service

	clockMu sync.Mutex
	now     time.Time
}

const testPublicURL = "https://fleetos.example.org"

// advance moves the approvals' clock forward.
func (h *harness) advance(d time.Duration) {
	h.clockMu.Lock()
	defer h.clockMu.Unlock()
	h.now = h.now.Add(d)
}

func (h *harness) clock() time.Time {
	h.clockMu.Lock()
	defer h.clockMu.Unlock()
	return h.now
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t}
	h.nodes = map[string]*fakeNode{
		"pki-root":    {role: "root", profiles: []*cryptosv1.CertificateProfile{leafProfile}},
		"pki-issuing": {role: "issuing", profiles: []*cryptosv1.CertificateProfile{leafProfile, caProfile}},
		// The inventory says issuing, but the node itself reports root: the
		// node's own config wins.
		"pki-liar": {role: "root", profiles: []*cryptosv1.CertificateProfile{leafProfile}},
	}
	catalogProfile, _ := proto.Marshal(leafProfile)
	h.st = memory.NewWithCatalog([]store.Node{
		{Name: "pki-root", Role: "root"},
		{Name: "pki-issuing", Role: "issuing"},
		{Name: "pki-liar", Role: "issuing"},
	}, []store.Profile{{Name: leafProfile.GetName(), Spec: catalogProfile}},
		[]store.Adapter{{Kind: "ACME", Name: "acme-web", Endpoint: "https://192.0.2.10/acme", Profile: "tls-server", Enabled: false}},
		nil, nil)
	svc := fleet.New(h.st, func(n store.Node) (fleet.NodeConn, error) { return h.nodes[n.Name], nil })

	h.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Operator CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &h.caKey.PublicKey, h.caKey)
	h.ca, _ = x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(h.ca)

	resolver := &mcpauth.Resolver{Store: h.st, Roots: pool, Revoked: noneRevoked{}}
	mux := http.NewServeMux()
	h.now = time.Now().UTC()
	h.approvals = &approval.Service{Store: h.st, Now: h.clock}
	mux.Handle("/mcp", mcpauth.Middleware(resolver, "")(Handler(svc, h.st, h.approvals, testPublicURL, "test")))
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

type noneRevoked struct{}

func (noneRevoked) IsRevoked(string) bool { return false }

// key mints a key for a fresh operator certificate at level with ceiling.
func (h *harness) key(level authz.Level, ceiling string) string {
	h.t.Helper()
	value, _ := asn1.Marshal(level.Token())
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "operator@example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 1}, Value: value}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, h.ca, &key.PublicKey, h.caKey)
	if err != nil {
		h.t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	owner, _ := authz.IdentityFromCertificate(cert)
	owner.Via = authz.ViaWeb
	plain, _, err := (&mcpauth.Keys{Store: h.st}).Mint(context.Background(), owner, der, "test", "harness", ceiling)
	if err != nil {
		h.t.Fatal(err)
	}
	return plain
}

type bearerTransport struct{ key string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.key)
	return http.DefaultTransport.RoundTrip(r)
}

// session connects a real MCP client with key.
func (h *harness) session(key string) *mcp.ClientSession {
	h.t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "1"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             h.srv.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: bearerTransport{key: key}},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
	if err != nil {
		h.t.Fatalf("connect: %v", err)
	}
	h.t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func (h *harness) call(cs *mcp.ClientSession, tool string, args map[string]any) *mcp.CallToolResult {
	h.t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		h.t.Fatalf("CallTool %s: %v", tool, err)
	}
	return res
}

func csrPEM(t *testing.T, isCA bool) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "svc.example.org"}, DNSNames: []string{"svc.example.org"}}
	if isCA {
		bc, _ := asn1.Marshal(struct {
			IsCA bool `asn1:"optional"`
		}{true})
		tmpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bc}}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func text(res *mcp.CallToolResult) string {
	var out string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			out += tc.Text
		}
	}
	return out
}
