package ctl

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1/fleetv1connect"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

const testNodeID = "01a19a92-71b1-781a-b953-77e84e2b57c6"

// fakeFleet answers the RPCs the CLI calls and records what it was asked.
type fakeFleet struct {
	fleetv1connect.UnimplementedFleetServiceHandler

	mu       sync.Mutex
	peerCN   string
	listNode *fleetv1.ListCertificatesRequest
	getNode  *fleetv1.GetNodeRequest
	issue    *fleetv1.IssueLeafRequest
	revoke   *fleetv1.RevokeCertificateRequest
	approve  *fleetv1.ApproveEnrollmentRequest
	reject   *fleetv1.RejectEnrollmentRequest
	decide   *fleetv1.DecideApprovalRequest
	status   string
}

func (f *fakeFleet) ListNodes(_ context.Context, _ *connect.Request[fleetv1.ListNodesRequest]) (*connect.Response[fleetv1.ListNodesResponse], error) {
	return connect.NewResponse(&fleetv1.ListNodesResponse{Nodes: []*fleetv1.NodeSummary{
		{Name: "issuing-1", Id: testNodeID, Role: "issuing", Address: "192.0.2.10:4443", Health: fleetv1.Health_HEALTH_UP},
	}}), nil
}

func (f *fakeFleet) GetNode(_ context.Context, req *connect.Request[fleetv1.GetNodeRequest]) (*connect.Response[fleetv1.GetNodeResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getNode = req.Msg
	return connect.NewResponse(&fleetv1.GetNodeResponse{Node: &fleetv1.NodeDetail{}}), nil
}

func (f *fakeFleet) WhoAmI(_ context.Context, _ *connect.Request[fleetv1.WhoAmIRequest]) (*connect.Response[fleetv1.WhoAmIResponse], error) {
	return connect.NewResponse(&fleetv1.WhoAmIResponse{Operator: &fleetv1.OperatorIdentity{Cn: "alice", Serial: "ab12", Level: "admin"}}), nil
}

func (f *fakeFleet) ListProfiles(_ context.Context, _ *connect.Request[fleetv1.ListProfilesRequest]) (*connect.Response[fleetv1.ListProfilesResponse], error) {
	return connect.NewResponse(&fleetv1.ListProfilesResponse{Items: []*nodev1.CertificateProfile{{Name: "web-server"}}}), nil
}

func (f *fakeFleet) ListCertificates(_ context.Context, req *connect.Request[fleetv1.ListCertificatesRequest]) (*connect.Response[fleetv1.ListCertificatesResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listNode = req.Msg
	return connect.NewResponse(&fleetv1.ListCertificatesResponse{Certificates: []*fleetv1.Certificate{
		{Serial: "0a0b", SubjectCn: "www.example.org", IssuerNode: "issuing-1", Status: "valid", NotAfter: "2027-01-01T00:00:00Z"},
	}}), nil
}

func (f *fakeFleet) GetCertificate(_ context.Context, _ *connect.Request[fleetv1.GetCertificateRequest]) (*connect.Response[fleetv1.GetCertificateResponse], error) {
	return connect.NewResponse(&fleetv1.GetCertificateResponse{CertificatePem: "LEAF-PEM\n", ChainPem: "CHAIN-PEM\n", Status: "valid"}), nil
}

func (f *fakeFleet) IssueLeaf(_ context.Context, req *connect.Request[fleetv1.IssueLeafRequest]) (*connect.Response[fleetv1.IssueLeafResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issue = req.Msg
	return connect.NewResponse(&fleetv1.IssueLeafResponse{CertDer: []byte("issued")}), nil
}

func (f *fakeFleet) RevokeCertificate(_ context.Context, req *connect.Request[fleetv1.RevokeCertificateRequest]) (*connect.Response[fleetv1.RevokeCertificateResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoke = req.Msg
	return connect.NewResponse(&fleetv1.RevokeCertificateResponse{SerialHex: req.Msg.GetSerialHex(), RevokedAt: "2026-11-02T00:00:00Z", ReasonCode: req.Msg.GetReasonCode()}), nil
}

func (f *fakeFleet) ListEnrollments(_ context.Context, _ *connect.Request[fleetv1.ListEnrollmentsRequest]) (*connect.Response[fleetv1.ListEnrollmentsResponse], error) {
	return connect.NewResponse(&fleetv1.ListEnrollmentsResponse{Items: []*fleetv1.EnrollmentRequest{
		{Id: "e1", ProposedName: "issuing-2", Kind: "LINK", Status: "PENDING", Address: "192.0.2.11:4443"},
	}}), nil
}

func (f *fakeFleet) ApproveEnrollment(_ context.Context, req *connect.Request[fleetv1.ApproveEnrollmentRequest]) (*connect.Response[fleetv1.ApproveEnrollmentResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approve = req.Msg
	return connect.NewResponse(&fleetv1.ApproveEnrollmentResponse{Enrollment: &fleetv1.EnrollmentRequest{Id: req.Msg.GetId(), Status: "APPROVED"}}), nil
}

func (f *fakeFleet) RejectEnrollment(_ context.Context, req *connect.Request[fleetv1.RejectEnrollmentRequest]) (*connect.Response[fleetv1.RejectEnrollmentResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reject = req.Msg
	return connect.NewResponse(&fleetv1.RejectEnrollmentResponse{Enrollment: &fleetv1.EnrollmentRequest{Id: req.Msg.GetId(), Status: "REJECTED"}}), nil
}

func (f *fakeFleet) ListApprovals(_ context.Context, req *connect.Request[fleetv1.ListApprovalsRequest]) (*connect.Response[fleetv1.ListApprovalsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = req.Msg.GetStatus()
	return connect.NewResponse(&fleetv1.ListApprovalsResponse{Items: []*fleetv1.Approval{
		{Id: "a1", Tool: "revoke_certificate", Summary: "Revoke 0a0b", Status: "pending", RequestedByCn: "agent"},
	}}), nil
}

func (f *fakeFleet) DecideApproval(_ context.Context, req *connect.Request[fleetv1.DecideApprovalRequest]) (*connect.Response[fleetv1.DecideApprovalResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decide = req.Msg
	return connect.NewResponse(&fleetv1.DecideApprovalResponse{Approval: &fleetv1.Approval{Id: req.Msg.GetId(), Status: "approved"}}), nil
}

// harness is a fake manager on mTLS and the flags that reach it.
type harness struct {
	fake  *fakeFleet
	flags []string
	dir   string
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(cn string, usage x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{"localhost"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: nil,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, k
	}

	serverDER, serverKey := leaf("localhost", x509.ExtKeyUsageServerAuth)
	clientDER, clientKey := leaf("alice", x509.ExtKeyUsageClientAuth)
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{fake: &fakeFleet{}, dir: dir}
	certPath, keyPath, caPath := filepath.Join(dir, "op.crt"), filepath.Join(dir, "op.key"), filepath.Join(dir, "ca.pem")
	writePEM(t, certPath, "CERTIFICATE", clientDER)
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
	writePEM(t, caPath, "CERTIFICATE", caDER)

	path, handler := fleetv1connect.NewFleetServiceHandler(h.fake)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) > 0 {
			h.fake.mu.Lock()
			h.fake.peerCN = r.TLS.PeerCertificates[0].Subject.CommonName
			h.fake.mu.Unlock()
		}
		handler.ServeHTTP(w, r)
	}))
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	addr := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	h.flags = []string{"--server", addr, "--cert", certPath, "--key", keyPath, "--ca", caPath}
	return h
}

func (h *harness) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := NewRootCommand(Streams{Out: &out, Err: &bytes.Buffer{}})
	cmd.SetArgs(append(append([]string{}, h.flags...), args...))
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func (h *harness) mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := h.run(t, args...)
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out
}

func contains(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Fatalf("output %q doesn't contain %q", got, w)
		}
	}
}

func TestWhoAmIPresentsTheOperatorCertificate(t *testing.T) {
	h := newHarness(t)
	contains(t, h.mustRun(t, "whoami"), "alice", "admin")
	if h.fake.peerCN != "alice" {
		t.Fatalf("server saw client CN %q", h.fake.peerCN)
	}
}

func TestNodes(t *testing.T) {
	h := newHarness(t)
	contains(t, h.mustRun(t, "nodes", "list"), "issuing-1", testNodeID, "issuing", "UP")

	h.mustRun(t, "nodes", "get", "issuing-1")
	if h.fake.getNode.GetName() != "issuing-1" || h.fake.getNode.GetNodeId() != "" {
		t.Fatalf("by name: %+v", h.fake.getNode)
	}
	h.mustRun(t, "nodes", "get", testNodeID)
	if h.fake.getNode.GetNodeId() != testNodeID || h.fake.getNode.GetName() != "" {
		t.Fatalf("by id: %+v", h.fake.getNode)
	}
}

func TestOutputFormats(t *testing.T) {
	h := newHarness(t)
	out := h.mustRun(t, "nodes", "list", "-o", "json")
	var got struct {
		Nodes []struct{ Name string } `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if len(got.Nodes) != 1 || got.Nodes[0].Name != "issuing-1" {
		t.Fatalf("got %+v", got)
	}
	contains(t, h.mustRun(t, "nodes", "list", "-o", "yaml"), "name: issuing-1")
	if _, err := h.run(t, "nodes", "list", "-o", "xml"); err == nil {
		t.Fatal("an unknown format was accepted")
	}
}

func TestCertificates(t *testing.T) {
	h := newHarness(t)
	contains(t, h.mustRun(t, "certs", "list", "--node", "issuing-1"), "0a0b", "www.example.org", "valid")
	if h.fake.listNode.GetNode() != "issuing-1" {
		t.Fatalf("list: %+v", h.fake.listNode)
	}
	contains(t, h.mustRun(t, "certs", "get", "--node", "issuing-1", "--serial", "0a0b"), "LEAF-PEM", "CHAIN-PEM")
}

func TestIssue(t *testing.T) {
	h := newHarness(t)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "www.example.org"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	csr := filepath.Join(h.dir, "req.csr")
	writePEM(t, csr, "CERTIFICATE REQUEST", der)

	out := h.mustRun(t, "certs", "issue", "--node", "issuing-1", "--profile", "web-server", "--csr", csr)
	if !bytes.Equal(h.fake.issue.GetCsrDer(), der) || h.fake.issue.GetProfileName() != "web-server" || h.fake.issue.GetNodeName() != "issuing-1" {
		t.Fatalf("issue: %+v", h.fake.issue)
	}
	block, _ := pem.Decode([]byte(out))
	if block == nil || block.Type != "CERTIFICATE" || string(block.Bytes) != "issued" {
		t.Fatalf("output isn't the issued PEM: %q", out)
	}

	rawDER := filepath.Join(h.dir, "req.der")
	if err := os.WriteFile(rawDER, der, 0o600); err != nil {
		t.Fatal(err)
	}
	h.mustRun(t, "certs", "issue", "--node", testNodeID, "--profile", "web-server", "--csr", rawDER)
	if !bytes.Equal(h.fake.issue.GetCsrDer(), der) || h.fake.issue.GetNodeId() != testNodeID {
		t.Fatalf("issue from DER: %+v", h.fake.issue)
	}

	junk := filepath.Join(h.dir, "junk")
	if err := os.WriteFile(junk, []byte("not a csr"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.fake.issue = nil
	if _, err := h.run(t, "certs", "issue", "--node", "n", "--profile", "p", "--csr", junk); err == nil || h.fake.issue != nil {
		t.Fatalf("a bad CSR reached the server: %v", err)
	}
}

func TestRevokeNeedsConfirmation(t *testing.T) {
	h := newHarness(t)
	args := []string{"certs", "revoke", "--node", "issuing-1", "--serial", "0a0b", "--reason", "1"}
	if _, err := h.run(t, args...); err == nil || h.fake.revoke != nil {
		t.Fatalf("revoke ran without --yes: %v", err)
	}
	contains(t, h.mustRun(t, append(args, "--yes")...), "0a0b")
	if h.fake.revoke.GetReasonCode() != 1 || h.fake.revoke.GetSerialHex() != "0a0b" {
		t.Fatalf("revoke: %+v", h.fake.revoke)
	}
}

func TestEnrollments(t *testing.T) {
	h := newHarness(t)
	contains(t, h.mustRun(t, "enrollments", "list"), "e1", "issuing-2", "LINK", "PENDING")

	admin := filepath.Join(h.dir, "admin.crt")
	adminKey := filepath.Join(h.dir, "admin.key")
	ca := filepath.Join(h.dir, "node-ca.pem")
	for p, body := range map[string]string{admin: "CERT", adminKey: "KEY", ca: "CA"} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	contains(t, h.mustRun(t, "enrollments", "approve", "e1", "--endpoint", "192.0.2.11:4443",
		"--admin-cert", admin, "--admin-key", adminKey, "--node-ca", ca), "APPROVED")
	got := h.fake.approve
	if got.GetId() != "e1" || got.GetNodeEndpoint() != "192.0.2.11:4443" || got.GetAdminCertPem() != "CERT" || got.GetAdminKeyPem() != "KEY" || got.GetCaPem() != "CA" {
		t.Fatalf("approve: %+v", got)
	}

	contains(t, h.mustRun(t, "enrollments", "reject", "e1", "--reason", "wrong site"), "REJECTED")
	if h.fake.reject.GetReason() != "wrong site" {
		t.Fatalf("reject: %+v", h.fake.reject)
	}
}

func TestApprovals(t *testing.T) {
	h := newHarness(t)
	contains(t, h.mustRun(t, "approvals", "list", "--status", "pending"), "a1", "revoke_certificate", "pending")
	if h.fake.status != "pending" {
		t.Fatalf("status = %q", h.fake.status)
	}
	h.mustRun(t, "approvals", "approve", "a1")
	if !h.fake.decide.GetApprove() {
		t.Fatalf("approve: %+v", h.fake.decide)
	}
	h.mustRun(t, "approvals", "deny", "a1")
	if h.fake.decide.GetApprove() {
		t.Fatalf("deny: %+v", h.fake.decide)
	}
}

func TestProfiles(t *testing.T) {
	h := newHarness(t)
	contains(t, h.mustRun(t, "profiles", "list"), "web-server")
}

func TestConnectionSettings(t *testing.T) {
	h := newHarness(t)

	var out bytes.Buffer
	cmd := NewRootCommand(Streams{Out: &out, Err: &bytes.Buffer{}})
	cmd.SetArgs([]string{"nodes", "list"})
	if err := cmd.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "--server") {
		t.Fatalf("no server: %v", err)
	}

	for i, name := range []string{EnvServer, EnvCert, EnvKey, EnvCA} {
		t.Setenv(name, h.flags[2*i+1])
	}
	cmd = NewRootCommand(Streams{Out: &out, Err: &bytes.Buffer{}})
	cmd.SetArgs([]string{"whoami"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("from the environment: %v", err)
	}

	bad := append([]string{}, h.flags...)
	bad[7] = bad[3] // the operator certificate is not the CA that signed the server
	h.flags = bad
	if _, err := h.run(t, "whoami"); err == nil {
		t.Fatal("a server the CA doesn't vouch for was accepted")
	}
}

func TestPlainHTTPIsRefused(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(Streams{Out: &out, Err: &bytes.Buffer{}})
	cmd.SetArgs([]string{"--server", "http://manager.example.org", "whoami"})
	if err := cmd.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v", err)
	}
}

func TestServerErrorsComeBack(t *testing.T) {
	h := newHarness(t)
	_, err := h.run(t, "certs", "list", "--node", "x", "--bad-flag")
	if err == nil {
		t.Fatal("a bad flag was accepted")
	}
	h2 := newHarness(t)
	_, err = h2.run(t, "enrollments", "approve", "e1", "--admin-cert", filepath.Join(h2.dir, "missing"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestVersion(t *testing.T) {
	h := newHarness(t)
	contains(t, h.mustRun(t, "version"), "cryptos-managerctl", "dev")
}
