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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/nodeclient"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/memory"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// linkCAPEM is the CA certificate a LINK request names as ca_pem.
func linkCAPEM(t *testing.T) string {
	t.Helper()
	der, _, _ := signCert(t, "Example Root CA G1", nil, nil)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// linkServerCertPEM is a self-signed, non-CA management certificate, as a
// node presents before its CA ceremony; given as ca_pem it acts as a pin.
func linkServerCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "192.0.2.10"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// linkFixture creates a PENDING LINK enrollment for a node whose identity
// leaf is cn and returns the service, store and enrollment id.
func linkFixture(t *testing.T, cn, endpoint, caPEM string) (*Service, store.Store, string, *ecdsa.PrivateKey) {
	t.Helper()
	adoptCredsBaseDir = t.TempDir()
	key := mustKey(t)
	identity := &nodev1.GetIdentityResponse{Identity: &nodev1.Identity{ChainDer: [][]byte{issuedLeafDER(t, cn, cn)}}}
	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{attestKey: key, identity: identity}))
	resp, err := svc.CreateEnrollment(operatorCtx("op@example.org", authz.LevelOperator), connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind: "LINK", NodeEndpoint: endpoint, AdminCertPem: "admin-cert-pem", AdminKeyPem: "admin-key-pem", CaPem: caPEM,
	}))
	if err != nil {
		t.Fatalf("CreateEnrollment(LINK): %v", err)
	}
	return svc, st, resp.Msg.GetEnrollment().GetId(), key
}

func approveLink(svc *Service, id, endpoint, caPEM string) (*connect.Response[fleetv1.ApproveEnrollmentResponse], error) {
	return svc.ApproveEnrollment(operatorCtx("admin@example.org", authz.LevelAdmin), connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{
		Id: id, NodeEndpoint: endpoint, AdminCertPem: "admin-cert-pem", AdminKeyPem: "admin-key-pem", CaPem: caPEM,
	}))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestCreateEnrollment_Link_RequiresCAPEM(t *testing.T) {
	dialed := false
	svc := New(memory.New(nil), dialFor(nil)).WithEnrollment(func(string, string, string, string) (NodeConn, error) {
		dialed = true
		return &fakeConn{}, nil
	})
	_, err := svc.CreateEnrollment(operatorCtx("op@example.org", authz.LevelOperator), connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind: "LINK", NodeEndpoint: "192.0.2.10:443", AdminCertPem: "cert", AdminKeyPem: "key",
	}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	requireAppCode(t, err, apperr.CodeLinkCARequired)
	if dialed {
		t.Error("the node was dialled without a ca_pem to verify it against")
	}
}

func TestCreateEnrollment_Link_RefusesAnUnverifiedNode(t *testing.T) {
	st := memory.New(nil)
	svc := New(st, dialFor(nil)).WithEnrollment(func(string, string, string, string) (NodeConn, error) {
		return nil, fmt.Errorf("refused: %w", nodeclient.ErrNodeUntrusted)
	})
	_, err := svc.CreateEnrollment(operatorCtx("op@example.org", authz.LevelOperator), connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind: "LINK", NodeEndpoint: "192.0.2.10:443", AdminCertPem: "cert", AdminKeyPem: "key", CaPem: linkCAPEM(t),
	}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
	requireAppCode(t, err, apperr.CodeNodeUntrusted)
	if n := len(st.Enrollments()); n != 0 {
		t.Errorf("enrollments = %d, want none recorded for a refused node", n)
	}
}

func TestCreateEnrollment_Link_UnreachableNode(t *testing.T) {
	svc := New(memory.New(nil), dialFor(nil)).WithEnrollment(func(string, string, string, string) (NodeConn, error) {
		return nil, fmt.Errorf("%w: connection refused", nodeclient.ErrNodeUnreachable)
	})
	_, err := svc.CreateEnrollment(operatorCtx("op@example.org", authz.LevelOperator), connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind: "LINK", NodeEndpoint: "192.0.2.10:443", AdminCertPem: "cert", AdminKeyPem: "key", CaPem: linkCAPEM(t),
	}))
	requireConnectCode(t, err, connect.CodeUnavailable)
	requireAppCode(t, err, apperr.CodeNodeUnreachable)
}

func TestApproveEnrollment_Link_RefusesAnUnverifiedNode(t *testing.T) {
	caPEM := linkCAPEM(t)
	svc, st, id, _ := linkFixture(t, "Example Root CA G1", "192.0.2.10:443", caPEM)
	svc.dialPEM = func(string, string, string, string) (NodeConn, error) {
		return nil, fmt.Errorf("refused: %w", nodeclient.ErrNodeUntrusted)
	}

	_, err := approveLink(svc, id, "192.0.2.10:443", caPEM)
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
	requireAppCode(t, err, apperr.CodeNodeUntrusted)
	if e, _ := st.Enrollment(id); e.Status != "PENDING" {
		t.Errorf("enrollment status = %q, want PENDING", e.Status)
	}
	if n := len(st.Nodes()); n != 0 {
		t.Errorf("inventory = %d node(s), want none", n)
	}
}

func TestApproveEnrollment_Link_RequiresCAPEM(t *testing.T) {
	svc, _, id, _ := linkFixture(t, "Example Root CA G1", "192.0.2.10:443", linkCAPEM(t))
	_, err := approveLink(svc, id, "192.0.2.10:443", "")
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	requireAppCode(t, err, apperr.CodeLinkCARequired)
}

func TestApproveEnrollment_Link_RegistersTheNode(t *testing.T) {
	caPEM := linkCAPEM(t)
	svc, st, id, key := linkFixture(t, "Example Root CA G1", "192.0.2.10:443", caPEM)
	approveConn := &fakeConn{attestKey: key, getConfigResp: &nodev1.GetConfigResponse{Config: &nodev1.MachineConfig{Role: &nodev1.Role{Kind: "root"}}}}
	svc.dialPEM = dialPEMFakeFor(approveConn)

	resp, err := approveLink(svc, id, "192.0.2.10:443", caPEM)
	if err != nil {
		t.Fatalf("ApproveEnrollment(LINK): %v", err)
	}
	enr := resp.Msg.GetEnrollment()

	n, ok := st.NodeByID(enr.GetAdmittedNodeId())
	if !ok {
		t.Fatalf("admitted node %s is not in the inventory", enr.GetAdmittedNodeId())
	}
	if n.Name != "example-root-ca-g1" || enr.GetAdmittedNodeName() != n.Name {
		t.Errorf("node name = %q (admitted %q), want example-root-ca-g1 for both", n.Name, enr.GetAdmittedNodeName())
	}
	if n.Endpoint != "192.0.2.10:443" || n.Role != "root" {
		t.Errorf("node = %+v, want endpoint 192.0.2.10:443 and role root", n)
	}
	dir := filepath.Join(adoptCredsBaseDir, n.Name)
	if n.AdminCert != filepath.Join(dir, "admin.crt") || n.AdminKey != filepath.Join(dir, "admin.key") {
		t.Errorf("admin paths = %q, %q, want admin.crt and admin.key in %s", n.AdminCert, n.AdminKey, dir)
	}
	if readFile(t, n.AdminCert) != "admin-cert-pem" || readFile(t, n.AdminKey) != "admin-key-pem" {
		t.Error("the saved admin credential is not the one the request supplied")
	}
	if n.CACert != filepath.Join(dir, caChainFile) || readFile(t, n.CACert) != caPEM {
		t.Errorf("CACert = %q, want ca_pem recorded at %s", n.CACert, filepath.Join(dir, caChainFile))
	}
	if _, err := os.Stat(filepath.Join(dir, nodeclient.ServerCertFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a pin was written for a node verified by its CA (stat err %v)", err)
	}

	list, err := svc.ListNodes(operatorCtx("viewer@example.org", authz.LevelViewer), connect.NewRequest(&fleetv1.ListNodesRequest{}))
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(list.Msg.GetNodes()) != 1 || list.Msg.GetNodes()[0].GetId() != n.ID {
		t.Errorf("ListNodes = %v, want the linked node", list.Msg.GetNodes())
	}
}

// A ca_pem holding the node's own (non-CA) management certificate is a pin:
// it is saved as the node's pinned server certificate, not as a CA chain.
func TestApproveEnrollment_Link_PinnedCertIsSavedAsThePin(t *testing.T) {
	pinPEM := linkServerCertPEM(t)
	svc, st, id, key := linkFixture(t, "Example Root CA G1", "192.0.2.10:443", pinPEM)
	svc.dialPEM = dialPEMFakeFor(&fakeConn{attestKey: key})

	resp, err := approveLink(svc, id, "192.0.2.10:443", pinPEM)
	if err != nil {
		t.Fatalf("ApproveEnrollment(LINK): %v", err)
	}
	n, _ := st.NodeByID(resp.Msg.GetEnrollment().GetAdmittedNodeId())
	if n.CACert != "" {
		t.Errorf("CACert = %q, want none for a pinned node", n.CACert)
	}
	if got := readFile(t, nodeclient.PinPath(n)); got != pinPEM {
		t.Errorf("pin = %q, want the ca_pem certificate", got)
	}
}

func TestApproveEnrollment_Link_NameTakenByAnotherNode(t *testing.T) {
	caPEM := linkCAPEM(t)
	svc, st, id, key := linkFixture(t, "Example Root CA G1", "192.0.2.10:443", caPEM)
	st.AddNode(store.Node{Name: "example-root-ca-g1", Endpoint: "192.0.2.99:443"})
	approveConn := &fakeConn{attestKey: key}
	svc.dialPEM = dialPEMFakeFor(approveConn)

	_, err := approveLink(svc, id, "192.0.2.10:443", caPEM)
	requireConnectCode(t, err, connect.CodeAlreadyExists)
	requireAppCode(t, err, apperr.CodeNodeNameTaken)
	if approveConn.gotManagement != nil {
		t.Error("SetManagement was pushed although the node could not be registered")
	}
	if e, _ := st.Enrollment(id); e.Status != "PENDING" {
		t.Errorf("enrollment status = %q, want PENDING", e.Status)
	}
}

// A node already in the inventory at the same endpoint keeps its entry and
// ID; nothing it already holds is overwritten.
func TestApproveEnrollment_Link_AlreadyInventoriedByEndpoint(t *testing.T) {
	caPEM := linkCAPEM(t)
	svc, st, id, key := linkFixture(t, "Example Root CA G1", "192.0.2.10:443", caPEM)
	st.AddNode(store.Node{Name: "pki-root", Endpoint: "192.0.2.10:443", AdminCert: "/etc/cryptos/fleet/pki-root/admin.crt"})
	want := nodeID(t, st, "pki-root")
	svc.dialPEM = dialPEMFakeFor(&fakeConn{attestKey: key})

	resp, err := approveLink(svc, id, "192.0.2.10:443", caPEM)
	if err != nil {
		t.Fatalf("ApproveEnrollment(LINK): %v", err)
	}
	if got := resp.Msg.GetEnrollment().GetAdmittedNodeId(); got != want {
		t.Errorf("admitted node id = %q, want the inventoried node's %q", got, want)
	}
	if n := len(st.Nodes()); n != 1 {
		t.Errorf("inventory = %d node(s), want 1", n)
	}
	if n, _ := st.Node("pki-root"); n.AdminCert != "/etc/cryptos/fleet/pki-root/admin.crt" {
		t.Errorf("AdminCert = %q, want the existing credential kept", n.AdminCert)
	}
}

func TestLinkNodeName(t *testing.T) {
	for _, tc := range []struct{ cn, endpoint, want string }{
		{"Example Root CA G1 (lab)", "192.0.2.10:443", "example-root-ca-g1-lab"},
		{"pki-inter", "192.0.2.11:443", "pki-inter"},
		{"", "192.0.2.12:443", "node-192-0-2-12"},
		{"***", "node.example.org:443", "node-node-example-org"},
	} {
		if got := linkNodeName(tc.cn, tc.endpoint); got != tc.want {
			t.Errorf("linkNodeName(%q, %q) = %q, want %q", tc.cn, tc.endpoint, got, tc.want)
		}
		if err := validateNodeName(linkNodeName(tc.cn, tc.endpoint)); err != nil {
			t.Errorf("linkNodeName(%q, %q) is not a valid node name: %v", tc.cn, tc.endpoint, err)
		}
	}
}
