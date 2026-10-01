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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/nodeclient"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/memory"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// detailSink records every streamed phase with its detail.
type detailSink struct {
	details []string
}

func (d *detailSink) send(phase, detail string, _ bool) error {
	d.details = append(d.details, phase+": "+detail)
	return nil
}

// readPEMCerts parses every certificate in the PEM file at path.
func readPEMCerts(t *testing.T, path string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out [][]byte
	for rest := b; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		out = append(out, block.Bytes)
	}
}

// rootIdentity is what an adopted root reports from GetIdentity once its
// ceremony is done: its self-signed CA certificate.
func rootIdentity(t *testing.T) *nodev1.GetIdentityResponse {
	t.Helper()
	return &nodev1.GetIdentityResponse{Identity: &nodev1.Identity{
		ChainDer: [][]byte{issuedLeafDER(t, "Example Root CA G1", "Example Root CA G1")},
	}}
}

// fakeRunningCert is the management certificate the installed node presents
// when it comes back in running mode.
func fakeRunningCert(t *testing.T) *x509.Certificate {
	t.Helper()
	der, cert, _ := signCert(t, "192.0.2.30", nil, nil)
	if !bytes.Equal(der, cert.Raw) {
		t.Fatal("signCert returned mismatched DER")
	}
	return cert
}

// confirmingSink wraps send and confirms the presented fingerprint as soon as
// the adoption under id asks for it, as an operator whose console matches.
func confirmingSink(t *testing.T, svc *Service, id string, send phaseSink) phaseSink {
	return func(phase, detail string, done bool) error {
		if err := send(phase, detail, done); err != nil {
			return err
		}
		if phase == phaseAwaitingFingerprint {
			if _, err := svc.ConfirmAdoptionFingerprint(operatorCtx("admin@example.org", authz.LevelAdmin),
				connect.NewRequest(&fleetv1.ConfirmAdoptionFingerprintRequest{AdoptionId: id, CertSha256: svc.adoptions.presented(id)})); err != nil {
				t.Errorf("ConfirmAdoptionFingerprint() error = %v", err)
			}
		}
		return nil
	}
}

// Adoption pins the certificate the installed node presents once the operator
// confirms its fingerprint against the console, and records the root's CA
// chain so the node is verified by its CA once its management certificate is
// CA-signed.
func TestRunAdoption_Root_PinsRunningCertAndRecordsCAChain(t *testing.T) {
	adoptCredsBaseDir = t.TempDir()
	st := memory.New(nil)
	running := fakeRunningCert(t)
	rootDER := issuedLeafDER(t, "Example Root CA G1", "Example Root CA G1")

	mconn := &fakeConn{applyConfigResp: &nodev1.ApplyConfigResponse{RequiresReboot: true, Generation: 1}}
	runningConn := &fakeConn{
		status:   &nodev1.GetStatusResponse{},
		identity: &nodev1.GetIdentityResponse{Identity: &nodev1.Identity{ChainDer: [][]byte{rootDER}}},
		ceremonyStream: &scriptedCeremony{kinds: []nodev1.CeremonyEventKind{
			nodev1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE,
		}},
	}
	var captured []string
	svc := New(st, dialFor(map[string]*fakeConn{"new-node": runningConn})).
		WithAdoption(nil, func(string, string, string, string) (NodeConn, error) { return mconn, nil }).
		WithServerCertCapture(func(n store.Node) (*x509.Certificate, error) {
			captured = append(captured, n.Endpoint)
			return running, nil
		})
	defer setRebootTiming(5*time.Millisecond, time.Millisecond, time.Millisecond)()

	sink := &detailSink{}
	if err := svc.runAdoptionAs(context.Background(), "adopt-root", &fleetv1.AdoptNodeRequest{
		Endpoint: "192.0.2.30:4443", PinnedCertSha256: "abc", Config: adoptConfig(),
	}, confirmingSink(t, svc, "adopt-root", sink.send)); err != nil {
		t.Fatalf("runAdoption() error = %v", err)
	}

	if len(captured) == 0 || captured[0] != "192.0.2.30:4443" {
		t.Fatalf("captured the running certificate from %v, want 192.0.2.30:4443", captured)
	}
	nodeDir := filepath.Join(adoptCredsBaseDir, "new-node")
	pins := readPEMCerts(t, filepath.Join(nodeDir, nodeclient.ServerCertFile))
	if len(pins) != 1 || !bytes.Equal(pins[0], running.Raw) {
		t.Errorf("server.crt = %d cert(s), want exactly the running certificate", len(pins))
	}
	sum := sha256.Sum256(running.Raw)
	if !strings.Contains(strings.Join(sink.details, "\n"), hex.EncodeToString(sum[:])) {
		t.Errorf("streamed details = %q, want the pinned fingerprint", sink.details)
	}

	n, ok := st.Node("new-node")
	if !ok {
		t.Fatal("adopted node not registered")
	}
	if want := filepath.Join(nodeDir, "ca.crt"); n.CACert != want {
		t.Errorf("node CACert = %q, want %q", n.CACert, want)
	}
	chain := readPEMCerts(t, n.CACert)
	if len(chain) != 1 || !bytes.Equal(chain[0], rootDER) {
		t.Errorf("recorded CA chain = %d cert(s), want the root from GetIdentity", len(chain))
	}
}

// A subordinate has no CA yet at adoption, so only the pin is recorded.
func TestRunAdoption_Subordinate_PinsRunningCertWithoutChain(t *testing.T) {
	adoptCredsBaseDir = t.TempDir()
	st := memory.New(nil)
	mconn := &fakeConn{applyConfigResp: &nodev1.ApplyConfigResponse{RequiresReboot: true, Generation: 1}}
	svc := New(st, dialFor(map[string]*fakeConn{"sub-node": {status: &nodev1.GetStatusResponse{}}})).
		WithAdoption(nil, func(string, string, string, string) (NodeConn, error) { return mconn, nil }).
		WithServerCertCapture(func(store.Node) (*x509.Certificate, error) { return fakeRunningCert(t), nil })
	defer setRebootTiming(5*time.Millisecond, time.Millisecond, time.Millisecond)()

	cfg := adoptConfig()
	cfg.Metadata.Name = "sub-node"
	cfg.Role = &nodev1.Role{Kind: "issuing"}
	if err := svc.runAdoptionAs(context.Background(), "adopt-sub", &fleetv1.AdoptNodeRequest{
		Endpoint: "192.0.2.31:4443", PinnedCertSha256: "abc", Config: cfg,
	}, confirmingSink(t, svc, "adopt-sub", (&detailSink{}).send)); err != nil {
		t.Fatalf("runAdoption() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(adoptCredsBaseDir, "sub-node", nodeclient.ServerCertFile)); err != nil {
		t.Errorf("server.crt not written for the subordinate: %v", err)
	}
	if n, _ := st.Node("sub-node"); n.CACert != "" {
		t.Errorf("subordinate CACert = %q at adoption, want empty (no CA yet)", n.CACert)
	}
}

// Until the node answers, capture keeps failing and adoption keeps waiting
// rather than pinning nothing and dialing unverified.
func TestRunAdoption_CaptureFails_KeepsWaitingThenErrors(t *testing.T) {
	adoptCredsBaseDir = t.TempDir()
	st := memory.New(nil)
	mconn := &fakeConn{applyConfigResp: &nodev1.ApplyConfigResponse{RequiresReboot: true}}
	dialed := false
	svc := New(st, func(store.Node) (NodeConn, error) {
		dialed = true
		return &fakeConn{status: &nodev1.GetStatusResponse{}}, nil
	}).
		WithAdoption(nil, func(string, string, string, string) (NodeConn, error) { return mconn, nil }).
		WithServerCertCapture(func(store.Node) (*x509.Certificate, error) { return nil, errors.New("connection refused") })
	defer setRebootTiming(5*time.Millisecond, time.Millisecond, time.Millisecond)()

	err := svc.runAdoption(context.Background(), &fleetv1.AdoptNodeRequest{
		Endpoint: "192.0.2.32:4443", PinnedCertSha256: "abc", Config: adoptConfig(),
	}, (&detailSink{}).send)
	if err == nil {
		t.Fatal("runAdoption() with a node that never answers: error = nil, want an error")
	}
	if dialed {
		t.Error("the node was dialed although its certificate could not be captured and pinned")
	}
}

func TestApproveEnrollment_Subordinate_RecordsChildCAChain(t *testing.T) {
	childDir := t.TempDir()
	childAdmin := filepath.Join(childDir, "admin.crt")
	chainDER := [][]byte{
		issuedLeafDER(t, "Example Issuing CA", "Example Root CA G1"),
		issuedLeafDER(t, "Example Root CA G1", "Example Root CA G1"),
	}
	parentConn := &fakeConn{signSubordinateResp: &nodev1.SignSubordinateCSRResponse{ChainDer: chainDER}}
	st := memory.NewWithCatalog(
		[]store.Node{
			{Name: "child-1", Endpoint: "192.0.2.41:4443", AdminCert: childAdmin, AdminKey: filepath.Join(childDir, "admin.key")},
			{Name: "parent-1", Endpoint: "192.0.2.40:4443"},
		},
		nil, nil, nil,
		[]store.Enrollment{{ID: "enr-1", Kind: "SUBORDINATE", Status: "PENDING", ProposedName: "child-1", ParentCN: "Example Root CA G1", Profile: "subordinate-ca"}},
	)
	parentIdentity := &fakeConn{identity: &nodev1.GetIdentityResponse{Identity: &nodev1.Identity{ChainDer: [][]byte{chainDER[1]}}}}
	childIdentity := &fakeConn{identity: &nodev1.GetIdentityResponse{Identity: &nodev1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "child-1", "child-1")}}}}
	dial := func(n store.Node) (NodeConn, error) {
		switch n.Name {
		case "child-1":
			return &routingConn{identity: childIdentity, ferry: &fakeConn{}}, nil
		case "parent-1":
			return &routingConn{identity: parentIdentity, ferry: parentConn}, nil
		}
		return nil, errors.New("no fake conn for " + n.Name)
	}
	svc := New(st, dial).WithEnrollment(dialPEMFakeFor(&fakeConn{}))

	if _, err := svc.ApproveEnrollment(operatorCtx("op@example.org", authz.LevelOperator),
		connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{Id: "enr-1"})); err != nil {
		t.Fatalf("ApproveEnrollment() error = %v", err)
	}

	child, _ := st.Node("child-1")
	if want := filepath.Join(childDir, "ca.crt"); child.CACert != want {
		t.Fatalf("child CACert = %q, want %q", child.CACert, want)
	}
	got := readPEMCerts(t, child.CACert)
	if len(got) != 2 || !bytes.Equal(got[0], chainDER[0]) || !bytes.Equal(got[1], chainDER[1]) {
		t.Errorf("recorded child chain = %d cert(s), want the signed chain leaf-first", len(got))
	}
}

// A node whose caCertPath the operator set in the config keeps it: the
// manager never overwrites operator-managed trust.
func TestRecordCAChain_KeepsOperatorManagedPath(t *testing.T) {
	dir := t.TempDir()
	n := store.Node{Name: "cfg-node", AdminCert: filepath.Join(dir, "admin.crt"), CACert: "/etc/cryptos/fleet/cfg-node/ca.pem"}
	got, recorded, err := recordCAChain(n, [][]byte{issuedLeafDER(t, "Example Root CA G1", "Example Root CA G1")})
	if err != nil {
		t.Fatalf("recordCAChain() error = %v", err)
	}
	if recorded || got.CACert != n.CACert {
		t.Errorf("recordCAChain() = (%q, %t), want the operator's path kept and nothing recorded", got.CACert, recorded)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.crt")); !os.IsNotExist(err) {
		t.Errorf("recordCAChain() wrote ca.crt for an operator-managed node (stat err %v)", err)
	}
}

func TestListNodes_InsecureNodeFlaggedUnverified(t *testing.T) {
	st := memory.New([]store.Node{
		{Name: "lab-node", Endpoint: "192.0.2.50:4443"},
		{Name: "prod-node", Endpoint: "192.0.2.51:4443"},
	})
	up := func() *fakeConn {
		return &fakeConn{status: &nodev1.GetStatusResponse{Status: &nodev1.NodeStatus{}}}
	}
	svc := New(st, dialFor(map[string]*fakeConn{"lab-node": up(), "prod-node": up()})).
		WithUnverifiedNodes(func(n store.Node) bool { return n.Name == "lab-node" })

	resp, err := svc.ListNodes(context.Background(), connect.NewRequest(&fleetv1.ListNodesRequest{}))
	if err != nil {
		t.Fatalf("ListNodes() error = %v", err)
	}
	for _, s := range resp.Msg.GetNodes() {
		flagged := strings.Contains(s.GetHealthDetail(), "insecureSkipNodeVerify")
		if s.GetName() == "lab-node" && (!flagged || s.GetHealth() != fleetv1.Health_HEALTH_UP) {
			t.Errorf("lab-node = health %v detail %q, want UP and flagged unverified", s.GetHealth(), s.GetHealthDetail())
		}
		if s.GetName() == "prod-node" && flagged {
			t.Errorf("prod-node detail = %q, want it not flagged", s.GetHealthDetail())
		}
	}
}
