package fleet

/*
Apache License 2.0

Copyright 2026 Shane

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
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/nodeclient"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

// fakeConn is a canned NodeConn used to drive Service without a real dial.
type fakeConn struct {
	status      *cryptosv1.GetStatusResponse
	disks       *cryptosv1.ListInstallDisksResponse
	identity    *cryptosv1.GetIdentityResponse
	issued      *cryptosv1.ListIssuedResponse
	revocations *cryptosv1.ListRevocationsResponse
	err         error
	closed      bool

	// attestKey, when set, makes Attest sign the nonce for real (mirroring
	// the node's CA-identity signer) instead of returning a zero response.
	attestKey *ecdsa.PrivateKey
	// attestBadSig makes Attest sign a digest that does NOT match the
	// nonce it was given, so verifyAttestation must reject the signature.
	attestBadSig bool
	// gotNonce records the nonce the fake received, so a test can assert
	// verifyAttestation actually sent one.
	gotNonce []byte

	// gotManagement records the Management the fake received via
	// SetManagement, so a test can assert what a LINK approval pushed.
	gotManagement *cryptosv1.Management
	// gotCSRProfile records the profile name SignSubordinateCSR was called
	// with, so a test can assert the ferry used the enrollment's profile.
	gotCSRProfile string
	// signSubordinateResp, when set, is returned by SignSubordinateCSR
	// instead of the zero-value response.
	signSubordinateResp *cryptosv1.SignSubordinateCSRResponse
	// calls records the ordered sequence of ferry-relevant method names
	// invoked on this fake, so a test can assert call order.
	calls *[]string

	// gotRevokeSerial and gotRevokeReason record the serial and reason code
	// RevokeCertificate was called with, so a test can assert the handler
	// forwarded them to the node unchanged.
	gotRevokeSerial string
	gotRevokeReason int32
	// revokeResp, when set, is returned by RevokeCertificate instead of the
	// zero-value response.
	revokeResp *cryptosv1.RevokeCertificateResponse

	// gotIssueCSR and gotIssueProfile record the CSR and profile name
	// IssueLeaf was called with, so a test can assert the handler forwarded
	// them to the node unchanged.
	gotIssueCSR     []byte
	gotIssueProfile string
	// issueResp, when set, is returned by IssueLeaf instead of the
	// zero-value response.
	issueResp *cryptosv1.IssueLeafResponse

	// beginRotationResp, when set, is returned by BeginKeyRotation instead of
	// the zero-value response (the re-key ferry reads its CSR).
	beginRotationResp *cryptosv1.BeginKeyRotationResponse
	// gotCompleteChainDER and gotCompleteChainPEM record the chain
	// CompleteKeyRotation was called with, so a re-key test can assert the
	// ferry delivered the parent-signed chain unchanged.
	gotCompleteChainDER [][]byte
	gotCompleteChainPEM string
	// completeRotationResp, when set, is returned by CompleteKeyRotation
	// instead of the zero-value response (it carries the adopted identity).
	completeRotationResp *cryptosv1.CompleteKeyRotationResponse

	// gotExportPassphrase records the passphrase ExportCAKey was called with,
	// so an escrow test can assert the handler relayed it to the node and that
	// the audit never contains it.
	gotExportPassphrase []byte
	// exportResp, when set, is returned by ExportCAKey instead of the
	// zero-value response (it carries the encrypted envelope).
	exportResp *cryptosv1.ExportCAKeyResponse

	// gotImportEnvelope and gotImportPassphrase record the envelope and
	// passphrase ImportCAKey was called with, so an escrow test can assert the
	// handler relayed them to the node unchanged.
	gotImportEnvelope   []byte
	gotImportPassphrase []byte
	// importResp, when set, is returned by ImportCAKey instead of the
	// zero-value response (it carries the restored identity).
	importResp *cryptosv1.ImportCAKeyResponse

	// gotRemoteResetCN records the confirmation CN RemoteReset was called with,
	// so a decommission test can assert the handler relayed it unchanged.
	gotRemoteResetCN string
	// remoteResetErr, when set, is returned by RemoteReset (e.g. a gRPC
	// PermissionDenied for a CN mismatch); remoteResetResp is the success reply.
	remoteResetErr  error
	remoteResetResp *cryptosv1.RemoteResetResponse

	// gotCeremonyYAML records the config YAML StartCeremony was called with;
	// ceremonyStream, when set, is the stream it returns (an adoption test
	// feeds it a scripted event sequence). ceremonyErr fails StartCeremony.
	gotCeremonyYAML []byte
	ceremonyStream  nodeclient.CeremonyStream
	ceremonyErr     error

	// getConfigResp, when set, is returned by GetConfig instead of the
	// zero-value response (the config-push flow fetches the node's baseline).
	getConfigResp *cryptosv1.GetConfigResponse
	// gotApplyConfig records the MachineConfig ApplyConfig was called with, so
	// a test can assert the handler pushed the exact config from the request.
	gotApplyConfig *cryptosv1.MachineConfig
	// applyConfigResp, when set, is returned by ApplyConfig instead of the
	// zero-value response (it carries the generation and requires_reboot).
	applyConfigResp *cryptosv1.ApplyConfigResponse
}

func (f *fakeConn) BeginKeyRotation(context.Context) (*cryptosv1.BeginKeyRotationResponse, error) {
	f.record("BeginKeyRotation")
	if f.err != nil {
		return nil, f.err
	}
	if f.beginRotationResp != nil {
		return f.beginRotationResp, nil
	}
	return &cryptosv1.BeginKeyRotationResponse{}, nil
}

func (f *fakeConn) CompleteKeyRotation(_ context.Context, chainDER [][]byte, chainPEM string) (*cryptosv1.CompleteKeyRotationResponse, error) {
	f.record("CompleteKeyRotation")
	f.gotCompleteChainDER = chainDER
	f.gotCompleteChainPEM = chainPEM
	if f.err != nil {
		return nil, f.err
	}
	if f.completeRotationResp != nil {
		return f.completeRotationResp, nil
	}
	return &cryptosv1.CompleteKeyRotationResponse{}, nil
}

func (f *fakeConn) GetStatus(context.Context) (*cryptosv1.GetStatusResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.status, nil
}

func (f *fakeConn) ListInstallDisks(context.Context) (*cryptosv1.ListInstallDisksResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.disks, nil
}

func (f *fakeConn) GetIdentity(context.Context) (*cryptosv1.GetIdentityResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.identity, nil
}

func (f *fakeConn) ListIssued(context.Context) (*cryptosv1.ListIssuedResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.issued, nil
}

func (f *fakeConn) ListRevocations(context.Context) (*cryptosv1.ListRevocationsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.revocations, nil
}

func (f *fakeConn) Attest(_ context.Context, nonce []byte) (*cryptosv1.AttestResponse, error) {
	f.gotNonce = nonce
	if f.err != nil {
		return nil, f.err
	}
	if f.attestKey == nil {
		return &cryptosv1.AttestResponse{}, nil
	}
	signed := nonce
	if f.attestBadSig {
		// Sign different bytes than the nonce so the signature is valid
		// ASN.1 but does not verify against the nonce's digest.
		signed = append([]byte("wrong-bytes-"), nonce...)
	}
	digest := sha512.Sum384(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, f.attestKey, digest[:])
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&f.attestKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &cryptosv1.AttestResponse{
		Signature:      sig,
		IdentityPubDer: pubDER,
	}, nil
}

func (f *fakeConn) GetSubordinateCSR(context.Context) (*cryptosv1.GetSubordinateCSRResponse, error) {
	f.record("GetSubordinateCSR")
	if f.err != nil {
		return nil, f.err
	}
	return &cryptosv1.GetSubordinateCSRResponse{}, nil
}

func (f *fakeConn) SignSubordinateCSR(_ context.Context, _ []byte, profile string) (*cryptosv1.SignSubordinateCSRResponse, error) {
	f.record("SignSubordinateCSR")
	f.gotCSRProfile = profile
	if f.err != nil {
		return nil, f.err
	}
	if f.signSubordinateResp != nil {
		return f.signSubordinateResp, nil
	}
	return &cryptosv1.SignSubordinateCSRResponse{}, nil
}

func (f *fakeConn) SubmitSubordinateCertificate(context.Context, [][]byte, string) (*cryptosv1.SubmitSubordinateCertificateResponse, error) {
	f.record("SubmitSubordinateCertificate")
	if f.err != nil {
		return nil, f.err
	}
	return &cryptosv1.SubmitSubordinateCertificateResponse{}, nil
}

func (f *fakeConn) ApplyConfig(_ context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error) {
	f.gotApplyConfig = cfg
	if f.err != nil {
		return nil, f.err
	}
	if f.applyConfigResp != nil {
		return f.applyConfigResp, nil
	}
	return &cryptosv1.ApplyConfigResponse{}, nil
}

func (f *fakeConn) GetConfig(context.Context) (*cryptosv1.GetConfigResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.getConfigResp != nil {
		return f.getConfigResp, nil
	}
	return &cryptosv1.GetConfigResponse{}, nil
}

func (f *fakeConn) SetManagement(_ context.Context, m *cryptosv1.Management) (*cryptosv1.SetManagementResponse, error) {
	f.gotManagement = m
	if f.err != nil {
		return nil, f.err
	}
	return &cryptosv1.SetManagementResponse{}, nil
}

func (f *fakeConn) RevokeCertificate(_ context.Context, serialHex string, reasonCode int32) (*cryptosv1.RevokeCertificateResponse, error) {
	f.gotRevokeSerial = serialHex
	f.gotRevokeReason = reasonCode
	if f.err != nil {
		return nil, f.err
	}
	if f.revokeResp != nil {
		return f.revokeResp, nil
	}
	return &cryptosv1.RevokeCertificateResponse{}, nil
}

func (f *fakeConn) IssueLeaf(_ context.Context, csrDER []byte, profileName string) (*cryptosv1.IssueLeafResponse, error) {
	f.gotIssueCSR = csrDER
	f.gotIssueProfile = profileName
	if f.err != nil {
		return nil, f.err
	}
	if f.issueResp != nil {
		return f.issueResp, nil
	}
	return &cryptosv1.IssueLeafResponse{}, nil
}

func (f *fakeConn) ExportCAKey(_ context.Context, passphrase []byte) (*cryptosv1.ExportCAKeyResponse, error) {
	f.gotExportPassphrase = passphrase
	if f.err != nil {
		return nil, f.err
	}
	if f.exportResp != nil {
		return f.exportResp, nil
	}
	return &cryptosv1.ExportCAKeyResponse{}, nil
}

func (f *fakeConn) ImportCAKey(_ context.Context, envelope, passphrase []byte) (*cryptosv1.ImportCAKeyResponse, error) {
	f.gotImportEnvelope = envelope
	f.gotImportPassphrase = passphrase
	if f.err != nil {
		return nil, f.err
	}
	if f.importResp != nil {
		return f.importResp, nil
	}
	return &cryptosv1.ImportCAKeyResponse{}, nil
}

func (f *fakeConn) RemoteReset(_ context.Context, confirmCN string) (*cryptosv1.RemoteResetResponse, error) {
	f.record("RemoteReset")
	f.gotRemoteResetCN = confirmCN
	if f.remoteResetErr != nil {
		return nil, f.remoteResetErr
	}
	if f.remoteResetResp != nil {
		return f.remoteResetResp, nil
	}
	return &cryptosv1.RemoteResetResponse{Rebooting: true}, nil
}

func (f *fakeConn) StartCeremony(_ context.Context, _ cryptosv1.CeremonyKind, machineConfigYAML []byte) (nodeclient.CeremonyStream, error) {
	f.record("StartCeremony")
	f.gotCeremonyYAML = machineConfigYAML
	if f.ceremonyErr != nil {
		return nil, f.ceremonyErr
	}
	return f.ceremonyStream, nil
}

// record appends name to the shared call log, if this fake was given one.
// Used by the SUBORDINATE ferry tests to assert child/parent call order.
func (f *fakeConn) record(name string) {
	if f.calls != nil {
		*f.calls = append(*f.calls, name)
	}
}

func (f *fakeConn) Close() error {
	f.closed = true
	return nil
}

func testStore() store.Store {
	return memory.New([]store.Node{
		{
			Name:     "A",
			Endpoint: "a.acme.com:4443",
			Role:     "root",
		},
		{
			Name:     "B",
			Endpoint: "b.acme.com:4444",
			Role:     "intermediate",
		},
	})
}

// dialFor returns a dial func that hands back conns keyed by node name, and
// records which conns it produced so a test can assert Close() was called.
func dialFor(conns map[string]*fakeConn) func(store.Node) (NodeConn, error) {
	return func(n store.Node) (NodeConn, error) {
		c, ok := conns[n.Name]
		if !ok {
			return nil, errors.New("dialFor: no fake conn for " + n.Name)
		}
		return c, nil
	}
}

func TestListNodes_PerNodeDegradation(t *testing.T) {
	connA := &fakeConn{
		status: &cryptosv1.GetStatusResponse{
			Status: &cryptosv1.NodeStatus{
				Role:          cryptosv1.NodeRole_NODE_ROLE_ROOT,
				IdentityState: cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED,
			},
		},
	}
	connB := &fakeConn{err: errors.New("dial refused")}

	svc := New(testStore(), dialFor(map[string]*fakeConn{"A": connA, "B": connB}))

	resp, err := svc.ListNodes(context.Background(), connect.NewRequest(&fleetv1.ListNodesRequest{}))
	if err != nil {
		t.Fatalf("ListNodes() error = %v, want nil", err)
	}

	nodes := resp.Msg.GetNodes()
	if len(nodes) != 2 {
		t.Fatalf("len(nodes) = %d, want 2", len(nodes))
	}

	byName := map[string]*fleetv1.NodeSummary{}
	for _, n := range nodes {
		byName[n.GetName()] = n
	}

	a := byName["A"]
	if a == nil {
		t.Fatal("missing summary for A")
	}
	if a.GetHealth() != fleetv1.Health_HEALTH_UP {
		t.Errorf("A.Health = %v, want HEALTH_UP", a.GetHealth())
	}
	if a.GetRole() != "root" {
		t.Errorf("A.Role = %q, want root", a.GetRole())
	}
	if a.GetIdentityState() != "ESTABLISHED" {
		t.Errorf("A.IdentityState = %q, want ESTABLISHED", a.GetIdentityState())
	}

	b := byName["B"]
	if b == nil {
		t.Fatal("missing summary for B")
	}
	if b.GetHealth() != fleetv1.Health_HEALTH_DOWN {
		t.Errorf("B.Health = %v, want HEALTH_DOWN", b.GetHealth())
	}
	if b.GetHealthDetail() == "" {
		t.Error("B.HealthDetail is empty, want the dial error text")
	}

	if !connA.closed {
		t.Error("connA was not closed")
	}
	if !connB.closed {
		t.Error("connB dial returned an error so there is no conn to close, but fake still shouldn't leak state")
	}
}

func TestGetNode_ReturnsDetailWithIdentity(t *testing.T) {
	connA := &fakeConn{
		status: &cryptosv1.GetStatusResponse{
			Status: &cryptosv1.NodeStatus{
				Role:          cryptosv1.NodeRole_NODE_ROLE_ROOT,
				IdentityState: cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED,
				TpmState:      cryptosv1.TpmState_TPM_STATE_OK,
				BootCount:     3,
			},
		},
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{
				ChainPem:   "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
				ChainDer:   [][]byte{[]byte("fake-der")},
				LeafSha256: []byte{0xde, 0xad, 0xbe, 0xef},
			},
		},
	}

	svc := New(testStore(), dialFor(map[string]*fakeConn{"A": connA}))

	resp, err := svc.GetNode(context.Background(), connect.NewRequest(&fleetv1.GetNodeRequest{Name: "A"}))
	if err != nil {
		t.Fatalf("GetNode(A) error = %v, want nil", err)
	}

	detail := resp.Msg.GetNode()
	if detail == nil {
		t.Fatal("GetNode(A) returned nil detail")
	}
	if detail.GetSummary().GetHealth() != fleetv1.Health_HEALTH_UP {
		t.Errorf("detail.Summary.Health = %v, want HEALTH_UP", detail.GetSummary().GetHealth())
	}
	if detail.GetIdentity().GetChainPem() != connA.identity.GetIdentity().GetChainPem() {
		t.Errorf("detail.Identity.ChainPem = %q, want %q", detail.GetIdentity().GetChainPem(), connA.identity.GetIdentity().GetChainPem())
	}
	if detail.GetTpmAvailable() != true {
		t.Error("detail.TpmAvailable = false, want true (TpmState = TPM_STATE_OK)")
	}
	if detail.GetBootCount() != 3 {
		t.Errorf("detail.BootCount = %d, want 3", detail.GetBootCount())
	}
}

// signCert builds a DER certificate for cn signed by the parent cert/key. When
// parent is nil the cert is self-signed (a root): it is signed with its own
// freshly generated key and its issuer is its own subject.
func signCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	signer, signerKey := parent, parentKey
	if signer == nil {
		signer, signerKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %v", cn, err)
	}
	return der, cert, key
}

func TestLeafCNs(t *testing.T) {
	rootDER, rootCert, rootKey := signCert(t, "ACME Root CA", nil, nil)
	interDER, _, _ := signCert(t, "ACME Intermediate CA", rootCert, rootKey)

	t.Run("self-signed root has issuer == cn", func(t *testing.T) {
		cn, issuer := leafCNs(&cryptosv1.Identity{ChainDer: [][]byte{rootDER}})
		if cn != "ACME Root CA" || issuer != "ACME Root CA" {
			t.Errorf("leafCNs(root) = (%q, %q), want (ACME Root CA, ACME Root CA)", cn, issuer)
		}
	})

	t.Run("subordinate issuer names the parent CA", func(t *testing.T) {
		cn, issuer := leafCNs(&cryptosv1.Identity{ChainDer: [][]byte{interDER, rootDER}})
		if cn != "ACME Intermediate CA" || issuer != "ACME Root CA" {
			t.Errorf("leafCNs(intermediate) = (%q, %q), want (ACME Intermediate CA, ACME Root CA)", cn, issuer)
		}
	})

	t.Run("nil identity yields empty", func(t *testing.T) {
		if cn, issuer := leafCNs(nil); cn != "" || issuer != "" {
			t.Errorf("leafCNs(nil) = (%q, %q), want empty", cn, issuer)
		}
	})

	t.Run("empty chain yields empty", func(t *testing.T) {
		if cn, issuer := leafCNs(&cryptosv1.Identity{}); cn != "" || issuer != "" {
			t.Errorf("leafCNs(empty) = (%q, %q), want empty", cn, issuer)
		}
	})

	t.Run("unparseable leaf yields empty", func(t *testing.T) {
		if cn, issuer := leafCNs(&cryptosv1.Identity{ChainDer: [][]byte{[]byte("not-a-cert")}}); cn != "" || issuer != "" {
			t.Errorf("leafCNs(garbage) = (%q, %q), want empty", cn, issuer)
		}
	})
}

func TestGetNode_NotFound(t *testing.T) {
	svc := New(testStore(), dialFor(map[string]*fakeConn{}))

	_, err := svc.GetNode(context.Background(), connect.NewRequest(&fleetv1.GetNodeRequest{Name: "missing"}))
	if err == nil {
		t.Fatal("GetNode(missing) error = nil, want NotFound")
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("GetNode(missing) error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeNotFound {
		t.Errorf("GetNode(missing) error code = %v, want CodeNotFound", connectErr.Code())
	}
}
