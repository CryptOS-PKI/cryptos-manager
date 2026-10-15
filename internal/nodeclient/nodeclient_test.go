package nodeclient

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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// fakeNodeService is a minimal NodeService that answers GetStatus and
// GetIdentity with canned, distinctive responses.
type fakeNodeService struct {
	nodev1.UnimplementedNodeServiceServer
}

func (fakeNodeService) GetStatus(context.Context, *nodev1.GetStatusRequest) (*nodev1.GetStatusResponse, error) {
	return &nodev1.GetStatusResponse{
		Status: &nodev1.NodeStatus{
			SoftwareVersion: "fake-node-v0.0.1-test-marker",
		},
	}, nil
}

func (fakeNodeService) GetIdentity(context.Context, *nodev1.GetIdentityRequest) (*nodev1.GetIdentityResponse, error) {
	return &nodev1.GetIdentityResponse{
		Identity: &nodev1.Identity{
			ChainPem: "-----BEGIN CERTIFICATE-----\nfake-identity-test-marker\n-----END CERTIFICATE-----\n",
		},
	}, nil
}

func (fakeNodeService) GetConfig(context.Context, *nodev1.GetConfigRequest) (*nodev1.GetConfigResponse, error) {
	return &nodev1.GetConfigResponse{
		Config: &nodev1.MachineConfig{
			ApiVersion: "cryptos.dev/v1alpha1",
			Kind:       "MachineConfig",
			Role:       &nodev1.Role{Kind: "fake-config-test-marker"},
		},
	}, nil
}

func (fakeNodeService) ListIssued(context.Context, *nodev1.ListIssuedRequest) (*nodev1.ListIssuedResponse, error) {
	return &nodev1.ListIssuedResponse{
		Issued: []*nodev1.IssuedCert{
			{SerialHex: "fake-issued-test-marker"},
		},
	}, nil
}

func (fakeNodeService) ListRevocations(context.Context, *nodev1.ListRevocationsRequest) (*nodev1.ListRevocationsResponse, error) {
	return &nodev1.ListRevocationsResponse{
		Revocations: []*nodev1.Revocation{
			{SerialHex: "fake-revoked-test-marker"},
		},
	}, nil
}

// GetIssuedCertificate echoes the requested serial back as the certificate
// bytes, so the test can assert the Client relayed it unchanged.
func (fakeNodeService) GetIssuedCertificate(_ context.Context, req *nodev1.GetIssuedCertificateRequest) (*nodev1.GetIssuedCertificateResponse, error) {
	return &nodev1.GetIssuedCertificateResponse{CertificateDer: []byte(req.GetSerialHex()), Status: "valid"}, nil
}

func (fakeNodeService) ExportCAKey(_ context.Context, req *nodev1.ExportCAKeyRequest) (*nodev1.ExportCAKeyResponse, error) {
	// Echo the passphrase back inside the envelope so the test can assert the
	// Client relayed it unchanged.
	return &nodev1.ExportCAKeyResponse{
		Envelope: append([]byte("envelope-for-"), req.GetPassphrase()...),
	}, nil
}

func (fakeNodeService) ImportCAKey(_ context.Context, req *nodev1.ImportCAKeyRequest) (*nodev1.ImportCAKeyResponse, error) {
	return &nodev1.ImportCAKeyResponse{
		Identity: &nodev1.Identity{
			ChainPem: "imported:" + string(req.GetEnvelope()) + ":" + string(req.GetPassphrase()),
		},
	}, nil
}

func (fakeNodeService) ListScepEnrollments(_ context.Context, req *nodev1.ListScepEnrollmentsRequest) (*nodev1.ListScepEnrollmentsResponse, error) {
	return &nodev1.ListScepEnrollmentsResponse{
		Enrollments: []*nodev1.ScepEnrollment{{Id: "fake-enrollment-id", Profile: req.GetProfile()}},
	}, nil
}

func (fakeNodeService) ApproveScepEnrollment(_ context.Context, req *nodev1.ApproveScepEnrollmentRequest) (*nodev1.ApproveScepEnrollmentResponse, error) {
	return &nodev1.ApproveScepEnrollmentResponse{
		Enrollment: &nodev1.ScepEnrollment{Id: req.GetId()},
		SerialHex:  "fake-serial-test-marker",
	}, nil
}

func (fakeNodeService) RejectScepEnrollment(_ context.Context, req *nodev1.RejectScepEnrollmentRequest) (*nodev1.RejectScepEnrollmentResponse, error) {
	return &nodev1.RejectScepEnrollmentResponse{
		Enrollment: &nodev1.ScepEnrollment{Id: req.GetId() + ":" + req.GetReason()},
	}, nil
}

func (fakeNodeService) MintScepChallenge(_ context.Context, req *nodev1.MintScepChallengeRequest) (*nodev1.MintScepChallengeResponse, error) {
	return &nodev1.MintScepChallengeResponse{
		ChallengePassword: "fake-password-test-marker",
		Challenge:         &nodev1.ScepChallenge{Id: "fake-challenge-id", Profile: req.GetProfile()},
	}, nil
}

func (fakeNodeService) ListScepChallenges(context.Context, *nodev1.ListScepChallengesRequest) (*nodev1.ListScepChallengesResponse, error) {
	return &nodev1.ListScepChallengesResponse{
		Challenges: []*nodev1.ScepChallenge{{Id: "fake-challenge-id"}},
	}, nil
}

func (fakeNodeService) RevokeScepChallenge(_ context.Context, req *nodev1.RevokeScepChallengeRequest) (*nodev1.RevokeScepChallengeResponse, error) {
	return &nodev1.RevokeScepChallengeResponse{Challenge: &nodev1.ScepChallenge{Id: req.GetId()}}, nil
}

func (fakeNodeService) GetImageStatus(context.Context, *nodev1.GetImageStatusRequest) (*nodev1.GetImageStatusResponse, error) {
	return &nodev1.GetImageStatusResponse{
		Status: &nodev1.ImageStatus{RunningSha256: "fake-image-test-marker"},
	}, nil
}

// StageImage reads the begin header and every chunk, and echoes the
// reassembled image's length and the begin header's fields back so the test
// can assert the Client split and reassembled it correctly across the wire.
func (fakeNodeService) StageImage(stream nodev1.NodeService_StageImageServer) error {
	var (
		begin *nodev1.StageImageBegin
		image []byte
	)
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch p := req.GetPayload().(type) {
		case *nodev1.StageImageRequest_Begin:
			begin = p.Begin
		case *nodev1.StageImageRequest_Chunk:
			image = append(image, p.Chunk...)
		}
	}
	return stream.SendAndClose(&nodev1.StageImageResponse{
		Status: &nodev1.ImageStatus{
			ActiveSha256:   fmt.Sprintf("len=%d sig=%s sha256=%s", len(image), begin.GetSignature(), begin.GetSha256()),
			RunningVersion: string(image),
		},
		RequiresReboot: true,
	})
}

func (fakeNodeService) ActivateImage(_ context.Context, req *nodev1.ActivateImageRequest) (*nodev1.ActivateImageResponse, error) {
	if req.GetConfirmCaCn() != "fake-node" {
		return nil, status.Error(codes.PermissionDenied, "confirmation CN does not match the CA CN")
	}
	return &nodev1.ActivateImageResponse{Rebooting: true}, nil
}

func (fakeNodeService) RollbackImage(context.Context, *nodev1.RollbackImageRequest) (*nodev1.RollbackImageResponse, error) {
	return &nodev1.RollbackImageResponse{Status: &nodev1.ImageStatus{ActiveSha256: "rolled-back-test-marker"}}, nil
}

// testCA is a minimal self-signed CA used to mint both the fake node's
// server cert and the test admin client cert.
type testCA struct {
	cert    *x509.Certificate
	certDER []byte
	key     *rsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	return &testCA{cert: cert, certDER: der, key: key}
}

// issueLeaf mints a leaf certificate signed by the CA for the given common
// name, suitable for either server or client use.
func (ca *testCA) issueLeaf(t *testing.T, cn string, extKeyUsage []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  extKeyUsage,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build tls.Certificate: %v", err)
	}

	return pair
}

func (ca *testCA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	return pool
}

// writePEMFiles writes the cert+key of pair to PEM files under dir and
// returns their paths.
func writePEMFiles(t *testing.T, dir string, pair tls.Certificate) (certPath, keyPath string) {
	t.Helper()

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})

	key, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("private key is not RSA")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	certPath = filepath.Join(dir, "admin.crt")
	keyPath = filepath.Join(dir, "admin.key")

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certPath, keyPath
}

// startFakeNode starts a fake NodeService over TLS that requires and
// verifies a client cert signed by clientCA. It returns the listen address
// and a stop function.
func startFakeNode(t *testing.T, serverCA *testCA, clientCA *testCA) (addr string, stop func()) {
	t.Helper()

	serverPair := serverCA.issueLeaf(t, "fake-node", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA.pool(),
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	nodev1.RegisterNodeServiceServer(srv, fakeNodeService{})

	go func() {
		_ = srv.Serve(lis)
	}()

	addr = lis.Addr().String()
	stop = func() {
		srv.Stop()
	}

	return addr, stop
}

func TestDial_GetStatus_GetIdentity(t *testing.T) {
	serverCA := newTestCA(t, "fake-node-server-ca")
	clientCA := newTestCA(t, "fake-node-client-ca")

	addr, stop := startFakeNode(t, serverCA, clientCA)
	defer stop()

	adminPair := clientCA.issueLeaf(t, "manager-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	dir := t.TempDir()
	certPath, keyPath := writePEMFiles(t, dir, adminPair)

	node := store.Node{
		Name:      "fake-node",
		Endpoint:  addr,
		Role:      "root",
		AdminCert: certPath,
		AdminKey:  keyPath,
		CACert:    writeCAChainPEM(t, dir, serverCA),
	}

	client, err := Dial(node)
	if err != nil {
		t.Fatalf("Dial() error = %v, want nil", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	statusResp, err := client.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus() error = %v, want nil", err)
	}
	if got := statusResp.GetStatus().GetSoftwareVersion(); got != "fake-node-v0.0.1-test-marker" {
		t.Errorf("GetStatus().Status.SoftwareVersion = %q, want fake-node-v0.0.1-test-marker", got)
	}

	identityResp, err := client.GetIdentity(ctx)
	if err != nil {
		t.Fatalf("GetIdentity() error = %v, want nil", err)
	}
	wantChain := "-----BEGIN CERTIFICATE-----\nfake-identity-test-marker\n-----END CERTIFICATE-----\n"
	if got := identityResp.GetIdentity().GetChainPem(); got != wantChain {
		t.Errorf("GetIdentity().Identity.ChainPem = %q, want %q", got, wantChain)
	}

	issuedResp, err := client.ListIssued(ctx)
	if err != nil {
		t.Fatalf("ListIssued() error = %v, want nil", err)
	}
	if len(issuedResp.GetIssued()) != 1 || issuedResp.GetIssued()[0].GetSerialHex() != "fake-issued-test-marker" {
		t.Errorf("ListIssued().Issued = %v, want one entry with serial fake-issued-test-marker", issuedResp.GetIssued())
	}

	revocationsResp, err := client.ListRevocations(ctx)
	if err != nil {
		t.Fatalf("ListRevocations() error = %v, want nil", err)
	}
	if len(revocationsResp.GetRevocations()) != 1 || revocationsResp.GetRevocations()[0].GetSerialHex() != "fake-revoked-test-marker" {
		t.Errorf("ListRevocations().Revocations = %v, want one entry with serial fake-revoked-test-marker", revocationsResp.GetRevocations())
	}

	configResp, err := client.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig() error = %v, want nil", err)
	}
	if got := configResp.GetConfig().GetRole().GetKind(); got != "fake-config-test-marker" {
		t.Errorf("GetConfig().Config.Role.Kind = %q, want fake-config-test-marker", got)
	}

	exportResp, err := client.ExportCAKey(ctx, []byte("relayed-passphrase"))
	if err != nil {
		t.Fatalf("ExportCAKey() error = %v, want nil", err)
	}
	if got := string(exportResp.GetEnvelope()); got != "envelope-for-relayed-passphrase" {
		t.Errorf("ExportCAKey().Envelope = %q, want envelope-for-relayed-passphrase (passphrase not relayed)", got)
	}

	importResp, err := client.ImportCAKey(ctx, []byte("env-bytes"), []byte("relayed-passphrase"))
	if err != nil {
		t.Fatalf("ImportCAKey() error = %v, want nil", err)
	}
	if got := importResp.GetIdentity().GetChainPem(); got != "imported:env-bytes:relayed-passphrase" {
		t.Errorf("ImportCAKey().Identity.ChainPem = %q, want imported:env-bytes:relayed-passphrase (envelope/passphrase not relayed)", got)
	}

	listEnrollResp, err := client.ListScepEnrollments(ctx, "network-device")
	if err != nil {
		t.Fatalf("ListScepEnrollments() error = %v, want nil", err)
	}
	if len(listEnrollResp.GetEnrollments()) != 1 || listEnrollResp.GetEnrollments()[0].GetProfile() != "network-device" {
		t.Errorf("ListScepEnrollments().Enrollments = %v, want one network-device entry", listEnrollResp.GetEnrollments())
	}

	approveResp, err := client.ApproveScepEnrollment(ctx, "enr-123")
	if err != nil {
		t.Fatalf("ApproveScepEnrollment() error = %v, want nil", err)
	}
	if approveResp.GetEnrollment().GetId() != "enr-123" || approveResp.GetSerialHex() != "fake-serial-test-marker" {
		t.Errorf("ApproveScepEnrollment() = %+v, want id enr-123 relayed with the fake's serial", approveResp)
	}

	rejectResp, err := client.RejectScepEnrollment(ctx, "enr-456", "unexpected device")
	if err != nil {
		t.Fatalf("RejectScepEnrollment() error = %v, want nil", err)
	}
	if got := rejectResp.GetEnrollment().GetId(); got != "enr-456:unexpected device" {
		t.Errorf("RejectScepEnrollment().Enrollment.Id = %q, want enr-456:unexpected device (id/reason not relayed)", got)
	}

	mintResp, err := client.MintScepChallenge(ctx, "network-device", 3600, []string{"switch-1.example.org"})
	if err != nil {
		t.Fatalf("MintScepChallenge() error = %v, want nil", err)
	}
	if mintResp.GetChallengePassword() != "fake-password-test-marker" || mintResp.GetChallenge().GetProfile() != "network-device" {
		t.Errorf("MintScepChallenge() = %+v, want the fake's canned response relayed through", mintResp)
	}

	listChallengesResp, err := client.ListScepChallenges(ctx)
	if err != nil {
		t.Fatalf("ListScepChallenges() error = %v, want nil", err)
	}
	if len(listChallengesResp.GetChallenges()) != 1 || listChallengesResp.GetChallenges()[0].GetId() != "fake-challenge-id" {
		t.Errorf("ListScepChallenges().Challenges = %v, want one fake-challenge-id entry", listChallengesResp.GetChallenges())
	}

	revokeResp, err := client.RevokeScepChallenge(ctx, "ch-123")
	if err != nil {
		t.Fatalf("RevokeScepChallenge() error = %v, want nil", err)
	}
	if got := revokeResp.GetChallenge().GetId(); got != "ch-123" {
		t.Errorf("RevokeScepChallenge().Challenge.Id = %q, want ch-123 (id not relayed)", got)
	}

	imageStatusResp, err := client.GetImageStatus(ctx)
	if err != nil {
		t.Fatalf("GetImageStatus() error = %v, want nil", err)
	}
	if got := imageStatusResp.GetStatus().GetRunningSha256(); got != "fake-image-test-marker" {
		t.Errorf("GetImageStatus().Status.RunningSha256 = %q, want fake-image-test-marker", got)
	}

	rollbackResp, err := client.RollbackImage(ctx)
	if err != nil {
		t.Fatalf("RollbackImage() error = %v, want nil", err)
	}
	if got := rollbackResp.GetStatus().GetActiveSha256(); got != "rolled-back-test-marker" {
		t.Errorf("RollbackImage().Status.ActiveSha256 = %q, want rolled-back-test-marker", got)
	}

	activateResp, err := client.ActivateImage(ctx, "fake-node")
	if err != nil {
		t.Fatalf("ActivateImage() error = %v, want nil", err)
	}
	if !activateResp.GetRebooting() {
		t.Error("ActivateImage().Rebooting = false, want true")
	}
	if _, err := client.ActivateImage(ctx, "wrong-cn"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("ActivateImage(wrong CN) code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestClient_StageImage_ChunksAndReassembles proves StageImage splits an
// image larger than one chunk into multiple StageImageRequest_Chunk
// messages and that the fake node's reassembly matches byte for byte, so
// chunking never reorders or drops bytes.
func TestClient_StageImage_ChunksAndReassembles(t *testing.T) {
	serverCA := newTestCA(t, "fake-node-server-ca")
	clientCA := newTestCA(t, "fake-node-client-ca")

	addr, stop := startFakeNode(t, serverCA, clientCA)
	defer stop()

	adminPair := clientCA.issueLeaf(t, "manager-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	dir := t.TempDir()
	certPath, keyPath := writePEMFiles(t, dir, adminPair)

	node := store.Node{
		Name:      "fake-node",
		Endpoint:  addr,
		Role:      "root",
		AdminCert: certPath,
		AdminKey:  keyPath,
		CACert:    writeCAChainPEM(t, dir, serverCA),
	}

	client, err := Dial(node)
	if err != nil {
		t.Fatalf("Dial() error = %v, want nil", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Bigger than stageImageChunkSize (1 MiB) so the Client must send more
	// than one chunk.
	image := strings.Repeat("a", stageImageChunkSize+12345)

	resp, err := client.StageImage(ctx, []byte("sig-bytes"), uint64(len(image)), "deadbeef", strings.NewReader(image))
	if err != nil {
		t.Fatalf("StageImage() error = %v, want nil", err)
	}
	if got := resp.GetStatus().GetRunningVersion(); got != image {
		t.Errorf("fake node reassembled %d bytes, want the original %d bytes back byte for byte", len(got), len(image))
	}
	wantMarker := fmt.Sprintf("len=%d sig=sig-bytes sha256=deadbeef", len(image))
	if got := resp.GetStatus().GetActiveSha256(); got != wantMarker {
		t.Errorf("fake node begin header = %q, want %q", got, wantMarker)
	}
	if !resp.GetRequiresReboot() {
		t.Error("StageImage().RequiresReboot = false, want true")
	}
}

func TestDial_BadCertPath(t *testing.T) {
	node := store.Node{
		Name:      "broken-node",
		Endpoint:  "127.0.0.1:0",
		Role:      "root",
		AdminCert: "/nonexistent/admin.crt",
		AdminKey:  "/nonexistent/admin.key",
		CACert:    "/nonexistent/ca.pem",
	}

	_, err := Dial(node)
	if err == nil {
		t.Fatal("Dial() error = nil, want non-nil for missing cert/key files")
	}
}

func TestClient_GetStatus_NotListening(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	adminPair := clientCA.issueLeaf(t, "manager-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	certPath, keyPath := writePEMFiles(t, t.TempDir(), adminPair)

	node := store.Node{
		Name:      "unreachable-node",
		Endpoint:  "127.0.0.1:1",
		Role:      "root",
		AdminCert: certPath,
		AdminKey:  keyPath,
		CACert:    "",
	}

	client, err := Dial(node)
	if err != nil {
		t.Fatalf("Dial() error = %v, want nil (dial is lazy)", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := client.GetStatus(ctx); err == nil {
		t.Fatal("GetStatus() error = nil, want non-nil for a node that is not listening")
	}
}

// selfSignedECDSAPEM generates a self-signed ECDSA cert/key pair, PEM-encoded,
// for exercising DialPEM without touching the filesystem.
func selfSignedECDSAPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "operator-admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed cert: %v", err)
	}

	certBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certBlock), string(keyBlock)
}

func TestDialPEM_MalformedKey(t *testing.T) {
	certPEM, _ := selfSignedECDSAPEM(t)

	_, err := DialPEM("127.0.0.1:0", certPEM, "not-a-valid-pem-key", "")
	if err == nil {
		t.Fatal("DialPEM() error = nil, want non-nil for a malformed key PEM")
	}
}

func TestClient_GetIssuedCertificate(t *testing.T) {
	serverCA := newTestCA(t, "fake-node-server-ca")
	clientCA := newTestCA(t, "fake-node-client-ca")
	addr, stop := startFakeNode(t, serverCA, clientCA)
	defer stop()

	adminPair := clientCA.issueLeaf(t, "manager-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	dir := t.TempDir()
	certPath, keyPath := writePEMFiles(t, dir, adminPair)
	client, err := Dial(store.Node{Name: "fake-node", Endpoint: addr, Role: "issuing", AdminCert: certPath, AdminKey: keyPath, CACert: writeCAChainPEM(t, dir, serverCA)})
	if err != nil {
		t.Fatalf("Dial() error = %v, want nil", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.GetIssuedCertificate(ctx, "0a1b")
	if err != nil {
		t.Fatalf("GetIssuedCertificate() error = %v, want nil", err)
	}
	if string(resp.GetCertificateDer()) != "0a1b" || resp.GetStatus() != "valid" {
		t.Errorf("GetIssuedCertificate() = %v, want the serial echoed back", resp)
	}
}
