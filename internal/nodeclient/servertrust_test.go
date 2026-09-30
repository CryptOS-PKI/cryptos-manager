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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// bootServerCert mints a self-signed server certificate the way a CryptOS node
// does for its management listener on every boot: a fresh key, serverAuth, and
// the node's address as the SAN.
func bootServerCert(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate boot key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP(host)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create boot cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse boot cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// writeServerCertPEM writes the public half of cert to path, as an operator
// saves a node's management certificate for pinning.
func writeServerCertPEM(t *testing.T, path string, cert tls.Certificate) {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write server cert: %v", err)
	}
}

// startBootedNode serves the fake NodeService on lis with the given management
// certificate, requiring a client certificate from clientCA.
func startBootedNode(t *testing.T, lis net.Listener, serverCert tls.Certificate, clientCA *testCA) func() {
	t.Helper()
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA.pool(),
		MinVersion:   tls.VersionTLS13,
	})))
	cryptosv1.RegisterNodeServiceServer(srv, fakeNodeService{})
	go func() { _ = srv.Serve(lis) }()
	return srv.Stop
}

// pinnedNode returns an inventory node whose admin credentials live in dir;
// a server.crt written next to them pins the node's server certificate.
func pinnedNode(t *testing.T, addr, dir string, clientCA *testCA) store.Node {
	t.Helper()
	adminPair := clientCA.issueLeaf(t, "manager-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	certPath, keyPath := writePEMFiles(t, dir, adminPair)
	return store.Node{
		Name:      "pinned-node",
		Endpoint:  addr,
		Role:      "root",
		AdminCert: certPath,
		AdminKey:  keyPath,
	}
}

func getStatus(t *testing.T, node store.Node) error {
	t.Helper()
	client, err := Dial(node)
	if err != nil {
		t.Fatalf("Dial() error = %v, want nil", err)
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.GetStatus(ctx)
	return err
}

func listenLocal(t *testing.T, addr string) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	return lis
}

func TestDial_PinnedServerCert_Accepted(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	serverCert := bootServerCert(t, "127.0.0.1")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, serverCert, clientCA)
	defer stop()

	dir := t.TempDir()
	writeServerCertPEM(t, filepath.Join(dir, ServerCertFile), serverCert)

	if err := getStatus(t, pinnedNode(t, lis.Addr().String(), dir, clientCA)); err != nil {
		t.Fatalf("GetStatus() against the pinned certificate: error = %v, want nil", err)
	}
}

// An exact copy of the presented certificate pins the node even when the
// endpoint names the node by a host the certificate does not list, as when
// the manager dials a DNS name and the node's certificate carries only its IP.
func TestDial_PinnedServerCert_ExactCopyIgnoresHostName(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	serverCert := bootServerCert(t, "127.0.0.1")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, serverCert, clientCA)
	defer stop()

	dir := t.TempDir()
	writeServerCertPEM(t, filepath.Join(dir, ServerCertFile), serverCert)
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}

	if err := getStatus(t, pinnedNode(t, net.JoinHostPort("localhost", port), dir, clientCA)); err != nil {
		t.Fatalf("GetStatus() via localhost against the exact pinned certificate: error = %v, want nil", err)
	}
}

func TestDial_PinnedServerCert_WrongCertRefused(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, bootServerCert(t, "127.0.0.1"), clientCA)
	defer stop()

	dir := t.TempDir()
	writeServerCertPEM(t, filepath.Join(dir, ServerCertFile), bootServerCert(t, "127.0.0.1"))

	err := getStatus(t, pinnedNode(t, lis.Addr().String(), dir, clientCA))
	if err == nil {
		t.Fatal("GetStatus() against a different certificate: error = nil, want the handshake refused")
	}
	if !strings.Contains(err.Error(), "does not match the pinned server certificate") {
		t.Errorf("GetStatus() error = %v, want it to name the pin mismatch", err)
	}
}

func TestDial_PinnedServerCert_AcrossNodeReboot(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	dir := t.TempDir()
	pin := filepath.Join(dir, ServerCertFile)

	firstBoot := bootServerCert(t, "127.0.0.1")
	lis := listenLocal(t, "127.0.0.1:0")
	addr := lis.Addr().String()
	stop := startBootedNode(t, lis, firstBoot, clientCA)
	writeServerCertPEM(t, pin, firstBoot)
	node := pinnedNode(t, addr, dir, clientCA)
	if err := getStatus(t, node); err != nil {
		t.Fatalf("first boot: GetStatus() error = %v, want nil", err)
	}
	stop()

	// The node reboots and presents a new self-signed certificate on the same
	// address; the old pin no longer matches and the manager must refuse it.
	secondBoot := bootServerCert(t, "127.0.0.1")
	stop = startBootedNode(t, listenLocal(t, addr), secondBoot, clientCA)
	defer stop()
	err := getStatus(t, node)
	if err == nil {
		t.Fatal("after reboot with the old pin: GetStatus() error = nil, want the handshake refused")
	}
	if !strings.Contains(err.Error(), "does not match the pinned server certificate") {
		t.Errorf("after reboot: GetStatus() error = %v, want it to name the pin mismatch", err)
	}

	// Re-pinning to the certificate the node now presents restores access.
	writeServerCertPEM(t, pin, secondBoot)
	if err := getStatus(t, node); err != nil {
		t.Fatalf("after re-pin: GetStatus() error = %v, want nil", err)
	}
}

func TestDial_UnpinnedNodeStillConnects(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, bootServerCert(t, "127.0.0.1"), clientCA)
	defer stop()

	if err := getStatus(t, pinnedNode(t, lis.Addr().String(), t.TempDir(), clientCA)); err != nil {
		t.Fatalf("GetStatus() with no server.crt: error = %v, want nil", err)
	}
}

func TestDial_PinnedServerCert_UnreadableFileFailsDial(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	dir := t.TempDir()
	// A directory where the file should be cannot be read as a certificate.
	if err := os.Mkdir(filepath.Join(dir, ServerCertFile), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := Dial(pinnedNode(t, "127.0.0.1:1", dir, clientCA)); err == nil {
		t.Fatal("Dial() with an unreadable server.crt: error = nil, want non-nil")
	}
}

func TestDial_PinnedServerCert_NoPEMFailsDial(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ServerCertFile), []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Dial(pinnedNode(t, "127.0.0.1:1", dir, clientCA)); err == nil {
		t.Fatal("Dial() with a server.crt holding no PEM: error = nil, want non-nil")
	}
}
