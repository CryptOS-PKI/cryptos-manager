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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// writeCAChainPEM records ca as a node's CA chain file in dir, the way the
// manager stores the chain it read from the node at adoption.
func writeCAChainPEM(t *testing.T, dir string, cas ...*testCA) string {
	t.Helper()
	var buf bytes.Buffer
	for _, ca := range cas {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.certDER}); err != nil {
			t.Fatalf("encode CA: %v", err)
		}
	}
	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write CA chain: %v", err)
	}
	return path
}

// caSignedServerCert is the management certificate a node presents once it
// has its CA: signed by nodeCA, serverAuth, with the node's IP as the SAN.
func caSignedServerCert(t *testing.T, nodeCA *testCA) tls.Certificate {
	t.Helper()
	return nodeCA.issueLeaf(t, "node.example.org", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

// captureLog routes the standard logger into a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func sha256Hex(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}

func TestDial_CAChain_Accepted(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	nodeCA := newTestCA(t, "Example Root CA G1")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, caSignedServerCert(t, nodeCA), clientCA)
	defer stop()

	dir := t.TempDir()
	node := pinnedNode(t, lis.Addr().String(), dir, clientCA)
	node.CACert = writeCAChainPEM(t, dir, nodeCA)

	if err := getStatus(t, node); err != nil {
		t.Fatalf("GetStatus() against a certificate chaining to the recorded CA: error = %v, want nil", err)
	}
}

// The endpoint is a literal IP so the test never depends on how a name
// resolves: a name with several addresses (localhost is both 127.0.0.1 and
// ::1 on some hosts) makes gRPC report the last address's dial error instead
// of the refused handshake.
func TestDial_CAChain_HostMismatchRefused(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	nodeCA := newTestCA(t, "Example Root CA G1")
	serverCert := dnsOnlyServerCert(t, nodeCA, "node.example.org")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, serverCert, clientCA)
	defer stop()

	dir := t.TempDir()
	// The certificate chains to the recorded CA but names only
	// node.example.org, so dialing the node at 127.0.0.1 must fail the host
	// check.
	node := pinnedNode(t, lis.Addr().String(), dir, clientCA)
	node.CACert = writeCAChainPEM(t, dir, nodeCA)

	err := getStatus(t, node)
	if err == nil {
		t.Fatal("GetStatus() with a host the certificate does not name: error = nil, want refused")
	}
	for _, want := range []string{node.Name, sha256Hex(serverCert), "recorded CA chain", "for host 127.0.0.1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("GetStatus() error = %v, want it to contain %q", err, want)
		}
	}
}

// dnsOnlyServerCert is a management certificate signed by nodeCA whose only
// SAN is the DNS name dnsName.
func dnsOnlyServerCert(t *testing.T, nodeCA *testCA, dnsName string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, nodeCA.cert, &key.PublicKey, nodeCA.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestDial_CAChain_OtherCARefused(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, caSignedServerCert(t, newTestCA(t, "Other CA")), clientCA)
	defer stop()

	dir := t.TempDir()
	node := pinnedNode(t, lis.Addr().String(), dir, clientCA)
	node.CACert = writeCAChainPEM(t, dir, newTestCA(t, "Example Root CA G1"))

	if err := getStatus(t, node); err == nil {
		t.Fatal("GetStatus() against a certificate from another CA: error = nil, want refused")
	}
}

// A node pinned before its ceremony keeps working through the switch to a
// CA-signed certificate: while the node still presents the pinned
// self-signed certificate the pin accepts it, even once the chain is
// recorded, and after the switch the chain accepts the new certificate
// although the old pin no longer matches.
func TestDial_PinToChainTransition(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	nodeCA := newTestCA(t, "Example Root CA G1")
	dir := t.TempDir()

	preCeremony := bootServerCert(t, "127.0.0.1")
	lis := listenLocal(t, "127.0.0.1:0")
	addr := lis.Addr().String()
	stop := startBootedNode(t, lis, preCeremony, clientCA)
	writeServerCertPEM(t, filepath.Join(dir, ServerCertFile), preCeremony)
	node := pinnedNode(t, addr, dir, clientCA)
	if err := getStatus(t, node); err != nil {
		t.Fatalf("pre-ceremony, pinned: GetStatus() error = %v, want nil", err)
	}

	// The ceremony ran and the manager recorded the chain; the node has not
	// switched its listener yet.
	node.CACert = writeCAChainPEM(t, dir, nodeCA)
	if err := getStatus(t, node); err != nil {
		t.Fatalf("chain recorded, node still self-signed: GetStatus() error = %v, want nil", err)
	}
	stop()

	stop = startBootedNode(t, listenLocal(t, addr), caSignedServerCert(t, nodeCA), clientCA)
	defer stop()
	if err := getStatus(t, node); err != nil {
		t.Fatalf("after the switch to a CA-signed certificate: GetStatus() error = %v, want nil", err)
	}
}

func TestDial_UnpinnedNodeRefused(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	serverCert := bootServerCert(t, "127.0.0.1")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, serverCert, clientCA)
	defer stop()

	dir := t.TempDir()
	node := pinnedNode(t, lis.Addr().String(), dir, clientCA)
	err := getStatus(t, node)
	if err == nil {
		t.Fatal("GetStatus() with no CA chain and no pin: error = nil, want refused")
	}
	for _, want := range []string{
		node.Name,
		sha256Hex(serverCert),
		"no CA chain is recorded and no server certificate is pinned",
		filepath.Join(dir, ServerCertFile),
		"-pin-node",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("GetStatus() error = %v, want it to contain %q", err, want)
		}
	}
}

// A recorded chain file that is not there yet leaves the node to its pin.
func TestDial_MissingCAChainFileFallsBackToPin(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	serverCert := bootServerCert(t, "127.0.0.1")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, serverCert, clientCA)
	defer stop()

	dir := t.TempDir()
	node := pinnedNode(t, lis.Addr().String(), dir, clientCA)
	node.CACert = filepath.Join(dir, "missing-ca.pem")
	if err := getStatus(t, node); err == nil {
		t.Fatal("GetStatus() with a missing chain file and no pin: error = nil, want refused")
	}

	writeServerCertPEM(t, filepath.Join(dir, ServerCertFile), serverCert)
	if err := getStatus(t, node); err != nil {
		t.Fatalf("GetStatus() with a missing chain file and a pin: error = %v, want nil", err)
	}
}

func TestDial_CAChainFileWithoutCertificatesFailsDial(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	dir := t.TempDir()
	node := pinnedNode(t, "127.0.0.1:1", dir, clientCA)
	node.CACert = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(node.CACert, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Dial(node); err == nil {
		t.Fatal("Dial() with a CA chain file holding no certificate: error = nil, want non-nil")
	}
}

func TestDial_InsecureSkipNodeVerify_ConnectsAndWarns(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	serverCert := bootServerCert(t, "127.0.0.1")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, serverCert, clientCA)
	defer stop()

	logs := captureLog(t)
	node := pinnedNode(t, lis.Addr().String(), t.TempDir(), clientCA)
	for i := 0; i < 2; i++ {
		client, err := Dial(node, InsecureSkipNodeVerify())
		if err != nil {
			t.Fatalf("Dial() error = %v, want nil", err)
		}
		if _, err := client.GetStatus(t.Context()); err != nil {
			t.Fatalf("GetStatus() with insecureSkipNodeVerify: error = %v, want nil", err)
		}
		_ = client.Close()
	}

	if got := strings.Count(logs.String(), "WARNING"); got < 2 {
		t.Errorf("logged %d warnings over two connections, want one per connection; log:\n%s", got, logs.String())
	}
	for _, want := range []string{node.Name, "insecureSkipNodeVerify", sha256Hex(serverCert)} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log = %q, want it to contain %q", logs.String(), want)
		}
	}
}

func TestNodeTrust(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	nodeCA := newTestCA(t, "Example Root CA G1")

	none := pinnedNode(t, "192.0.2.10:443", t.TempDir(), clientCA)

	pinnedDir := t.TempDir()
	pinned := pinnedNode(t, "192.0.2.11:443", pinnedDir, clientCA)
	writeServerCertPEM(t, filepath.Join(pinnedDir, ServerCertFile), bootServerCert(t, "192.0.2.11"))

	chainDir := t.TempDir()
	chained := pinnedNode(t, "192.0.2.12:443", chainDir, clientCA)
	chained.CACert = writeCAChainPEM(t, chainDir, nodeCA)

	bothDir := t.TempDir()
	both := pinnedNode(t, "192.0.2.13:443", bothDir, clientCA)
	both.CACert = writeCAChainPEM(t, bothDir, nodeCA)
	writeServerCertPEM(t, filepath.Join(bothDir, ServerCertFile), bootServerCert(t, "192.0.2.13"))

	tests := []struct {
		name string
		node store.Node
		opts []Option
		want TrustMode
	}{
		{"none", none, nil, TrustNone},
		{"pinned", pinned, nil, TrustPinned},
		{"chain", chained, nil, TrustCAChain},
		{"chain and pin", both, nil, TrustCAChainAndPin},
		{"insecure", none, []Option{InsecureSkipNodeVerify()}, TrustInsecure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NodeTrust(tt.node, tt.opts...)
			if err != nil {
				t.Fatalf("NodeTrust() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("NodeTrust() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFetchServerCert_ReturnsThePresentedLeaf(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	serverCert := bootServerCert(t, "127.0.0.1")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, serverCert, clientCA)
	defer stop()

	node := pinnedNode(t, lis.Addr().String(), t.TempDir(), clientCA)
	got, err := FetchServerCert(node)
	if err != nil {
		t.Fatalf("FetchServerCert() error = %v", err)
	}
	if !bytes.Equal(got.Raw, serverCert.Certificate[0]) {
		t.Error("FetchServerCert() returned a different certificate than the node presents")
	}
}

func TestPinServerCert(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	serverCert := bootServerCert(t, "127.0.0.1")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, serverCert, clientCA)
	defer stop()

	dir := t.TempDir()
	node := pinnedNode(t, lis.Addr().String(), dir, clientCA)

	if _, err := PinServerCert(node, strings.Repeat("ab", 32)); err == nil {
		t.Fatal("PinServerCert() with a fingerprint the node does not present: error = nil, want refused")
	}
	if _, err := os.Stat(filepath.Join(dir, ServerCertFile)); !os.IsNotExist(err) {
		t.Fatalf("PinServerCert() wrote %s after a mismatch (stat err %v)", ServerCertFile, err)
	}

	// The console shows the fingerprint in capitals and groups of four.
	fp := strings.ToUpper(sha256Hex(serverCert))
	var grouped []string
	for i := 0; i < len(fp); i += 4 {
		grouped = append(grouped, fp[i:i+4])
	}
	path, err := PinServerCert(node, strings.Join(grouped, " "))
	if err != nil {
		t.Fatalf("PinServerCert() with the console fingerprint: error = %v", err)
	}
	if path != filepath.Join(dir, ServerCertFile) {
		t.Errorf("PinServerCert() path = %q, want %q", path, filepath.Join(dir, ServerCertFile))
	}
	if err := getStatus(t, node); err != nil {
		t.Fatalf("GetStatus() after PinServerCert(): error = %v, want nil", err)
	}
}
