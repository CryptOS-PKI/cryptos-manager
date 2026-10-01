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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

// adminPEM returns the admin client credential a LINK request carries, as
// PEM strings.
func adminPEM(t *testing.T, clientCA *testCA) (certPEM, keyPEM string) {
	t.Helper()
	pair := clientCA.issueLeaf(t, "manager-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	key, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("admin key is not RSA")
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

func certPEMOf(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// startLinkNode serves the fake NodeService with serverCert and returns its
// address.
func startLinkNode(t *testing.T, serverCert tls.Certificate, clientCA *testCA) string {
	t.Helper()
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, serverCert, clientCA)
	t.Cleanup(stop)
	return lis.Addr().String()
}

func TestDialPEM_CAChainAccepted(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	nodeCA := newTestCA(t, "Example Root CA G1")
	addr := startLinkNode(t, caSignedServerCert(t, nodeCA), clientCA)
	certPEM, keyPEM := adminPEM(t, clientCA)

	client, err := DialPEM(addr, certPEM, keyPEM, certPEMOf(nodeCA.certDER))
	if err != nil {
		t.Fatalf("DialPEM() with the node's CA as ca_pem: error = %v, want nil", err)
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.GetStatus(ctx); err != nil {
		t.Fatalf("GetStatus() over the verified connection: error = %v, want nil", err)
	}
}

func TestDialPEM_UnrelatedCARefused(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	serverCert := caSignedServerCert(t, newTestCA(t, "Example Root CA G1"))
	addr := startLinkNode(t, serverCert, clientCA)
	certPEM, keyPEM := adminPEM(t, clientCA)

	client, err := DialPEM(addr, certPEM, keyPEM, certPEMOf(newTestCA(t, "Unrelated CA").certDER))
	if err == nil {
		_ = client.Close()
		t.Fatal("DialPEM() with an unrelated ca_pem: error = nil, want the node refused")
	}
	if !errors.Is(err, ErrNodeUntrusted) {
		t.Errorf("DialPEM() error = %v, want it to wrap ErrNodeUntrusted", err)
	}
	for _, want := range []string{sha256Hex(serverCert), "ca_pem"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("DialPEM() error = %v, want it to contain %q", err, want)
		}
	}
}

func TestDialPEM_HostMismatchRefused(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	nodeCA := newTestCA(t, "Example Root CA G1")
	addr := startLinkNode(t, dnsOnlyServerCert(t, nodeCA, "node.example.org"), clientCA)
	certPEM, keyPEM := adminPEM(t, clientCA)

	client, err := DialPEM(addr, certPEM, keyPEM, certPEMOf(nodeCA.certDER))
	if err == nil {
		_ = client.Close()
		t.Fatal("DialPEM() to a host the certificate does not name: error = nil, want refused")
	}
	if !errors.Is(err, ErrNodeUntrusted) {
		t.Errorf("DialPEM() error = %v, want it to wrap ErrNodeUntrusted", err)
	}
	if !strings.Contains(err.Error(), "for host 127.0.0.1") {
		t.Errorf("DialPEM() error = %v, want it to name the host", err)
	}
}

// A node still on a self-signed management certificate is linked by giving
// that exact certificate as ca_pem, the same as a pin.
func TestDialPEM_PinnedServerCertAccepted(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	serverCert := bootServerCert(t, "192.0.2.10")
	addr := startLinkNode(t, serverCert, clientCA)
	certPEM, keyPEM := adminPEM(t, clientCA)

	client, err := DialPEM(addr, certPEM, keyPEM, certPEMOf(serverCert.Certificate[0]))
	if err != nil {
		t.Fatalf("DialPEM() with the node's exact certificate as ca_pem: error = %v, want nil", err)
	}
	_ = client.Close()
}

func TestDialPEM_CAPEMRequired(t *testing.T) {
	certPEM, keyPEM := selfSignedECDSAPEM(t)
	for label, caPEM := range map[string]string{"empty": "", "no certificate": "not a pem block"} {
		t.Run(label, func(t *testing.T) {
			client, err := DialPEM("127.0.0.1:1", certPEM, keyPEM, caPEM)
			if err == nil {
				_ = client.Close()
				t.Fatal("DialPEM() error = nil, want ca_pem required")
			}
			if !errors.Is(err, ErrCAPEMRequired) {
				t.Errorf("DialPEM() error = %v, want it to wrap ErrCAPEMRequired", err)
			}
		})
	}
}

func TestDialPEM_UnreachableNode(t *testing.T) {
	lis := listenLocal(t, "127.0.0.1:0")
	addr := lis.Addr().String()
	_ = lis.Close()
	certPEM, keyPEM := selfSignedECDSAPEM(t)

	client, err := DialPEM(addr, certPEM, keyPEM, certPEMOf(newTestCA(t, "Example Root CA G1").certDER))
	if err == nil {
		_ = client.Close()
		t.Fatal("DialPEM() to a closed port: error = nil, want unreachable")
	}
	if !errors.Is(err, ErrNodeUnreachable) || errors.Is(err, ErrNodeUntrusted) {
		t.Errorf("DialPEM() error = %v, want ErrNodeUnreachable and not ErrNodeUntrusted", err)
	}
}
