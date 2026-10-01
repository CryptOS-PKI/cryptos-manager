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
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckNode_VerifiedByRecordedChain(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	nodeCA := newTestCA(t, "Example Root CA G1")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, caSignedServerCert(t, nodeCA), clientCA)
	defer stop()

	dir := t.TempDir()
	node := pinnedNode(t, lis.Addr().String(), dir, clientCA)
	node.CACert = writeCAChainPEM(t, dir, nodeCA)

	mode, err := CheckNode(node)
	if err != nil {
		t.Fatalf("CheckNode() error = %v, want nil", err)
	}
	if mode != TrustCAChain {
		t.Errorf("CheckNode() mode = %q, want %q", mode, TrustCAChain)
	}
}

// The trust files exist but are stale: the recorded chain is an old CA and
// the pin an old certificate. The file check calls that ca-chain+pinned; the
// live check must refuse the node, as every dial does.
func TestCheckNode_StaleChainAndPinRefused(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	serverCert := caSignedServerCert(t, newTestCA(t, "Example Root CA G1"))
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, serverCert, clientCA)
	defer stop()

	dir := t.TempDir()
	node := pinnedNode(t, lis.Addr().String(), dir, clientCA)
	node.CACert = writeCAChainPEM(t, dir, newTestCA(t, "Stale Self-Signed CA"))
	writeServerCertPEM(t, filepath.Join(dir, ServerCertFile), bootServerCert(t, "127.0.0.1"))

	if mode, err := NodeTrust(node); err != nil || mode != TrustCAChainAndPin {
		t.Fatalf("NodeTrust() = %q, %v; the fixture should look fine on file", mode, err)
	}
	_, err := CheckNode(node)
	if err == nil {
		t.Fatal("CheckNode() with a stale chain and pin: error = nil, want refused")
	}
	for _, want := range []string{"refused", sha256Hex(serverCert), "recorded CA chain", "pinned server certificate"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckNode() error = %v, want it to contain %q", err, want)
		}
	}
}

func TestCheckNode_NoTrustRefusedWithoutDialling(t *testing.T) {
	dir := t.TempDir()
	node := pinnedNode(t, "127.0.0.1:1", dir, newTestCA(t, "fake-node-client-ca"))

	mode, err := CheckNode(node)
	if err == nil || mode != TrustNone {
		t.Fatalf("CheckNode() = %q, %v; want TrustNone and an error", mode, err)
	}
}

func TestCheckNode_UnreachableNode(t *testing.T) {
	lis := listenLocal(t, "127.0.0.1:0")
	addr := lis.Addr().String()
	_ = lis.Close()

	dir := t.TempDir()
	clientCA := newTestCA(t, "fake-node-client-ca")
	node := pinnedNode(t, addr, dir, clientCA)
	node.CACert = writeCAChainPEM(t, dir, newTestCA(t, "Example Root CA G1"))

	if _, err := CheckNode(node); err == nil {
		t.Fatal("CheckNode() against a closed port: error = nil, want unreachable")
	}
}

func TestCheckNode_InsecureSkipsTheDial(t *testing.T) {
	node := pinnedNode(t, "127.0.0.1:1", t.TempDir(), newTestCA(t, "fake-node-client-ca"))

	mode, err := CheckNode(node, InsecureSkipNodeVerify())
	if err != nil || mode != TrustInsecure {
		t.Fatalf("CheckNode(insecure) = %q, %v; want TrustInsecure and no error", mode, err)
	}
}
