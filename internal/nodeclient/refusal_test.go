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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// A refused node certificate comes back from a gRPC call as text only; the
// manager tells it apart from an unreachable node with IsRefusal.
func TestIsRefusal_DialRefusalThroughGRPC(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, caSignedServerCert(t, newTestCA(t, "Other CA")), clientCA)
	defer stop()
	dir := t.TempDir()
	node := pinnedNode(t, lis.Addr().String(), dir, clientCA)
	node.CACert = writeCAChainPEM(t, dir, newTestCA(t, "Example Root CA G1"))

	err := getStatus(t, node)
	if err == nil {
		t.Fatal("GetStatus() = nil, want refused")
	}
	if errors.Is(err, ErrNodeUntrusted) {
		t.Log("the gRPC error kept the chain; IsRefusal must still hold")
	}
	if !IsRefusal(err) {
		t.Errorf("IsRefusal(%v) = false, want true", err)
	}
}

func TestIsRefusal_UnreachableIsNot(t *testing.T) {
	if IsRefusal(errors.New("rpc error: code = Unavailable desc = connection error: dial tcp 127.0.0.1:1: connect: connection refused")) {
		t.Error("IsRefusal(connection refused) = true, want false")
	}
}

func TestDialMaintenance_WrongPinIsARefusal(t *testing.T) {
	clientCA := newTestCA(t, "fake-node-client-ca")
	serverCert := bootServerCert(t, "127.0.0.1")
	lis := listenLocal(t, "127.0.0.1:0")
	stop := startBootedNode(t, lis, serverCert, clientCA)
	defer stop()

	wrong := sha256.Sum256([]byte("not the node's certificate"))
	client, err := DialMaintenance(lis.Addr().String(), hex.EncodeToString(wrong[:]), "", "")
	if err != nil {
		t.Fatalf("DialMaintenance() error = %v (the dial is lazy)", err)
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.ListInstallDisks(ctx)
	if err == nil {
		t.Fatal("ListInstallDisks() with a wrong pin: error = nil, want refused")
	}
	if !IsRefusal(err) || !strings.Contains(err.Error(), sha256Hex(serverCert)) {
		t.Errorf("error = %v, want a refusal naming the presented sha256", err)
	}
}
