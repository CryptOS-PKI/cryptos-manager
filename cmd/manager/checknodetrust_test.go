package main

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
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/manager/internal/nodeclient"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// serveTLSNode answers TLS handshakes on a local port with the certificate at
// certPath, asking for any client certificate, and returns the address.
func serveTLSNode(t *testing.T, certPath, keyPath string) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAnyClientCert})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	return lis.Addr().String()
}

// liveNode is an inventory node at addr with a working admin credential.
func liveNode(t *testing.T, name, addr string) store.Node {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir)
	return store.Node{Name: name, Endpoint: addr, AdminCert: certPath, AdminKey: keyPath}
}

func TestCheckNodeTrust_DialsEveryNode(t *testing.T) {
	nodeCert, nodeKey := writeSelfSigned(t, t.TempDir())
	addr := serveTLSNode(t, nodeCert, nodeKey)

	verified := liveNode(t, "verified-node", addr)
	b, err := os.ReadFile(nodeCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodeclient.PinPath(verified), b, 0o600); err != nil {
		t.Fatal(err)
	}

	// A pin that is on file but no longer matches: the file check passed
	// this; the live check must refuse it.
	stale := liveNode(t, "stale-node", addr)
	otherCert, _ := writeSelfSigned(t, t.TempDir())
	b, err = os.ReadFile(otherCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodeclient.PinPath(stale), b, 0o600); err != nil {
		t.Fatal(err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := lis.Addr().String()
	_ = lis.Close()
	down := liveNode(t, "down-node", closedAddr)
	if err := os.WriteFile(nodeclient.PinPath(down), b, 0o600); err != nil {
		t.Fatal(err)
	}

	unpinned := liveNode(t, "unpinned-node", addr)
	lab := liveNode(t, "lab-node", closedAddr)

	var out bytes.Buffer
	refused := liveNodeTrust(&out, []store.Node{verified, stale, down, unpinned, lab}, insecureNodeSet{"lab-node": true})
	if refused != 3 {
		t.Errorf("liveNodeTrust() refused = %d, want 3 (stale, down, unpinned)\n%s", refused, out.String())
	}
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		for _, n := range []string{"verified-node", "stale-node", "down-node", "unpinned-node", "lab-node"} {
			if strings.Contains(l, "trust: "+n+" ") {
				got[n] = l
			}
		}
	}
	for name, want := range map[string]string{
		"verified-node": "verified (pinned)",
		"stale-node":    "REFUSED",
		"down-node":     "REFUSED",
		"unpinned-node": "REFUSED",
		"lab-node":      "WARNING",
	} {
		if !strings.Contains(got[name], want) {
			t.Errorf("line for %s = %q, want it to contain %q", name, got[name], want)
		}
	}
	if !strings.Contains(got["stale-node"], "pinned server certificate") {
		t.Errorf("stale-node line = %q, want the dial's reason", got["stale-node"])
	}
	if !strings.Contains(got["unpinned-node"], filepath.Base(nodeclient.PinPath(unpinned))) {
		t.Errorf("unpinned-node line = %q, want it to say where to pin", got["unpinned-node"])
	}
}
