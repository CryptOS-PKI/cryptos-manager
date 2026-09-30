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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/manager/internal/config"
	"github.com/CryptOS-PKI/manager/internal/nodeclient"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// trustNode returns a node whose admin credentials live in their own folder.
func trustNode(t *testing.T, name, endpoint string) store.Node {
	t.Helper()
	dir := t.TempDir()
	return store.Node{Name: name, Endpoint: endpoint, AdminCert: filepath.Join(dir, "admin.crt"), AdminKey: filepath.Join(dir, "admin.key")}
}

func TestInsecureNodes(t *testing.T) {
	cfg := config.Config{Nodes: []config.NodeCfg{
		{Name: "lab-node", InsecureSkipNodeVerify: true},
		{Name: "prod-node"},
	}}
	got := insecureNodes(cfg)
	if !got.skip(store.Node{Name: "lab-node"}) || got.skip(store.Node{Name: "prod-node"}) || got.skip(store.Node{Name: "adopted"}) {
		t.Errorf("insecureNodes() = %v, want lab-node only", got)
	}
	if len(got.options(store.Node{Name: "lab-node"})) != 1 || len(got.options(store.Node{Name: "prod-node"})) != 0 {
		t.Error("options() should carry InsecureSkipNodeVerify for lab-node only")
	}
}

func TestReportNodeTrust(t *testing.T) {
	unpinned := trustNode(t, "unpinned-node", "192.0.2.10:443")
	pinned := trustNode(t, "pinned-node", "192.0.2.11:443")
	selfSigned, _ := writeSelfSigned(t, t.TempDir())
	b, err := os.ReadFile(selfSigned)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodeclient.PinPath(pinned), b, 0o600); err != nil {
		t.Fatal(err)
	}
	lab := trustNode(t, "lab-node", "192.0.2.12:443")
	insecure := insecureNodeSet{"lab-node": true}

	var out bytes.Buffer
	refused := reportNodeTrust(&out, []store.Node{unpinned, pinned, lab}, insecure)
	if refused != 1 {
		t.Errorf("reportNodeTrust() refused = %d, want 1", refused)
	}
	lines := out.String()
	for _, want := range []string{
		"unpinned-node", "REFUSED", nodeclient.PinPath(unpinned),
		"pinned-node", string(nodeclient.TrustPinned),
		"lab-node", "WARNING", "insecureSkipNodeVerify", "lab testing only",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("report = %q, want it to contain %q", lines, want)
		}
	}
	for _, l := range strings.Split(strings.TrimSpace(lines), "\n") {
		if strings.Contains(l, "trust: pinned-node ") && strings.Contains(l, "REFUSED") {
			t.Errorf("pinned node reported as refused: %q", l)
		}
	}
}

func TestPinNode_UnknownNode(t *testing.T) {
	if _, err := pinNode([]store.Node{trustNode(t, "a", "192.0.2.10:443")}, "missing", "ab"); err == nil {
		t.Fatal("pinNode() for a node not in the inventory: error = nil, want non-nil")
	}
}
