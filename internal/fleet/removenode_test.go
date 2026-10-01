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
	"errors"
	"os"
	"path/filepath"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/memory"
)

// removeFixture is an inventory with an adopted node whose credentials sit in
// the node credentials folder, plus a second node.
func removeFixture(t *testing.T) (*Service, store.Store, store.Node) {
	t.Helper()
	adoptCredsBaseDir = t.TempDir()
	certPath, keyPath := adminCredPaths("lab-adopt")
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{certPath, keyPath} {
		if err := os.WriteFile(p, []byte("pem"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st := memory.New(nil)
	st.AddNode(store.Node{Name: "lab-adopt", Endpoint: "192.0.2.60:443", Role: "root", AdminCert: certPath, AdminKey: keyPath})
	st.AddNode(store.Node{Name: "pki-root", Endpoint: "192.0.2.10:443", Role: "root"})
	n, _ := st.Node("lab-adopt")
	// dialFor(nil) fails every dial: removal must never contact the node.
	return New(st, dialFor(nil)), st, n
}

func removeNode(svc *Service, level authz.Level, id, confirm string) (*connect.Response[fleetv1.RemoveNodeResponse], error) {
	return svc.RemoveNode(operatorCtx("admin@example.org", level), connect.NewRequest(&fleetv1.RemoveNodeRequest{NodeId: id, ConfirmName: confirm}))
}

func TestRemoveNode_RemovesWithoutContactingTheNode(t *testing.T) {
	svc, st, n := removeFixture(t)
	st.AddAuditEvent(store.AuditEvent{ID: "aud-1", Kind: "node-adopted", TargetKind: "node", TargetPath: nodeTarget(n)})
	before := len(st.Audit())

	resp, err := removeNode(svc, authz.LevelAdmin, n.ID, "lab-adopt")
	if err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	if got := resp.Msg.GetNode(); got.GetId() != n.ID || got.GetName() != "lab-adopt" || got.GetAddress() != "192.0.2.60:443" {
		t.Errorf("RemoveNode returned %+v, want the removed node", got)
	}
	if _, ok := st.NodeByID(n.ID); ok {
		t.Error("the node is still in the inventory")
	}
	if _, ok := st.Node("pki-root"); !ok {
		t.Error("another node was removed too")
	}

	audit := st.Audit()
	if len(audit) != before+1 {
		t.Fatalf("audit len = %d, want %d (history kept, one event added)", len(audit), before+1)
	}
	if audit[0].ID != "aud-1" {
		t.Error("the node's earlier audit history is gone")
	}
	last := audit[len(audit)-1]
	if last.Kind != "node-removed" || last.TargetPath != nodeTarget(n) {
		t.Errorf("audit = %+v, want node-removed against %s", last, nodeTarget(n))
	}

	if _, err := os.Stat(filepath.Join(adoptCredsBaseDir, "lab-adopt")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the credentials folder is still in place (stat err %v)", err)
	}
	moved := filepath.Join(adoptCredsBaseDir, removedCredsDir, "lab-adopt-"+n.ID, "admin.key")
	if _, err := os.Stat(moved); err != nil {
		t.Errorf("the credentials were not moved aside to %s: %v", moved, err)
	}
}

// A node from the config file keeps its credentials where the operator put
// them: only folders the manager owns are moved.
func TestRemoveNode_LeavesOperatorCredentialsAlone(t *testing.T) {
	svc, st, _ := removeFixture(t)
	dir := t.TempDir()
	cert := filepath.Join(dir, "admin.crt")
	if err := os.WriteFile(cert, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	st.AddNode(store.Node{Name: "cfg-node", Endpoint: "192.0.2.20:443", AdminCert: cert, AdminKey: filepath.Join(dir, "admin.key")})
	n, _ := st.Node("cfg-node")

	if _, err := removeNode(svc, authz.LevelAdmin, n.ID, "cfg-node"); err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	if _, err := os.Stat(cert); err != nil {
		t.Errorf("an operator-managed credential was moved: %v", err)
	}
}

func TestRemoveNode_Refusals(t *testing.T) {
	t.Run("operator", func(t *testing.T) {
		svc, _, n := removeFixture(t)
		_, err := removeNode(svc, authz.LevelOperator, n.ID, "lab-adopt")
		requireConnectCode(t, err, connect.CodePermissionDenied)
	})
	t.Run("no node_id", func(t *testing.T) {
		svc, _, _ := removeFixture(t)
		_, err := removeNode(svc, authz.LevelAdmin, "", "lab-adopt")
		requireConnectCode(t, err, connect.CodeInvalidArgument)
	})
	t.Run("unknown node", func(t *testing.T) {
		svc, _, _ := removeFixture(t)
		_, err := removeNode(svc, authz.LevelAdmin, store.NewNodeID(), "lab-adopt")
		requireConnectCode(t, err, connect.CodeNotFound)
		requireAppCode(t, err, apperr.CodeNodeNotFound)
	})
	t.Run("wrong confirmation", func(t *testing.T) {
		svc, st, n := removeFixture(t)
		_, err := removeNode(svc, authz.LevelAdmin, n.ID, "pki-root")
		requireConnectCode(t, err, connect.CodeInvalidArgument)
		requireAppCode(t, err, apperr.CodeRemoveNotConfirmed)
		if _, ok := st.NodeByID(n.ID); !ok {
			t.Error("the node was removed without a matching confirmation")
		}
	})
	t.Run("pending enrollment names the node", func(t *testing.T) {
		svc, st, n := removeFixture(t)
		st.AddEnrollment(store.Enrollment{ID: "enr-1", Kind: "SUBORDINATE", Status: "PENDING", ProposedName: "lab-adopt", ParentCN: "Example Root CA G1", Profile: "sub-ca"})
		_, err := removeNode(svc, authz.LevelAdmin, n.ID, "lab-adopt")
		requireConnectCode(t, err, connect.CodeFailedPrecondition)
		requireAppCode(t, err, apperr.CodeNodeInUse)
		if _, ok := st.NodeByID(n.ID); !ok {
			t.Error("the node was removed although a pending enrollment names it")
		}
	})
}
