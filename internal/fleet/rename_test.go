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
	"context"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"github.com/google/uuid"
)

func nodeID(t *testing.T, st store.Store, name string) string {
	t.Helper()
	n, ok := st.Node(name)
	if !ok {
		t.Fatalf("node %s not in the store", name)
	}
	return n.ID
}

func rename(t *testing.T, svc *Service, id, name string) *fleetv1.NodeSummary {
	t.Helper()
	resp, err := svc.RenameNode(operatorCtx("admin@acme.example", authz.LevelAdmin),
		connect.NewRequest(&fleetv1.RenameNodeRequest{NodeId: id, NewName: name}))
	if err != nil {
		t.Fatalf("RenameNode(%s, %s): %v", id, name, err)
	}
	return resp.Msg.GetNode()
}

func TestRenameNode_Admin_RenamesAndAudits(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))
	id := nodeID(t, st, "A")

	got := rename(t, svc, id, "root-east")
	if got.GetId() != id || got.GetName() != "root-east" || got.GetAddress() != "a.acme.com:4443" || got.GetRole() != "root" {
		t.Fatalf("RenameNode returned %+v, want node %s named root-east", got, id)
	}
	if n, ok := st.NodeByID(id); !ok || n.Name != "root-east" {
		t.Fatalf("store has %+v, want the node renamed", n)
	}
	if _, ok := st.Node("A"); ok {
		t.Fatal("the old name still resolves as a current name")
	}

	audit := st.Audit()
	if len(audit) != 1 {
		t.Fatalf("audit = %+v, want one entry", audit)
	}
	ev := audit[0]
	if ev.Kind != "node-renamed" || ev.TargetKind != "node" || ev.TargetPath != "/nodes/"+id {
		t.Errorf("audit = (%s, %s, %s), want (node-renamed, node, /nodes/%s)", ev.Kind, ev.TargetKind, ev.TargetPath, id)
	}
	if !strings.Contains(ev.Summary, "A") || !strings.Contains(ev.Summary, "root-east") {
		t.Errorf("audit summary %q should name both the old and new names", ev.Summary)
	}
	if ev.ActorCN != "admin@acme.example" {
		t.Errorf("audit actor = %q, want admin@acme.example", ev.ActorCN)
	}
}

func TestRenameNode_BelowAdmin_PermissionDenied(t *testing.T) {
	for _, level := range []authz.Level{authz.LevelViewer, authz.LevelOperator} {
		st := certsTestStore()
		svc := New(st, dialFor(nil))
		id := nodeID(t, st, "A")

		_, err := svc.RenameNode(operatorCtx("op@acme.example", level),
			connect.NewRequest(&fleetv1.RenameNodeRequest{NodeId: id, NewName: "renamed"}))
		requireConnectCode(t, err, connect.CodePermissionDenied)
		if n, _ := st.NodeByID(id); n.Name != "A" {
			t.Errorf("level %v: a denied rename changed the name to %q", level, n.Name)
		}
		if len(st.Audit()) != 0 {
			t.Errorf("level %v: a denied rename wrote an audit entry", level)
		}
	}
}

func TestRenameNode_NoIdentity_Unauthenticated(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))
	_, err := svc.RenameNode(context.Background(),
		connect.NewRequest(&fleetv1.RenameNodeRequest{NodeId: nodeID(t, st, "A"), NewName: "renamed"}))
	requireConnectCode(t, err, connect.CodeUnauthenticated)
}

func TestRenameNode_UnknownID_NotFound(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))

	for _, id := range []string{store.NewNodeID(), "A", "not-an-id"} {
		_, err := svc.RenameNode(operatorCtx("admin@acme.example", authz.LevelAdmin),
			connect.NewRequest(&fleetv1.RenameNodeRequest{NodeId: id, NewName: "renamed"}))
		requireConnectCode(t, err, connect.CodeNotFound)
	}
	if len(st.Audit()) != 0 {
		t.Error("a refused rename wrote an audit entry")
	}
}

func TestRenameNode_MissingNodeID_InvalidArgument(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))
	_, err := svc.RenameNode(operatorCtx("admin@acme.example", authz.LevelAdmin),
		connect.NewRequest(&fleetv1.RenameNodeRequest{NewName: "renamed"}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestRenameNode_TakenName_AlreadyExists(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))
	id := nodeID(t, st, "A")
	// B is not a valid label, so give the other node a valid one first.
	rename(t, svc, nodeID(t, st, "B"), "pki-inter")
	before := len(st.Audit())

	_, err := svc.RenameNode(operatorCtx("admin@acme.example", authz.LevelAdmin),
		connect.NewRequest(&fleetv1.RenameNodeRequest{NodeId: id, NewName: "pki-inter"}))
	requireConnectCode(t, err, connect.CodeAlreadyExists)
	if n, _ := st.NodeByID(id); n.Name != "A" {
		t.Errorf("a refused rename changed the name to %q", n.Name)
	}
	if len(st.Audit()) != before {
		t.Error("a refused rename wrote an audit entry")
	}
}

func TestRenameNode_InvalidName_InvalidArgument(t *testing.T) {
	bad := map[string]string{
		"empty":            "",
		"uppercase":        "Root",
		"leading hyphen":   "-root",
		"trailing hyphen":  "root-",
		"underscore":       "root_1",
		"dot":              "root.east",
		"space":            "root east",
		"64 characters":    strings.Repeat("a", 64),
		"non-ASCII letter": "röot",
		"a node ID":        store.NewNodeID(),
	}
	for label, name := range bad {
		t.Run(label, func(t *testing.T) {
			st := certsTestStore()
			svc := New(st, dialFor(nil))
			id := nodeID(t, st, "A")

			_, err := svc.RenameNode(operatorCtx("admin@acme.example", authz.LevelAdmin),
				connect.NewRequest(&fleetv1.RenameNodeRequest{NodeId: id, NewName: name}))
			requireConnectCode(t, err, connect.CodeInvalidArgument)
			if n, _ := st.NodeByID(id); n.Name != "A" {
				t.Errorf("an invalid rename changed the name to %q", n.Name)
			}
			if len(st.Audit()) != 0 {
				t.Error("an invalid rename wrote an audit entry")
			}
		})
	}
}

func TestRenameNode_ValidLabels(t *testing.T) {
	for _, name := range []string{"a", "0", "root-east-1", "1root", strings.Repeat("a", 63)} {
		st := certsTestStore()
		svc := New(st, dialFor(nil))
		if got := rename(t, svc, nodeID(t, st, "A"), name); got.GetName() != name {
			t.Errorf("RenameNode(%q) returned name %q", name, got.GetName())
		}
	}
}

func TestRenameNode_SameName_NoOpNoAudit(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))
	id := nodeID(t, st, "A")
	rename(t, svc, id, "root")
	before := len(st.Audit())
	hist := len(st.NodeNames())

	got := rename(t, svc, id, "root")
	if got.GetId() != id || got.GetName() != "root" {
		t.Fatalf("RenameNode(same name) = %+v, want the node unchanged", got)
	}
	if len(st.Audit()) != before {
		t.Error("renaming to the current name wrote an audit entry")
	}
	if len(st.NodeNames()) != hist {
		t.Error("renaming to the current name wrote name history")
	}
}

func TestListNodes_CarriesNodeIDs(t *testing.T) {
	st := certsTestStore()
	up := &fakeConn{status: &cryptosv1.GetStatusResponse{Status: &cryptosv1.NodeStatus{}}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": up}))

	resp, err := svc.ListNodes(context.Background(), connect.NewRequest(&fleetv1.ListNodesRequest{}))
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	for _, n := range resp.Msg.GetNodes() {
		if want := nodeID(t, st, n.GetName()); n.GetId() != want {
			t.Errorf("node %s summary id = %q, want %q (health %v)", n.GetName(), n.GetId(), want, n.GetHealth())
		}
	}
}

func getNode(svc *Service, id, name string) (*fleetv1.NodeSummary, error) {
	resp, err := svc.GetNode(context.Background(), connect.NewRequest(&fleetv1.GetNodeRequest{NodeId: id, Name: name}))
	if err != nil {
		return nil, err
	}
	return resp.Msg.GetNode().GetSummary(), nil
}

func TestGetNode_ByID(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))
	id := nodeID(t, st, "B")

	got, err := getNode(svc, id, "")
	if err != nil {
		t.Fatalf("GetNode(node_id): %v", err)
	}
	if got.GetId() != id || got.GetName() != "B" {
		t.Fatalf("GetNode(node_id) = %+v, want node B", got)
	}

	_, err = getNode(svc, store.NewNodeID(), "")
	requireConnectCode(t, err, connect.CodeNotFound)
}

func TestGetNode_OldNameResolvesAfterRename(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))
	id := nodeID(t, st, "A")
	rename(t, svc, id, "root-east")

	got, err := getNode(svc, "", "A")
	if err != nil {
		t.Fatalf("GetNode(old name): %v", err)
	}
	if got.GetId() != id || got.GetName() != "root-east" {
		t.Fatalf("GetNode(old name) = %+v, want node %s under its new name", got, id)
	}

	// Both set: the old name and the ID name the same node.
	if _, err := getNode(svc, id, "A"); err != nil {
		t.Fatalf("GetNode(node_id, old name): %v", err)
	}
}

func TestGetNode_CurrentNameWinsOverAFormerHolder(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))
	first := nodeID(t, st, "A")
	rename(t, svc, first, "root-east")
	st.AddNode(store.Node{Name: "A", Endpoint: "new.acme.com:4443", Role: "root"})
	second := nodeID(t, st, "A")

	got, err := getNode(svc, "", "A")
	if err != nil {
		t.Fatalf("GetNode(reused name): %v", err)
	}
	if got.GetId() != second {
		t.Fatalf("GetNode(reused name) id = %s, want the current holder %s", got.GetId(), second)
	}
}

func TestGetNode_IDAndNameDisagree_InvalidArgument(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))

	for label, name := range map[string]string{"another node": "B", "no node": "nobody"} {
		_, err := getNode(svc, nodeID(t, st, "A"), name)
		requireConnectCode(t, err, connect.CodeInvalidArgument)
		if !strings.Contains(err.Error(), "different nodes") {
			t.Errorf("%s: error %q does not say the fields disagree", label, err)
		}
	}
}

// Every node-addressed request takes node_id, and refuses a node_id and a
// name that point at different nodes before it dials anything.
func TestNodeRequests_IDAndNameDisagree_InvalidArgument(t *testing.T) {
	st := memory.NewWithCatalog([]store.Node{
		{Name: "A", Endpoint: "a.acme.com:4443", Role: "root"},
		{Name: "B", Endpoint: "b.acme.com:4444", Role: "intermediate"},
	}, []store.Profile{{Name: "p1"}}, nil, nil, nil)
	conn := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn, "B": conn}))
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	a := nodeID(t, st, "A")
	pass := []byte(strongPassphrase)

	calls := map[string]func() error{
		"ListCertificates": func() error {
			_, err := svc.ListCertificates(ctx, connect.NewRequest(&fleetv1.ListCertificatesRequest{NodeId: a, Node: "B"}))
			return err
		},
		"ApplyProfileToNode": func() error {
			_, err := svc.ApplyProfileToNode(ctx, connect.NewRequest(&fleetv1.ApplyProfileToNodeRequest{NodeId: a, NodeName: "B", ProfileName: "p1"}))
			return err
		},
		"RevokeCertificate": func() error {
			_, err := svc.RevokeCertificate(ctx, connect.NewRequest(&fleetv1.RevokeCertificateRequest{NodeId: a, NodeName: "B", SerialHex: "01", ReasonCode: 1}))
			return err
		},
		"IssueLeaf": func() error {
			_, err := svc.IssueLeaf(ctx, connect.NewRequest(&fleetv1.IssueLeafRequest{NodeId: a, NodeName: "B", CsrDer: []byte{1}, ProfileName: "p1"}))
			return err
		},
		"RekeyNode": func() error {
			_, err := svc.RekeyNode(ctx, connect.NewRequest(&fleetv1.RekeyNodeRequest{NodeId: a, NodeName: "B", ProfileName: "p1"}))
			return err
		},
		"GetNodeConfig": func() error {
			_, err := svc.GetNodeConfig(ctx, connect.NewRequest(&fleetv1.GetNodeConfigRequest{NodeId: a, NodeName: "B"}))
			return err
		},
		"ApplyNodeConfig": func() error {
			_, err := svc.ApplyNodeConfig(ctx, connect.NewRequest(&fleetv1.ApplyNodeConfigRequest{NodeId: a, NodeName: "B", Config: &cryptosv1.MachineConfig{}}))
			return err
		},
		"ExportCAKey": func() error {
			_, err := svc.ExportCAKey(ctx, connect.NewRequest(&fleetv1.ExportCAKeyRequest{NodeId: a, NodeName: "B", Passphrase: pass}))
			return err
		},
		"ImportCAKey": func() error {
			_, err := svc.ImportCAKey(ctx, connect.NewRequest(&fleetv1.ImportCAKeyRequest{NodeId: a, NodeName: "B", Envelope: []byte{1}, Passphrase: pass}))
			return err
		},
		"DecommissionNode": func() error {
			_, err := svc.DecommissionNode(ctx, connect.NewRequest(&fleetv1.DecommissionNodeRequest{NodeId: a, NodeName: "B", ConfirmCommonName: "x"}))
			return err
		},
		"CreateEnrollment": func() error {
			_, err := svc.CreateEnrollment(ctx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
				Kind: "SUBORDINATE", ChildNodeId: a, ChildNode: "B", ParentCn: "Root", Profile: "p1",
			}))
			return err
		},
	}
	for rpc, call := range calls {
		t.Run(rpc, func(t *testing.T) {
			err := call()
			requireConnectCode(t, err, connect.CodeInvalidArgument)
			if !strings.Contains(err.Error(), "different nodes") {
				t.Errorf("error %q does not say the fields disagree", err)
			}
		})
	}
	if conn.closed {
		t.Error("a node was dialed for a request whose node fields disagree")
	}
	if len(st.Audit()) != 0 || len(st.Enrollments()) != 0 {
		t.Error("a refused request wrote to the store")
	}
}

func TestNodeRequests_UnknownNodeID_NotFound(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	missing := store.NewNodeID()

	_, err := svc.GetNodeConfig(ctx, connect.NewRequest(&fleetv1.GetNodeConfigRequest{NodeId: missing}))
	requireConnectCode(t, err, connect.CodeNotFound)
	_, err = svc.ListCertificates(ctx, connect.NewRequest(&fleetv1.ListCertificatesRequest{NodeId: missing}))
	requireConnectCode(t, err, connect.CodeNotFound)
	_, err = svc.CreateEnrollment(ctx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
		Kind: "SUBORDINATE", ChildNodeId: missing, ParentCn: "Root", Profile: "p1",
	}))
	requireConnectCode(t, err, connect.CodeNotFound)
}

func TestGetNodeConfig_ByNodeIDAfterRename(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{getConfigResp: &cryptosv1.GetConfigResponse{}}
	svc := New(st, func(n store.Node) (NodeConn, error) {
		if n.Name != "root-east" {
			t.Fatalf("dialed %q, want the renamed node", n.Name)
		}
		return connA, nil
	})
	id := nodeID(t, st, "A")
	rename(t, svc, id, "root-east")

	if _, err := svc.GetNodeConfig(operatorCtx("op@acme.example", authz.LevelOperator),
		connect.NewRequest(&fleetv1.GetNodeConfigRequest{NodeId: id})); err != nil {
		t.Fatalf("GetNodeConfig(node_id): %v", err)
	}
	if !connA.closed {
		t.Error("the node was not dialed")
	}

	// Only GetNode falls back to a former name; other requests resolve
	// current names only.
	_, err := svc.GetNodeConfig(operatorCtx("op@acme.example", authz.LevelOperator),
		connect.NewRequest(&fleetv1.GetNodeConfigRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodeNotFound)
}

func TestSubordinateEnrollment_ByChildNodeID(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(nil))
	id := nodeID(t, st, "B")

	resp, err := svc.CreateEnrollment(operatorCtx("op@acme.example", authz.LevelOperator),
		connect.NewRequest(&fleetv1.CreateEnrollmentRequest{Kind: "SUBORDINATE", ChildNodeId: id, ParentCn: "Root", Profile: "p1"}))
	if err != nil {
		t.Fatalf("CreateEnrollment(child_node_id): %v", err)
	}
	if got := resp.Msg.GetEnrollment().GetProposedName(); got != "B" {
		t.Errorf("proposed name = %q, want the child's name B", got)
	}
}

func TestListCertificates_CarriesIssuerNodeID(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{
		issued:      &cryptosv1.ListIssuedResponse{Issued: []*cryptosv1.IssuedCert{{SerialHex: "01"}}},
		revocations: &cryptosv1.ListRevocationsResponse{},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))
	id := nodeID(t, st, "A")

	resp, err := svc.ListCertificates(context.Background(), connect.NewRequest(&fleetv1.ListCertificatesRequest{NodeId: id}))
	if err != nil {
		t.Fatalf("ListCertificates(node_id): %v", err)
	}
	certs := resp.Msg.GetCertificates()
	if len(certs) != 1 || certs[0].GetIssuerNode() != "A" || certs[0].GetIssuerNodeId() != id {
		t.Fatalf("certificates = %+v, want one from A carrying its node id", certs)
	}
}

func TestListAudit_FillsNodeIDsWithoutRewritingEntries(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	st := memory.New([]store.Node{{Name: "pki-root", Endpoint: "root:443", Role: "root"}})
	first := nodeID(t, st, "pki-root")
	at := func(d time.Duration) string { return t0.Add(d).Format(time.RFC3339) }

	st.AddAuditEvent(store.AuditEvent{ID: "legacy", At: at(0), Kind: "config-applied", TargetKind: "node", TargetPath: "/nodes/pki-root"})
	st.AddAuditEvent(store.AuditEvent{ID: "legacy-cert", At: at(time.Hour), Kind: "revoked", TargetKind: "cert", TargetPath: "/nodes/pki-root/certs/01"})
	if _, err := st.RenameNode(first, "root-east", t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("RenameNode: %v", err)
	}
	st.AddNode(store.Node{Name: "pki-root", Endpoint: "other:443", Role: "root"})
	second := nodeID(t, st, "pki-root")
	st.AddAuditEvent(store.AuditEvent{ID: "reused-name", At: at(3 * time.Hour), Kind: "config-applied", TargetKind: "node", TargetPath: "/nodes/pki-root"})
	st.AddAuditEvent(store.AuditEvent{ID: "by-id", At: at(4 * time.Hour), Kind: "config-applied", TargetKind: "node", TargetPath: "/nodes/" + first})
	st.AddAuditEvent(store.AuditEvent{ID: "profile", At: at(5 * time.Hour), Kind: "profile-created", TargetKind: "profile", TargetPath: "/profiles/p1"})
	st.AddAuditEvent(store.AuditEvent{ID: "unknown", At: at(6 * time.Hour), Kind: "issued", TargetKind: "node", TargetPath: "/nodes/never-existed"})
	stored := st.Audit()

	svc := New(st, dialFor(nil))
	resp, err := svc.ListAudit(context.Background(), connect.NewRequest(&fleetv1.ListAuditRequest{}))
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}

	want := map[string]string{
		"legacy":      first,
		"legacy-cert": first,
		"reused-name": second,
		"by-id":       first,
		"profile":     "",
		"unknown":     "",
	}
	for i, item := range resp.Msg.GetItems() {
		if got := item.GetNodeId(); got != want[item.GetId()] {
			t.Errorf("entry %s node_id = %q, want %q", item.GetId(), got, want[item.GetId()])
		}
		if item.GetTargetPath() != stored[i].TargetPath {
			t.Errorf("entry %s target_path = %q, want the stored %q", item.GetId(), item.GetTargetPath(), stored[i].TargetPath)
		}
	}

	after := st.Audit()
	for i := range stored {
		if after[i] != stored[i] {
			t.Errorf("ListAudit changed stored entry %s", stored[i].ID)
		}
		if got := store.HashEvent(after[i].PrevHash, after[i]); got != after[i].Hash {
			t.Errorf("entry %s no longer verifies against its hash", after[i].ID)
		}
	}
}

func TestNodeAudit_TargetsTheNodeID(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{remoteResetResp: &cryptosv1.RemoteResetResponse{Rebooting: true}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))
	id := nodeID(t, st, "A")

	if _, err := svc.DecommissionNode(operatorCtx("admin@acme.example", authz.LevelAdmin),
		connect.NewRequest(&fleetv1.DecommissionNodeRequest{NodeId: id, ConfirmCommonName: "Root CA A"})); err != nil {
		t.Fatalf("DecommissionNode(node_id): %v", err)
	}
	audit := st.Audit()
	if len(audit) != 1 || audit[0].TargetPath != "/nodes/"+id {
		t.Fatalf("audit = %+v, want one entry targeting /nodes/%s", audit, id)
	}
	if !strings.Contains(audit[0].Summary, "A") {
		t.Errorf("audit summary %q should keep the node's name", audit[0].Summary)
	}
}

func TestApproveEnrollment_Subordinate_RecordsAdmittedNodeID(t *testing.T) {
	st, svc := subordinateApprovalFixture(t)
	resp, err := svc.ApproveEnrollment(operatorCtx("op@acme.example", authz.LevelOperator),
		connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{Id: "enr-1"}))
	if err != nil {
		t.Fatalf("ApproveEnrollment: %v", err)
	}
	want := nodeID(t, st, "child-1")
	if got := resp.Msg.GetEnrollment().GetAdmittedNodeId(); got != want {
		t.Errorf("admitted_node_id = %q, want %q", got, want)
	}
	if e, _ := st.Enrollment("enr-1"); e.AdmittedNodeID != want {
		t.Errorf("stored admitted node id = %q, want %q", e.AdmittedNodeID, want)
	}
}

func TestApproveEnrollment_Subordinate_ChildRenamedAfterRequest(t *testing.T) {
	st, svc := subordinateApprovalFixture(t)
	child := nodeID(t, st, "child-1")
	if _, err := st.RenameNode(child, "child-east", time.Now()); err != nil {
		t.Fatalf("RenameNode: %v", err)
	}
	resp, err := svc.ApproveEnrollment(operatorCtx("op@acme.example", authz.LevelOperator),
		connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{Id: "enr-1"}))
	if err != nil {
		t.Fatalf("ApproveEnrollment after the child was renamed: %v", err)
	}
	if got := resp.Msg.GetEnrollment().GetAdmittedNodeId(); got != child {
		t.Errorf("admitted_node_id = %q, want %q", got, child)
	}
}

func subordinateApprovalFixture(t *testing.T) (store.Store, *Service) {
	t.Helper()
	parentConn := &fakeConn{signSubordinateResp: &cryptosv1.SignSubordinateCSRResponse{ChainDer: [][]byte{[]byte("c")}, ChainPem: "pem"}}
	st := memory.NewWithCatalog(
		[]store.Node{{Name: "child-1", Endpoint: "child:4443"}, {Name: "parent-1", Endpoint: "parent:4443"}},
		nil, nil, nil,
		[]store.Enrollment{{ID: "enr-1", Kind: "SUBORDINATE", Status: "PENDING", ProposedName: "child-1", ParentCN: "ACME Intermediate CA", Profile: "sub-ca"}},
	)
	parentID := &fakeConn{identity: &cryptosv1.GetIdentityResponse{Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "ACME Intermediate CA", "ACME Root CA")}}}}
	childID := &fakeConn{identity: &cryptosv1.GetIdentityResponse{Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "child-1", "ACME Intermediate CA")}}}}
	svc := New(st, func(n store.Node) (NodeConn, error) {
		if n.Name == "parent-1" {
			return &routingConn{identity: parentID, ferry: parentConn}, nil
		}
		return &routingConn{identity: childID, ferry: &fakeConn{}}, nil
	}).WithEnrollment(dialPEMFakeFor(&fakeConn{}))
	return st, svc
}

func TestApproveEnrollment_Link_RecordsAdmittedNodeID(t *testing.T) {
	for label, inventoried := range map[string]bool{"node in the inventory": true, "node not in the inventory": false} {
		t.Run(label, func(t *testing.T) {
			key := mustKey(t)
			st := memory.New(nil)
			nodeIdentity := &cryptosv1.GetIdentityResponse{Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "node-1", "ACME Root CA")}}}
			svc := New(st, dialFor(nil)).WithEnrollment(dialPEMFakeFor(&fakeConn{attestKey: key, identity: nodeIdentity}))
			create, err := svc.CreateEnrollment(operatorCtx("op@acme.example", authz.LevelOperator), connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
				Kind: "LINK", NodeEndpoint: "node:4443", AdminCertPem: "cert", AdminKeyPem: "key", CaPem: "ca",
			}))
			if err != nil {
				t.Fatalf("CreateEnrollment: %v", err)
			}
			enr := create.Msg.GetEnrollment()
			var want string
			if inventoried {
				st.AddNode(store.Node{Name: enr.GetProposedName(), Endpoint: "node:4443"})
				want = nodeID(t, st, enr.GetProposedName())
			}

			resp, err := svc.ApproveEnrollment(operatorCtx("admin@acme.example", authz.LevelAdmin), connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{
				Id: enr.GetId(), NodeEndpoint: "node:4443", AdminCertPem: "cert", AdminKeyPem: "key", CaPem: "ca",
			}))
			if err != nil {
				t.Fatalf("ApproveEnrollment: %v", err)
			}
			got := resp.Msg.GetEnrollment().GetAdmittedNodeId()
			u, perr := uuid.Parse(got)
			if perr != nil || u.Version() != 7 {
				t.Fatalf("admitted_node_id = %q, want a UUIDv7", got)
			}
			if inventoried && got != want {
				t.Errorf("admitted_node_id = %q, want the inventoried node's %q", got, want)
			}
		})
	}
}

func TestRunAdoption_RegistersANodeIDAndReturnsIt(t *testing.T) {
	adoptCredsBaseDir = t.TempDir()
	st := memory.New(nil)
	mconn := &fakeConn{applyConfigResp: &cryptosv1.ApplyConfigResponse{RequiresReboot: true, Generation: 1}}
	running := &fakeConn{
		identity: rootIdentity(t),
		status:   &cryptosv1.GetStatusResponse{},
		ceremonyStream: &scriptedCeremony{kinds: []cryptosv1.CeremonyEventKind{
			cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE,
		}},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"new-node": running})).WithAdoption(nil,
		func(string, string, string, string) (NodeConn, error) { return mconn, nil })
	restore := setRebootTiming(5*time.Millisecond, time.Millisecond, time.Millisecond)
	defer restore()

	req := &fleetv1.AdoptNodeRequest{Endpoint: "node:4443", PinnedCertSha256: "abc", Config: adoptConfig()}
	var final *fleetv1.AdoptNodeResponse
	if err := svc.runAdoption(context.Background(), req, func(phase, detail string, done bool) error {
		final = svc.adoptResponse(req, phase, detail, done)
		return nil
	}); err != nil {
		t.Fatalf("runAdoption: %v", err)
	}

	id := nodeID(t, st, "new-node")
	if u, err := uuid.Parse(id); err != nil || u.Version() != 7 {
		t.Fatalf("adopted node id = %q, want a UUIDv7", id)
	}
	if !final.GetDone() || final.GetNodeId() != id {
		t.Fatalf("final message = %+v, want done carrying node id %s", final, id)
	}
	if ev := st.Audit(); len(ev) != 1 || ev[0].TargetPath != "/nodes/"+id {
		t.Fatalf("audit = %+v, want node-adopted targeting /nodes/%s", ev, id)
	}
	if mid := svc.adoptResponse(req, phaseCeremony, "", false); mid.GetNodeId() != "" {
		t.Errorf("a progress message carries node id %q, want it on the final message only", mid.GetNodeId())
	}
	if failed := svc.adoptResponse(req, phaseError, "boom", true); failed.GetNodeId() != "" {
		t.Errorf("an error message carries node id %q", failed.GetNodeId())
	}
}
