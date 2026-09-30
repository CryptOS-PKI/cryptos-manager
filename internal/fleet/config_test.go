package fleet

/*
Apache License 2.0

Copyright 2026 Shane

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
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"google.golang.org/protobuf/proto"
)

// configFixture returns a fully-populated MachineConfig standing in for the
// node's current config, so the fleet flow has real management/role/pki content
// to round-trip.
func configFixture() *cryptosv1.MachineConfig {
	return &cryptosv1.MachineConfig{
		ApiVersion: "cryptos.dev/v1alpha1",
		Kind:       "MachineConfig",
		Metadata:   &cryptosv1.Metadata{Name: "A"},
		Role:       &cryptosv1.Role{Kind: "root"},
		Pki:        &cryptosv1.Pki{RootKeyAlg: "ECDSA-P384", RevocationBaseUrl: "http://ca.acme/crl"},
		Management: &cryptosv1.Management{ManagerCn: "fm-op", TrustPem: "trust-pem"},
	}
}

func TestGetNodeConfig_ViewerDenied_NoDial(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{getConfigResp: &cryptosv1.GetConfigResponse{Config: configFixture()}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.GetNodeConfig(ctx, connect.NewRequest(&fleetv1.GetNodeConfigRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)

	if connA.closed {
		t.Error("node connection was opened, want no dial for a denied caller")
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (reads are never audited)", len(st.Audit()), before)
	}
}

func TestGetNodeConfig_UnknownNode_NotFound(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{}))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.GetNodeConfig(ctx, connect.NewRequest(&fleetv1.GetNodeConfigRequest{NodeName: "missing"}))
	requireConnectCode(t, err, connect.CodeNotFound)
}

func TestGetNodeConfig_Operator_ReturnsConfig_NoAudit(t *testing.T) {
	st := certsTestStore()
	want := configFixture()
	connA := &fakeConn{getConfigResp: &cryptosv1.GetConfigResponse{Config: want}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.GetNodeConfig(ctx, connect.NewRequest(&fleetv1.GetNodeConfigRequest{NodeName: "A"}))
	if err != nil {
		t.Fatalf("GetNodeConfig(operator) error = %v, want nil", err)
	}
	if !proto.Equal(resp.Msg.GetConfig(), want) {
		t.Errorf("GetNodeConfig returned %v, want %v", resp.Msg.GetConfig(), want)
	}
	if !connA.closed {
		t.Error("node connection was not closed")
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (a read is not audited)", len(st.Audit()), before)
	}
}

func TestApplyNodeConfig_OperatorDenied_AdminRequired_NoDialNoAudit(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.ApplyNodeConfig(ctx, connect.NewRequest(&fleetv1.ApplyNodeConfigRequest{
		NodeName: "A",
		Config:   configFixture(),
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)

	if connA.gotApplyConfig != nil {
		t.Error("node ApplyConfig was called for a non-admin caller")
	}
	if connA.closed {
		t.Error("node connection was opened, want no dial for a denied caller")
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event on denial)", len(st.Audit()), before)
	}
}

func TestApplyNodeConfig_NilConfig_InvalidArgument(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ApplyNodeConfig(ctx, connect.NewRequest(&fleetv1.ApplyNodeConfigRequest{
		NodeName: "A",
		Config:   nil,
	}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)

	if connA.gotApplyConfig != nil {
		t.Error("node ApplyConfig was called with a nil config")
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event on invalid argument)", len(st.Audit()), before)
	}
}

func TestApplyNodeConfig_UnknownNode_NotFound(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{}))

	before := len(st.Audit())
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ApplyNodeConfig(ctx, connect.NewRequest(&fleetv1.ApplyNodeConfigRequest{
		NodeName: "missing",
		Config:   configFixture(),
	}))
	requireConnectCode(t, err, connect.CodeNotFound)

	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event when node unknown)", len(st.Audit()), before)
	}
}

func TestApplyNodeConfig_Admin_AppliesExactConfig_AuditsOnce(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{applyConfigResp: &cryptosv1.ApplyConfigResponse{Generation: 7, RequiresReboot: true}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	sent := configFixture()
	before := len(st.Audit())
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.ApplyNodeConfig(ctx, connect.NewRequest(&fleetv1.ApplyNodeConfigRequest{
		NodeName: "A",
		Config:   sent,
	}))
	if err != nil {
		t.Fatalf("ApplyNodeConfig(admin) error = %v, want nil", err)
	}

	// The handler must forward the exact config from the request to the node,
	// never a partial or re-derived one.
	if !proto.Equal(connA.gotApplyConfig, sent) {
		t.Errorf("node ApplyConfig got %v, want the request config %v", connA.gotApplyConfig, sent)
	}
	if !connA.closed {
		t.Error("node connection was not closed")
	}

	if resp.Msg.GetGeneration() != 7 {
		t.Errorf("response generation = %d, want 7", resp.Msg.GetGeneration())
	}
	if !resp.Msg.GetRequiresReboot() {
		t.Error("response requiresReboot = false, want true")
	}

	audit := st.Audit()
	if len(audit) != before+1 {
		t.Fatalf("audit len = %d, want %d (exactly one new event)", len(audit), before+1)
	}
	last := audit[len(audit)-1]
	if last.Kind != "config-applied" {
		t.Errorf("audit Kind = %q, want config-applied", last.Kind)
	}
	if !strings.Contains(last.Summary, "A") {
		t.Errorf("audit Summary = %q, want it to name the node", last.Summary)
	}
	if last.TargetKind != "node" {
		t.Errorf("audit TargetKind = %q, want node", last.TargetKind)
	}
	if last.TargetPath != "/nodes/A" {
		t.Errorf("audit TargetPath = %q, want /nodes/A", last.TargetPath)
	}
}

func TestApplyNodeConfig_NodeError_MappedNoAudit(t *testing.T) {
	st := certsTestStore()
	connA := &fakeConn{err: errors.New("node down")}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ApplyNodeConfig(ctx, connect.NewRequest(&fleetv1.ApplyNodeConfigRequest{
		NodeName: "A",
		Config:   configFixture(),
	}))
	requireConnectCode(t, err, connect.CodeInternal)

	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event when the node errors)", len(st.Audit()), before)
	}
}
