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
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	acme = cryptosv1.ServiceProtocol_SERVICE_PROTOCOL_ACME
	est  = cryptosv1.ServiceProtocol_SERVICE_PROTOCOL_EST
)

func protocolTestStore() store.Store {
	return memory.New([]store.Node{{Name: "issuing-1", Endpoint: "i1.acme.com:4443", Role: "issuing"}})
}

// protocolConfigFixture is an issuing node's config as GetConfig returns it:
// both protocol blocks explicit, write-only secrets blank.
func protocolConfigFixture() *cryptosv1.MachineConfig {
	return &cryptosv1.MachineConfig{
		ApiVersion: "cryptos.dev/v1alpha1",
		Kind:       "MachineConfig",
		Metadata:   &cryptosv1.Metadata{Name: "issuing-1"},
		Role:       &cryptosv1.Role{Kind: "issuing"},
		Pki: &cryptosv1.Pki{
			RevocationBaseUrl: "http://ca.acme/crl",
			Acme: &cryptosv1.Acme{
				Enabled:             false,
				BaseUrl:             "https://ca.acme/acme",
				Profile:             "tls-server",
				ExternalAccountKeys: []*cryptosv1.AcmeExternalAccountKey{{KeyId: "k1"}},
			},
			Est: &cryptosv1.Est{
				Enabled:           true,
				Hostnames:         []string{"est.acme"},
				Profile:           "device",
				EnrollCredentials: []*cryptosv1.EstEnrollCredential{{Username: "router"}},
			},
		},
		Management: &cryptosv1.Management{ManagerCn: "fm-op", TrustPem: "trust-pem"},
	}
}

func setProtocol(t *testing.T, svc *Service, level authz.Level, p cryptosv1.ServiceProtocol, enabled bool) (*connect.Response[fleetv1.SetNodeProtocolResponse], error) {
	t.Helper()
	ctx := operatorCtx("admin@acme.example", level)
	return svc.SetNodeProtocol(ctx, connect.NewRequest(&fleetv1.SetNodeProtocolRequest{
		NodeName: "issuing-1", Protocol: p, Enabled: enabled,
	}))
}

func TestSetNodeProtocol_OperatorDenied_NoDialNoAudit(t *testing.T) {
	st := protocolTestStore()
	conn := &fakeConn{getConfigResp: &cryptosv1.GetConfigResponse{Config: protocolConfigFixture()}}
	svc := New(st, dialFor(map[string]*fakeConn{"issuing-1": conn}))

	_, err := setProtocol(t, svc, authz.LevelOperator, acme, true)
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if conn.closed || conn.gotApplyConfig != nil {
		t.Error("a denied caller reached the node")
	}
	if len(st.Audit()) != 0 {
		t.Errorf("audit len = %d, want 0", len(st.Audit()))
	}
}

func TestSetNodeProtocol_UnswitchableProtocol_InvalidArgument(t *testing.T) {
	conn := &fakeConn{}
	svc := New(protocolTestStore(), dialFor(map[string]*fakeConn{"issuing-1": conn}))

	_, err := setProtocol(t, svc, authz.LevelAdmin, cryptosv1.ServiceProtocol_SERVICE_PROTOCOL_UNSPECIFIED, true)
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	if conn.closed {
		t.Error("the node was dialed for a protocol the manager cannot switch")
	}
}

func TestSetNodeProtocol_UnknownNode_NotFound(t *testing.T) {
	svc := New(protocolTestStore(), dialFor(map[string]*fakeConn{}))
	_, err := svc.SetNodeProtocol(operatorCtx("admin@acme.example", authz.LevelAdmin), connect.NewRequest(&fleetv1.SetNodeProtocolRequest{
		NodeName: "missing", Protocol: acme, Enabled: true,
	}))
	requireConnectCode(t, err, connect.CodeNotFound)
}

func TestSetNodeProtocol_EnableACME_FlipsOnlyThatBlock(t *testing.T) {
	st := protocolTestStore()
	conn := &fakeConn{
		getConfigResp:   &cryptosv1.GetConfigResponse{Config: protocolConfigFixture()},
		applyConfigResp: &cryptosv1.ApplyConfigResponse{Generation: 12, RequiresReboot: true},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"issuing-1": conn}))

	resp, err := setProtocol(t, svc, authz.LevelAdmin, acme, true)
	if err != nil {
		t.Fatalf("SetNodeProtocol: %v", err)
	}
	if resp.Msg.GetGeneration() != 12 || !resp.Msg.GetRequiresReboot() {
		t.Errorf("response = %v, want generation 12 and requires_reboot", resp.Msg)
	}

	want := protocolConfigFixture()
	want.Pki.Acme.Enabled = true
	// The other protocol block is left out, so the node keeps it as stored.
	want.Pki.Est = nil
	if !proto.Equal(conn.gotApplyConfig, want) {
		t.Errorf("applied config:\n got  %v\n want %v", conn.gotApplyConfig, want)
	}
	if got := conn.gotApplyConfig.GetPki().GetAcme().GetExternalAccountKeys()[0]; got.GetKeyId() != "k1" || got.GetHmacKeyBase64() != "" {
		t.Errorf("EAB key = %v, want key_id k1 with the secret left blank for the node to keep", got)
	}
	if !conn.closed {
		t.Error("node connection was not closed")
	}

	audit := st.Audit()
	if len(audit) != 1 {
		t.Fatalf("audit len = %d, want 1", len(audit))
	}
	e := audit[0]
	if e.Kind != "protocol-enabled" || e.ActorCN != "admin@acme.example" || e.TargetPath != "/nodes/issuing-1" {
		t.Errorf("audit = %+v, want protocol-enabled by admin@acme.example on /nodes/issuing-1", e)
	}
	if !strings.Contains(e.Summary, "ACME") || !strings.Contains(e.Summary, "issuing-1") {
		t.Errorf("audit summary = %q, want it to name the protocol and the node", e.Summary)
	}
}

func TestSetNodeProtocol_DisableEST_KeepsItsSettings(t *testing.T) {
	st := protocolTestStore()
	conn := &fakeConn{
		getConfigResp:   &cryptosv1.GetConfigResponse{Config: protocolConfigFixture()},
		applyConfigResp: &cryptosv1.ApplyConfigResponse{Generation: 3, RequiresReboot: true},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"issuing-1": conn}))

	if _, err := setProtocol(t, svc, authz.LevelAdmin, est, false); err != nil {
		t.Fatalf("SetNodeProtocol: %v", err)
	}
	want := protocolConfigFixture()
	want.Pki.Est.Enabled = false
	want.Pki.Acme = nil
	if !proto.Equal(conn.gotApplyConfig, want) {
		t.Errorf("applied config:\n got  %v\n want %v", conn.gotApplyConfig, want)
	}
	if audit := st.Audit(); len(audit) != 1 || audit[0].Kind != "protocol-disabled" || !strings.Contains(audit[0].Summary, "EST") {
		t.Errorf("audit = %+v, want one protocol-disabled event naming EST", audit)
	}
}

func TestSetNodeProtocol_NoBlockYet_SendsEnabledBlockForTheNodeToValidate(t *testing.T) {
	cfg := protocolConfigFixture()
	cfg.Pki.Acme = nil
	conn := &fakeConn{
		getConfigResp:   &cryptosv1.GetConfigResponse{Config: cfg},
		applyConfigResp: &cryptosv1.ApplyConfigResponse{Generation: 4, RequiresReboot: true},
	}
	svc := New(protocolTestStore(), dialFor(map[string]*fakeConn{"issuing-1": conn}))

	if _, err := setProtocol(t, svc, authz.LevelAdmin, acme, true); err != nil {
		t.Fatalf("SetNodeProtocol: %v", err)
	}
	if !proto.Equal(conn.gotApplyConfig.GetPki().GetAcme(), &cryptosv1.Acme{Enabled: true}) {
		t.Errorf("acme block = %v, want a bare enabled block", conn.gotApplyConfig.GetPki().GetAcme())
	}
}

func TestSetNodeProtocol_AlreadyInState_NoApplyNoAudit(t *testing.T) {
	st := protocolTestStore()
	conn := &fakeConn{getConfigResp: &cryptosv1.GetConfigResponse{Config: protocolConfigFixture()}}
	svc := New(st, dialFor(map[string]*fakeConn{"issuing-1": conn}))

	resp, err := setProtocol(t, svc, authz.LevelAdmin, est, true)
	if err != nil {
		t.Fatalf("SetNodeProtocol: %v", err)
	}
	if conn.gotApplyConfig != nil {
		t.Error("the node config was applied for a protocol already in the requested state")
	}
	if resp.Msg.GetRequiresReboot() {
		t.Error("requires_reboot = true for a no-op")
	}
	if len(st.Audit()) != 0 {
		t.Errorf("audit len = %d, want 0 for a no-op", len(st.Audit()))
	}
}

func TestSetNodeProtocol_NodeRefusal_KeepsItsCodeAndReason(t *testing.T) {
	st := protocolTestStore()
	conn := &fakeConn{
		getConfigResp:  &cryptosv1.GetConfigResponse{Config: protocolConfigFixture()},
		applyConfigErr: status.Error(codes.InvalidArgument, `pki.acme: profile "tls-server" not found`),
	}
	svc := New(st, dialFor(map[string]*fakeConn{"issuing-1": conn}))

	_, err := setProtocol(t, svc, authz.LevelAdmin, acme, true)
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	if !strings.Contains(err.Error(), `profile "tls-server" not found`) {
		t.Errorf("error = %v, want the node's reason", err)
	}
	if len(st.Audit()) != 0 {
		t.Errorf("audit len = %d, want 0 when the node refuses", len(st.Audit()))
	}
	if svc.reboots.pendingFor("issuing-1") != 0 {
		t.Error("a refused switch was recorded as waiting for a reboot")
	}
}

func protocolStatusResp(protocols []*cryptosv1.ProtocolStatus, pending bool) *cryptosv1.GetStatusResponse {
	return &cryptosv1.GetStatusResponse{Status: &cryptosv1.NodeStatus{
		IdentityState:       cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED,
		Protocols:           protocols,
		ConfigRebootPending: pending,
	}}
}

func getSummary(t *testing.T, svc *Service) *fleetv1.NodeSummary {
	t.Helper()
	resp, err := svc.GetNode(operatorCtx("viewer@acme.example", authz.LevelViewer), connect.NewRequest(&fleetv1.GetNodeRequest{Name: "issuing-1"}))
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	return resp.Msg.GetNode().GetSummary()
}

func TestSetNodeProtocol_RebootRequiredUntilTheNodeRunsIt(t *testing.T) {
	conn := &fakeConn{
		getConfigResp:   &cryptosv1.GetConfigResponse{Config: protocolConfigFixture()},
		applyConfigResp: &cryptosv1.ApplyConfigResponse{Generation: 5, RequiresReboot: true},
		// A node that predates the protocol report says nothing either way.
		status: protocolStatusResp(nil, false),
	}
	svc := New(protocolTestStore(), dialFor(map[string]*fakeConn{"issuing-1": conn}))

	if _, err := setProtocol(t, svc, authz.LevelAdmin, acme, true); err != nil {
		t.Fatalf("SetNodeProtocol: %v", err)
	}
	if !getSummary(t, svc).GetRebootRequired() {
		t.Error("reboot_required = false straight after a reboot-required switch")
	}

	// Stored but not booted: the node reports it configured and pending.
	conn.status = protocolStatusResp([]*cryptosv1.ProtocolStatus{
		{Protocol: acme, Configured: true, Running: false, RebootPending: true},
		{Protocol: est, Configured: true, Running: true},
	}, true)
	s := getSummary(t, svc)
	if !s.GetRebootRequired() {
		t.Error("reboot_required = false while the node reports config_reboot_pending")
	}
	if len(s.GetProtocols()) != 2 || !s.GetProtocols()[0].GetRebootPending() || s.GetProtocols()[0].GetRunning() {
		t.Errorf("protocols = %v, want ACME configured, not running, reboot pending", s.GetProtocols())
	}

	// A boot that did not bring ACME up keeps the flag.
	conn.status = protocolStatusResp([]*cryptosv1.ProtocolStatus{
		{Protocol: acme, Configured: true, Running: false},
		{Protocol: est, Configured: true, Running: true},
	}, false)
	s = getSummary(t, svc)
	if !s.GetRebootRequired() || !s.GetProtocols()[0].GetRebootPending() {
		t.Errorf("summary = %v, want ACME still waiting until it runs", s)
	}

	// After the reboot ACME runs and nothing is pending.
	conn.status = protocolStatusResp([]*cryptosv1.ProtocolStatus{
		{Protocol: acme, Configured: true, Running: true},
		{Protocol: est, Configured: true, Running: true},
	}, false)
	s = getSummary(t, svc)
	if s.GetRebootRequired() || s.GetProtocols()[0].GetRebootPending() {
		t.Errorf("summary = %v, want the reboot confirmed and cleared", s)
	}
	if svc.reboots.pendingFor("issuing-1") != 0 {
		t.Error("the confirmed switch is still recorded")
	}
}

func TestListNodes_ReportsProtocolStateAndNodeRebootFlag(t *testing.T) {
	conn := &fakeConn{status: protocolStatusResp([]*cryptosv1.ProtocolStatus{
		{Protocol: acme, Configured: false, Running: false},
		{Protocol: est, Configured: true, Running: true},
	}, true)}
	svc := New(protocolTestStore(), dialFor(map[string]*fakeConn{"issuing-1": conn}))

	resp, err := svc.ListNodes(operatorCtx("viewer@acme.example", authz.LevelViewer), connect.NewRequest(&fleetv1.ListNodesRequest{}))
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	s := resp.Msg.GetNodes()[0]
	if len(s.GetProtocols()) != 2 || s.GetProtocols()[1].GetProtocol() != est || !s.GetProtocols()[1].GetRunning() {
		t.Errorf("protocols = %v, want the node's report", s.GetProtocols())
	}
	if !s.GetRebootRequired() {
		t.Error("reboot_required = false while the node reports config_reboot_pending")
	}
}

func TestApplyNodeConfig_ProtocolSwitch_AuditedPerProtocolAndTracked(t *testing.T) {
	st := protocolTestStore()
	conn := &fakeConn{
		getConfigResp:   &cryptosv1.GetConfigResponse{Config: protocolConfigFixture()},
		applyConfigResp: &cryptosv1.ApplyConfigResponse{Generation: 8, RequiresReboot: true},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"issuing-1": conn}))

	sent := protocolConfigFixture()
	sent.Pki.Acme.Enabled = true
	sent.Pki.Est.Hostnames = []string{"est.acme", "est2.acme"}
	if _, err := svc.ApplyNodeConfig(operatorCtx("admin@acme.example", authz.LevelAdmin), connect.NewRequest(&fleetv1.ApplyNodeConfigRequest{
		NodeName: "issuing-1", Config: sent,
	})); err != nil {
		t.Fatalf("ApplyNodeConfig: %v", err)
	}
	if !proto.Equal(conn.gotApplyConfig, sent) {
		t.Error("ApplyNodeConfig did not forward the exact config")
	}

	var kinds []string
	for _, e := range st.Audit() {
		kinds = append(kinds, e.Kind)
	}
	if strings.Join(kinds, ",") != "protocol-enabled,config-applied" {
		t.Errorf("audit kinds = %v, want protocol-enabled then config-applied (EST only changed settings)", kinds)
	}
	if svc.reboots.pendingFor("issuing-1") != 1 {
		t.Error("the ACME switch was not recorded as waiting for a reboot")
	}
}

func TestApplyNodeConfig_ProtocolBlock_BaselineUnreadable_NoApply(t *testing.T) {
	st := protocolTestStore()
	conn := &fakeConn{err: status.Error(codes.Unavailable, "node gone")}
	svc := New(st, dialFor(map[string]*fakeConn{"issuing-1": conn}))

	_, err := svc.ApplyNodeConfig(operatorCtx("admin@acme.example", authz.LevelAdmin), connect.NewRequest(&fleetv1.ApplyNodeConfigRequest{
		NodeName: "issuing-1", Config: protocolConfigFixture(),
	}))
	if err == nil {
		t.Fatal("ApplyNodeConfig succeeded without the baseline the protocol audit needs")
	}
	if conn.gotApplyConfig != nil {
		t.Error("the config was applied although its protocol changes could not be audited")
	}
	if len(st.Audit()) != 0 {
		t.Errorf("audit len = %d, want 0", len(st.Audit()))
	}
}
