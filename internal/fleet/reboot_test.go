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
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRebootNode_Admin_RebootsAndAudits(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{rebootResp: &nodev1.RebootResponse{Rebooting: true}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.RebootNode(ctx, connect.NewRequest(&fleetv1.RebootNodeRequest{
		NodeName: "A", ConfirmCaCn: "Root CA A",
	}))
	if err != nil {
		t.Fatalf("RebootNode(admin) error = %v", err)
	}
	if conn.gotRebootCN != "Root CA A" {
		t.Errorf("node Reboot CN = %q, want Root CA A", conn.gotRebootCN)
	}
	if conn.gotRebootPowerOff {
		t.Error("node Reboot power_off = true, want false")
	}
	if !resp.Msg.GetRebooting() {
		t.Error("response Rebooting = false, want true")
	}
	if !conn.closed {
		t.Error("node connection was not closed")
	}

	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "node-rebooted" {
		t.Fatalf("audit = %+v, want one node-rebooted event", audit)
	}
	if !strings.Contains(audit[0].Summary, "A") {
		t.Errorf("audit summary %q does not name the node", audit[0].Summary)
	}
}

func TestRebootNode_PowerOff_RelaysFlagAndAudits(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{rebootResp: &nodev1.RebootResponse{Rebooting: true}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.RebootNode(ctx, connect.NewRequest(&fleetv1.RebootNodeRequest{
		NodeName: "A", ConfirmCaCn: "Root CA A", PowerOff: true,
	}))
	if err != nil {
		t.Fatalf("RebootNode(power_off) error = %v", err)
	}
	if !conn.gotRebootPowerOff {
		t.Error("node Reboot power_off = false, want true")
	}
	if !resp.Msg.GetRebooting() {
		t.Error("response Rebooting = false, want true")
	}

	audit := st.Audit()
	if len(audit) != 1 || !strings.Contains(audit[0].Summary, "power off") {
		t.Fatalf("audit = %+v, want a power-off summary", audit)
	}
}

func TestRebootNode_ViewerDenied_NoDialNoAudit(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.RebootNode(ctx, connect.NewRequest(&fleetv1.RebootNodeRequest{
		NodeName: "A", ConfirmCaCn: "Root CA A",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if conn.gotRebootCN != "" || conn.closed {
		t.Error("node was dialed/rebooted on a denied request")
	}
	if len(st.Audit()) != 0 {
		t.Error("denied request wrote an audit event")
	}
}

func TestRebootNode_UnknownNode_NotFound(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.RebootNode(ctx, connect.NewRequest(&fleetv1.RebootNodeRequest{
		NodeName: "missing", ConfirmCaCn: "x",
	}))
	requireConnectCode(t, err, connect.CodeNotFound)
	if len(st.Audit()) != 0 {
		t.Error("unknown node wrote an audit event")
	}
}

func TestRebootNode_MissingConfirmCN_InvalidArgument(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{"A": {}}))
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.RebootNode(ctx, connect.NewRequest(&fleetv1.RebootNodeRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestRebootNode_CNMismatch_MappedToNodeRefused_WithReason(t *testing.T) {
	st := certsTestStore()
	// The node rejects a wrong CA CN with gRPC PermissionDenied (reboot.go:
	// reset.ErrConfirmMismatch).
	conn := &fakeConn{rebootErr: status.Error(codes.PermissionDenied, "Reboot: confirmation CN does not match the CA CN")}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.RebootNode(ctx, connect.NewRequest(&fleetv1.RebootNodeRequest{
		NodeName: "A", ConfirmCaCn: "wrong CN",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	requireAppCode(t, err, apperr.CodeNodeRefused)
	requireNodeReason(t, err, "Reboot: confirmation CN does not match the CA CN")
	if len(st.Audit()) != 0 {
		t.Error("a CN mismatch wrote an audit event")
	}
}
