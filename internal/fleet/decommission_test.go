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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDecommissionNode_Admin_ResetsAndAudits(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{remoteResetResp: &cryptosv1.RemoteResetResponse{Rebooting: true}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.DecommissionNode(ctx, connect.NewRequest(&fleetv1.DecommissionNodeRequest{
		NodeName: "A", ConfirmCommonName: "Root CA A",
	}))
	if err != nil {
		t.Fatalf("DecommissionNode(admin) error = %v", err)
	}
	if conn.gotRemoteResetCN != "Root CA A" {
		t.Errorf("node RemoteReset CN = %q, want Root CA A", conn.gotRemoteResetCN)
	}
	if !resp.Msg.GetRebooting() {
		t.Error("response Rebooting = false, want true")
	}
	if !conn.closed {
		t.Error("node connection was not closed")
	}

	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "node-decommissioned" {
		t.Fatalf("audit = %+v, want one node-decommissioned event", audit)
	}
	if !strings.Contains(audit[0].Summary, "A") {
		t.Errorf("audit summary %q does not name the node", audit[0].Summary)
	}
}

func TestDecommissionNode_ViewerDenied_NoDialNoAudit(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.DecommissionNode(ctx, connect.NewRequest(&fleetv1.DecommissionNodeRequest{
		NodeName: "A", ConfirmCommonName: "Root CA A",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if conn.gotRemoteResetCN != "" || conn.closed {
		t.Error("node was dialed/reset on a denied request")
	}
	if len(st.Audit()) != 0 {
		t.Error("denied request wrote an audit event")
	}
}

func TestDecommissionNode_UnknownNode_NotFound(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.DecommissionNode(ctx, connect.NewRequest(&fleetv1.DecommissionNodeRequest{
		NodeName: "missing", ConfirmCommonName: "x",
	}))
	requireConnectCode(t, err, connect.CodeNotFound)
	if len(st.Audit()) != 0 {
		t.Error("unknown node wrote an audit event")
	}
}

func TestDecommissionNode_CNMismatch_MappedToPermissionDenied_NoAudit(t *testing.T) {
	st := certsTestStore()
	// The node rejects a wrong Root-CA CN with gRPC PermissionDenied.
	conn := &fakeConn{remoteResetErr: status.Error(codes.PermissionDenied, "confirm_common_name mismatch")}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.DecommissionNode(ctx, connect.NewRequest(&fleetv1.DecommissionNodeRequest{
		NodeName: "A", ConfirmCommonName: "wrong CN",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)

	var cerr *connect.Error
	_ = errors.As(err, &cerr)
	if cerr != nil && !strings.Contains(strings.ToLower(cerr.Message()), "root ca cn") {
		t.Errorf("error message %q should explain the Root CA CN confirmation mismatch", cerr.Message())
	}
	if len(st.Audit()) != 0 {
		t.Error("a CN mismatch wrote an audit event")
	}
}

func TestDecommissionNode_MissingConfirmCN_InvalidArgument(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{"A": {}}))
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.DecommissionNode(ctx, connect.NewRequest(&fleetv1.DecommissionNodeRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}
