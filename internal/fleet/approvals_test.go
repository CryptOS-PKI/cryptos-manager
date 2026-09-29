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
	"context"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/approval"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

var approvalAgent = authz.Identity{CN: "operator@example.org", Serial: "0A:BC", Level: authz.LevelAdmin, Via: authz.ViaMCP, KeyID: "mk-1"}

func approvalService() (*Service, *memory.Store, *approval.Service) {
	st := memory.New(nil)
	ap := &approval.Service{Store: st}
	return New(st, nil).WithApprovals(ap), st, ap
}

func TestApprovalRPCs_RefuseAnMCPKey(t *testing.T) {
	svc, _, ap := approvalService()
	a := ap.Request(context.Background(), approvalAgent, "cert_revoke", "d", "Revoke 0A", authz.LevelOperator)
	keyCtx := authz.NewContext(context.Background(), approvalAgent)

	_, err := svc.ListApprovals(keyCtx, connect.NewRequest(&fleetv1.ListApprovalsRequest{}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	requireAppCode(t, err, apperr.CodeApprovalNeedsCert)

	_, err = svc.DecideApproval(keyCtx, connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: a.ID, Approve: true}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	requireAppCode(t, err, apperr.CodeApprovalNeedsCert)
	if got, _ := ap.Get(a.ID); got.Status != store.ApprovalPending {
		t.Fatalf("status = %s after a key tried to decide", got.Status)
	}
}

func TestListApprovals_NewestFirstWithStatusFilter(t *testing.T) {
	svc, _, ap := approvalService()
	first := ap.Request(context.Background(), approvalAgent, "cert_revoke", "d1", "Revoke 0A", authz.LevelOperator)
	second := ap.Request(context.Background(), approvalAgent, "profile_delete", "d2", "Delete tls-server", authz.LevelAdmin)
	viewer := certCtx(t, 0x21, authz.LevelViewer)
	if _, err := svc.DecideApproval(certCtx(t, 0x22, authz.LevelAdmin), connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: first.ID})); err != nil {
		t.Fatalf("deny: %v", err)
	}

	resp, err := svc.ListApprovals(viewer, connect.NewRequest(&fleetv1.ListApprovalsRequest{}))
	if err != nil {
		t.Fatalf("ListApprovals: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 2 {
		t.Fatalf("items = %v", items)
	}
	ids := map[string]*fleetv1.Approval{items[0].GetId(): items[0], items[1].GetId(): items[1]}
	if ids[second.ID].GetStatus() != "pending" || ids[second.ID].GetRequiredLevel() != "admin" || ids[second.ID].GetKeyId() != "mk-1" ||
		ids[second.ID].GetRequestedBySerial() != "0A:BC" || ids[second.ID].GetSummary() != "Delete tls-server" || ids[second.ID].GetExpiresAt() == "" {
		t.Fatalf("pending item = %v", ids[second.ID])
	}
	if ids[first.ID].GetStatus() != "denied" || ids[first.ID].GetDecidedBySerial() != "22" || ids[first.ID].GetDecidedAt() == "" {
		t.Fatalf("denied item = %v", ids[first.ID])
	}

	pending, err := svc.ListApprovals(viewer, connect.NewRequest(&fleetv1.ListApprovalsRequest{Status: "pending"}))
	if err != nil || len(pending.Msg.GetItems()) != 1 || pending.Msg.GetItems()[0].GetId() != second.ID {
		t.Fatalf("ListApprovals(pending) = %v, %v", pending, err)
	}
	_, err = svc.ListApprovals(viewer, connect.NewRequest(&fleetv1.ListApprovalsRequest{Status: "bogus"}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestDecideApproval_ApprovesWithTheDecidersIdentity(t *testing.T) {
	svc, st, ap := approvalService()
	a := ap.Request(context.Background(), approvalAgent, "cert_revoke", "d", "Revoke 0A", authz.LevelOperator)

	resp, err := svc.DecideApproval(certCtx(t, 0x0def, authz.LevelOperator), connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: a.ID, Approve: true}))
	if err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	got := resp.Msg.GetApproval()
	if got.GetStatus() != "approved" || got.GetDecidedBySerial() != "0D:EF" || got.GetDecidedByCn() != "operator@example.org" {
		t.Fatalf("approval = %v", got)
	}
	all := st.Audit()
	if e := all[len(all)-1]; e.Kind != approval.KindApproved || e.ApprovalID != a.ID || e.ApproverSerial != "0D:EF" || e.Via != "web" {
		t.Fatalf("audit = %+v", e)
	}
}

func TestDecideApproval_Refusals(t *testing.T) {
	t.Run("decider below the required level", func(t *testing.T) {
		svc, _, ap := approvalService()
		a := ap.Request(context.Background(), approvalAgent, "profile_delete", "d", "Delete", authz.LevelAdmin)
		_, err := svc.DecideApproval(certCtx(t, 5, authz.LevelOperator), connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: a.ID, Approve: true}))
		requireConnectCode(t, err, connect.CodePermissionDenied)
		requireAppCode(t, err, apperr.CodeApproverLevelTooLow)
	})
	t.Run("unknown id", func(t *testing.T) {
		svc, _, _ := approvalService()
		_, err := svc.DecideApproval(certCtx(t, 5, authz.LevelAdmin), connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: "apr-missing", Approve: true}))
		requireConnectCode(t, err, connect.CodeNotFound)
		requireAppCode(t, err, apperr.CodeApprovalNotFound)
	})
	t.Run("already decided", func(t *testing.T) {
		svc, _, ap := approvalService()
		a := ap.Request(context.Background(), approvalAgent, "cert_revoke", "d", "Revoke", authz.LevelOperator)
		admin := certCtx(t, 5, authz.LevelAdmin)
		if _, err := svc.DecideApproval(admin, connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: a.ID, Approve: true})); err != nil {
			t.Fatal(err)
		}
		_, err := svc.DecideApproval(admin, connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: a.ID}))
		requireConnectCode(t, err, connect.CodeFailedPrecondition)
		requireAppCode(t, err, apperr.CodeApprovalNotPending)
	})
	t.Run("approvals not configured", func(t *testing.T) {
		svc := New(memory.New(nil), nil)
		_, err := svc.ListApprovals(certCtx(t, 5, authz.LevelAdmin), connect.NewRequest(&fleetv1.ListApprovalsRequest{}))
		requireConnectCode(t, err, connect.CodeFailedPrecondition)
		requireAppCode(t, err, apperr.CodeMcpDisabled)
	})
}
