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
	"errors"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestListNodeAuditEvents_Viewer_ReturnsEntries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	connA := &fakeConn{
		listAuditEventsResp: &nodev1.ListAuditEventsResponse{
			Entries: []*nodev1.AuditLogEntry{
				{
					Event: &nodev1.AuditEvent{
						Seq:          1,
						Ts:           timestamppb.New(now),
						ActorSubject: "CN=operator",
						RpcMethod:    "/cryptos.node.v1.NodeService/RevokeCertificate",
						Outcome:      nodev1.Outcome_OUTCOME_OK,
						Details:      map[string]string{"serial": "0a1b"},
					},
					EntrySha256: []byte{0xde, 0xad},
					Target:      "0a1b",
					Summary:     "revoked 0a1b",
				},
			},
			NextPageToken: "tok2",
		},
	}

	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	resp, err := svc.ListNodeAuditEvents(ctx, connect.NewRequest(&fleetv1.ListNodeAuditEventsRequest{
		NodeName: "A",
		PageSize: 10,
		Actor:    "operator",
	}))
	if err != nil {
		t.Fatalf("ListNodeAuditEvents() error = %v, want nil", err)
	}

	if connA.gotListAuditEvents == nil || connA.gotListAuditEvents.GetPageSize() != 10 || connA.gotListAuditEvents.GetActor() != "operator" {
		t.Errorf("node was called with %+v, want the request filters forwarded unchanged", connA.gotListAuditEvents)
	}

	entries := resp.Msg.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.GetSeq() != 1 || e.GetActorSubject() != "CN=operator" || e.GetOutcome() != "OK" || e.GetTarget() != "0a1b" || e.GetSummary() != "revoked 0a1b" {
		t.Errorf("entry = %+v, want the node's fields flattened through", e)
	}
	if e.GetTs() != now.Format(time.RFC3339) {
		t.Errorf("Ts = %q, want %q", e.GetTs(), now.Format(time.RFC3339))
	}
	if e.GetEntrySha256Hex() != "dead" {
		t.Errorf("EntrySha256Hex = %q, want %q", e.GetEntrySha256Hex(), "dead")
	}
	if e.GetDetails()["serial"] != "0a1b" {
		t.Errorf("Details = %v, want serial=0a1b", e.GetDetails())
	}
	if resp.Msg.GetNextPageToken() != "tok2" {
		t.Errorf("NextPageToken = %q, want %q", resp.Msg.GetNextPageToken(), "tok2")
	}
}

func TestListNodeAuditEvents_UnknownNode_NotFound(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.ListNodeAuditEvents(ctx, connect.NewRequest(&fleetv1.ListNodeAuditEventsRequest{NodeName: "missing"}))
	if err == nil {
		t.Fatal("ListNodeAuditEvents(unknown node) error = nil, want NotFound")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeNotFound {
		t.Errorf("code = %v, want CodeNotFound", connectErr.Code())
	}
}

func TestListNodeAuditEvents_Unauthenticated_Refused(t *testing.T) {
	connA := &fakeConn{}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	_, err := svc.ListNodeAuditEvents(context.Background(), connect.NewRequest(&fleetv1.ListNodeAuditEventsRequest{NodeName: "A"}))
	if err == nil {
		t.Fatal("ListNodeAuditEvents(no identity) error = nil, want Unauthenticated")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeUnauthenticated {
		t.Errorf("code = %v, want CodeUnauthenticated", connectErr.Code())
	}
	if connA.gotListAuditEvents != nil {
		t.Error("node was dialed, want no call for an unauthenticated caller")
	}
}

func TestListNodeAuditEvents_NodeError_Mapped(t *testing.T) {
	connA := &fakeConn{listAuditEventsErr: status.Error(codes.InvalidArgument, "page_token reused with different filters")}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.ListNodeAuditEvents(ctx, connect.NewRequest(&fleetv1.ListNodeAuditEventsRequest{NodeName: "A"}))
	if err == nil {
		t.Fatal("ListNodeAuditEvents() error = nil, want InvalidArgument")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want CodeInvalidArgument", connectErr.Code())
	}
}

func TestVerifyNodeAuditChain_Viewer_ReturnsResult(t *testing.T) {
	connA := &fakeConn{
		verifyAuditChainResp: &nodev1.VerifyAuditChainResponse{
			EntryCount:          3,
			Intact:              false,
			FirstBrokenSequence: 2,
			Reason:              "prev_entry_sha256 mismatch",
		},
	}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	resp, err := svc.VerifyNodeAuditChain(ctx, connect.NewRequest(&fleetv1.VerifyNodeAuditChainRequest{NodeName: "A"}))
	if err != nil {
		t.Fatalf("VerifyNodeAuditChain() error = %v, want nil", err)
	}
	if resp.Msg.GetEntryCount() != 3 || resp.Msg.GetIntact() || resp.Msg.GetFirstBrokenSequence() != 2 || resp.Msg.GetReason() != "prev_entry_sha256 mismatch" {
		t.Errorf("response = %+v, want the node's result passed through unchanged", resp.Msg)
	}
}

func TestVerifyNodeAuditChain_UnknownNode_NotFound(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.VerifyNodeAuditChain(ctx, connect.NewRequest(&fleetv1.VerifyNodeAuditChainRequest{NodeName: "missing"}))
	if err == nil {
		t.Fatal("VerifyNodeAuditChain(unknown node) error = nil, want NotFound")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeNotFound {
		t.Errorf("code = %v, want CodeNotFound", connectErr.Code())
	}
}
