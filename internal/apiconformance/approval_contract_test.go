package apiconformance_test

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
	"testing"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestFleetServiceDeclaresApprovalRPCs(t *testing.T) {
	svc := fleetv1.File_cryptos_fleet_v1_fleet_proto.Services().ByName("FleetService")
	want := map[protoreflect.Name][2]protoreflect.FullName{
		"ListApprovals":  {"cryptos.fleet.v1.ListApprovalsRequest", "cryptos.fleet.v1.ListApprovalsResponse"},
		"DecideApproval": {"cryptos.fleet.v1.DecideApprovalRequest", "cryptos.fleet.v1.DecideApprovalResponse"},
	}
	for rpc, io := range want {
		m := svc.Methods().ByName(rpc)
		if m == nil {
			t.Errorf("FleetService.%s is not declared", rpc)
			continue
		}
		if m.IsStreamingClient() || m.IsStreamingServer() {
			t.Errorf("FleetService.%s must be unary", rpc)
		}
		if got := m.Input().FullName(); got != io[0] {
			t.Errorf("FleetService.%s takes %s, want %s", rpc, got, io[0])
		}
		if got := m.Output().FullName(); got != io[1] {
			t.Errorf("FleetService.%s returns %s, want %s", rpc, got, io[1])
		}
	}
}

func TestApprovalRequestsAndResponses(t *testing.T) {
	assertFields(t, message(t, "ListApprovalsRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"status": 1})
	assertFields(t, message(t, "ListApprovalsResponse"), map[protoreflect.Name]protoreflect.FieldNumber{"items": 1})
	assertFields(t, message(t, "DecideApprovalRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"id": 1, "approve": 2})
	assertFields(t, message(t, "DecideApprovalResponse"), map[protoreflect.Name]protoreflect.FieldNumber{"approval": 1})
	assertKind(t, message(t, "DecideApprovalRequest"), "approve", protoreflect.BoolKind)
	assertMessage(t, message(t, "ListApprovalsResponse"), "items", "cryptos.fleet.v1.Approval", true)
	assertMessage(t, message(t, "DecideApprovalResponse"), "approval", "cryptos.fleet.v1.Approval", false)
}

// Timestamps are RFC3339 strings, empty when unset, as on McpKey, so every
// Approval field is a string.
func TestApprovalShape(t *testing.T) {
	md := message(t, "Approval")
	want := map[protoreflect.Name]protoreflect.FieldNumber{
		"id": 1, "tool": 2, "summary": 3, "request_digest": 4,
		"requested_by_cn": 5, "requested_by_serial": 6, "key_id": 7,
		"required_level": 8, "created_at": 9, "expires_at": 10, "status": 11,
		"decided_by_cn": 12, "decided_by_serial": 13, "decided_at": 14, "kind": 15,
	}
	assertFields(t, md, want)
	if got := md.Fields().Len(); got != len(want) {
		t.Errorf("Approval has %d fields, want %d", got, len(want))
	}
	for name := range want {
		assertKind(t, md, name, protoreflect.StringKind)
	}
}

func assertKind(t *testing.T, md protoreflect.MessageDescriptor, name protoreflect.Name, kind protoreflect.Kind) {
	t.Helper()
	fd := md.Fields().ByName(name)
	if fd == nil {
		return
	}
	if fd.Kind() != kind || fd.IsList() {
		t.Errorf("%s.%s is %v (list=%v), want singular %v", md.Name(), name, fd.Kind(), fd.IsList(), kind)
	}
}

func assertMessage(t *testing.T, md protoreflect.MessageDescriptor, name protoreflect.Name, typ protoreflect.FullName, list bool) {
	t.Helper()
	fd := md.Fields().ByName(name)
	if fd == nil {
		return
	}
	if fd.Message() == nil || fd.Message().FullName() != typ || fd.IsList() != list {
		t.Errorf("%s.%s is not %s (list=%v)", md.Name(), name, typ, list)
	}
}
