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

func TestNodeSummaryCarriesStableID(t *testing.T) {
	md := message(t, "NodeSummary")
	assertFields(t, md, map[protoreflect.Name]protoreflect.FieldNumber{
		"name": 1, "address": 2, "role": 3, "identity_state": 4, "cn": 5,
		"issuer": 6, "health": 7, "health_detail": 8, "id": 9,
	})
	assertKind(t, md, "id", protoreflect.StringKind)
}

// Every request that addresses a node takes node_id alongside the name field
// it already had, which keeps its number so existing clients still work.
func TestNodeAddressedRequestsTakeNodeID(t *testing.T) {
	cases := []struct {
		msg        protoreflect.Name
		nameField  protoreflect.Name
		nameNumber protoreflect.FieldNumber
		idField    protoreflect.Name
		idNumber   protoreflect.FieldNumber
	}{
		{"GetNodeRequest", "name", 1, "node_id", 2},
		{"ListCertificatesRequest", "node", 1, "node_id", 2},
		{"ApplyProfileToNodeRequest", "node_name", 1, "node_id", 3},
		{"RevokeCertificateRequest", "node_name", 1, "node_id", 4},
		{"IssueLeafRequest", "node_name", 1, "node_id", 4},
		{"RekeyNodeRequest", "node_name", 1, "node_id", 3},
		{"GetNodeConfigRequest", "node_name", 1, "node_id", 2},
		{"ApplyNodeConfigRequest", "node_name", 1, "node_id", 3},
		{"ExportCAKeyRequest", "node_name", 1, "node_id", 3},
		{"ImportCAKeyRequest", "node_name", 1, "node_id", 4},
		{"DecommissionNodeRequest", "node_name", 1, "node_id", 3},
		{"CreateEnrollmentRequest", "child_node", 6, "child_node_id", 9},
	}
	for _, c := range cases {
		md := message(t, c.msg)
		assertFields(t, md, map[protoreflect.Name]protoreflect.FieldNumber{c.nameField: c.nameNumber, c.idField: c.idNumber})
		assertKind(t, md, c.idField, protoreflect.StringKind)
	}
}

func TestResponsesThatPointAtANodeCarryItsID(t *testing.T) {
	cases := []struct {
		msg    protoreflect.Name
		field  protoreflect.Name
		number protoreflect.FieldNumber
	}{
		{"Certificate", "issuer_node_id", 11},
		{"EnrollmentRequest", "admitted_node_id", 16},
		{"AuditEvent", "node_id", 17},
		{"AdoptNodeResponse", "node_id", 4},
	}
	for _, c := range cases {
		md := message(t, c.msg)
		assertFields(t, md, map[protoreflect.Name]protoreflect.FieldNumber{c.field: c.number})
		assertKind(t, md, c.field, protoreflect.StringKind)
	}
}

func TestFleetServiceDeclaresRenameNode(t *testing.T) {
	svc := fleetv1.File_cryptos_fleet_v1_fleet_proto.Services().ByName("FleetService")
	m := svc.Methods().ByName("RenameNode")
	if m == nil {
		t.Fatal("FleetService.RenameNode is not declared")
	}
	if m.IsStreamingClient() || m.IsStreamingServer() {
		t.Error("FleetService.RenameNode must be unary")
	}
	if got := m.Input().FullName(); got != "cryptos.fleet.v1.RenameNodeRequest" {
		t.Errorf("RenameNode takes %s", got)
	}
	if got := m.Output().FullName(); got != "cryptos.fleet.v1.RenameNodeResponse" {
		t.Errorf("RenameNode returns %s", got)
	}
}

func TestRenameNodeRequestAndResponse(t *testing.T) {
	req := message(t, "RenameNodeRequest")
	assertFields(t, req, map[protoreflect.Name]protoreflect.FieldNumber{"node_id": 1, "new_name": 2})
	if got := req.Fields().Len(); got != 2 {
		t.Errorf("RenameNodeRequest has %d fields, want 2: a rename addresses the node by ID only", got)
	}
	assertKind(t, req, "node_id", protoreflect.StringKind)
	assertKind(t, req, "new_name", protoreflect.StringKind)
	assertMessage(t, message(t, "RenameNodeResponse"), "node", "cryptos.fleet.v1.NodeSummary", false)
}
