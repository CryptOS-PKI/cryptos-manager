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
	"strings"
	"testing"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func message(t *testing.T, name protoreflect.Name) protoreflect.MessageDescriptor {
	t.Helper()
	md := fleetv1.File_cryptos_fleet_v1_fleet_proto.Messages().ByName(name)
	if md == nil {
		t.Fatalf("message %s is not declared", name)
	}
	return md
}

func assertFields(t *testing.T, md protoreflect.MessageDescriptor, want map[protoreflect.Name]protoreflect.FieldNumber) {
	t.Helper()
	for name, num := range want {
		fd := md.Fields().ByName(name)
		if fd == nil {
			t.Errorf("%s.%s is not declared", md.Name(), name)
			continue
		}
		if fd.Number() != num {
			t.Errorf("%s.%s is field %d, want %d", md.Name(), name, fd.Number(), num)
		}
	}
}

func TestFleetServiceDeclaresMcpKeyRPCs(t *testing.T) {
	svc := fleetv1.File_cryptos_fleet_v1_fleet_proto.Services().ByName("FleetService")
	for _, rpc := range []protoreflect.Name{"ListMcpKeys", "RevokeMcpKey", "CreateMcpKey"} {
		m := svc.Methods().ByName(rpc)
		if m == nil {
			t.Errorf("FleetService.%s is not declared", rpc)
			continue
		}
		if m.IsStreamingClient() || m.IsStreamingServer() {
			t.Errorf("FleetService.%s must be unary", rpc)
		}
	}
}

// The key is shown to the operator exactly once, at mint; a listing that
// carried the key or its hash would turn every reader into a key holder.
func TestMcpKeyNeverCarriesKeyMaterial(t *testing.T) {
	md := message(t, "McpKey")
	assertFields(t, md, map[protoreflect.Name]protoreflect.FieldNumber{
		"id": 1, "label": 2, "client_name": 3, "operator_cn": 4, "operator_serial": 5,
		"level_ceiling": 6, "created_at": 7, "last_used_at": 8, "revoked_at": 9,
	})
	if got := md.Fields().Len(); got != 9 {
		t.Errorf("McpKey has %d fields, want 9", got)
	}
	for i := range md.Fields().Len() {
		name := strings.ToLower(string(md.Fields().Get(i).Name()))
		if strings.Contains(name, "hash") || strings.Contains(name, "token") || name == "key" || name == "plaintext_key" {
			t.Errorf("McpKey.%s looks like key material", name)
		}
	}
}

func TestMcpKeyRequestsAndResponses(t *testing.T) {
	assertFields(t, message(t, "ListMcpKeysRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"all": 1})
	assertFields(t, message(t, "ListMcpKeysResponse"), map[protoreflect.Name]protoreflect.FieldNumber{"items": 1})
	assertFields(t, message(t, "RevokeMcpKeyRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"id": 1})
	assertFields(t, message(t, "RevokeMcpKeyResponse"), map[protoreflect.Name]protoreflect.FieldNumber{"mcp_key": 1})
	assertFields(t, message(t, "CreateMcpKeyRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"label": 1, "level_ceiling": 2})
	assertFields(t, message(t, "CreateMcpKeyResponse"), map[protoreflect.Name]protoreflect.FieldNumber{"plaintext_key": 1, "mcp_key": 2})
}

func TestAuditEventActorFieldsAreAdditive(t *testing.T) {
	assertFields(t, message(t, "AuditEvent"), map[protoreflect.Name]protoreflect.FieldNumber{
		"id": 1, "at": 2, "kind": 3, "summary": 4, "target_kind": 5, "target_path": 6,
		"actor_kind": 7, "actor_cn": 8, "actor_serial": 9, "key_id": 10, "via": 11,
		"tool": 12, "request_digest": 13, "outcome": 14, "approval_id": 15, "approver_serial": 16,
	})
}
