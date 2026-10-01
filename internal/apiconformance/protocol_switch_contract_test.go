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

func TestFleetServiceDeclaresSetNodeProtocol(t *testing.T) {
	m := fleetv1.File_cryptos_fleet_v1_fleet_proto.Services().ByName("FleetService").Methods().ByName("SetNodeProtocol")
	if m == nil {
		t.Fatal("FleetService.SetNodeProtocol is not declared")
	}
	if m.IsStreamingClient() || m.IsStreamingServer() {
		t.Error("FleetService.SetNodeProtocol must be unary")
	}
	if got := m.Input().FullName(); got != "cryptos.fleet.v1.SetNodeProtocolRequest" {
		t.Errorf("SetNodeProtocol takes %s", got)
	}
	if got := m.Output().FullName(); got != "cryptos.fleet.v1.SetNodeProtocolResponse" {
		t.Errorf("SetNodeProtocol returns %s", got)
	}
}

func TestSetNodeProtocolMessages(t *testing.T) {
	req := message(t, "SetNodeProtocolRequest")
	assertFields(t, req, map[protoreflect.Name]protoreflect.FieldNumber{"node_name": 1, "protocol": 2, "enabled": 3})
	assertKind(t, req, "node_name", protoreflect.StringKind)
	assertKind(t, req, "enabled", protoreflect.BoolKind)
	if fd := req.Fields().ByName("protocol"); fd == nil || fd.Enum() == nil || fd.Enum().FullName() != "cryptos.node.v1.ServiceProtocol" {
		t.Error("SetNodeProtocolRequest.protocol must be a cryptos.node.v1.ServiceProtocol")
	}

	resp := message(t, "SetNodeProtocolResponse")
	assertFields(t, resp, map[protoreflect.Name]protoreflect.FieldNumber{"generation": 1, "requires_reboot": 2})
	assertKind(t, resp, "generation", protoreflect.Uint64Kind)
	assertKind(t, resp, "requires_reboot", protoreflect.BoolKind)
}

// NodeSummary numbers 1-8 are on main and 9 is taken by the stable node ID
// (CryptOS-PKI/api#110), so the protocol fields start at 10.
func TestNodeSummaryReportsProtocolState(t *testing.T) {
	md := message(t, "NodeSummary")
	assertFields(t, md, map[protoreflect.Name]protoreflect.FieldNumber{"protocols": 10, "reboot_required": 11})
	assertMessage(t, md, "protocols", "cryptos.node.v1.ProtocolStatus", true)
	assertKind(t, md, "reboot_required", protoreflect.BoolKind)
}
