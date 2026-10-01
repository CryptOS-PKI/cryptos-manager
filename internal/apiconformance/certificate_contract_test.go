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

func TestFleetServiceDeclaresGetCertificate(t *testing.T) {
	m := fleetv1.File_cryptos_fleet_v1_fleet_proto.Services().ByName("FleetService").Methods().ByName("GetCertificate")
	if m == nil {
		t.Fatal("FleetService.GetCertificate is not declared")
	}
	if m.IsStreamingClient() || m.IsStreamingServer() {
		t.Error("FleetService.GetCertificate must be unary")
	}
	if got := m.Input().FullName(); got != "cryptos.fleet.v1.GetCertificateRequest" {
		t.Errorf("GetCertificate takes %s", got)
	}
	if got := m.Output().FullName(); got != "cryptos.fleet.v1.GetCertificateResponse" {
		t.Errorf("GetCertificate returns %s", got)
	}
}

func TestGetCertificateMessages(t *testing.T) {
	for name, want := range map[protoreflect.Name]map[protoreflect.Name]protoreflect.FieldNumber{
		"GetCertificateRequest":  {"node_name": 1, "serial_hex": 2},
		"GetCertificateResponse": {"certificate_pem": 1, "chain_pem": 2, "status": 3, "revoked_at": 4},
	} {
		md := message(t, name)
		assertFields(t, md, want)
		if got := md.Fields().Len(); got != len(want) {
			t.Errorf("%s has %d fields, want %d", name, got, len(want))
		}
		for field := range want {
			if fd := md.Fields().ByName(field); fd != nil && (fd.Kind() != protoreflect.StringKind || fd.IsList()) {
				t.Errorf("%s.%s must be a singular string", name, field)
			}
		}
	}
}
