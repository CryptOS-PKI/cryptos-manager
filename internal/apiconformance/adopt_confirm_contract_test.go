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

// AdoptNodeResponse numbers 1-4 are on main, so the confirm fields start at 5.
// adoption_id names the run on every message; presented_cert_sha256 is set on
// the awaiting-fingerprint-confirmation phase.
func TestAdoptNodeResponseCarriesTheFingerprintToConfirm(t *testing.T) {
	md := message(t, "AdoptNodeResponse")
	assertExactFields(t, md, map[protoreflect.Name]protoreflect.FieldNumber{
		"phase": 1, "detail": 2, "done": 3, "node_id": 4,
		"adoption_id": 5, "presented_cert_sha256": 6,
	})
	assertKind(t, md, "adoption_id", protoreflect.StringKind)
	assertKind(t, md, "presented_cert_sha256", protoreflect.StringKind)
}

func TestFleetServiceDeclaresConfirmAdoptionFingerprint(t *testing.T) {
	svc := fleetv1.File_cryptos_fleet_v1_fleet_proto.Services().ByName("FleetService")
	assertUnaryRPCs(t, svc, map[protoreflect.Name][2]protoreflect.Name{
		"ConfirmAdoptionFingerprint": {"ConfirmAdoptionFingerprintRequest", "ConfirmAdoptionFingerprintResponse"},
	})
}

func TestConfirmAdoptionFingerprintMessages(t *testing.T) {
	req := message(t, "ConfirmAdoptionFingerprintRequest")
	assertExactFields(t, req, map[protoreflect.Name]protoreflect.FieldNumber{"adoption_id": 1, "cert_sha256": 2})
	assertKind(t, req, "adoption_id", protoreflect.StringKind)
	assertKind(t, req, "cert_sha256", protoreflect.StringKind)

	resp := message(t, "ConfirmAdoptionFingerprintResponse")
	assertExactFields(t, resp, map[protoreflect.Name]protoreflect.FieldNumber{})
}
