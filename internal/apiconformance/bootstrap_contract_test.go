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
	"google.golang.org/protobuf/reflect/protoregistry"
)

// The bootstrap and operator-CA types live in their own files, so these
// helpers look names up across the whole cryptos.fleet.v1 package rather than
// in fleet.proto alone.
var _ = fleetv1.File_cryptos_fleet_v1_fleet_proto

func lookup(name protoreflect.Name) protoreflect.Descriptor {
	d, err := protoregistry.GlobalFiles.FindDescriptorByName("cryptos.fleet.v1." + protoreflect.FullName(name))
	if err != nil {
		return nil
	}
	return d
}

func pkgMessage(t *testing.T, name protoreflect.Name) protoreflect.MessageDescriptor {
	t.Helper()
	md, ok := lookup(name).(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("message %s is not declared", name)
	}
	return md
}

func pkgEnum(t *testing.T, name protoreflect.Name) protoreflect.EnumDescriptor {
	t.Helper()
	ed, ok := lookup(name).(protoreflect.EnumDescriptor)
	if !ok {
		t.Fatalf("enum %s is not declared", name)
	}
	return ed
}

func pkgService(t *testing.T, name protoreflect.Name) protoreflect.ServiceDescriptor {
	t.Helper()
	sd, ok := lookup(name).(protoreflect.ServiceDescriptor)
	if !ok {
		t.Fatalf("service %s is not declared", name)
	}
	return sd
}

// assertUnaryRPCs checks each RPC exists, is unary, and takes and returns the
// named messages.
func assertUnaryRPCs(t *testing.T, svc protoreflect.ServiceDescriptor, want map[protoreflect.Name][2]protoreflect.Name) {
	t.Helper()
	for rpc, io := range want {
		m := svc.Methods().ByName(rpc)
		if m == nil {
			t.Errorf("%s.%s is not declared", svc.Name(), rpc)
			continue
		}
		if m.IsStreamingClient() || m.IsStreamingServer() {
			t.Errorf("%s.%s must be unary", svc.Name(), rpc)
		}
		if got := m.Input().Name(); got != io[0] {
			t.Errorf("%s.%s takes %s, want %s", svc.Name(), rpc, got, io[0])
		}
		if got := m.Output().Name(); got != io[1] {
			t.Errorf("%s.%s returns %s, want %s", svc.Name(), rpc, got, io[1])
		}
	}
}

// assertExactFields checks the field numbers and that the message has no
// others, so an accidental extra field fails the contract.
func assertExactFields(t *testing.T, md protoreflect.MessageDescriptor, want map[protoreflect.Name]protoreflect.FieldNumber) {
	t.Helper()
	assertFields(t, md, want)
	if got := md.Fields().Len(); got != len(want) {
		t.Errorf("%s has %d fields, want %d", md.Name(), got, len(want))
	}
}

func assertEnum(t *testing.T, ed protoreflect.EnumDescriptor, want map[protoreflect.Name]protoreflect.EnumNumber) {
	t.Helper()
	for name, num := range want {
		v := ed.Values().ByName(name)
		if v == nil {
			t.Errorf("%s.%s is not declared", ed.Name(), name)
			continue
		}
		if v.Number() != num {
			t.Errorf("%s.%s is %d, want %d", ed.Name(), name, v.Number(), num)
		}
	}
	if got := ed.Values().Len(); got != len(want) {
		t.Errorf("%s has %d values, want %d", ed.Name(), got, len(want))
	}
}

func assertEnumField(t *testing.T, md protoreflect.MessageDescriptor, name, enum protoreflect.Name, list bool) {
	t.Helper()
	fd := md.Fields().ByName(name)
	if fd == nil {
		return
	}
	if fd.Enum() == nil || fd.Enum().Name() != enum || fd.IsList() != list {
		t.Errorf("%s.%s is not %s (list=%v)", md.Name(), name, enum, list)
	}
}

func assertOneof(t *testing.T, md protoreflect.MessageDescriptor, oneof protoreflect.Name, fields ...protoreflect.Name) {
	t.Helper()
	od := md.Oneofs().ByName(oneof)
	if od == nil {
		t.Errorf("%s has no oneof %s", md.Name(), oneof)
		return
	}
	if od.Fields().Len() != len(fields) {
		t.Errorf("%s.%s has %d fields, want %d", md.Name(), oneof, od.Fields().Len(), len(fields))
	}
	for _, f := range fields {
		if od.Fields().ByName(f) == nil {
			t.Errorf("%s.%s does not hold %s", md.Name(), oneof, f)
		}
	}
}

// The day-zero surface is exactly four procedures, so no allow-list inside
// the FleetService middleware can drift.
func TestBootstrapServiceDeclaresFourUnaryRPCs(t *testing.T) {
	svc := pkgService(t, "BootstrapService")
	want := map[protoreflect.Name][2]protoreflect.Name{
		"GetBootstrapState":           {"GetBootstrapStateRequest", "GetBootstrapStateResponse"},
		"StartBootstrapSession":       {"StartBootstrapSessionRequest", "StartBootstrapSessionResponse"},
		"RegisterOperatorCA":          {"BootstrapServiceRegisterOperatorCARequest", "BootstrapServiceRegisterOperatorCAResponse"},
		"SubmitFirstAdminCertificate": {"SubmitFirstAdminCertificateRequest", "SubmitFirstAdminCertificateResponse"},
	}
	assertUnaryRPCs(t, svc, want)
	if got := svc.Methods().Len(); got != len(want) {
		t.Errorf("BootstrapService has %d methods, want %d", got, len(want))
	}
}

func TestBootstrapStateMessages(t *testing.T) {
	assertExactFields(t, pkgMessage(t, "GetBootstrapStateRequest"), map[protoreflect.Name]protoreflect.FieldNumber{})
	res := pkgMessage(t, "GetBootstrapStateResponse")
	assertExactFields(t, res, map[protoreflect.Name]protoreflect.FieldNumber{
		"state": 1, "reason_code": 2, "token_expires_at": 3,
	})
	assertEnumField(t, res, "state", "BootstrapState", false)
	assertEnumField(t, res, "reason_code", "ErrorReason", false)

	assertEnum(t, pkgEnum(t, "BootstrapState"), map[protoreflect.Name]protoreflect.EnumNumber{
		"BOOTSTRAP_STATE_UNSPECIFIED":      0,
		"BOOTSTRAP_STATE_NOT_APPLICABLE":   1,
		"BOOTSTRAP_STATE_OPEN":             2,
		"BOOTSTRAP_STATE_OPEN_IN_PROGRESS": 3,
		"BOOTSTRAP_STATE_CLOSED":           4,
		"BOOTSTRAP_STATE_UNAVAILABLE":      5,
	})
}

func TestBootstrapSessionMessages(t *testing.T) {
	assertExactFields(t, pkgMessage(t, "StartBootstrapSessionRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"token": 1})
	assertExactFields(t, pkgMessage(t, "StartBootstrapSessionResponse"), map[protoreflect.Name]protoreflect.FieldNumber{
		"session_secret": 1, "expires_at": 2,
	})
}

// The token is printed to the log and never returned; the session secret is
// returned once, by StartBootstrapSession, and nowhere else.
func TestBootstrapResponsesNeverCarryTheTokenOrSession(t *testing.T) {
	svc := pkgService(t, "BootstrapService")
	for i := range svc.Methods().Len() {
		m := svc.Methods().Get(i)
		out := m.Output()
		for j := range out.Fields().Len() {
			name := strings.ToLower(string(out.Fields().Get(j).Name()))
			if strings.Contains(name, "token") && name != "token_expires_at" {
				t.Errorf("%s.%s looks like the bootstrap token", out.Name(), name)
			}
			if strings.Contains(name, "session") && m.Name() != "StartBootstrapSession" {
				t.Errorf("%s.%s carries the session outside StartBootstrapSession", out.Name(), name)
			}
		}
	}
}

// Both RegisterOperatorCA procedures (bootstrap and admin) take the same
// fields, so the web builds one form for both.
func TestRegisterOperatorCARequests(t *testing.T) {
	want := map[protoreflect.Name]protoreflect.FieldNumber{
		"ca_cert_der": 1, "url": 2, "crl_der": 3, "none": 4,
		"ocsp_mode": 5, "ocsp_url": 6, "acknowledgements": 7, "confirm_sha256": 8,
	}
	for _, name := range []protoreflect.Name{"BootstrapServiceRegisterOperatorCARequest", "RegisterOperatorCARequest"} {
		md := pkgMessage(t, name)
		assertExactFields(t, md, want)
		assertOneof(t, md, "crl_source", "url", "crl_der", "none")
		assertKind(t, md, "ca_cert_der", protoreflect.BytesKind)
		assertKind(t, md, "crl_der", protoreflect.BytesKind)
		assertKind(t, md, "none", protoreflect.BoolKind)
		assertEnumField(t, md, "ocsp_mode", "OcspMode", false)
		assertEnumField(t, md, "acknowledgements", "OperatorCAAcknowledgement", true)
	}
}

func TestRegisterOperatorCAResponses(t *testing.T) {
	want := map[protoreflect.Name]protoreflect.FieldNumber{
		"operator_ca": 1, "confirmed": 2, "admin_extfile": 3, "ocsp_probe": 4,
	}
	for _, name := range []protoreflect.Name{"BootstrapServiceRegisterOperatorCAResponse", "RegisterOperatorCAResponse"} {
		md := pkgMessage(t, name)
		assertExactFields(t, md, want)
		assertMessage(t, md, "operator_ca", "cryptos.fleet.v1.OperatorCA", false)
		assertMessage(t, md, "ocsp_probe", "cryptos.fleet.v1.OcspProbeResult", false)
	}
}

func TestSubmitFirstAdminCertificateMessages(t *testing.T) {
	req := pkgMessage(t, "SubmitFirstAdminCertificateRequest")
	assertExactFields(t, req, map[protoreflect.Name]protoreflect.FieldNumber{
		"cert_der": 1, "csr_der": 2, "full_name": 3,
	})
	assertKind(t, req, "cert_der", protoreflect.BytesKind)
	assertKind(t, req, "csr_der", protoreflect.BytesKind)
	assertExactFields(t, pkgMessage(t, "SubmitFirstAdminCertificateResponse"), map[protoreflect.Name]protoreflect.FieldNumber{
		"serial_hex": 1, "not_after": 2, "email": 3, "issuer_sha256": 4, "warnings": 5,
	})
}
