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

func TestFleetServiceDeclaresCredentialRequestRPCs(t *testing.T) {
	svc := fleetv1.File_cryptos_fleet_v1_fleet_proto.Services().ByName("FleetService")
	assertUnaryRPCs(t, svc, map[protoreflect.Name][2]protoreflect.Name{
		"CreateOperatorCredentialRequest": {"CreateOperatorCredentialRequestRequest", "CreateOperatorCredentialRequestResponse"},
		"ListOperatorCredentialRequests":  {"ListOperatorCredentialRequestsRequest", "ListOperatorCredentialRequestsResponse"},
		"CancelOperatorCredentialRequest": {"CancelOperatorCredentialRequestRequest", "CancelOperatorCredentialRequestResponse"},
		"RecordOperatorCredential":        {"RecordOperatorCredentialRequest", "RecordOperatorCredentialResponse"},
		"RevokeOperatorCredential":        {"RevokeOperatorCredentialRequest", "RevokeOperatorCredentialResponse"},
		"ListOperatorCredentials":         {"ListOperatorCredentialsRequest", "ListOperatorCredentialsResponse"},
	})
}

func TestCredentialRequestMessages(t *testing.T) {
	create := pkgMessage(t, "CreateOperatorCredentialRequestRequest")
	assertExactFields(t, create, map[protoreflect.Name]protoreflect.FieldNumber{
		"level": 1, "email": 2, "full_name": 3, "csr_der": 4,
	})
	assertKind(t, create, "csr_der", protoreflect.BytesKind)
	assertExactFields(t, pkgMessage(t, "CreateOperatorCredentialRequestResponse"), map[protoreflect.Name]protoreflect.FieldNumber{
		"request_id": 1, "csr_pem": 2, "extfile_section": 3, "openssl_command": 4, "expires_at": 5,
	})

	assertExactFields(t, pkgMessage(t, "ListOperatorCredentialRequestsRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"state": 1})
	list := pkgMessage(t, "ListOperatorCredentialRequestsResponse")
	assertExactFields(t, list, map[protoreflect.Name]protoreflect.FieldNumber{"items": 1})
	assertMessage(t, list, "items", "cryptos.fleet.v1.OperatorCredentialRequest", true)

	assertExactFields(t, pkgMessage(t, "CancelOperatorCredentialRequestRequest"), map[protoreflect.Name]protoreflect.FieldNumber{"request_id": 1})
	cancel := pkgMessage(t, "CancelOperatorCredentialRequestResponse")
	assertExactFields(t, cancel, map[protoreflect.Name]protoreflect.FieldNumber{"request": 1})
	assertMessage(t, cancel, "request", "cryptos.fleet.v1.OperatorCredentialRequest", false)

	assertExactFields(t, pkgMessage(t, "OperatorCredentialRequest"), map[protoreflect.Name]protoreflect.FieldNumber{
		"id": 1, "level": 2, "email": 3, "full_name": 4, "csr_pem": 5, "state": 6,
		"created_by_cn": 7, "created_at": 8, "expires_at": 9, "completed_serial": 10,
	})
}

func TestRecordOperatorCredentialMessages(t *testing.T) {
	req := pkgMessage(t, "RecordOperatorCredentialRequest")
	assertExactFields(t, req, map[protoreflect.Name]protoreflect.FieldNumber{
		"cert_der": 1, "request_id": 2, "full_name": 3,
	})
	assertKind(t, req, "cert_der", protoreflect.BytesKind)
	res := pkgMessage(t, "RecordOperatorCredentialResponse")
	assertExactFields(t, res, map[protoreflect.Name]protoreflect.FieldNumber{"credential": 1, "warnings": 2})
	assertMessage(t, res, "credential", "cryptos.fleet.v1.OperatorCredential", false)
}

// Revoking writes the manager's denylist keyed by issuer and serial; the
// existing fields keep their numbers.
func TestRevokeOperatorCredentialAdditions(t *testing.T) {
	assertExactFields(t, pkgMessage(t, "RevokeOperatorCredentialRequest"), map[protoreflect.Name]protoreflect.FieldNumber{
		"serial_hex": 1, "reason_code": 2, "issuer_sha256": 3, "note": 4,
	})
	assertExactFields(t, pkgMessage(t, "RevokeOperatorCredentialResponse"), map[protoreflect.Name]protoreflect.FieldNumber{
		"serial_hex": 1, "revoked_at": 2, "issuer_sha256": 3, "warnings": 4,
	})
}

func TestOperatorCredentialFields(t *testing.T) {
	md := pkgMessage(t, "OperatorCredential")
	assertExactFields(t, md, map[protoreflect.Name]protoreflect.FieldNumber{
		"common_name": 1, "serial_hex": 2, "level": 3, "not_after": 4, "revoked": 5,
		"kind": 6, "issuer_sha256": 7, "email": 8, "full_name": 9,
		"denylisted": 10, "crl_revoked": 11, "first_seen_at": 12, "last_seen_at": 13,
	})
	assertKind(t, md, "denylisted", protoreflect.BoolKind)
	assertKind(t, md, "crl_revoked", protoreflect.BoolKind)
}

// The manager never signs an operator credential, so the issue RPC and its
// messages are gone and nothing in the package may bring them back.
func TestIssueOperatorCredentialIsRemoved(t *testing.T) {
	svc := fleetv1.File_cryptos_fleet_v1_fleet_proto.Services().ByName("FleetService")
	for i := range svc.Methods().Len() {
		if name := string(svc.Methods().Get(i).Name()); strings.HasPrefix(name, "Issue") && strings.Contains(name, "Operator") {
			t.Errorf("FleetService.%s is declared; the manager issues no operator credentials", name)
		}
	}
	for _, name := range []protoreflect.Name{"IssueOperatorCredentialRequest", "IssueOperatorCredentialResponse"} {
		if lookup(name) != nil {
			t.Errorf("%s is still declared", name)
		}
	}
}
