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

func TestFleetServiceDeclaresOperatorCARPCs(t *testing.T) {
	svc := fleetv1.File_cryptos_fleet_v1_fleet_proto.Services().ByName("FleetService")
	assertUnaryRPCs(t, svc, map[protoreflect.Name][2]protoreflect.Name{
		"ListOperatorCAs":        {"ListOperatorCAsRequest", "ListOperatorCAsResponse"},
		"RegisterOperatorCA":     {"RegisterOperatorCARequest", "RegisterOperatorCAResponse"},
		"RetireOperatorCA":       {"RetireOperatorCARequest", "RetireOperatorCAResponse"},
		"SetOperatorCACRLSource": {"SetOperatorCACRLSourceRequest", "SetOperatorCACRLSourceResponse"},
		"UploadOperatorCRL":      {"UploadOperatorCRLRequest", "UploadOperatorCRLResponse"},
		"SetOperatorCAOCSP":      {"SetOperatorCAOCSPRequest", "SetOperatorCAOCSPResponse"},
	})
}

func TestOperatorCAAdminMessages(t *testing.T) {
	assertExactFields(t, pkgMessage(t, "ListOperatorCAsRequest"), map[protoreflect.Name]protoreflect.FieldNumber{})
	list := pkgMessage(t, "ListOperatorCAsResponse")
	assertExactFields(t, list, map[protoreflect.Name]protoreflect.FieldNumber{"items": 1})
	assertMessage(t, list, "items", "cryptos.fleet.v1.OperatorCA", true)

	retire := pkgMessage(t, "RetireOperatorCARequest")
	assertExactFields(t, retire, map[protoreflect.Name]protoreflect.FieldNumber{"sha256": 1, "i_understand_self_lockout": 2})
	assertKind(t, retire, "i_understand_self_lockout", protoreflect.BoolKind)

	crlSource := pkgMessage(t, "SetOperatorCACRLSourceRequest")
	assertExactFields(t, crlSource, map[protoreflect.Name]protoreflect.FieldNumber{
		"sha256": 1, "url": 2, "none": 3, "acknowledgements": 4, "crl_der": 5,
	})
	assertOneof(t, crlSource, "crl_source", "url", "none", "crl_der")
	assertEnumField(t, crlSource, "acknowledgements", "OperatorCAAcknowledgement", true)

	upload := pkgMessage(t, "UploadOperatorCRLRequest")
	assertExactFields(t, upload, map[protoreflect.Name]protoreflect.FieldNumber{"sha256": 1, "crl_der": 2})
	assertKind(t, upload, "crl_der", protoreflect.BytesKind)

	ocsp := pkgMessage(t, "SetOperatorCAOCSPRequest")
	assertExactFields(t, ocsp, map[protoreflect.Name]protoreflect.FieldNumber{"sha256": 1, "ocsp_mode": 2, "ocsp_url": 3})
	assertEnumField(t, ocsp, "ocsp_mode", "OcspMode", false)

	for _, name := range []protoreflect.Name{"RetireOperatorCAResponse", "SetOperatorCACRLSourceResponse", "UploadOperatorCRLResponse"} {
		md := pkgMessage(t, name)
		assertExactFields(t, md, map[protoreflect.Name]protoreflect.FieldNumber{"operator_ca": 1})
		assertMessage(t, md, "operator_ca", "cryptos.fleet.v1.OperatorCA", false)
	}
	ocspRes := pkgMessage(t, "SetOperatorCAOCSPResponse")
	assertExactFields(t, ocspRes, map[protoreflect.Name]protoreflect.FieldNumber{"operator_ca": 1, "ocsp_probe": 2})
	assertMessage(t, ocspRes, "ocsp_probe", "cryptos.fleet.v1.OcspProbeResult", false)
}

// OperatorCA carries only public material: the manager never holds an
// operator CA key.
func TestOperatorCAShape(t *testing.T) {
	md := pkgMessage(t, "OperatorCA")
	assertExactFields(t, md, map[protoreflect.Name]protoreflect.FieldNumber{
		"sha256": 1, "subject": 2, "issuer": 3, "not_after": 4, "state": 5,
		"crl_source": 6, "crl_location": 7, "crl": 8, "ocsp_mode": 9, "ocsp_url": 10,
		"ocsp_last_error": 11, "warnings": 12, "acknowledgements": 13,
		"registered_at": 14, "retired_at": 15, "retired_reason": 16,
		"managed_by_config": 17,
	})
	assertEnumField(t, md, "state", "OperatorCAState", false)
	assertEnumField(t, md, "crl_source", "CrlSource", false)
	assertEnumField(t, md, "ocsp_mode", "OcspMode", false)
	assertEnumField(t, md, "acknowledgements", "OperatorCAAcknowledgement", true)
	assertMessage(t, md, "crl", "cryptos.fleet.v1.CrlStatus", false)

	assertExactFields(t, pkgMessage(t, "CrlStatus"), map[protoreflect.Name]protoreflect.FieldNumber{
		"this_update": 1, "next_update": 2, "revoked_count": 3, "crl_number": 4,
		"fetched_at": 5, "last_error": 6, "stale": 7,
	})
	probe := pkgMessage(t, "OcspProbeResult")
	assertExactFields(t, probe, map[protoreflect.Name]protoreflect.FieldNumber{
		"signer": 1, "signer_subject": 2, "signer_not_after": 3, "cert_status": 4,
	})
	assertEnumField(t, probe, "signer", "OcspSigner", false)
}

func TestOperatorCAEnums(t *testing.T) {
	assertEnum(t, pkgEnum(t, "OperatorCAState"), map[protoreflect.Name]protoreflect.EnumNumber{
		"OPERATOR_CA_STATE_UNSPECIFIED": 0, "OPERATOR_CA_STATE_ACTIVE": 1,
		"OPERATOR_CA_STATE_RETIRING": 2, "OPERATOR_CA_STATE_RETIRED": 3,
	})
	assertEnum(t, pkgEnum(t, "CrlSource"), map[protoreflect.Name]protoreflect.EnumNumber{
		"CRL_SOURCE_UNSPECIFIED": 0, "CRL_SOURCE_NONE": 1, "CRL_SOURCE_URL": 2,
		"CRL_SOURCE_UPLOAD": 3, "CRL_SOURCE_PATH": 4,
	})
	assertEnum(t, pkgEnum(t, "OcspMode"), map[protoreflect.Name]protoreflect.EnumNumber{
		"OCSP_MODE_UNSPECIFIED": 0, "OCSP_MODE_OFF": 1, "OCSP_MODE_AIA": 2, "OCSP_MODE_URL": 3,
	})
	assertEnum(t, pkgEnum(t, "OcspSigner"), map[protoreflect.Name]protoreflect.EnumNumber{
		"OCSP_SIGNER_UNSPECIFIED": 0, "OCSP_SIGNER_ANCHOR": 1, "OCSP_SIGNER_DELEGATED": 2,
	})
	assertEnum(t, pkgEnum(t, "OperatorCAAcknowledgement"), map[protoreflect.Name]protoreflect.EnumNumber{
		"OPERATOR_CA_ACKNOWLEDGEMENT_UNSPECIFIED": 0, "OPERATOR_CA_ACKNOWLEDGEMENT_NO_CRL": 1,
	})
}
