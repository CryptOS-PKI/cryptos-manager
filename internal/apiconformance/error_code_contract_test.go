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

	"google.golang.org/protobuf/reflect/protoreflect"
)

// The numbers are a promise to operators quoting a code in a report, so each
// is pinned here.
func TestErrorCodes(t *testing.T) {
	assertEnum(t, pkgEnum(t, "ErrorCode"), map[protoreflect.Name]protoreflect.EnumNumber{
		"ERROR_CODE_UNSPECIFIED":                   0,
		"ERROR_CODE_TOKEN_INVALID":                 1600,
		"ERROR_CODE_CLOSED":                        1601,
		"ERROR_CODE_RATE_LIMITED":                  1602,
		"ERROR_CODE_UNAVAILABLE":                   1603,
		"ERROR_CODE_SESSION_INVALID":               1604,
		"ERROR_CODE_OPERATOR_CA_REJECTED":          1605,
		"ERROR_CODE_CSR_REJECTED":                  1606,
		"ERROR_CODE_OPERATOR_CA_MANAGED_BY_CONFIG": 1607,
		"ERROR_CODE_NO_REVOCATION_SOURCE":          1608,
		"ERROR_CODE_OPERATOR_CA_IN_USE":            1609,
		"ERROR_CODE_CERT_REJECTED":                 1610,
		"ERROR_CODE_REQUEST_INVALID":               1611,
	})
}

// Sub-reasons travel as the value name without the ERROR_REASON_ prefix, so
// the names are the contract the web branches on.
func TestErrorReasons(t *testing.T) {
	names := []protoreflect.Name{
		"DATABASE_REQUIRED", "FIRST_RUN_DISABLED",
		"NOT_A_CA", "EXPIRING", "KEY_TYPE", "IS_NODE_CA", "CRL_SIGN_MISSING",
		"NO_CRL_NOT_ACKNOWLEDGED", "CRL_UNREACHABLE", "CRL_INVALID", "CRL_ROLLBACK",
		"OCSP_UNREACHABLE", "OCSP_INVALID", "NOT_CONFIRMED", "ROTATION_IN_PROGRESS",
		"SIZE", "SIGNATURE", "SUBJECT_MISMATCH",
		"STALE_CRL", "STALE_OCSP", "STALE_DENYLIST", "NO_CRL",
		"NOT_CHAINED", "NOT_ACTIVE_ANCHOR", "WRONG_LEVEL", "LEVEL_EXT_CRITICAL", "EKU",
		"KEY_USAGE", "BASIC_CONSTRAINTS", "KEY_MISMATCH", "REVOKED", "REVOKED_OCSP",
		"OCSP_UNKNOWN", "DUPLICATE",
		"NOT_FOUND", "EXPIRED", "NOT_PENDING",
		"FULL_NAME",
	}
	want := map[protoreflect.Name]protoreflect.EnumNumber{"ERROR_REASON_UNSPECIFIED": 0}
	for i, n := range names {
		want["ERROR_REASON_"+n] = protoreflect.EnumNumber(i + 1)
	}
	assertEnum(t, pkgEnum(t, "ErrorReason"), want)
}
