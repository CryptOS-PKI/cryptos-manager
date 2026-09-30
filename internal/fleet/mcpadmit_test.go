package fleet

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
	"errors"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/mcpauth"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

// CreateMcpKey refuses up front, with the admission check's 1608 NO_CRL,
// rather than minting a key the certificate's operator CA can't support.
func TestCreateMcpKey_RefusesWithTheAdmissionReason(t *testing.T) {
	st := memory.New(nil)
	noCRL := apperr.Reasoned(apperr.CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_NO_CRL, errors.New("no CRL source"))
	svc := New(st, nil).WithMCP(&mcpauth.Keys{Store: st, Admit: func([]byte) error { return noCRL }}, true)

	_, err := svc.CreateMcpKey(certCtx(t, 0x0abc, authz.LevelOperator), connect.NewRequest(&fleetv1.CreateMcpKeyRequest{Label: "ci"}))
	requireAppCode(t, err, apperr.CodeNoRevocationSource)
	if r, ok := apperr.ReasonOf(err); !ok || r != fleetv1.ErrorReason_ERROR_REASON_NO_CRL {
		t.Fatalf("reason = %v, %v; want NO_CRL", r, ok)
	}
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("connect code = %v, want FailedPrecondition", connect.CodeOf(err))
	}
	if len(st.McpKeys()) != 0 {
		t.Fatal("a key was stored")
	}
}
