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
	"context"
	"reflect"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	fleetv1connect "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
)

// The manager never signs an operator credential, so the contract it serves
// must not offer a method that asks it to.
func TestFleetService_HasNoIssueOperatorCredential(t *testing.T) {
	handler := reflect.TypeFor[fleetv1connect.FleetServiceHandler]()
	if _, ok := handler.MethodByName("IssueOperatorCredential"); ok {
		t.Fatal("FleetServiceHandler still has IssueOperatorCredential")
	}
	if _, ok := reflect.TypeFor[*Service]().MethodByName("IssueOperatorCredential"); ok {
		t.Fatal("fleet.Service still implements IssueOperatorCredential")
	}
}

// The operator CA methods are served: with no operator CA configured they
// answer the operator-CA-unconfigured code, never Unimplemented.
func TestFleetService_OperatorCAMethodsNeedAnOperatorCA(t *testing.T) {
	svc := New(operatorsStore(), dialFor(nil))
	ctx := operatorCtx("admin@example.org", authz.LevelAdmin)
	calls := writeCalls(svc, strings.Repeat("ab", 32), nil)
	calls["ListOperatorCAs"] = func(ctx context.Context) error {
		_, err := svc.ListOperatorCAs(ctx, connect.NewRequest(&fleetv1.ListOperatorCAsRequest{}))
		return err
	}
	for name, call := range calls {
		if code, _ := apperr.Code(call(ctx)); code != apperr.CodeOperatorCAUnconfigured {
			t.Errorf("%s: code = %d, want %d", name, code, apperr.CodeOperatorCAUnconfigured)
		}
	}
}
