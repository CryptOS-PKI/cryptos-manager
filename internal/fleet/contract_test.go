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
	"reflect"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	fleetv1connect "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/manager/internal/authz"
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

// Methods the contract has but this build doesn't serve answer Unimplemented,
// never a success or a generic failure.
func TestFleetService_UnservedOperatorCAMethodsAreUnimplemented(t *testing.T) {
	svc := New(operatorsStore(), dialFor(nil))
	ctx := operatorCtx("admin@example.org", authz.LevelAdmin)
	calls := map[string]func() error{
		"ListOperatorCAs": func() error {
			_, err := svc.ListOperatorCAs(ctx, connect.NewRequest(&fleetv1.ListOperatorCAsRequest{}))
			return err
		},
		"RegisterOperatorCA": func() error {
			_, err := svc.RegisterOperatorCA(ctx, connect.NewRequest(&fleetv1.RegisterOperatorCARequest{}))
			return err
		},
		"RetireOperatorCA": func() error {
			_, err := svc.RetireOperatorCA(ctx, connect.NewRequest(&fleetv1.RetireOperatorCARequest{}))
			return err
		},
		"SetOperatorCACRLSource": func() error {
			_, err := svc.SetOperatorCACRLSource(ctx, connect.NewRequest(&fleetv1.SetOperatorCACRLSourceRequest{}))
			return err
		},
		"UploadOperatorCRL": func() error {
			_, err := svc.UploadOperatorCRL(ctx, connect.NewRequest(&fleetv1.UploadOperatorCRLRequest{}))
			return err
		},
		"SetOperatorCAOCSP": func() error {
			_, err := svc.SetOperatorCAOCSP(ctx, connect.NewRequest(&fleetv1.SetOperatorCAOCSPRequest{}))
			return err
		},
	}
	for name, call := range calls {
		if got := connect.CodeOf(call()); got != connect.CodeUnimplemented {
			t.Errorf("%s: code = %v, want Unimplemented", name, got)
		}
	}
}
