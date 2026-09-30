package fleet

/*
Apache License 2.0

Copyright 2026 Shane

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
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
)

func TestWhoAmI_EchoesContextIdentity(t *testing.T) {
	svc := New(testStore(), dialFor(map[string]*fakeConn{}))
	ctx := authz.NewContext(context.Background(), authz.Identity{CN: "op@acme.example", Serial: "0A:BC", Level: authz.LevelOperator})

	resp, err := svc.WhoAmI(ctx, connect.NewRequest(&fleetv1.WhoAmIRequest{}))
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	op := resp.Msg.GetOperator()
	if op.GetCn() != "op@acme.example" || op.GetSerial() != "0A:BC" || op.GetLevel() != "operator" {
		t.Fatalf("operator = %+v, want op@acme.example/0A:BC/operator", op)
	}
}

func TestWhoAmI_NoIdentityUnauthenticated(t *testing.T) {
	svc := New(testStore(), dialFor(map[string]*fakeConn{}))
	_, err := svc.WhoAmI(context.Background(), connect.NewRequest(&fleetv1.WhoAmIRequest{}))
	if err == nil {
		t.Fatal("WhoAmI(no identity) = nil error, want Unauthenticated")
	}
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}
