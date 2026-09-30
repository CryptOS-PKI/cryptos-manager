package fleet

/*
Apache License 2.0

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
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/authz"
)

// Every audited write names who made it, whichever surface it came through.
func TestAuditedWrite_RecordsWebActor(t *testing.T) {
	svc, st := serviceWithAdapter()
	ctx := authz.NewContext(context.Background(), authz.Identity{
		CN: "admin@example.org", Serial: "0A:BC", Level: authz.LevelAdmin, Via: authz.ViaWeb,
	})

	if _, err := svc.SetAdapterEnabled(ctx, connect.NewRequest(&fleetv1.SetAdapterEnabledRequest{
		Name: "ACME (RFC 8555)", Enabled: false,
	})); err != nil {
		t.Fatalf("SetAdapterEnabled: %v", err)
	}

	resp, err := svc.ListAudit(ctx, connect.NewRequest(&fleetv1.ListAuditRequest{}))
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	items := resp.Msg.GetItems()
	got := items[len(items)-1]
	if got.GetActorKind() != "cert" || got.GetActorCn() != "admin@example.org" || got.GetActorSerial() != "0A:BC" ||
		got.GetVia() != "web" || got.GetOutcome() != "ok" || got.GetKeyId() != "" {
		t.Fatalf("audit row = %+v", got)
	}
	if st.Audit()[len(st.Audit())-1].ChainVersion == 0 {
		t.Fatal("row was not hashed under the current chain version")
	}
}

func TestAuditedWrite_RecordsMCPActorAndTool(t *testing.T) {
	svc, _ := serviceWithAdapter()
	ctx := authz.NewContext(context.Background(), authz.Identity{
		CN: "admin@example.org", Serial: "0A:BC", Level: authz.LevelAdmin, Via: authz.ViaMCP, KeyID: "key-1",
	})
	ctx = auditlog.WithCall(ctx, auditlog.Call{Tool: "adapter_set_enabled", RequestDigest: "abc"})

	if _, err := svc.SetAdapterEnabled(ctx, connect.NewRequest(&fleetv1.SetAdapterEnabledRequest{
		Name: "ACME (RFC 8555)", Enabled: false,
	})); err != nil {
		t.Fatalf("SetAdapterEnabled: %v", err)
	}
	resp, _ := svc.ListAudit(ctx, connect.NewRequest(&fleetv1.ListAuditRequest{}))
	items := resp.Msg.GetItems()
	got := items[len(items)-1]
	if got.GetActorKind() != "mcp_key" || got.GetKeyId() != "key-1" || got.GetVia() != "mcp" ||
		got.GetTool() != "adapter_set_enabled" || got.GetRequestDigest() != "abc" {
		t.Fatalf("audit row = %+v", got)
	}
}
