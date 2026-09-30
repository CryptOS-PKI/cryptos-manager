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
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

// adapterFixture is a seeded enrollment adapter used by the toggle tests.
func adapterFixture() store.Adapter {
	return store.Adapter{
		Kind:       "acme",
		Name:       "ACME (RFC 8555)",
		Endpoint:   "https://mgr.acme.example/acme",
		Profile:    "TLS Server",
		Enabled:    true,
		Challenges: []string{"http-01"},
	}
}

// serviceWithAdapter builds a Service over a memory store seeded with one
// adapter.
func serviceWithAdapter() (*Service, *memory.Store) {
	st := memory.NewWithCatalog(nil, nil, []store.Adapter{adapterFixture()}, nil, nil)
	return New(st, nil), st
}

func TestSetAdapterEnabled_NonAdminDenied_NoWrite(t *testing.T) {
	for _, level := range []authz.Level{authz.LevelViewer, authz.LevelOperator} {
		svc, st := serviceWithAdapter()
		before := len(st.Audit())

		ctx := operatorCtx("u@acme.example", level)
		_, err := svc.SetAdapterEnabled(ctx, connect.NewRequest(&fleetv1.SetAdapterEnabledRequest{
			Name: "ACME (RFC 8555)", Enabled: false,
		}))
		requireConnectCode(t, err, connect.CodePermissionDenied)

		if !st.Adapters()[0].Enabled {
			t.Errorf("level %v: adapter mutated despite denial", level)
		}
		if len(st.Audit()) != before {
			t.Errorf("level %v: audit written on denial", level)
		}
	}
}

func TestSetAdapterEnabled_EmptyName_InvalidArgument(t *testing.T) {
	svc, st := serviceWithAdapter()
	before := len(st.Audit())

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.SetAdapterEnabled(ctx, connect.NewRequest(&fleetv1.SetAdapterEnabledRequest{
		Name: "", Enabled: true,
	}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)

	if len(st.Audit()) != before {
		t.Error("audit written on invalid argument")
	}
}

func TestSetAdapterEnabled_Unknown_NotFound_NoAudit(t *testing.T) {
	svc, st := serviceWithAdapter()
	before := len(st.Audit())

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.SetAdapterEnabled(ctx, connect.NewRequest(&fleetv1.SetAdapterEnabledRequest{
		Name: "missing", Enabled: true,
	}))
	requireConnectCode(t, err, connect.CodeNotFound)

	if len(st.Audit()) != before {
		t.Error("audit written on not-found")
	}
}

func TestSetAdapterEnabled_AdminDisable_MutatesAndAuditsOnce(t *testing.T) {
	svc, st := serviceWithAdapter()
	before := len(st.Audit())

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.SetAdapterEnabled(ctx, connect.NewRequest(&fleetv1.SetAdapterEnabledRequest{
		Name: "ACME (RFC 8555)", Enabled: false,
	}))
	if err != nil {
		t.Fatalf("SetAdapterEnabled(admin) error = %v, want nil", err)
	}

	if resp.Msg.GetAdapter().GetEnabled() {
		t.Error("response adapter Enabled = true, want false")
	}
	if resp.Msg.GetAdapter().GetName() != "ACME (RFC 8555)" {
		t.Errorf("response adapter Name = %q, want the toggled adapter", resp.Msg.GetAdapter().GetName())
	}
	if st.Adapters()[0].Enabled {
		t.Error("store adapter still enabled after disable")
	}

	audit := st.Audit()
	if len(audit) != before+1 {
		t.Fatalf("audit len = %d, want exactly one new event", len(audit))
	}
	if audit[len(audit)-1].Kind != "adapter-disabled" {
		t.Errorf("audit Kind = %q, want adapter-disabled", audit[len(audit)-1].Kind)
	}
	if audit[len(audit)-1].TargetKind != "adapter" {
		t.Errorf("audit TargetKind = %q, want adapter", audit[len(audit)-1].TargetKind)
	}
}

func TestSetAdapterEnabled_AdminEnable_AuditsEnabledKind(t *testing.T) {
	st := memory.NewWithCatalog(nil, nil, []store.Adapter{
		{Kind: "est", Name: "EST", Enabled: false},
	}, nil, nil)
	svc := New(st, nil)

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.SetAdapterEnabled(ctx, connect.NewRequest(&fleetv1.SetAdapterEnabledRequest{
		Name: "EST", Enabled: true,
	}))
	if err != nil {
		t.Fatalf("SetAdapterEnabled(admin) error = %v, want nil", err)
	}
	if !resp.Msg.GetAdapter().GetEnabled() {
		t.Error("response adapter Enabled = false, want true")
	}

	audit := st.Audit()
	if audit[len(audit)-1].Kind != "adapter-enabled" {
		t.Errorf("audit Kind = %q, want adapter-enabled", audit[len(audit)-1].Kind)
	}
}
