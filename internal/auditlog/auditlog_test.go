package auditlog

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
	"strings"
	"testing"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

func TestRecord_StampsCertActor(t *testing.T) {
	st := memory.New(nil)
	ctx := authz.NewContext(context.Background(), authz.Identity{CN: "operator@example.org", Serial: "0A:BC", Level: authz.LevelOperator, Via: authz.ViaWeb})

	got := Record(ctx, st, store.AuditEvent{Kind: "revoked", Summary: "s", TargetKind: "cert", TargetPath: "/p"})

	if got.ActorKind != "cert" || got.ActorCN != "operator@example.org" || got.ActorSerial != "0A:BC" ||
		got.Via != "web" || got.KeyID != "" || got.Tool != "" || got.Outcome != "ok" {
		t.Fatalf("row = %+v", got)
	}
	if !strings.HasPrefix(got.ID, "aud-") || got.At == "" {
		t.Fatalf("id/at not filled: %+v", got)
	}
	if len(st.Audit()) != 1 {
		t.Fatal("row not appended")
	}
}

func TestRecord_StampsMCPActorAndTool(t *testing.T) {
	st := memory.New(nil)
	ctx := authz.NewContext(context.Background(), authz.Identity{CN: "operator@example.org", Serial: "0A:BC", Level: authz.LevelViewer, Via: authz.ViaMCP, KeyID: "key-1"})
	ctx = WithCall(ctx, Call{Tool: "cert_list", RequestDigest: "abc"})

	got := Record(ctx, st, store.AuditEvent{ID: "aud-x", At: "2026-09-29T00:00:00Z", Kind: "mcp-call", Outcome: "denied"})

	if got.ActorKind != "mcp_key" || got.KeyID != "key-1" || got.Via != "mcp" || got.Tool != "cert_list" ||
		got.RequestDigest != "abc" || got.Outcome != "denied" || got.ID != "aud-x" {
		t.Fatalf("row = %+v", got)
	}
}
