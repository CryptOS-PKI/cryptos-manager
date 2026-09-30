package mcpauth

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
	"errors"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

func owner(serial string, level authz.Level) authz.Identity {
	return authz.Identity{CN: "operator@example.org", Serial: serial, Level: level, Via: authz.ViaWeb}
}

func TestMint_StoresOnlyTheHashAndAudits(t *testing.T) {
	st := memory.New(nil)
	k := &Keys{Store: st}
	plain, key, err := k.Mint(context.Background(), owner("0A:BC", authz.LevelOperator), []byte{1, 2}, "laptop", "agent", "viewer")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	stored, ok := st.McpKey(key.ID)
	if !ok || stored.TokenHash != HashKey(plain) || stored.OperatorSerial != "0A:BC" || stored.LevelCeiling != "viewer" ||
		stored.Label != "laptop" || stored.ClientName != "agent" || string(stored.OperatorCertDER) != "\x01\x02" || stored.CreatedAt.IsZero() {
		t.Fatalf("stored key = %+v", stored)
	}
	e := st.Audit()[0]
	if e.Kind != "mcp-key-created" || e.TargetKind != "mcp-key" || e.ActorSerial != "0A:BC" || e.Via != "web" {
		t.Fatalf("audit = %+v", e)
	}
	if strings.Contains(e.Summary, plain) || strings.Contains(e.Summary, stored.TokenHash) {
		t.Fatal("audit summary leaks the key or its hash")
	}
}

func TestMint_CeilingMayNotExceedLevel(t *testing.T) {
	k := &Keys{Store: memory.New(nil)}
	if _, _, err := k.Mint(context.Background(), owner("01", authz.LevelOperator), nil, "", "", "admin"); !errors.Is(err, ErrCeilingTooHigh) {
		t.Fatalf("admin ceiling for an operator: err = %v", err)
	}
	if _, _, err := k.Mint(context.Background(), owner("01", authz.LevelOperator), nil, "", "", "root"); !errors.Is(err, ErrBadCeiling) {
		t.Fatalf("unknown ceiling: err = %v", err)
	}
}

func TestList_OwnKeysOrAllForAdmin(t *testing.T) {
	st := memory.New(nil)
	k := &Keys{Store: st}
	_, _, _ = k.Mint(context.Background(), owner("01", authz.LevelOperator), nil, "a", "", "")
	_, _, _ = k.Mint(context.Background(), owner("02", authz.LevelAdmin), nil, "b", "", "")

	own, err := k.List(owner("01", authz.LevelOperator), false)
	if err != nil || len(own) != 1 || own[0].Label != "a" {
		t.Fatalf("own = %+v, %v", own, err)
	}
	if _, err := k.List(owner("01", authz.LevelOperator), true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin all: err = %v", err)
	}
	all, err := k.List(owner("02", authz.LevelAdmin), true)
	if err != nil || len(all) != 2 {
		t.Fatalf("admin all = %+v, %v", all, err)
	}
}

func TestRevoke_OwnerOrAdminAndIdempotent(t *testing.T) {
	st := memory.New(nil)
	k := &Keys{Store: st}
	_, mine, _ := k.Mint(context.Background(), owner("01", authz.LevelOperator), nil, "a", "", "")

	if _, err := k.Revoke(context.Background(), owner("02", authz.LevelOperator), mine.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("other operator: err = %v", err)
	}
	if _, err := k.Revoke(context.Background(), owner("01", authz.LevelOperator), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: err = %v", err)
	}
	first, err := k.Revoke(context.Background(), owner("01", authz.LevelOperator), mine.ID)
	if err != nil || first.RevokedAt.IsZero() {
		t.Fatalf("own revoke = %+v, %v", first, err)
	}
	again, err := k.Revoke(context.Background(), owner("03", authz.LevelAdmin), mine.ID)
	if err != nil || !again.RevokedAt.Equal(first.RevokedAt) {
		t.Fatalf("admin re-revoke = %+v, %v", again, err)
	}

	revocations := 0
	for _, e := range st.Audit() {
		if e.Kind == "mcp-key-revoked" {
			revocations++
			if e.ActorSerial != "01" || e.TargetKind != "mcp-key" {
				t.Errorf("revocation row = %+v", e)
			}
		}
	}
	if revocations != 1 {
		t.Fatalf("revocation rows = %d, want 1", revocations)
	}
}
