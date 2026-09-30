package approval

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
	"errors"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

var (
	t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	agent    = authz.Identity{CN: "operator@example.org", Serial: "0A:BC", Level: authz.LevelAdmin, Via: authz.ViaMCP, KeyID: "mk-1"}
	admin    = authz.Identity{CN: "admin@example.org", Serial: "0D:EF", Level: authz.LevelAdmin, Via: authz.ViaWeb}
	operator = authz.Identity{CN: "ops@example.org", Serial: "01:23", Level: authz.LevelOperator, Via: authz.ViaWeb}
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newService() (*Service, *memory.Store, *clock) {
	st := memory.New(nil)
	c := &clock{now: t0}
	return &Service{Store: st, Now: c.Now}, st, c
}

func lastAudit(st store.Store) store.AuditEvent {
	all := st.Audit()
	return all[len(all)-1]
}

func TestRequest_StoresAPendingApprovalAndAuditsIt(t *testing.T) {
	s, st, _ := newService()
	a := s.Request(context.Background(), agent, "profile_delete", "digest-1", "Delete profile tls-server", authz.LevelAdmin)

	if a.ID == "" || a.Tool != "profile_delete" || a.RequestDigest != "digest-1" || a.Summary != "Delete profile tls-server" ||
		a.RequestedByCN != agent.CN || a.RequestedBySerial != agent.Serial || a.KeyID != agent.KeyID ||
		a.RequiredLevel != "admin" || a.Status != store.ApprovalPending || !a.CreatedAt.Equal(t0) || !a.ExpiresAt.Equal(t0.Add(15*time.Minute)) {
		t.Fatalf("approval = %+v", a)
	}
	if stored, ok := st.Approval(a.ID); !ok || stored.RequestDigest != "digest-1" {
		t.Fatalf("stored = %+v, %v", stored, ok)
	}
	e := lastAudit(st)
	if e.Kind != KindRequested || e.Outcome != "pending" || e.ApprovalID != a.ID || e.ActorKind != "mcp_key" ||
		e.KeyID != "mk-1" || e.ActorSerial != agent.Serial || e.Tool != "profile_delete" || e.RequestDigest != "digest-1" {
		t.Fatalf("audit = %+v", e)
	}
}

func TestDecide_ApproveAndDenyAreAuditedWithBothIdentities(t *testing.T) {
	for _, approve := range []bool{true, false} {
		s, st, c := newService()
		a := s.Request(context.Background(), agent, "cert_revoke", "d", "Revoke 0A", authz.LevelOperator)
		c.now = t0.Add(time.Minute)

		got, err := s.Decide(context.Background(), operator, a.ID, approve)
		if err != nil {
			t.Fatalf("Decide(%v): %v", approve, err)
		}
		want, kind := store.ApprovalApproved, KindApproved
		if !approve {
			want, kind = store.ApprovalDenied, KindDenied
		}
		if got.Status != want || got.DecidedBySerial != operator.Serial || got.DecidedByCN != operator.CN || got.DecidedByLevel != "operator" {
			t.Fatalf("decided = %+v", got)
		}
		e := lastAudit(st)
		if e.Kind != kind || e.ApprovalID != a.ID || e.ApproverSerial != operator.Serial || e.ActorSerial != operator.Serial ||
			e.ActorKind != "cert" || e.Via != "web" || e.Tool != "cert_revoke" || e.Outcome != "ok" {
			t.Fatalf("decision audit = %+v", e)
		}
	}
}

func TestDecide_Refusals(t *testing.T) {
	t.Run("approver below the required level", func(t *testing.T) {
		s, st, _ := newService()
		a := s.Request(context.Background(), agent, "profile_delete", "d", "Delete", authz.LevelAdmin)
		if _, err := s.Decide(context.Background(), operator, a.ID, true); !errors.Is(err, ErrApproverLevel) {
			t.Fatalf("err = %v, want ErrApproverLevel", err)
		}
		if got, _ := st.Approval(a.ID); got.Status != store.ApprovalPending {
			t.Fatalf("status = %s", got.Status)
		}
		if e := lastAudit(st); e.Kind != KindDecideRefused || e.Outcome != "denied" || e.ApprovalID != a.ID || e.ActorSerial != operator.Serial {
			t.Fatalf("audit = %+v", e)
		}
	})
	t.Run("MCP key", func(t *testing.T) {
		s, _, _ := newService()
		a := s.Request(context.Background(), agent, "cert_revoke", "d", "Revoke", authz.LevelOperator)
		if _, err := s.Decide(context.Background(), agent, a.ID, true); !errors.Is(err, ErrNeedsCert) {
			t.Fatalf("err = %v, want ErrNeedsCert", err)
		}
	})
	t.Run("unknown id", func(t *testing.T) {
		s, _, _ := newService()
		if _, err := s.Decide(context.Background(), admin, "apr-missing", true); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
	t.Run("already decided", func(t *testing.T) {
		s, _, _ := newService()
		a := s.Request(context.Background(), agent, "cert_revoke", "d", "Revoke", authz.LevelOperator)
		if _, err := s.Decide(context.Background(), admin, a.ID, false); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Decide(context.Background(), admin, a.ID, true); !errors.Is(err, ErrNotPending) {
			t.Fatalf("err = %v, want ErrNotPending", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		s, _, c := newService()
		a := s.Request(context.Background(), agent, "cert_revoke", "d", "Revoke", authz.LevelOperator)
		c.now = t0.Add(15 * time.Minute)
		if _, err := s.Decide(context.Background(), admin, a.ID, true); !errors.Is(err, ErrNotPending) {
			t.Fatalf("err = %v, want ErrNotPending", err)
		}
	})
}

func TestUse_RunsOnceForTheExactRequest(t *testing.T) {
	s, st, c := newService()
	a := s.Request(context.Background(), agent, "cert_revoke", "d", "Revoke", authz.LevelOperator)
	if _, err := s.Decide(context.Background(), operator, a.ID, true); err != nil {
		t.Fatal(err)
	}
	c.now = t0.Add(2 * time.Minute)

	used, err := s.Use(context.Background(), agent, a.ID, "cert_revoke", "d", authz.LevelOperator)
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	if used.Status != store.ApprovalUsed || !used.UsedAt.Equal(c.now) {
		t.Fatalf("used = %+v", used)
	}
	e := lastAudit(st)
	if e.Kind != KindUsed || e.ApprovalID != a.ID || e.ApproverSerial != operator.Serial || e.KeyID != agent.KeyID ||
		e.ActorSerial != agent.Serial || e.Via != "mcp" || e.Outcome != "ok" {
		t.Fatalf("use audit = %+v", e)
	}

	if _, err := s.Use(context.Background(), agent, a.ID, "cert_revoke", "d", authz.LevelOperator); !errors.Is(err, ErrUsed) {
		t.Fatalf("replay err = %v, want ErrUsed", err)
	}
}

func TestUse_Refusals(t *testing.T) {
	otherKey := agent
	otherKey.KeyID = "mk-2"
	viewerKey := agent
	viewerKey.Level = authz.LevelViewer

	cases := []struct {
		name    string
		decide  *bool
		caller  authz.Identity
		tool    string
		digest  string
		min     authz.Level
		advance time.Duration
		want    error
	}{
		{name: "not yet decided", caller: agent, tool: "cert_revoke", digest: "d", min: authz.LevelOperator, want: ErrAwaiting},
		{name: "denied", decide: new(false), caller: agent, tool: "cert_revoke", digest: "d", min: authz.LevelOperator, want: ErrDenied},
		{name: "digest mismatch", decide: new(true), caller: agent, tool: "cert_revoke", digest: "other", min: authz.LevelOperator, want: ErrMismatch},
		{name: "different tool", decide: new(true), caller: agent, tool: "profile_delete", digest: "d", min: authz.LevelOperator, want: ErrMismatch},
		{name: "different key", decide: new(true), caller: otherKey, tool: "cert_revoke", digest: "d", min: authz.LevelOperator, want: ErrMismatch},
		{name: "expired", decide: new(true), caller: agent, tool: "cert_revoke", digest: "d", min: authz.LevelOperator, advance: 15 * time.Minute, want: ErrExpired},
		{name: "key level now below minimum", decide: new(true), caller: viewerKey, tool: "cert_revoke", digest: "d", min: authz.LevelOperator, want: ErrKeyLevel},
		{name: "approver level below the tool minimum", decide: new(true), caller: agent, tool: "cert_revoke", digest: "d", min: authz.LevelAdmin, want: ErrApproverLevel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, st, c := newService()
			a := s.Request(context.Background(), agent, "cert_revoke", "d", "Revoke", authz.LevelOperator)
			if tc.decide != nil {
				if _, err := s.Decide(context.Background(), operator, a.ID, *tc.decide); err != nil {
					t.Fatal(err)
				}
			}
			c.now = c.now.Add(tc.advance)

			_, err := s.Use(context.Background(), tc.caller, a.ID, tc.tool, tc.digest, tc.min)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if got, _ := st.Approval(a.ID); got.Status == store.ApprovalUsed {
				t.Fatal("a refused approval was marked used")
			}
		})
	}
	t.Run("unknown id", func(t *testing.T) {
		s, _, _ := newService()
		if _, err := s.Use(context.Background(), agent, "apr-missing", "cert_revoke", "d", authz.LevelOperator); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
}

func TestList_DerivesExpiryAndFilters(t *testing.T) {
	s, _, c := newService()
	old := s.Request(context.Background(), agent, "cert_revoke", "d1", "Revoke 1", authz.LevelOperator)
	c.now = t0.Add(10 * time.Minute)
	fresh := s.Request(context.Background(), agent, "cert_revoke", "d2", "Revoke 2", authz.LevelOperator)
	c.now = t0.Add(16 * time.Minute)

	all, err := s.List("")
	if err != nil || len(all) != 2 || all[0].ID != fresh.ID || all[1].Status != store.ApprovalExpired || all[0].Status != store.ApprovalPending {
		t.Fatalf("List() = %+v, %v", all, err)
	}
	if exp, _ := s.List("expired"); len(exp) != 1 || exp[0].ID != old.ID {
		t.Fatalf("List(expired) = %+v", exp)
	}
	if _, err := s.List("bogus"); !errors.Is(err, ErrBadStatus) {
		t.Fatalf("List(bogus) err = %v", err)
	}
	if mine := s.ForKey("mk-2"); len(mine) != 0 {
		t.Fatalf("ForKey(mk-2) = %+v", mine)
	}
	if mine := s.ForKey(agent.KeyID); len(mine) != 2 {
		t.Fatalf("ForKey(agent) = %+v", mine)
	}
}
