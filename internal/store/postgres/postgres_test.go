package postgres

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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

func TestNodeRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO nodes (id, name, endpoint, role, admin_cert, admin_key, ca_cert)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		store.NewNodeID(), "x", "x.example:443", "root", "cert", "key", "ca"); err != nil {
		t.Fatalf("insert node: %v", err)
	}

	got, ok := s.Node("x")
	if !ok {
		t.Fatal("Node(x) not found")
	}
	if got.Endpoint != "x.example:443" || got.Role != "root" || got.CACert != "ca" {
		t.Fatalf("Node(x) = %+v, unexpected fields", got)
	}

	if _, ok := s.Node("missing"); ok {
		t.Fatal("Node(missing) returned found")
	}

	all := s.Nodes()
	if len(all) != 1 || all[0].Name != "x" {
		t.Fatalf("Nodes() = %+v, want single node x", all)
	}
}

func TestProfileAndAdapterReads(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO profiles (name, spec) VALUES ($1,$2)`,
		"p1", []byte{0x0a, 0x02, 0x70, 0x31}); err != nil {
		t.Fatalf("insert profile: %v", err)
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO adapters (name, kind, endpoint, profile, enabled, challenges, gpo_template)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		"acme", "acme", "https://x/acme", "p1", true, []string{"http-01", "dns-01"}, ""); err != nil {
		t.Fatalf("insert adapter: %v", err)
	}

	profiles := s.Profiles()
	if len(profiles) != 1 || profiles[0].Name != "p1" || len(profiles[0].Spec) != 4 {
		t.Fatalf("Profiles() = %+v, unexpected", profiles)
	}

	adapters := s.Adapters()
	if len(adapters) != 1 || !adapters[0].Enabled || len(adapters[0].Challenges) != 2 {
		t.Fatalf("Adapters() = %+v, unexpected", adapters)
	}
}

func TestEnrollmentMutations(t *testing.T) {
	s := testStore(t)

	e := store.Enrollment{
		ID:           "enr-abc",
		Kind:         "LINK",
		Status:       "PENDING",
		ProposedName: "node-1",
		RequestedAt:  "2026-07-17T00:00:00Z",
	}
	s.AddEnrollment(e)

	got, ok := s.Enrollment("enr-abc")
	if !ok || got.Status != "PENDING" || got.ProposedName != "node-1" {
		t.Fatalf("Enrollment after add = %+v, ok=%v", got, ok)
	}

	if err := s.UpdateEnrollment("enr-abc", func(en *store.Enrollment) {
		en.Status = "APPROVED"
		en.AdmittedNodeName = "node-1"
	}); err != nil {
		t.Fatalf("UpdateEnrollment: %v", err)
	}

	got, _ = s.Enrollment("enr-abc")
	if got.Status != "APPROVED" || got.AdmittedNodeName != "node-1" {
		t.Fatalf("Enrollment after update = %+v, want APPROVED/node-1", got)
	}

	if err := s.UpdateEnrollment("missing", func(*store.Enrollment) {}); err == nil {
		t.Fatal("UpdateEnrollment(missing) = nil, want error")
	}

	all := s.Enrollments()
	if len(all) != 1 {
		t.Fatalf("Enrollments() len = %d, want 1", len(all))
	}
}

func TestAuditChain(t *testing.T) {
	s := testStore(t)

	first := s.AddAuditEvent(store.AuditEvent{ID: "a1", At: "t1", Kind: "issued", Summary: "one"})
	second := s.AddAuditEvent(store.AuditEvent{ID: "a2", At: "t2", Kind: "revoked", Summary: "two"})

	if first.Hash == "" || second.Hash == "" {
		t.Fatal("hashes must be non-empty")
	}
	if first.PrevHash != "" {
		t.Fatalf("first PrevHash = %q, want empty", first.PrevHash)
	}
	if second.PrevHash != first.Hash {
		t.Fatalf("second PrevHash = %q, want first Hash %q", second.PrevHash, first.Hash)
	}
	if first.Hash == second.Hash {
		t.Fatal("distinct events must have distinct hashes")
	}

	log := s.Audit()
	if len(log) != 2 || log[0].ID != "a1" || log[1].ID != "a2" {
		t.Fatalf("Audit() = %+v, want ordered a1,a2", log)
	}
	if log[1].PrevHash != log[0].Hash {
		t.Fatalf("persisted chain broken: log[1].PrevHash=%q log[0].Hash=%q", log[1].PrevHash, log[0].Hash)
	}
}

// TestAuditChainConcurrentAppends drives many concurrent AddAuditEvent calls
// against one store and asserts the persisted chain stays linear: every event
// links to its predecessor, no prev_hash is reused, and every append lands.
// Without the advisory lock in AddAuditEvent two appends could read the same
// prev_hash and fork the chain, which this test would catch.
func TestAuditChainConcurrentAppends(t *testing.T) {
	s := testStore(t)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			s.AddAuditEvent(store.AuditEvent{
				ID:      fmt.Sprintf("evt-%d", i),
				At:      "t",
				Kind:    "issued",
				Summary: fmt.Sprintf("append %d", i),
			})
		}(i)
	}
	wg.Wait()

	log := s.Audit()
	if len(log) != n {
		t.Fatalf("Audit() len = %d, want %d", len(log), n)
	}

	seenPrev := make(map[string]struct{}, n)
	for i, e := range log {
		if e.Hash == "" {
			t.Fatalf("event %d has empty hash", i)
		}
		if i == 0 {
			if e.PrevHash != "" {
				t.Fatalf("first event PrevHash = %q, want empty", e.PrevHash)
			}
		} else {
			if e.PrevHash != log[i-1].Hash {
				t.Fatalf("chain fork at %d: PrevHash=%q, want prior Hash %q", i, e.PrevHash, log[i-1].Hash)
			}
		}
		if _, dup := seenPrev[e.PrevHash]; dup && e.PrevHash != "" {
			t.Fatalf("duplicate PrevHash %q at event %d: chain forked", e.PrevHash, i)
		}
		seenPrev[e.PrevHash] = struct{}{}
	}
}

func TestSeedIfEmpty(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	nodes := []store.Node{{Name: "n1", Endpoint: "n1:443", Role: "root", AdminCert: "c", AdminKey: "k", CACert: "ca"}}
	profiles := []store.Profile{{Name: "p1", Spec: []byte("spec-p1")}}
	adapters := []store.Adapter{{Name: "acme", Kind: "acme", Endpoint: "https://x", Profile: "p1", Enabled: true}}
	audit := []store.AuditEvent{{ID: "aud-0", At: "t0", Kind: "issued", Summary: "seed"}}
	enrollments := []store.Enrollment{{ID: "enr-0", Kind: "LINK", Status: "PENDING", ProposedName: "n1", RequestedAt: "t0"}}

	if err := s.SeedIfEmpty(ctx, nodes, profiles, adapters, audit, enrollments); err != nil {
		t.Fatalf("first SeedIfEmpty: %v", err)
	}
	if len(s.Nodes()) != 1 || len(s.Profiles()) != 1 || len(s.Adapters()) != 1 || len(s.Audit()) != 1 || len(s.Enrollments()) != 1 {
		t.Fatal("first seed did not populate every table")
	}

	// A second seed is a no-op: counts must not change.
	if err := s.SeedIfEmpty(ctx, nodes, profiles, adapters, audit, enrollments); err != nil {
		t.Fatalf("second SeedIfEmpty: %v", err)
	}
	if len(s.Nodes()) != 1 || len(s.Enrollments()) != 1 {
		t.Fatalf("second seed duplicated rows: nodes=%d enrollments=%d", len(s.Nodes()), len(s.Enrollments()))
	}
}

func TestProfileCRUD_RoundTripsSpec(t *testing.T) {
	s := testStore(t)

	spec := []byte{0x00, 0x01, 0x02, 0xff, 0xfe}
	if err := s.CreateProfile(store.Profile{Name: "P", Spec: spec}); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}

	got, ok := s.Profile("P")
	if !ok {
		t.Fatal("Profile(P) not found after create")
	}
	if string(got.Spec) != string(spec) {
		t.Errorf("Profile(P).Spec = %v, want %v", got.Spec, spec)
	}

	all := s.Profiles()
	if len(all) != 1 || all[0].Name != "P" || string(all[0].Spec) != string(spec) {
		t.Fatalf("Profiles() = %+v, want single P with the exact spec", all)
	}
}

func TestProfileCRUD_DuplicateCreateErrors(t *testing.T) {
	s := testStore(t)

	if err := s.CreateProfile(store.Profile{Name: "P", Spec: []byte("a")}); err != nil {
		t.Fatalf("first CreateProfile: %v", err)
	}
	if err := s.CreateProfile(store.Profile{Name: "P", Spec: []byte("b")}); err == nil {
		t.Fatal("duplicate CreateProfile returned nil, want error")
	}
	if got, _ := s.Profile("P"); string(got.Spec) != "a" {
		t.Errorf("Profile(P).Spec = %q, want the original a", got.Spec)
	}
}

func TestProfileCRUD_UpdateReplacesSpec(t *testing.T) {
	s := testStore(t)

	if err := s.CreateProfile(store.Profile{Name: "P", Spec: []byte("a")}); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	if err := s.UpdateProfile(store.Profile{Name: "P", Spec: []byte("b")}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if got, _ := s.Profile("P"); string(got.Spec) != "b" {
		t.Errorf("Profile(P).Spec = %q, want b", got.Spec)
	}
}

func TestProfileCRUD_UpdateMissingErrors(t *testing.T) {
	s := testStore(t)
	if err := s.UpdateProfile(store.Profile{Name: "nope", Spec: []byte("x")}); err == nil {
		t.Fatal("UpdateProfile(missing) returned nil, want error")
	}
}

func TestProfileCRUD_DeleteRemoves(t *testing.T) {
	s := testStore(t)

	if err := s.CreateProfile(store.Profile{Name: "P", Spec: []byte("a")}); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	if err := s.DeleteProfile("P"); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	if _, ok := s.Profile("P"); ok {
		t.Error("Profile(P) still found after delete")
	}
	if len(s.Profiles()) != 0 {
		t.Errorf("Profiles() len = %d, want 0", len(s.Profiles()))
	}
}

func TestProfileCRUD_DeleteMissingErrors(t *testing.T) {
	s := testStore(t)
	if err := s.DeleteProfile("nope"); err == nil {
		t.Fatal("DeleteProfile(missing) returned nil, want error")
	}
}

func TestSetAdapterEnabled_Flips(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO adapters (name, kind, endpoint, profile, enabled, challenges, gpo_template)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		"acme", "acme", "https://x/acme", "p1", true, []string{"http-01"}, ""); err != nil {
		t.Fatalf("insert adapter: %v", err)
	}

	got, err := s.SetAdapterEnabled("acme", false)
	if err != nil {
		t.Fatalf("SetAdapterEnabled: %v", err)
	}
	if got.Enabled {
		t.Error("returned adapter Enabled = true, want false")
	}
	if got.Name != "acme" || got.Kind != "acme" || len(got.Challenges) != 1 {
		t.Errorf("returned adapter = %+v, unexpected fields", got)
	}

	adapters := s.Adapters()
	if len(adapters) != 1 || adapters[0].Enabled {
		t.Errorf("Adapters() = %+v, want the adapter disabled", adapters)
	}
}

func TestSetAdapterEnabled_MissingErrors(t *testing.T) {
	s := testStore(t)
	if _, err := s.SetAdapterEnabled("nope", true); err == nil {
		t.Fatal("SetAdapterEnabled(missing) returned nil, want error")
	}
}

func TestOperatorCredentialsCRUD(t *testing.T) {
	s := testStore(t)

	if len(s.OperatorCredentials()) != 0 {
		t.Fatalf("fresh store has %d operator credentials, want 0", len(s.OperatorCredentials()))
	}

	s.AddOperatorCredential(store.OperatorCredential{
		CommonName: "op@acme.example", SerialHex: "0a1b", Level: "operator",
		NotAfter: "2027-01-01T00:00:00Z",
	})
	s.AddOperatorCredential(store.OperatorCredential{
		CommonName: "admin@acme.example", SerialHex: "0c2d", Level: "admin",
		NotAfter: "2027-02-01T00:00:00Z",
	})

	creds := s.OperatorCredentials()
	if len(creds) != 2 {
		t.Fatalf("len(creds) = %d, want 2", len(creds))
	}
	if creds[0].SerialHex != "0a1b" || creds[0].Level != "operator" || creds[0].Revoked {
		t.Errorf("creds[0] = %+v, want the operator row not revoked", creds[0])
	}

	if err := s.MarkOperatorCredentialRevoked("0a1b"); err != nil {
		t.Fatalf("MarkOperatorCredentialRevoked: %v", err)
	}
	var revoked *store.OperatorCredential
	for i := range s.OperatorCredentials() {
		if c := s.OperatorCredentials()[i]; c.SerialHex == "0a1b" {
			revoked = &c
		}
	}
	if revoked == nil || !revoked.Revoked {
		t.Fatalf("credential 0a1b not marked revoked: %+v", revoked)
	}

	if err := s.MarkOperatorCredentialRevoked("nope"); err == nil {
		t.Fatal("MarkOperatorCredentialRevoked(unknown) = nil, want an error")
	}
}

func TestAuditActorFieldsRoundTripAndVerify(t *testing.T) {
	s := testStore(t)

	// A pre-actor row, as a database migrated from an older release holds it.
	legacy := store.AuditEvent{ID: "ev-0", At: "2026-07-17T00:00:00Z", Kind: "issued", Summary: "s", TargetKind: "cert", TargetPath: "/p"}
	legacy.Hash = store.HashEvent("", legacy)
	if _, err := s.pool.Exec(context.Background(),
		`INSERT INTO audit_events (id, at, kind, summary, target_kind, target_path, prev_hash, hash)
		 VALUES ($1,$2,$3,$4,$5,$6,'',$7)`,
		legacy.ID, legacy.At, legacy.Kind, legacy.Summary, legacy.TargetKind, legacy.TargetPath, legacy.Hash); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	got := s.AddAuditEvent(store.AuditEvent{
		ID: "ev-1", At: "2026-09-29T00:00:00Z", Kind: "issued", Summary: "Issued", TargetKind: "cert", TargetPath: "/nodes/n/certs",
		ActorKind: "mcp_key", ActorCN: "operator@example.org", ActorSerial: "0A:BC", KeyID: "key-1",
		Via: "mcp", Tool: "cert_issue_from_csr", RequestDigest: "abc", Outcome: "ok",
	})
	if got.ChainVersion != store.AuditChainVersion || got.PrevHash != legacy.Hash {
		t.Fatalf("appended = %+v", got)
	}

	all := s.Audit()
	if len(all) != 2 {
		t.Fatalf("Audit() len = %d", len(all))
	}
	if all[0].ChainVersion != 1 {
		t.Fatalf("legacy row chain version = %d, want 1", all[0].ChainVersion)
	}
	prev := ""
	for _, e := range all {
		if e.Hash != store.HashEvent(prev, e) {
			t.Fatalf("row %s does not verify", e.ID)
		}
		prev = e.Hash
	}
	e := all[1]
	if e.ActorKind != "mcp_key" || e.ActorCN != "operator@example.org" || e.ActorSerial != "0A:BC" ||
		e.KeyID != "key-1" || e.Via != "mcp" || e.Tool != "cert_issue_from_csr" || e.RequestDigest != "abc" || e.Outcome != "ok" {
		t.Fatalf("actor fields = %+v", e)
	}
}

func TestMcpKeys(t *testing.T) {
	s := testStore(t)
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	s.AddMcpKey(store.McpKey{
		ID: "k1", TokenHash: "h1", Label: "laptop", ClientName: "agent", OperatorSerial: "01",
		OperatorCN: "operator@example.org", OperatorCertDER: []byte{1, 2, 3}, LevelCeiling: "viewer", CreatedAt: t0,
	})
	s.AddMcpKey(store.McpKey{ID: "k2", TokenHash: "h2", OperatorSerial: "02", OperatorCertDER: []byte{4}, CreatedAt: t0.Add(time.Hour)})

	k, ok := s.McpKeyByHash("h1")
	if !ok || k.ID != "k1" || k.Label != "laptop" || k.ClientName != "agent" || k.LevelCeiling != "viewer" ||
		string(k.OperatorCertDER) != string([]byte{1, 2, 3}) || !k.CreatedAt.Equal(t0) || !k.LastUsedAt.IsZero() || !k.RevokedAt.IsZero() {
		t.Fatalf("McpKeyByHash(h1) = %+v, %v", k, ok)
	}
	if _, ok := s.McpKeyByHash("nope"); ok {
		t.Fatal("McpKeyByHash(nope) found a key")
	}
	if all := s.McpKeys(); len(all) != 2 || all[0].ID != "k2" {
		t.Fatalf("McpKeys() = %+v, want newest first", all)
	}

	if !s.TouchMcpKey("k1", t0.Add(time.Minute)) {
		t.Fatal("first TouchMcpKey did not report first use")
	}
	if s.TouchMcpKey("k1", t0.Add(2*time.Minute)) {
		t.Fatal("second TouchMcpKey reported first use")
	}

	rev, err := s.RevokeMcpKey("k1", t0.Add(3*time.Minute))
	if err != nil || !rev.RevokedAt.Equal(t0.Add(3*time.Minute)) || !rev.LastUsedAt.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("RevokeMcpKey = %+v, %v", rev, err)
	}
	again, err := s.RevokeMcpKey("k1", t0.Add(4*time.Minute))
	if err != nil || !again.RevokedAt.Equal(t0.Add(3*time.Minute)) {
		t.Fatalf("second RevokeMcpKey = %+v, %v", again, err)
	}
	if _, err := s.RevokeMcpKey("missing", t0); err == nil {
		t.Fatal("RevokeMcpKey(missing) = nil error")
	}
}

func TestOAuthStateIsSingleUseAndExpires(t *testing.T) {
	s := testStore(t)
	future := time.Now().Add(time.Minute).UTC().Truncate(time.Microsecond)
	past := time.Now().Add(-time.Minute)

	s.AddOAuthRequest(store.OAuthRequest{ID: "old", ExpiresAt: past})
	s.AddOAuthCode(store.OAuthCode{CodeHash: "oldc", OperatorCertDER: []byte{9}, ExpiresAt: past})
	s.AddOAuthRequest(store.OAuthRequest{
		ID: "r1", ClientID: "cid", ClientName: "agent", RedirectURI: "http://127.0.0.1:1/cb",
		State: "st", CodeChallenge: "ch", ExpiresAt: future,
	})
	if _, ok := s.OAuthRequest("old"); ok {
		t.Fatal("expired request survived a later add")
	}
	if _, ok := s.TakeOAuthCode("oldc"); ok {
		t.Fatal("expired code survived a later add")
	}

	r, ok := s.OAuthRequest("r1")
	if !ok || r.ClientName != "agent" || r.RedirectURI != "http://127.0.0.1:1/cb" || r.State != "st" || !r.ExpiresAt.Equal(future) {
		t.Fatalf("OAuthRequest(r1) = %+v, %v", r, ok)
	}
	if _, ok := s.TakeOAuthRequest("r1"); !ok {
		t.Fatal("TakeOAuthRequest(r1) missing")
	}
	if _, ok := s.TakeOAuthRequest("r1"); ok {
		t.Fatal("TakeOAuthRequest(r1) succeeded twice")
	}

	s.AddOAuthCode(store.OAuthCode{
		CodeHash: "c1", ClientID: "cid", ClientName: "agent", RedirectURI: "http://127.0.0.1:1/cb", CodeChallenge: "ch",
		OperatorCN: "operator@example.org", OperatorSerial: "01", OperatorCertDER: []byte{1}, LevelCeiling: "operator",
		Label: "laptop", ExpiresAt: future,
	})
	c, ok := s.TakeOAuthCode("c1")
	if !ok || c.OperatorSerial != "01" || c.LevelCeiling != "operator" || c.Label != "laptop" || len(c.OperatorCertDER) != 1 {
		t.Fatalf("TakeOAuthCode(c1) = %+v, %v", c, ok)
	}
	if _, ok := s.TakeOAuthCode("c1"); ok {
		t.Fatal("TakeOAuthCode(c1) succeeded twice")
	}
}

func TestApprovals(t *testing.T) {
	s := testStore(t)
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	exp := t0.Add(15 * time.Minute)
	pending := func(id string, created time.Time) store.Approval {
		return store.Approval{
			ID: id, Tool: "cert_revoke", Summary: "Revoke 0A on pki-issuing", RequestDigest: "d-" + id,
			RequestedByCN: "operator@example.org", RequestedBySerial: "01", KeyID: "k1", RequiredLevel: "operator",
			CreatedAt: created, ExpiresAt: created.Add(15 * time.Minute), Status: store.ApprovalPending,
		}
	}
	s.AddApproval(pending("a1", t0))
	s.AddApproval(pending("a2", t0.Add(time.Minute)))

	got, ok := s.Approval("a1")
	if !ok || got.Tool != "cert_revoke" || got.Summary != "Revoke 0A on pki-issuing" || got.RequestDigest != "d-a1" ||
		got.RequestedByCN != "operator@example.org" || got.RequestedBySerial != "01" || got.KeyID != "k1" ||
		got.RequiredLevel != "operator" || got.Status != store.ApprovalPending || !got.CreatedAt.Equal(t0) ||
		!got.ExpiresAt.Equal(exp) || !got.DecidedAt.IsZero() || !got.UsedAt.IsZero() {
		t.Fatalf("Approval(a1) = %+v, %v", got, ok)
	}
	if _, ok := s.Approval("missing"); ok {
		t.Fatal("Approval(missing) found one")
	}
	if all := s.Approvals(); len(all) != 2 || all[0].ID != "a2" || all[1].ID != "a1" {
		t.Fatalf("Approvals() = %+v, want newest first", all)
	}

	if _, ok := s.UseApproval("a1", t0.Add(time.Minute)); ok {
		t.Fatal("a pending approval was used")
	}
	d, ok := s.DecideApproval("a1", store.ApprovalApproved, "admin@example.org", "02", "admin", t0.Add(time.Minute))
	if !ok || d.Status != store.ApprovalApproved || d.DecidedByCN != "admin@example.org" || d.DecidedBySerial != "02" ||
		d.DecidedByLevel != "admin" || !d.DecidedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("DecideApproval(a1) = %+v, %v", d, ok)
	}
	if _, ok := s.DecideApproval("a1", store.ApprovalDenied, "other@example.org", "03", "admin", t0.Add(2*time.Minute)); ok {
		t.Fatal("a decided approval was decided again")
	}
	if _, ok := s.DecideApproval("a2", store.ApprovalApproved, "admin@example.org", "02", "admin", t0.Add(16*time.Minute)); ok {
		t.Fatal("an expired approval was decided")
	}
	if _, ok := s.DecideApproval("missing", store.ApprovalApproved, "admin@example.org", "02", "admin", t0); ok {
		t.Fatal("a missing approval was decided")
	}

	if _, ok := s.UseApproval("a1", exp); ok {
		t.Fatal("an approval was used at its expiry")
	}
	u, ok := s.UseApproval("a1", t0.Add(2*time.Minute))
	if !ok || u.Status != store.ApprovalUsed || !u.UsedAt.Equal(t0.Add(2*time.Minute)) || u.DecidedBySerial != "02" {
		t.Fatalf("UseApproval(a1) = %+v, %v", u, ok)
	}
	if _, ok := s.UseApproval("a1", t0.Add(3*time.Minute)); ok {
		t.Fatal("an approval was used twice")
	}
}

// Concurrent calls presenting the same approval must run at most once.
func TestUseApproval_ConcurrentUseWinsOnce(t *testing.T) {
	s := testStore(t)
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	s.AddApproval(store.Approval{ID: "a1", Tool: "cert_revoke", RequestDigest: "d", KeyID: "k1", RequiredLevel: "operator",
		CreatedAt: t0, ExpiresAt: t0.Add(15 * time.Minute), Status: store.ApprovalPending})
	if _, ok := s.DecideApproval("a1", store.ApprovalApproved, "admin@example.org", "02", "admin", t0); !ok {
		t.Fatal("DecideApproval failed")
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := s.UseApproval("a1", t0.Add(time.Second)); ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("approval used %d times, want 1", wins)
	}
}
