package memory

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
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
)

func testNodes() []store.Node {
	return []store.Node{
		{
			Name:      "pki-root",
			Endpoint:  "pki-root.acme.com:4443",
			Role:      "root",
			AdminCert: "/tmp/root/admin.crt",
			AdminKey:  "/tmp/root/admin.key",
			CACert:    "/tmp/root/ca.pem",
		},
		{
			Name:      "pki-inter",
			Endpoint:  "pki-inter.acme.com:4444",
			Role:      "intermediate",
			AdminCert: "/tmp/inter/admin.crt",
			AdminKey:  "/tmp/inter/admin.key",
			CACert:    "/tmp/inter/ca.pem",
		},
	}
}

func TestStore_Nodes(t *testing.T) {
	s := New(testNodes())

	nodes := s.Nodes()
	if len(nodes) != 2 {
		t.Fatalf("len(Nodes()) = %d, want 2", len(nodes))
	}
}

func TestStore_Node_Found(t *testing.T) {
	s := New(testNodes())

	n, ok := s.Node("pki-root")
	if !ok {
		t.Fatal("Node(\"pki-root\") ok = false, want true")
	}
	if n.Endpoint != "pki-root.acme.com:4443" {
		t.Errorf("Node(\"pki-root\").Endpoint = %q, want pki-root.acme.com:4443", n.Endpoint)
	}
}

func TestStore_Node_NotFound(t *testing.T) {
	s := New(testNodes())

	_, ok := s.Node("does-not-exist")
	if ok {
		t.Fatal("Node(\"does-not-exist\") ok = true, want false")
	}
}

func TestStore_ImplementsInterface(t *testing.T) {
	var _ store.Store = New(testNodes())
}

func testCatalog() ([]store.Profile, []store.Adapter, []store.AuditEvent, []store.Enrollment) {
	profiles := []store.Profile{
		{Name: "TLS Server (LDAPS)", Spec: []byte("spec-a")},
	}
	adapters := []store.Adapter{
		{Kind: "acme", Name: "ACME (RFC 8555)", Enabled: true},
	}
	audit := []store.AuditEvent{
		{ID: "aud-0000", Kind: "issued", Summary: "Issued leaf svc-1.acme.example"},
	}
	enrollments := []store.Enrollment{
		{ID: "enr-0001", ProposedName: "acme-issuing-04", Status: "PENDING"},
	}

	return profiles, adapters, audit, enrollments
}

func TestStore_New_HasEmptyCatalog(t *testing.T) {
	s := New(testNodes())

	if got := s.Profiles(); len(got) != 0 {
		t.Errorf("Profiles() len = %d, want 0", len(got))
	}
	if got := s.Adapters(); len(got) != 0 {
		t.Errorf("Adapters() len = %d, want 0", len(got))
	}
	if got := s.Audit(); len(got) != 0 {
		t.Errorf("Audit() len = %d, want 0", len(got))
	}
	if got := s.Enrollments(); len(got) != 0 {
		t.Errorf("Enrollments() len = %d, want 0", len(got))
	}
}

func TestStore_NewWithCatalog_RoundTrip(t *testing.T) {
	profiles, adapters, audit, enrollments := testCatalog()

	s := NewWithCatalog(testNodes(), profiles, adapters, audit, enrollments)

	if got := s.Profiles(); len(got) != 1 || got[0].Name != "TLS Server (LDAPS)" {
		t.Errorf("Profiles() = %+v, want the seeded profile", got)
	}
	if got := s.Adapters(); len(got) != 1 || got[0].Kind != "acme" {
		t.Errorf("Adapters() = %+v, want the seeded adapter", got)
	}
	if got := s.Audit(); len(got) != 1 || got[0].ID != "aud-0000" {
		t.Errorf("Audit() = %+v, want the seeded event", got)
	}
	if got := s.Enrollments(); len(got) != 1 || got[0].Status != "PENDING" {
		t.Errorf("Enrollments() = %+v, want the seeded enrollment", got)
	}

	// Nodes() is unaffected by the catalog constructor.
	if got := s.Nodes(); len(got) != 2 {
		t.Errorf("Nodes() len = %d, want 2", len(got))
	}
}

func TestStore_AddEnrollment(t *testing.T) {
	s := New(testNodes())

	s.AddEnrollment(store.Enrollment{ID: "enr-0001", ProposedName: "acme-issuing-04", Status: "PENDING"})

	got, ok := s.Enrollment("enr-0001")
	if !ok {
		t.Fatal("Enrollment(\"enr-0001\") ok = false, want true")
	}
	if got.ProposedName != "acme-issuing-04" {
		t.Errorf("Enrollment(\"enr-0001\").ProposedName = %q, want acme-issuing-04", got.ProposedName)
	}

	all := s.Enrollments()
	if len(all) != 1 {
		t.Fatalf("len(Enrollments()) = %d, want 1", len(all))
	}
	if all[0].ID != "enr-0001" {
		t.Errorf("Enrollments()[0].ID = %q, want enr-0001", all[0].ID)
	}
}

func TestStore_Enrollment_NotFound(t *testing.T) {
	s := New(testNodes())

	_, ok := s.Enrollment("does-not-exist")
	if ok {
		t.Fatal("Enrollment(\"does-not-exist\") ok = true, want false")
	}
}

func TestStore_UpdateEnrollment(t *testing.T) {
	s := New(testNodes())
	s.AddEnrollment(store.Enrollment{ID: "enr-0001", Status: "PENDING"})

	err := s.UpdateEnrollment("enr-0001", func(e *store.Enrollment) {
		e.Status = "APPROVED"
	})
	if err != nil {
		t.Fatalf("UpdateEnrollment() error = %v, want nil", err)
	}

	got, ok := s.Enrollment("enr-0001")
	if !ok {
		t.Fatal("Enrollment(\"enr-0001\") ok = false, want true")
	}
	if got.Status != "APPROVED" {
		t.Errorf("Enrollment(\"enr-0001\").Status = %q, want APPROVED", got.Status)
	}
}

func TestStore_UpdateEnrollment_NotFound(t *testing.T) {
	s := New(testNodes())

	err := s.UpdateEnrollment("does-not-exist", func(e *store.Enrollment) {
		e.Status = "APPROVED"
	})
	if err == nil {
		t.Fatal("UpdateEnrollment(\"does-not-exist\") error = nil, want non-nil")
	}
}

func TestStore_Enrollment_ReturnsCopy(t *testing.T) {
	s := New(testNodes())
	s.AddEnrollment(store.Enrollment{ID: "enr-0001", Status: "PENDING"})

	got, ok := s.Enrollment("enr-0001")
	if !ok {
		t.Fatal("Enrollment(\"enr-0001\") ok = false, want true")
	}
	got.Status = "APPROVED"

	again, ok := s.Enrollment("enr-0001")
	if !ok {
		t.Fatal("Enrollment(\"enr-0001\") ok = false, want true")
	}
	if again.Status != "PENDING" {
		t.Errorf("Enrollment(\"enr-0001\").Status = %q after mutating a returned copy, want PENDING", again.Status)
	}
}

func TestStore_Enrollments_ReturnsCopy(t *testing.T) {
	s := New(testNodes())
	s.AddEnrollment(store.Enrollment{ID: "enr-0001", Status: "PENDING"})

	all := s.Enrollments()
	all[0].Status = "APPROVED"

	again, ok := s.Enrollment("enr-0001")
	if !ok {
		t.Fatal("Enrollment(\"enr-0001\") ok = false, want true")
	}
	if again.Status != "PENDING" {
		t.Errorf("Enrollment(\"enr-0001\").Status = %q after mutating Enrollments() slice, want PENDING", again.Status)
	}
}

func TestStore_AddAuditEvent_ChainsHashes(t *testing.T) {
	s := New(testNodes())

	first := s.AddAuditEvent(store.AuditEvent{ID: "a1", At: "t1", Kind: "issued", Summary: "one"})
	second := s.AddAuditEvent(store.AuditEvent{ID: "a2", At: "t2", Kind: "revoked", Summary: "two"})

	if first.Hash == "" || second.Hash == "" {
		t.Fatal("hashes must be non-empty")
	}
	if first.PrevHash != "" {
		t.Errorf("first PrevHash = %q, want empty", first.PrevHash)
	}
	if second.PrevHash != first.Hash {
		t.Errorf("second PrevHash = %q, want first Hash %q", second.PrevHash, first.Hash)
	}
	if first.Hash == second.Hash {
		t.Error("distinct events must have distinct hashes")
	}

	log := s.Audit()
	if len(log) != 2 || log[0].ID != "a1" || log[1].ID != "a2" {
		t.Fatalf("Audit() = %+v, want ordered a1,a2", log)
	}
}

func TestStore_CreateProfile_RoundTripsSpec(t *testing.T) {
	s := New(testNodes())

	p := store.Profile{Name: "P", Spec: []byte{0x01, 0x02, 0x03}}
	if err := s.CreateProfile(p); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}

	all := s.Profiles()
	if len(all) != 1 || all[0].Name != "P" {
		t.Fatalf("Profiles() = %+v, want single P", all)
	}

	got, ok := s.Profile("P")
	if !ok {
		t.Fatal("Profile(P) not found")
	}
	if string(got.Spec) != string(p.Spec) {
		t.Errorf("Profile(P).Spec = %v, want %v", got.Spec, p.Spec)
	}
}

func TestStore_CreateProfile_DuplicateErrors(t *testing.T) {
	s := New(testNodes())

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

func TestStore_UpdateProfile_ReplacesSpec(t *testing.T) {
	s := New(testNodes())

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

func TestStore_UpdateProfile_MissingErrors(t *testing.T) {
	s := New(testNodes())
	if err := s.UpdateProfile(store.Profile{Name: "nope", Spec: []byte("x")}); err == nil {
		t.Fatal("UpdateProfile(missing) returned nil, want error")
	}
}

func TestStore_DeleteProfile_Removes(t *testing.T) {
	s := New(testNodes())

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

func TestStore_DeleteProfile_MissingErrors(t *testing.T) {
	s := New(testNodes())
	if err := s.DeleteProfile("nope"); err == nil {
		t.Fatal("DeleteProfile(missing) returned nil, want error")
	}
}

func TestStore_SetAdapterEnabled_Flips(t *testing.T) {
	profiles, adapters, audit, enrollments := testCatalog()
	s := NewWithCatalog(testNodes(), profiles, adapters, audit, enrollments)

	got, err := s.SetAdapterEnabled("ACME (RFC 8555)", false)
	if err != nil {
		t.Fatalf("SetAdapterEnabled: %v", err)
	}
	if got.Enabled {
		t.Error("returned adapter Enabled = true, want false")
	}
	if got.Name != "ACME (RFC 8555)" {
		t.Errorf("returned adapter Name = %q, want the named adapter", got.Name)
	}

	list := s.Adapters()
	if len(list) != 1 || list[0].Enabled {
		t.Errorf("Adapters() = %+v, want the seeded adapter disabled", list)
	}
}

func TestStore_SetAdapterEnabled_MissingErrors(t *testing.T) {
	profiles, adapters, audit, enrollments := testCatalog()
	s := NewWithCatalog(testNodes(), profiles, adapters, audit, enrollments)

	if _, err := s.SetAdapterEnabled("missing", true); err == nil {
		t.Fatal("SetAdapterEnabled(missing) returned nil, want error")
	}
}

func TestStore_AddAuditEvent_StampsCurrentChainVersionAndKeepsActor(t *testing.T) {
	s := New(nil)
	got := s.AddAuditEvent(store.AuditEvent{
		ID: "ev-1", Kind: "issued", ActorKind: "mcp_key", ActorCN: "operator@example.org",
		ActorSerial: "0A:BC", KeyID: "key-1", Via: "mcp", Tool: "cert_issue_from_csr", Outcome: "ok",
	})
	if got.ChainVersion != store.AuditChainVersion {
		t.Fatalf("ChainVersion = %d, want %d", got.ChainVersion, store.AuditChainVersion)
	}
	if got.Hash != store.HashEvent("", got) {
		t.Fatal("stored hash does not verify")
	}
	stored := s.Audit()[0]
	if stored.ActorCN != "operator@example.org" || stored.KeyID != "key-1" || stored.Tool != "cert_issue_from_csr" {
		t.Fatalf("stored actor fields = %+v", stored)
	}
}

func TestStore_McpKeys(t *testing.T) {
	s := New(nil)
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	s.AddMcpKey(store.McpKey{ID: "k1", TokenHash: "h1", OperatorSerial: "01", CreatedAt: t0})
	s.AddMcpKey(store.McpKey{ID: "k2", TokenHash: "h2", OperatorSerial: "02", CreatedAt: t0.Add(time.Hour)})

	if k, ok := s.McpKeyByHash("h2"); !ok || k.ID != "k2" {
		t.Fatalf("McpKeyByHash(h2) = %+v, %v", k, ok)
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
	if k, _ := s.McpKey("k1"); !k.LastUsedAt.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("LastUsedAt = %v", k.LastUsedAt)
	}

	rev, err := s.RevokeMcpKey("k1", t0.Add(3*time.Minute))
	if err != nil || !rev.RevokedAt.Equal(t0.Add(3*time.Minute)) {
		t.Fatalf("RevokeMcpKey = %+v, %v", rev, err)
	}
	again, err := s.RevokeMcpKey("k1", t0.Add(4*time.Minute))
	if err != nil || !again.RevokedAt.Equal(t0.Add(3*time.Minute)) {
		t.Fatalf("second RevokeMcpKey = %+v, %v; want first revocation time kept", again, err)
	}
	if _, err := s.RevokeMcpKey("missing", t0); err == nil {
		t.Fatal("RevokeMcpKey(missing) = nil error")
	}
}

func TestStore_OAuthStateIsSingleUse(t *testing.T) {
	s := New(nil)
	future := time.Now().Add(time.Minute)
	s.AddOAuthRequest(store.OAuthRequest{ID: "r1", ClientName: "agent", ExpiresAt: future})
	if r, ok := s.OAuthRequest("r1"); !ok || r.ClientName != "agent" {
		t.Fatalf("OAuthRequest(r1) = %+v, %v", r, ok)
	}
	if _, ok := s.TakeOAuthRequest("r1"); !ok {
		t.Fatal("TakeOAuthRequest(r1) missing")
	}
	if _, ok := s.TakeOAuthRequest("r1"); ok {
		t.Fatal("TakeOAuthRequest(r1) succeeded twice")
	}

	s.AddOAuthCode(store.OAuthCode{CodeHash: "c1", OperatorSerial: "01", ExpiresAt: future})
	if c, ok := s.TakeOAuthCode("c1"); !ok || c.OperatorSerial != "01" {
		t.Fatalf("TakeOAuthCode(c1) = %+v, %v", c, ok)
	}
	if _, ok := s.TakeOAuthCode("c1"); ok {
		t.Fatal("TakeOAuthCode(c1) succeeded twice")
	}
}

func TestStore_AddOAuthRequestDropsExpiredState(t *testing.T) {
	s := New(nil)
	past := time.Now().Add(-time.Minute)
	s.AddOAuthRequest(store.OAuthRequest{ID: "old", ExpiresAt: past})
	s.AddOAuthCode(store.OAuthCode{CodeHash: "oldc", ExpiresAt: past})
	s.AddOAuthRequest(store.OAuthRequest{ID: "new", ExpiresAt: time.Now().Add(time.Minute)})
	if _, ok := s.OAuthRequest("old"); ok {
		t.Fatal("expired request survived a later add")
	}
	if _, ok := s.TakeOAuthCode("oldc"); ok {
		t.Fatal("expired code survived a later add")
	}
}
