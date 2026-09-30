package store

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

import "testing"

// A row written before the chain carried actors must keep verifying, so the
// legacy formula is pinned to a known digest.
func TestHashEvent_LegacyRowsKeepTheirHash(t *testing.T) {
	e := AuditEvent{ID: "ev-1", At: "2026-07-17T00:00:00Z", Kind: "issued", Summary: "s", TargetKind: "cert", TargetPath: "/p"}
	const want = "587863eaad7dd58515e56742bd889bd81f410704370e07cdbfdde02aef706010"
	if got := HashEvent("", e); got != want {
		t.Fatalf("legacy hash = %s, want %s", got, want)
	}
}

func TestHashEvent_CurrentVersionCoversActorFields(t *testing.T) {
	base := AuditEvent{
		ID: "ev-1", At: "2026-07-17T00:00:00Z", Kind: "issued", Summary: "s", TargetKind: "cert", TargetPath: "/p",
		ChainVersion: AuditChainVersion,
		ActorKind:    "mcp_key", ActorCN: "operator@example.org", ActorSerial: "0A:BC", KeyID: "key-1",
		Via: "mcp", Tool: "cert_list", RequestDigest: "d", Outcome: "ok",
	}
	h := HashEvent("prev", base)
	if h == HashEvent("prev", AuditEvent{ID: base.ID, At: base.At, Kind: base.Kind, Summary: base.Summary, TargetKind: base.TargetKind, TargetPath: base.TargetPath}) {
		t.Fatal("current-version hash equals the legacy hash of the same core fields")
	}
	mutations := map[string]func(*AuditEvent){
		"actor_kind":      func(e *AuditEvent) { e.ActorKind = "cert" },
		"actor_cn":        func(e *AuditEvent) { e.ActorCN = "other@example.org" },
		"actor_serial":    func(e *AuditEvent) { e.ActorSerial = "0A:BD" },
		"key_id":          func(e *AuditEvent) { e.KeyID = "key-2" },
		"via":             func(e *AuditEvent) { e.Via = "web" },
		"tool":            func(e *AuditEvent) { e.Tool = "fleet_whoami" },
		"request_digest":  func(e *AuditEvent) { e.RequestDigest = "e" },
		"outcome":         func(e *AuditEvent) { e.Outcome = "denied" },
		"approval_id":     func(e *AuditEvent) { e.ApprovalID = "a" },
		"approver_serial": func(e *AuditEvent) { e.ApproverSerial = "01" },
	}
	for name, mutate := range mutations {
		e := base
		mutate(&e)
		if HashEvent("prev", e) == h {
			t.Errorf("changing %s did not change the hash", name)
		}
	}
	// Field boundaries are length-prefixed, so shifting text between two
	// adjacent fields must not collide.
	shifted := base
	shifted.ActorKind, shifted.ActorCN = "mcp_keyoperator@example.org", ""
	if HashEvent("prev", shifted) == h {
		t.Error("moving text across a field boundary kept the same hash")
	}
}
