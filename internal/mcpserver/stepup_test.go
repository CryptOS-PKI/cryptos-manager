package mcpserver

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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/approval"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type pending struct {
	Status     string `json:"status"`
	ApprovalID string `json:"approval_id"`
	ApproveURL string `json:"approve_url"`
	Summary    string `json:"summary"`
}

func asPending(t *testing.T, res *mcp.CallToolResult) pending {
	t.Helper()
	if res.IsError {
		t.Fatalf("step-up call failed: %s", text(res))
	}
	var p pending
	if err := json.Unmarshal([]byte(text(res)), &p); err != nil {
		t.Fatalf("result %q is not a pending approval: %v", text(res), err)
	}
	if p.Status != "pending_approval" || p.ApprovalID == "" || p.Summary == "" ||
		p.ApproveURL != testPublicURL+"/approvals?id="+p.ApprovalID {
		t.Fatalf("pending = %+v", p)
	}
	return p
}

var (
	approverOperator = authz.Identity{CN: "approver@example.org", Serial: "0D:EF", Level: authz.LevelOperator, Via: authz.ViaWeb}
	approverAdmin    = authz.Identity{CN: "approver@example.org", Serial: "0D:F0", Level: authz.LevelAdmin, Via: authz.ViaWeb}
)

func (h *harness) approve(id string, by authz.Identity) {
	h.t.Helper()
	if _, err := h.approvals.Decide(context.Background(), by, id, true); err != nil {
		h.t.Fatalf("approve %s: %v", id, err)
	}
}

// stepUpCalls are valid calls to every step-up tool.
var stepUpCalls = map[string]map[string]any{
	"cert_revoke":           {"node": "pki-issuing", "serial_hex": "0A1B", "reason_code": 1},
	"profile_create":        {"profile": map[string]any{"name": "code-sign", "validity_days": 365}},
	"profile_update":        {"profile": map[string]any{"name": "tls-server", "validity_days": 90}},
	"profile_delete":        {"name": "tls-server"},
	"profile_apply_to_node": {"profile": "tls-server", "node": "pki-issuing"},
	"adapter_set_enabled":   {"name": "acme-web", "enabled": true},
}

// changed reports whether anything a step-up tool can change was changed.
func (h *harness) changed(t *testing.T, profilesBefore []store.Profile, adaptersBefore []store.Adapter) bool {
	t.Helper()
	for _, n := range h.nodes {
		if n.changes() != 0 {
			return true
		}
	}
	after := h.st.Profiles()
	if len(after) != len(profilesBefore) {
		return true
	}
	for i := range after {
		if after[i].Name != profilesBefore[i].Name || string(after[i].Spec) != string(profilesBefore[i].Spec) {
			return true
		}
	}
	for i, a := range h.st.Adapters() {
		if a.Enabled != adaptersBefore[i].Enabled {
			return true
		}
	}
	return false
}

func TestStepUp_NeverExecutesWithoutAnApproval(t *testing.T) {
	for tool, args := range stepUpCalls {
		t.Run(tool, func(t *testing.T) {
			h := newHarness(t)
			cs := h.session(h.key(authz.LevelAdmin, ""))
			profiles, adapters := h.st.Profiles(), h.st.Adapters()

			p := asPending(t, h.call(cs, tool, args))

			if h.changed(t, profiles, adapters) {
				t.Fatal("a step-up tool changed something without an approval")
			}
			a, ok := h.st.Approval(p.ApprovalID)
			if !ok || a.Tool != tool || a.Status != store.ApprovalPending || a.RequiredLevel != spec(tool).MinLevel.Token() ||
				a.KeyID == "" || a.RequestedBySerial == "" || a.Summary != p.Summary || !a.ExpiresAt.Equal(a.CreatedAt.Add(15*time.Minute)) {
				t.Fatalf("approval record = %+v, %v", a, ok)
			}
			last := lastAudit(h.st)
			if last.Kind != approval.KindRequested || last.Outcome != "pending" || last.ApprovalID != p.ApprovalID ||
				last.Tool != tool || last.Via != "mcp" || last.KeyID != a.KeyID || last.RequestDigest != a.RequestDigest {
				t.Fatalf("pending audit = %+v", last)
			}
		})
	}
}

func TestStepUp_RunsOnceWithAnApprovalAndAuditsBothIdentities(t *testing.T) {
	for tool, args := range stepUpCalls {
		t.Run(tool, func(t *testing.T) {
			h := newHarness(t)
			cs := h.session(h.key(authz.LevelAdmin, ""))
			profiles, adapters := h.st.Profiles(), h.st.Adapters()
			p := asPending(t, h.call(cs, tool, args))
			h.approve(p.ApprovalID, approverAdmin)
			before := len(h.st.Audit())

			withID := map[string]any{"approval_id": p.ApprovalID}
			for k, v := range args {
				withID[k] = v
			}
			res := h.call(cs, tool, withID)
			if res.IsError {
				t.Fatalf("approved call failed: %s", text(res))
			}
			if !h.changed(t, profiles, adapters) {
				t.Fatal("the approved call changed nothing")
			}
			if a, _ := h.st.Approval(p.ApprovalID); a.Status != store.ApprovalUsed {
				t.Fatalf("approval status = %s after use", a.Status)
			}

			rows := h.st.Audit()[before:]
			var used, action bool
			for _, e := range rows {
				if e.ApprovalID != p.ApprovalID || e.ApproverSerial != approverAdmin.Serial || e.Tool != tool || e.Via != "mcp" || e.KeyID == "" {
					t.Errorf("row without both identities: %+v", e)
					continue
				}
				switch e.Kind {
				case approval.KindUsed:
					used = true
				default:
					action = e.Outcome == "ok"
				}
			}
			if !used || !action {
				t.Fatalf("want an approval-used row and the action's row, got %+v", rows)
			}

			// The same approval cannot run the call again.
			if res := h.call(cs, tool, withID); !res.IsError || !strings.Contains(text(res), "1013") {
				t.Fatalf("replay = %q (error %v)", text(res), res.IsError)
			}
		})
	}
}

func TestStepUp_RefusesAnUnusableApproval(t *testing.T) {
	revoke := stepUpCalls["cert_revoke"]
	cases := []struct {
		name  string
		setup func(h *harness, id string) (args map[string]any, otherKey bool)
		code  string
	}{
		{name: "not decided yet", code: "1011", setup: func(_ *harness, id string) (map[string]any, bool) {
			return map[string]any{"node": "pki-issuing", "serial_hex": "0A1B", "reason_code": 1, "approval_id": id}, false
		}},
		{name: "denied", code: "1013", setup: func(h *harness, id string) (map[string]any, bool) {
			if _, err := h.approvals.Decide(context.Background(), approverAdmin, id, false); err != nil {
				h.t.Fatal(err)
			}
			return map[string]any{"node": "pki-issuing", "serial_hex": "0A1B", "reason_code": 1, "approval_id": id}, false
		}},
		{name: "digest mismatch", code: "1012", setup: func(h *harness, id string) (map[string]any, bool) {
			h.approve(id, approverOperator)
			return map[string]any{"node": "pki-issuing", "serial_hex": "FFFF", "reason_code": 1, "approval_id": id}, false
		}},
		{name: "another key", code: "1012", setup: func(h *harness, id string) (map[string]any, bool) {
			h.approve(id, approverOperator)
			return map[string]any{"node": "pki-issuing", "serial_hex": "0A1B", "reason_code": 1, "approval_id": id}, true
		}},
		{name: "expired", code: "1013", setup: func(h *harness, id string) (map[string]any, bool) {
			h.approve(id, approverOperator)
			h.advance(15 * time.Minute)
			return map[string]any{"node": "pki-issuing", "serial_hex": "0A1B", "reason_code": 1, "approval_id": id}, false
		}},
		{name: "unknown approval", code: "1008", setup: func(_ *harness, _ string) (map[string]any, bool) {
			return map[string]any{"node": "pki-issuing", "serial_hex": "0A1B", "reason_code": 1, "approval_id": "apr-missing"}, false
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			cs := h.session(h.key(authz.LevelOperator, ""))
			p := asPending(t, h.call(cs, "cert_revoke", revoke))
			args, other := tc.setup(h, p.ApprovalID)
			caller := cs
			if other {
				caller = h.session(h.key(authz.LevelOperator, ""))
			}

			res := h.call(caller, "cert_revoke", args)
			if !res.IsError || !strings.Contains(text(res), tc.code) {
				t.Fatalf("result = %q (error %v), want refusal %s", text(res), res.IsError, tc.code)
			}
			if h.nodes["pki-issuing"].changes() != 0 {
				t.Fatal("the node was asked to revoke")
			}
			if a, _ := h.st.Approval(p.ApprovalID); a.Status == store.ApprovalUsed {
				t.Fatal("a refused approval was marked used")
			}
			last := lastAudit(h.st)
			if last.Kind != "mcp-call" || last.Outcome != "denied" || last.Tool != "cert_revoke" || last.ApprovalID != args["approval_id"] {
				t.Fatalf("refusal audit = %+v", last)
			}
		})
	}
}

func TestStepUp_ApproverBelowTheRequiredLevelCannotApprove(t *testing.T) {
	h := newHarness(t)
	cs := h.session(h.key(authz.LevelAdmin, ""))
	p := asPending(t, h.call(cs, "profile_delete", stepUpCalls["profile_delete"]))

	if _, err := h.approvals.Decide(context.Background(), approverOperator, p.ApprovalID, true); err == nil {
		t.Fatal("an operator approved an admin-level request")
	}
	res := h.call(cs, "profile_delete", map[string]any{"name": "tls-server", "approval_id": p.ApprovalID})
	if !res.IsError || !strings.Contains(text(res), "1011") {
		t.Fatalf("result = %q (error %v)", text(res), res.IsError)
	}
	if _, ok := h.st.Profile("tls-server"); !ok {
		t.Fatal("the profile was deleted")
	}
}

func TestStepUp_KeyBelowTheToolMinimumRaisesNoApproval(t *testing.T) {
	h := newHarness(t)
	cs := h.session(h.key(authz.LevelAdmin, "operator"))

	res := h.call(cs, "profile_create", stepUpCalls["profile_create"])
	if !res.IsError {
		t.Fatalf("an operator-capped key raised an admin approval: %s", text(res))
	}
	if len(h.st.Approvals()) != 0 {
		t.Fatal("an approval was stored")
	}
	if last := lastAudit(h.st); last.Outcome != "denied" || last.Tool != "profile_create" {
		t.Fatalf("audit = %+v", last)
	}
}

func TestStepUp_KeyLevelIsCheckedLiveWhenTheApprovalIsUsed(t *testing.T) {
	h := newHarness(t)
	plain := h.key(authz.LevelAdmin, "")
	cs := h.session(plain)
	p := asPending(t, h.call(cs, "adapter_set_enabled", stepUpCalls["adapter_set_enabled"]))
	h.approve(p.ApprovalID, approverAdmin)

	// The key is capped below admin after the approval was raised.
	a, _ := h.st.Approval(p.ApprovalID)
	k, _ := h.st.McpKey(a.KeyID)
	k.LevelCeiling = "operator"
	h.st.AddMcpKey(k)

	res := h.call(cs, "adapter_set_enabled", map[string]any{"name": "acme-web", "enabled": true, "approval_id": p.ApprovalID})
	if !res.IsError {
		t.Fatalf("a key now below admin used an admin approval: %s", text(res))
	}
	if h.st.Adapters()[0].Enabled {
		t.Fatal("the adapter was enabled")
	}
}

func TestStepUp_InvalidArgumentsRaiseNoApproval(t *testing.T) {
	cases := map[string]struct {
		tool string
		args map[string]any
	}{
		"revoke on an unknown node":    {"cert_revoke", map[string]any{"node": "pki-missing", "serial_hex": "0A"}},
		"revoke with a bad reason":     {"cert_revoke", map[string]any{"node": "pki-issuing", "serial_hex": "0A", "reason_code": 7}},
		"create an existing profile":   {"profile_create", map[string]any{"profile": map[string]any{"name": "tls-server"}}},
		"create with an unknown field": {"profile_create", map[string]any{"profile": map[string]any{"name": "x", "bogus": 1}}},
		"update a missing profile":     {"profile_update", map[string]any{"profile": map[string]any{"name": "missing"}}},
		"delete a missing profile":     {"profile_delete", map[string]any{"name": "missing"}},
		"apply to an unknown node":     {"profile_apply_to_node", map[string]any{"profile": "tls-server", "node": "pki-missing"}},
		"enable an unknown adapter":    {"adapter_set_enabled", map[string]any{"name": "missing", "enabled": true}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			res := h.call(h.session(h.key(authz.LevelAdmin, "")), tc.tool, tc.args)
			if !res.IsError {
				t.Fatalf("result = %s", text(res))
			}
			if len(h.st.Approvals()) != 0 {
				t.Fatal("an approval was raised for an invalid request")
			}
		})
	}
}

func TestIssueFromCSR_StepUpCasesRaiseAnApproval(t *testing.T) {
	cases := map[string]map[string]any{
		"root node":            {"node": "pki-root", "profile": "tls-server"},
		"node reports root":    {"node": "pki-liar", "profile": "tls-server"},
		"CA profile":           {"node": "pki-issuing", "profile": "sub-ca"},
		"CSR asks for CA:TRUE": {"node": "pki-issuing", "profile": "tls-server", "ca_csr": true},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			cs := h.session(h.key(authz.LevelOperator, ""))
			_, isCA := args["ca_csr"]
			delete(args, "ca_csr")
			args["csr_pem"] = csrPEM(t, isCA)

			p := asPending(t, h.call(cs, "cert_issue_from_csr", args))
			for _, n := range h.nodes {
				if n.issuedCount() != 0 {
					t.Fatal("a node signed before approval")
				}
			}
			if a, _ := h.st.Approval(p.ApprovalID); a.RequiredLevel != "operator" || a.Tool != "cert_issue_from_csr" {
				t.Fatalf("approval = %+v", a)
			}

			h.approve(p.ApprovalID, approverOperator)
			args["approval_id"] = p.ApprovalID
			res := h.call(cs, "cert_issue_from_csr", args)
			if res.IsError || !strings.HasPrefix(text(res), "-----BEGIN CERTIFICATE-----") {
				t.Fatalf("approved issue = %q (error %v)", text(res), res.IsError)
			}
			if last := lastAudit(h.st); last.Kind != "issued" || last.ApprovalID != p.ApprovalID || last.ApproverSerial != approverOperator.Serial {
				t.Fatalf("issue audit = %+v", last)
			}
		})
	}
}

func TestApprovalStatus_ShowsOnlyTheKeysOwnApprovals(t *testing.T) {
	h := newHarness(t)
	mine := h.session(h.key(authz.LevelOperator, ""))
	p := asPending(t, h.call(mine, "cert_revoke", stepUpCalls["cert_revoke"]))

	res := h.call(mine, "approval_status", map[string]any{"approval_id": p.ApprovalID})
	if res.IsError || !strings.Contains(text(res), `"status":"pending"`) || !strings.Contains(text(res), p.ApprovalID) {
		t.Fatalf("own status = %q (error %v)", text(res), res.IsError)
	}
	h.approve(p.ApprovalID, approverOperator)
	if res := h.call(mine, "approval_status", map[string]any{"approval_id": p.ApprovalID}); !strings.Contains(text(res), `"status":"approved"`) {
		t.Fatalf("after approval = %q", text(res))
	}
	if res := h.call(mine, "approval_status", nil); res.IsError || !strings.Contains(text(res), p.ApprovalID) {
		t.Fatalf("own list = %q", text(res))
	}

	viewer := h.session(h.key(authz.LevelViewer, ""))
	if res := h.call(viewer, "approval_status", map[string]any{"approval_id": p.ApprovalID}); !res.IsError {
		t.Fatalf("another key saw the approval: %s", text(res))
	}
	if res := h.call(viewer, "approval_status", nil); res.IsError || strings.Contains(text(res), p.ApprovalID) {
		t.Fatalf("another key's list = %q", text(res))
	}
}

func TestApprovals_CannotBeListedOrDecidedOverMCP(t *testing.T) {
	h := newHarness(t)
	cs := h.session(h.key(authz.LevelAdmin, ""))
	p := asPending(t, h.call(cs, "cert_revoke", stepUpCalls["cert_revoke"]))

	for _, tool := range []string{"approval_decide", "approval_list"} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: map[string]any{"id": p.ApprovalID, "approve": true}})
		if err == nil && !res.IsError {
			t.Fatalf("%s ran over MCP: %s", tool, text(res))
		}
	}
	if a, _ := h.st.Approval(p.ApprovalID); a.Status != store.ApprovalPending {
		t.Fatalf("status = %s", a.Status)
	}
}
