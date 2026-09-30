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
	"encoding/pem"
	"sort"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
)

var registeredTools = []string{
	"adapter_list", "adapter_set_enabled", "approval_status", "audit_list", "cert_issue_from_csr", "cert_list", "cert_revoke",
	"enrollment_list", "enrollment_reject", "fleet_get_node", "fleet_get_node_config", "fleet_list_nodes", "fleet_whoami",
	"operator_credential_list", "profile_apply_to_node", "profile_create", "profile_delete", "profile_list", "profile_update",
}

func TestListTools_RegistersDirectAndStepUpToolsOnly(t *testing.T) {
	h := newHarness(t)
	res, err := h.session(h.key(authz.LevelAdmin, "")).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var got []string
	for _, tool := range res.Tools {
		got = append(got, tool.Name)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(registeredTools, ",") {
		t.Fatalf("tools = %v, want %v", got, registeredTools)
	}

	present := map[string]bool{}
	for _, name := range got {
		present[name] = true
	}
	for _, spec := range Catalog {
		if spec.Policy == Excluded && present[spec.Name] {
			t.Errorf("%s is excluded but registered", spec.Name)
		}
		if spec.Policy != Excluded && !present[spec.Name] {
			t.Errorf("%s (policy %v) is not registered", spec.Name, spec.Policy)
		}
	}
	for _, never := range []string{
		"export_ca_key", "import_ca_key", "decommission_node", "adopt_node", "apply_node_config", "rekey_node",
		"enrollment_create", "enrollment_approve", "operator_credential_issue", "operator_credential_revoke",
		"mcp_key_create", "mcp_key_list", "mcp_key_revoke", "approval_list", "approval_decide",
	} {
		if present[never] {
			t.Errorf("excluded tool %s is registered", never)
		}
	}
}

func TestCatalog_ExcludedAndStepUpToolsAreListedWithAReason(t *testing.T) {
	for _, spec := range Catalog {
		if spec.Policy != Direct && spec.Reason == "" {
			t.Errorf("%s has policy %v but no reason", spec.Name, spec.Policy)
		}
	}
}

func TestWhoAmI_ReportsTheKeysEffectiveLevel(t *testing.T) {
	h := newHarness(t)
	res := h.call(h.session(h.key(authz.LevelAdmin, "viewer")), "fleet_whoami", nil)
	if res.IsError || !strings.Contains(text(res), `"level":"viewer"`) {
		t.Fatalf("whoami = %s (error %v)", text(res), res.IsError)
	}
}

func TestPolicy_LevelBelowToolMinimumIsDeniedAndAudited(t *testing.T) {
	h := newHarness(t)
	cs := h.session(h.key(authz.LevelAdmin, "viewer"))

	res := h.call(cs, "cert_issue_from_csr", map[string]any{"node": "pki-issuing", "profile": "tls-server", "csr_pem": csrPEM(t, false)})
	if !res.IsError {
		t.Fatalf("viewer-capped key issued a certificate: %s", text(res))
	}
	if h.nodes["pki-issuing"].issuedCount() != 0 {
		t.Fatal("the node was asked to sign")
	}
	last := lastAudit(h.st)
	if last.Tool != "cert_issue_from_csr" || last.Outcome != "denied" || last.Via != "mcp" || last.ActorKind != "mcp_key" {
		t.Fatalf("audit = %+v", last)
	}
}

func TestReads_AreAuditedWithTheTool(t *testing.T) {
	h := newHarness(t)
	cs := h.session(h.key(authz.LevelViewer, ""))
	before := len(h.st.Audit())

	if res := h.call(cs, "cert_list", nil); res.IsError {
		t.Fatalf("cert_list: %s", text(res))
	}
	rows := h.st.Audit()[before:]
	var found bool
	for _, e := range rows {
		if e.Kind == "mcp-call" && e.Tool == "cert_list" && e.Outcome == "ok" && e.KeyID != "" && e.RequestDigest != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audited read among %+v", rows)
	}
}

func TestIssueFromCSR_DirectLeafOnAnIssuingNode(t *testing.T) {
	h := newHarness(t)
	cs := h.session(h.key(authz.LevelOperator, ""))

	res := h.call(cs, "cert_issue_from_csr", map[string]any{"node": "pki-issuing", "profile": "tls-server", "csr_pem": csrPEM(t, false)})
	if res.IsError {
		t.Fatalf("issue: %s", text(res))
	}
	block, _ := pem.Decode([]byte(text(res)))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("result is not a PEM certificate: %q", text(res))
	}
	last := lastAudit(h.st)
	if last.Kind != "issued" || last.Tool != "cert_issue_from_csr" || last.Via != "mcp" || last.KeyID == "" || last.ActorSerial == "" {
		t.Fatalf("issue audit row = %+v", last)
	}
}

func TestIssueFromCSR_Refusals(t *testing.T) {
	cases := map[string]map[string]any{
		"profile unknown to node":         {"node": "pki-issuing", "profile": "nope"},
		"unknown node":                    {"node": "pki-missing", "profile": "tls-server"},
		"unknown node with a CA:TRUE CSR": {"node": "pki-missing", "profile": "tls-server", "ca_csr": true},
		"not a CSR":                       {"node": "pki-issuing", "profile": "tls-server", "csr_pem": "junk"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			cs := h.session(h.key(authz.LevelAdmin, ""))
			if _, ok := args["csr_pem"]; !ok {
				_, isCA := args["ca_csr"]
				args["csr_pem"] = csrPEM(t, isCA)
			}
			delete(args, "ca_csr")

			res := h.call(cs, "cert_issue_from_csr", args)
			if !res.IsError {
				t.Fatalf("issued: %s", text(res))
			}
			for _, n := range h.nodes {
				if n.issuedCount() != 0 {
					t.Fatal("a node was asked to sign")
				}
			}
			if last := lastAudit(h.st); last.Tool != "cert_issue_from_csr" || last.Outcome == "ok" {
				t.Fatalf("refusal audit = %+v", last)
			}
		})
	}
}

func lastAudit(st store.Store) store.AuditEvent {
	all := st.Audit()
	return all[len(all)-1]
}
