// Package mcpserver serves the Fleet Manager's MCP tools. Each tool calls the
// matching FleetService handler in process, with the identity the MCP key
// resolved to, so the handlers' own level checks apply unchanged.
package mcpserver

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

import "github.com/CryptOS-PKI/manager/internal/authz"

// Policy says how a FleetService operation is exposed over MCP.
type Policy int

const (
	// Direct tools run immediately for a key at or above the minimum level.
	Direct Policy = iota
	// StepUp operations need a human approval outside the agent's reach: a
	// call raises the approval, and the operation runs only when the agent
	// calls again with the approved approval_id.
	StepUp
	// Excluded operations are never exposed over MCP.
	Excluded
)

func (p Policy) String() string {
	switch p {
	case Direct:
		return "direct"
	case StepUp:
		return "step-up"
	default:
		return "excluded"
	}
}

// Spec is one row of the tool policy table.
type Spec struct {
	Name     string
	RPC      string
	MinLevel authz.Level
	Policy   Policy
	// Reason explains why a non-direct operation is not a plain tool.
	Reason string
}

// Catalog is the complete policy table: every FleetService operation and how
// MCP treats it. Direct and StepUp rows are registered as tools; Excluded
// rows never are. It is enforced before dispatch, on top of each handler's
// own level check. cert_issue_from_csr is Direct but needs an approval for a
// CA certificate or the root node.
var Catalog = []Spec{
	{Name: "fleet_whoami", RPC: "WhoAmI", MinLevel: authz.LevelViewer, Policy: Direct},
	{Name: "fleet_list_nodes", RPC: "ListNodes", MinLevel: authz.LevelViewer, Policy: Direct},
	{Name: "fleet_get_node", RPC: "GetNode", MinLevel: authz.LevelViewer, Policy: Direct},
	{Name: "fleet_get_node_config", RPC: "GetNodeConfig", MinLevel: authz.LevelOperator, Policy: Direct},
	{Name: "cert_list", RPC: "ListCertificates", MinLevel: authz.LevelViewer, Policy: Direct},
	{Name: "cert_issue_from_csr", RPC: "IssueLeaf", MinLevel: authz.LevelOperator, Policy: Direct},
	{Name: "profile_list", RPC: "ListProfiles", MinLevel: authz.LevelViewer, Policy: Direct},
	{Name: "adapter_list", RPC: "ListAdapters", MinLevel: authz.LevelViewer, Policy: Direct},
	{Name: "audit_list", RPC: "ListAudit", MinLevel: authz.LevelViewer, Policy: Direct},
	{Name: "enrollment_list", RPC: "ListEnrollments", MinLevel: authz.LevelViewer, Policy: Direct},
	{Name: "enrollment_reject", RPC: "RejectEnrollment", MinLevel: authz.LevelOperator, Policy: Direct},
	{Name: "operator_credential_list", RPC: "ListOperatorCredentials", MinLevel: authz.LevelOperator, Policy: Direct},
	{Name: "approval_status", MinLevel: authz.LevelViewer, Policy: Direct},

	{Name: "cert_revoke", RPC: "RevokeCertificate", MinLevel: authz.LevelOperator, Policy: StepUp, Reason: "revocation is irreversible"},
	{Name: "profile_create", RPC: "CreateProfile", MinLevel: authz.LevelAdmin, Policy: StepUp, Reason: "changes what every node may issue"},
	{Name: "profile_update", RPC: "UpdateProfile", MinLevel: authz.LevelAdmin, Policy: StepUp, Reason: "changes what every node may issue"},
	{Name: "profile_delete", RPC: "DeleteProfile", MinLevel: authz.LevelAdmin, Policy: StepUp, Reason: "changes what every node may issue"},
	{Name: "profile_apply_to_node", RPC: "ApplyProfileToNode", MinLevel: authz.LevelAdmin, Policy: StepUp, Reason: "rewrites a node's configuration"},
	{Name: "adapter_set_enabled", RPC: "SetAdapterEnabled", MinLevel: authz.LevelAdmin, Policy: StepUp, Reason: "opens or closes an enrollment protocol"},

	{Name: "export_ca_key", RPC: "ExportCAKey", Policy: Excluded, Reason: "CA key material"},
	{Name: "import_ca_key", RPC: "ImportCAKey", Policy: Excluded, Reason: "CA key material"},
	{Name: "decommission_node", RPC: "DecommissionNode", Policy: Excluded, Reason: "wipes a node"},
	{Name: "rename_node", RPC: "RenameNode", Policy: Excluded, Reason: "changes the name people and configs use for a node"},
	{Name: "adopt_node", RPC: "AdoptNode", Policy: Excluded, Reason: "wipes and provisions a disk"},
	{Name: "preview_adoption", RPC: "PreviewAdoption", Policy: Excluded, Reason: "part of disk provisioning"},
	{Name: "list_install_disks", RPC: "ListInstallDisks", Policy: Excluded, Reason: "part of disk provisioning"},
	{Name: "apply_node_config", RPC: "ApplyNodeConfig", Policy: Excluded, Reason: "replaces a node's network, revocation and trust configuration"},
	{Name: "rekey_node", RPC: "RekeyNode", Policy: Excluded, Reason: "rotates a CA key"},
	{Name: "enrollment_create", RPC: "CreateEnrollment", Policy: Excluded, Reason: "carries node admin credentials"},
	{Name: "enrollment_approve", RPC: "ApproveEnrollment", Policy: Excluded, Reason: "signs a subordinate CA or links a node"},
	{Name: "operator_credential_issue", RPC: "IssueOperatorCredential", Policy: Excluded, Reason: "an agent must never mint operator certificates"},
	{Name: "operator_credential_revoke", RPC: "RevokeOperatorCredential", Policy: Excluded, Reason: "operator certificates are managed by people"},
	{Name: "mcp_key_create", RPC: "CreateMcpKey", Policy: Excluded, Reason: "keys are never managed with a key"},
	{Name: "mcp_key_list", RPC: "ListMcpKeys", Policy: Excluded, Reason: "keys are never managed with a key"},
	{Name: "mcp_key_revoke", RPC: "RevokeMcpKey", Policy: Excluded, Reason: "keys are never managed with a key"},
	{Name: "approval_list", RPC: "ListApprovals", Policy: Excluded, Reason: "approvals are decided by people, outside the agent's reach"},
	{Name: "approval_decide", RPC: "DecideApproval", Policy: Excluded, Reason: "an agent must never approve its own requests"},
}

func spec(name string) Spec {
	for _, s := range Catalog {
		if s.Name == name {
			return s
		}
	}
	panic("mcpserver: no catalog entry for tool " + name)
}
