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

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/approval"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/fleet"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
)

type tools struct {
	svc       *fleet.Service
	st        store.Store
	approvals *approval.Service
	publicURL string
}

type noArgs struct{}

type nodeArg struct {
	Node string `json:"node" jsonschema:"the node's inventory name"`
}

type certListArgs struct {
	Node string `json:"node,omitempty" jsonschema:"limit the list to this node; empty lists every node"`
}

type getNodeArgs struct {
	Name string `json:"name" jsonschema:"the node's inventory name"`
}

type rejectArgs struct {
	ID     string `json:"id" jsonschema:"the enrollment request id"`
	Reason string `json:"reason" jsonschema:"why the request is rejected; shown to operators"`
}

type issueArgs struct {
	Node       string `json:"node" jsonschema:"the node that signs the certificate"`
	Profile    string `json:"profile" jsonschema:"an issuance profile configured on that node"`
	CSRPEM     string `json:"csr_pem" jsonschema:"a PEM-encoded PKCS#10 certificate request; generate the key locally, it never leaves the agent"`
	ApprovalID string `json:"approval_id,omitempty" jsonschema:"leave empty on the first call; if the call returns pending_approval, call again with the same arguments plus the approval_id once a person has approved it"`
}

func (a issueArgs) approvalID() string { return a.ApprovalID }

type approvalStatusArgs struct {
	ApprovalID string `json:"approval_id,omitempty" jsonschema:"the approval to show; empty lists every approval this key raised"`
}

func registerTools(s *mcp.Server, t *tools) {
	add(s, t, "fleet_whoami", "Show the operator this key acts as and its effective access level.", false,
		func(ctx context.Context, _ noArgs) (string, error) {
			return call(ctx, t.svc.WhoAmI, &fleetv1.WhoAmIRequest{})
		})
	add(s, t, "fleet_list_nodes", "List every CA node in the fleet with its role and health.", false,
		func(ctx context.Context, _ noArgs) (string, error) {
			return call(ctx, t.svc.ListNodes, &fleetv1.ListNodesRequest{})
		})
	add(s, t, "fleet_get_node", "Show one CA node's detail, including its certificate chain.", false,
		func(ctx context.Context, in getNodeArgs) (string, error) {
			return call(ctx, t.svc.GetNode, &fleetv1.GetNodeRequest{Name: in.Name})
		})
	add(s, t, "fleet_get_node_config", "Read a node's full machine configuration (read-only).", false,
		func(ctx context.Context, in nodeArg) (string, error) {
			return call(ctx, t.svc.GetNodeConfig, &fleetv1.GetNodeConfigRequest{NodeName: in.Node})
		})
	add(s, t, "cert_list", "List issued and revoked certificates across the fleet or on one node.", false,
		func(ctx context.Context, in certListArgs) (string, error) {
			return call(ctx, t.svc.ListCertificates, &fleetv1.ListCertificatesRequest{Node: in.Node})
		})
	addGated(s, t, "cert_issue_from_csr",
		"Issue a certificate from a CSR. An end-entity certificate on an intermediate or issuing node under a non-CA profile "+
			"is issued at once. A CA profile, a CSR asking for CA:TRUE, or the root node needs a person's approval first: "+
			"the call returns pending_approval with a link to show them. Returns the certificate as PEM.",
		t.issueFromCSR)
	add(s, t, "profile_list", "List the certificate issuance profiles in the catalog.", false,
		func(ctx context.Context, _ noArgs) (string, error) {
			return call(ctx, t.svc.ListProfiles, &fleetv1.ListProfilesRequest{})
		})
	add(s, t, "adapter_list", "List the enrollment protocol adapters (ACME, SCEP, EST, ...) and whether each is enabled.", false,
		func(ctx context.Context, _ noArgs) (string, error) {
			return call(ctx, t.svc.ListAdapters, &fleetv1.ListAdaptersRequest{})
		})
	add(s, t, "audit_list", "List the hash-chained audit log.", false,
		func(ctx context.Context, _ noArgs) (string, error) {
			return call(ctx, t.svc.ListAudit, &fleetv1.ListAuditRequest{})
		})
	add(s, t, "enrollment_list", "List node enrollment requests and their status.", false,
		func(ctx context.Context, _ noArgs) (string, error) {
			return call(ctx, t.svc.ListEnrollments, &fleetv1.ListEnrollmentsRequest{})
		})
	add(s, t, "enrollment_reject", "Reject a pending node enrollment request.", true,
		func(ctx context.Context, in rejectArgs) (string, error) {
			return call(ctx, t.svc.RejectEnrollment, &fleetv1.RejectEnrollmentRequest{Id: in.ID, Reason: in.Reason})
		})
	add(s, t, "operator_credential_list", "List the operator certificates the manager has issued.", false,
		func(ctx context.Context, _ noArgs) (string, error) {
			return call(ctx, t.svc.ListOperatorCredentials, &fleetv1.ListOperatorCredentialsRequest{})
		})
	add(s, t, "approval_status", "Show the status of an approval this key raised (pending, approved, denied, expired or used), or list them all.", false,
		t.approvalStatus)

	registerStepUpTools(s, t)
}

// approvalStatus shows the caller's own approvals only: another key's
// approval is reported as missing.
func (t *tools) approvalStatus(ctx context.Context, in approvalStatusArgs) (string, error) {
	id, _ := authz.FromContext(ctx) // the MCP wrapper always sets it
	if in.ApprovalID == "" {
		items := make([]*fleetv1.Approval, 0)
		for _, a := range t.approvals.ForKey(id.KeyID) {
			items = append(items, approval.ToProto(a))
		}
		return render(&fleetv1.ListApprovalsResponse{Items: items})
	}
	a, ok := t.approvals.Get(in.ApprovalID)
	if !ok || a.KeyID != id.KeyID {
		return "", refuse(apperr.CodeApprovalNotFound, "no approval %q raised by this key", in.ApprovalID)
	}
	return render(approval.ToProto(a))
}

// call dispatches to a FleetService handler in process and renders its
// response.
func call[Req, Resp any](ctx context.Context, h func(context.Context, *connect.Request[Req]) (*connect.Response[Resp], error), req *Req) (string, error) {
	resp, err := h(ctx, connect.NewRequest(req))
	if err != nil {
		return "", err
	}
	return render(any(resp.Msg).(proto.Message))
}

// directIssuerRoles are the node roles on which an agent may issue without
// approval. The root is deliberately absent.
var directIssuerRoles = map[string]bool{"intermediate": true, "issuing": true}

var oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

// issueFromCSR issues a non-CA leaf on an intermediate or issuing node at
// once. A CSR asking for CA:TRUE, a CA profile or a root node needs a step-up
// approval. The node's own configuration is authoritative for its role and
// the profile, so both the inventory and the node are checked, and the
// request is fully validated before an approval is raised.
func (t *tools) issueFromCSR(ctx context.Context, in issueArgs, g *gate) (string, error) {
	block, _ := pem.Decode([]byte(in.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", invalid("csr_pem is not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", invalid("csr_pem does not parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", invalid("csr_pem signature does not verify: %v", err)
	}

	var needs []string
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidBasicConstraints) && requestsCA(ext.Value) {
			needs = append(needs, "the CSR asks for a CA certificate")
		}
	}

	node, ok := t.st.Node(in.Node)
	if !ok {
		return "", refuse(apperr.CodeNodeNotFound, "no node named %q", in.Node)
	}
	if !directIssuerRoles[strings.ToLower(node.Role)] {
		needs = append(needs, fmt.Sprintf("the inventory lists %q as a %s node", in.Node, node.Role))
	}

	cfgResp, err := t.svc.GetNodeConfig(ctx, connect.NewRequest(&fleetv1.GetNodeConfigRequest{NodeName: in.Node}))
	if err != nil {
		return "", err
	}
	cfg := cfgResp.Msg.GetConfig()
	role := cfg.GetRole().GetKind()
	if !directIssuerRoles[strings.ToLower(role)] {
		needs = append(needs, fmt.Sprintf("node %q reports role %q", in.Node, role))
	}
	var found bool
	for _, p := range cfg.GetPki().GetProfiles() {
		if p.GetName() != in.Profile {
			continue
		}
		found = true
		if p.GetBasicConstraints().GetIsCa() {
			needs = append(needs, fmt.Sprintf("profile %q issues CA certificates", in.Profile))
		}
	}
	if !found {
		return "", refuse(apperr.CodeProfileNotFound, "node %q has no profile named %q", in.Node, in.Profile)
	}

	if len(needs) > 0 {
		summary := fmt.Sprintf("Issue a certificate for %s on node %q (role %s) under profile %q. Needs approval because %s.",
			csrSubject(csr), in.Node, role, in.Profile, strings.Join(needs, "; "))
		if ctx, err = g.require(ctx, summary); err != nil {
			return "", err
		}
	}

	resp, err := t.svc.IssueLeaf(ctx, connect.NewRequest(&fleetv1.IssueLeafRequest{
		NodeName: in.Node, CsrDer: block.Bytes, ProfileName: in.Profile,
	}))
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: resp.Msg.GetCertDer()})), nil
}

// csrSubject names what a CSR asks to be certified, for an approval summary.
func csrSubject(csr *x509.CertificateRequest) string {
	out := fmt.Sprintf("subject %q", csr.Subject.String())
	if len(csr.DNSNames) > 0 {
		out += fmt.Sprintf(" (DNS names %s)", strings.Join(csr.DNSNames, ", "))
	}
	return out
}

// requestsCA reports whether a basicConstraints extension value asks for
// cA=TRUE. An unparseable value is treated as a CA request.
func requestsCA(value []byte) bool {
	var bc struct {
		IsCA bool `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(value, &bc); err != nil {
		return true
	}
	return bc.IsCA
}
