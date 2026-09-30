package apperr

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

// Package apperr gives the manager's web-facing failures stable, reportable
// numeric codes (#64).
//
// Before this, almost every failure reaching the web layer was an unstructured
// string: the UI had nothing to branch on except message text, and an operator
// filing a report had no code to quote. Diagnosing an alpha report started with
// working out which error was even meant.
//
// The codes are a manager-owned namespace. go-apperr's WithService convention
// reserves the first digit per service, and the manager takes **1**, so every
// code here is 1xxx and is attributable at a glance. Another service taking
// codes later picks its own digit rather than coordinating a shared registry.
//
// Ranges within the manager's block, so a new code lands somewhere predictable:
//
//	1000-1099  authorization and identity
//	1100-1199  fleet inventory and node reachability
//	1200-1299  catalog: profiles, adapters
//	1300-1399  certificates and issuance
//	1400-1499  operator credentials
//	1500-1599  configuration and apply
//	1900-1999  unclassified, including the catch-all
//
// A failure with no registered code still reaches the client as CodeUnknown
// (1900) rather than as prose, so the UI always has something to show and a
// report always has something to quote.

import (
	"fmt"

	apperr "github.com/Bugs5382/go-apperr"
)

// Codes the web-facing surface returns. Each one is a promise: the number is
// stable, so an operator's report from six months ago still means this.
const (
	// CodeUnknown is the default for a failure nobody has classified yet.
	CodeUnknown = 1900

	CodeUnauthenticated   = 1001
	CodeForbidden         = 1002
	CodeMcpKeyNeedsCert   = 1003
	CodeMcpDisabled       = 1004
	CodeMcpKeyNotFound    = 1005
	CodeMcpCeilingTooHigh = 1006

	CodeApprovalNeedsCert     = 1007
	CodeApprovalNotFound      = 1008
	CodeApprovalNotPending    = 1009
	CodeApproverLevelTooLow   = 1010
	CodeApprovalAwaiting      = 1011
	CodeApprovalMismatch      = 1012
	CodeApprovalUnusable      = 1013
	CodeApprovalStatusInvalid = 1014

	CodeNodeUnreachable   = 1100
	CodeNodeNotFound      = 1101
	CodeNodeNameTaken     = 1102
	CodeNodeNameInvalid   = 1103
	CodeNodeRefMismatch   = 1104
	CodeNodeRenameRefused = 1105

	CodeProfileNotFound = 1200

	CodeIssuanceRefused       = 1300
	CodeIssuanceNeedsApproval = 1301
	CodeCertificateNotFound   = 1302

	CodeOperatorCAUnconfigured = 1400
	CodeOperatorNotFound       = 1401

	CodeConfigRejected = 1500
)

// entries carry the internal description and the area label. Neither is ever
// shown to a client -- they exist so Markdown() can generate the code table an
// operator or a maintainer reads.
var entries = []apperr.Entry{
	{Code: CodeUnknown, Title: "Unclassified", Cause: "a failure with no registered code"},
	{Code: CodeUnauthenticated, Title: "Authorization", Cause: "no verified client certificate was presented"},
	{Code: CodeForbidden, Title: "Authorization", Cause: "the certificate lacks the access level the call needs"},
	{Code: CodeMcpKeyNeedsCert, Title: "Authorization", Cause: "MCP keys are managed only with an operator client certificate, never with an MCP key"},
	{Code: CodeMcpDisabled, Title: "Authorization", Cause: "the MCP endpoint is disabled (mcp.enabled is false), so no MCP key can be created"},
	{Code: CodeMcpKeyNotFound, Title: "Authorization", Cause: "no MCP key with that id exists"},
	{Code: CodeMcpCeilingTooHigh, Title: "Authorization", Cause: "the requested level ceiling is not viewer, operator or admin, or is above the operator's own level"},
	{Code: CodeApprovalNeedsCert, Title: "Authorization", Cause: "step-up approvals are listed and decided only with an operator client certificate, never with an MCP key"},
	{Code: CodeApprovalNotFound, Title: "Authorization", Cause: "no step-up approval with that id exists"},
	{Code: CodeApprovalNotPending, Title: "Authorization", Cause: "the approval was already decided or has expired, so it cannot be decided"},
	{Code: CodeApproverLevelTooLow, Title: "Authorization", Cause: "the approver's level is below the level the approved operation needs"},
	{Code: CodeApprovalAwaiting, Title: "Authorization", Cause: "over MCP, the approval has not been decided yet; poll approval_status and call again once it is approved"},
	{Code: CodeApprovalMismatch, Title: "Authorization", Cause: "over MCP, the approval was raised for a different tool, different arguments or a different key"},
	{Code: CodeApprovalUnusable, Title: "Authorization", Cause: "over MCP, the approval was denied, has expired or was already used; call the tool without approval_id to request a new one"},
	{Code: CodeApprovalStatusInvalid, Title: "Authorization", Cause: "the approval status filter is not pending, approved, denied, expired or used"},
	{Code: CodeNodeUnreachable, Title: "Fleet", Cause: "the node could not be dialled or did not answer"},
	{Code: CodeNodeNotFound, Title: "Fleet", Cause: "no node with that name or ID is in the inventory"},
	{Code: CodeNodeNameTaken, Title: "Fleet", Cause: "another node already has that name"},
	{Code: CodeNodeNameInvalid, Title: "Fleet", Cause: "the node name is not an RFC 1123 label (1 to 63 lowercase letters, digits and hyphens, starting and ending with a letter or digit), or has the form of a node ID"},
	{Code: CodeNodeRefMismatch, Title: "Fleet", Cause: "the request's node_id and node name point at different nodes; send node_id alone"},
	{Code: CodeNodeRenameRefused, Title: "Fleet", Cause: "the node is the configured operator_ca_node, which the manager finds by name, so renaming it would cut off operator credentials"},
	{Code: CodeProfileNotFound, Title: "Catalog", Cause: "no certificate profile of that name is known"},
	{Code: CodeIssuanceRefused, Title: "Certificates", Cause: "the issuing node refused to sign the request"},
	{Code: CodeIssuanceNeedsApproval, Title: "Certificates", Cause: "the request needs human step-up approval (a CA profile or the root node)"},
	{Code: CodeCertificateNotFound, Title: "Certificates", Cause: "the node has no issued certificate with that serial"},
	{Code: CodeOperatorCAUnconfigured, Title: "Operators", Cause: "no operator_ca_node is configured, so operator credentials cannot be listed, issued or revoked, and operator-cert revocation is not enforced"},
	{Code: CodeOperatorNotFound, Title: "Operators", Cause: "no operator credential with that serial is recorded"},
	{Code: CodeConfigRejected, Title: "Configuration", Cause: "the node rejected the configuration as invalid"},
}

// registry is built once at package init. A malformed entry set is a
// programming error -- a duplicate or out-of-block code -- so it panics rather
// than starting a manager that cannot describe its own failures.
var registry = func() *apperr.Registry {
	r, err := apperr.NewRegistry(entries,
		apperr.WithService(1),
		// The client sees the code and this sentence, never the internal cause.
		// It says where to look rather than apologising.
		apperr.WithMessageTemplate("The Fleet Manager refused this request (error %d). Quote that code when reporting it."),
	)
	if err != nil {
		panic(fmt.Sprintf("apperr: building the code registry: %v", err))
	}

	return r
}()

// Registry exposes the built registry for the boundary and for the code-table
// generator.
func Registry() *apperr.Registry { return registry }

// Coded tags cause with a code, leaving the error chain intact so errors.Is and
// errors.As keep working through it.
func Coded(code int, cause error) error { return apperr.Coded(code, cause) }

// Code recovers the nearest code from an error chain.
func Code(err error) (int, bool) { return apperr.Code(err) }

// Doc renders the error-code table that docs/error-codes.md holds. It is
// generated rather than hand-maintained so a new code cannot be added without
// the table following it -- the point of a stable code is that an operator can
// look it up.
func Doc() string {
	return "<!-- Generated by `go run ./tools/errorcodes`. Do not edit by hand. -->\n\n" +
		"# Manager error codes\n\n" +
		"Every failure leaving the web-facing API carries one of these numbers, on the\n" +
		"`" + MetadataKey + "` error metadata and quoted in the message an operator sees.\n" +
		"The manager owns the 1000-1999 block; another service takes its own first digit.\n\n" +
		registry.Markdown()
}
