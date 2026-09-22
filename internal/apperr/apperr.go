package apperr

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

	CodeUnauthenticated = 1001
	CodeForbidden       = 1002

	CodeNodeUnreachable = 1100
	CodeNodeNotFound    = 1101

	CodeProfileNotFound = 1200

	CodeIssuanceRefused = 1300

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
	{Code: CodeNodeUnreachable, Title: "Fleet", Cause: "the node could not be dialled or did not answer"},
	{Code: CodeNodeNotFound, Title: "Fleet", Cause: "no node of that name is in the inventory"},
	{Code: CodeProfileNotFound, Title: "Catalog", Cause: "no certificate profile of that name is known"},
	{Code: CodeIssuanceRefused, Title: "Certificates", Cause: "the issuing node refused to sign the request"},
	{Code: CodeOperatorCAUnconfigured, Title: "Operators", Cause: "no operator_ca_node is configured, so credentials cannot be issued or revoked"},
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
		apperr.WithMessageTemplate("The Fleet Manager refused this request (error {{.Code}}). Quote that code when reporting it."),
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
