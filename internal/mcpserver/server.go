package mcpserver

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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	connect "connectrpc.com/connect"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/approval"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/fleet"
	"github.com/CryptOS-PKI/cryptos-manager/internal/mcpauth"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// maxRequestBodyBytes caps one MCP POST. The largest legitimate call is a
// CSR, which is a few kilobytes.
const maxRequestBodyBytes = 1 << 20

// Handler returns the stateless Streamable HTTP handler that serves the MCP
// tools. It must sit behind mcpauth.Middleware, which supplies the identity
// every tool acts as. publicURL is the origin approve links point at.
func Handler(svc *fleet.Service, st store.Store, approvals *approval.Service, publicURL, version string) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "fleetos", Title: "FleetOS Fleet Manager", Version: version}, nil)
	registerTools(server, &tools{svc: svc, st: st, approvals: approvals, publicURL: publicURL})

	return mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, MaxRequestBodyBytes: maxRequestBodyBytes},
	)
}

// refusal is an MCP-side refusal whose message is safe to show the agent.
// approvalID names the approval the refused call presented, for the audit.
type refusal struct {
	code       int
	outcome    string
	msg        string
	approvalID string
}

func (r *refusal) Error() string { return r.msg }

func refuse(code int, format string, args ...any) error {
	return &refusal{code: code, outcome: auditlog.OutcomeDenied, msg: fmt.Sprintf(format, args...)}
}

func invalid(format string, args ...any) error {
	return &refusal{code: apperr.CodeUnknown, outcome: auditlog.OutcomeError, msg: fmt.Sprintf(format, args...)}
}

// approvalRef is implemented by the arguments of every tool that can run
// under a step-up approval.
type approvalRef interface {
	approvalID() string
}

// gate is handed to a tool that may need a step-up approval. The tool calls
// require immediately before the operation the approval covers.
type gate struct {
	t      *tools
	id     authz.Identity
	sp     Spec
	digest string
	ref    string
}

// pendingApproval stops a call that raised an approval; the agent gets the
// approval to show a person instead of a result.
type pendingApproval struct {
	result pendingResult
}

func (p *pendingApproval) Error() string { return "pending approval " + p.result.ApprovalID }

// pendingResult is what a step-up call returns instead of running.
type pendingResult struct {
	Status     string `json:"status"`
	ApprovalID string `json:"approval_id"`
	ApproveURL string `json:"approve_url"`
	Summary    string `json:"summary"`
	ExpiresAt  string `json:"expires_at"`
}

// require lets the call proceed only under a usable approval. Without an
// approval_id it raises one for exactly this request and stops the call.
// With one, it consumes the approval and returns ctx stamped with it, so the
// operation's own audit row names the approval and its approver.
func (g *gate) require(ctx context.Context, summary string) (context.Context, error) {
	if g.ref == "" {
		a := g.t.approvals.Request(ctx, g.id, g.sp.Name, g.digest, summary, g.sp.MinLevel)
		log.Printf("mcpserver: %s by key %s needs approval %s", g.sp.Name, g.id.KeyID, a.ID)
		return ctx, &pendingApproval{result: pendingResult{
			Status:     "pending_approval",
			ApprovalID: a.ID,
			ApproveURL: g.t.publicURL + "/approvals?id=" + url.QueryEscape(a.ID),
			Summary:    summary,
			ExpiresAt:  a.ExpiresAt.UTC().Format(time.RFC3339),
		}}
	}

	a, err := g.t.approvals.Use(ctx, g.id, g.ref, g.sp.Name, g.digest, g.sp.MinLevel)
	if err != nil {
		r := approvalRefusal(err)
		r.approvalID = g.ref
		return ctx, r
	}
	log.Printf("mcpserver: %s by key %s runs under approval %s approved by %s", g.sp.Name, g.id.KeyID, a.ID, a.DecidedBySerial)
	return auditlog.WithCall(ctx, auditlog.Call{
		Tool: g.sp.Name, RequestDigest: g.digest, ApprovalID: a.ID, ApproverSerial: a.DecidedBySerial,
	}), nil
}

func approvalRefusal(err error) *refusal {
	r := func(code int, msg string) *refusal {
		return &refusal{code: code, outcome: auditlog.OutcomeDenied, msg: msg}
	}
	switch {
	case errors.Is(err, approval.ErrNotFound):
		return r(apperr.CodeApprovalNotFound, "no approval with that id exists")
	case errors.Is(err, approval.ErrMismatch):
		return r(apperr.CodeApprovalMismatch, "the approval was raised for a different tool, different arguments or a different key; call again with the exact arguments that raised it")
	case errors.Is(err, approval.ErrAwaiting):
		return r(apperr.CodeApprovalAwaiting, "the approval has not been decided yet; poll approval_status and call again once it is approved")
	case errors.Is(err, approval.ErrDenied):
		return r(apperr.CodeApprovalUnusable, "the approval was denied")
	case errors.Is(err, approval.ErrExpired):
		return r(apperr.CodeApprovalUnusable, "the approval has expired; call without approval_id to request a new one")
	case errors.Is(err, approval.ErrUsed):
		return r(apperr.CodeApprovalUnusable, "the approval was already used; call without approval_id to request a new one")
	case errors.Is(err, approval.ErrApproverLevel):
		return r(apperr.CodeApproverLevelTooLow, "the approver's level is below what this tool needs")
	case errors.Is(err, approval.ErrKeyLevel):
		return r(apperr.CodeForbidden, "this key no longer has the level the tool needs")
	default:
		return r(apperr.CodeUnknown, "the approval could not be checked")
	}
}

// add registers a Direct tool.
func add[In any](s *mcp.Server, t *tools, name, description string, handlerAudits bool, run func(context.Context, In) (string, error)) {
	if spec(name).Policy != Direct {
		panic("mcpserver: " + name + " is not a direct tool")
	}
	register(s, t, name, description, handlerAudits, func(ctx context.Context, in In, _ *gate) (string, error) {
		return run(ctx, in)
	})
}

// addGated registers a Direct tool that needs a step-up approval in some
// cases. run decides, and calls the gate before the operation in those
// cases.
func addGated[In approvalRef](s *mcp.Server, t *tools, name, description string, run func(context.Context, In, *gate) (string, error)) {
	if spec(name).Policy != Direct {
		panic("mcpserver: " + name + " is not a direct tool")
	}
	register(s, t, name, description, true, run)
}

// addStepUp registers a StepUp tool. On the first call summarize validates
// the arguments and describes exactly what the call will do, and an approval
// is raised for it. On the call that presents an approval_id, the approval
// is judged first: the arguments were validated when it was raised and the
// digest proves they are unchanged. Either way run is reached only after the
// gate has consumed an approval.
func addStepUp[In approvalRef](s *mcp.Server, t *tools, name, description string, summarize, run func(context.Context, In) (string, error)) {
	if spec(name).Policy != StepUp {
		panic("mcpserver: " + name + " is not a step-up tool")
	}
	register(s, t, name, description, true, func(ctx context.Context, in In, g *gate) (string, error) {
		var summary string
		if g.ref == "" {
			var err error
			if summary, err = summarize(ctx, in); err != nil {
				return "", err
			}
		}
		ctx, err := g.require(ctx, summary)
		if err != nil {
			return "", err
		}
		return run(ctx, in)
	})
}

// register wires one tool. Every call is checked against the tool's
// minimum level before it runs, and audited: a read or a failed call gets an
// "mcp-call" row here, a raised approval gets its own pending row, and a
// successful write is audited by the handler it dispatched to
// (handlerAudits), stamped with the same key and tool.
func register[In any](s *mcp.Server, t *tools, name, description string, handlerAudits bool, run func(context.Context, In, *gate) (string, error)) {
	sp := spec(name)

	mcp.AddTool(s, &mcp.Tool{Name: name, Description: description},
		func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
			id, ok := mcpauth.IdentityFromTokenInfo(req.Extra.TokenInfo)
			if !ok {
				return nil, nil, errors.New("no MCP identity on the request")
			}
			var ref string
			if r, ok := any(in).(approvalRef); ok {
				ref = r.approvalID()
			}
			dig := digest(name, in)
			ctx = auditlog.WithCall(authz.NewContext(ctx, id), auditlog.Call{Tool: name, RequestDigest: dig})
			g := &gate{t: t, id: id, sp: sp, digest: dig, ref: ref}

			var (
				out string
				err error
			)
			if id.Level < sp.MinLevel {
				err = refuse(apperr.CodeForbidden, "%s needs %s level; this key acts at %s level", name, sp.MinLevel.Token(), id.Level.Token())
			} else {
				out, err = run(ctx, in, g)
			}

			var pending *pendingApproval
			if errors.As(err, &pending) {
				b, _ := json.Marshal(pending.result) // a struct of strings always marshals
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
			}

			if err != nil || !handlerAudits {
				e := store.AuditEvent{
					Kind:       "mcp-call",
					Summary:    callSummary(name, err),
					TargetKind: "mcp-tool",
					TargetPath: "/mcp/tools/" + name,
					Outcome:    outcome(err),
				}
				var r *refusal
				if errors.As(err, &r) {
					e.ApprovalID = r.approvalID
				}
				auditlog.Record(ctx, t.st, e)
			}
			if err != nil {
				log.Printf("mcpserver: %s by key %s refused: %v", name, id.KeyID, err)
				return nil, nil, toolError(ctx, err)
			}

			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: out}}}, nil, nil
		})
}

// digest is the lowercase hex SHA-256 of the tool name and its canonical
// arguments, so an audit row can be matched to an exact request without
// storing the request, and an approval covers exactly one request. For a
// tool that runs under approvals, approval_id is left out: it names the
// approval, it is not part of the request. The arguments are re-encoded
// through a map, so keys are sorted and field order cannot change the
// digest.
func digest(name string, in any) string {
	b, _ := json.Marshal(in) // the typed arguments always marshal
	if _, ok := in.(approvalRef); ok {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var m map[string]any
		if dec.Decode(&m) == nil {
			delete(m, "approval_id")
			b, _ = json.Marshal(m)
		}
	}
	h := sha256.Sum256(append([]byte(name+"\n"), b...))
	return hex.EncodeToString(h[:])
}

func outcome(err error) string {
	var r *refusal
	switch {
	case err == nil:
		return auditlog.OutcomeOK
	case errors.As(err, &r):
		return r.outcome
	case connect.CodeOf(err) == connect.CodePermissionDenied, connect.CodeOf(err) == connect.CodeUnauthenticated:
		return auditlog.OutcomeDenied
	default:
		return auditlog.OutcomeError
	}
}

func callSummary(name string, err error) string {
	var r *refusal
	switch {
	case err == nil:
		return "MCP " + name
	case errors.As(err, &r):
		return fmt.Sprintf("MCP %s refused: %s", name, r.msg)
	default:
		return fmt.Sprintf("MCP %s failed (%s)", name, connect.CodeOf(err))
	}
}

// toolError turns a failure into what the agent sees. Handler failures are
// sanitised exactly like the web API: a stable code and no internal cause.
func toolError(ctx context.Context, err error) error {
	var r *refusal
	if errors.As(err, &r) {
		return fmt.Errorf("%s (error %d)", r.msg, r.code)
	}
	msg, _ := apperr.Registry().PresentContext(ctx, err, apperr.CodeUnknown)
	return errors.New(msg)
}

// render returns m as compact JSON with the proto field names.
func render(m proto.Message) (string, error) {
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	if err != nil {
		return "", err
	}
	// protojson deliberately varies its whitespace; compact it so agents and
	// tests see stable output.
	var out bytes.Buffer
	if err := json.Compact(&out, b); err != nil {
		return "", err
	}
	return out.String(), nil
}
