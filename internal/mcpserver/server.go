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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	connect "connectrpc.com/connect"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/fleet"
	"github.com/CryptOS-PKI/manager/internal/mcpauth"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// maxRequestBodyBytes caps one MCP POST. The largest legitimate call is a
// CSR, which is a few kilobytes.
const maxRequestBodyBytes = 1 << 20

// Handler returns the stateless Streamable HTTP handler that serves the
// Direct tools. It must sit behind mcpauth.Middleware, which supplies the
// identity every tool acts as.
func Handler(svc *fleet.Service, st store.Store, version string) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "fleetos", Title: "FleetOS Fleet Manager", Version: version}, nil)
	registerTools(server, &tools{svc: svc, st: st})

	return mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, MaxRequestBodyBytes: maxRequestBodyBytes},
	)
}

// refusal is an MCP-side refusal whose message is safe to show the agent.
type refusal struct {
	code    int
	outcome string
	msg     string
}

func (r *refusal) Error() string { return r.msg }

func refuse(code int, format string, args ...any) error {
	return &refusal{code: code, outcome: auditlog.OutcomeDenied, msg: fmt.Sprintf(format, args...)}
}

func invalid(format string, args ...any) error {
	return &refusal{code: apperr.CodeUnknown, outcome: auditlog.OutcomeError, msg: fmt.Sprintf(format, args...)}
}

// add registers a Direct tool. Every call is checked against the tool's
// minimum level before it runs, and audited: a read or a failed call gets an
// "mcp-call" row here, while a successful write is audited by the handler it
// dispatched to (handlerAudits), stamped with the same key and tool.
func add[In any](s *mcp.Server, st store.Store, name, description string, handlerAudits bool, run func(context.Context, In) (string, error)) {
	sp := spec(name)
	if sp.Policy != Direct {
		panic("mcpserver: " + name + " is not a direct tool")
	}

	mcp.AddTool(s, &mcp.Tool{Name: name, Description: description},
		func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
			id, ok := mcpauth.IdentityFromTokenInfo(req.Extra.TokenInfo)
			if !ok {
				return nil, nil, errors.New("no MCP identity on the request")
			}
			ctx = auditlog.WithCall(authz.NewContext(ctx, id), auditlog.Call{Tool: name, RequestDigest: digest(name, in)})

			var (
				out string
				err error
			)
			if id.Level < sp.MinLevel {
				err = refuse(apperr.CodeForbidden, "%s needs %s level; this key acts at %s level", name, sp.MinLevel.Token(), id.Level.Token())
			} else {
				out, err = run(ctx, in)
			}

			if err != nil || !handlerAudits {
				auditlog.Record(ctx, st, store.AuditEvent{
					Kind:       "mcp-call",
					Summary:    callSummary(name, err),
					TargetKind: "mcp-tool",
					TargetPath: "/mcp/tools/" + name,
					Outcome:    outcome(err),
				})
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
// storing the request.
func digest(name string, in any) string {
	b, _ := json.Marshal(in) // the typed arguments always marshal
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
