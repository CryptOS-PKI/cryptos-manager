// Package auditlog appends audit rows stamped with the identity that acted.
package auditlog

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
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// Outcomes recorded on audit rows.
const (
	OutcomeOK     = "ok"
	OutcomeDenied = "denied"
	OutcomeError  = "error"
	// OutcomePending marks a step-up call that raised an approval instead of
	// running.
	OutcomePending = "pending"
)

// Call describes the MCP tool call in flight. Rows written by the handlers
// the call dispatches to carry its tool name and request digest, and, for a
// step-up call running under an approval, the approval and its approver.
type Call struct {
	Tool           string
	RequestDigest  string
	ApprovalID     string
	ApproverSerial string
}

type callCtxKey struct{}

// WithCall returns ctx carrying c.
func WithCall(ctx context.Context, c Call) context.Context {
	return context.WithValue(ctx, callCtxKey{}, c)
}

// Record appends e to st's audit chain, stamped with the actor carried by
// ctx and the MCP call, if any. An empty ID or At is filled in, and an empty
// Outcome means the action succeeded.
func Record(ctx context.Context, st store.Store, e store.AuditEvent) store.AuditEvent {
	if e.ID == "" {
		e.ID = NewID()
	}
	if e.At == "" {
		e.At = time.Now().UTC().Format(time.RFC3339)
	}
	if e.Outcome == "" {
		e.Outcome = OutcomeOK
	}
	if id, ok := authz.FromContext(ctx); ok {
		e.ActorKind = id.ActorKind()
		e.ActorCN = id.CN
		e.ActorSerial = id.Serial
		e.KeyID = id.KeyID
		e.Via = id.Via
	}
	if c, ok := ctx.Value(callCtxKey{}).(Call); ok {
		e.Tool = c.Tool
		e.RequestDigest = c.RequestDigest
		if e.ApprovalID == "" {
			e.ApprovalID = c.ApprovalID
		}
		if e.ApproverSerial == "" {
			e.ApproverSerial = c.ApproverSerial
		}
	}

	return st.AddAuditEvent(e)
}

// NewID returns a fresh random audit event ID.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error

	return "aud-" + hex.EncodeToString(b)
}
