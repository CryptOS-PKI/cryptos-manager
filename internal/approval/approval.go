// Package approval raises, decides and uses the step-up approvals that stand
// between an MCP tool call and a high-risk FleetService operation.
package approval

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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// DefaultTTL is how long an approval can be decided and used after it is
// raised.
const DefaultTTL = 15 * time.Minute

// Audit kinds and target for the approval lifecycle.
const (
	KindRequested     = "approval-requested"
	KindApproved      = "approval-approved"
	KindDenied        = "approval-denied"
	KindDecideRefused = "approval-decide-refused"
	KindUsed          = "approval-used"
	TargetKind        = "approval"
)

// Errors the approval operations return. Callers map them to their
// transport's status codes.
var (
	ErrNotFound      = errors.New("approval: no such approval")
	ErrBadStatus     = errors.New("approval: unknown status filter")
	ErrNeedsCert     = errors.New("approval: approvals are decided with an operator certificate, never an MCP key")
	ErrNotPending    = errors.New("approval: the approval is no longer pending")
	ErrApproverLevel = errors.New("approval: the approver's level is below the level the request needs")
	ErrAwaiting      = errors.New("approval: the approval has not been decided yet")
	ErrDenied        = errors.New("approval: the approval was denied")
	ErrExpired       = errors.New("approval: the approval has expired")
	ErrUsed          = errors.New("approval: the approval was already used")
	ErrMismatch      = errors.New("approval: the approval was raised for a different tool, request or key")
	ErrKeyLevel      = errors.New("approval: the key's level is below the tool's minimum")
)

// Service raises, decides and uses approvals over a store.
type Service struct {
	Store store.Store
	// Now defaults to time.Now.
	Now func() time.Time
	// TTL defaults to DefaultTTL.
	TTL time.Duration
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return DefaultTTL
}

// Status is the approval's status at now: a pending or approved approval
// past its expiry reports expired.
func Status(a store.Approval, now time.Time) string {
	if (a.Status == store.ApprovalPending || a.Status == store.ApprovalApproved) && !now.Before(a.ExpiresAt) {
		return store.ApprovalExpired
	}
	return a.Status
}

// Request raises a pending approval for tool with the request digest, made
// by requester (an MCP key identity), that a person at required level or
// above must decide. The ctx must carry the requester for the audit row.
func (s *Service) Request(ctx context.Context, requester authz.Identity, tool, digest, summary string, required authz.Level) store.Approval {
	now := s.now()
	a := store.Approval{
		ID:                newID(),
		Tool:              tool,
		Summary:           summary,
		RequestDigest:     digest,
		RequestedByCN:     requester.CN,
		RequestedBySerial: requester.Serial,
		KeyID:             requester.KeyID,
		RequiredLevel:     required.Token(),
		CreatedAt:         now,
		ExpiresAt:         now.Add(s.ttl()),
		Status:            store.ApprovalPending,
	}
	s.Store.AddApproval(a)

	auditlog.Record(authz.NewContext(ctx, requester), s.Store, store.AuditEvent{
		Kind:          KindRequested,
		Summary:       fmt.Sprintf("Approval %s requested for %s: %s", a.ID, tool, summary),
		TargetKind:    TargetKind,
		TargetPath:    "/approvals/" + a.ID,
		Tool:          tool,
		RequestDigest: digest,
		Outcome:       auditlog.OutcomePending,
		ApprovalID:    a.ID,
	})

	return a
}

// Get returns the approval with the given ID with its status at now.
func (s *Service) Get(id string) (store.Approval, bool) {
	a, ok := s.Store.Approval(id)
	if !ok {
		return store.Approval{}, false
	}
	a.Status = Status(a, s.now())
	return a, true
}

// List returns every approval, newest first, with its status at now. A
// non-empty status keeps only approvals in that status.
func (s *Service) List(status string) ([]store.Approval, error) {
	switch status {
	case "", store.ApprovalPending, store.ApprovalApproved, store.ApprovalDenied, store.ApprovalExpired, store.ApprovalUsed:
	default:
		return nil, ErrBadStatus
	}
	now := s.now()
	out := make([]store.Approval, 0)
	for _, a := range s.Store.Approvals() {
		a.Status = Status(a, now)
		if status == "" || a.Status == status {
			out = append(out, a)
		}
	}
	return out, nil
}

// ForKey returns the approvals raised by the MCP key keyID, newest first,
// with their status at now.
func (s *Service) ForKey(keyID string) []store.Approval {
	now := s.now()
	out := make([]store.Approval, 0)
	for _, a := range s.Store.Approvals() {
		if a.KeyID == keyID {
			a.Status = Status(a, now)
			out = append(out, a)
		}
	}
	return out
}

// Decide approves or denies a pending approval. The decider must have
// arrived with an operator certificate and be at or above the approval's
// required level. The requester may decide their own request in the
// browser, because the agent holds only the key, which cannot decide.
func (s *Service) Decide(ctx context.Context, decider authz.Identity, id string, approve bool) (store.Approval, error) {
	if decider.KeyID != "" {
		return store.Approval{}, ErrNeedsCert
	}
	a, ok := s.Store.Approval(id)
	if !ok {
		return store.Approval{}, ErrNotFound
	}
	now := s.now()
	if st := Status(a, now); st != store.ApprovalPending {
		return store.Approval{}, fmt.Errorf("%w (it is %s)", ErrNotPending, st)
	}
	required, err := authz.LevelFromToken(a.RequiredLevel)
	if err != nil {
		return store.Approval{}, fmt.Errorf("approval: stored required level: %w", err)
	}
	ctx = authz.NewContext(ctx, decider)
	if decider.Level < required {
		auditlog.Record(ctx, s.Store, store.AuditEvent{
			Kind:          KindDecideRefused,
			Summary:       fmt.Sprintf("Refused a decision on approval %s: it needs %s level, the decider is %s", id, a.RequiredLevel, decider.Level.Token()),
			TargetKind:    TargetKind,
			TargetPath:    "/approvals/" + id,
			Tool:          a.Tool,
			RequestDigest: a.RequestDigest,
			Outcome:       auditlog.OutcomeDenied,
			ApprovalID:    id,
		})
		return store.Approval{}, ErrApproverLevel
	}

	status, kind, verb := store.ApprovalApproved, KindApproved, "Approved"
	if !approve {
		status, kind, verb = store.ApprovalDenied, KindDenied, "Denied"
	}
	decided, ok := s.Store.DecideApproval(id, status, decider.CN, decider.Serial, decider.Level.Token(), now)
	if !ok {
		return store.Approval{}, ErrNotPending
	}
	auditlog.Record(ctx, s.Store, store.AuditEvent{
		Kind: kind,
		Summary: fmt.Sprintf("%s approval %s for %s requested by %s (%s) with key %s: %s",
			verb, id, a.Tool, a.RequestedByCN, a.RequestedBySerial, a.KeyID, a.Summary),
		TargetKind:     TargetKind,
		TargetPath:     "/approvals/" + id,
		Tool:           a.Tool,
		RequestDigest:  a.RequestDigest,
		ApprovalID:     id,
		ApproverSerial: decider.Serial,
	})

	return decided, nil
}

// Use consumes an approval so the call it covers can run. It succeeds only
// for the key that raised it, the same tool and request digest, an approved
// and unexpired approval that has not been used, a caller whose live level
// is at least min, and an approver whose level was at least min. The
// approval is marked used before the call runs, so it runs at most once
// even if the call then fails. The ctx must carry the caller for the audit
// row.
func (s *Service) Use(ctx context.Context, caller authz.Identity, id, tool, digest string, min authz.Level) (store.Approval, error) {
	a, ok := s.Store.Approval(id)
	if !ok {
		return store.Approval{}, ErrNotFound
	}
	if a.KeyID != caller.KeyID || a.Tool != tool || a.RequestDigest != digest {
		return store.Approval{}, ErrMismatch
	}
	now := s.now()
	if err := statusErr(Status(a, now)); err != nil {
		return store.Approval{}, err
	}
	if caller.Level < min {
		return store.Approval{}, ErrKeyLevel
	}
	approver, err := authz.LevelFromToken(a.DecidedByLevel)
	if err != nil || approver < min {
		return store.Approval{}, ErrApproverLevel
	}

	used, ok := s.Store.UseApproval(id, now)
	if !ok {
		// Lost a race with another call or with the expiry.
		latest, _ := s.Store.Approval(id)
		if err := statusErr(Status(latest, now)); err != nil {
			return store.Approval{}, err
		}
		return store.Approval{}, ErrUsed
	}
	auditlog.Record(authz.NewContext(ctx, caller), s.Store, store.AuditEvent{
		Kind:           KindUsed,
		Summary:        fmt.Sprintf("Approval %s used for %s (approved by %s)", id, tool, a.DecidedByCN),
		TargetKind:     TargetKind,
		TargetPath:     "/approvals/" + id,
		Tool:           tool,
		RequestDigest:  digest,
		ApprovalID:     id,
		ApproverSerial: a.DecidedBySerial,
	})

	return used, nil
}

func statusErr(status string) error {
	switch status {
	case store.ApprovalApproved:
		return nil
	case store.ApprovalPending:
		return ErrAwaiting
	case store.ApprovalDenied:
		return ErrDenied
	case store.ApprovalExpired:
		return ErrExpired
	default:
		return ErrUsed
	}
}

// ToProto renders a (status-resolved) approval for the API.
func ToProto(a store.Approval) *fleetv1.Approval {
	return &fleetv1.Approval{
		Id:                a.ID,
		Tool:              a.Tool,
		Summary:           a.Summary,
		RequestDigest:     a.RequestDigest,
		RequestedByCn:     a.RequestedByCN,
		RequestedBySerial: a.RequestedBySerial,
		KeyId:             a.KeyID,
		RequiredLevel:     a.RequiredLevel,
		CreatedAt:         rfc3339OrEmpty(a.CreatedAt),
		ExpiresAt:         rfc3339OrEmpty(a.ExpiresAt),
		Status:            a.Status,
		DecidedByCn:       a.DecidedByCN,
		DecidedBySerial:   a.DecidedBySerial,
		DecidedAt:         rfc3339OrEmpty(a.DecidedAt),
	}
}

func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error

	return "apr-" + hex.EncodeToString(b)
}
