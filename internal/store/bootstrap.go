package store

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
	"context"
	"errors"
	"time"
)

// Why a bootstrap session ended.
const (
	SessionEndedSuperseded  = "superseded"
	SessionEndedExpired     = "expired"
	SessionEndedClosed      = "closed"
	SessionEndedRateLimited = "rate_limited"
)

// RetiredSuperseded is the retired_reason of a first-run operator CA that a
// later first-run registration replaced.
const RetiredSuperseded = "superseded"

// RetiredReset is the retired_reason of an operator CA retired by the
// break-glass reset.
const RetiredReset = "reset"

// ErrBootstrapClosed is returned by first-run writes once first run is
// closed.
var ErrBootstrapClosed = errors.New("store: first run is closed")

// BootstrapState is the one-way first-run latch. A zero ClosedAt means first
// run is open.
type BootstrapState struct {
	ClosedAt             time.Time
	ClosedBySerial       string
	ClosedByCN           string
	ClosedByIssuerSHA256 string
}

// Closed reports whether first run is closed.
func (s BootstrapState) Closed() bool { return !s.ClosedAt.IsZero() }

// BootstrapToken is a stored bootstrap token. Only the SHA-256 of the token
// is kept; the token itself is printed once and never stored.
type BootstrapToken struct {
	Hash      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// BootstrapSession is a stored bootstrap session. Only the SHA-256 of the
// session secret is kept. A zero EndedAt means the session wasn't ended,
// though it may have expired.
type BootstrapSession struct {
	Hash        string
	CreatedAt   time.Time
	LastUsedAt  time.Time
	ExpiresAt   time.Time
	EndedAt     time.Time
	EndedReason string
}

// FirstRunReset is what the break-glass reset changed: the latch as it was
// before, and how many sessions, tokens and operator CA rows it removed or
// retired.
type FirstRunReset struct {
	Previous   BootstrapState
	Sessions   int
	Tokens     int
	RetiredCAs int
}

// Bootstrap is the storage behind first run: the latch, the token and
// session hashes, first-run operator CA registration and the first admin's
// credential record. Only the Postgres store implements it; without
// Postgres first run is unavailable.
type Bootstrap interface {
	// BootstrapState returns the latch.
	BootstrapState(ctx context.Context) (BootstrapState, error)
	// CloseBootstrap closes first run if it is open, recording who closed
	// it, and ends every session and deletes every token in the same step.
	// It reports whether this call closed it; closing an already closed
	// latch changes nothing.
	CloseBootstrap(ctx context.Context, by BootstrapState) (bool, error)

	// IssueBootstrapToken stores a new token and marks every other unused
	// token used, so exactly one token is live. It returns
	// ErrBootstrapClosed once first run is closed.
	IssueBootstrapToken(ctx context.Context, t BootstrapToken) error
	// LiveBootstrapToken returns the unused token that hasn't expired at now.
	LiveBootstrapToken(ctx context.Context, now time.Time) (BootstrapToken, bool, error)

	// StartBootstrapSession consumes the token with tokenHash, if it is
	// unused and unexpired at now and first run is open, ends every live
	// session as superseded and stores s, all in one step. It reports false,
	// changing nothing, when the token can't be used.
	StartBootstrapSession(ctx context.Context, tokenHash string, s BootstrapSession, now time.Time) (bool, error)
	// BootstrapSession returns the session with the given hash, ended or not.
	BootstrapSession(ctx context.Context, hash string) (BootstrapSession, bool, error)
	// TouchBootstrapSession records a use of the session at at.
	TouchBootstrapSession(ctx context.Context, hash string, at time.Time) error
	// EndBootstrapSession ends one session.
	EndBootstrapSession(ctx context.Context, hash, reason string, at time.Time) error
	// EndBootstrapSessions ends every session not yet ended and reports how
	// many it ended.
	EndBootstrapSessions(ctx context.Context, reason string, at time.Time) (int, error)
	// HasLiveBootstrapSession reports whether a session is neither ended nor
	// past its absolute expiry or idle limit at now.
	HasLiveBootstrapSession(ctx context.Context, now time.Time, idle time.Duration) (bool, error)

	// RegisterFirstRunOperatorCA makes ca the active operator CA in one
	// step: every other active or retiring row is retired as superseded,
	// ca is stored as active and confirmed by sessionHash (a row with the
	// same fingerprint is brought back), crl, when set, is stored if decide
	// accepts it, and the revocation epoch moves. It returns
	// ErrBootstrapClosed once first run is closed.
	RegisterFirstRunOperatorCA(ctx context.Context, ca OperatorCA, sessionHash string, crl *OperatorCRL, decide DecideCRL) error
	// ConfirmOperatorCA records that sessionHash confirmed the operator CA
	// with the given fingerprint.
	ConfirmOperatorCA(ctx context.Context, sha256, sessionHash string) error
	// OperatorCAConfirmedBy returns the hash of the session that last
	// confirmed the operator CA, empty if none.
	OperatorCAConfirmedBy(ctx context.Context, sha256 string) (string, error)

	// RecordFirstAdmin stores c as the first admin's credential, replacing
	// the name and kind of a row with the same issuer and serial.
	RecordFirstAdmin(ctx context.Context, c OperatorCredential, at time.Time) error
	// RecordFirstUse stores c, kind first_admin, unless a credential with
	// the same issuer and serial is already recorded. It reports whether it
	// stored it.
	RecordFirstUse(ctx context.Context, c OperatorCredential, at time.Time) (bool, error)
	// FirstAdminCredentials returns every first_admin credential.
	FirstAdminCredentials(ctx context.Context) ([]OperatorCredential, error)

	// ResetFirstRun reopens first run in one step: it clears the latch,
	// deletes every session and token, and retires every operator CA row
	// that isn't retired yet (reason RetiredReset, rows kept). The
	// denylist and stored CRLs are kept, so a CA registered again keeps its
	// earlier revocations.
	ResetFirstRun(ctx context.Context, at time.Time) (FirstRunReset, error)
}
