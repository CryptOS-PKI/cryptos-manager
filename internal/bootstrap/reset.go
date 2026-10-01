package bootstrap

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
	"fmt"
	"io"
	"time"

	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// KindBootstrapReset is the audit kind of the break-glass reset.
const KindBootstrapReset = "bootstrap-reset"

// The audit actor of the break-glass reset: whoever has shell access to a
// host that can reach the database, through the command line.
const (
	ActorHost = "host"
	ViaCLI    = "cli"
)

// ResetGuidance is printed after every reset. The manager never held the
// operator CA key and can't revoke at the CA, so the guidance says what is
// left for the operator to do there.
var ResetGuidance = []string{
	"The FM never held your operator CA key. If you believe the CA itself is compromised, create a new operator CA before registering again. Otherwise you may register the same CA again.",
	"Revoke at your CA any credential you no longer trust, and publish a new CRL.",
}

// ErrManagerRunning is returned by Reset when a manager is still running
// against the database or on the configured listen address.
var ErrManagerRunning = errors.New("bootstrap: a Fleet Manager is running; stop every replica before resetting first run")

// ResetStore is what the break-glass reset needs from the database.
type ResetStore interface {
	TryAdvisoryLock(ctx context.Context, name string) (release func(), acquired bool, err error)
	ResetFirstRun(ctx context.Context, at time.Time) (store.FirstRunReset, error)
}

// ResetOptions configures Reset.
type ResetOptions struct {
	Store ResetStore
	Audit store.Store
	// Live reports whether a manager answers its health endpoint on the
	// configured listen address.
	Live func(ctx context.Context) bool
	// FileSource is set when operatorCAPath is configured.
	FileSource bool
	// FirstRunDisabled is firstRun: disabled.
	FirstRunDisabled bool
	// Host names the machine the reset ran on, for the audit row.
	Host string
	Now  func() time.Time
	Out  io.Writer
}

// Reset is the offline break-glass reset. It refuses while a manager holds
// the token lock or answers its health endpoint. Otherwise it reopens first
// run (the latch, sessions and tokens cleared, every operator CA retired,
// the denylist and CRLs kept), writes an audit row and prints what it did
// and the guidance.
func Reset(ctx context.Context, o ResetOptions) error {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}

	release, ok, err := o.Store.TryAdvisoryLock(ctx, TokenLockName)
	if err != nil {
		return fmt.Errorf("bootstrap: take the first-run token lock: %w", err)
	}
	if !ok {
		return fmt.Errorf("%w (a replica holds the first-run token lock)", ErrManagerRunning)
	}
	defer release()
	if o.Live(ctx) {
		return fmt.Errorf("%w (its health endpoint answers on the configured listen address)", ErrManagerRunning)
	}

	at := now().UTC()
	r, err := o.Store.ResetFirstRun(ctx, at)
	if err != nil {
		return err
	}

	was := "first run was open"
	if r.Previous.Closed() {
		was = fmt.Sprintf("first run was closed by %s (serial %s, operator CA %s) at %s",
			r.Previous.ClosedByCN, r.Previous.ClosedBySerial, r.Previous.ClosedByIssuerSHA256, r.Previous.ClosedAt.UTC().Format(time.RFC3339))
	}
	done := fmt.Sprintf("%d bootstrap session(s) and %d token(s) deleted, %d operator CA(s) retired (rows kept)", r.Sessions, r.Tokens, r.RetiredCAs)
	auditlog.Record(ctx, o.Audit, store.AuditEvent{
		At:         at.Format(time.RFC3339),
		Kind:       KindBootstrapReset,
		Summary:    fmt.Sprintf("First run reopened by the break-glass reset: %s; %s; the denylist and stored CRLs are kept", was, done),
		TargetKind: "bootstrap",
		ActorKind:  ActorHost,
		ActorCN:    o.Host,
		Via:        ViaCLI,
	})

	w := o.Out
	_, _ = fmt.Fprintf(w, "First run reset. The next start opens a fresh first run and prints a new bootstrap token.\n")
	_, _ = fmt.Fprintf(w, "  %s.\n  %s.\n", was, done)
	_, _ = fmt.Fprintf(w, "  The operator denylist and stored CRLs are kept, so an operator CA registered again keeps its earlier revocations.\n\n")
	for _, g := range ResetGuidance {
		_, _ = fmt.Fprintf(w, "%s\n", g)
	}
	if o.FileSource {
		_, _ = fmt.Fprintf(w, "\nWARNING operatorCAPath is set, so first run stays NOT_APPLICABLE while the file source is configured. "+
			"Remove operatorCAPath from the config to use first run.\n")
	}
	if o.FirstRunDisabled {
		_, _ = fmt.Fprintf(w, "\nWARNING firstRun is disabled, so first run stays unavailable. Set firstRun: auto to use first run.\n")
	}
	return nil
}
