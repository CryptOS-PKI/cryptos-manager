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
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/operatorca"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// LatchOptions configures a Latch.
type LatchOptions struct {
	// Store is nil without Postgres; the latch then never closes, because
	// there is no first run to close.
	Store store.Bootstrap
	Audit store.Store
	Now   func() time.Time
	Logf  func(string, ...any)
	// OnClose runs once when this process learns first run is closed.
	OnClose func()
}

// Latch closes first run the first time an admin certificate that chains to
// a trusted operator CA, and isn't revoked, makes an API request, from
// either operator CA source. It is one-way: nothing here reopens it.
//
// Each process keeps a flag, so a closed latch costs one atomic load per
// request.
type Latch struct {
	st      store.Bootstrap
	audit   store.Store
	now     func() time.Time
	logf    func(string, ...any)
	onClose func()

	closed    atomic.Bool
	mu        sync.Mutex
	closeOnce sync.Once
}

// NewLatch builds a latch and reads whether first run is already closed.
func NewLatch(ctx context.Context, o LatchOptions) (*Latch, error) {
	l := &Latch{st: o.Store, audit: o.Audit, now: o.Now, logf: o.Logf, onClose: o.OnClose}
	if l.now == nil {
		l.now = time.Now
	}
	if l.logf == nil {
		l.logf = func(string, ...any) {}
	}
	if l.onClose == nil {
		l.onClose = func() {}
	}
	if l.st != nil {
		st, err := l.st.BootstrapState(ctx)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: read the first-run latch: %w", err)
		}
		if st.Closed() {
			l.markClosed()
		}
	}
	return l, nil
}

// Closed reports whether this process knows first run is closed.
func (l *Latch) Closed() bool { return l != nil && l.closed.Load() }

func (l *Latch) markClosed() {
	l.closed.Store(true)
	l.closeOnce.Do(l.onClose)
}

// Observe is the authz.AuthHook: it runs after a request's certificate
// passed the chain and revocation checks. An admin certificate closes first
// run, ends every session, deletes every token, and is recorded as the first
// admin unless a pre-flight already recorded it. A failure to close is
// logged and retried on the next admin request.
func (l *Latch) Observe(ctx context.Context, id authz.Identity, cert *x509.Certificate) {
	if l == nil || l.st == nil || id.Level != authz.LevelAdmin || l.closed.Load() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed.Load() {
		return
	}
	now := l.now().UTC()
	serial := operatorca.SerialKey(cert.SerialNumber)
	closedNow, err := l.st.CloseBootstrap(ctx, store.BootstrapState{
		ClosedAt: now, ClosedBySerial: serial, ClosedByCN: id.CN, ClosedByIssuerSHA256: id.IssuerSHA256,
	})
	if err != nil {
		l.logf("bootstrap: ERROR can't close first run for %s (%s), will retry on the next admin request: %v", id.CN, serial, err)
		return
	}
	l.markClosed()
	if !closedNow {
		return
	}

	email := strings.ToLower(cert.Subject.CommonName)
	if _, err := l.st.RecordFirstUse(ctx, store.OperatorCredential{
		IssuerSHA256: id.IssuerSHA256, SerialHex: serial, CommonName: email, Email: email, Level: id.Level.Token(),
		NotAfter: cert.NotAfter.UTC().Format(time.RFC3339), LeafSHA256: operatorca.Fingerprint(cert),
	}, now); err != nil {
		l.logf("bootstrap: can't record %s (%s) as the first admin: %v", id.CN, serial, err)
	}
	l.logf("manager: first run CLOSED by %s (%s)", id.CN, serial)
	if l.audit != nil {
		auditlog.Record(ctx, l.audit, store.AuditEvent{
			Kind:       KindBootstrapClosed,
			Summary:    fmt.Sprintf("First run closed by %s (serial %s, operator CA %s); bootstrap sessions ended and tokens deleted", id.CN, serial, id.IssuerSHA256),
			TargetKind: "operator-credential",
			TargetPath: "/operators/" + serial,
		})
	}
}
