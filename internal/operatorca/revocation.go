package operatorca

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
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// operatorRevocationPolicy values: what the web path does when no fresh
// revocation data is available for a certificate.
const (
	PolicySoft = "soft"
	PolicyHard = "hard"
)

// Status badges for an operator CA with no CRL source.
const (
	BadgeNotObserved = "CA revocations not observed"
	BadgeOCSPOnly    = "CA revocations seen through OCSP only"
)

// Audit kinds written by the revocation engine.
const (
	KindCRLExpired = "operator-crl-expired"
)

// How long a replica's denylist view may go without a successful poll
// before MCP stops trusting it, and how often a stale CRL is logged.
const (
	maxDenylistAge = 5 * time.Minute
	staleLogEvery  = time.Hour
	expiringShare  = 0.2
)

// ErrUnknownAnchor is returned for an operator CA fingerprint the manager
// doesn't currently trust.
var ErrUnknownAnchor = errors.New("operatorca: not a trusted operator CA")

// Anchor is one trusted operator CA with its revocation settings.
type Anchor struct {
	Cert   *x509.Certificate
	SHA256 string
	State  string
	// CRLSource is none, url, upload or path. A config-file anchor with
	// operatorCRL entries has CRLSource url or path.
	CRLSource   string
	CRLLocation string
	OCSPMode    string
	OCSPURL     string
	FromConfig  bool
}

// HasCRL reports whether the anchor has a CRL source at all.
func (a Anchor) HasCRL() bool {
	return a.CRLSource != "" && a.CRLSource != store.CRLSourceNone
}

func (a Anchor) name() string {
	return a.Cert.Subject.CommonName
}

// AnchorStatus is what the Operator CAs page and banners show for one
// anchor on this replica.
type AnchorStatus struct {
	CRLConfigured bool
	CRLLoaded     bool
	CRLFresh      bool
	ThisUpdate    time.Time
	NextUpdate    time.Time
	RevokedCount  int
	LastError     string
	Banner        string
	Badge         string
	OCSPBanner    string
}

type anchorState struct {
	anchor         Anchor
	denied         map[string]struct{}
	crl            *VerifiedCRL
	lastError      string
	lastStaleLog   time.Time
	expiredAudited bool
	// ocspOutage is set while the web path is allowing certificates under
	// soft policy with no fresh OCSP response and no fresh CRL.
	ocspOutage  bool
	lastOCSPLog time.Time
}

// RevocationOptions configures a Revocations.
type RevocationOptions struct {
	Store  store.OperatorTrust
	Policy string
	Now    func() time.Time
	Logf   func(format string, args ...any)
	// Audit records an audit event on behalf of the manager itself.
	Audit func(store.AuditEvent)
	// OCSPFetcher turns OCSP on; nil leaves it off.
	OCSPFetcher    *Fetcher
	OCSPBackground func(func())
}

// Revocations holds, per anchor, the manager's denylist and the anchor's
// last good CRL, and decides whether a certificate may be used. A serial is
// revoked if either source lists it; serials are keyed by anchor because
// they are unique per issuer only.
type Revocations struct {
	st     store.OperatorTrust
	policy string
	now    func() time.Time
	logf   func(string, ...any)
	audit  func(store.AuditEvent)

	mu       sync.RWMutex
	anchors  map[string]*anchorState
	denylist map[string]map[string]struct{}
	polledAt time.Time

	ocsp *OCSPClient
}

// NewRevocations builds an empty engine; SetAnchors and Reload fill it.
func NewRevocations(o RevocationOptions) *Revocations {
	r := &Revocations{st: o.Store, policy: o.Policy, now: o.Now, logf: o.Logf, audit: o.Audit,
		anchors: map[string]*anchorState{}, denylist: map[string]map[string]struct{}{}}
	if r.policy == "" {
		r.policy = PolicySoft
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.logf == nil {
		r.logf = func(string, ...any) {}
	}
	if r.audit == nil {
		r.audit = func(store.AuditEvent) {}
	}
	if o.OCSPFetcher != nil {
		r.ocsp = NewOCSPClient(OCSPOptions{Fetch: o.OCSPFetcher, Now: r.now, Logf: r.logf, Audit: r.audit, Background: o.OCSPBackground})
	}
	return r
}

// OCSP returns the OCSP client, nil when OCSP is off.
func (r *Revocations) OCSP() *OCSPClient { return r.ocsp }

// Policy returns the operatorRevocationPolicy in force.
func (r *Revocations) Policy() string { return r.policy }

// SetAnchors replaces the set of trusted anchors, keeping what is already
// loaded for anchors that stay. An anchor whose OCSP mode or URL changed has
// its cached OCSP answers dropped, so the old responder's answers aren't used.
func (r *Revocations) SetAnchors(anchors []Anchor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := make(map[string]*anchorState, len(anchors))
	for _, a := range anchors {
		st, ok := r.anchors[a.SHA256]
		if !ok {
			st = &anchorState{}
		}
		if ok && r.ocsp != nil && (st.anchor.OCSPMode != a.OCSPMode || st.anchor.OCSPURL != a.OCSPURL) {
			r.ocsp.ClearAnchor(a.SHA256)
			st.ocspOutage = false
		}
		st.anchor = a
		st.denied = r.denylist[a.SHA256]
		next[a.SHA256] = st
	}
	r.anchors = next
}

// Anchors returns the anchors the engine knows.
func (r *Revocations) Anchors() []Anchor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Anchor, 0, len(r.anchors))
	for _, st := range r.anchors {
		out = append(out, st.anchor)
	}
	return out
}

// Reload reads the denylist and every stored CRL, re-verifying each CRL
// against its anchor so the database is never trusted blindly. A CRL that
// fails verification is logged and not used. A successful reload counts as
// a successful revocation poll.
func (r *Revocations) Reload(ctx context.Context) error {
	if err := r.reloadDenylist(ctx); err != nil {
		return err
	}
	crls, err := r.st.OperatorCRLs(ctx)
	if err != nil {
		return fmt.Errorf("operatorca: load CRLs: %w", err)
	}
	byIssuer := make(map[string]store.OperatorCRL, len(crls))
	for _, c := range crls {
		byIssuer[c.IssuerSHA256] = c
	}

	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for sha, st := range r.anchors {
		stored, ok := byIssuer[sha]
		if ok {
			st.lastError = stored.LastError
		}
		if ok && stored.DER != nil && (st.crl == nil || string(st.crl.DER) != string(stored.DER)) {
			v, err := VerifyCRL(stored.DER, st.anchor.Cert, now)
			if err != nil {
				r.logf("operatorca: refused the stored CRL for operator CA %s (%s): %v", st.anchor.name(), sha, err)
			} else {
				st.crl = v
				if v.Fresh(now) {
					st.expiredAudited = false
				}
			}
		}
		if st.anchor.HasCRL() && st.crl == nil {
			r.logf("operatorca: WARNING operator CA %s CRL NOT YET ENFORCED: no CRL has been loaded yet (policy %s)", st.anchor.name(), r.policy)
			st.lastStaleLog = now
		}
	}
	r.polledAt = now
	return nil
}

func (r *Revocations) reloadDenylist(ctx context.Context) error {
	entries, err := r.st.OperatorDenylist(ctx)
	if err != nil {
		return fmt.Errorf("operatorca: load denylist: %w", err)
	}
	next := map[string]map[string]struct{}{}
	for _, e := range entries {
		set, ok := next[e.IssuerSHA256]
		if !ok {
			set = map[string]struct{}{}
			next[e.IssuerSHA256] = set
		}
		set[NormalizeSerial(e.SerialHex)] = struct{}{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.denylist = next
	for sha, st := range r.anchors {
		st.denied = next[sha]
	}
	return nil
}

// MarkPolled records a successful poll that found nothing new.
func (r *Revocations) MarkPolled() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.polledAt = r.now()
}

// IsRevoked reports whether the anchor's denylist or its last good CRL,
// fresh or not, lists serial.
func (r *Revocations) IsRevoked(anchorSHA256, serial string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.revokedLocked(anchorSHA256, NormalizeSerial(serial))
}

func (r *Revocations) revokedLocked(anchorSHA256, serial string) bool {
	if _, ok := r.denylist[anchorSHA256][serial]; ok {
		return true
	}
	st, ok := r.anchors[anchorSHA256]
	return ok && st.crl != nil && st.crl.IsRevoked(serial)
}

// Deny puts a serial on the manager's denylist. The writing replica enforces
// it at once; the store bumps the revocation epoch, so every other replica
// picks it up on its next poll. It needs Postgres.
func (r *Revocations) Deny(ctx context.Context, e store.DenylistEntry) error {
	e.SerialHex = NormalizeSerial(e.SerialHex)
	if e.RevokedAt.IsZero() {
		e.RevokedAt = r.now().UTC()
	}
	if _, err := r.st.AddOperatorDenylistEntry(ctx, e); err != nil {
		if errors.Is(err, store.ErrDatabaseRequired) {
			return apperr.Reasoned(apperr.CodeUnavailable, fleetv1.ErrorReason_ERROR_REASON_DATABASE_REQUIRED,
				fmt.Errorf("operatorca: the denylist needs Postgres: %w", err))
		}
		return fmt.Errorf("operatorca: deny %s/%s: %w", e.IssuerSHA256, e.SerialHex, err)
	}
	r.logf("operatorca: denied serial %s under operator CA %s", e.SerialHex, e.IssuerSHA256)
	return r.reloadDenylist(ctx)
}

// StoreCRL verifies der against the anchor, stores it if it is newer than
// the stored CRL (anti-rollback), and uses it at once on this replica. It
// reports whether the CRL was new.
func (r *Revocations) StoreCRL(ctx context.Context, anchorSHA256 string, der []byte, source string) (bool, error) {
	r.mu.RLock()
	st, ok := r.anchors[anchorSHA256]
	r.mu.RUnlock()
	if !ok {
		return false, ErrUnknownAnchor
	}
	now := r.now()
	v, err := VerifyCRL(der, st.anchor.Cert, now)
	if err != nil {
		return false, err
	}
	stored, err := r.st.PutOperatorCRL(ctx, store.OperatorCRL{
		IssuerSHA256: anchorSHA256, DER: v.DER, Number: v.Number,
		ThisUpdate: v.List.ThisUpdate, NextUpdate: v.List.NextUpdate, FetchedAt: now.UTC(), Source: source,
	}, func(cur store.OperatorCRL, has bool) (bool, error) { return AcceptNewer(cur, has, v) })
	if err != nil || !stored {
		return false, err
	}
	r.mu.Lock()
	st.crl = v
	st.lastError = ""
	if v.Fresh(now) {
		st.expiredAudited = false
	}
	r.mu.Unlock()
	r.logf("operatorca: stored a new CRL for operator CA %s: %d revoked, next update %s",
		st.anchor.name(), len(v.Revoked), v.List.NextUpdate.UTC().Format(time.RFC3339))
	return true, nil
}

// RecordCRLError keeps the last refresh failure for an anchor's status.
func (r *Revocations) RecordCRLError(anchorSHA256, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st, ok := r.anchors[anchorSHA256]; ok {
		st.lastError = msg
	}
}

// CRL returns the anchor's last good CRL, if any.
func (r *Revocations) CRL(anchorSHA256 string) (*VerifiedCRL, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.anchors[anchorSHA256]
	if !ok || st.crl == nil {
		return nil, false
	}
	return st.crl, true
}

func revoked(serial string, a Anchor) error {
	return rejectCert(fleetv1.ErrorReason_ERROR_REASON_REVOKED,
		"serial %s under operator CA %s is on the denylist or in the CRL", serial, a.name())
}

func unknownAnchor(sha string) error {
	return apperr.Reasoned(apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_NOT_CHAINED,
		fmt.Errorf("%w: %s", ErrUnknownAnchor, sha))
}

func noRevocationSource(reason fleetv1.ErrorReason, format string, args ...any) error {
	return apperr.Reasoned(apperr.CodeNoRevocationSource, reason, fmt.Errorf("operatorca: "+format, args...))
}

// CheckWeb is the web-path revocation decision for a serial under an
// anchor, when only the serial is known. It is CheckWebCert without the
// leaf, so an aia-mode anchor has no responder URI and no OCSP check.
func (r *Revocations) CheckWeb(anchorSHA256, serial string) error {
	n, ok := new(big.Int).SetString(NormalizeSerial(serial), 16)
	if !ok {
		return rejectCert(fleetv1.ErrorReason_ERROR_REASON_REVOKED, "serial %q isn't hex", serial)
	}
	return r.checkWeb(anchorSHA256, n, nil)
}

// CheckWebCert is the web-path revocation decision for a certificate that
// already verified against the anchor, in order:
//  1. the denylist or the last good CRL, fresh or not, lists the serial:
//     refuse (1610 REVOKED);
//  2. OCSP is configured for the certificate: revoked or unknown refuse
//     (1610 REVOKED_OCSP, OCSP_UNKNOWN); a fresh good allows;
//  3. otherwise a CRL within nextUpdate, or no CRL source and no OCSP for
//     the certificate at all, allows;
//  4. otherwise operatorRevocationPolicy: soft allows, with a banner, an
//     hourly log line and one audit row per CRL expiry or OCSP outage; hard
//     refuses with 1608 STALE_OCSP when OCSP was configured for the
//     certificate, else 1608 STALE_CRL.
func (r *Revocations) CheckWebCert(anchorSHA256 string, leaf *x509.Certificate) error {
	return r.checkWeb(anchorSHA256, leaf.SerialNumber, leaf)
}

func (r *Revocations) checkWeb(anchorSHA256 string, serial *big.Int, leaf *x509.Certificate) error {
	key := SerialKey(serial)
	r.mu.RLock()
	st, ok := r.anchors[anchorSHA256]
	if !ok {
		r.mu.RUnlock()
		return unknownAnchor(anchorSHA256)
	}
	a := st.anchor
	isRevoked := r.revokedLocked(anchorSHA256, key)
	r.mu.RUnlock()
	if isRevoked {
		return revoked(key, a)
	}

	responder := r.responderFor(a, leaf)
	if responder != "" {
		res, err := r.ocsp.Check(a, serial, responder, func(s string) bool { return r.IsRevoked(anchorSHA256, s) })
		if err == nil {
			r.endOCSPOutage(anchorSHA256)
			if refusal := ocspRefusal(res, key, a); refusal != nil {
				return refusal
			}
			return nil
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok = r.anchors[anchorSHA256]
	if !ok {
		return unknownAnchor(anchorSHA256)
	}
	now := r.now()
	crlFresh := st.anchor.HasCRL() && st.crl != nil && st.crl.Fresh(now)
	if crlFresh || (!st.anchor.HasCRL() && responder == "") {
		return nil
	}
	if r.policy == PolicyHard {
		if responder != "" {
			return noRevocationSource(fleetv1.ErrorReason_ERROR_REASON_STALE_OCSP,
				"no fresh OCSP response and no fresh CRL for serial %s under operator CA %s, and operatorRevocationPolicy is hard", key, st.anchor.name())
		}
		return noRevocationSource(fleetv1.ErrorReason_ERROR_REASON_STALE_CRL,
			"no fresh CRL for operator CA %s and operatorRevocationPolicy is hard", st.anchor.name())
	}
	if st.anchor.HasCRL() {
		r.noteStaleLocked(st, now)
	}
	if responder != "" {
		r.noteOCSPOutageLocked(st, responder, now)
	}
	return nil
}

func (r *Revocations) responderFor(a Anchor, leaf *x509.Certificate) string {
	if r.ocsp == nil {
		return ""
	}
	return ResponderURL(a, leaf)
}

func ocspRefusal(res OCSPResult, serial string, a Anchor) error {
	switch res.Status {
	case OCSPRevoked:
		return rejectCert(fleetv1.ErrorReason_ERROR_REASON_REVOKED_OCSP,
			"the OCSP responder for operator CA %s says serial %s is revoked", a.name(), serial)
	case OCSPUnknown:
		return rejectCert(fleetv1.ErrorReason_ERROR_REASON_OCSP_UNKNOWN,
			"the OCSP responder for operator CA %s says serial %s is unknown, which counts as revoked", a.name(), serial)
	}
	return nil
}

func (r *Revocations) endOCSPOutage(anchorSHA256 string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st, ok := r.anchors[anchorSHA256]; ok && st.ocspOutage {
		st.ocspOutage = false
		r.logf("operatorca: the OCSP responder for operator CA %s answers again", st.anchor.name())
	}
}

func (r *Revocations) noteOCSPOutageLocked(st *anchorState, responder string, now time.Time) {
	if st.lastOCSPLog.IsZero() || now.Sub(st.lastOCSPLog) >= staleLogEvery {
		st.lastOCSPLog = now
		r.logf("operatorca: WARNING OCSP responder unreachable for operator CA %s (%s) and no fresh CRL; allowing under operatorRevocationPolicy soft",
			st.anchor.name(), redact(responder))
	}
	if !st.ocspOutage {
		st.ocspOutage = true
		r.audit(store.AuditEvent{
			Kind: KindOCSPUnavailable,
			Summary: fmt.Sprintf("No fresh OCSP response and no fresh CRL for operator CA %s; certificates are allowed under operatorRevocationPolicy soft until the responder answers",
				st.anchor.name()),
			TargetKind: "operator-ca",
			TargetPath: "/operator-cas/" + st.anchor.SHA256,
		})
	}
}

func (r *Revocations) noteStaleLocked(st *anchorState, now time.Time) {
	if st.lastStaleLog.IsZero() || now.Sub(st.lastStaleLog) >= staleLogEvery {
		st.lastStaleLog = now
		if st.crl == nil {
			r.logf("operatorca: WARNING operator CA %s CRL NOT YET ENFORCED: no CRL has been loaded; enforcing the denylist only", st.anchor.name())
		} else {
			r.logf("operatorca: WARNING the CRL for operator CA %s is past nextUpdate (%s); enforcing the last good CRL and the denylist",
				st.anchor.name(), st.crl.List.NextUpdate.UTC().Format(time.RFC3339))
		}
	}
	if st.crl != nil && !st.expiredAudited {
		st.expiredAudited = true
		r.audit(store.AuditEvent{
			Kind: KindCRLExpired,
			Summary: fmt.Sprintf("The CRL for operator CA %s expired at %s; the last good CRL and the denylist stay enforced",
				st.anchor.name(), st.crl.List.NextUpdate.UTC().Format(time.RFC3339)),
			TargetKind: "operator-ca",
			TargetPath: "/operator-cas/" + st.anchor.SHA256,
		})
	}
}

// CheckMCP is CheckMCPCert when only the serial is known, so an aia-mode
// anchor has no responder URI and no OCSP check.
func (r *Revocations) CheckMCP(anchorSHA256, serial string) error {
	n, ok := new(big.Int).SetString(NormalizeSerial(serial), 16)
	if !ok {
		return rejectCert(fleetv1.ErrorReason_ERROR_REASON_REVOKED, "serial %q isn't hex", serial)
	}
	return r.checkMCP(anchorSHA256, n, nil)
}

// CheckMCPCert is the stricter decision for MCP keys, which are long-lived
// bearer credentials: the serial must not be revoked, this replica's last
// successful revocation poll must be under 5 minutes old, and the anchor
// must have a CRL source whose CRL is within nextUpdate. Both policies fail
// closed here. When OCSP is configured for the certificate and a fresh
// response is available, it must be good; an OCSP failure is allowed,
// because the fresh CRL covers it.
func (r *Revocations) CheckMCPCert(anchorSHA256 string, cert *x509.Certificate) error {
	return r.checkMCP(anchorSHA256, cert.SerialNumber, cert)
}

func (r *Revocations) checkMCP(anchorSHA256 string, serial *big.Int, cert *x509.Certificate) error {
	key := SerialKey(serial)
	a, err := r.checkMCPSets(anchorSHA256, key)
	if err != nil {
		return err
	}
	responder := r.responderFor(a, cert)
	if responder == "" {
		return nil
	}
	res, err := r.ocsp.Check(a, serial, responder, func(s string) bool { return r.IsRevoked(anchorSHA256, s) })
	if err != nil {
		return nil
	}
	r.endOCSPOutage(anchorSHA256)
	return ocspRefusal(res, key, a)
}

func (r *Revocations) checkMCPSets(anchorSHA256, serial string) (Anchor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.anchors[anchorSHA256]
	if !ok {
		return Anchor{}, unknownAnchor(anchorSHA256)
	}
	if r.revokedLocked(anchorSHA256, serial) {
		return Anchor{}, revoked(serial, st.anchor)
	}
	now := r.now()
	if now.Sub(r.polledAt) > maxDenylistAge {
		return Anchor{}, noRevocationSource(fleetv1.ErrorReason_ERROR_REASON_STALE_DENYLIST,
			"the last successful revocation poll was at %s, more than 5 minutes ago", r.polledAt.UTC().Format(time.RFC3339))
	}
	if !st.anchor.HasCRL() {
		return Anchor{}, noRevocationSource(fleetv1.ErrorReason_ERROR_REASON_NO_CRL,
			"operator CA %s has no CRL source, and MCP needs one", st.anchor.name())
	}
	if st.crl == nil || !st.crl.Fresh(now) {
		return Anchor{}, noRevocationSource(fleetv1.ErrorReason_ERROR_REASON_STALE_CRL,
			"no CRL within nextUpdate for operator CA %s", st.anchor.name())
	}
	return st.anchor, nil
}

// Status reports the anchor's revocation state on this replica.
func (r *Revocations) Status(anchorSHA256 string) AnchorStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.anchors[anchorSHA256]
	if !ok {
		return AnchorStatus{}
	}
	now := r.now()
	out := AnchorStatus{CRLConfigured: st.anchor.HasCRL(), LastError: st.lastError}
	if st.ocspOutage {
		out.OCSPBanner = fmt.Sprintf("OCSP responder unreachable for %s.", st.anchor.name())
	}
	if !st.anchor.HasCRL() {
		out.Badge = BadgeNotObserved
		if st.anchor.OCSPMode != "" && st.anchor.OCSPMode != store.OCSPModeOff {
			out.Badge = BadgeOCSPOnly
		}
		return out
	}
	if st.crl == nil {
		out.Banner = fmt.Sprintf("No CRL has been loaded for operator CA %s yet.", st.anchor.name())
		return out
	}
	out.CRLLoaded = true
	out.ThisUpdate, out.NextUpdate = st.crl.List.ThisUpdate, st.crl.List.NextUpdate
	out.RevokedCount = len(st.crl.Revoked)
	out.CRLFresh = st.crl.Fresh(now)
	window := st.crl.List.NextUpdate.Sub(st.crl.List.ThisUpdate)
	switch {
	case !out.CRLFresh:
		out.Banner = fmt.Sprintf("The CRL for operator CA %s expired at %s.", st.anchor.name(), out.NextUpdate.UTC().Format(time.RFC3339))
	case st.crl.List.NextUpdate.Sub(now) < time.Duration(float64(window)*expiringShare):
		out.Banner = fmt.Sprintf("The CRL for operator CA %s expires at %s.", st.anchor.name(), out.NextUpdate.UTC().Format(time.RFC3339))
		if st.anchor.CRLSource == store.CRLSourceUpload {
			out.Banner = fmt.Sprintf("Upload a new CRL for operator CA %s before %s.", st.anchor.name(), out.NextUpdate.UTC().Format(time.RFC3339))
		}
	}
	return out
}

// Rebuilder rebuilds the trusted anchor set from the store.
type Rebuilder interface {
	Rebuild(ctx context.Context) error
}

// DefaultPollInterval is how often each replica checks for other replicas'
// trust and revocation changes.
const DefaultPollInterval = 5 * time.Second

// Poller watches the store's trust version: an operator CA change rebuilds
// the trust store, a revocation epoch change reloads the denylist and CRLs.
type Poller struct {
	st    store.OperatorTrust
	trust Rebuilder
	rev   *Revocations
	logf  func(string, ...any)
	last  store.TrustVersion
	first bool
}

// NewPoller builds a Poller. trust may be nil when the anchors can't change
// at runtime (the config-file source).
func NewPoller(st store.OperatorTrust, trust Rebuilder, rev *Revocations, logf func(string, ...any)) *Poller {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Poller{st: st, trust: trust, rev: rev, logf: logf, first: true}
}

// PollOnce checks the trust version once.
func (p *Poller) PollOnce(ctx context.Context) error {
	v, err := p.st.OperatorTrustVersion(ctx)
	if err != nil {
		return fmt.Errorf("operatorca: poll trust version: %w", err)
	}
	if p.trust != nil && (p.first || v.CAs != p.last.CAs) {
		if err := p.trust.Rebuild(ctx); err != nil {
			return err
		}
	}
	if p.first || v.Epoch != p.last.Epoch {
		if err := p.rev.Reload(ctx); err != nil {
			return err
		}
	} else {
		p.rev.MarkPolled()
	}
	p.last, p.first = v, false
	return nil
}

// Run polls every interval until ctx ends, logging failures. A replica that
// can't poll keeps enforcing what it has; MCP stops after 5 minutes.
func (p *Poller) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.PollOnce(ctx); err != nil {
				p.logf("operatorca: trust poll failed, keeping the last good state: %v", err)
			}
		}
	}
}

// Denylisted reports whether the manager's denylist lists serial under the
// anchor.
func (r *Revocations) Denylisted(anchorSHA256, serial string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.denylist[anchorSHA256][NormalizeSerial(serial)]
	return ok
}

// CRLRevoked reports whether the anchor's last good CRL lists serial.
func (r *Revocations) CRLRevoked(anchorSHA256, serial string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.anchors[anchorSHA256]
	return ok && st.crl != nil && st.crl.IsRevoked(NormalizeSerial(serial))
}
