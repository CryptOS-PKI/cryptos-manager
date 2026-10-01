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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"golang.org/x/sync/singleflight"
)

// OCSP cache lifetimes (RFC 6960; the manager's own bounds).
const (
	ocspMaxTTL      = time.Hour
	ocspNoNextTTL   = 5 * time.Minute
	ocspFailureTTL  = 30 * time.Second
	ocspCacheSize   = 4096
	maxOCSPGETBytes = 255
)

// Audit kinds written for OCSP.
const (
	KindOCSPUnknown     = "operator-ocsp-unknown"
	KindOCSPUnavailable = "operator-ocsp-unavailable"
)

// OCSPOptions configures an OCSPClient.
type OCSPOptions struct {
	// Fetch carries the requests; NewOCSPFetcher gives the standard limits.
	Fetch *Fetcher
	Now   func() time.Time
	Logf  func(string, ...any)
	// Audit records an audit event on behalf of the manager itself.
	Audit func(store.AuditEvent)
	// Background runs a half-life refresh; it defaults to a goroutine.
	Background func(func())
}

type ocspKey struct {
	anchor string
	serial string
}

// ocspEntry is one cached outcome: a validated response, or a failure
// ("no fresh response") that is kept for 30 seconds.
type ocspEntry struct {
	result      OCSPResult
	err         error
	fetchedAt   time.Time
	expires     time.Time
	nextRefresh time.Time
	refreshing  bool
}

// OCSPClient asks operator CAs' OCSP responders about operator
// certificates. It keeps a per-replica LRU of validated responses for
// min(nextUpdate, 1 h), or 5 minutes without a nextUpdate, refreshes an
// entry in the background once it is half way through its life and still
// in use, single-flights a miss per certificate, and remembers a failure
// for 30 seconds so a dead responder doesn't slow every request.
type OCSPClient struct {
	fetch *Fetcher
	now   func() time.Time
	logf  func(string, ...any)
	audit func(store.AuditEvent)
	bg    func(func())
	cache *lru[ocspKey, *ocspEntry]
	group singleflight.Group

	errMu   sync.Mutex
	lastErr map[string]string
}

// NewOCSPFetcher is a Fetcher with the OCSP limits: the CRL fetch limits
// with a 64 KiB body cap.
func NewOCSPFetcher() *Fetcher {
	return NewFetcher(FetchLimits{Timeout: DefaultFetchTimeout, MaxBytes: MaxOCSPSize})
}

// NewOCSPClient builds an OCSPClient.
func NewOCSPClient(o OCSPOptions) *OCSPClient {
	c := &OCSPClient{fetch: o.Fetch, now: o.Now, logf: o.Logf, audit: o.Audit, bg: o.Background,
		cache: newLRU[ocspKey, *ocspEntry](ocspCacheSize), lastErr: map[string]string{}}
	if c.fetch == nil {
		c.fetch = NewOCSPFetcher()
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.logf == nil {
		c.logf = func(string, ...any) {}
	}
	if c.audit == nil {
		c.audit = func(store.AuditEvent) {}
	}
	if c.bg == nil {
		c.bg = func(f func()) { go f() }
	}
	return c
}

// ResponderURL is where to ask about leaf under a: the anchor's URL in url
// mode, the leaf's authorityInfoAccess OCSP URI in aia mode, nothing when
// OCSP is off or an aia leaf carries no URI. The leaf must already have
// been verified to chain to a, so only the CA can choose the URI.
func ResponderURL(a Anchor, leaf *x509.Certificate) string {
	switch a.OCSPMode {
	case store.OCSPModeURL:
		return a.OCSPURL
	case store.OCSPModeAIA:
		if leaf != nil && len(leaf.OCSPServer) > 0 {
			return leaf.OCSPServer[0]
		}
	}
	return ""
}

// cached returns the live cache entry for a certificate.
func (c *OCSPClient) cached(anchor string, serial *big.Int) (ocspEntry, bool) {
	e, ok := c.cache.get(ocspKey{anchor, SerialKey(serial)})
	if !ok {
		return ocspEntry{}, false
	}
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()
	if !c.now().Before(e.expires) {
		return ocspEntry{}, false
	}
	return *e, true
}

// ClearAnchor drops every cached response for an operator CA, for when its
// OCSP settings change.
func (c *OCSPClient) ClearAnchor(anchorSHA256 string) {
	c.cache.remove(func(k ocspKey) bool { return k.anchor == anchorSHA256 })
	c.noteResult(anchorSHA256, "", nil)
}

// Check returns the status of serial under a from the cache, or from one
// synchronous, single-flighted fetch from responderURL. An error means no
// fresh response; its sub-reason is OCSP_UNREACHABLE or OCSP_INVALID.
// isRevoked is the anchor's denylist and CRL, used for a delegated
// responder certificate without noCheck.
func (c *OCSPClient) Check(a Anchor, serial *big.Int, responderURL string, isRevoked func(serial string) bool) (OCSPResult, error) {
	key := ocspKey{a.SHA256, SerialKey(serial)}
	now := c.now()
	if e, ok := c.cache.get(key); ok {
		c.cache.mu.Lock()
		live := now.Before(e.expires)
		refresh := live && e.err == nil && !e.refreshing && !now.Before(e.nextRefresh)
		if refresh {
			e.refreshing = true
		}
		res, err := e.result, e.err
		c.cache.mu.Unlock()
		if refresh {
			c.bg(func() { c.refresh(key, a, serial, responderURL, isRevoked) })
		}
		if live {
			return res, err
		}
	}
	v, _, _ := c.group.Do(key.anchor+"/"+key.serial, func() (any, error) {
		return c.fill(key, a, serial, responderURL, isRevoked, nil), nil
	})
	e := v.(*ocspEntry)
	return e.result, e.err
}

// refresh fetches again in the background. A failed refresh keeps the
// response still in its lifetime and allows another try after 30 seconds.
func (c *OCSPClient) refresh(key ocspKey, a Anchor, serial *big.Int, responderURL string, isRevoked func(string) bool) {
	old, _ := c.cache.get(key)
	_, _, _ = c.group.Do(key.anchor+"/"+key.serial, func() (any, error) {
		return c.fill(key, a, serial, responderURL, isRevoked, old), nil
	})
}

func (c *OCSPClient) fill(key ocspKey, a Anchor, serial *big.Int, responderURL string, isRevoked func(string) bool, old *ocspEntry) *ocspEntry {
	res, err := c.lookup(context.Background(), a.Cert, serial, responderURL, isRevoked)
	c.noteResult(a.SHA256, responderURL, err)
	now := c.now()
	if err != nil {
		c.logf("operatorca: OCSP check of serial %s under operator CA %s at %s failed (%s): %v",
			key.serial, a.name(), redact(responderURL), ocspClass(err), err)
		if old != nil {
			c.cache.mu.Lock()
			live := now.Before(old.expires)
			if live {
				old.refreshing = false
				old.nextRefresh = now.Add(ocspFailureTTL)
			}
			c.cache.mu.Unlock()
			if live {
				return old
			}
		}
		e := &ocspEntry{err: err, fetchedAt: now, expires: now.Add(ocspFailureTTL)}
		c.cache.put(key, e)
		return e
	}
	expires := now.Add(ocspMaxTTL)
	switch {
	case res.NextUpdate.IsZero():
		expires = now.Add(ocspNoNextTTL)
	case res.NextUpdate.Before(expires):
		expires = res.NextUpdate
	}
	e := &ocspEntry{result: res, fetchedAt: now, expires: expires, nextRefresh: now.Add(expires.Sub(now) / 2)}
	c.cache.put(key, e)
	if res.Status == OCSPUnknown {
		c.audit(store.AuditEvent{
			Kind: KindOCSPUnknown,
			Summary: fmt.Sprintf("The OCSP responder for operator CA %s answered unknown for serial %s; the certificate is refused as revoked",
				a.name(), key.serial),
			TargetKind: "operator-ca",
			TargetPath: "/operator-cas/" + a.SHA256,
		})
	}
	return e
}

// Probe checks at registration that responderURL answers for anchor: it
// asks about a random serial and needs a validly signed response, whatever
// the status. A failure is 1605 OCSP_UNREACHABLE or OCSP_INVALID.
func (c *OCSPClient) Probe(ctx context.Context, anchor *x509.Certificate, responderURL string) error {
	_, err := c.ProbeResult(ctx, anchor, responderURL)
	return err
}

// ProbeResult is Probe returning the validated answer, including the
// certificate that signed it.
func (c *OCSPClient) ProbeResult(ctx context.Context, anchor *x509.Certificate, responderURL string) (OCSPResult, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return OCSPResult{}, fmt.Errorf("operatorca: OCSP probe serial: %w", err)
	}
	b[0] &= 0x7f
	b[0] |= 0x40
	serial := new(big.Int).SetBytes(b)
	res, err := c.lookup(ctx, anchor, serial, responderURL, nil)
	if err != nil {
		c.logf("operatorca: OCSP probe of %s for operator CA %s failed (%s): %v", redact(responderURL), anchor.Subject.CommonName, ocspClass(err), err)
		return OCSPResult{}, err
	}
	c.logf("operatorca: OCSP probe of %s for operator CA %s answered %s, signed by %s", redact(responderURL), anchor.Subject.CommonName, res.Status, res.Signer.Subject)
	return res, nil
}

// LastError is this replica's last OCSP failure for a certificate under the
// operator CA, empty when the responder last answered or nothing failed.
func (c *OCSPClient) LastError(anchorSHA256 string) string {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.lastErr[anchorSHA256]
}

func (c *OCSPClient) noteResult(anchorSHA256, responderURL string, err error) {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if err == nil {
		delete(c.lastErr, anchorSHA256)
		return
	}
	c.lastErr[anchorSHA256] = fmt.Sprintf("%s from %s at %s", ocspClass(err), redact(responderURL), c.now().UTC().Format(time.RFC3339))
}

func ocspClass(err error) string {
	if r, ok := apperr.ReasonOf(err); ok && r == fleetv1.ErrorReason_ERROR_REASON_OCSP_INVALID {
		return "OCSP_INVALID"
	}
	return "OCSP_UNREACHABLE"
}

func (c *OCSPClient) lookup(ctx context.Context, anchor *x509.Certificate, serial *big.Int, responderURL string, isRevoked func(string) bool) (OCSPResult, error) {
	q, err := newOCSPQuery(anchor, serial)
	if err != nil {
		return OCSPResult{}, ocspInvalid("build the request: %v", err)
	}
	start := c.now()
	body, err := c.post(ctx, responderURL, q.der)
	if err != nil {
		return OCSPResult{}, err
	}
	res, err := q.validate(body, c.now(), isRevoked)
	if err == nil {
		c.logf("operatorca: OCSP %s for serial %s from %s in %s", res.Status, SerialKey(serial), redact(responderURL), c.now().Sub(start))
	}
	return res, err
}

// post sends the request by POST. Only when the responder refuses POST
// with 405 and the base64 request is under 255 bytes does it retry with
// GET (RFC 6960 appendix A.1).
func (c *OCSPClient) post(ctx context.Context, responderURL string, der []byte) ([]byte, error) {
	body, err := c.fetch.request(ctx, http.MethodPost, responderURL, "application/ocsp-request", bytes.NewReader(der))
	var se *httpStatusError
	if errors.As(err, &se) && se.code == http.StatusMethodNotAllowed {
		enc := url.PathEscape(base64.StdEncoding.EncodeToString(der))
		if len(enc) < maxOCSPGETBytes {
			body, err = c.fetch.request(ctx, http.MethodGet, strings.TrimSuffix(responderURL, "/")+"/"+enc, "", nil)
		}
	}
	switch {
	case errors.Is(err, errBodyTooLarge):
		return nil, ocspInvalid("the response is more than %d bytes", MaxOCSPSize)
	case err != nil:
		return nil, ocspUnreachable("%s: %v", redact(responderURL), err)
	}
	return body, nil
}
