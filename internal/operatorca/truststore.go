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
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
)

const verifyCacheSize = 1024

// trustGen is one generation of trusted anchors: the pool the handshake
// verifies against and the TLS config that carries it.
type trustGen struct {
	n        uint64
	pool     *x509.CertPool
	anchors  map[string]Anchor
	settings string
	tlsCfg   *tls.Config
}

type verifyKey struct {
	leaf [sha256.Size]byte
	gen  uint64
}

type verifyResult struct {
	anchor   Anchor
	notAfter time.Time
}

// TrustStore holds the operator CAs trusted now, as numbered generations.
// The registered source builds a new generation whenever the rows change;
// the file source builds one at start. The handshake gets the current
// generation through GetConfigForClient, and every request is re-verified
// against it with VerifyPeer, so a retired CA stops working on the next
// request rather than the next handshake.
type TrustStore struct {
	src  Source
	st   store.OperatorTrust
	rev  *Revocations
	base *tls.Config
	logf func(string, ...any)
	now  func() time.Time

	mu    sync.Mutex
	gen   atomic.Pointer[trustGen]
	cache *lru[verifyKey, verifyResult]

	verifications atomic.Int64
}

// NewTrustStore builds the first generation from src and hands its anchors
// to rev. base is the server TLS config every generation is cloned from; it
// must carry the server certificate and the ALPN protocols.
func NewTrustStore(ctx context.Context, src Source, st store.OperatorTrust, rev *Revocations, base *tls.Config, logf func(string, ...any)) (*TrustStore, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	t := &TrustStore{src: src, st: st, rev: rev, base: base, logf: logf, now: time.Now, cache: newLRU[verifyKey, verifyResult](verifyCacheSize)}
	anchors, err := t.load(ctx)
	if err != nil {
		return nil, err
	}
	if err := t.install(anchors, 1); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *TrustStore) load(ctx context.Context) ([]Anchor, error) {
	switch t.src.Kind {
	case KindFile:
		return t.src.File, nil
	case KindRegistered:
		rows, err := t.st.OperatorCAs(ctx)
		if err != nil {
			return nil, fmt.Errorf("operatorca: read operator CAs: %w", err)
		}
		var out []Anchor
		for _, row := range rows {
			if row.State != store.OperatorCAActive && row.State != store.OperatorCARetiring {
				continue
			}
			cert, err := x509.ParseCertificate(row.CertDER)
			if err != nil {
				t.logf("operatorca: ERROR the registered operator CA %s doesn't parse and is not trusted: %v", row.SHA256, err)
				continue
			}
			if Fingerprint(cert) != row.SHA256 {
				t.logf("operatorca: ERROR the registered operator CA %s has a certificate with another fingerprint and is not trusted", row.SHA256)
				continue
			}
			out = append(out, Anchor{
				Cert: cert, SHA256: row.SHA256, State: row.State,
				CRLSource: row.CRLSource, CRLLocation: row.CRLURL, OCSPMode: row.OCSPMode, OCSPURL: row.OCSPURL,
			})
		}
		return out, nil
	default:
		return nil, nil
	}
}

func settingsOf(anchors []Anchor) string {
	parts := make([]string, 0, len(anchors))
	for _, a := range anchors {
		parts = append(parts, strings.Join([]string{a.SHA256, a.State, a.CRLSource, a.CRLLocation, a.OCSPMode, a.OCSPURL}, "|"))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

func (t *TrustStore) install(anchors []Anchor, n uint64) error {
	pool := x509.NewCertPool()
	byFP := make(map[string]Anchor, len(anchors))
	for _, a := range anchors {
		pool.AddCert(a.Cert)
		byFP[a.SHA256] = a
	}

	// Every generation gets fresh session ticket keys, so a session resumed
	// from an older generation can't skip the new trust.
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return fmt.Errorf("operatorca: ticket key: %w", err)
	}
	cfg := t.base.Clone()
	cfg.GetConfigForClient = nil
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	// Never nil: a nil pool would make the handshake fall back to the
	// system roots.
	cfg.ClientCAs = pool
	cfg.SetSessionTicketKeys([][32]byte{key})

	t.gen.Store(&trustGen{n: n, pool: pool, anchors: byFP, settings: settingsOf(anchors), tlsCfg: cfg})
	t.rev.SetAnchors(anchors)
	t.logAnchors(anchors, n)
	return nil
}

func (t *TrustStore) logAnchors(anchors []Anchor, n uint64) {
	if len(anchors) == 0 {
		t.logf("operatorca: WARNING no operator CA is trusted (source %s, generation %d); every API caller is refused", t.src.Kind, n)
		return
	}
	for _, a := range anchors {
		t.logf("operatorca: trusting operator CA %s, SHA-256 %s (source %s, %s, generation %d)",
			a.Cert.Subject, ColonFingerprint(a.Cert.Raw), t.src.Kind, a.State, n)
	}
}

// Rebuild re-reads the registered rows and installs a new generation if the
// trusted set or its settings changed. It does nothing for the file source.
func (t *TrustStore) Rebuild(ctx context.Context) error {
	if t.src.Kind != KindRegistered {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	anchors, err := t.load(ctx)
	if err != nil {
		return err
	}
	cur := t.gen.Load()
	if settingsOf(anchors) == cur.settings {
		return nil
	}
	return t.install(anchors, cur.n+1)
}

// GetConfigForClient hands the handshake the current generation's TLS
// config. Set it as the server's tls.Config.GetConfigForClient.
func (t *TrustStore) GetConfigForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	return t.gen.Load().tlsCfg, nil
}

// Roots returns the current generation's pool.
func (t *TrustStore) Roots() *x509.CertPool {
	return t.gen.Load().pool
}

// Anchors returns the current generation's anchors.
func (t *TrustStore) Anchors() []Anchor {
	g := t.gen.Load()
	out := make([]Anchor, 0, len(g.anchors))
	for _, a := range g.anchors {
		out = append(out, a)
	}
	return out
}

// Source returns the resolved source.
func (t *TrustStore) Source() Source { return t.src }

// VerifyPeer verifies a client certificate, with the intermediates the peer
// sent, against the current generation for client auth and returns the
// anchor it chains to. Results are cached per leaf and generation.
func (t *TrustStore) VerifyPeer(leaf *x509.Certificate, intermediates []*x509.Certificate) (Anchor, error) {
	g := t.gen.Load()
	now := t.now()
	key := verifyKey{leaf: sha256.Sum256(leaf.Raw), gen: g.n}
	if hit, ok := t.cache.get(key); ok && now.Before(hit.notAfter) {
		return hit.anchor, nil
	}

	t.verifications.Add(1)
	inter := x509.NewCertPool()
	for _, c := range intermediates {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: g.pool, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return Anchor{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_NOT_CHAINED,
			"the certificate no longer chains to a trusted operator CA: %v", err)
	}
	root := chains[0][len(chains[0])-1]
	a, ok := g.anchors[Fingerprint(root)]
	if !ok {
		return Anchor{}, rejectCert(fleetv1.ErrorReason_ERROR_REASON_NOT_CHAINED, "the certificate chains to %s, which isn't trusted", root.Subject)
	}
	t.cache.put(key, verifyResult{anchor: a, notAfter: leaf.NotAfter})
	return a, nil
}

// PeerAuthorizer is the authz.PeerAuthorizer the web path uses: the chain
// against the current trust, then the web revocation decision.
type PeerAuthorizer struct {
	Trust *TrustStore
	Rev   *Revocations
}

// AuthorizePeer re-verifies a peer certificate and checks its revocation.
// The chain check comes first, so an OCSP URI is only ever read from a
// certificate the operator CA issued.
func (p PeerAuthorizer) AuthorizePeer(leaf *x509.Certificate, intermediates []*x509.Certificate) (string, error) {
	a, err := p.Trust.VerifyPeer(leaf, intermediates)
	if err != nil {
		return "", err
	}
	if err := p.Rev.CheckWebCert(a.SHA256, leaf); err != nil {
		return "", err
	}
	return a.SHA256, nil
}

// AdmitMCP decides whether an operator certificate may hold an MCP key: it
// must chain to a trusted operator CA and pass the MCP revocation rules.
func (p PeerAuthorizer) AdmitMCP(certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return rejectCert(fleetv1.ErrorReason_ERROR_REASON_NOT_CHAINED, "the certificate doesn't parse: %v", err)
	}
	a, err := p.Trust.VerifyPeer(cert, nil)
	if err != nil {
		return err
	}
	return p.Rev.CheckMCPCert(a.SHA256, cert)
}
