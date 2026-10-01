package nodeclient

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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
)

// ServerCertFile is the name of the file, in the same directory as a node's
// admin certificate, that pins the node's management server certificate. It
// holds the PEM certificate the node presents, the same file cryptosctl takes
// as --trust.
const ServerCertFile = "server.crt"

// ErrNodeUntrusted is wrapped by every refusal of a node's server
// certificate: it chained to nothing the manager trusts for the node, and
// matched no pin.
var ErrNodeUntrusted = errors.New("nodeclient: node server certificate refused")

// ErrNodeUnreachable is wrapped when DialPEM can't complete a TLS handshake
// with the node for a reason other than the node's certificate.
var ErrNodeUnreachable = errors.New("nodeclient: node unreachable")

// ErrCAPEMRequired is returned by DialPEM when caPEM holds no PEM
// certificate, so there is nothing to verify the node against.
var ErrCAPEMRequired = errors.New("nodeclient: ca_pem with at least one PEM certificate is required to verify the node")

// Option adjusts how Dial verifies a node.
type Option func(*dialOptions)

type dialOptions struct {
	insecureSkipNodeVerify bool
}

// InsecureSkipNodeVerify dials the node without verifying its server
// certificate and logs a warning on every handshake. It is the per-node
// insecureSkipNodeVerify config key, for lab testing only.
func InsecureSkipNodeVerify() Option {
	return func(o *dialOptions) { o.insecureSkipNodeVerify = true }
}

// TrustMode says how a node's server certificate is verified.
type TrustMode string

const (
	// TrustCAChain verifies the node against its recorded CA chain.
	TrustCAChain TrustMode = "ca-chain"
	// TrustPinned verifies the node against its pinned server certificate.
	TrustPinned TrustMode = "pinned"
	// TrustCAChainAndPin accepts either the recorded chain or the pin.
	TrustCAChainAndPin TrustMode = "ca-chain+pinned"
	// TrustInsecure skips verification (insecureSkipNodeVerify, lab only).
	TrustInsecure TrustMode = "insecure-skip-verify"
	// TrustNone means the node has nothing to verify against and is refused.
	TrustNone TrustMode = "none"
)

// PinPath returns where node's pinned server certificate lives: ServerCertFile
// next to its admin certificate.
func PinPath(node store.Node) string {
	return filepath.Join(filepath.Dir(node.AdminCert), ServerCertFile)
}

// NodeTrust reports how Dial would verify node, from its recorded CA chain,
// its pin and opts. It reads the same files Dial reads and fails the same way
// on an unreadable or empty one.
func NodeTrust(node store.Node, opts ...Option) (TrustMode, error) {
	t, err := loadServerTrust(node, opts)
	if err != nil {
		return "", err
	}
	return t.mode(), nil
}

// serverTrust is what a node's server certificate is checked against on one
// dial.
type serverTrust struct {
	node     store.Node
	host     string
	insecure bool
	chain    *x509.CertPool
	// chainLabel names the chain in a refusal: the recorded file for an
	// inventory node, the request's ca_pem for LINK.
	chainLabel string
	// exact holds certificates accepted as an exact copy without a chain
	// or host check (LINK's ca_pem doubling as a pin).
	exact    [][]byte
	pinRoots *x509.CertPool
	pinned   [][]byte
	pinPath  string
	// hint ends a refusal with what the operator should check.
	hint string
}

// refusal is a refused node certificate. Its text is what the operator
// reads; it wraps ErrNodeUntrusted so callers can classify it.
type refusal struct{ msg string }

func (r *refusal) Error() string { return r.msg }
func (r *refusal) Unwrap() error { return ErrNodeUntrusted }

// missingChainWarned records nodes already logged as having a recorded chain
// path with no file behind it, so the line is not repeated on every dial.
var missingChainWarned sync.Map

func loadServerTrust(node store.Node, opts []Option) (*serverTrust, error) {
	var o dialOptions
	for _, opt := range opts {
		opt(&o)
	}
	host, _, err := net.SplitHostPort(node.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: endpoint %q for %s: %w", node.Endpoint, node.Name, err)
	}
	t := &serverTrust{
		node:     node,
		host:     host,
		insecure: o.insecureSkipNodeVerify,
		pinPath:  PinPath(node),
		hint:     "If the node rebooted before its CA ceremony it has a new certificate: check it against the node's console and re-pin it",
	}
	if t.insecure {
		return t, nil
	}

	if node.CACert != "" {
		certs, err := readCertFile(node.CACert)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if _, seen := missingChainWarned.LoadOrStore(node.Name, struct{}{}); !seen {
				log.Printf("nodeclient: node %s: recorded CA chain %s does not exist; the node is verified by its pin only", node.Name, node.CACert)
			}
		case err != nil:
			return nil, fmt.Errorf("nodeclient: recorded CA chain for %s: %w", node.Name, err)
		default:
			t.chain = x509.NewCertPool()
			for _, c := range certs {
				t.chain.AddCert(c)
			}
			t.chainLabel = "the recorded CA chain " + node.CACert
		}
	}

	certs, err := readCertFile(t.pinPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("nodeclient: pinned server certificate for %s: %w", node.Name, err)
	default:
		t.pinRoots = x509.NewCertPool()
		for _, c := range certs {
			t.pinRoots.AddCert(c)
			t.pinned = append(t.pinned, c.Raw)
		}
	}
	return t, nil
}

// pemServerTrust is the trust for a LINK dial: every certificate in caPEM is
// both a chain root and an exact pin.
func pemServerTrust(endpoint, caPEM string) (*serverTrust, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: endpoint %q: %w", endpoint, err)
	}
	certs, err := parseCertsPEM([]byte(caPEM), "ca_pem")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCAPEMRequired, err)
	}
	t := &serverTrust{
		node:       store.Node{Name: "at " + endpoint, Endpoint: endpoint},
		host:       host,
		chain:      x509.NewCertPool(),
		chainLabel: "the supplied ca_pem",
		hint:       "Check that ca_pem holds the CA certificate that signed the node's management certificate (cryptosctl identity show -o pem prints the chain), or the node's exact management certificate",
	}
	for _, c := range certs {
		t.chain.AddCert(c)
		t.exact = append(t.exact, c.Raw)
	}
	return t, nil
}

// probe completes one TLS handshake with endpoint under cfg and closes it,
// so a refused or unreachable node is reported before any RPC is sent.
func probe(endpoint string, cfg *tls.Config) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", endpoint, cfg)
	if err != nil {
		if errors.Is(err, ErrNodeUntrusted) {
			return err
		}
		return fmt.Errorf("%w: %s: %w", ErrNodeUnreachable, endpoint, err)
	}
	return conn.Close()
}

// readCertFile parses every PEM certificate in path. A file with none is an
// error: it would otherwise read as trust that verifies nothing.
func readCertFile(path string) ([]*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCertsPEM(pemBytes, path)
}

// parseCertsPEM parses every PEM certificate in pemBytes, naming them by
// source in errors. Input with none is an error.
func parseCertsPEM(pemBytes []byte, source string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s holds no PEM certificate", source)
	}
	return certs, nil
}

func (t *serverTrust) mode() TrustMode {
	switch {
	case t.insecure:
		return TrustInsecure
	case t.chain != nil && t.pinned != nil:
		return TrustCAChainAndPin
	case t.chain != nil:
		return TrustCAChain
	case t.pinned != nil:
		return TrustPinned
	default:
		return TrustNone
	}
}

// verify is the VerifyConnection callback: it accepts the presented
// certificate if the recorded chain or the pin vouches for it, and refuses it
// otherwise with the certificate's SHA-256 and what to do.
func (t *serverTrust) verify(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("nodeclient: node %s presented no server certificate", t.node.Name)
	}
	leaf := cs.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(sum[:])

	if t.insecure {
		log.Printf("nodeclient: WARNING node %s: server certificate NOT verified (sha256 %s): insecureSkipNodeVerify is set; lab testing only, never in production",
			t.node.Name, fingerprint)
		return nil
	}

	for _, raw := range t.exact {
		if bytes.Equal(raw, leaf.Raw) {
			return nil
		}
	}

	intermediates := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	chainsTo := func(roots *x509.CertPool) error {
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			DNSName:       t.host,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		return err
	}

	var reasons []string
	if t.chain != nil {
		err := chainsTo(t.chain)
		if err == nil {
			return nil
		}
		reasons = append(reasons, fmt.Sprintf("does not verify against %s for host %s: %v", t.chainLabel, t.host, err))
	}
	if t.pinned != nil {
		for _, raw := range t.pinned {
			if bytes.Equal(raw, leaf.Raw) {
				return nil
			}
		}
		err := chainsTo(t.pinRoots)
		if err == nil {
			return nil
		}
		reasons = append(reasons, fmt.Sprintf("does not match the pinned server certificate %s: %v", t.pinPath, err))
	}

	var r *refusal
	if len(reasons) == 0 {
		r = &refusal{msg: fmt.Sprintf("nodeclient: node %s refused: its server certificate (sha256 %s) cannot be verified: no CA chain is recorded and no server certificate is pinned. "+
			"Check the fingerprint against the Mgmt SHA-256 line on the node's console, then pin it by saving the certificate as %s or with manager -pin-node %q -expect-sha256 <fingerprint>",
			t.node.Name, fingerprint, t.pinPath, t.node.Name)}
	} else {
		r = &refusal{msg: fmt.Sprintf("nodeclient: node %s refused: its server certificate (sha256 %s) %s. %s",
			t.node.Name, fingerprint, strings.Join(reasons, "; and it "), t.hint)}
	}
	log.Print(r)
	return r
}

// FetchServerCert performs a TLS handshake with node's endpoint, presenting
// its admin certificate, and returns the server certificate the node
// presented. Nothing is verified: the caller shows or compares the
// certificate before trusting it.
func FetchServerCert(node store.Node) (*x509.Certificate, error) {
	adminCert, err := tls.LoadX509KeyPair(node.AdminCert, node.AdminKey)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: load admin cert/key for %s: %w", node.Name, err)
	}
	var leaf *x509.Certificate
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", node.Endpoint, &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &adminCert, nil
		},
		InsecureSkipVerify: true, //nolint:gosec // capture only: the caller compares the certificate before trusting it.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("nodeclient: node %s presented no server certificate", node.Name)
			}
			leaf = cs.PeerCertificates[0]
			return nil
		},
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("nodeclient: fetch server certificate from %s (%s): %w", node.Name, node.Endpoint, err)
	}
	_ = conn.Close()
	return leaf, nil
}

// WritePin saves cert as node's pinned server certificate and returns the
// file's path.
func WritePin(node store.Node, cert *x509.Certificate) (string, error) {
	path := PinPath(node)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return "", fmt.Errorf("nodeclient: write pinned server certificate for %s: %w", node.Name, err)
	}
	return path, nil
}

// PinServerCert fetches the certificate node presents and pins it, but only
// when its SHA-256 equals expectSHA256, the fingerprint the operator read on
// the node's console (any case, with or without colons or spaces). It returns
// the pin's path.
func PinServerCert(node store.Node, expectSHA256 string) (string, error) {
	want := normalizeFingerprint(expectSHA256)
	if want == "" {
		return "", fmt.Errorf("nodeclient: pin %s: the expected SHA-256 from the node's console is required", node.Name)
	}
	cert, err := FetchServerCert(node)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	if got := hex.EncodeToString(sum[:]); got != want {
		return "", fmt.Errorf("nodeclient: pin %s: the node presents sha256 %s, not the expected %s; nothing was pinned. Find out what answered on %s before pinning",
			node.Name, got, want, node.Endpoint)
	}
	return WritePin(node, cert)
}
