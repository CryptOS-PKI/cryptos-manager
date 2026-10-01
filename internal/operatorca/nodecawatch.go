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
	"crypto/x509"
	"fmt"
	"sync"
)

// NodeCAWatch catches, at runtime, a trusted operator CA that turns out to be
// a CryptOS node's CA: a node reached through GetIdentity reports a chain
// holding the anchor, or a certificate with the anchor's public key. The
// start-up check only sees the CA chains the inventory had then.
//
// A match logs one ERROR per anchor and raises an admin banner flag. The
// anchor stays trusted: dropping it mid-run could lock every admin out.
// For the config-file source the next start refuses it.
type NodeCAWatch struct {
	trust *TrustStore
	logf  func(string, ...any)

	mu    sync.Mutex
	flags map[string]string
}

// NewNodeCAWatch builds a watch over trust's current anchors.
func NewNodeCAWatch(trust *TrustStore, logf func(string, ...any)) *NodeCAWatch {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &NodeCAWatch{trust: trust, logf: logf, flags: map[string]string{}}
}

// Observe checks the chain a node reported against the trusted anchors.
// Certificates that don't parse are skipped.
func (w *NodeCAWatch) Observe(node string, chainDER [][]byte) {
	if w == nil || w.trust == nil {
		return
	}
	var chain []*x509.Certificate
	for _, der := range chainDER {
		if c, err := x509.ParseCertificate(der); err == nil {
			chain = append(chain, c)
		}
	}
	if len(chain) == 0 {
		return
	}
	for _, a := range w.trust.Anchors() {
		nodeCA := matchingNodeCA(a.Cert, chain)
		if nodeCA == nil {
			continue
		}
		w.mu.Lock()
		_, seen := w.flags[a.SHA256]
		if !seen {
			w.flags[a.SHA256] = fmt.Sprintf(
				"Operator CA %s is the CA of CryptOS node %s. A CryptOS node can't be the operator CA: replace it with an external operator CA.",
				a.Cert.Subject.CommonName, node)
		}
		w.mu.Unlock()
		if !seen {
			w.logf("operatorca: ERROR operator CA %s (SHA-256 %s, source %s) is the CA of CryptOS node %s (%s, same certificate or key); "+
				"it stays trusted until the next start so no admin is locked out, but a CryptOS node can't be the operator CA: replace it with an external operator CA",
				a.Cert.Subject, ColonFingerprint(a.Cert.Raw), w.trust.Source().Kind, node, nodeCA.Subject)
		}
	}
}

// Flags returns the banner text for each flagged anchor, keyed by its
// fingerprint.
func (w *NodeCAWatch) Flags() map[string]string {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]string, len(w.flags))
	for k, v := range w.flags {
		out[k] = v
	}
	return out
}
