package fleet

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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// caChainFile is the name of the file, next to a node's admin certificate,
// where the manager records the node's CA chain once the node has one.
const caChainFile = "ca.crt"

// unverifiedDetail is the health detail of a node dialed with
// insecureSkipNodeVerify, so the fleet view shows it is not verified.
const unverifiedDetail = "server certificate not verified: insecureSkipNodeVerify is set (lab testing only)"

// WithServerCertCapture supplies the seam adoption uses to read the
// certificate an installed node presents when it comes back in running mode,
// so it can be pinned before the node is dialed. Production wires
// nodeclient.FetchServerCert.
func (s *Service) WithServerCertCapture(capture func(store.Node) (*x509.Certificate, error)) *Service {
	s.captureServerCert = capture
	return s
}

// WithUnverifiedNodes supplies the predicate naming the nodes dialed without
// server certificate verification (insecureSkipNodeVerify), which the fleet
// view flags in their health detail.
func (s *Service) WithUnverifiedNodes(unverified func(store.Node) bool) *Service {
	s.unverified = unverified
	return s
}

// withTrustState flags an up node dialed without verification.
func (s *Service) withTrustState(n store.Node, summary *fleetv1.NodeSummary) *fleetv1.NodeSummary {
	if s.unverified != nil && s.unverified(n) {
		summary.HealthDetail = unverifiedDetail
	}
	return summary
}

// recordCAChain writes chainDER (leaf-first, as the node reports it) as n's
// recorded CA chain next to its admin certificate and returns n pointing at
// it, with recorded true. A node whose CACert already names another file (a
// caCertPath the operator set) keeps it, and nothing is written.
func recordCAChain(n store.Node, chainDER [][]byte) (store.Node, bool, error) {
	if n.AdminCert == "" {
		return n, false, fmt.Errorf("fleet: record CA chain for %s: the node has no admin credential folder", n.Name)
	}
	path := filepath.Join(filepath.Dir(n.AdminCert), caChainFile)
	if n.CACert != "" && n.CACert != path {
		log.Printf("fleet: node %s: keeping the operator's CA chain %s; not recording the node's chain", n.Name, n.CACert)
		return n, false, nil
	}
	if len(chainDER) == 0 {
		return n, false, errors.New("fleet: record CA chain for " + n.Name + ": the node reported an empty chain")
	}
	var buf bytes.Buffer
	for i, der := range chainDER {
		if _, err := x509.ParseCertificate(der); err != nil {
			return n, false, fmt.Errorf("fleet: record CA chain for %s: certificate %d: %w", n.Name, i, err)
		}
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return n, false, fmt.Errorf("fleet: record CA chain for %s: %w", n.Name, err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return n, false, fmt.Errorf("fleet: record CA chain for %s: %w", n.Name, err)
	}
	n.CACert = path
	log.Printf("fleet: node %s: recorded its CA chain (%d certificate(s)) at %s", n.Name, len(chainDER), path)
	return n, true, nil
}
