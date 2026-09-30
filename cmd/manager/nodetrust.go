package main

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
	"fmt"
	"io"

	"github.com/CryptOS-PKI/manager/internal/config"
	"github.com/CryptOS-PKI/manager/internal/nodeclient"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// insecureNodeSet names the nodes whose config sets insecureSkipNodeVerify.
// It is keyed by the configured name: a node renamed since is verified again,
// which fails safe.
type insecureNodeSet map[string]bool

func insecureNodes(cfg config.Config) insecureNodeSet {
	set := insecureNodeSet{}
	for _, n := range cfg.Nodes {
		if n.InsecureSkipNodeVerify {
			set[n.Name] = true
		}
	}
	return set
}

func (s insecureNodeSet) skip(n store.Node) bool { return s[n.Name] }

// options returns the nodeclient dial options for n.
func (s insecureNodeSet) options(n store.Node) []nodeclient.Option {
	if s.skip(n) {
		return []nodeclient.Option{nodeclient.InsecureSkipNodeVerify()}
	}
	return nil
}

// reportNodeTrust writes one line per node saying how its server certificate
// is verified, flags the nodes that will be refused and the ones that skip
// verification, and returns how many nodes will be refused.
func reportNodeTrust(w io.Writer, nodes []store.Node, insecure insecureNodeSet) (refused int) {
	for _, n := range nodes {
		mode, err := nodeclient.NodeTrust(n, insecure.options(n)...)
		switch {
		case err != nil:
			refused++
			_, _ = fmt.Fprintf(w, "node trust: %s (%s): REFUSED: %v\n", n.Name, n.Endpoint, err)
		case mode == nodeclient.TrustNone:
			refused++
			_, _ = fmt.Fprintf(w, "node trust: %s (%s): REFUSED: no CA chain is recorded and no server certificate is pinned; pin it at %s or with -pin-node\n",
				n.Name, n.Endpoint, nodeclient.PinPath(n))
		case mode == nodeclient.TrustInsecure:
			_, _ = fmt.Fprintf(w, "node trust: %s (%s): WARNING server certificate NOT verified: insecureSkipNodeVerify is set; lab testing only, never in production\n",
				n.Name, n.Endpoint)
		default:
			_, _ = fmt.Fprintf(w, "node trust: %s (%s): %s\n", n.Name, n.Endpoint, mode)
		}
	}
	return refused
}

// pinNode pins the server certificate the named node presents, provided its
// SHA-256 is the one the operator read on the node's console.
func pinNode(nodes []store.Node, name, expectSHA256 string) (string, error) {
	for _, n := range nodes {
		if n.Name == name {
			return nodeclient.PinServerCert(n, expectSHA256)
		}
	}
	return "", fmt.Errorf("no node named %q in the inventory", name)
}
