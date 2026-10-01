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
	"encoding/pem"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// NodeCAs collects the CryptOS node CA certificates the inventory knows, from
// each node's CA chain file, so an operator CA can be refused when it is one
// of them. A node with no chain file is skipped; one whose file can't be read
// is skipped with a log line.
func NodeCAs(nodes []store.Node, readFile func(string) ([]byte, error), logf func(string, ...any)) []*x509.Certificate {
	var out []*x509.Certificate
	for _, n := range nodes {
		if n.CACert == "" {
			continue
		}
		b, err := readFile(n.CACert)
		if err != nil {
			logf("operatorca: WARNING can't read the CA chain of node %s to check operator CAs against it: %v", n.Name, err)
			continue
		}
		for rest := b; ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				logf("operatorca: WARNING a certificate in the CA chain of node %s doesn't parse: %v", n.Name, err)
				continue
			}
			out = append(out, c)
		}
	}
	return out
}
