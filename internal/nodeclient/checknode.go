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
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// checkTimeout bounds one CheckNode handshake.
const checkTimeout = 10 * time.Second

// CheckNode connects to node, presenting its admin certificate, and runs the
// same verification Dial runs on the certificate the node presents. It
// returns how the node is verified and nil when the node would be accepted,
// or the refusal (or the connection failure) otherwise. A node with nothing
// to verify against returns TrustNone and an error without being dialled; a
// node with insecureSkipNodeVerify returns TrustInsecure without being
// dialled, since it is accepted whatever it presents.
func CheckNode(node store.Node, opts ...Option) (TrustMode, error) {
	t, err := loadServerTrust(node, opts)
	if err != nil {
		return "", err
	}
	mode := t.mode()
	switch mode {
	case TrustInsecure:
		return mode, nil
	case TrustNone:
		return mode, fmt.Errorf("nodeclient: node %s refused: no CA chain is recorded and no server certificate is pinned; pin it at %s or with -pin-node", node.Name, t.pinPath)
	}

	adminCert, err := tls.LoadX509KeyPair(node.AdminCert, node.AdminKey)
	if err != nil {
		return mode, fmt.Errorf("nodeclient: load admin cert/key for %s: %w", node.Name, err)
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: checkTimeout}, "tcp", node.Endpoint, &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &adminCert, nil
		},
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection by the node's recorded trust, as Dial does.
		VerifyConnection:   t.verify,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return mode, fmt.Errorf("nodeclient: check %s (%s): %w", node.Name, node.Endpoint, err)
	}
	_ = conn.Close()
	return mode, nil
}
