package fleet

/*
Apache License 2.0

Copyright 2026 Shane

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// adoptCredsBaseDir is where the manager writes the per-node bootstrap admin
// key material it mints during adoption (Option A: the manager holds each
// managed node's admin key). Defaults to a standard state path; override with
// MANAGER_NODE_CREDS_DIR (e.g. a writable dir in local dev).
var adoptCredsBaseDir = func() string {
	if d := os.Getenv("MANAGER_NODE_CREDS_DIR"); d != "" {
		return d
	}
	return "/var/lib/cryptos-manager/node-creds"
}()

// mintedAdmin is a freshly generated bootstrap admin client identity: the
// self-signed client certificate the node will trust (embedded in the config's
// bootstrap.admin_cert_pem) and the private key the manager keeps to dial the
// node's admin mTLS endpoint afterward.
type mintedAdmin struct {
	certPEM []byte
	keyPEM  []byte
}

// mintBootstrapAdmin generates a self-signed ECDSA P-256 client certificate for
// the fleet admin identity. The node pins this exact certificate as its trusted
// bootstrap admin; the manager presents the matching key when it dials the node.
func mintBootstrapAdmin(cn string) (*mintedAdmin, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mint admin: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("mint admin: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute).UTC(),
		NotAfter:              time.Now().AddDate(10, 0, 0).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("mint admin: create certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("mint admin: marshal key: %w", err)
	}
	return &mintedAdmin{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// writeAdminCreds persists the minted admin cert+key to a per-node directory and
// returns the file paths, which the inventory Node records so nodeclient.Dial
// can load them for managed operations.
func writeAdminCreds(node string, a *mintedAdmin) (certPath, keyPath string, err error) {
	certPath, keyPath = adminCredPaths(node)
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return "", "", fmt.Errorf("write admin creds: mkdir: %w", err)
	}
	if err := os.WriteFile(certPath, a.certPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write admin creds: cert: %w", err)
	}
	if err := os.WriteFile(keyPath, a.keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write admin creds: key: %w", err)
	}
	return certPath, keyPath, nil
}

// adminCredPaths returns where a node's bootstrap admin cert and key live.
func adminCredPaths(node string) (certPath, keyPath string) {
	dir := filepath.Join(adoptCredsBaseDir, node)
	return filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key")
}

// loadOrMintAdmin returns the bootstrap admin for node. An admin minted by an
// earlier adoption attempt is reused, because once that attempt reached
// ApplyConfig the node's staged config pins that exact cert and refuses any
// other; minting a new one would lock the manager out of the node. It also
// keeps a repeat adoption of an adopted node from overwriting the key its
// managed operations use. Only when no usable pair is stored is a new admin
// minted and written.
func loadOrMintAdmin(node string) (a *mintedAdmin, certPath, keyPath string, reused bool, err error) {
	certPath, keyPath = adminCredPaths(node)
	certPEM, cerr := os.ReadFile(certPath)
	keyPEM, kerr := os.ReadFile(keyPath)
	switch {
	case cerr == nil && kerr == nil:
		_, perr := tls.X509KeyPair(certPEM, keyPEM)
		if perr == nil {
			log.Printf("fleet: adopt %s: reusing the bootstrap admin from an earlier attempt (%s)", node, certPath)
			return &mintedAdmin{certPEM: certPEM, keyPEM: keyPEM}, certPath, keyPath, true, nil
		}
		log.Printf("fleet: adopt %s: stored bootstrap admin is unusable, minting a new one: %v", node, perr)
	case errors.Is(cerr, fs.ErrNotExist) && errors.Is(kerr, fs.ErrNotExist):
		log.Printf("fleet: adopt %s: no stored bootstrap admin, minting one", node)
	default:
		log.Printf("fleet: adopt %s: stored bootstrap admin is incomplete, minting a new one (cert: %v, key: %v)", node, cerr, kerr)
	}

	a, err = mintBootstrapAdmin("fleet-admin@" + node)
	if err != nil {
		return nil, "", "", false, err
	}
	certPath, keyPath, err = writeAdminCreds(node, a)
	if err != nil {
		return nil, "", "", false, err
	}
	return a, certPath, keyPath, false, nil
}
