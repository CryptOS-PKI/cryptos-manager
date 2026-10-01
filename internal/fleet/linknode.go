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
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	connect "connectrpc.com/connect"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/nodeclient"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// linkCARequired refuses a LINK request that names nothing to verify the
// node against.
func linkCARequired(cause error) error {
	return apperr.Coded(apperr.CodeLinkCARequired, connect.NewError(connect.CodeInvalidArgument, cause))
}

// requireLinkCA refuses an empty ca_pem before the node is dialled.
func requireLinkCA(caPEM string) error {
	if strings.TrimSpace(caPEM) == "" {
		return linkCARequired(errors.New("fleet: LINK needs ca_pem: the CA certificate that signed the node's management certificate, or that certificate itself"))
	}
	return nil
}

// linkDialError classifies a failed LINK dial: a node whose certificate did
// not verify, one that could not be reached, a ca_pem with no certificate, or
// connection material that would not parse.
func linkDialError(err error) error {
	err = fmt.Errorf("fleet: dial node: %w", err)
	log.Printf("fleet: LINK: %v", err)
	switch {
	case errors.Is(err, nodeclient.ErrNodeUntrusted):
		return apperr.Coded(apperr.CodeNodeUntrusted, connect.NewError(connect.CodeFailedPrecondition, err))
	case errors.Is(err, nodeclient.ErrNodeUnreachable):
		return apperr.Coded(apperr.CodeNodeUnreachable, connect.NewError(connect.CodeUnavailable, err))
	case errors.Is(err, nodeclient.ErrCAPEMRequired):
		return linkCARequired(err)
	default:
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
}

// linkPlan is what a LINK approval will register, worked out before the
// node is told it is managed, so a node that can't be registered is never
// half-linked.
type linkPlan struct {
	// existing is the inventory node already at the endpoint, if any; it is
	// kept as it is.
	existing *store.Node
	name     string
	endpoint string
	certPEM  string
	keyPEM   string
	caPEM    string
	// pinned is true when ca_pem holds the node's own management
	// certificate rather than its CA.
	pinned bool
}

// planLinkedNode decides how an approved LINK joins the inventory. A node
// already registered at the endpoint keeps its entry. Otherwise the node
// gets a name derived from its CA's common name, and the approval is
// refused if another node already has that name.
func (s *Service) planLinkedNode(proposedName, endpoint, certPEM, keyPEM, caPEM string) (linkPlan, error) {
	for _, n := range s.store.Nodes() {
		if n.Endpoint == endpoint {
			return linkPlan{existing: &n, name: n.Name, endpoint: endpoint}, nil
		}
	}

	certs, err := parseLinkCAPEM(caPEM)
	if err != nil {
		return linkPlan{}, linkCARequired(err)
	}
	pinned := false
	for _, c := range certs {
		if !c.IsCA {
			pinned = true
		}
	}

	name := linkNodeName(proposedName, endpoint)
	if n, ok := s.store.Node(name); ok {
		return linkPlan{}, apperr.Coded(apperr.CodeNodeNameTaken, connect.NewError(connect.CodeAlreadyExists,
			fmt.Errorf("fleet: LINK: node name %q is already used by node %s at %s; rename that node first", name, n.ID, n.Endpoint)))
	}
	return linkPlan{name: name, endpoint: endpoint, certPEM: certPEM, keyPEM: keyPEM, caPEM: caPEM, pinned: pinned}, nil
}

// registerLinkedNode saves the LINK's admin credential and trust next to
// each other in the node credentials folder, as adoption does, and adds the
// node to the inventory. ca_pem is recorded as the node's CA chain, or as
// its pinned server certificate when it is the node's own certificate.
func (s *Service) registerLinkedNode(ctx context.Context, conn NodeConn, p linkPlan) (store.Node, error) {
	if p.existing != nil {
		log.Printf("fleet: LINK: node at %s is already inventory node %s (%s); keeping its entry", p.endpoint, p.existing.Name, p.existing.ID)
		return *p.existing, nil
	}

	certPath, keyPath := adminCredPaths(p.name)
	dir := filepath.Dir(certPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return store.Node{}, fmt.Errorf("fleet: LINK: save credentials for %s: %w", p.name, err)
	}
	trustPath := filepath.Join(dir, caChainFile)
	if p.pinned {
		trustPath = filepath.Join(dir, nodeclient.ServerCertFile)
	}
	for path, content := range map[string]string{certPath: p.certPEM, keyPath: p.keyPEM, trustPath: p.caPEM} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return store.Node{}, fmt.Errorf("fleet: LINK: save credentials for %s: %w", p.name, err)
		}
	}

	role := "node"
	if cfg, err := conn.GetConfig(ctx); err == nil {
		role = adoptedNodeRole(cfg.GetConfig())
	} else {
		log.Printf("fleet: LINK: node %s: could not read its config for the role, recording %q: %v", p.name, role, err)
	}

	n := store.Node{
		ID:        store.NewNodeID(),
		Name:      p.name,
		Endpoint:  p.endpoint,
		Role:      role,
		AdminCert: certPath,
		AdminKey:  keyPath,
	}
	if !p.pinned {
		n.CACert = trustPath
	}
	s.store.AddNode(n)
	registered, ok := s.store.Node(p.name)
	if !ok {
		return store.Node{}, fmt.Errorf("fleet: LINK: node %s vanished after it was added", p.name)
	}
	mode := "its CA chain"
	if p.pinned {
		mode = "its pinned server certificate"
	}
	log.Printf("fleet: LINK: node %s (%s) at %s joined the inventory, verified by %s at %s", registered.Name, registered.ID, registered.Endpoint, mode, trustPath)
	return registered, nil
}

// parseLinkCAPEM parses the certificates in a LINK's ca_pem.
func parseLinkCAPEM(caPEM string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for rest := []byte(caPEM); ; {
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
			return nil, fmt.Errorf("fleet: LINK ca_pem: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("fleet: LINK ca_pem holds no PEM certificate")
	}
	return certs, nil
}

// linkNodeName derives an inventory name for a linked node from its CA's
// common name: lowercase, with every run of other characters turned into one
// hyphen, cut to 63 characters. A name that comes out empty falls back to
// "node-" and the endpoint's host. The operator can rename it afterwards.
func linkNodeName(cn, endpoint string) string {
	if name := nodeLabelFrom(cn); name != "" {
		return name
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	return nodeLabelFrom("node-" + host)
}

func nodeLabelFrom(s string) string {
	var b strings.Builder
	hyphen := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			hyphen = false
			continue
		}
		if !hyphen && b.Len() > 0 {
			b.WriteByte('-')
			hyphen = true
		}
	}
	name := b.String()
	if len(name) > 63 {
		name = name[:63]
	}
	name = strings.Trim(name, "-")
	if store.IsNodeID(name) {
		return ""
	}
	return name
}
