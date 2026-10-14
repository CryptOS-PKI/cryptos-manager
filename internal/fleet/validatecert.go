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

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
)

// ValidateCertificateChain checks whether a submitted certificate chains to a
// managed node's CA, the check cryptosctl identity validate runs locally
// against a node's own chain. It is operator-gated, since it parses
// operator-supplied certificate material: it verifies the caller is at least
// operator level, resolves the named node, fetches the node's own identity
// chain, parses the submitted PEM (the first block is the certificate to
// check; any further blocks are intermediates that help it reach the node's
// CA), and verifies the first against a pool built from the node's chain plus
// those intermediates. A certificate that does not chain is reported as
// valid=false with a reason, not an RPC error; only a parse failure, an
// unknown node, or a node error is one.
func (s *Service) ValidateCertificateChain(ctx context.Context, req *connect.Request[fleetv1.ValidateCertificateChainRequest]) (*connect.Response[fleetv1.ValidateCertificateChainResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	node, err := s.resolveNode("ValidateCertificateChain", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	subject, intermediates, err := parseCertificateChainPEM(req.Msg.GetCertificatePem())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("fleet: certificate_pem: %w", err))
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	identity, err := conn.GetIdentity(ctx)
	if err != nil {
		return nil, nodeError("validate certificate chain", err)
	}

	nodeChain, err := parseCertificateChainDER(identity.GetIdentity().GetChainDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: node %q identity: %w", node.Name, err))
	}
	if len(nodeChain) == 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("fleet: node %q has no identity", node.Name))
	}

	roots := x509.NewCertPool()
	roots.AddCert(nodeChain[len(nodeChain)-1])
	pool := x509.NewCertPool()
	for _, c := range nodeChain[1:] {
		pool.AddCert(c)
	}
	for _, c := range intermediates {
		pool.AddCert(c)
	}

	resp := &fleetv1.ValidateCertificateChainResponse{
		Subject:       subject.Subject.String(),
		Issuer:        subject.Issuer.String(),
		NodeCaSubject: nodeChain[0].Subject.String(),
	}
	// KeyUsages: ExtKeyUsageAny, since this checks only that the certificate
	// chains to the node's CA, not that it was issued for TLS server auth
	// (crypto/x509's default when KeyUsages is empty).
	opts := x509.VerifyOptions{Roots: roots, Intermediates: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	if _, verifyErr := subject.Verify(opts); verifyErr != nil {
		resp.Reason = verifyErr.Error()
	} else {
		resp.Valid = true
	}

	return connect.NewResponse(resp), nil
}

// parseCertificateChainPEM parses one or more PEM CERTIFICATE blocks,
// returning the first as the certificate to validate and the rest as
// intermediates. An empty input, a block that is not a CERTIFICATE, or a
// block that does not parse as X.509 is an error.
func parseCertificateChainPEM(certPEM string) (subject *x509.Certificate, intermediates []*x509.Certificate, err error) {
	rest := []byte(certPEM)
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("PEM block is %q, want CERTIFICATE", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("no PEM CERTIFICATE block found")
	}
	return certs[0], certs[1:], nil
}

// parseCertificateChainDER parses a leaf-first DER chain, the shape
// GetIdentity returns.
func parseCertificateChainDER(chainDER [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(chainDER))
	for i, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse chain[%d]: %w", i, err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}
