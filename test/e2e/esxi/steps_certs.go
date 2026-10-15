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
	"context"
	"crypto/x509"
	"fmt"
	"math/big"

	connect "connectrpc.com/connect"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// certStep exercises IssueLeaf and RevokeCertificate under the profile the
// profile step pushed to the primary node, and checks both results on the
// node itself: ListIssued must carry the new serial, and after the revoke
// ListRevocations must carry it too.
func (s *scenario) certStep() step {
	return step{name: "certificates/issue-and-revoke", run: func(ctx context.Context) (string, error) {
		primary, err := s.primary()
		if err != nil {
			return "", err
		}
		id, name := s.nodeRef(primary)

		csrDER, _, err := generateCSR("e2e-leaf.example.org")
		if err != nil {
			return "", err
		}
		issued, err := s.fleet.IssueLeaf(ctx, connect.NewRequest(&fleetv1.IssueLeafRequest{
			NodeId: id, NodeName: name, CsrDer: csrDER, ProfileName: s.profile,
		}))
		if err != nil {
			return "", fmt.Errorf("IssueLeaf: %w", err)
		}
		leaf, err := x509.ParseCertificate(issued.Msg.GetCertDer())
		if err != nil {
			return "", fmt.Errorf("parsing issued leaf: %w", err)
		}

		c, err := dialNode(primary)
		if err != nil {
			return "", err
		}
		defer func() { _ = c.Close() }()

		listed, err := c.ListIssued(ctx)
		if err != nil {
			return "", fmt.Errorf("ListIssued on %s: %w", primary.Name, err)
		}
		if !issuedContains(listed.GetIssued(), leaf.SerialNumber) {
			return "", fmt.Errorf("%s's own ListIssued does not carry the certificate IssueLeaf just returned", primary.Name)
		}

		if _, err := s.fleet.RevokeCertificate(ctx, connect.NewRequest(&fleetv1.RevokeCertificateRequest{
			NodeId: id, NodeName: name, SerialHex: fmt.Sprintf("%x", leaf.SerialNumber), ReasonCode: 0,
		})); err != nil {
			return "", fmt.Errorf("RevokeCertificate: %w", err)
		}

		revoked, err := c.ListRevocations(ctx)
		if err != nil {
			return "", fmt.Errorf("ListRevocations on %s: %w", primary.Name, err)
		}
		if !revocationsContains(revoked.GetRevocations(), leaf.SerialNumber) {
			return "", fmt.Errorf("%s's own ListRevocations does not carry the certificate RevokeCertificate just revoked", primary.Name)
		}
		return fmt.Sprintf("issued and revoked a leaf on %s, confirmed on the node both times", primary.Name), nil
	}}
}

func issuedContains(items []*nodev1.IssuedCert, serial *big.Int) bool {
	for _, c := range items {
		if serialMatches(c.GetSerialHex(), serial) {
			return true
		}
	}
	return false
}

func revocationsContains(items []*nodev1.Revocation, serial *big.Int) bool {
	for _, r := range items {
		if serialMatches(r.GetSerialHex(), serial) {
			return true
		}
	}
	return false
}
