package fleet

/*
Apache License 2.0

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
	"errors"
	"fmt"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// RekeyNode re-keys a subordinate CA in one orchestrated call, mirroring the
// SUBORDINATE path of ApproveEnrollment. It is operator-gated: it resolves the
// named child node, has the child mint a new key + CSR (BeginKeyRotation),
// resolves the parent from the child's issuer CN, routes the CSR to the parent
// for signing under the request profile (SignSubordinateCSR), and delivers the
// signed chain back to the child (CompleteKeyRotation) so it adopts the rotated
// key. On success it appends a single "rekeyed" audit event and returns the
// re-keyed identity's subject/issuer CN and chain length.
//
// A denied caller, an unknown child, or a parent that is not a known fleet node
// never reaches CompleteKeyRotation and never writes an audit event; the
// parent-not-in-fleet case is a clear failed-precondition (manual ferry is out
// of scope for v1.0.0).
func (s *Service) RekeyNode(ctx context.Context, req *connect.Request[fleetv1.RekeyNodeRequest]) (*connect.Response[fleetv1.RekeyNodeResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	name := req.Msg.GetNodeName()
	child, ok := s.store.Node(name)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: node %q not found", name))
	}

	subjectCN, issuerCN, chainLen, err := s.runRekeyFerry(ctx, child, req.Msg.GetProfileName())
	if err != nil {
		return nil, err
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "rekeyed",
		Summary:    fmt.Sprintf("Re-keyed %s under %s", name, issuerCN),
		TargetKind: "node",
		TargetPath: "/nodes/" + name,
	})

	return connect.NewResponse(&fleetv1.RekeyNodeResponse{
		SubjectCn: subjectCN,
		IssuerCn:  issuerCN,
		ChainLen:  chainLen,
	}), nil
}

// runRekeyFerry drives the three-call re-key sequence: the child mints a new
// key and hands over its rotation CSR, the parent (resolved from the child's
// issuer CN) signs it under profile, and the signed chain is delivered back to
// the child so it adopts the rotated key. It reuses runSubordinateFerry's
// chain-field mapping (SignSubordinateCSR's chain_der/chain_pem feed
// CompleteKeyRotation verbatim) to avoid a DER/PEM mismatch. It returns the
// re-keyed identity's subject/issuer CN and chain length read from the adopted
// chain. Every dialed conn is closed. Any node-step failure is mapped to a
// Connect error so no audit is written on failure.
func (s *Service) runRekeyFerry(ctx context.Context, child store.Node, profile string) (subjectCN, issuerCN string, chainLen int32, err error) {
	cc, err := s.dial(child)
	if err != nil {
		return "", "", 0, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial child %q: %w", child.Name, err))
	}
	defer func() { _ = cc.Close() }()

	begin, err := cc.BeginKeyRotation(ctx)
	if err != nil {
		return "", "", 0, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: begin key rotation on %q: %w", child.Name, err))
	}

	issuer, err := s.childIssuerCN(ctx, child)
	if err != nil {
		return "", "", 0, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: read child issuer for %q: %w", child.Name, err))
	}

	parent, err := s.resolveParentByCN(ctx, issuer)
	if err != nil {
		return "", "", 0, connect.NewError(connect.CodeFailedPrecondition, err)
	}

	// A self-signed root's leaf has subject CN == issuer CN, so resolveParentByCN
	// resolves the child as its own parent. Re-keying through the ferry would then
	// ask the root to re-sign itself under a subordinate profile. Rotating a root's
	// key is not a fleet-mediated operation, so refuse it.
	if parent.Name == child.Name {
		return "", "", 0, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("fleet: node %q is its own issuer (self-signed root); re-key through the manager is only for subordinate CAs", child.Name))
	}

	pc, err := s.dial(parent)
	if err != nil {
		return "", "", 0, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial parent %q: %w", parent.Name, err))
	}
	defer func() { _ = pc.Close() }()

	signed, err := pc.SignSubordinateCSR(ctx, begin.GetCsrDer(), profile)
	if err != nil {
		return "", "", 0, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: sign rotation csr on %q: %w", parent.Name, err))
	}

	done, err := cc.CompleteKeyRotation(ctx, signed.GetChainDer(), signed.GetChainPem())
	if err != nil {
		return "", "", 0, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: complete key rotation on %q: %w", child.Name, err))
	}

	newIdentity := done.GetIdentity()
	subjectCN, issuerCN = leafCNs(newIdentity)
	return subjectCN, issuerCN, int32(len(newIdentity.GetChainDer())), nil
}

// childIssuerCN dials the child and reads its current identity's issuer CN,
// which names the parent CA the re-key ferry must resolve. It uses a fresh dial
// so it does not consume the ferry connection's canned responses in tests.
func (s *Service) childIssuerCN(ctx context.Context, child store.Node) (string, error) {
	conn, err := s.dial(child)
	if err != nil {
		return "", fmt.Errorf("dial child %q: %w", child.Name, err)
	}
	defer func() { _ = conn.Close() }()

	idResp, err := conn.GetIdentity(ctx)
	if err != nil {
		return "", fmt.Errorf("get identity from %q: %w", child.Name, err)
	}
	_, issuer := leafCNs(idResp.GetIdentity())
	if issuer == "" {
		return "", fmt.Errorf("child %q has no resolvable issuer CN", child.Name)
	}
	return issuer, nil
}
