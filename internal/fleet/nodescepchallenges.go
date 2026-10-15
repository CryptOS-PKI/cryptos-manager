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
	"errors"
	"fmt"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// requireOperatorLevel resolves the caller's identity and returns a
// PermissionDenied error unless the caller is at least operator level.
func requireOperatorLevel(ctx context.Context) (authz.Identity, error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return authz.Identity{}, err
	}
	if id.Level < authz.LevelOperator {
		return authz.Identity{}, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}
	return id, nil
}

// MintNodeScepChallenge mints a one-time SCEP challenge password on a
// managed node, for example to enroll a network device via its SCEP
// trustpoint. Operator-gated and audited; the challenge_password itself is
// never written to the audit log, only the challenge's id and profile.
func (s *Service) MintNodeScepChallenge(ctx context.Context, req *connect.Request[fleetv1.MintNodeScepChallengeRequest]) (*connect.Response[fleetv1.MintNodeScepChallengeResponse], error) {
	if _, err := requireOperatorLevel(ctx); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("MintNodeScepChallenge", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.MintScepChallenge(ctx, req.Msg.GetProfile(), req.Msg.GetTtlSeconds(), req.Msg.GetBoundNames())
	if err != nil {
		return nil, nodeError("mint scep challenge", err)
	}

	challenge := nodeScepChallengeFromProto(resp.GetChallenge())
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-scep-challenge-minted",
		Summary:    fmt.Sprintf("Minted a SCEP challenge (%s) on %s for profile %q", challenge.GetId(), node.Name, challenge.GetProfile()),
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})

	return connect.NewResponse(&fleetv1.MintNodeScepChallengeResponse{
		ChallengePassword: resp.GetChallengePassword(),
		Challenge:         challenge,
	}), nil
}

// ListNodeScepChallenges lists a managed node's usable SCEP challenges,
// soonest to expire first. Operator-gated; a read, so it is not audited.
func (s *Service) ListNodeScepChallenges(ctx context.Context, req *connect.Request[fleetv1.ListNodeScepChallengesRequest]) (*connect.Response[fleetv1.ListNodeScepChallengesResponse], error) {
	if _, err := requireOperatorLevel(ctx); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("ListNodeScepChallenges", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.ListScepChallenges(ctx)
	if err != nil {
		return nil, nodeError("list scep challenges", err)
	}

	challenges := make([]*fleetv1.NodeScepChallenge, 0, len(resp.GetChallenges()))
	for _, c := range resp.GetChallenges() {
		challenges = append(challenges, nodeScepChallengeFromProto(c))
	}

	return connect.NewResponse(&fleetv1.ListNodeScepChallengesResponse{Challenges: challenges}), nil
}

// RevokeNodeScepChallenge withdraws a managed node's SCEP challenge before it
// is used or expires. Operator-gated and audited.
func (s *Service) RevokeNodeScepChallenge(ctx context.Context, req *connect.Request[fleetv1.RevokeNodeScepChallengeRequest]) (*connect.Response[fleetv1.RevokeNodeScepChallengeResponse], error) {
	if _, err := requireOperatorLevel(ctx); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("RevokeNodeScepChallenge", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	id := req.Msg.GetId()
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: id is required"))
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.RevokeScepChallenge(ctx, id)
	if err != nil {
		return nil, nodeError("revoke scep challenge", err)
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-scep-challenge-revoked",
		Summary:    fmt.Sprintf("Revoked SCEP challenge %s on %s", id, node.Name),
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})

	return connect.NewResponse(&fleetv1.RevokeNodeScepChallengeResponse{
		Challenge: nodeScepChallengeFromProto(resp.GetChallenge()),
	}), nil
}

// nodeScepChallengeFromProto flattens a node's ScepChallenge into the fleet
// API's display shape: RFC3339 timestamps in place of the node's protobuf
// timestamps.
func nodeScepChallengeFromProto(c *nodev1.ScepChallenge) *fleetv1.NodeScepChallenge {
	return &fleetv1.NodeScepChallenge{
		Id:          c.GetId(),
		Profile:     c.GetProfile(),
		BoundNames:  c.GetBoundNames(),
		CreatedAt:   formatTimestamp(c.GetCreatedAt()),
		ExpiresAt:   formatTimestamp(c.GetExpiresAt()),
		CreatedByCn: c.GetCreatedByCn(),
	}
}
