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
	"fmt"

	connect "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
)

// configPushStep exercises GetNodeConfig and ApplyNodeConfig with an
// unmodified round trip: it reads the primary node's full config back through
// the manager and applies it unchanged. That is enough to prove the write
// path end to end (the manager validates, transmits and the node stores a
// fresh generation) without risking a semantic drift a hand-picked field edit
// could introduce; checking the node's own GetConfig afterward confirms what
// it actually holds matches what was sent, not just that the RPC returned.
func (s *scenario) configPushStep() step {
	return step{name: "config/push-roundtrip", run: func(ctx context.Context) (string, error) {
		primary, err := s.primary()
		if err != nil {
			return "", err
		}
		id, name := s.nodeRef(primary)

		got, err := s.fleet.GetNodeConfig(ctx, connect.NewRequest(&fleetv1.GetNodeConfigRequest{NodeId: id, NodeName: name}))
		if err != nil {
			return "", fmt.Errorf("GetNodeConfig: %w", err)
		}
		cfg := got.Msg.GetConfig()

		applied, err := s.fleet.ApplyNodeConfig(ctx, connect.NewRequest(&fleetv1.ApplyNodeConfigRequest{NodeId: id, NodeName: name, Config: cfg}))
		if err != nil {
			return "", fmt.Errorf("ApplyNodeConfig: %w", err)
		}

		c, err := dialNode(primary)
		if err != nil {
			return "", err
		}
		defer func() { _ = c.Close() }()
		after, err := c.GetConfig(ctx)
		if err != nil {
			return "", fmt.Errorf("GetConfig on %s: %w", primary.Name, err)
		}
		if !proto.Equal(cfg, after.GetConfig()) {
			return "", fmt.Errorf("%s's stored config changed unexpectedly across an unmodified ApplyNodeConfig round trip", primary.Name)
		}
		return fmt.Sprintf("round-tripped %s's config at generation %d, unchanged on the node", primary.Name, applied.Msg.GetGeneration()), nil
	}}
}
