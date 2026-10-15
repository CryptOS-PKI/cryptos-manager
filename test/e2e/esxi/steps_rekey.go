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
	"bytes"
	"context"
	"fmt"

	connect "connectrpc.com/connect"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
)

// rekeyStep exercises RekeyNode: re-issuing a subordinate CA's own key and
// certificate under its current parent is destructive to whatever already
// trusts its old identity, so it only runs when E2E_REKEY_NODE and
// E2E_REKEY_PROFILE opt a specific node in; otherwise it skips. On success it
// checks the node's own GetIdentity for a changed leaf fingerprint.
func (s *scenario) rekeyStep(cfg config) step {
	return step{name: "rekey/subordinate-ca", run: func(ctx context.Context) (string, error) {
		if cfg.RekeyNode == "" || cfg.RekeyProfile == "" {
			return "", skip("E2E_REKEY_NODE/E2E_REKEY_PROFILE not set; rekeying a shared node is destructive, so it needs an explicit target")
		}
		target, ok := s.findNode(cfg.RekeyNode)
		if !ok {
			return "", fmt.Errorf("E2E_REKEY_NODE names %q, which is not in E2E_NODES_FILE", cfg.RekeyNode)
		}
		id, name := s.nodeRef(target)

		c, err := dialNode(target)
		if err != nil {
			return "", err
		}
		before, err := c.GetIdentity(ctx)
		_ = c.Close()
		if err != nil {
			return "", fmt.Errorf("GetIdentity on %s before rekey: %w", target.Name, err)
		}
		beforeSHA := before.GetIdentity().GetLeafSha256()

		resp, err := s.fleet.RekeyNode(ctx, connect.NewRequest(&fleetv1.RekeyNodeRequest{NodeId: id, NodeName: name, ProfileName: cfg.RekeyProfile}))
		if err != nil {
			return "", fmt.Errorf("RekeyNode: %w", err)
		}

		c2, err := dialNode(target)
		if err != nil {
			return "", err
		}
		defer func() { _ = c2.Close() }()
		after, err := c2.GetIdentity(ctx)
		if err != nil {
			return "", fmt.Errorf("GetIdentity on %s after rekey: %w", target.Name, err)
		}
		afterSHA := after.GetIdentity().GetLeafSha256()
		if len(beforeSHA) > 0 && bytes.Equal(beforeSHA, afterSHA) {
			return "", fmt.Errorf("%s's identity leaf fingerprint did not change after RekeyNode", target.Name)
		}
		return fmt.Sprintf("rekeyed %s under %s (new subject %s, issuer %s)", target.Name, cfg.RekeyProfile, resp.Msg.GetSubjectCn(), resp.Msg.GetIssuerCn()), nil
	}}
}

// findNode looks up a configured node (static or spare) by name.
func (s *scenario) findNode(name string) (nodeUnderTest, bool) {
	for _, n := range s.nodes {
		if n.Name == name {
			return n, true
		}
	}
	if s.spare != nil && s.spare.Name == name {
		return *s.spare, true
	}
	return nodeUnderTest{}, false
}
