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

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
)

// scepStep exercises MintNodeScepChallenge, ListNodeScepChallenges and
// RevokeNodeScepChallenge. A node only accepts a mint when its own stored
// config already names at least one Pki.scep.profiles entry: this script
// does not configure one for the primary node itself, since doing so needs a
// reboot before the listener (and so the mint) would actually work, and the
// config-push step already proves a config round trip. So this step runs
// for real only against a node the lab gate (or an earlier manual
// config-push) already enabled SCEP on; otherwise it skips with that reason.
//
// Driving an actual device enrolment through that challenge
// (ApproveNodeScepEnrollment/RejectNodeScepEnrollment) needs a real RFC 8894
// SCEP client talking to the node, separate lab tooling this script does not
// yet have; see the issue filed alongside this change.
func (s *scenario) scepStep() step {
	return step{name: "scep/mint-list-revoke-challenge", run: func(ctx context.Context) (string, error) {
		primary, err := s.primary()
		if err != nil {
			return "", err
		}
		id, name := s.nodeRef(primary)

		c, err := dialNode(primary)
		if err != nil {
			return "", err
		}
		cfg, err := c.GetConfig(ctx)
		_ = c.Close()
		if err != nil {
			return "", fmt.Errorf("GetConfig on %s: %w", primary.Name, err)
		}
		profiles := cfg.GetConfig().GetPki().GetScep().GetProfiles()
		if len(profiles) == 0 {
			return "", skip(fmt.Sprintf("%s has no pki.scep.profiles configured; nothing to mint a challenge under", primary.Name))
		}
		scepProfile := profiles[0].GetProfile()

		minted, err := s.fleet.MintNodeScepChallenge(ctx, connect.NewRequest(&fleetv1.MintNodeScepChallengeRequest{
			NodeId: id, NodeName: name, Profile: scepProfile,
		}))
		if err != nil {
			return "", fmt.Errorf("MintNodeScepChallenge: %w", err)
		}
		challengeID := minted.Msg.GetChallenge().GetId()

		listed, err := s.fleet.ListNodeScepChallenges(ctx, connect.NewRequest(&fleetv1.ListNodeScepChallengesRequest{NodeId: id, NodeName: name}))
		if err != nil {
			return "", fmt.Errorf("ListNodeScepChallenges: %w", err)
		}
		if !scepChallengeListed(listed.Msg.GetChallenges(), challengeID) {
			return "", fmt.Errorf("%s's ListNodeScepChallenges does not carry the challenge MintNodeScepChallenge just minted", primary.Name)
		}

		if _, err := s.fleet.RevokeNodeScepChallenge(ctx, connect.NewRequest(&fleetv1.RevokeNodeScepChallengeRequest{
			NodeId: id, NodeName: name, Id: challengeID,
		})); err != nil {
			return "", fmt.Errorf("RevokeNodeScepChallenge: %w", err)
		}

		after, err := s.fleet.ListNodeScepChallenges(ctx, connect.NewRequest(&fleetv1.ListNodeScepChallengesRequest{NodeId: id, NodeName: name}))
		if err != nil {
			return "", fmt.Errorf("ListNodeScepChallenges (after revoke): %w", err)
		}
		if scepChallengeListed(after.Msg.GetChallenges(), challengeID) {
			return "", fmt.Errorf("%s's ListNodeScepChallenges still carries the challenge after RevokeNodeScepChallenge", primary.Name)
		}
		return fmt.Sprintf("minted and revoked a scep challenge on %s under profile %s", primary.Name, scepProfile), nil
	}}
}

func scepChallengeListed(items []*fleetv1.NodeScepChallenge, id string) bool {
	for _, c := range items {
		if c.GetId() == id {
			return true
		}
	}
	return false
}
