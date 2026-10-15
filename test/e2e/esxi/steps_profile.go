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
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// leafProfile builds the catalog CertificateProfile this run creates and
// pushes to the primary node, with validityDays as given: the profile step
// creates it at 30 days, then updates it to 60 to prove UpdateProfile and a
// second ApplyProfileToNode both land.
func leafProfile(name string, validityDays uint32) *nodev1.CertificateProfile {
	return &nodev1.CertificateProfile{
		Name:             name,
		KeyAlg:           "ECDSA-P384",
		Subject:          &nodev1.Subject{CommonName: "cryptos e2e leaf"},
		ValidityDays:     validityDays,
		BasicConstraints: &nodev1.BasicConstraints{IsCa: false},
		KeyUsage:         []string{"digital_signature"},
		ExtKeyUsage:      []string{"client_auth"},
	}
}

// profileStep exercises CreateProfile, ApplyProfileToNode, UpdateProfile (a
// second apply), SetProfileRequestable, ListRequestableProfiles and
// DeleteProfile, checking on the node itself (via GetConfig) that the pushed
// profile actually lands in its stored Pki.profiles both times.
func (s *scenario) profileStep() step {
	return step{name: "profiles/create-apply-update-delete", run: func(ctx context.Context) (string, error) {
		primary, err := s.primary()
		if err != nil {
			return "", err
		}
		id, name := s.nodeRef(primary)

		if _, err := s.fleet.CreateProfile(ctx, connect.NewRequest(&fleetv1.CreateProfileRequest{Profile: leafProfile(s.profile, 30)})); err != nil {
			return "", fmt.Errorf("CreateProfile: %w", err)
		}
		if _, err := s.fleet.ApplyProfileToNode(ctx, connect.NewRequest(&fleetv1.ApplyProfileToNodeRequest{NodeId: id, NodeName: name, ProfileName: s.profile})); err != nil {
			return "", fmt.Errorf("ApplyProfileToNode: %w", err)
		}
		if err := s.checkNodeHasProfile(primary, s.profile, 30); err != nil {
			return "", err
		}

		if _, err := s.fleet.UpdateProfile(ctx, connect.NewRequest(&fleetv1.UpdateProfileRequest{Profile: leafProfile(s.profile, 60)})); err != nil {
			return "", fmt.Errorf("UpdateProfile: %w", err)
		}
		if _, err := s.fleet.ApplyProfileToNode(ctx, connect.NewRequest(&fleetv1.ApplyProfileToNodeRequest{NodeId: id, NodeName: name, ProfileName: s.profile})); err != nil {
			return "", fmt.Errorf("ApplyProfileToNode (update): %w", err)
		}
		if err := s.checkNodeHasProfile(primary, s.profile, 60); err != nil {
			return "", err
		}

		if _, err := s.fleet.SetProfileRequestable(ctx, connect.NewRequest(&fleetv1.SetProfileRequestableRequest{Name: s.profile, Requestable: true})); err != nil {
			return "", fmt.Errorf("SetProfileRequestable: %w", err)
		}
		listed, err := s.fleet.ListRequestableProfiles(ctx, connect.NewRequest(&fleetv1.ListRequestableProfilesRequest{}))
		if err != nil {
			return "", fmt.Errorf("ListRequestableProfiles: %w", err)
		}
		if !containsProfile(listed.Msg.GetItems(), s.profile) {
			return "", fmt.Errorf("ListRequestableProfiles does not list %s after SetProfileRequestable(true)", s.profile)
		}

		if _, err := s.fleet.DeleteProfile(ctx, connect.NewRequest(&fleetv1.DeleteProfileRequest{Name: s.profile})); err != nil {
			return "", fmt.Errorf("DeleteProfile: %w", err)
		}
		return fmt.Sprintf("created, applied, updated, made requestable and deleted catalog profile %s on %s", s.profile, primary.Name), nil
	}}
}

// checkNodeHasProfile dials n directly and confirms its own stored config
// carries a profile named name with exactly wantValidityDays, the on-the-node
// proof that ApplyProfileToNode did more than return success.
func (s *scenario) checkNodeHasProfile(n nodeUnderTest, name string, wantValidityDays uint32) error {
	c, err := dialNode(n)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.GetConfig(context.Background())
	if err != nil {
		return fmt.Errorf("GetConfig on %s: %w", n.Name, err)
	}
	for _, p := range resp.GetConfig().GetPki().GetProfiles() {
		if p.GetName() == name {
			if p.GetValidityDays() != wantValidityDays {
				return fmt.Errorf("%s's stored profile %s has validity_days %d, want %d", n.Name, name, p.GetValidityDays(), wantValidityDays)
			}
			return nil
		}
	}
	return fmt.Errorf("%s's stored config has no profile named %s after ApplyProfileToNode", n.Name, name)
}

func containsProfile(items []*nodev1.CertificateProfile, name string) bool {
	for _, p := range items {
		if p.GetName() == name {
			return true
		}
	}
	return false
}
