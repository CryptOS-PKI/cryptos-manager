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
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/protobuf/proto"
)

// CreateProfile adds a new profile to the manager's catalog. It is admin-gated,
// rejects a nil profile or empty name (InvalidArgument), marshals the profile
// into its stored spec, and maps a name collision to AlreadyExists. On success
// it appends a single "profile-created" audit event. A denied caller, an
// invalid argument, or a store collision never writes an audit event.
func (s *Service) CreateProfile(ctx context.Context, req *connect.Request[fleetv1.CreateProfileRequest]) (*connect.Response[fleetv1.CreateProfileResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	profile := req.Msg.GetProfile()
	name, err := validateProfile(profile)
	if err != nil {
		return nil, err
	}

	p, err := marshalProfile(profile)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := s.store.CreateProfile(p); err != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("fleet: create profile: %w", err))
	}

	s.auditProfile(ctx, "profile-created", "Created profile "+name, name)

	return connect.NewResponse(&fleetv1.CreateProfileResponse{}), nil
}

// UpdateProfile replaces a catalog profile by name. It is admin-gated, rejects
// a nil profile or empty name (InvalidArgument), and maps an absent profile to
// NotFound. On success it appends a single "profile-updated" audit event. A
// denied caller, an invalid argument, or an absent profile never writes an
// audit event.
func (s *Service) UpdateProfile(ctx context.Context, req *connect.Request[fleetv1.UpdateProfileRequest]) (*connect.Response[fleetv1.UpdateProfileResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	profile := req.Msg.GetProfile()
	name, err := validateProfile(profile)
	if err != nil {
		return nil, err
	}

	p, err := marshalProfile(profile)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// UpdateProfileRequest carries no requestable field, so a plain profile
	// edit must not silently reset it; carry the stored value forward.
	if current, ok := s.store.Profile(name); ok {
		p.Requestable = current.Requestable
	}

	if err := s.store.UpdateProfile(p); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: update profile: %w", err))
	}

	s.auditProfile(ctx, "profile-updated", "Updated profile "+name, name)

	return connect.NewResponse(&fleetv1.UpdateProfileResponse{}), nil
}

// DeleteProfile removes a catalog profile by name. It is admin-gated, rejects
// an empty name (InvalidArgument), and maps an absent profile to NotFound.
// Deletion is non-cascading: node copies of the profile are untouched. On
// success it appends a single "profile-deleted" audit event.
func (s *Service) DeleteProfile(ctx context.Context, req *connect.Request[fleetv1.DeleteProfileRequest]) (*connect.Response[fleetv1.DeleteProfileResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	name := req.Msg.GetName()
	if name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: profile name is required"))
	}

	if err := s.store.DeleteProfile(name); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: delete profile: %w", err))
	}

	s.auditProfile(ctx, "profile-deleted", "Deleted profile "+name, name)

	return connect.NewResponse(&fleetv1.DeleteProfileResponse{}), nil
}

// SetProfileRequestable records whether a signed-in user may request a
// certificate under the named catalog profile via CreateCertificateRequest.
// It is admin-gated, rejects an empty name (InvalidArgument), and maps an
// absent profile to NotFound. On success it appends a single
// "profile-requestable-set" audit event.
func (s *Service) SetProfileRequestable(ctx context.Context, req *connect.Request[fleetv1.SetProfileRequestableRequest]) (*connect.Response[fleetv1.SetProfileRequestableResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	name := req.Msg.GetName()
	if name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: profile name is required"))
	}

	if _, err := s.store.SetProfileRequestable(name, req.Msg.GetRequestable()); err != nil {
		return nil, apperr.Coded(apperr.CodeProfileNotFound,
			connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: set profile requestable: %w", err)))
	}

	verb := "Marked"
	if !req.Msg.GetRequestable() {
		verb = "Unmarked"
	}
	s.auditProfile(ctx, "profile-requestable-set", fmt.Sprintf("%s profile %s requestable", verb, name), name)

	return connect.NewResponse(&fleetv1.SetProfileRequestableResponse{}), nil
}

// ListRequestableProfiles returns the catalog profiles marked requestable,
// for the "Request a certificate" picker. Any signed-in identity may list
// them; a read, so it is not audited.
func (s *Service) ListRequestableProfiles(ctx context.Context, _ *connect.Request[fleetv1.ListRequestableProfilesRequest]) (*connect.Response[fleetv1.ListRequestableProfilesResponse], error) {
	if _, err := operatorLevel(ctx); err != nil {
		return nil, err
	}

	var items []*nodev1.CertificateProfile
	for _, p := range s.store.Profiles() {
		if !p.Requestable {
			continue
		}
		cp, err := unmarshalProfile(p)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		items = append(items, cp)
	}

	return connect.NewResponse(&fleetv1.ListRequestableProfilesResponse{Items: items}), nil
}

// ApplyProfileToNode pushes a catalog profile onto a managed node. It is
// admin-gated, resolves the named catalog profile (NotFound if absent) and the
// named node (NotFound if absent), then dials the node and follows the
// whole-config-safe path S5 established: fetch the node's FULL current config,
// clone it, insert-or-replace the profile in pki.profiles[] (matched by name;
// appended if new), and apply the whole config back. Every other field of the
// fetched config -- management, role, bootstrap, and the rest -- is preserved.
// On success it appends a single "profile-applied" audit event and returns the
// node's config generation and requires_reboot. A denied caller, an unknown
// profile/node, or a node error never writes an audit event.
func (s *Service) ApplyProfileToNode(ctx context.Context, req *connect.Request[fleetv1.ApplyProfileToNodeRequest]) (*connect.Response[fleetv1.ApplyProfileToNodeResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	profileName := req.Msg.GetProfileName()
	stored, ok := s.store.Profile(profileName)
	if !ok {
		return nil, apperr.Coded(apperr.CodeProfileNotFound,
			connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: profile %q not found", profileName)))
	}
	profile, err := unmarshalProfile(stored)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	node, err := s.resolveNode("ApplyProfileToNode", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}
	nodeName := node.Name

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	current, err := conn.GetConfig(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: get config: %w", err))
	}

	// Clone the fetched config and change ONLY pki.profiles, so every other
	// field survives the whole-config replace that ApplyConfig performs.
	cfg := proto.Clone(current.GetConfig()).(*nodev1.MachineConfig)
	if cfg == nil {
		cfg = &nodev1.MachineConfig{}
	}
	if cfg.Pki == nil {
		cfg.Pki = &nodev1.Pki{}
	}
	cfg.Pki.Profiles = insertOrReplaceProfile(cfg.Pki.GetProfiles(), profile)

	applied, err := conn.ApplyConfig(ctx, cfg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: apply config: %w", err))
	}

	s.auditProfile(ctx, "profile-applied", fmt.Sprintf("Applied profile %s to %s", profileName, nodeName), profileName)

	return connect.NewResponse(&fleetv1.ApplyProfileToNodeResponse{
		Generation:     applied.GetGeneration(),
		RequiresReboot: applied.GetRequiresReboot(),
	}), nil
}

// requireAdmin resolves the caller's identity and returns a PermissionDenied
// error unless the caller is at least admin level.
func requireAdmin(ctx context.Context) error {
	id, err := operatorLevel(ctx)
	if err != nil {
		return err
	}
	if id.Level < authz.LevelAdmin {
		return connect.NewError(connect.CodePermissionDenied, errors.New("fleet: admin level required"))
	}
	return nil
}

// validateProfile rejects a nil profile or an empty name and returns the name.
func validateProfile(profile *nodev1.CertificateProfile) (string, error) {
	if profile == nil {
		return "", connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: profile is required"))
	}
	if profile.GetName() == "" {
		return "", connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: profile name is required"))
	}
	return profile.GetName(), nil
}

// marshalProfile serializes a profile into its stored form.
func marshalProfile(profile *nodev1.CertificateProfile) (store.Profile, error) {
	raw, err := proto.Marshal(profile)
	if err != nil {
		return store.Profile{}, fmt.Errorf("fleet: marshal profile %q: %w", profile.GetName(), err)
	}
	return store.Profile{Name: profile.GetName(), Spec: raw}, nil
}

// insertOrReplaceProfile returns profiles with p inserted, replacing an entry
// with the same name if one exists and appending otherwise. It does not mutate
// the input slice's entries in place beyond the matched element.
func insertOrReplaceProfile(profiles []*nodev1.CertificateProfile, p *nodev1.CertificateProfile) []*nodev1.CertificateProfile {
	for i, existing := range profiles {
		if existing.GetName() == p.GetName() {
			profiles[i] = p
			return profiles
		}
	}
	return append(profiles, p)
}

// auditProfile appends a single profile-scoped audit event.
func (s *Service) auditProfile(ctx context.Context, kind, summary, name string) {
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       kind,
		Summary:    summary,
		TargetKind: "profile",
		TargetPath: "/profiles/" + name,
	})
}
