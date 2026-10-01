package mcpserver

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
	"encoding/json"
	"fmt"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type revokeArgs struct {
	Node       string `json:"node" jsonschema:"the node that issued the certificate"`
	SerialHex  string `json:"serial_hex" jsonschema:"the certificate's serial number in hex, as cert_list shows it"`
	ReasonCode int32  `json:"reason_code,omitempty" jsonschema:"the RFC 5280 CRLReason code: 0 unspecified (default), 1 keyCompromise, 2 cACompromise, 3 affiliationChanged, 4 superseded, 5 cessationOfOperation, 6 certificateHold, 8 removeFromCRL, 9 privilegeWithdrawn, 10 aACompromise"`
	ApprovalID string `json:"approval_id,omitempty" jsonschema:"leave empty on the first call; if the call returns pending_approval, call again with the same arguments plus the approval_id once a person has approved it"`
}

func (a revokeArgs) approvalID() string { return a.ApprovalID }

type profileArgs struct {
	Profile    map[string]any `json:"profile" jsonschema:"the certificate profile as JSON with proto field names, as profile_list shows it; name is required"`
	ApprovalID string         `json:"approval_id,omitempty" jsonschema:"leave empty on the first call; if the call returns pending_approval, call again with the same arguments plus the approval_id once a person has approved it"`
}

func (a profileArgs) approvalID() string { return a.ApprovalID }

type profileNameArgs struct {
	Name       string `json:"name" jsonschema:"the catalog profile's name"`
	ApprovalID string `json:"approval_id,omitempty" jsonschema:"leave empty on the first call; if the call returns pending_approval, call again with the same arguments plus the approval_id once a person has approved it"`
}

func (a profileNameArgs) approvalID() string { return a.ApprovalID }

type applyProfileArgs struct {
	Profile    string `json:"profile" jsonschema:"the catalog profile's name"`
	Node       string `json:"node" jsonschema:"the node to apply it to"`
	ApprovalID string `json:"approval_id,omitempty" jsonschema:"leave empty on the first call; if the call returns pending_approval, call again with the same arguments plus the approval_id once a person has approved it"`
}

func (a applyProfileArgs) approvalID() string { return a.ApprovalID }

type adapterArgs struct {
	Name       string `json:"name" jsonschema:"the adapter's name, as adapter_list shows it"`
	Enabled    bool   `json:"enabled" jsonschema:"true to enable the adapter, false to disable it"`
	ApprovalID string `json:"approval_id,omitempty" jsonschema:"leave empty on the first call; if the call returns pending_approval, call again with the same arguments plus the approval_id once a person has approved it"`
}

func (a adapterArgs) approvalID() string { return a.ApprovalID }

// crlReasons are the RFC 5280 section 5.3.1 CRLReason codes; 7 is unused.
var crlReasons = map[int32]string{
	0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged", 4: "superseded",
	5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL", 9: "privilegeWithdrawn", 10: "aACompromise",
}

const stepUpNote = " Needs a person's approval: the first call returns pending_approval with a link to show them, " +
	"and nothing changes until you call again with the approval_id after they approve."

func registerStepUpTools(s *mcp.Server, t *tools) {
	addStepUp(s, t, "cert_revoke", "Revoke a certificate on the node that issued it. Irreversible."+stepUpNote,
		t.summarizeRevoke,
		func(ctx context.Context, in revokeArgs) (string, error) {
			return call(ctx, t.svc.RevokeCertificate, &fleetv1.RevokeCertificateRequest{
				NodeName: in.Node, SerialHex: in.SerialHex, ReasonCode: in.ReasonCode,
			})
		})
	addStepUp(s, t, "profile_create", "Add a certificate profile to the catalog."+stepUpNote,
		t.summarizeProfileCreate,
		func(ctx context.Context, in profileArgs) (string, error) {
			p, err := profileFromArgs(in.Profile)
			if err != nil {
				return "", err
			}
			return call(ctx, t.svc.CreateProfile, &fleetv1.CreateProfileRequest{Profile: p})
		})
	addStepUp(s, t, "profile_update", "Replace a catalog certificate profile, matched by name."+stepUpNote,
		t.summarizeProfileUpdate,
		func(ctx context.Context, in profileArgs) (string, error) {
			p, err := profileFromArgs(in.Profile)
			if err != nil {
				return "", err
			}
			return call(ctx, t.svc.UpdateProfile, &fleetv1.UpdateProfileRequest{Profile: p})
		})
	addStepUp(s, t, "profile_delete", "Delete a catalog certificate profile. Copies already applied to nodes are kept."+stepUpNote,
		t.summarizeProfileDelete,
		func(ctx context.Context, in profileNameArgs) (string, error) {
			return call(ctx, t.svc.DeleteProfile, &fleetv1.DeleteProfileRequest{Name: in.Name})
		})
	addStepUp(s, t, "profile_apply_to_node", "Push a catalog certificate profile onto a node's configuration."+stepUpNote,
		t.summarizeApplyProfile,
		func(ctx context.Context, in applyProfileArgs) (string, error) {
			return call(ctx, t.svc.ApplyProfileToNode, &fleetv1.ApplyProfileToNodeRequest{ProfileName: in.Profile, NodeName: in.Node})
		})
	addStepUp(s, t, "adapter_set_enabled", "Enable or disable an enrollment protocol adapter (ACME, SCEP, EST, ...)."+stepUpNote,
		t.summarizeAdapter,
		func(ctx context.Context, in adapterArgs) (string, error) {
			return call(ctx, t.svc.SetAdapterEnabled, &fleetv1.SetAdapterEnabledRequest{Name: in.Name, Enabled: in.Enabled})
		})
}

func (t *tools) summarizeRevoke(_ context.Context, in revokeArgs) (string, error) {
	node, ok := t.st.Node(in.Node)
	if !ok {
		return "", refuse(apperr.CodeNodeNotFound, "no node named %q", in.Node)
	}
	if in.SerialHex == "" {
		return "", invalid("serial_hex is required")
	}
	reason, ok := crlReasons[in.ReasonCode]
	if !ok {
		return "", invalid("reason_code %d is not an RFC 5280 CRLReason", in.ReasonCode)
	}
	return fmt.Sprintf("Revoke certificate %s issued by node %q (%s), reason %d (%s). This cannot be undone.",
		in.SerialHex, in.Node, node.Role, in.ReasonCode, reason), nil
}

func (t *tools) summarizeProfileCreate(_ context.Context, in profileArgs) (string, error) {
	p, err := profileFromArgs(in.Profile)
	if err != nil {
		return "", err
	}
	if _, exists := t.st.Profile(p.GetName()); exists {
		return "", invalid("a profile named %q already exists; use profile_update", p.GetName())
	}
	body, err := render(p)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Create catalog profile %q: %s", p.GetName(), body), nil
}

func (t *tools) summarizeProfileUpdate(_ context.Context, in profileArgs) (string, error) {
	p, err := profileFromArgs(in.Profile)
	if err != nil {
		return "", err
	}
	old, err := t.catalogProfile(p.GetName())
	if err != nil {
		return "", err
	}
	body, err := render(p)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Update catalog profile %q from %s to %s", p.GetName(), old, body), nil
}

func (t *tools) summarizeProfileDelete(_ context.Context, in profileNameArgs) (string, error) {
	old, err := t.catalogProfile(in.Name)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Delete catalog profile %q (copies already applied to nodes are kept): %s", in.Name, old), nil
}

func (t *tools) summarizeApplyProfile(_ context.Context, in applyProfileArgs) (string, error) {
	body, err := t.catalogProfile(in.Profile)
	if err != nil {
		return "", err
	}
	node, ok := t.st.Node(in.Node)
	if !ok {
		return "", refuse(apperr.CodeNodeNotFound, "no node named %q", in.Node)
	}
	return fmt.Sprintf("Apply catalog profile %q to node %q (%s), replacing the node's profile of that name or adding it; "+
		"the rest of the node's configuration is kept: %s", in.Profile, in.Node, node.Role, body), nil
}

func (t *tools) summarizeAdapter(_ context.Context, in adapterArgs) (string, error) {
	for _, a := range t.st.Adapters() {
		if a.Name != in.Name {
			continue
		}
		verb := "Disable"
		if in.Enabled {
			verb = "Enable"
		}
		state := "disabled"
		if a.Enabled {
			state = "enabled"
		}
		return fmt.Sprintf("%s the %s adapter %q at %s (profile %q; it is %s now)", verb, a.Kind, a.Name, a.Endpoint, a.Profile, state), nil
	}
	return "", invalid("no adapter named %q", in.Name)
}

// catalogProfile renders the catalog profile named name, or refuses if there
// is none.
func (t *tools) catalogProfile(name string) (string, error) {
	stored, ok := t.st.Profile(name)
	if !ok {
		return "", refuse(apperr.CodeProfileNotFound, "no catalog profile named %q", name)
	}
	var p nodev1.CertificateProfile
	if err := proto.Unmarshal(stored.Spec, &p); err != nil {
		return "", err
	}
	return render(&p)
}

// profileFromArgs decodes a profile given as JSON. Unknown fields are
// refused, so a typo cannot silently drop a constraint.
func profileFromArgs(m map[string]any) (*nodev1.CertificateProfile, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, invalid("profile is not JSON: %v", err)
	}
	var p nodev1.CertificateProfile
	if err := protojson.Unmarshal(b, &p); err != nil {
		return nil, invalid("profile does not parse: %v", err)
	}
	if p.GetName() == "" {
		return nil, invalid("profile.name is required")
	}
	return &p, nil
}
