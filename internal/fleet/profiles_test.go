package fleet

/*
Apache License 2.0

Copyright 2026 Shane

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
	"errors"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"google.golang.org/protobuf/proto"
)

// profileFixture is a full CertificateProfile carrying a subject, typed SANs,
// and an extra extension, so tests prove the whole shape round-trips.
func profileFixture(name string) *cryptosv1.CertificateProfile {
	pathLen := uint32(0)
	return &cryptosv1.CertificateProfile{
		Name:             name,
		KeyAlg:           "ECDSA-P384",
		Subject:          &cryptosv1.Subject{CommonName: "svc.acme.example", Organization: "ACME", Country: "US"},
		ValidityDays:     365,
		BasicConstraints: &cryptosv1.BasicConstraints{IsCa: false, PathLen: &pathLen},
		KeyUsage:         []string{"digital_signature", "key_encipherment"},
		ExtKeyUsage:      []string{"server_auth"},
		Sans: &cryptosv1.SubjectAltNames{
			Dns:   []string{"svc.acme.example"},
			Ip:    []string{"10.0.0.1"},
			Email: []string{"ops@acme.example"},
			Uri:   []string{"spiffe://acme/svc"},
		},
		ExtraExtensions: []*cryptosv1.X509Extension{
			{Oid: "1.2.3.4", Critical: true, Value: []byte{0x01, 0x02}},
		},
	}
}

// storeProfile marshals a fixture into a store.Profile.
func storeProfile(t *testing.T, cp *cryptosv1.CertificateProfile) store.Profile {
	t.Helper()
	raw, err := proto.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return store.Profile{Name: cp.GetName(), Spec: raw}
}

func TestListProfiles_UnmarshalsFullProfile(t *testing.T) {
	st := memory.New(nil)
	if err := st.CreateProfile(storeProfile(t, profileFixture("web"))); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	svc := New(st, nil)

	resp, err := svc.ListProfiles(t.Context(), connect.NewRequest(&fleetv1.ListProfilesRequest{}))
	if err != nil {
		t.Fatalf("ListProfiles error = %v, want nil", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 1 {
		t.Fatalf("ListProfiles items = %d, want 1", len(items))
	}
	got := items[0]
	if !proto.Equal(got, profileFixture("web")) {
		t.Errorf("ListProfiles returned %v, want the full seeded profile", got)
	}
	if got.GetSubject().GetCommonName() != "svc.acme.example" {
		t.Errorf("subject CN = %q, want svc.acme.example", got.GetSubject().GetCommonName())
	}
	if len(got.GetSans().GetDns()) != 1 || len(got.GetExtraExtensions()) != 1 {
		t.Error("typed SANs / extra extensions did not survive the round-trip")
	}
}

func TestCreateProfile_NonAdminDenied_NoWrite(t *testing.T) {
	for _, level := range []authz.Level{authz.LevelViewer, authz.LevelOperator} {
		st := memory.New(nil)
		svc := New(st, nil)
		before := len(st.Audit())

		ctx := operatorCtx("u@acme.example", level)
		_, err := svc.CreateProfile(ctx, connect.NewRequest(&fleetv1.CreateProfileRequest{Profile: profileFixture("web")}))
		requireConnectCode(t, err, connect.CodePermissionDenied)

		if len(st.Profiles()) != 0 {
			t.Errorf("level %v: profile was created despite denial", level)
		}
		if len(st.Audit()) != before {
			t.Errorf("level %v: audit written on denial", level)
		}
	}
}

func TestCreateProfile_AdminHappyPath_MutatesAndAuditsOnce(t *testing.T) {
	st := memory.New(nil)
	svc := New(st, nil)
	before := len(st.Audit())

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.CreateProfile(ctx, connect.NewRequest(&fleetv1.CreateProfileRequest{Profile: profileFixture("web")}))
	if err != nil {
		t.Fatalf("CreateProfile(admin) error = %v, want nil", err)
	}

	stored, ok := st.Profile("web")
	if !ok {
		t.Fatal("profile not stored after CreateProfile")
	}
	roundTrip := &cryptosv1.CertificateProfile{}
	if err := proto.Unmarshal(stored.Spec, roundTrip); err != nil {
		t.Fatalf("stored spec did not unmarshal: %v", err)
	}
	if !proto.Equal(roundTrip, profileFixture("web")) {
		t.Error("stored spec is not the full profile")
	}

	audit := st.Audit()
	if len(audit) != before+1 {
		t.Fatalf("audit len = %d, want exactly one new event", len(audit))
	}
	if audit[len(audit)-1].Kind != "profile-created" {
		t.Errorf("audit Kind = %q, want profile-created", audit[len(audit)-1].Kind)
	}
}

func TestCreateProfile_Duplicate_AlreadyExists_NoSecondAudit(t *testing.T) {
	st := memory.New(nil)
	if err := st.CreateProfile(storeProfile(t, profileFixture("web"))); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := New(st, nil)
	before := len(st.Audit())

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.CreateProfile(ctx, connect.NewRequest(&fleetv1.CreateProfileRequest{Profile: profileFixture("web")}))
	requireConnectCode(t, err, connect.CodeAlreadyExists)

	if len(st.Audit()) != before {
		t.Error("audit written on duplicate create")
	}
}

func TestCreateProfile_NilAndEmptyName_InvalidArgument(t *testing.T) {
	st := memory.New(nil)
	svc := New(st, nil)
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)

	_, err := svc.CreateProfile(ctx, connect.NewRequest(&fleetv1.CreateProfileRequest{Profile: nil}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)

	_, err = svc.CreateProfile(ctx, connect.NewRequest(&fleetv1.CreateProfileRequest{
		Profile: &cryptosv1.CertificateProfile{Name: ""},
	}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)

	if len(st.Profiles()) != 0 {
		t.Error("invalid create still stored a profile")
	}
}

func TestUpdateProfile_AdminReplaces_AuditsOnce(t *testing.T) {
	st := memory.New(nil)
	if err := st.CreateProfile(storeProfile(t, profileFixture("web"))); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := New(st, nil)
	before := len(st.Audit())

	updated := profileFixture("web")
	updated.ValidityDays = 730
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.UpdateProfile(ctx, connect.NewRequest(&fleetv1.UpdateProfileRequest{Profile: updated}))
	if err != nil {
		t.Fatalf("UpdateProfile(admin) error = %v, want nil", err)
	}

	stored, _ := st.Profile("web")
	roundTrip := &cryptosv1.CertificateProfile{}
	_ = proto.Unmarshal(stored.Spec, roundTrip)
	if roundTrip.GetValidityDays() != 730 {
		t.Errorf("stored validity = %d, want 730", roundTrip.GetValidityDays())
	}
	if audit := st.Audit(); len(audit) != before+1 || audit[len(audit)-1].Kind != "profile-updated" {
		t.Errorf("want exactly one profile-updated audit, got %+v", audit)
	}
}

func TestUpdateProfile_Missing_NotFound(t *testing.T) {
	st := memory.New(nil)
	svc := New(st, nil)
	before := len(st.Audit())

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.UpdateProfile(ctx, connect.NewRequest(&fleetv1.UpdateProfileRequest{Profile: profileFixture("nope")}))
	requireConnectCode(t, err, connect.CodeNotFound)

	if len(st.Audit()) != before {
		t.Error("audit written on missing update")
	}
}

func TestUpdateProfile_NonAdminDenied(t *testing.T) {
	st := memory.New(nil)
	_ = st.CreateProfile(storeProfile(t, profileFixture("web")))
	svc := New(st, nil)

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.UpdateProfile(ctx, connect.NewRequest(&fleetv1.UpdateProfileRequest{Profile: profileFixture("web")}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func TestDeleteProfile_AdminRemoves_AuditsOnce(t *testing.T) {
	st := memory.New(nil)
	if err := st.CreateProfile(storeProfile(t, profileFixture("web"))); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := New(st, nil)
	before := len(st.Audit())

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.DeleteProfile(ctx, connect.NewRequest(&fleetv1.DeleteProfileRequest{Name: "web"}))
	if err != nil {
		t.Fatalf("DeleteProfile(admin) error = %v, want nil", err)
	}

	if _, ok := st.Profile("web"); ok {
		t.Error("profile still present after delete")
	}
	if audit := st.Audit(); len(audit) != before+1 || audit[len(audit)-1].Kind != "profile-deleted" {
		t.Errorf("want exactly one profile-deleted audit, got %+v", audit)
	}
}

func TestDeleteProfile_Missing_NotFound(t *testing.T) {
	st := memory.New(nil)
	svc := New(st, nil)
	before := len(st.Audit())

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.DeleteProfile(ctx, connect.NewRequest(&fleetv1.DeleteProfileRequest{Name: "nope"}))
	requireConnectCode(t, err, connect.CodeNotFound)

	if len(st.Audit()) != before {
		t.Error("audit written on missing delete")
	}
}

func TestDeleteProfile_NonAdminDenied(t *testing.T) {
	st := memory.New(nil)
	_ = st.CreateProfile(storeProfile(t, profileFixture("web")))
	svc := New(st, nil)

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.DeleteProfile(ctx, connect.NewRequest(&fleetv1.DeleteProfileRequest{Name: "web"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

// applyTestStore seeds one node "A" and the given catalog profiles.
func applyTestStore(t *testing.T, profiles ...*cryptosv1.CertificateProfile) *memory.Store {
	t.Helper()
	st := memory.New([]store.Node{{Name: "A", Endpoint: "a.acme.com:4443", Role: "issuing"}})
	for _, p := range profiles {
		if err := st.CreateProfile(storeProfile(t, p)); err != nil {
			t.Fatalf("seed profile %q: %v", p.GetName(), err)
		}
	}
	return st
}

func TestApplyProfileToNode_OperatorDenied_NoDialNoAudit(t *testing.T) {
	st := applyTestStore(t, profileFixture("web"))
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))
	before := len(st.Audit())

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.ApplyProfileToNode(ctx, connect.NewRequest(&fleetv1.ApplyProfileToNodeRequest{
		NodeName: "A", ProfileName: "web",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)

	if connA.closed || connA.gotApplyConfig != nil {
		t.Error("node was dialed / ApplyConfig called for a denied caller")
	}
	if len(st.Audit()) != before {
		t.Error("audit written on denial")
	}
}

func TestApplyProfileToNode_UnknownProfile_NotFound(t *testing.T) {
	st := applyTestStore(t)
	svc := New(st, dialFor(map[string]*fakeConn{"A": {}}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ApplyProfileToNode(ctx, connect.NewRequest(&fleetv1.ApplyProfileToNodeRequest{
		NodeName: "A", ProfileName: "missing",
	}))
	requireConnectCode(t, err, connect.CodeNotFound)
}

func TestApplyProfileToNode_UnknownNode_NotFound(t *testing.T) {
	st := applyTestStore(t, profileFixture("web"))
	svc := New(st, dialFor(map[string]*fakeConn{}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ApplyProfileToNode(ctx, connect.NewRequest(&fleetv1.ApplyProfileToNodeRequest{
		NodeName: "missing", ProfileName: "web",
	}))
	requireConnectCode(t, err, connect.CodeNotFound)
}

// TestApplyProfileToNode_Admin_PreservesWholeConfig is the S5 safety assertion:
// applying a profile fetches the node's FULL config, inserts the profile into
// pki.profiles[], and applies back a config that still carries management and
// every other fetched field.
func TestApplyProfileToNode_Admin_PreservesWholeConfig(t *testing.T) {
	st := applyTestStore(t, profileFixture("web"))

	// The node's current config carries management, role, and an existing
	// profile that must survive the apply.
	current := &cryptosv1.MachineConfig{
		ApiVersion: "cryptos.dev/v1alpha1",
		Kind:       "MachineConfig",
		Metadata:   &cryptosv1.Metadata{Name: "A"},
		Role:       &cryptosv1.Role{Kind: "issuing"},
		Management: &cryptosv1.Management{ManagerCn: "fm-op", TrustPem: "trust-pem", OperatorSurfaceReadonly: true},
		Pki: &cryptosv1.Pki{
			RootKeyAlg:        "ECDSA-P384",
			RevocationBaseUrl: "http://ca.acme/crl",
			Profiles:          []*cryptosv1.CertificateProfile{{Name: "existing", KeyAlg: "RSA-3072"}},
		},
	}
	connA := &fakeConn{
		getConfigResp:   &cryptosv1.GetConfigResponse{Config: current},
		applyConfigResp: &cryptosv1.ApplyConfigResponse{Generation: 9, RequiresReboot: true},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))
	before := len(st.Audit())

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.ApplyProfileToNode(ctx, connect.NewRequest(&fleetv1.ApplyProfileToNodeRequest{
		NodeName: "A", ProfileName: "web",
	}))
	if err != nil {
		t.Fatalf("ApplyProfileToNode(admin) error = %v, want nil", err)
	}

	sent := connA.gotApplyConfig
	if sent == nil {
		t.Fatal("ApplyConfig was not called")
	}
	// Every non-profile field of the fetched config must survive.
	if sent.GetManagement().GetManagerCn() != "fm-op" || !sent.GetManagement().GetOperatorSurfaceReadonly() {
		t.Errorf("management was dropped or altered: %v", sent.GetManagement())
	}
	if sent.GetRole().GetKind() != "issuing" || sent.GetMetadata().GetName() != "A" {
		t.Error("role/metadata did not survive the apply")
	}
	if sent.GetPki().GetRevocationBaseUrl() != "http://ca.acme/crl" || sent.GetPki().GetRootKeyAlg() != "ECDSA-P384" {
		t.Error("pki scalar fields did not survive the apply")
	}

	// The applied profile is present and the pre-existing profile is retained.
	names := map[string]bool{}
	var appliedWeb *cryptosv1.CertificateProfile
	for _, p := range sent.GetPki().GetProfiles() {
		names[p.GetName()] = true
		if p.GetName() == "web" {
			appliedWeb = p
		}
	}
	if !names["existing"] || !names["web"] {
		t.Errorf("pki.profiles = %v, want both existing and web", names)
	}
	if appliedWeb == nil || !proto.Equal(appliedWeb, profileFixture("web")) {
		t.Error("applied web profile is not the verbatim catalog profile")
	}

	if resp.Msg.GetGeneration() != 9 || !resp.Msg.GetRequiresReboot() {
		t.Errorf("response gen/reboot = %d/%v, want 9/true", resp.Msg.GetGeneration(), resp.Msg.GetRequiresReboot())
	}
	if !connA.closed {
		t.Error("node connection was not closed")
	}
	if audit := st.Audit(); len(audit) != before+1 || audit[len(audit)-1].Kind != "profile-applied" {
		t.Errorf("want exactly one profile-applied audit, got %+v", audit)
	}
}

// TestApplyProfileToNode_ReplacesSameName asserts applying a profile whose name
// already exists on the node replaces that entry rather than appending a
// duplicate.
func TestApplyProfileToNode_ReplacesSameName(t *testing.T) {
	st := applyTestStore(t, profileFixture("web"))
	current := &cryptosv1.MachineConfig{
		Pki: &cryptosv1.Pki{
			Profiles: []*cryptosv1.CertificateProfile{{Name: "web", KeyAlg: "RSA-3072"}},
		},
	}
	connA := &fakeConn{getConfigResp: &cryptosv1.GetConfigResponse{Config: current}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	if _, err := svc.ApplyProfileToNode(ctx, connect.NewRequest(&fleetv1.ApplyProfileToNodeRequest{
		NodeName: "A", ProfileName: "web",
	})); err != nil {
		t.Fatalf("ApplyProfileToNode error = %v", err)
	}

	profiles := connA.gotApplyConfig.GetPki().GetProfiles()
	if len(profiles) != 1 {
		t.Fatalf("pki.profiles len = %d, want 1 (replaced, not appended)", len(profiles))
	}
	if !proto.Equal(profiles[0], profileFixture("web")) {
		t.Error("same-name profile was not replaced with the catalog version")
	}
}

func TestApplyProfileToNode_NodeError_MappedNoAudit(t *testing.T) {
	st := applyTestStore(t, profileFixture("web"))
	connA := &fakeConn{err: errors.New("node down")}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))
	before := len(st.Audit())

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ApplyProfileToNode(ctx, connect.NewRequest(&fleetv1.ApplyProfileToNodeRequest{
		NodeName: "A", ProfileName: "web",
	}))
	requireConnectCode(t, err, connect.CodeInternal)

	if len(st.Audit()) != before {
		t.Error("audit written when the node errored")
	}
}
