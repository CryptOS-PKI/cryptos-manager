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
	"context"
	"errors"
	"slices"
	"sort"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"github.com/CryptOS-PKI/manager/internal/store/seed"
)

func catalogTestStore() store.Store {
	profiles, adapters, audit, enrollments := seed.Catalog()
	return memory.NewWithCatalog(nil, profiles, adapters, audit, enrollments)
}

func TestListProfiles_ReturnsSeededRows(t *testing.T) {
	svc := New(catalogTestStore(), nil)

	resp, err := svc.ListProfiles(context.Background(), connect.NewRequest(&fleetv1.ListProfilesRequest{}))
	if err != nil {
		t.Fatalf("ListProfiles() error = %v, want nil", err)
	}

	items := resp.Msg.GetItems()
	if len(items) == 0 {
		t.Fatal("ListProfiles() returned no items, want seeded profiles")
	}

	var found bool
	for _, p := range items {
		if p.GetName() == "TLS Server (LDAPS)" {
			found = true
			if p.GetKeyAlg() != "ECDSA-P384" {
				t.Errorf("profile KeyAlg = %q, want ECDSA-P384", p.GetKeyAlg())
			}
			if p.GetBasicConstraints().GetIsCa() {
				t.Error("TLS Server (LDAPS) IsCa = true, want false")
			}
		}
	}
	if !found {
		t.Error(`ListProfiles() missing "TLS Server (LDAPS)"`)
	}
}

func TestListAdapters_ReturnsAllFourProtocols(t *testing.T) {
	svc := New(catalogTestStore(), nil)

	resp, err := svc.ListAdapters(context.Background(), connect.NewRequest(&fleetv1.ListAdaptersRequest{}))
	if err != nil {
		t.Fatalf("ListAdapters() error = %v, want nil", err)
	}

	items := resp.Msg.GetItems()
	byKind := make(map[string]*fleetv1.EnrollmentAdapter, len(items))
	for _, a := range items {
		byKind[a.GetKind()] = a
	}

	for _, kind := range []string{"acme", "est", "scep", "ms-autoenroll"} {
		if _, ok := byKind[kind]; !ok {
			t.Errorf("ListAdapters() missing kind %q", kind)
		}
	}

	acme := byKind["acme"]
	if acme != nil {
		if !acme.GetEnabled() {
			t.Error("acme adapter Enabled = false, want true")
		}
		if acme.GetEndpoint() == "" {
			t.Error("acme adapter Endpoint is empty")
		}
		if acme.GetProfile() == "" {
			t.Error("acme adapter Profile is empty")
		}
	}
}

func TestListAudit_ReturnsSeededEvents(t *testing.T) {
	svc := New(catalogTestStore(), nil)

	resp, err := svc.ListAudit(context.Background(), connect.NewRequest(&fleetv1.ListAuditRequest{}))
	if err != nil {
		t.Fatalf("ListAudit() error = %v, want nil", err)
	}

	items := resp.Msg.GetItems()
	if len(items) < 6 {
		t.Fatalf("ListAudit() returned %d items, want at least 6", len(items))
	}

	var found bool
	for _, e := range items {
		if e.GetId() == "aud-0000" {
			found = true
			if e.GetKind() != "issued" {
				t.Errorf("aud-0000 Kind = %q, want issued", e.GetKind())
			}
		}
	}
	if !found {
		t.Error(`ListAudit() missing "aud-0000"`)
	}
}

func TestListEnrollments_ReturnsAtLeastOnePending(t *testing.T) {
	svc := New(catalogTestStore(), nil)

	resp, err := svc.ListEnrollments(context.Background(), connect.NewRequest(&fleetv1.ListEnrollmentsRequest{}))
	if err != nil {
		t.Fatalf("ListEnrollments() error = %v, want nil", err)
	}

	items := resp.Msg.GetItems()
	if len(items) == 0 {
		t.Fatal("ListEnrollments() returned no items, want seeded enrollments")
	}

	var pending int
	for _, r := range items {
		if r.GetStatus() == "PENDING" {
			pending++
		}
	}
	if pending == 0 {
		t.Error("ListEnrollments() has no PENDING requests, want at least 1")
	}
}

// nodeConfigWith returns a GetConfigResponse carrying the named profiles, as a
// node reports its own pki.profiles.
func nodeConfigWith(names ...string) *cryptosv1.GetConfigResponse {
	profiles := make([]*cryptosv1.CertificateProfile, 0, len(names))
	for _, n := range names {
		profiles = append(profiles, &cryptosv1.CertificateProfile{
			KeyAlg:       "ECDSA-P384",
			Name:         n,
			ValidityDays: 90,
		})
	}

	return &cryptosv1.GetConfigResponse{
		Config: &cryptosv1.MachineConfig{Pki: &cryptosv1.Pki{Profiles: profiles}},
	}
}

func nodeStore(names ...string) store.Store {
	nodes := make([]store.Node, 0, len(names))
	for _, n := range names {
		nodes = append(nodes, store.Node{Endpoint: n + ".example:443", Name: n, Role: "issuing"})
	}

	return memory.NewWithCatalog(nodes, nil, nil, nil, nil)
}

func profileNames(items []*cryptosv1.CertificateProfile) []string {
	out := make([]string, 0, len(items))
	for _, p := range items {
		out = append(out, p.GetName())
	}
	sort.Strings(out)

	return out
}

// TestListProfiles_IncludesProfilesFromNodes is the alpha-run bug (#83): a fleet
// whose nodes carry profiles reported zero, because the catalog only ever read
// the FM's own store. The nodes are authoritative for what they serve, so the
// list has to read through to them.
func TestListProfiles_IncludesProfilesFromNodes(t *testing.T) {
	svc := New(nodeStore("A", "B"), dialFor(map[string]*fakeConn{
		"A": {getConfigResp: nodeConfigWith("leaf-server")},
		"B": {getConfigResp: nodeConfigWith("sub-ca")},
	}))

	resp, err := svc.ListProfiles(context.Background(), connect.NewRequest(&fleetv1.ListProfilesRequest{}))
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}

	got := profileNames(resp.Msg.GetItems())
	if len(got) != 2 || got[0] != "leaf-server" || got[1] != "sub-ca" {
		t.Errorf("profiles = %v, want [leaf-server sub-ca]", got)
	}
}

// A profile the FM holds and a node reports under the same name is one profile,
// not two. The FM's own row wins, since that is the one an operator edited.
func TestListProfiles_DedupesByName(t *testing.T) {
	seeded := catalogTestStore().Profiles()
	if len(seeded) == 0 {
		t.Fatal("expected the seeded catalog to have profiles")
	}
	dup := seeded[0].Name

	profiles, adapters, audit, enrollments := seed.Catalog()
	st := memory.NewWithCatalog(
		[]store.Node{{Endpoint: "a.example:443", Name: "A", Role: "issuing"}},
		profiles, adapters, audit, enrollments,
	)
	svc := New(st, dialFor(map[string]*fakeConn{
		"A": {getConfigResp: nodeConfigWith(dup, "only-on-the-node")},
	}))

	resp, err := svc.ListProfiles(context.Background(), connect.NewRequest(&fleetv1.ListProfilesRequest{}))
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}

	seen := 0
	for _, p := range resp.Msg.GetItems() {
		if p.GetName() == dup {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("profile %q appeared %d times, want exactly 1", dup, seen)
	}
	if !slices.Contains(profileNames(resp.Msg.GetItems()), "only-on-the-node") {
		t.Error("a profile only the node has was dropped")
	}
}

// One unreachable node must not blank the catalog. A fleet view that fails
// whole because a single node is down is worse than a partial one.
func TestListProfiles_ToleratesANodeBeingDown(t *testing.T) {
	svc := New(nodeStore("A", "B"), dialFor(map[string]*fakeConn{
		"A": {getConfigResp: nodeConfigWith("leaf-server")},
		"B": {err: errors.New("dial refused")},
	}))

	resp, err := svc.ListProfiles(context.Background(), connect.NewRequest(&fleetv1.ListProfilesRequest{}))
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if got := profileNames(resp.Msg.GetItems()); len(got) != 1 || got[0] != "leaf-server" {
		t.Errorf("profiles = %v, want [leaf-server] from the reachable node", got)
	}
}

// A Service with no dial function (the catalog-only tests) must still work.
func TestListProfiles_NoDialConfigured(t *testing.T) {
	svc := New(catalogTestStore(), nil)

	resp, err := svc.ListProfiles(context.Background(), connect.NewRequest(&fleetv1.ListProfilesRequest{}))
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if len(resp.Msg.GetItems()) == 0 {
		t.Error("no profiles returned, want the seeded catalog")
	}
}
