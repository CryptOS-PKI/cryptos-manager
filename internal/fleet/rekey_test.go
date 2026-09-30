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
)

// rekeyStore builds an inventory with a child subordinate and its parent, the
// shape RekeyNode's ferry resolves against.
func rekeyStore() store.Store {
	return memory.New([]store.Node{
		{Name: "child-1", Endpoint: "child.acme.com:4443"},
		{Name: "parent-1", Endpoint: "parent.acme.com:4443"},
	})
}

// rekeyDial routes each inventory node to a routingConn that splits GetIdentity
// (used by resolveParentByCN) from the ferry calls, exactly like the
// SUBORDINATE ferry test does.
func rekeyDial(childIdentity, childFerry, parentIdentity, parentFerry *fakeConn) func(store.Node) (NodeConn, error) {
	return func(n store.Node) (NodeConn, error) {
		switch n.Name {
		case "child-1":
			return &routingConn{identity: childIdentity, ferry: childFerry}, nil
		case "parent-1":
			return &routingConn{identity: parentIdentity, ferry: parentFerry}, nil
		}
		return nil, errors.New("no fake conn for " + n.Name)
	}
}

func TestRekeyNode_Viewer_PermissionDenied(t *testing.T) {
	var calls []string
	childFerry := &fakeConn{calls: &calls}
	dial := rekeyDial(&fakeConn{}, childFerry, &fakeConn{}, &fakeConn{calls: &calls})
	svc := New(rekeyStore(), dial)

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.RekeyNode(ctx, connect.NewRequest(&fleetv1.RekeyNodeRequest{NodeName: "child-1", ProfileName: "sub-ca"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)

	if len(calls) != 0 {
		t.Errorf("calls = %v, want none (denied before any dial)", calls)
	}
	if got := len(svc.store.Audit()); got != 0 {
		t.Errorf("audit events = %d, want 0 on a denied re-key", got)
	}
}

func TestRekeyNode_UnknownNode_NotFound(t *testing.T) {
	svc := New(rekeyStore(), rekeyDial(&fakeConn{}, &fakeConn{}, &fakeConn{}, &fakeConn{}))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.RekeyNode(ctx, connect.NewRequest(&fleetv1.RekeyNodeRequest{NodeName: "missing", ProfileName: "sub-ca"}))
	requireConnectCode(t, err, connect.CodeNotFound)

	if got := len(svc.store.Audit()); got != 0 {
		t.Errorf("audit events = %d, want 0 for an unknown node", got)
	}
}

func TestRekeyNode_ParentNotInFleet_FailedPrecondition(t *testing.T) {
	var calls []string
	// The child's issuer CN names a parent that no inventory node's identity
	// leaf matches, so resolveParentByCN finds nothing.
	childIdentity := &fakeConn{
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "child-1", "Off-Fleet Parent CA")}},
		},
	}
	childFerry := &fakeConn{
		calls:             &calls,
		beginRotationResp: &cryptosv1.BeginKeyRotationResponse{CsrDer: []byte("child-csr")},
	}
	parentIdentity := &fakeConn{
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "parent-1", "ACME Root CA")}},
		},
	}
	parentFerry := &fakeConn{calls: &calls}

	svc := New(rekeyStore(), rekeyDial(childIdentity, childFerry, parentIdentity, parentFerry))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.RekeyNode(ctx, connect.NewRequest(&fleetv1.RekeyNodeRequest{NodeName: "child-1", ProfileName: "sub-ca"}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)

	if got := len(svc.store.Audit()); got != 0 {
		t.Errorf("audit events = %d, want 0 when the parent is not in the fleet", got)
	}
}

func TestRekeyNode_SelfSignedRoot_FailedPrecondition(t *testing.T) {
	var calls []string
	// A self-signed root's identity leaf has subject CN == issuer CN, so
	// resolveParentByCN resolves the child as its own parent. Re-keying must
	// refuse rather than ask the root to re-sign itself under a sub-ca profile.
	childIdentity := &fakeConn{
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "ACME Root CA", "ACME Root CA")}},
		},
	}
	childFerry := &fakeConn{
		calls:             &calls,
		beginRotationResp: &cryptosv1.BeginKeyRotationResponse{CsrDer: []byte("root-csr")},
	}
	// parent-1's leaf does not match "ACME Root CA", so only child-1 (itself) matches.
	parentIdentity := &fakeConn{
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "parent-1", "ACME Other CA")}},
		},
	}
	parentFerry := &fakeConn{calls: &calls}

	svc := New(rekeyStore(), rekeyDial(childIdentity, childFerry, parentIdentity, parentFerry))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.RekeyNode(ctx, connect.NewRequest(&fleetv1.RekeyNodeRequest{NodeName: "child-1", ProfileName: "sub-ca"}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)

	if got := len(svc.store.Audit()); got != 0 {
		t.Errorf("audit events = %d, want 0 for a self-signed root", got)
	}
	// The ferry must not complete the rotation.
	if childFerry.gotCompleteChainPEM != "" {
		t.Error("CompleteKeyRotation must not run for a self-signed root")
	}
}

func TestRekeyNode_Operator_RunsFerryAndAudits(t *testing.T) {
	var calls []string
	childIssuerCN := "ACME Intermediate CA"

	childIdentity := &fakeConn{
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "child-1", childIssuerCN)}},
		},
	}
	childFerry := &fakeConn{
		calls:             &calls,
		beginRotationResp: &cryptosv1.BeginKeyRotationResponse{CsrDer: []byte("child-csr")},
		completeRotationResp: &cryptosv1.CompleteKeyRotationResponse{
			Identity: &cryptosv1.Identity{
				ChainDer: [][]byte{
					issuedLeafDER(t, "ACME Issuing CA", childIssuerCN),
					issuedLeafDER(t, childIssuerCN, "ACME Root CA"),
				},
			},
		},
	}
	// The parent's identity leaf CN matches the child's issuer CN, so
	// resolveParentByCN maps it to parent-1.
	parentIdentity := &fakeConn{
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, childIssuerCN, "ACME Root CA")}},
		},
	}
	parentFerry := &fakeConn{
		calls: &calls,
		signSubordinateResp: &cryptosv1.SignSubordinateCSRResponse{
			ChainDer: [][]byte{[]byte("child-der"), []byte("parent-der")},
			ChainPem: "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
		},
	}

	svc := New(rekeyStore(), rekeyDial(childIdentity, childFerry, parentIdentity, parentFerry))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.RekeyNode(ctx, connect.NewRequest(&fleetv1.RekeyNodeRequest{NodeName: "child-1", ProfileName: "sub-ca"}))
	if err != nil {
		t.Fatalf("RekeyNode() error = %v, want nil", err)
	}

	// The parent signed under the requested profile with the child's CSR.
	if parentFerry.gotCSRProfile != "sub-ca" {
		t.Errorf("SignSubordinateCSR profile = %q, want sub-ca", parentFerry.gotCSRProfile)
	}

	// The parent-signed chain was ferried verbatim to CompleteKeyRotation.
	if childFerry.gotCompleteChainPEM != parentFerry.signSubordinateResp.GetChainPem() {
		t.Errorf("CompleteKeyRotation chainPEM = %q, want %q", childFerry.gotCompleteChainPEM, parentFerry.signSubordinateResp.GetChainPem())
	}
	if len(childFerry.gotCompleteChainDER) != len(parentFerry.signSubordinateResp.GetChainDer()) {
		t.Fatalf("CompleteKeyRotation chainDER len = %d, want %d", len(childFerry.gotCompleteChainDER), len(parentFerry.signSubordinateResp.GetChainDer()))
	}

	// The ferry ran child.Begin -> parent.Sign -> child.Complete in order.
	want := []string{"BeginKeyRotation", "SignSubordinateCSR", "CompleteKeyRotation"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("calls[%d] = %q, want %q (full: %v)", i, calls[i], want[i], calls)
		}
	}

	// Response reflects the adopted identity.
	if resp.Msg.GetSubjectCn() != "ACME Issuing CA" {
		t.Errorf("SubjectCn = %q, want ACME Issuing CA", resp.Msg.GetSubjectCn())
	}
	if resp.Msg.GetIssuerCn() != childIssuerCN {
		t.Errorf("IssuerCn = %q, want %q", resp.Msg.GetIssuerCn(), childIssuerCN)
	}
	if resp.Msg.GetChainLen() != 2 {
		t.Errorf("ChainLen = %d, want 2", resp.Msg.GetChainLen())
	}

	// Exactly one "rekeyed" audit event.
	events := svc.store.Audit()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].Kind != "rekeyed" {
		t.Errorf("audit kind = %q, want rekeyed", events[0].Kind)
	}
}

func TestRekeyNode_NodeStepError_MappedNoAudit(t *testing.T) {
	var calls []string
	childIdentity := &fakeConn{
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "child-1", "ACME Intermediate CA")}},
		},
	}
	// The child fails BeginKeyRotation, so the ferry aborts before signing.
	childFerry := &fakeConn{calls: &calls, err: errors.New("node down")}
	parentIdentity := &fakeConn{
		identity: &cryptosv1.GetIdentityResponse{
			Identity: &cryptosv1.Identity{ChainDer: [][]byte{issuedLeafDER(t, "ACME Intermediate CA", "ACME Root CA")}},
		},
	}
	parentFerry := &fakeConn{calls: &calls}

	svc := New(rekeyStore(), rekeyDial(childIdentity, childFerry, parentIdentity, parentFerry))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.RekeyNode(ctx, connect.NewRequest(&fleetv1.RekeyNodeRequest{NodeName: "child-1", ProfileName: "sub-ca"}))
	if err == nil {
		t.Fatal("RekeyNode() error = nil, want a mapped Connect error")
	}
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}

	if got := len(svc.store.Audit()); got != 0 {
		t.Errorf("audit events = %d, want 0 when a node step errors", got)
	}
}
