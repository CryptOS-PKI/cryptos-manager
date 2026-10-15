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
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

func TestMintNodeScepChallenge_Operator_MintsAndAuditsWithoutPassword(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{mintChallengeResp: &nodev1.MintScepChallengeResponse{
		ChallengePassword: "super-secret-one-time-password",
		Challenge:         &nodev1.ScepChallenge{Id: "ch-1", Profile: "network-device"},
	}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("operator@acme.example", authz.LevelOperator)
	resp, err := svc.MintNodeScepChallenge(ctx, connect.NewRequest(&fleetv1.MintNodeScepChallengeRequest{
		NodeName: "A", Profile: "network-device", TtlSeconds: 3600,
	}))
	if err != nil {
		t.Fatalf("MintNodeScepChallenge(operator) error = %v", err)
	}
	if conn.gotMintProfile != "network-device" || conn.gotMintTTL != 3600 {
		t.Errorf("node MintScepChallenge profile/ttl = %q/%d, want network-device/3600", conn.gotMintProfile, conn.gotMintTTL)
	}
	if resp.Msg.GetChallengePassword() != "super-secret-one-time-password" {
		t.Error("response did not carry the one-time password")
	}
	if resp.Msg.GetChallenge().GetId() != "ch-1" {
		t.Errorf("response challenge id = %q, want ch-1", resp.Msg.GetChallenge().GetId())
	}

	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "node-scep-challenge-minted" {
		t.Fatalf("audit = %+v, want one node-scep-challenge-minted event", audit)
	}
	if strings.Contains(audit[0].Summary, "super-secret-one-time-password") {
		t.Fatal("audit summary carries the one-time challenge password")
	}
}

func TestMintNodeScepChallenge_ViewerDenied_NoDialNoAudit(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.MintNodeScepChallenge(ctx, connect.NewRequest(&fleetv1.MintNodeScepChallengeRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if conn.closed {
		t.Error("node was dialed on a denied request")
	}
	if len(st.Audit()) != 0 {
		t.Error("denied request wrote an audit event")
	}
}

func TestMintNodeScepChallenge_Unauthenticated_Refused(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}}))
	_, err := svc.MintNodeScepChallenge(context.Background(), connect.NewRequest(&fleetv1.MintNodeScepChallengeRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodeUnauthenticated)
}

func TestListNodeScepChallenges_Operator_ReturnsChallenges(t *testing.T) {
	conn := &fakeConn{listChallengesResp: &nodev1.ListScepChallengesResponse{
		Challenges: []*nodev1.ScepChallenge{{Id: "ch-1", Profile: "network-device"}},
	}}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("operator@acme.example", authz.LevelOperator)
	resp, err := svc.ListNodeScepChallenges(ctx, connect.NewRequest(&fleetv1.ListNodeScepChallengesRequest{NodeName: "A"}))
	if err != nil {
		t.Fatalf("ListNodeScepChallenges(operator) error = %v", err)
	}
	if len(resp.Msg.GetChallenges()) != 1 || resp.Msg.GetChallenges()[0].GetId() != "ch-1" {
		t.Errorf("challenges = %+v, want one entry ch-1", resp.Msg.GetChallenges())
	}
}

func TestListNodeScepChallenges_ViewerDenied(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}}))
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.ListNodeScepChallenges(ctx, connect.NewRequest(&fleetv1.ListNodeScepChallengesRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func TestRevokeNodeScepChallenge_Operator_RevokesAndAudits(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{revokeChallengeResp: &nodev1.RevokeScepChallengeResponse{
		Challenge: &nodev1.ScepChallenge{Id: "ch-1"},
	}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("operator@acme.example", authz.LevelOperator)
	resp, err := svc.RevokeNodeScepChallenge(ctx, connect.NewRequest(&fleetv1.RevokeNodeScepChallengeRequest{
		NodeName: "A", Id: "ch-1",
	}))
	if err != nil {
		t.Fatalf("RevokeNodeScepChallenge(operator) error = %v", err)
	}
	if conn.gotRevokeChallengeID != "ch-1" {
		t.Errorf("node RevokeScepChallenge id = %q, want ch-1", conn.gotRevokeChallengeID)
	}
	if resp.Msg.GetChallenge().GetId() != "ch-1" {
		t.Errorf("response challenge id = %q, want ch-1", resp.Msg.GetChallenge().GetId())
	}
	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "node-scep-challenge-revoked" {
		t.Fatalf("audit = %+v, want one node-scep-challenge-revoked event", audit)
	}
}

func TestRevokeNodeScepChallenge_MissingID_InvalidArgument(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}}))
	ctx := operatorCtx("operator@acme.example", authz.LevelOperator)
	_, err := svc.RevokeNodeScepChallenge(ctx, connect.NewRequest(&fleetv1.RevokeNodeScepChallengeRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestRevokeNodeScepChallenge_ViewerDenied_NoAudit(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.RevokeNodeScepChallenge(ctx, connect.NewRequest(&fleetv1.RevokeNodeScepChallengeRequest{
		NodeName: "A", Id: "ch-1",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if conn.closed {
		t.Error("node was dialed on a denied request")
	}
	if len(st.Audit()) != 0 {
		t.Error("denied request wrote an audit event")
	}
}
