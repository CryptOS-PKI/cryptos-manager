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
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

func TestListNodeScepEnrollments_Operator_ReturnsEnrollments(t *testing.T) {
	conn := &fakeConn{listEnrollmentsResp: &nodev1.ListScepEnrollmentsResponse{
		Enrollments: []*nodev1.ScepEnrollment{{Id: "enr-1", Profile: "network-device", SubjectDn: "CN=switch-1"}},
	}}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("operator@acme.example", authz.LevelOperator)
	resp, err := svc.ListNodeScepEnrollments(ctx, connect.NewRequest(&fleetv1.ListNodeScepEnrollmentsRequest{
		NodeName: "A", Profile: "network-device",
	}))
	if err != nil {
		t.Fatalf("ListNodeScepEnrollments(operator) error = %v", err)
	}
	if conn.gotListEnrollmentsProfile != "network-device" {
		t.Errorf("node ListScepEnrollments profile = %q, want network-device", conn.gotListEnrollmentsProfile)
	}
	if len(resp.Msg.GetEnrollments()) != 1 || resp.Msg.GetEnrollments()[0].GetSubjectDn() != "CN=switch-1" {
		t.Errorf("enrollments = %+v, want one entry for CN=switch-1", resp.Msg.GetEnrollments())
	}
}

func TestListNodeScepEnrollments_ViewerDenied(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}}))
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.ListNodeScepEnrollments(ctx, connect.NewRequest(&fleetv1.ListNodeScepEnrollmentsRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func TestListNodeScepEnrollments_Unauthenticated_Refused(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}}))
	_, err := svc.ListNodeScepEnrollments(context.Background(), connect.NewRequest(&fleetv1.ListNodeScepEnrollmentsRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodeUnauthenticated)
}

func TestApproveNodeScepEnrollment_Operator_ApprovesAndAudits(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{approveEnrollmentResp: &nodev1.ApproveScepEnrollmentResponse{
		Enrollment: &nodev1.ScepEnrollment{Id: "enr-1"},
		SerialHex:  "0a1b2c",
	}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("operator@acme.example", authz.LevelOperator)
	resp, err := svc.ApproveNodeScepEnrollment(ctx, connect.NewRequest(&fleetv1.ApproveNodeScepEnrollmentRequest{
		NodeName: "A", Id: "enr-1",
	}))
	if err != nil {
		t.Fatalf("ApproveNodeScepEnrollment(operator) error = %v", err)
	}
	if conn.gotApproveEnrollmentID != "enr-1" {
		t.Errorf("node ApproveScepEnrollment id = %q, want enr-1", conn.gotApproveEnrollmentID)
	}
	if resp.Msg.GetSerialHex() != "0a1b2c" {
		t.Errorf("response serial_hex = %q, want 0a1b2c", resp.Msg.GetSerialHex())
	}
	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "node-scep-enrollment-approved" {
		t.Fatalf("audit = %+v, want one node-scep-enrollment-approved event", audit)
	}
}

func TestApproveNodeScepEnrollment_MissingID_InvalidArgument(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}}))
	ctx := operatorCtx("operator@acme.example", authz.LevelOperator)
	_, err := svc.ApproveNodeScepEnrollment(ctx, connect.NewRequest(&fleetv1.ApproveNodeScepEnrollmentRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestApproveNodeScepEnrollment_ViewerDenied_NoAudit(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.ApproveNodeScepEnrollment(ctx, connect.NewRequest(&fleetv1.ApproveNodeScepEnrollmentRequest{
		NodeName: "A", Id: "enr-1",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if conn.closed {
		t.Error("node was dialed on a denied request")
	}
	if len(st.Audit()) != 0 {
		t.Error("denied request wrote an audit event")
	}
}

func TestRejectNodeScepEnrollment_Operator_RejectsAndAudits(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{rejectEnrollmentResp: &nodev1.RejectScepEnrollmentResponse{
		Enrollment: &nodev1.ScepEnrollment{Id: "enr-1"},
	}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("operator@acme.example", authz.LevelOperator)
	resp, err := svc.RejectNodeScepEnrollment(ctx, connect.NewRequest(&fleetv1.RejectNodeScepEnrollmentRequest{
		NodeName: "A", Id: "enr-1", Reason: "unexpected device",
	}))
	if err != nil {
		t.Fatalf("RejectNodeScepEnrollment(operator) error = %v", err)
	}
	if conn.gotRejectEnrollmentID != "enr-1" || conn.gotRejectEnrollmentReason != "unexpected device" {
		t.Errorf("node RejectScepEnrollment id/reason = %q/%q, want enr-1/unexpected device", conn.gotRejectEnrollmentID, conn.gotRejectEnrollmentReason)
	}
	if resp.Msg.GetEnrollment().GetId() != "enr-1" {
		t.Errorf("response enrollment id = %q, want enr-1", resp.Msg.GetEnrollment().GetId())
	}
	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "node-scep-enrollment-rejected" {
		t.Fatalf("audit = %+v, want one node-scep-enrollment-rejected event", audit)
	}
}

func TestRejectNodeScepEnrollment_MissingID_InvalidArgument(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}}))
	ctx := operatorCtx("operator@acme.example", authz.LevelOperator)
	_, err := svc.RejectNodeScepEnrollment(ctx, connect.NewRequest(&fleetv1.RejectNodeScepEnrollmentRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestRejectNodeScepEnrollment_ViewerDenied_NoAudit(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.RejectNodeScepEnrollment(ctx, connect.NewRequest(&fleetv1.RejectNodeScepEnrollmentRequest{
		NodeName: "A", Id: "enr-1",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if conn.closed {
		t.Error("node was dialed on a denied request")
	}
	if len(st.Audit()) != 0 {
		t.Error("denied request wrote an audit event")
	}
}
