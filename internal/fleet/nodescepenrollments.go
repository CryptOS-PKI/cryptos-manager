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
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// ListNodeScepEnrollments lists a managed node's pending SCEP device
// enrolments, proxying the node's own queue rather than teaching the
// manager's own enrollment model a SCEP kind: the node is already the
// system of record for a request it received directly over its SCEP
// listener, and a proxy keeps that queue in one place instead of two.
// Operator-gated; a read, so it is not audited.
func (s *Service) ListNodeScepEnrollments(ctx context.Context, req *connect.Request[fleetv1.ListNodeScepEnrollmentsRequest]) (*connect.Response[fleetv1.ListNodeScepEnrollmentsResponse], error) {
	caller, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if caller.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	node, err := s.resolveNode("ListNodeScepEnrollments", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.ListScepEnrollments(ctx, req.Msg.GetProfile())
	if err != nil {
		return nil, nodeError("list scep enrollments", err)
	}

	enrollments := make([]*fleetv1.NodeScepEnrollment, 0, len(resp.GetEnrollments()))
	for _, e := range resp.GetEnrollments() {
		enrollments = append(enrollments, nodeScepEnrollmentFromProto(e))
	}

	return connect.NewResponse(&fleetv1.ListNodeScepEnrollmentsResponse{Enrollments: enrollments}), nil
}

// ApproveNodeScepEnrollment approves a pending SCEP enrolment on a managed
// node, issuing the device a certificate. Operator-gated and audited.
func (s *Service) ApproveNodeScepEnrollment(ctx context.Context, req *connect.Request[fleetv1.ApproveNodeScepEnrollmentRequest]) (*connect.Response[fleetv1.ApproveNodeScepEnrollmentResponse], error) {
	caller, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if caller.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	node, err := s.resolveNode("ApproveNodeScepEnrollment", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	id := req.Msg.GetId()
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: id is required"))
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.ApproveScepEnrollment(ctx, id)
	if err != nil {
		return nil, nodeError("approve scep enrollment", err)
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-scep-enrollment-approved",
		Summary:    fmt.Sprintf("Approved SCEP enrolment %s on %s, issued serial %s", id, node.Name, resp.GetSerialHex()),
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})

	return connect.NewResponse(&fleetv1.ApproveNodeScepEnrollmentResponse{
		Enrollment: nodeScepEnrollmentFromProto(resp.GetEnrollment()),
		SerialHex:  resp.GetSerialHex(),
	}), nil
}

// RejectNodeScepEnrollment rejects a pending SCEP enrolment on a managed node
// with a reason, recorded in the node's own audit log. Operator-gated and
// audited.
func (s *Service) RejectNodeScepEnrollment(ctx context.Context, req *connect.Request[fleetv1.RejectNodeScepEnrollmentRequest]) (*connect.Response[fleetv1.RejectNodeScepEnrollmentResponse], error) {
	caller, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if caller.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	node, err := s.resolveNode("RejectNodeScepEnrollment", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	id := req.Msg.GetId()
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: id is required"))
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.RejectScepEnrollment(ctx, id, req.Msg.GetReason())
	if err != nil {
		return nil, nodeError("reject scep enrollment", err)
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-scep-enrollment-rejected",
		Summary:    fmt.Sprintf("Rejected SCEP enrolment %s on %s", id, node.Name),
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})

	return connect.NewResponse(&fleetv1.RejectNodeScepEnrollmentResponse{
		Enrollment: nodeScepEnrollmentFromProto(resp.GetEnrollment()),
	}), nil
}

// nodeScepEnrollmentFromProto flattens a node's ScepEnrollment into the
// fleet API's display shape: RFC3339 timestamps in place of the node's
// protobuf timestamps.
func nodeScepEnrollmentFromProto(e *nodev1.ScepEnrollment) *fleetv1.NodeScepEnrollment {
	return &fleetv1.NodeScepEnrollment{
		Id:            e.GetId(),
		TransactionId: e.GetTransactionId(),
		Profile:       e.GetProfile(),
		SubjectDn:     e.GetSubjectDn(),
		DnsNames:      e.GetDnsNames(),
		IpAddresses:   e.GetIpAddresses(),
		KeyAlg:        e.GetKeyAlg(),
		CsrPem:        e.GetCsrPem(),
		ChallengeId:   e.GetChallengeId(),
		ReceivedAt:    formatTimestamp(e.GetReceivedAt()),
	}
}
