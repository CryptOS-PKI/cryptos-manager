package fleet

/*
Apache License 2.0

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

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/approval"
	"github.com/CryptOS-PKI/manager/internal/authz"
)

// ListApprovals returns the step-up approvals, newest first, optionally
// filtered by status. Any operator certificate may list them; an MCP key
// never can.
func (s *Service) ListApprovals(ctx context.Context, req *connect.Request[fleetv1.ListApprovalsRequest]) (*connect.Response[fleetv1.ListApprovalsResponse], error) {
	if _, err := approvalOperator(ctx); err != nil {
		return nil, err
	}
	if s.approvals == nil {
		return nil, mcpDisabled()
	}

	list, err := s.approvals.List(req.Msg.GetStatus())
	if err != nil {
		return nil, approvalError(err)
	}
	items := make([]*fleetv1.Approval, 0, len(list))
	for _, a := range list {
		items = append(items, approval.ToProto(a))
	}

	return connect.NewResponse(&fleetv1.ListApprovalsResponse{Items: items}), nil
}

// DecideApproval approves or denies a pending approval. The deciding
// operator certificate must be at or above the approval's required level.
func (s *Service) DecideApproval(ctx context.Context, req *connect.Request[fleetv1.DecideApprovalRequest]) (*connect.Response[fleetv1.DecideApprovalResponse], error) {
	id, err := approvalOperator(ctx)
	if err != nil {
		return nil, err
	}
	if s.approvals == nil {
		return nil, mcpDisabled()
	}

	decided, err := s.approvals.Decide(ctx, id, req.Msg.GetId(), req.Msg.GetApprove())
	if err != nil {
		return nil, approvalError(err)
	}

	return connect.NewResponse(&fleetv1.DecideApprovalResponse{Approval: approval.ToProto(decided)}), nil
}

// approvalOperator returns the caller's identity, refusing one that arrived
// with an MCP key: an agent must never see or decide approvals.
func approvalOperator(ctx context.Context) (authz.Identity, error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return authz.Identity{}, err
	}
	if id.KeyID != "" {
		return authz.Identity{}, approvalError(approval.ErrNeedsCert)
	}
	return id, nil
}

func approvalError(err error) error {
	switch {
	case errors.Is(err, approval.ErrNeedsCert):
		return apperr.Coded(apperr.CodeApprovalNeedsCert, connect.NewError(connect.CodePermissionDenied, err))
	case errors.Is(err, approval.ErrNotFound):
		return apperr.Coded(apperr.CodeApprovalNotFound, connect.NewError(connect.CodeNotFound, err))
	case errors.Is(err, approval.ErrNotPending):
		return apperr.Coded(apperr.CodeApprovalNotPending, connect.NewError(connect.CodeFailedPrecondition, err))
	case errors.Is(err, approval.ErrApproverLevel):
		return apperr.Coded(apperr.CodeApproverLevelTooLow, connect.NewError(connect.CodePermissionDenied, err))
	case errors.Is(err, approval.ErrBadStatus):
		return apperr.Coded(apperr.CodeApprovalStatusInvalid, connect.NewError(connect.CodeInvalidArgument, err))
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
