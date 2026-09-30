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
	"fmt"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DecommissionNode remotely wipes a managed node's identity and data via the
// node's mTLS-served RemoteReset, then the node reboots into maintenance. It is
// admin-gated: it verifies the caller is admin, resolves the named node
// (NotFound if absent), dials it over mTLS, and calls RemoteReset echoing the
// operator-supplied Root CA CN. The node itself constant-time compares the CN
// and refuses (PermissionDenied) on a mismatch; that is mapped to a clear
// message so the operator knows the confirmation was wrong rather than that
// they lack authorization. On success it appends a single, secret-free
// "node-decommissioned" audit event naming the node and that it was wiped. A
// denied caller, an unknown node, a CN mismatch, or a dial/node error never
// writes an audit event.
func (s *Service) DecommissionNode(ctx context.Context, req *connect.Request[fleetv1.DecommissionNodeRequest]) (*connect.Response[fleetv1.DecommissionNodeResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	name := req.Msg.GetNodeName()
	node, ok := s.store.Node(name)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: node %q not found", name))
	}

	confirmCN := req.Msg.GetConfirmCommonName()
	if confirmCN == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: confirm_common_name is required"))
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.RemoteReset(ctx, confirmCN)
	if err != nil {
		// The node returns gRPC PermissionDenied for a Root-CA-CN mismatch;
		// surface that as a clear confirmation error rather than an opaque authz
		// denial. Any other node error maps to Internal.
		if status.Code(err) == codes.PermissionDenied {
			return nil, connect.NewError(connect.CodePermissionDenied,
				errors.New("fleet: decommission confirmation did not match the node's Root CA CN"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: remote reset: %w", err))
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-decommissioned",
		Summary:    fmt.Sprintf("Decommissioned %s: identity and data wiped remotely", name),
		TargetKind: "node",
		TargetPath: "/nodes/" + name,
	})

	return connect.NewResponse(&fleetv1.DecommissionNodeResponse{
		Rebooting: resp.GetRebooting(),
	}), nil
}
