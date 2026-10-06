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
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// RebootNode asks a managed node to perform an orderly reboot or power-off, so
// a config change ApplyNodeConfig reported as requires_reboot (or any other
// staged change surfaced as NodeSummary.reboot_required) can take effect
// without an out-of-band hypervisor reset. It is admin-gated (rebooting an
// issuing CA is an outage of everything that depends on it): it resolves the
// named node, requires confirm_ca_cn, dials the node and calls its Reboot.
// The node itself constant-time compares confirm_ca_cn against its CA CN and
// refuses (PermissionDenied) on a mismatch; that, like any other node
// refusal, is mapped through nodeError so the operator sees the node's own
// reason (x-cryptos-node-reason) rather than an opaque denial. On success it
// appends a single "node-rebooted" audit event naming the node and whether it
// was a reboot or a power-off. A denied caller, a missing confirmation, an
// unknown node, or a node error never writes an audit event.
func (s *Service) RebootNode(ctx context.Context, req *connect.Request[fleetv1.RebootNodeRequest]) (*connect.Response[fleetv1.RebootNodeResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("RebootNode", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}
	name := node.Name

	confirmCN := req.Msg.GetConfirmCaCn()
	if confirmCN == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: confirm_ca_cn is required"))
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	powerOff := req.Msg.GetPowerOff()
	resp, err := conn.Reboot(ctx, confirmCN, powerOff)
	if err != nil {
		return nil, nodeError("reboot", err)
	}

	kind := "reboot"
	if powerOff {
		kind = "power off"
	}
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-rebooted",
		Summary:    fmt.Sprintf("Requested a %s of %s", kind, name),
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})

	return connect.NewResponse(&fleetv1.RebootNodeResponse{
		Rebooting: resp.GetRebooting(),
	}), nil
}
