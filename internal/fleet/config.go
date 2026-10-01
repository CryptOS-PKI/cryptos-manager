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
	log "github.com/Bugs5382/go-log"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// GetNodeConfig fetches a managed node's current machine configuration. It is
// operator-gated: it verifies the caller is at least operator level, resolves
// the named node, dials it, and returns the node's GetConfig proto verbatim so
// the caller can edit a subset and apply the whole config back. It is a read,
// so it never writes an audit event.
func (s *Service) GetNodeConfig(ctx context.Context, req *connect.Request[fleetv1.GetNodeConfigRequest]) (*connect.Response[fleetv1.GetNodeConfigResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	node, err := s.resolveNode("GetNodeConfig", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.GetConfig(ctx)
	if err != nil {
		return nil, nodeError("get config", err)
	}

	return connect.NewResponse(&fleetv1.GetNodeConfigResponse{Config: resp.GetConfig()}), nil
}

// ApplyNodeConfig applies a full machine configuration to a managed node. It is
// admin-gated (config can reshape the node), rejects a nil config, resolves the
// named node, dials it, and forwards the exact config from the request to the
// node's ApplyConfig -- a whole-config replace, so the caller must have merged
// its edits onto the fetched baseline before calling. On success it appends a
// single "config-applied" audit event and returns the node's config generation
// and requires_reboot. A config that carries a protocol block is first compared
// with the node's current config: each protocol it switches on or off gets its
// own audit event ahead of "config-applied", and a reboot-required switch is
// recorded against the node until the node reports it running. If that
// baseline cannot be read, nothing is applied. A denied caller, a nil config,
// an unknown node, or a node error never writes an audit event.
func (s *Service) ApplyNodeConfig(ctx context.Context, req *connect.Request[fleetv1.ApplyNodeConfigRequest]) (*connect.Response[fleetv1.ApplyNodeConfigResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelAdmin {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: admin level required"))
	}

	cfg := req.Msg.GetConfig()
	if cfg == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: config is required"))
	}

	node, err := s.resolveNode("ApplyNodeConfig", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}
	name := node.Name

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	l := s.log.Ctx(ctx).With(log.F("node", name))
	var switches []protocolSwitch
	if carriesProtocolBlock(cfg) {
		current, err := conn.GetConfig(ctx)
		if err != nil {
			l.Error(err, "apply node config: read the baseline for the protocol audit")
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("%w: %w", errNoBaseline, err))
		}
		switches = protocolSwitches(current.GetConfig().GetPki(), cfg.GetPki())
		l.Debug("apply node config: protocol switches in this apply", log.F("switches", len(switches)))
	}

	applied, err := conn.ApplyConfig(ctx, cfg)
	if err != nil {
		l.Error(err, "apply node config: node refused the config")
		return nil, nodeError("apply config", err)
	}
	l.Info("apply node config: applied", log.F("generation", applied.GetGeneration()), log.F("requires_reboot", applied.GetRequiresReboot()))

	for _, sw := range switches {
		if applied.GetRequiresReboot() {
			s.reboots.record(node.ID, sw.protocol, sw.enabled)
		}
		s.auditProtocol(ctx, node, sw.protocol, sw.enabled, applied.GetRequiresReboot(), "config apply")
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "config-applied",
		Summary:    fmt.Sprintf("Applied config to %s (gen %d)", name, applied.GetGeneration()),
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})

	return connect.NewResponse(&fleetv1.ApplyNodeConfigResponse{
		Generation:     applied.GetGeneration(),
		RequiresReboot: applied.GetRequiresReboot(),
	}), nil
}
