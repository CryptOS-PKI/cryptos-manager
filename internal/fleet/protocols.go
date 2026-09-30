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
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	connect "connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/store"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// protocolBlocks maps each enrolment protocol the manager can switch to its
// block on cryptos.v1.Pki. Every block has `enabled` as its first field, so a
// new protocol (SCEP, then WSTEP and RFC 3161) is one entry here.
var protocolBlocks = map[cryptosv1.ServiceProtocol]protoreflect.Name{
	cryptosv1.ServiceProtocol_SERVICE_PROTOCOL_ACME: "acme",
	cryptosv1.ServiceProtocol_SERVICE_PROTOCOL_EST:  "est",
}

// protocolLabel is the protocol's display name for audit summaries and logs:
// "ACME" for SERVICE_PROTOCOL_ACME.
func protocolLabel(p cryptosv1.ServiceProtocol) string {
	return strings.TrimPrefix(p.String(), "SERVICE_PROTOCOL_")
}

// blockField returns the Pki field descriptor for p's block.
func blockField(p cryptosv1.ServiceProtocol) (protoreflect.FieldDescriptor, bool) {
	name, ok := protocolBlocks[p]
	if !ok {
		return nil, false
	}
	fd := (&cryptosv1.Pki{}).ProtoReflect().Descriptor().Fields().ByName(name)
	return fd, fd != nil
}

// blockState reports whether pki carries p's block and whether that block is
// enabled. A nil pki has no blocks.
func blockState(pki *cryptosv1.Pki, fd protoreflect.FieldDescriptor) (present, enabled bool) {
	if pki == nil || !pki.ProtoReflect().Has(fd) {
		return false, false
	}
	block := pki.ProtoReflect().Get(fd).Message()
	return true, block.Get(block.Descriptor().Fields().ByName("enabled")).Bool()
}

// setBlockEnabled sets the enabled flag on pki's block for fd, creating an
// empty block when the node has none, and leaves every other field as it was.
func setBlockEnabled(pki *cryptosv1.Pki, fd protoreflect.FieldDescriptor, enabled bool) {
	block := pki.ProtoReflect().Mutable(fd).Message()
	block.Set(block.Descriptor().Fields().ByName("enabled"), protoreflect.ValueOfBool(enabled))
}

// SetNodeProtocol switches one enrolment protocol on or off on one managed
// node. It is admin-gated, rejects a protocol the manager has no block for
// (InvalidArgument) and an unknown node (NotFound), then fetches the node's
// config, sets that block's enabled flag and applies the config back. The
// block's other settings go back as the node returned them, write-only secrets
// included (blank, so the node keeps what it stores), and every other protocol
// block is left out so the node keeps it. A protocol already in the requested
// state applies nothing and audits nothing. On success it records a
// reboot-required answer against the node and appends one audit event; a node
// refusal comes back with the node's code and reason and writes nothing.
func (s *Service) SetNodeProtocol(ctx context.Context, req *connect.Request[fleetv1.SetNodeProtocolRequest]) (*connect.Response[fleetv1.SetNodeProtocolResponse], error) {
	name, p, enabled := req.Msg.GetNodeName(), req.Msg.GetProtocol(), req.Msg.GetEnabled()
	l := s.log.Ctx(ctx).With(log.F("node", name), log.F("protocol", protocolLabel(p)), log.F("enabled", enabled))
	l.Debug("set node protocol: start")

	if err := requireAdmin(ctx); err != nil {
		l.Warn("set node protocol: caller is not an admin")
		return nil, err
	}

	fd, ok := blockField(p)
	if !ok {
		l.Warn("set node protocol: protocol has no config block the manager can switch")
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("fleet: protocol %s cannot be switched", p))
	}

	node, err := s.resolveNode("SetNodeProtocol", "", name, currentNames)
	if err != nil {
		l.Warn("set node protocol: node not in inventory")
		return nil, err
	}
	l = l.With(log.F("node_id", node.ID))

	conn, err := s.dial(node)
	if err != nil {
		l.Error(err, "set node protocol: dial node")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	started := time.Now()
	current, err := conn.GetConfig(ctx)
	if err != nil {
		l.Error(err, "set node protocol: get config", log.F("elapsed_ms", time.Since(started).Milliseconds()))
		return nil, nodeError("get config", err)
	}
	l.Debug("set node protocol: fetched node config", log.F("elapsed_ms", time.Since(started).Milliseconds()))

	cfg := proto.Clone(current.GetConfig()).(*cryptosv1.MachineConfig)
	if cfg == nil {
		cfg = &cryptosv1.MachineConfig{}
	}
	if cfg.Pki == nil {
		cfg.Pki = &cryptosv1.Pki{}
	}

	present, was := blockState(cfg.Pki, fd)
	if present && was == enabled {
		l.Info("set node protocol: already in the requested state, nothing applied")
		return connect.NewResponse(&fleetv1.SetNodeProtocolResponse{}), nil
	}

	// An absent block keeps what the node stores, so dropping the other blocks
	// guarantees the apply changes nothing but the one switch.
	for other := range protocolBlocks {
		if other == p {
			continue
		}
		if ofd, ok := blockField(other); ok {
			cfg.Pki.ProtoReflect().Clear(ofd)
		}
	}
	setBlockEnabled(cfg.Pki, fd, enabled)
	l.Debug("set node protocol: applying", log.F("block_present", present), log.F("was_enabled", was))

	started = time.Now()
	applied, err := conn.ApplyConfig(ctx, cfg)
	if err != nil {
		l.Error(err, "set node protocol: node refused the config", log.F("elapsed_ms", time.Since(started).Milliseconds()))
		return nil, nodeError("apply config", err)
	}
	l.Info("set node protocol: applied",
		log.F("generation", applied.GetGeneration()),
		log.F("requires_reboot", applied.GetRequiresReboot()),
		log.F("elapsed_ms", time.Since(started).Milliseconds()))

	if applied.GetRequiresReboot() {
		s.reboots.record(node.ID, p, enabled)
		l.Info("set node protocol: reboot required before the switch takes effect")
	}
	s.auditProtocol(ctx, node, p, enabled, applied.GetRequiresReboot(), "")

	return connect.NewResponse(&fleetv1.SetNodeProtocolResponse{
		Generation:     applied.GetGeneration(),
		RequiresReboot: applied.GetRequiresReboot(),
	}), nil
}

// protocolSwitch is one protocol whose enabled flag an apply changes.
type protocolSwitch struct {
	protocol cryptosv1.ServiceProtocol
	enabled  bool
}

// protocolSwitches compares the protocol blocks sent in next against the
// node's current config and returns, in protocol order, the protocols whose
// enabled flag changes. An absent block keeps the node's, so it never counts.
func protocolSwitches(current, next *cryptosv1.Pki) []protocolSwitch {
	var switches []protocolSwitch
	for _, p := range slices.Sorted(maps.Keys(protocolBlocks)) {
		fd, ok := blockField(p)
		if !ok {
			continue
		}
		present, enabled := blockState(next, fd)
		if !present {
			continue
		}
		if _, was := blockState(current, fd); was != enabled {
			switches = append(switches, protocolSwitch{protocol: p, enabled: enabled})
		}
	}
	return switches
}

// carriesProtocolBlock reports whether cfg sends any protocol block, which is
// when an apply can switch a protocol.
func carriesProtocolBlock(cfg *cryptosv1.MachineConfig) bool {
	for p := range protocolBlocks {
		if fd, ok := blockField(p); ok {
			if present, _ := blockState(cfg.GetPki(), fd); present {
				return true
			}
		}
	}
	return false
}

// auditProtocol appends one protocol switch event against the node's stable
// ID, so the entry keeps pointing at the node after a rename. via names the
// path when it is not SetNodeProtocol.
func (s *Service) auditProtocol(ctx context.Context, node store.Node, p cryptosv1.ServiceProtocol, enabled, rebootRequired bool, via string) {
	kind, verb := "protocol-disabled", "Disabled"
	if enabled {
		kind, verb = "protocol-enabled", "Enabled"
	}
	summary := fmt.Sprintf("%s %s on %s", verb, protocolLabel(p), node.Name)
	if via != "" {
		summary += " via " + via
	}
	if rebootRequired {
		summary += " (takes effect at the next reboot)"
	}
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       kind,
		Summary:    summary,
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})
}

// nodeError wraps a node RPC failure, keeping the node's gRPC code and message
// so a refusal (InvalidArgument, FailedPrecondition) reaches the caller as
// the node said it. Anything without a status is Internal.
func nodeError(op string, err error) error {
	st, ok := status.FromError(err)
	if !ok || st.Code() == 0 || st.Code() > 16 {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: %s: %w", op, err))
	}
	code := connect.Code(st.Code())
	if code == connect.CodeUnknown {
		code = connect.CodeInternal
	}
	return connect.NewError(code, fmt.Errorf("fleet: %s: %s", op, st.Message()))
}

// rebootTracker holds, per node ID, the protocol switches a node accepted with
// requires_reboot and has not yet shown running. It lives in memory: the
// node's own config_reboot_pending and per-protocol reboot_pending carry the
// same fact across a manager restart, so losing the record loses nothing the
// node cannot report.
type rebootTracker struct {
	mu      sync.Mutex
	pending map[string]map[cryptosv1.ServiceProtocol]bool
}

func newRebootTracker() *rebootTracker {
	return &rebootTracker{pending: map[string]map[cryptosv1.ServiceProtocol]bool{}}
}

// record notes that the node with ID node accepted switching p to enabled and
// needs a reboot. Keying by ID keeps the record through a rename.
func (r *rebootTracker) record(node string, p cryptosv1.ServiceProtocol, enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending[node] == nil {
		r.pending[node] = map[cryptosv1.ServiceProtocol]bool{}
	}
	r.pending[node][p] = enabled
}

// pendingFor returns how many switches are recorded against the node ID.
func (r *rebootTracker) pendingFor(node string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending[node])
}

// reconcile folds the reported status of the node with ID node into its
// recorded switches. A recorded switch is confirmed, and dropped, once the
// node reports the protocol running in the switched state with nothing
// pending. It returns the node's protocol list with reboot_pending also set
// for every switch still recorded, and whether the node needs a reboot at all.
func (r *rebootTracker) reconcile(l log.Logger, node string, st *cryptosv1.NodeStatus) ([]*cryptosv1.ProtocolStatus, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	reported := map[cryptosv1.ServiceProtocol]*cryptosv1.ProtocolStatus{}
	protocols := make([]*cryptosv1.ProtocolStatus, 0, len(st.GetProtocols()))
	for _, ps := range st.GetProtocols() {
		c := proto.Clone(ps).(*cryptosv1.ProtocolStatus)
		reported[c.GetProtocol()] = c
		protocols = append(protocols, c)
	}

	for p, want := range r.pending[node] {
		ps, ok := reported[p]
		if ok && ps.GetRunning() == want && !ps.GetRebootPending() && !st.GetConfigRebootPending() {
			delete(r.pending[node], p)
			l.Info("protocol switch confirmed after reboot", log.F("protocol", protocolLabel(p)), log.F("enabled", want))
			continue
		}
		if ok {
			ps.RebootPending = true
		}
		l.Debug("protocol switch still waiting for a reboot", log.F("protocol", protocolLabel(p)), log.F("enabled", want), log.F("reported", ok))
	}
	if len(r.pending[node]) == 0 {
		delete(r.pending, node)
	}

	required := st.GetConfigRebootPending() || len(r.pending[node]) > 0
	for _, ps := range protocols {
		required = required || ps.GetRebootPending()
	}
	return protocols, required
}

// withProtocolState fills summary's protocol state from the node's status and
// the recorded switches.
func (s *Service) withProtocolState(ctx context.Context, summary *fleetv1.NodeSummary, st *cryptosv1.NodeStatus) *fleetv1.NodeSummary {
	l := s.log.Ctx(ctx).With(log.F("node", summary.GetName()), log.F("node_id", summary.GetId()))
	summary.Protocols, summary.RebootRequired = s.reboots.reconcile(l, summary.GetId(), st)
	l.Debug("node protocol state", log.F("protocols", len(summary.GetProtocols())), log.F("reboot_required", summary.GetRebootRequired()))
	return summary
}

var errNoBaseline = errors.New("fleet: the node's current config is needed to audit its protocol switches")
