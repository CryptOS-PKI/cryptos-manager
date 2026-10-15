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
	"encoding/hex"
	"strings"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// ListNodeAuditEvents pages through a managed node's own hash-chained audit
// log (distinct from ListAudit, the manager's own action log). Any level may
// read it; a read, so it is not audited.
func (s *Service) ListNodeAuditEvents(ctx context.Context, req *connect.Request[fleetv1.ListNodeAuditEventsRequest]) (*connect.Response[fleetv1.ListNodeAuditEventsResponse], error) {
	if _, err := operatorLevel(ctx); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("ListNodeAuditEvents", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.ListAuditEvents(ctx, req.Msg.GetPageSize(), req.Msg.GetPageToken(),
		req.Msg.GetFromTime(), req.Msg.GetToTime(), req.Msg.GetEventType(), req.Msg.GetActor())
	if err != nil {
		return nil, nodeError("list node audit events", err)
	}

	entries := make([]*fleetv1.NodeAuditEvent, 0, len(resp.GetEntries()))
	for _, e := range resp.GetEntries() {
		entries = append(entries, nodeAuditEventFromEntry(e))
	}

	return connect.NewResponse(&fleetv1.ListNodeAuditEventsResponse{
		Entries:       entries,
		NextPageToken: resp.GetNextPageToken(),
	}), nil
}

// VerifyNodeAuditChain asks a managed node to verify its own stored audit
// log: a gap-free sequence, each entry's signature, and the hash chain
// between entries. A broken chain is a result the node reports, not an RPC
// error. Any level may read it; a read, so it is not audited.
func (s *Service) VerifyNodeAuditChain(ctx context.Context, req *connect.Request[fleetv1.VerifyNodeAuditChainRequest]) (*connect.Response[fleetv1.VerifyNodeAuditChainResponse], error) {
	if _, err := operatorLevel(ctx); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("VerifyNodeAuditChain", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.VerifyAuditChain(ctx)
	if err != nil {
		return nil, nodeError("verify node audit chain", err)
	}

	return connect.NewResponse(&fleetv1.VerifyNodeAuditChainResponse{
		EntryCount:          resp.GetEntryCount(),
		Intact:              resp.GetIntact(),
		FirstBrokenSequence: resp.GetFirstBrokenSequence(),
		Reason:              resp.GetReason(),
	}), nil
}

// nodeAuditEventFromEntry flattens a node's AuditLogEntry into the fleet
// API's display shape: RFC3339 timestamp, a bare outcome string, and a hex
// entry hash in place of the node's bytes.
func nodeAuditEventFromEntry(e *nodev1.AuditLogEntry) *fleetv1.NodeAuditEvent {
	event := e.GetEvent()
	var ts string
	if event.GetTs() != nil {
		ts = event.GetTs().AsTime().UTC().Format(time.RFC3339)
	}
	return &fleetv1.NodeAuditEvent{
		Seq:            event.GetSeq(),
		Ts:             ts,
		ActorSubject:   event.GetActorSubject(),
		RpcMethod:      event.GetRpcMethod(),
		Outcome:        strings.TrimPrefix(event.GetOutcome().String(), "OUTCOME_"),
		Details:        event.GetDetails(),
		EntrySha256Hex: hex.EncodeToString(e.GetEntrySha256()),
		Target:         e.GetTarget(),
		Summary:        e.GetSummary(),
	}
}
