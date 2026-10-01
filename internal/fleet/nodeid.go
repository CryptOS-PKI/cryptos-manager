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
	"log"
	"regexp"
	"strings"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// nodeLabel is an RFC 1123 DNS label in lowercase: 1 to 63 letters, digits
// and hyphens, starting and ending with a letter or digit.
var nodeLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// nodeLookup says which names a node reference may match.
type nodeLookup int

const (
	// currentNames matches a node's current name only.
	currentNames nodeLookup = iota
	// formerNamesToo also matches the name a node gave up in a rename, when
	// no node has it now. Only GetNode resolves names this way, so an old
	// link still finds its node.
	formerNamesToo
)

// resolveNode finds the node a request addresses. node_id wins; the
// deprecated name field still resolves on its own. When both are set they
// must name the same node, or the request is refused before anything is
// dialed.
func (s *Service) resolveNode(rpc, nodeID, name string, lookup nodeLookup) (store.Node, error) {
	byName := func() (store.Node, bool) {
		if n, ok := s.store.Node(name); ok {
			return n, true
		}
		if lookup == formerNamesToo {
			if n, ok := s.store.NodeByFormerName(name); ok {
				log.Printf("fleet: %s: name %q resolved through the rename history to node %s (now %q)", rpc, name, n.ID, n.Name)
				return n, true
			}
		}
		return store.Node{}, false
	}

	if nodeID == "" {
		n, ok := byName()
		if !ok {
			log.Printf("fleet: %s: no node named %q", rpc, name)
			return store.Node{}, apperr.Coded(apperr.CodeNodeNotFound,
				connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: node %q not found", name)))
		}
		log.Printf("fleet: %s: resolved name %q to node %s", rpc, name, n.ID)
		return n, nil
	}

	n, ok := s.store.NodeByID(nodeID)
	if !ok {
		log.Printf("fleet: %s: no node with id %s", rpc, nodeID)
		return store.Node{}, apperr.Coded(apperr.CodeNodeNotFound,
			connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: node %s not found", nodeID)))
	}
	if name != "" {
		if other, ok := byName(); !ok || other.ID != n.ID {
			log.Printf("fleet: %s: refused, node_id %s is %q but the request also names %q", rpc, nodeID, n.Name, name)
			return store.Node{}, apperr.Coded(apperr.CodeNodeRefMismatch,
				connect.NewError(connect.CodeInvalidArgument,
					fmt.Errorf("fleet: node_id %s and node name %q name different nodes", nodeID, name)))
		}
	}
	log.Printf("fleet: %s: resolved node_id %s (%q)", rpc, n.ID, n.Name)
	return n, nil
}

// nodeTarget is the audit target path for a node. It uses the stable ID, so
// the entry keeps pointing at the node after a rename.
func nodeTarget(n store.Node) string {
	return "/nodes/" + n.ID
}

// validateNodeName checks a new display name. A name shaped like a node ID
// is refused too, because a link segment of that shape is read as an ID.
func validateNodeName(name string) error {
	if !nodeLabel.MatchString(name) {
		return fmt.Errorf("fleet: node name %q is not an RFC 1123 label (1 to 63 lowercase letters, digits and hyphens, starting and ending with a letter or digit)", name)
	}
	if store.IsNodeID(name) {
		return fmt.Errorf("fleet: node name %q has the form of a node ID", name)
	}
	return nil
}

// RenameNode changes a node's display name. The node is addressed by its
// stable ID, which does not change, so links and audit entries recorded
// against the ID keep pointing at it; the old name stays in the rename history.
// Admin-gated. Renaming to the current name returns the node and records
// nothing. The operator CA node is refused, because the manager config finds
// it by name.
func (s *Service) RenameNode(ctx context.Context, req *connect.Request[fleetv1.RenameNodeRequest]) (*connect.Response[fleetv1.RenameNodeResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		log.Printf("fleet: RenameNode: refused: %v", err)
		return nil, err
	}
	nodeID, newName := req.Msg.GetNodeId(), req.Msg.GetNewName()
	log.Printf("fleet: RenameNode: node %s to %q requested", nodeID, newName)
	if nodeID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: node_id is required"))
	}
	if err := validateNodeName(newName); err != nil {
		log.Printf("fleet: RenameNode: refused: %v", err)
		return nil, apperr.Coded(apperr.CodeNodeNameInvalid, connect.NewError(connect.CodeInvalidArgument, err))
	}

	current, err := s.resolveNode("RenameNode", nodeID, "", currentNames)
	if err != nil {
		return nil, err
	}
	if current.Name == newName {
		log.Printf("fleet: RenameNode: node %s is already named %q, nothing to do", current.ID, newName)
		return connect.NewResponse(&fleetv1.RenameNodeResponse{Node: storedSummary(current)}), nil
	}
	renamed, err := s.store.RenameNode(current.ID, newName, time.Now().UTC())
	switch {
	case errors.Is(err, store.ErrNodeNameTaken):
		log.Printf("fleet: RenameNode: refused, another node already has the name %q", newName)
		return nil, apperr.Coded(apperr.CodeNodeNameTaken, connect.NewError(connect.CodeAlreadyExists,
			fmt.Errorf("fleet: another node is already named %q", newName)))
	case errors.Is(err, store.ErrNodeNotFound):
		log.Printf("fleet: RenameNode: node %s disappeared before the rename", current.ID)
		return nil, apperr.Coded(apperr.CodeNodeNotFound, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("fleet: node %s not found", current.ID)))
	case err != nil:
		log.Printf("fleet: RenameNode: store error for node %s: %v", current.ID, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: rename node: %w", err))
	}
	log.Printf("fleet: RenameNode: node %s renamed from %q to %q", renamed.ID, current.Name, renamed.Name)

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-renamed",
		Summary:    fmt.Sprintf("Renamed node %s to %s", current.Name, renamed.Name),
		TargetKind: "node",
		TargetPath: nodeTarget(renamed),
	})

	return connect.NewResponse(&fleetv1.RenameNodeResponse{Node: storedSummary(renamed)}), nil
}

// storedSummary is a node's summary from the inventory alone, without probing
// the node. RenameNode returns it: a rename changes only what the manager
// stores.
func storedSummary(n store.Node) *fleetv1.NodeSummary {
	return &fleetv1.NodeSummary{Id: n.ID, Name: n.Name, Address: n.Endpoint, Role: n.Role}
}

// auditNodeIDs maps each audit entry that concerns a node to the node's ID.
// Entries written since node IDs carry the ID in their target path. Older
// entries carry the name, which is resolved through the rename history to
// the node that held it when the entry was written. Stored entries are
// never changed: the audit log is hash-chained over the target path.
type auditNodeIDs struct {
	history []store.NodeName
	byID    map[string]bool
}

func (s *Service) newAuditNodeIDs() auditNodeIDs {
	ids := map[string]bool{}
	for _, n := range s.store.Nodes() {
		ids[n.ID] = true
	}
	return auditNodeIDs{history: s.store.NodeNames(), byID: ids}
}

func (a auditNodeIDs) of(e store.AuditEvent) string {
	rest, ok := strings.CutPrefix(e.TargetPath, "/nodes/")
	if !ok {
		return ""
	}
	seg, _, _ := strings.Cut(rest, "/")
	if store.IsNodeID(seg) && a.byID[seg] {
		return seg
	}

	at, err := time.Parse(time.RFC3339, e.At)
	var latest store.NodeName
	for _, h := range a.history {
		if h.Name != seg {
			continue
		}
		if err == nil {
			if (h.From.IsZero() || !at.Before(h.From)) && (h.Until.IsZero() || at.Before(h.Until)) {
				return h.NodeID
			}
			continue
		}
		// An entry with an unreadable time goes to the node that held the
		// name last.
		if latest.NodeID == "" || h.Until.IsZero() || (!latest.Until.IsZero() && h.Until.After(latest.Until)) {
			latest = h
		}
	}
	return latest.NodeID
}
