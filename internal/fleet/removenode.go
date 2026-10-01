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
	"os"
	"path/filepath"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// removedCredsDir is where, inside the node credentials folder, a removed
// node's credentials folder is moved. Node names can't start with a dot, so
// it never collides with a node's folder.
const removedCredsDir = ".removed"

// RemoveNode drops a node from the inventory without contacting it, for a
// node that is gone. confirm_name must be the node's current name. It is
// refused while a pending enrollment names the node. The node's audit and
// name history stay; a credentials folder the manager owns is moved aside
// under the node credentials folder rather than deleted. Admin-gated and
// audited.
func (s *Service) RemoveNode(ctx context.Context, req *connect.Request[fleetv1.RemoveNodeRequest]) (*connect.Response[fleetv1.RemoveNodeResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		log.Printf("fleet: RemoveNode: refused: %v", err)
		return nil, err
	}
	id, confirm := req.Msg.GetNodeId(), req.Msg.GetConfirmName()
	log.Printf("fleet: RemoveNode: node %s requested", id)
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: node_id is required"))
	}
	n, ok := s.store.NodeByID(id)
	if !ok {
		return nil, apperr.Coded(apperr.CodeNodeNotFound, connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: no node with id %s", id)))
	}
	if confirm != n.Name {
		return nil, apperr.Coded(apperr.CodeRemoveNotConfirmed, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("fleet: RemoveNode %s: confirm_name %q is not the node's name %q", id, confirm, n.Name)))
	}
	for _, e := range s.store.Enrollments() {
		if e.Status == "PENDING" && (e.ProposedName == n.Name || e.AdmittedNodeID == n.ID) {
			return nil, apperr.Coded(apperr.CodeNodeInUse, connect.NewError(connect.CodeFailedPrecondition,
				fmt.Errorf("fleet: RemoveNode %s: pending enrollment %s names node %s; approve or reject it first", id, e.ID, n.Name)))
		}
	}

	removed, err := s.store.RemoveNode(n.ID, time.Now().UTC())
	if errors.Is(err, store.ErrNodeNotFound) {
		return nil, apperr.Coded(apperr.CodeNodeNotFound, connect.NewError(connect.CodeNotFound, err))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: RemoveNode %s: %w", id, err))
	}
	where := moveCredsAside(removed)

	summary := fmt.Sprintf("Removed node %s (%s) at %s from the inventory", removed.Name, removed.ID, removed.Endpoint)
	if where != "" {
		summary += "; its credentials were moved to " + where
	}
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-removed",
		Summary:    summary,
		TargetKind: "node",
		TargetPath: nodeTarget(removed),
	})
	log.Printf("fleet: RemoveNode: %s", summary)

	return connect.NewResponse(&fleetv1.RemoveNodeResponse{Node: &fleetv1.NodeSummary{
		Id:      removed.ID,
		Name:    removed.Name,
		Address: removed.Endpoint,
		Role:    removed.Role,
	}}), nil
}

// moveCredsAside moves a removed node's credentials folder, when the manager
// owns it (a folder directly under the node credentials folder), to
// .removed/<name>-<id> there, and returns the new path. Credentials an
// operator placed elsewhere are left alone. A failed move is logged and
// doesn't undo the removal.
func moveCredsAside(n store.Node) string {
	if n.AdminCert == "" {
		return ""
	}
	dir := filepath.Dir(n.AdminCert)
	base := filepath.Clean(adoptCredsBaseDir)
	if filepath.Dir(dir) != base {
		log.Printf("fleet: RemoveNode: node %s: credentials in %s are not in the node credentials folder; leaving them", n.Name, dir)
		return ""
	}
	dest := filepath.Join(base, removedCredsDir, n.Name+"-"+n.ID)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		log.Printf("fleet: RemoveNode: WARNING node %s: could not move its credentials aside: %v", n.Name, err)
		return ""
	}
	if err := os.Rename(dir, dest); err != nil {
		log.Printf("fleet: RemoveNode: WARNING node %s: could not move its credentials from %s: %v", n.Name, dir, err)
		return ""
	}
	return dest
}
