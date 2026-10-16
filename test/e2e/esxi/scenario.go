package main

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
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	connect "connectrpc.com/connect"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1/fleetv1connect"
)

// scenario carries the state every step shares: the authenticated FleetService
// client from the bootstrap ceremony, the nodes under test, and the node IDs
// the preflight step resolves (every later call prefers a node's stable ID
// over its deprecated display name).
type scenario struct {
	fleet   fleetv1connect.FleetServiceClient
	nodes   []nodeUnderTest // every node from E2E_NODES_FILE except the spare
	spare   *nodeUnderTest  // the one node, if any, destructive steps may use
	ca      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	nodeID  map[string]string // node name -> NodeSummary.id, filled by preflight
	profile string            // the certificate profile the profile/cert/scep steps create and share
	escrow  *escrowBackup     // the envelope escrowExportStep made, for escrowImportStep
}

// newScenario splits cfg.Nodes into the statically managed set and the spare.
func newScenario(fleet fleetv1connect.FleetServiceClient, cfg config, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *scenario {
	s := &scenario{fleet: fleet, ca: ca, caKey: caKey, nodeID: map[string]string{}, profile: "cryptos-e2e-leaf"}
	for _, n := range cfg.Nodes {
		if n.Spare {
			spare := n
			s.spare = &spare
			continue
		}
		s.nodes = append(s.nodes, n)
	}
	return s
}

// primary is the node most steps exercise: the first statically configured
// node. Any configured role works for a profile push, issuance, config push
// or image-status read, so there is no need to pick by role.
func (s *scenario) primary() (nodeUnderTest, error) {
	if len(s.nodes) == 0 {
		return nodeUnderTest{}, fmt.Errorf("no statically configured node to target (every node in E2E_NODES_FILE was marked spare)")
	}
	return s.nodes[0], nil
}

// nodeRef returns the request pair (id, name) a fleet RPC takes to address
// node n, preferring the ID preflight resolved.
func (s *scenario) nodeRef(n nodeUnderTest) (id, name string) {
	if id, ok := s.nodeID[n.Name]; ok {
		return id, ""
	}
	return "", n.Name
}

// allSteps builds the full ordered write-path matrix. Steps that need a
// resource this run was not given (a spare node, a rekey profile, a signed
// image, the SCEP listener's address) report stepSkipped with a clear reason
// rather than failing.
//
// The order matters in two places. The image step runs after the config
// steps, so its reboots start from the config they left. The escrow import
// runs after the enrolment step, because ImportCAKey can only address the
// spare once that step has linked it.
func (s *scenario) allSteps(cfg config) []step {
	return []step{
		s.preflightStep(),
		s.profileStep(),
		s.scepStep(),
		s.scepEnrolStep(cfg),
		s.protocolStep(),
		s.certStep(),
		s.configPushStep(),
		s.imageStep(cfg),
		s.rekeyStep(cfg),
		s.escrowExportStep(cfg),
		s.enrollmentStep(),
		s.escrowImportStep(),
		s.opCredStep(),
		s.decommissionStep(),
	}
}

// preflightStep confirms every statically configured node is in the
// manager's inventory and resolves its stable ID for every later step.
func (s *scenario) preflightStep() step {
	return step{name: "preflight/list-nodes", run: func(ctx context.Context) (string, error) {
		resp, err := s.fleet.ListNodes(ctx, connect.NewRequest(&fleetv1.ListNodesRequest{}))
		if err != nil {
			return "", fmt.Errorf("ListNodes: %w", err)
		}
		byName := map[string]*fleetv1.NodeSummary{}
		for _, n := range resp.Msg.GetNodes() {
			byName[n.GetName()] = n
		}
		for _, n := range s.nodes {
			found, ok := byName[n.Name]
			if !ok {
				return "", fmt.Errorf("configured node %s does not appear in ListNodes", n.Name)
			}
			s.nodeID[n.Name] = found.GetId()
		}
		return fmt.Sprintf("resolved %d node id(s)", len(s.nodeID)), nil
	}}
}
