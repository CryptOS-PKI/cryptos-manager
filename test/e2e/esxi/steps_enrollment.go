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
	"fmt"
	"os"

	connect "connectrpc.com/connect"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
)

// enrollmentStep exercises CreateEnrollment, ApproveEnrollment and
// RejectEnrollment (LINK kind: a node that already runs, declaring itself to
// this manager, the way a node the gate installed separately from this
// manager's own static inventory joins it). It needs a spare node this run
// may permanently link, since approval is not undone by this script;
// otherwise it skips. On approval it records the spare's resolved ID so the
// decommission step, later, can address it.
func (s *scenario) enrollmentStep() step {
	return step{name: "enrollment/link-approve-and-reject", run: func(ctx context.Context) (string, error) {
		if s.spare == nil {
			return "", skip("no spare node configured to link; enrollment would otherwise permanently add a node this run cannot safely pick")
		}
		adminCertPEM, err := os.ReadFile(s.spare.AdminCertPath)
		if err != nil {
			return "", fmt.Errorf("reading spare node admin cert: %w", err)
		}
		adminKeyPEM, err := os.ReadFile(s.spare.AdminKeyPath)
		if err != nil {
			return "", fmt.Errorf("reading spare node admin key: %w", err)
		}
		var caPEM []byte
		if s.spare.CACertPath != "" {
			caPEM, err = os.ReadFile(s.spare.CACertPath)
			if err != nil {
				return "", fmt.Errorf("reading spare node CA chain: %w", err)
			}
		}

		created, err := s.fleet.CreateEnrollment(ctx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
			Kind: "LINK", NodeEndpoint: s.spare.Endpoint,
			AdminCertPem: string(adminCertPEM), AdminKeyPem: string(adminKeyPEM), CaPem: string(caPEM),
		}))
		if err != nil {
			return "", fmt.Errorf("CreateEnrollment: %w", err)
		}
		approved, err := s.fleet.ApproveEnrollment(ctx, connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{
			Id: created.Msg.GetEnrollment().GetId(), NodeEndpoint: s.spare.Endpoint,
			AdminCertPem: string(adminCertPEM), AdminKeyPem: string(adminKeyPEM), CaPem: string(caPEM),
		}))
		if err != nil {
			return "", fmt.Errorf("ApproveEnrollment: %w", err)
		}
		admittedID := approved.Msg.GetEnrollment().GetAdmittedNodeId()
		if admittedID == "" {
			return "", fmt.Errorf("ApproveEnrollment did not admit a node")
		}
		s.nodeID[s.spare.Name] = admittedID

		confirmed, err := s.fleet.GetNode(ctx, connect.NewRequest(&fleetv1.GetNodeRequest{NodeId: admittedID}))
		if err != nil {
			return "", fmt.Errorf("GetNode on the newly linked node: %w", err)
		}
		if confirmed.Msg.GetNode().GetSummary().GetId() != admittedID {
			return "", fmt.Errorf("the linked node does not appear under GetNode by its admitted id")
		}

		// The reject path: a second request for the same node, declined
		// rather than approved, proves RejectEnrollment without touching the
		// node ApproveEnrollment just admitted.
		second, err := s.fleet.CreateEnrollment(ctx, connect.NewRequest(&fleetv1.CreateEnrollmentRequest{
			Kind: "LINK", NodeEndpoint: s.spare.Endpoint,
			AdminCertPem: string(adminCertPEM), AdminKeyPem: string(adminKeyPEM), CaPem: string(caPEM),
		}))
		if err != nil {
			return "", fmt.Errorf("CreateEnrollment (second, for the reject path): %w", err)
		}
		rejected, err := s.fleet.RejectEnrollment(ctx, connect.NewRequest(&fleetv1.RejectEnrollmentRequest{
			Id: second.Msg.GetEnrollment().GetId(), Reason: "e2e reject-path exercise",
		}))
		if err != nil {
			return "", fmt.Errorf("RejectEnrollment: %w", err)
		}
		if rejected.Msg.GetEnrollment().GetStatus() != "REJECTED" {
			return "", fmt.Errorf("RejectEnrollment left the request in status %q, want REJECTED", rejected.Msg.GetEnrollment().GetStatus())
		}
		return fmt.Sprintf("linked %s (node id %s) and separately rejected a second request for it", s.spare.Name, admittedID), nil
	}}
}

// decommissionStep exercises DecommissionNode against the spare node, and
// only after enrollmentStep actually linked it: decommissioning a node this
// run never added itself would destroy a node the gate or another run still
// depends on.
func (s *scenario) decommissionStep() step {
	return step{name: "decommission/spare-node", run: func(ctx context.Context) (string, error) {
		if s.spare == nil {
			return "", skip("no spare node configured")
		}
		id, ok := s.nodeID[s.spare.Name]
		if !ok {
			return "", skip("the spare node was never linked (the enrollment step did not run or did not succeed); decommissioning a node this run did not itself add is refused")
		}
		node, err := s.fleet.GetNode(ctx, connect.NewRequest(&fleetv1.GetNodeRequest{NodeId: id}))
		if err != nil {
			return "", fmt.Errorf("GetNode before decommission: %w", err)
		}
		resp, err := s.fleet.DecommissionNode(ctx, connect.NewRequest(&fleetv1.DecommissionNodeRequest{
			NodeId: id, ConfirmCommonName: node.Msg.GetNode().GetSummary().GetCn(),
		}))
		if err != nil {
			return "", fmt.Errorf("DecommissionNode: %w", err)
		}
		if !resp.Msg.GetRebooting() {
			return "", fmt.Errorf("DecommissionNode did not report the node rebooting")
		}
		return fmt.Sprintf("decommissioned %s; it is wiping and rebooting into maintenance", s.spare.Name), nil
	}}
}
