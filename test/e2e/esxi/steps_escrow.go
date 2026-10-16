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
	"crypto/rand"
	"fmt"

	connect "connectrpc.com/connect"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
)

// escrowSource is the node the escrow export runs against: E2E_ESCROW_NODE
// when set, else the primary node.
func (s *scenario) escrowSource(cfg config) (nodeUnderTest, error) {
	if cfg.EscrowNode != "" {
		n, ok := s.findNode(cfg.EscrowNode)
		if !ok {
			return nodeUnderTest{}, fmt.Errorf("E2E_ESCROW_NODE names %q, which is not in E2E_NODES_FILE", cfg.EscrowNode)
		}
		return n, nil
	}
	return s.primary()
}

// escrowExportStep exercises ExportCAKey, always (it does not change the
// node's own state), against escrowSource: a TPM-held CA key is never
// exportable, so a run whose primary is a TPM node names a software-key node
// in E2E_ESCROW_NODE. It keeps the envelope and its throwaway passphrase for
// escrowImportStep.
func (s *scenario) escrowExportStep(cfg config) step {
	return step{name: "escrow/export", run: func(ctx context.Context) (string, error) {
		source, err := s.escrowSource(cfg)
		if err != nil {
			return "", err
		}
		id, name := s.nodeRef(source)

		passphrase := make([]byte, 32)
		if _, err := rand.Read(passphrase); err != nil {
			return "", fmt.Errorf("generating a throwaway escrow passphrase: %w", err)
		}
		exported, err := s.fleet.ExportCAKey(ctx, connect.NewRequest(&fleetv1.ExportCAKeyRequest{NodeId: id, NodeName: name, Passphrase: passphrase}))
		if err != nil {
			return "", fmt.Errorf("ExportCAKey: %w", err)
		}
		envelope := exported.Msg.GetEnvelope()
		if len(envelope) == 0 {
			return "", fmt.Errorf("ExportCAKey on %s returned an empty envelope", source.Name)
		}
		s.escrow = &escrowBackup{from: source.Name, envelope: envelope, passphrase: passphrase}
		return fmt.Sprintf("exported %s's CA key (%d-byte envelope)", source.Name, len(envelope)), nil
	}}
}

// escrowImportStep exercises ImportCAKey: a restore onto a fresh node, so it
// only runs onto the spare node, and only once enrollmentStep has linked it
// (ImportCAKey addresses a node in the manager's inventory). Otherwise it
// skips, since there is no node this run may hand a foreign identity to
// without risking one the gate or another run still depends on.
func (s *scenario) escrowImportStep() step {
	return step{name: "escrow/import-onto-spare", run: func(ctx context.Context) (string, error) {
		if s.spare == nil {
			return "", skip("no spare node configured to import the escrowed key onto")
		}
		if s.escrow == nil {
			return "", skip("no escrow envelope to import (the export step did not succeed)")
		}
		spareID, ok := s.nodeID[s.spare.Name]
		if !ok {
			return "", skip("the spare node was never linked (the enrollment step did not run or did not succeed), so the manager cannot address it")
		}
		imported, err := s.fleet.ImportCAKey(ctx, connect.NewRequest(&fleetv1.ImportCAKeyRequest{
			NodeId: spareID, Envelope: s.escrow.envelope, Passphrase: s.escrow.passphrase,
		}))
		if err != nil {
			return "", fmt.Errorf("ImportCAKey onto %s: %w", s.spare.Name, err)
		}

		c, err := dialNode(*s.spare)
		if err != nil {
			return "", err
		}
		defer func() { _ = c.Close() }()
		identity, err := c.GetIdentity(ctx)
		if err != nil {
			return "", fmt.Errorf("GetIdentity on %s after import: %w", s.spare.Name, err)
		}
		if identity.GetIdentity().GetChainPem() == "" {
			return "", fmt.Errorf("%s has no identity chain after ImportCAKey", s.spare.Name)
		}
		return fmt.Sprintf("restored %s's escrowed CA key onto %s (now %s)", s.escrow.from, s.spare.Name, imported.Msg.GetSubjectCn()), nil
	}}
}

// escrowBackup is what escrowExportStep hands escrowImportStep.
type escrowBackup struct {
	from       string
	envelope   []byte
	passphrase []byte
}
