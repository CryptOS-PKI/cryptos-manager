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

// escrowStep exercises ExportCAKey against the primary node, always (it does
// not change the node's own state). ImportCAKey is a restore onto a fresh
// node, so it only runs onto the spare node when one is configured;
// otherwise it skips, since there is no node this run may hand a foreign
// identity to without risking one the gate or another run still depends on.
func (s *scenario) escrowStep() step {
	return step{name: "escrow/export-and-import", run: func(ctx context.Context) (string, error) {
		primary, err := s.primary()
		if err != nil {
			return "", err
		}
		id, name := s.nodeRef(primary)

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
			return "", fmt.Errorf("ExportCAKey on %s returned an empty envelope", primary.Name)
		}

		if s.spare == nil {
			return "", skip(fmt.Sprintf("exported %s's CA key (%d-byte envelope); no spare node configured to import it onto", primary.Name, len(envelope)))
		}
		spareID, spareName := s.nodeRef(*s.spare)
		imported, err := s.fleet.ImportCAKey(ctx, connect.NewRequest(&fleetv1.ImportCAKeyRequest{
			NodeId: spareID, NodeName: spareName, Envelope: envelope, Passphrase: passphrase,
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
		return fmt.Sprintf("exported %s's CA key and restored it onto %s (now %s)", primary.Name, s.spare.Name, imported.Msg.GetSubjectCn()), nil
	}}
}
