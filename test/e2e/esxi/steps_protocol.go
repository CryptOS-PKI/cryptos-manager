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

	connect "connectrpc.com/connect"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// protocolStep exercises SetAdapterEnabled (the manager's adapter catalog)
// and SetNodeProtocol (one node's own stored SCEP switch), toggling SCEP on
// and back off and checking the node's own stored config both times. The
// catalog matches adapters by name and a fresh manager's catalog is empty,
// so SetAdapterEnabled runs against the catalog's SCEP adapter when there is
// one, found by its kind, and the result says when there was none. The
// protocol only starts answering requests at the node's next boot
// (NodeSummary.reboot_required), which this script does not force by
// rebooting a shared root or intermediate node; it checks what was stored,
// not what is serving.
func (s *scenario) protocolStep() step {
	return step{name: "protocols/toggle-scep", run: func(ctx context.Context) (string, error) {
		primary, err := s.primary()
		if err != nil {
			return "", err
		}

		adapters, err := s.fleet.ListAdapters(ctx, connect.NewRequest(&fleetv1.ListAdaptersRequest{}))
		if err != nil {
			return "", fmt.Errorf("ListAdapters: %w", err)
		}
		adapterNote := "the catalog has no SCEP adapter, so SetAdapterEnabled was not exercised"
		if name := adapterNameOfKind(adapters.Msg.GetItems(), "scep"); name != "" {
			if _, err := s.fleet.SetAdapterEnabled(ctx, connect.NewRequest(&fleetv1.SetAdapterEnabledRequest{Name: name, Enabled: true})); err != nil {
				return "", fmt.Errorf("SetAdapterEnabled(%s, true): %w", name, err)
			}
			adapterNote = "enabled the catalog's SCEP adapter " + name
		}

		// SetNodeProtocolRequest, unlike every other node-addressed message in
		// this API, still takes only node_name (no node_id yet), so this
		// addresses the node by its display name.
		if _, err := s.fleet.SetNodeProtocol(ctx, connect.NewRequest(&fleetv1.SetNodeProtocolRequest{
			NodeName: primary.Name, Protocol: nodev1.ServiceProtocol_SERVICE_PROTOCOL_SCEP, Enabled: true,
		})); err != nil {
			return "", fmt.Errorf("SetNodeProtocol(scep, true): %w", err)
		}
		if err := s.checkNodeScepEnabled(primary, true); err != nil {
			return "", err
		}

		if _, err := s.fleet.SetNodeProtocol(ctx, connect.NewRequest(&fleetv1.SetNodeProtocolRequest{
			NodeName: primary.Name, Protocol: nodev1.ServiceProtocol_SERVICE_PROTOCOL_SCEP, Enabled: false,
		})); err != nil {
			return "", fmt.Errorf("SetNodeProtocol(scep, false): %w", err)
		}
		if err := s.checkNodeScepEnabled(primary, false); err != nil {
			return "", err
		}
		return fmt.Sprintf("toggled %s's stored SCEP switch on then off; %s", primary.Name, adapterNote), nil
	}}
}

func (s *scenario) checkNodeScepEnabled(n nodeUnderTest, want bool) error {
	c, err := dialNode(n)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.GetConfig(context.Background())
	if err != nil {
		return fmt.Errorf("GetConfig on %s: %w", n.Name, err)
	}
	got := resp.GetConfig().GetPki().GetScep().GetEnabled()
	if got != want {
		return fmt.Errorf("%s's stored scep.enabled is %v, want %v", n.Name, got, want)
	}
	return nil
}

// adapterNameOfKind returns the name of the first catalog adapter of kind,
// or "" when the catalog has none.
func adapterNameOfKind(items []*fleetv1.EnrollmentAdapter, kind string) string {
	for _, a := range items {
		if a.GetKind() == kind {
			return a.GetName()
		}
	}
	return ""
}
