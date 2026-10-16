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
	"strings"

	connect "connectrpc.com/connect"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// switchable is an enrolment protocol SetNodeProtocol can switch (the
// manager switches ACME and EST), with its adapter kind in the manager's
// catalog and how to read its stored switch off a node's config.
type switchable struct {
	protocol nodev1.ServiceProtocol
	kind     string
	enabled  func(*nodev1.Pki) bool
}

var switchableProtocols = []switchable{
	{nodev1.ServiceProtocol_SERVICE_PROTOCOL_EST, "est", func(p *nodev1.Pki) bool { return p.GetEst().GetEnabled() }},
	{nodev1.ServiceProtocol_SERVICE_PROTOCOL_ACME, "acme", func(p *nodev1.Pki) bool { return p.GetAcme().GetEnabled() }},
}

// pickSwitchable returns the first switchable protocol pki has on. Only an
// enabled protocol can be toggled safely: switching one off drops its stored
// block, and switching on a protocol with no block leaves the node without
// the settings it needs, which the node refuses.
func pickSwitchable(pki *nodev1.Pki) (switchable, bool) {
	for _, sw := range switchableProtocols {
		if sw.enabled(pki) {
			return sw, true
		}
	}
	return switchable{}, false
}

// protocolStep exercises SetAdapterEnabled (the manager's adapter catalog)
// and SetNodeProtocol (one node's own stored protocol switch): it switches a
// protocol the primary node has on (EST or ACME) on, which the manager
// answers as already in that state, then off, checking the node's own stored
// config both times. Switching off drops the protocol's stored block, so a
// node with neither on skips rather than being left without one. The catalog
// matches adapters by name and a fresh manager's catalog is empty, so
// SetAdapterEnabled runs against the catalog's adapter of that kind when
// there is one, and the result says when there was none. The switch only
// takes effect at the node's next boot (NodeSummary.reboot_required), which
// this step does not force; it checks what was stored, not what is serving.
func (s *scenario) protocolStep() step {
	return step{name: "protocols/toggle", run: func(ctx context.Context) (string, error) {
		primary, err := s.primary()
		if err != nil {
			return "", err
		}
		pki, err := s.nodePki(ctx, primary)
		if err != nil {
			return "", err
		}
		sw, ok := pickSwitchable(pki)
		if !ok {
			return "", skip(fmt.Sprintf("%s has neither EST nor ACME on; switching one on needs its settings, and switching one off drops them", primary.Name))
		}
		label := strings.ToUpper(sw.kind)

		adapters, err := s.fleet.ListAdapters(ctx, connect.NewRequest(&fleetv1.ListAdaptersRequest{}))
		if err != nil {
			return "", fmt.Errorf("ListAdapters: %w", err)
		}
		adapterNote := "the catalog has no " + label + " adapter, so SetAdapterEnabled was not exercised"
		if name := adapterNameOfKind(adapters.Msg.GetItems(), sw.kind); name != "" {
			if _, err := s.fleet.SetAdapterEnabled(ctx, connect.NewRequest(&fleetv1.SetAdapterEnabledRequest{Name: name, Enabled: true})); err != nil {
				return "", fmt.Errorf("SetAdapterEnabled(%s, true): %w", name, err)
			}
			adapterNote = "enabled the catalog's " + label + " adapter " + name
		}

		// SetNodeProtocolRequest, unlike every other node-addressed message in
		// this API, still takes only node_name (no node_id yet), so this
		// addresses the node by its display name.
		for _, want := range []bool{true, false} {
			if _, err := s.fleet.SetNodeProtocol(ctx, connect.NewRequest(&fleetv1.SetNodeProtocolRequest{
				NodeName: primary.Name, Protocol: sw.protocol, Enabled: want,
			})); err != nil {
				return "", fmt.Errorf("SetNodeProtocol(%s, %t): %w", sw.kind, want, err)
			}
			after, err := s.nodePki(ctx, primary)
			if err != nil {
				return "", err
			}
			if got := sw.enabled(after); got != want {
				return "", fmt.Errorf("%s's stored %s switch is %t after SetNodeProtocol(%t)", primary.Name, sw.kind, got, want)
			}
		}
		return fmt.Sprintf("switched %s's stored %s on (already on) then off; %s", primary.Name, label, adapterNote), nil
	}}
}

// nodePki reads n's stored pki config straight from the node.
func (s *scenario) nodePki(ctx context.Context, n nodeUnderTest) (*nodev1.Pki, error) {
	c, err := dialNode(n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.GetConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetConfig on %s: %w", n.Name, err)
	}
	return resp.GetConfig().GetPki(), nil
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
