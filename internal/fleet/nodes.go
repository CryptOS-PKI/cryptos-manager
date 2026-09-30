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
	"crypto/x509"
	"encoding/hex"
	"errors"
	"sync"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// ListNodes returns a summary for every node in the store. Each node is
// dialed and probed concurrently; a dial or GetStatus failure on one node
// is reported as that node's HEALTH_DOWN summary and never fails the
// overall request.
func (s *Service) ListNodes(ctx context.Context, _ *connect.Request[fleetv1.ListNodesRequest]) (*connect.Response[fleetv1.ListNodesResponse], error) {
	nodes := s.store.Nodes()
	summaries := make([]*fleetv1.NodeSummary, len(nodes))

	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n store.Node) {
			defer wg.Done()
			summaries[i] = s.summarize(ctx, n)
		}(i, n)
	}
	wg.Wait()

	return connect.NewResponse(&fleetv1.ListNodesResponse{Nodes: summaries}), nil
}

// GetNode returns the full detail for one node, including its identity
// chain. A dial/probe failure surfaces as a HEALTH_DOWN summary within the
// detail rather than a request error, so the UI can still render the row.
func (s *Service) GetNode(ctx context.Context, req *connect.Request[fleetv1.GetNodeRequest]) (*connect.Response[fleetv1.GetNodeResponse], error) {
	name := req.Msg.GetName()

	n, ok := s.store.Node(name)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("fleet: node not found: "+name))
	}

	conn, err := s.dial(n)
	if err != nil {
		return connect.NewResponse(&fleetv1.GetNodeResponse{
			Node: &fleetv1.NodeDetail{Summary: downSummary(n, err)},
		}), nil
	}
	defer func() { _ = conn.Close() }()

	statusResp, err := conn.GetStatus(ctx)
	if err != nil {
		return connect.NewResponse(&fleetv1.GetNodeResponse{
			Node: &fleetv1.NodeDetail{Summary: downSummary(n, err)},
		}), nil
	}

	identityResp, err := conn.GetIdentity(ctx)
	if err != nil {
		return connect.NewResponse(&fleetv1.GetNodeResponse{
			Node: &fleetv1.NodeDetail{Summary: downSummary(n, err)},
		}), nil
	}

	status := statusResp.GetStatus()
	cn, issuer := leafCNs(identityResp.GetIdentity())

	return connect.NewResponse(&fleetv1.GetNodeResponse{
		Node: &fleetv1.NodeDetail{
			Summary:      upSummary(n, status, cn, issuer),
			Identity:     mapIdentity(identityResp.GetIdentity()),
			TpmAvailable: status.GetTpmState() == cryptosv1.TpmState_TPM_STATE_OK,
			BootCount:    status.GetBootCount(),
		},
	}), nil
}

// summarize dials n and probes GetStatus, recovering any failure into a
// HEALTH_DOWN summary instead of propagating an error.
func (s *Service) summarize(ctx context.Context, n store.Node) *fleetv1.NodeSummary {
	conn, err := s.dial(n)
	if err != nil {
		return downSummary(n, err)
	}
	defer func() { _ = conn.Close() }()

	statusResp, err := conn.GetStatus(ctx)
	if err != nil {
		return downSummary(n, err)
	}

	// Also fetch identity to convey the node's CN + its trust parent (issuer)
	// to the fleet view; tolerate failure (summary stays UP without CN/issuer).
	cn, issuer := "", ""
	if identityResp, ierr := conn.GetIdentity(ctx); ierr == nil {
		cn, issuer = leafCNs(identityResp.GetIdentity())
	}

	return upSummary(n, statusResp.GetStatus(), cn, issuer)
}

// upSummary maps a successfully probed node's status to a NodeSummary. cn and
// issuer come from the node's leaf cert (see leafCNs); issuer lets the UI draw
// the trust edge to the node's parent CA.
func upSummary(n store.Node, status *cryptosv1.NodeStatus, cn, issuer string) *fleetv1.NodeSummary {
	return &fleetv1.NodeSummary{
		Name:          n.Name,
		Address:       n.Endpoint,
		Role:          n.Role,
		IdentityState: mapIdentityState(status.GetIdentityState()),
		Cn:            cn,
		Issuer:        issuer,
		Health:        fleetv1.Health_HEALTH_UP,
	}
}

// leafCNs parses the leaf (first) cert of the identity chain and returns its
// subject and issuer common names, empty if the chain is missing/unparseable.
// A self-signed root has subject == issuer, so the UI treats it as having no
// parent; a subordinate's issuer names its parent CA's subject CN.
func leafCNs(id *cryptosv1.Identity) (cn, issuer string) {
	if id == nil || len(id.GetChainDer()) == 0 {
		return "", ""
	}
	leaf, err := x509.ParseCertificate(id.GetChainDer()[0])
	if err != nil {
		return "", ""
	}
	return leaf.Subject.CommonName, leaf.Issuer.CommonName
}

// downSummary builds a NodeSummary for a node that could not be reached or
// probed, carrying err's text as the health detail.
func downSummary(n store.Node, err error) *fleetv1.NodeSummary {
	return &fleetv1.NodeSummary{
		Name:         n.Name,
		Address:      n.Endpoint,
		Role:         n.Role,
		Health:       fleetv1.Health_HEALTH_DOWN,
		HealthDetail: err.Error(),
	}
}

// mapIdentityState maps the node's cryptos.v1.IdentityState enum to the
// fleetv1.NodeSummary's string field. cryptos.v1.IdentityState has no
// REVOKED value today; NONE/CEREMONY_IN_PROGRESS/UNSPECIFIED all surface as
// UNKNOWN to the fleet view.
func mapIdentityState(s cryptosv1.IdentityState) string {
	switch s {
	case cryptosv1.IdentityState_IDENTITY_STATE_ESTABLISHED:
		return "ESTABLISHED"
	case cryptosv1.IdentityState_IDENTITY_STATE_AWAITING_CERT:
		return "AWAITING_CERT"
	default:
		return "UNKNOWN"
	}
}

// mapIdentity maps cryptos.v1.Identity to the FleetService's own
// NodeIdentity message. LeafSha256 is hex-encoded: the source field is raw
// digest bytes, but fleetv1.NodeIdentity.leaf_sha256 is a display string.
func mapIdentity(id *cryptosv1.Identity) *fleetv1.NodeIdentity {
	return &fleetv1.NodeIdentity{
		ChainPem:   id.GetChainPem(),
		ChainDer:   id.GetChainDer(),
		LeafSha256: hex.EncodeToString(id.GetLeafSha256()),
	}
}
