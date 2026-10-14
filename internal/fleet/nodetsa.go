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

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// ListNodeTsaCertificates lists the certificates a managed node's time-stamp
// authority has signed tokens with. Any level may read it; a read, so it is
// not audited. The node returns an empty list while its TSA is not running.
func (s *Service) ListNodeTsaCertificates(ctx context.Context, req *connect.Request[fleetv1.ListNodeTsaCertificatesRequest]) (*connect.Response[fleetv1.ListNodeTsaCertificatesResponse], error) {
	if _, err := operatorLevel(ctx); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("ListNodeTsaCertificates", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.ListTsaCertificates(ctx)
	if err != nil {
		return nil, nodeError("list node tsa certificates", err)
	}

	certs := make([]*fleetv1.NodeTsaCertificate, 0, len(resp.GetCertificates()))
	for _, c := range resp.GetCertificates() {
		certs = append(certs, nodeTsaCertificateFromProto(c))
	}

	return connect.NewResponse(&fleetv1.ListNodeTsaCertificatesResponse{Certificates: certs}), nil
}

// nodeTsaCertificateFromProto flattens a node's TsaCertificate into the
// fleet API's display shape: RFC3339 timestamps in place of the node's
// protobuf timestamps.
func nodeTsaCertificateFromProto(c *nodev1.TsaCertificate) *fleetv1.NodeTsaCertificate {
	return &fleetv1.NodeTsaCertificate{
		CertPem:   c.GetCertPem(),
		SerialHex: c.GetSerialHex(),
		Sha256Hex: c.GetSha256Hex(),
		NotBefore: formatTimestamp(c.GetNotBefore()),
		NotAfter:  formatTimestamp(c.GetNotAfter()),
		Current:   c.GetCurrent(),
	}
}
