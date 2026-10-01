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
	"crypto/tls"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/operatorca"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

// A node whose reported CA chain holds a trusted operator CA raises the
// runtime node-CA flag, through both the node list and the node detail.
func TestNodeCAWatch_SeesTheChainsNodesReport(t *testing.T) {
	caDER, caCert, _ := signCert(t, "Example Operator CA", nil, nil)
	st := memory.New(nil)
	rev := operatorca.NewRevocations(operatorca.RevocationOptions{Store: st})
	trust, err := operatorca.NewTrustStore(context.Background(), operatorca.Source{Kind: operatorca.KindFile,
		File: []operatorca.Anchor{{Cert: caCert, SHA256: operatorca.Fingerprint(caCert), State: store.OperatorCAActive, FromConfig: true}}},
		st, rev, &tls.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	for name, call := range map[string]func(*Service) error{
		"ListNodes": func(s *Service) error {
			_, err := s.ListNodes(context.Background(), connect.NewRequest(&fleetv1.ListNodesRequest{}))
			return err
		},
		"GetNode": func(s *Service) error {
			_, err := s.GetNode(context.Background(), connect.NewRequest(&fleetv1.GetNodeRequest{Name: "A"}))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			conn := &fakeConn{
				status:   &cryptosv1.GetStatusResponse{Status: &cryptosv1.NodeStatus{}},
				identity: &cryptosv1.GetIdentityResponse{Identity: &cryptosv1.Identity{ChainDer: [][]byte{caDER}}},
			}
			watch := operatorca.NewNodeCAWatch(trust, nil)
			svc := New(testStore(), dialFor(map[string]*fakeConn{"A": conn})).WithNodeCAWatch(watch)
			if err := call(svc); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if _, ok := watch.Flags()[operatorca.Fingerprint(caCert)]; !ok {
				t.Fatalf("%s didn't pass the node's chain to the watch", name)
			}
		})
	}
}
