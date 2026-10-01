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
	"fmt"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
)

// The operator CA management RPCs are part of the contract but not served by
// this build yet. Each answers Unimplemented so a client can tell "not here
// yet" from a refusal.

// ListOperatorCAs is not served yet.
func (s *Service) ListOperatorCAs(context.Context, *connect.Request[fleetv1.ListOperatorCAsRequest]) (*connect.Response[fleetv1.ListOperatorCAsResponse], error) {
	return nil, notServed("ListOperatorCAs")
}

// RegisterOperatorCA is not served yet.
func (s *Service) RegisterOperatorCA(context.Context, *connect.Request[fleetv1.RegisterOperatorCARequest]) (*connect.Response[fleetv1.RegisterOperatorCAResponse], error) {
	return nil, notServed("RegisterOperatorCA")
}

// RetireOperatorCA is not served yet.
func (s *Service) RetireOperatorCA(context.Context, *connect.Request[fleetv1.RetireOperatorCARequest]) (*connect.Response[fleetv1.RetireOperatorCAResponse], error) {
	return nil, notServed("RetireOperatorCA")
}

// SetOperatorCACRLSource is not served yet.
func (s *Service) SetOperatorCACRLSource(context.Context, *connect.Request[fleetv1.SetOperatorCACRLSourceRequest]) (*connect.Response[fleetv1.SetOperatorCACRLSourceResponse], error) {
	return nil, notServed("SetOperatorCACRLSource")
}

// UploadOperatorCRL is not served yet.
func (s *Service) UploadOperatorCRL(context.Context, *connect.Request[fleetv1.UploadOperatorCRLRequest]) (*connect.Response[fleetv1.UploadOperatorCRLResponse], error) {
	return nil, notServed("UploadOperatorCRL")
}

// SetOperatorCAOCSP is not served yet.
func (s *Service) SetOperatorCAOCSP(context.Context, *connect.Request[fleetv1.SetOperatorCAOCSPRequest]) (*connect.Response[fleetv1.SetOperatorCAOCSPResponse], error) {
	return nil, notServed("SetOperatorCAOCSP")
}

func notServed(method string) error {
	return connect.NewError(connect.CodeUnimplemented, fmt.Errorf("fleet: %s is not available in this build", method))
}
