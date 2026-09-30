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
	"errors"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
)

// WhoAmI returns the operator identity the HTTP client-cert middleware placed
// on the request context. Absent identity means the request reached the
// handler without a verified operator cert -> Unauthenticated.
func (s *Service) WhoAmI(ctx context.Context, _ *connect.Request[fleetv1.WhoAmIRequest]) (*connect.Response[fleetv1.WhoAmIResponse], error) {
	id, ok := authz.FromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("fleet: no operator identity"))
	}
	return connect.NewResponse(&fleetv1.WhoAmIResponse{
		Operator: &fleetv1.OperatorIdentity{Cn: id.CN, Serial: id.Serial, Level: id.Level.Token()},
	}), nil
}
