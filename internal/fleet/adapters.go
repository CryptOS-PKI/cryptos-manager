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
	"fmt"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// SetAdapterEnabled records whether an enrollment protocol adapter is enabled,
// matched by adapter name. It is admin-gated, rejects an empty name
// (InvalidArgument), and maps an absent adapter to NotFound. On success it
// updates the store, appends a single audit event ("adapter-enabled" or
// "adapter-disabled" per the requested state), and returns the updated adapter.
// A denied caller, an invalid argument, or an absent adapter never writes to
// the store or the audit log. This persists intent only: the protocol engines
// that serve enrollment requests ship in a later program, so an enabled adapter
// does not yet answer requests.
func (s *Service) SetAdapterEnabled(ctx context.Context, req *connect.Request[fleetv1.SetAdapterEnabledRequest]) (*connect.Response[fleetv1.SetAdapterEnabledResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	name := req.Msg.GetName()
	if name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: adapter name is required"))
	}

	enabled := req.Msg.GetEnabled()
	adapter, err := s.store.SetAdapterEnabled(name, enabled)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: set adapter enabled: %w", err))
	}

	kind := "adapter-disabled"
	summary := "Disabled adapter " + name
	if enabled {
		kind = "adapter-enabled"
		summary = "Enabled adapter " + name
	}
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       kind,
		Summary:    summary,
		TargetKind: "adapter",
		TargetPath: "/adapters/" + name,
	})

	return connect.NewResponse(&fleetv1.SetAdapterEnabledResponse{Adapter: adapterToProto(adapter)}), nil
}
