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
	"errors"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/mcpauth"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// CreateMcpKey mints an MCP key bound to the calling operator's certificate,
// for MCP clients that cannot run the OAuth login. The plaintext key is in
// this response only.
func (s *Service) CreateMcpKey(ctx context.Context, req *connect.Request[fleetv1.CreateMcpKeyRequest]) (*connect.Response[fleetv1.CreateMcpKeyResponse], error) {
	id, err := certOperator(ctx)
	if err != nil {
		return nil, err
	}
	if s.mcpKeys == nil || !s.mcpEnabled {
		return nil, mcpDisabled()
	}
	cert, ok := authz.PeerCertFromContext(ctx)
	if !ok {
		return nil, needsCert()
	}

	plain, key, err := s.mcpKeys.Mint(ctx, id, cert.Raw, req.Msg.GetLabel(), "", req.Msg.GetLevelCeiling())
	if err != nil {
		return nil, mcpKeyError(err)
	}

	return connect.NewResponse(&fleetv1.CreateMcpKeyResponse{PlaintextKey: plain, McpKey: mcpKeyToProto(key)}), nil
}

// ListMcpKeys returns the caller's MCP keys, or every key for an admin that
// sets all. Revoked keys are included.
func (s *Service) ListMcpKeys(ctx context.Context, req *connect.Request[fleetv1.ListMcpKeysRequest]) (*connect.Response[fleetv1.ListMcpKeysResponse], error) {
	id, err := certOperator(ctx)
	if err != nil {
		return nil, err
	}
	if s.mcpKeys == nil {
		return nil, mcpDisabled()
	}

	keys, err := s.mcpKeys.List(id, req.Msg.GetAll())
	if err != nil {
		return nil, mcpKeyError(err)
	}
	items := make([]*fleetv1.McpKey, 0, len(keys))
	for _, k := range keys {
		items = append(items, mcpKeyToProto(k))
	}

	return connect.NewResponse(&fleetv1.ListMcpKeysResponse{Items: items}), nil
}

// RevokeMcpKey revokes an MCP key. The caller's own keys, or any key for an
// admin. It takes effect on the key's next request.
func (s *Service) RevokeMcpKey(ctx context.Context, req *connect.Request[fleetv1.RevokeMcpKeyRequest]) (*connect.Response[fleetv1.RevokeMcpKeyResponse], error) {
	id, err := certOperator(ctx)
	if err != nil {
		return nil, err
	}
	if s.mcpKeys == nil {
		return nil, mcpDisabled()
	}

	key, err := s.mcpKeys.Revoke(ctx, id, req.Msg.GetId())
	if err != nil {
		return nil, mcpKeyError(err)
	}

	return connect.NewResponse(&fleetv1.RevokeMcpKeyResponse{McpKey: mcpKeyToProto(key)}), nil
}

// certOperator returns the caller's identity, refusing one that arrived with
// an MCP key: keys are never minted, listed or revoked with a key.
func certOperator(ctx context.Context) (authz.Identity, error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return authz.Identity{}, err
	}
	if id.KeyID != "" {
		return authz.Identity{}, needsCert()
	}
	return id, nil
}

func needsCert() error {
	return apperr.Coded(apperr.CodeMcpKeyNeedsCert,
		connect.NewError(connect.CodePermissionDenied, errors.New("fleet: MCP keys are managed with an operator client certificate only")))
}

func mcpDisabled() error {
	return apperr.Coded(apperr.CodeMcpDisabled,
		connect.NewError(connect.CodeFailedPrecondition, errors.New("fleet: the MCP endpoint is disabled")))
}

func mcpKeyError(err error) error {
	switch {
	case errors.Is(err, mcpauth.ErrBadCeiling), errors.Is(err, mcpauth.ErrCeilingTooHigh):
		return apperr.Coded(apperr.CodeMcpCeilingTooHigh, connect.NewError(connect.CodeInvalidArgument, err))
	case errors.Is(err, mcpauth.ErrForbidden):
		return apperr.Coded(apperr.CodeForbidden, connect.NewError(connect.CodePermissionDenied, err))
	case errors.Is(err, mcpauth.ErrNotFound):
		return apperr.Coded(apperr.CodeMcpKeyNotFound, connect.NewError(connect.CodeNotFound, err))
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

func mcpKeyToProto(k store.McpKey) *fleetv1.McpKey {
	return &fleetv1.McpKey{
		Id:             k.ID,
		Label:          k.Label,
		ClientName:     k.ClientName,
		OperatorCn:     k.OperatorCN,
		OperatorSerial: k.OperatorSerial,
		LevelCeiling:   k.LevelCeiling,
		CreatedAt:      rfc3339OrEmpty(k.CreatedAt),
		LastUsedAt:     rfc3339OrEmpty(k.LastUsedAt),
		RevokedAt:      rfc3339OrEmpty(k.RevokedAt),
	}
}

func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
