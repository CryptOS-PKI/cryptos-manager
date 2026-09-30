package mcpauth

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
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// Errors the key-management operations return. Callers map them to their
// transport's status codes.
var (
	ErrBadCeiling     = errors.New("mcpauth: unknown level ceiling")
	ErrCeilingTooHigh = errors.New("mcpauth: level ceiling exceeds the operator's level")
	ErrForbidden      = errors.New("mcpauth: not permitted for this operator")
	ErrNotFound       = errors.New("mcpauth: no such key")
)

// Audit kinds and target for key lifecycle events.
const (
	KindKeyCreated   = "mcp-key-created"
	KindKeyFirstUsed = "mcp-key-first-used"
	KindKeyRejected  = "mcp-key-rejected"
	KindKeyRevoked   = "mcp-key-revoked"
	TargetKind       = "mcp-key"
)

// Keys mints, lists and revokes MCP keys. The OAuth token endpoint and the
// CreateMcpKey RPC share Mint, so both logins bind a key the same way.
type Keys struct {
	Store store.Store
	// Now defaults to time.Now.
	Now func() time.Time
}

func (k *Keys) now() time.Time {
	if k.Now != nil {
		return k.Now().UTC()
	}
	return time.Now().UTC()
}

// Mint creates a key bound to owner's certificate serial and stores the
// certificate so every request can re-validate it. An empty ceiling means the
// key may use the operator's full level. It returns the plaintext key, which
// is never stored, and the stored record.
func (k *Keys) Mint(ctx context.Context, owner authz.Identity, certDER []byte, label, clientName, ceiling string) (string, store.McpKey, error) {
	if ceiling != "" {
		l, err := authz.LevelFromToken(ceiling)
		if err != nil {
			return "", store.McpKey{}, ErrBadCeiling
		}
		if l > owner.Level {
			return "", store.McpKey{}, ErrCeilingTooHigh
		}
	}

	plain, err := NewKey()
	if err != nil {
		return "", store.McpKey{}, fmt.Errorf("mcpauth: generate key: %w", err)
	}
	key := store.McpKey{
		ID:              newKeyID(),
		TokenHash:       HashKey(plain),
		Label:           label,
		ClientName:      clientName,
		OperatorSerial:  owner.Serial,
		OperatorCN:      owner.CN,
		OperatorCertDER: certDER,
		LevelCeiling:    ceiling,
		CreatedAt:       k.now(),
	}
	k.Store.AddMcpKey(key)

	auditlog.Record(authz.NewContext(ctx, owner), k.Store, store.AuditEvent{
		Kind:       KindKeyCreated,
		Summary:    fmt.Sprintf("Created MCP key %s (label %q, client %q, ceiling %q)", key.ID, label, clientName, ceilingText(ceiling)),
		TargetKind: TargetKind,
		TargetPath: "/mcp-keys/" + key.ID,
	})

	return plain, key, nil
}

// List returns the keys bound to caller's certificate serial, or every key
// when all is set, which only an admin may do. Newest first.
func (k *Keys) List(caller authz.Identity, all bool) ([]store.McpKey, error) {
	if all && caller.Level < authz.LevelAdmin {
		return nil, ErrForbidden
	}
	var out []store.McpKey
	for _, key := range k.Store.McpKeys() {
		if all || key.OperatorSerial == caller.Serial {
			out = append(out, key)
		}
	}
	return out, nil
}

// Revoke revokes the key with the given id. An operator may revoke the keys
// bound to their own certificate serial and an admin may revoke any key.
// Revoking a revoked key returns it unchanged and writes no second audit row.
func (k *Keys) Revoke(ctx context.Context, caller authz.Identity, id string) (store.McpKey, error) {
	key, ok := k.Store.McpKey(id)
	if !ok {
		return store.McpKey{}, ErrNotFound
	}
	if key.OperatorSerial != caller.Serial && caller.Level < authz.LevelAdmin {
		return store.McpKey{}, ErrForbidden
	}
	if !key.RevokedAt.IsZero() {
		return key, nil
	}

	revoked, err := k.Store.RevokeMcpKey(id, k.now())
	if err != nil {
		return store.McpKey{}, err
	}
	auditlog.Record(authz.NewContext(ctx, caller), k.Store, store.AuditEvent{
		Kind:       KindKeyRevoked,
		Summary:    fmt.Sprintf("Revoked MCP key %s (label %q, bound to %s)", id, key.Label, key.OperatorCN),
		TargetKind: TargetKind,
		TargetPath: "/mcp-keys/" + id,
	})

	return revoked, nil
}

func ceilingText(c string) string {
	if c == "" {
		return "none"
	}
	return c
}

func newKeyID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error

	return "mk-" + hex.EncodeToString(b)
}
