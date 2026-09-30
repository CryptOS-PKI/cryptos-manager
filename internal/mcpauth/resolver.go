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
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/CryptOS-PKI/manager/internal/auditlog"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// Reasons a key is refused. They are logged and audited, never returned to
// the caller, who always sees the same 401.
var (
	ErrMalformed     = errors.New("mcpauth: bearer is not an MCP key")
	ErrUnknownKey    = errors.New("mcpauth: unknown key")
	ErrKeyRevoked    = errors.New("mcpauth: key revoked")
	ErrKeyExpired    = errors.New("mcpauth: key expired")
	ErrCertUntrusted = errors.New("mcpauth: bound certificate no longer chains to the operator CA")
	ErrCertExpired   = errors.New("mcpauth: bound certificate is outside its validity period")
	ErrCertRevoked   = errors.New("mcpauth: bound certificate is revoked")
	ErrCertNoLevel   = errors.New("mcpauth: bound certificate carries no access level")
)

// Revoker reports whether an operator certificate serial is revoked. The
// operator revocation cache satisfies it.
type Revoker interface {
	IsRevoked(serial string) bool
}

// Resolver turns a bearer key into the live identity of the operator
// certificate it is bound to. Nothing is cached: every request re-checks the
// key row and re-validates the certificate against the current operator CA
// pool and revocation set.
type Resolver struct {
	Store   store.Store
	Roots   *x509.CertPool
	Revoked Revoker
	// Now defaults to time.Now.
	Now func() time.Time
}

// Resolve returns the identity for bearer with Level set to the lower of the
// certificate's level and the key's ceiling. A refused key that exists in the
// store gets an audit row naming the reason; an unknown bearer only returns
// its error, so scanning the endpoint cannot flood the audit chain.
func (r *Resolver) Resolve(ctx context.Context, bearer string) (authz.Identity, error) {
	if !WellFormed(bearer) {
		return authz.Identity{}, ErrMalformed
	}
	key, ok := r.Store.McpKeyByHash(HashKey(bearer))
	if !ok {
		return authz.Identity{}, ErrUnknownKey
	}

	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	id, err := r.validate(key, now)
	if err != nil {
		bound := authz.Identity{CN: key.OperatorCN, Serial: key.OperatorSerial, Via: authz.ViaMCP, KeyID: key.ID}
		auditlog.Record(authz.NewContext(ctx, bound), r.Store, store.AuditEvent{
			Kind:       KindKeyRejected,
			Summary:    fmt.Sprintf("Rejected MCP key %s: %v", key.ID, err),
			TargetKind: TargetKind,
			TargetPath: "/mcp-keys/" + key.ID,
			Outcome:    auditlog.OutcomeDenied,
		})
		return authz.Identity{}, err
	}

	if r.Store.TouchMcpKey(key.ID, now.UTC()) {
		auditlog.Record(authz.NewContext(ctx, id), r.Store, store.AuditEvent{
			Kind:       KindKeyFirstUsed,
			Summary:    fmt.Sprintf("MCP key %s used for the first time", key.ID),
			TargetKind: TargetKind,
			TargetPath: "/mcp-keys/" + key.ID,
		})
	}

	return id, nil
}

func (r *Resolver) validate(key store.McpKey, now time.Time) (authz.Identity, error) {
	if !key.RevokedAt.IsZero() {
		return authz.Identity{}, ErrKeyRevoked
	}
	if !key.ExpiresAt.IsZero() && !now.Before(key.ExpiresAt) {
		return authz.Identity{}, ErrKeyExpired
	}

	cert, err := x509.ParseCertificate(key.OperatorCertDER)
	if err != nil {
		return authz.Identity{}, fmt.Errorf("%w: %v", ErrCertUntrusted, err)
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return authz.Identity{}, ErrCertExpired
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       r.Roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return authz.Identity{}, fmt.Errorf("%w: %v", ErrCertUntrusted, err)
	}

	id, err := authz.IdentityFromCertificate(cert)
	if err != nil {
		return authz.Identity{}, ErrCertNoLevel
	}
	if r.Revoked.IsRevoked(id.Serial) {
		return authz.Identity{}, ErrCertRevoked
	}

	if key.LevelCeiling != "" {
		ceiling, err := authz.LevelFromToken(key.LevelCeiling)
		if err != nil {
			return authz.Identity{}, fmt.Errorf("mcpauth: stored ceiling: %w", err)
		}
		id.Level = min(id.Level, ceiling)
	}
	id.Via = authz.ViaMCP
	id.KeyID = key.ID

	return id, nil
}
