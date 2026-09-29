package authz

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
)

// Surfaces an identity can arrive through, recorded as the audit "via".
const (
	ViaWeb = "web"
	ViaMCP = "mcp"
)

// Actor kinds recorded on audit rows.
const (
	ActorCert   = "cert"
	ActorMCPKey = "mcp_key"
)

// Identity is the operator the manager derived from the presented client
// certificate, from an MCP key bound to one, or the dev identity under
// AuthBypass.
type Identity struct {
	CN     string
	Serial string
	Level  Level
	// Via is the surface the request arrived through: ViaWeb or ViaMCP.
	Via string
	// KeyID names the MCP key that authenticated the request; empty for a
	// client certificate.
	KeyID string
}

// ActorKind reports how the identity authenticated, for the audit trail.
func (id Identity) ActorKind() string {
	if id.KeyID != "" {
		return ActorMCPKey
	}
	return ActorCert
}

// IdentityFromCertificate reads the CN, serial and access level off an
// operator certificate. It errors if the certificate has no access-level
// extension. Via and KeyID are left for the caller to set.
func IdentityFromCertificate(cert *x509.Certificate) (Identity, error) {
	level, err := LevelFromCertificate(cert)
	if err != nil {
		return Identity{}, err
	}
	return Identity{CN: cert.Subject.CommonName, Serial: formatSerial(cert.SerialNumber), Level: level}, nil
}

// DevIdentity is the identity injected in the AuthBypass dev path, where the
// browser cannot present an installed client cert over h2c.
var DevIdentity = Identity{CN: "operator@acme.example", Serial: "DEV", Level: LevelAdmin, Via: ViaWeb}

type identityCtxKey struct{}

// NewContext returns ctx carrying id.
func NewContext(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityCtxKey{}, id)
}

type peerCertCtxKey struct{}

// PeerCertFromContext returns the verified client certificate the request
// presented, if any. Minting an MCP key needs it, because the key keeps the
// certificate to re-validate it on every call.
func PeerCertFromContext(ctx context.Context) (*x509.Certificate, bool) {
	c, ok := ctx.Value(peerCertCtxKey{}).(*x509.Certificate)
	return c, ok
}

// FromContext returns the Identity carried by ctx, if any.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityCtxKey{}).(Identity)
	return id, ok
}
