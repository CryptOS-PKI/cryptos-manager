// Package authz derives and carries the operator identity for the manager's
// management plane: the access-level certificate codec plus the client-cert
// verification middleware that runs ahead of the Connect handlers.
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
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Level is an operator's privilege, conveyed by their client certificate.
// Ordering matters: a higher Level is a superset of the lower ones.
type Level int

const (
	LevelViewer   Level = iota // read-only surfaces
	LevelOperator              // + issue/revoke, approve enrollment (when write paths land)
	LevelAdmin                 // + profiles/adapters/config
)

// AccessLevelOID is the dotted OID of the custom X.509 extension that carries
// an operator cert's access level. It is the single source of truth shared by
// the cryptos issuing-profile config (extra_extensions) and the manager
// verifier.
//
// TODO: register an IANA Private Enterprise Number before GA and replace this
// placeholder arc. 59999 is a placeholder, not an assigned PEN.
const AccessLevelOID = "1.3.6.1.4.1.59999.1.1"

var accessLevelOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 1}

// Token returns the wire token stamped into the certificate.
func (l Level) Token() string {
	switch l {
	case LevelViewer:
		return "viewer"
	case LevelOperator:
		return "operator"
	case LevelAdmin:
		return "admin"
	default:
		return "viewer"
	}
}

// LevelFromToken maps a wire token back to a Level.
func LevelFromToken(s string) (Level, error) {
	switch s {
	case "viewer":
		return LevelViewer, nil
	case "operator":
		return LevelOperator, nil
	case "admin":
		return LevelAdmin, nil
	default:
		return LevelViewer, fmt.Errorf("authz: unknown level token %q", s)
	}
}

// MarshalLevelValue returns the DER bytes for the access-level extension's
// value: an ASN.1 string of the level token. This is the raw value an adopter
// base64-encodes into a cryptos profile's extra_extensions entry.
func MarshalLevelValue(l Level) ([]byte, error) {
	return asn1.Marshal(l.Token())
}

// MarshalLevelExtension returns the dotted OID and DER value of the
// access-level extension for the given level token. It is the single encoding
// used by both cmd/opext (which prints the value for a profile's
// extra_extensions) and the operator-CA profile setup that stamps an
// operator-<level> profile with the level extension. It errors if level is not
// one of viewer|operator|admin.
func MarshalLevelExtension(level string) (oid string, der []byte, err error) {
	l, err := LevelFromToken(level)
	if err != nil {
		return "", nil, err
	}
	value, err := MarshalLevelValue(l)
	if err != nil {
		return "", nil, err
	}
	return AccessLevelOID, value, nil
}

// LevelFromCertificate reads the access-level extension off cert and decodes
// the level. It errors if the extension is absent or unparseable.
func LevelFromCertificate(cert *x509.Certificate) (Level, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(accessLevelOID) {
			continue
		}
		var token string
		if _, err := asn1.Unmarshal(ext.Value, &token); err != nil {
			return LevelViewer, fmt.Errorf("authz: decode access-level extension: %w", err)
		}
		return LevelFromToken(token)
	}
	return LevelViewer, errors.New("authz: certificate has no access-level extension")
}
