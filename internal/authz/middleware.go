package authz

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
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/CryptOS-PKI/manager/internal/apperr"
)

// serialRevoker reports whether a client-cert serial has been revoked. The
// RevocationCache satisfies it; a nil revoker disables enforcement.
type serialRevoker interface {
	IsRevoked(serial string) bool
}

// ClientCertMiddleware extracts the operator identity from the verified TLS
// peer certificate and puts it on the request context, with no revocation
// enforcement. It is the plain path used where no operator-CA revocation source
// is configured. A request with no peer cert is 401; a cert without the
// access-level extension is 403.
func ClientCertMiddleware(next http.Handler) http.Handler {
	return ClientCertMiddlewareWithRevocation(nil, next)
}

// ClientCertMiddlewareWithRevocation extracts the operator identity from the
// verified TLS peer certificate and puts it on the request context. The TLS
// layer (RequireAndVerifyClientCert + operator CA) guarantees any presented
// cert is trusted; this reads it and, when revoker is non-nil, additionally
// denies a client whose serial is in the operator-CA's revoked set. A request
// with no peer cert is 401; a cert without the access-level extension, or one
// whose serial has been revoked, is 403. A nil revoker disables the revocation
// check (identical to ClientCertMiddleware).
func ClientCertMiddlewareWithRevocation(revoker serialRevoker, next http.Handler) http.Handler {
	return clientCert(nil, revoker, next)
}

// PeerAuthorizer re-checks a peer certificate on every request against the
// operator CAs trusted now, including revocation, and returns the SHA-256 of
// the operator CA it chains to. The TLS handshake verified the certificate
// once, against whatever was trusted then; this is what makes a retired CA
// or a new denylist entry take effect on an open connection. A refusal
// carries its 16xx code and sub-reason.
type PeerAuthorizer interface {
	AuthorizePeer(leaf *x509.Certificate, intermediates []*x509.Certificate) (issuerSHA256 string, err error)
}

// ClientCertMiddlewareWith is ClientCertMiddleware plus a per-request
// PeerAuthorizer check. A refused certificate gets 403 with the refusal's
// code and reason headers.
func ClientCertMiddlewareWith(auth PeerAuthorizer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return clientCert(auth, nil, next) }
}

func clientCert(auth PeerAuthorizer, revoker serialRevoker, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			// A connection whose handshake carried no certificate can never
			// authenticate, yet HTTP/2 would keep reusing it for every later
			// API call -- typically because it was opened for the anonymous web
			// surface (#77). Close it (GOAWAY on h2) so the client's next
			// attempt makes a fresh handshake where a certificate can be
			// offered. The request is refused either way.
			w.Header().Set("Connection", "close")
			log.Printf("authz: refused %s %q from %s: the TLS connection carries no client certificate; closing it so the client re-handshakes",
				r.Method, r.URL.Path, r.RemoteAddr)
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		id, err := IdentityFromCertificate(cert)
		if err != nil {
			http.Error(w, "operator certificate missing access level", http.StatusForbidden)
			return
		}
		if revoker != nil && revoker.IsRevoked(id.Serial) {
			http.Error(w, "operator certificate revoked", http.StatusForbidden)
			return
		}
		if auth != nil {
			issuer, err := auth.AuthorizePeer(cert, r.TLS.PeerCertificates[1:])
			if err != nil {
				log.Printf("authz: refused %s %q from %s for %s (serial %s): %v", r.Method, r.URL.Path, r.RemoteAddr, id.CN, id.Serial, err)
				apperr.WriteHTTP(w, http.StatusForbidden, err)
				return
			}
			id.IssuerSHA256 = issuer
		}
		id.Via = ViaWeb
		ctx := context.WithValue(NewContext(r.Context(), id), peerCertCtxKey{}, cert)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// BypassMiddleware injects DevIdentity, for the AuthBypass dev path where the
// browser talks h2c and presents no client cert.
func BypassMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), DevIdentity)))
	})
}

// formatSerial renders a certificate serial as colon-separated uppercase hex.
func formatSerial(n *big.Int) string {
	b := n.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	parts := make([]string, len(b))
	const hexdigits = "0123456789ABCDEF"
	for i, by := range b {
		parts[i] = string([]byte{hexdigits[by>>4], hexdigits[by&0x0f]})
	}
	return strings.Join(parts, ":")
}
