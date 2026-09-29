package main

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
	"errors"
	"net/http"

	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/fleet"
	"github.com/CryptOS-PKI/manager/internal/mcpauth"
	"github.com/CryptOS-PKI/manager/internal/mcpserver"
	"github.com/CryptOS-PKI/manager/internal/oauth"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// mcpMount builds the routes for the MCP endpoint and its login. It refuses
// to build them without the operator CA pool and the revocation cache: every
// key is re-validated against both on each request, and serving /mcp without
// them would accept keys whose operator can no longer log in.
func mcpMount(
	publicURL string,
	svc *fleet.Service,
	st store.Store,
	keys *mcpauth.Keys,
	roots *x509.CertPool,
	revocations *authz.RevocationCache,
	certMW func(http.Handler) http.Handler,
	version string,
) (func(*http.ServeMux), error) {
	if roots == nil {
		return nil, errors.New("mcp: no operator CA pool to re-validate keys against")
	}
	if revocations == nil {
		return nil, errors.New("mcp: no operator revocation cache; set operator_ca_node")
	}

	login := &oauth.Server{Store: st, Keys: keys, PublicURL: publicURL}
	resolver := &mcpauth.Resolver{Store: st, Roots: roots, Revoked: revocations}
	endpoint := http.NewCrossOriginProtection().Handler(
		mcpauth.Middleware(resolver, login.ResourceMetadataURL())(mcpserver.Handler(svc, st, version)))

	return func(mux *http.ServeMux) {
		mux.Handle("/mcp", endpoint)
		login.Routes(mux, certMW)
	}, nil
}
