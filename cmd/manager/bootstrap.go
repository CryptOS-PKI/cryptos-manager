package main

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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"

	"github.com/CryptOS-PKI/manager/internal/bootstrap"
	"github.com/CryptOS-PKI/manager/internal/config"
	"github.com/CryptOS-PKI/manager/internal/operatorca"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// setupBootstrap builds the first-run service over the running operator
// trust, prints the first token when first run is open, and returns the
// route that mounts it. main mounts it on the TLS server only, never on the
// plaintext bypass listener, and outside the certificate middleware. bs is
// nil without Postgres, which leaves first run unavailable.
func setupBootstrap(ctx context.Context, cfg config.Config, st store.Store, bs bootstrap.Store, trust *operatorTrust, base *tls.Config, logf func(string, ...any)) (*bootstrap.Service, func(*http.ServeMux), error) {
	var server bootstrap.ServerInfo
	if len(base.Certificates) > 0 && base.Certificates[0].Leaf != nil {
		leaf := base.Certificates[0].Leaf
		server = bootstrap.ServerInfo{SHA256: operatorca.ColonFingerprint(leaf.Raw), NotAfter: leaf.NotAfter}
	}
	svc, err := bootstrap.New(ctx, bootstrap.Options{
		Store:            bs,
		Audit:            st,
		Trust:            trust.trust,
		Rev:              trust.rev,
		FirstRunDisabled: cfg.FirstRun == config.FirstRunDisabled,
		NodeCAs: func() []*x509.Certificate {
			return operatorca.NodeCAs(st.Nodes(), os.ReadFile, logf)
		},
		FetchCRL:       operatorca.NewFetcher(operatorca.FetchLimits{Timeout: operatorca.DefaultFetchTimeout, MaxBytes: operatorca.MaxCRLSize}).Fetch,
		TrustedOrigins: cfg.CORSOrigins,
		Server:         server,
		Logf:           logf,
	})
	if err != nil {
		return nil, nil, err
	}
	if err := svc.Start(ctx); err != nil {
		return nil, nil, err
	}
	path, handler := svc.Handler()
	return svc, func(mux *http.ServeMux) { mux.Handle(path, handler) }, nil
}
