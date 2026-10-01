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

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos-manager/internal/config"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// rootMounts is the optional route sets for the root handler: base, plus
// BootstrapService only when the manager serves TLS. Under authBypass the
// listener is plaintext, so the bootstrap mount is never added there.
func rootMounts(cfg config.Config, base []func(*http.ServeMux), boot func(*http.ServeMux)) []func(*http.ServeMux) {
	if cfg.AuthBypass || boot == nil {
		return base
	}
	return append(base, boot)
}

// ocspProbe is the registration probe for a url-mode OCSP responder, run by
// the revocation engine's OCSP client. It is nil when there is no client.
// The client reports only whether the responder gave a validly signed
// answer, so the probe returns no details for the preview.
func ocspProbe(rev *operatorca.Revocations) bootstrap.OCSPProbe {
	client := rev.OCSP()
	if client == nil {
		return nil
	}
	return func(ctx context.Context, anchor *x509.Certificate, url string) (*fleetv1.OcspProbeResult, error) {
		return nil, client.Probe(ctx, anchor, url)
	}
}

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
		OCSPProbe:      ocspProbe(trust.rev),
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
