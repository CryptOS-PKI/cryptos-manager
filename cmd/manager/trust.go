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
	"fmt"
	"os"

	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/config"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// operatorTrust is the running operator CA trust: the anchors, their
// revocation data, and the loops that keep both current. web is the
// authorizer the API path uses: auth, plus recording every certificate seen
// in use when Postgres is configured.
type operatorTrust struct {
	trust     *operatorca.TrustStore
	rev       *operatorca.Revocations
	poller    *operatorca.Poller
	refresher *operatorca.CRLRefresher
	auth      operatorca.PeerAuthorizer
	web       authz.PeerAuthorizer
	observed  *operatorca.ObservedRecorder
}

// setupOperatorTrust resolves the operator CA source, builds the trust store
// on base, and loads the denylist and every stored CRL before anything is
// served. A config-file operator CA that is a CryptOS node's CA stops the
// start.
func setupOperatorTrust(ctx context.Context, cfg config.Config, st store.Store, ot store.OperatorTrust, base *tls.Config, logf func(string, ...any)) (*operatorTrust, error) {
	nodeCAs := operatorca.NodeCAs(st.Nodes(), os.ReadFile, logf)
	src, err := operatorca.Resolve(ctx, cfg, ot, nodeCAs, logf)
	if err != nil {
		return nil, err
	}
	rev := operatorca.NewRevocations(operatorca.RevocationOptions{
		Store:  ot,
		Policy: src.Policy,
		Logf:   logf,
		Audit:  func(e store.AuditEvent) { auditlog.Record(context.Background(), st, e) },
		// OCSP per anchor (off, aia or url); the file source takes the mode
		// from operatorOCSP, a registered CA from its row.
		OCSPFetcher: operatorca.NewOCSPFetcher(),
	})
	trust, err := operatorca.NewTrustStore(ctx, src, ot, rev, base, logf)
	if err != nil {
		return nil, err
	}
	if err := rev.Reload(ctx); err != nil {
		return nil, fmt.Errorf("load operator revocation data: %w", err)
	}
	var rebuilder operatorca.Rebuilder
	if src.Kind == operatorca.KindRegistered {
		rebuilder = trust
	}
	auth := operatorca.PeerAuthorizer{Trust: trust, Rev: rev}
	var (
		web      authz.PeerAuthorizer = auth
		observed *operatorca.ObservedRecorder
	)
	// Observed credentials are rows in Postgres; the in-memory store has
	// nowhere to keep them.
	if cs, ok := st.(store.OperatorCredentialStore); ok && cfg.DatabaseURL != "" {
		observed = operatorca.NewObservedRecorder(operatorca.ObservedOptions{Store: cs, Logf: logf})
		web = observed.Authorizer(auth)
	}
	return &operatorTrust{
		trust:  trust,
		rev:    rev,
		poller: operatorca.NewPoller(ot, rebuilder, rev, logf),
		refresher: &operatorca.CRLRefresher{
			Rev: rev, Store: ot, ReadFile: os.ReadFile, Logf: logf, FileTargets: src.CRLTargets,
			Fetch: operatorca.NewFetcher(operatorca.FetchLimits{Timeout: operatorca.DefaultFetchTimeout, MaxBytes: operatorca.MaxCRLSize}),
		},
		auth:     auth,
		web:      web,
		observed: observed,
	}, nil
}

// refreshCRLs fetches every CRL once, so a CRL source is enforced from the
// first request rather than from the refresher's first pass. A failure is
// logged and left to the policy and the refresher's retries.
func (o *operatorTrust) refreshCRLs(ctx context.Context, logf func(string, ...any)) {
	for _, t := range o.refresher.Targets() {
		if _, err := o.refresher.RefreshOnce(ctx, t); err != nil {
			logf("manager: WARNING first CRL fetch from %s failed: %v", t.Source, err)
		}
	}
}

// run starts the trust poll and the CRL refresher.
func (o *operatorTrust) run(ctx context.Context, logf func(string, ...any)) {
	go o.poller.Run(ctx, operatorca.DefaultPollInterval)
	go o.refresher.Run(ctx)
	if o.observed != nil {
		go o.observed.Run(ctx)
	}
	logf("manager: operator CA source %s, revocation policy %s", o.trust.Source().Kind, o.rev.Policy())
}

// serverTLSConfig is the listener's TLS config: base, with every handshake
// handed the trust store's current generation.
func serverTLSConfig(base *tls.Config, trust *operatorca.TrustStore) *tls.Config {
	cfg := base.Clone()
	cfg.GetConfigForClient = trust.GetConfigForClient
	return cfg
}
