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
	"errors"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/CryptOS-PKI/cryptos-manager/internal/bootstrap"
	"github.com/CryptOS-PKI/cryptos-manager/internal/config"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/postgres"
)

// runResetFirstRun is -reset-first-run: the offline break-glass reset.
// Access to the host and the database is the authority, so it asks for
// nothing else.
func runResetFirstRun(ctx context.Context, cfg config.Config, out io.Writer) error {
	if cfg.DatabaseURL == "" {
		return errors.New("first run is kept in Postgres and no database_url is configured, so there is nothing to reset")
	}
	pg, err := postgres.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pg.Close()

	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return bootstrap.Reset(ctx, bootstrap.ResetOptions{
		Store:            pg,
		Audit:            pg,
		Live:             func(ctx context.Context) bool { return managerAnswers(ctx, cfg) },
		FileSource:       cfg.OperatorCAPath != "",
		FirstRunDisabled: cfg.FirstRun == config.FirstRunDisabled,
		Host:             host,
		Out:              out,
	})
}

// managerAnswers reports whether anything answers the health endpoint on
// the configured listen address. Any HTTP answer counts, a 503 from a
// manager that lost its database included: only a refused or timed-out
// connection means no manager is serving there.
func managerAnswers(ctx context.Context, cfg config.Config) bool {
	url, err := healthProbeURL(cfg)
	if err != nil {
		log.Printf("manager: can't build the health probe address, so assuming a manager is running: %v", err)
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Printf("manager: can't build the health probe, so assuming a manager is running: %v", err)
		return true
	}
	client := &http.Client{Transport: &http.Transport{
		// Only whether something answers matters here; nothing is sent.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // loopback liveness probe, see above
	}}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}
