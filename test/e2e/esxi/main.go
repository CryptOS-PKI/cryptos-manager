// Command esxi runs a scripted, live write-path exercise against real
// CryptOS nodes that a lab gate run (or the cryptos-lab tooling) already
// installed and handed admin credentials for: it starts a throwaway Fleet
// Manager, links it to those nodes, and drives every write path the manager
// exposes through its public API, checking each result on the node itself.
// See docs/e2e-esxi.md for prerequisites and how to run it (task e2e:esxi).
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
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1/fleetv1connect"
	mgrconfig "github.com/CryptOS-PKI/cryptos-manager/internal/config"
)

// printf writes a progress line to w. Nothing this script prints is load
// bearing for its exit code, so a write failure here is not worth aborting
// the run over; it would already have shown up as the run's own stdout being
// gone, which is loud enough on its own.
func printf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// managerListen is the loopback address the throwaway manager binds for the
// run. The port is fixed rather than chosen dynamically because nothing else
// on this box's loopback should be using it during a run that owns its own
// tmpfs work directory and exits when it's done.
const managerListen = "127.0.0.1:18443"

// managerStopTimeout bounds how long this script waits for a clean manager
// shutdown before killing it.
const managerStopTimeout = 5 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "esxi: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg, err := loadConfig(osGetenv, readFileOS)
	if err != nil {
		return err
	}
	red := newRedactor(cfg.secretsToRedact()...)
	out := red.writer(os.Stdout)
	defer func() { _ = out.Close() }()

	printf(out, "esxi: targeting %d node(s)\n", len(cfg.Nodes))

	configPath, err := writeManagerConfig(cfg)
	if err != nil {
		return fmt.Errorf("writing the manager's config: %w", err)
	}

	mp, err := startManager(ctx, cfg.ManagerBin, configPath, red, os.Stdout)
	if err != nil {
		return err
	}
	defer mp.stop(managerStopTimeout)

	baseURL := "https://" + managerListen
	healthCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = waitHealthy(healthCtx, baseURL)
	cancel()
	if err != nil {
		return fmt.Errorf("%w (manager exit error, if any: %v)", err, mp.exitErr)
	}
	printf(out, "esxi: manager is healthy\n")

	bootCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	boot, err := runBootstrap(bootCtx, mp, baseURL, cfg.AdminEmail)
	cancel()
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	printf(out, "esxi: bootstrapped the operator CA and the first admin credential\n")

	fleet := fleetv1connect.NewFleetServiceClient(boot.client, baseURL)
	s := newScenario(fleet, cfg, boot.ca, boot.caKey)

	results := runSteps(ctx, s.allSteps(cfg), cfg.StepTimeout, func(r stepResult) {
		printf(out, "%-5s %-40s %s\n", r.status, r.name, r.detail)
	})
	printf(out, "%s", summary(results))

	if anyFailed(results) {
		return fmt.Errorf("one or more write paths failed; see the step results above")
	}
	return nil
}

// writeManagerConfig renders the manager's own config.yaml under cfg.WorkDir
// (tmpfs): authBypass stays false and database_url is set, since only that
// combination wires up BootstrapService and the operator-CA/credential write
// paths this run exercises (internal/config, cmd/manager/bootstrap.go). TLS
// is left unset so the manager serves its own self-signed bootstrap
// certificate; this script never needs to trust it beyond the run's own
// loopback lifetime. The spare node, if any, is deliberately left out of the
// static inventory: it only becomes known to the manager through the
// enrollment step, the live write path this run is there to prove.
func writeManagerConfig(cfg config) (string, error) {
	mc := mgrconfig.Config{
		Listen:      managerListen,
		AuthBypass:  false,
		DatabaseURL: cfg.DatabaseURL,
	}
	for _, n := range cfg.Nodes {
		if n.Spare {
			continue
		}
		mc.Nodes = append(mc.Nodes, mgrconfig.NodeCfg{
			Name: n.Name, Endpoint: n.Endpoint, Role: n.Role,
			AdminCertPath: n.AdminCertPath, AdminKeyPath: n.AdminKeyPath, CACertPath: n.CACertPath,
			InsecureSkipNodeVerify: n.InsecureSkipNodeVerify,
		})
	}
	data, err := yaml.Marshal(mc)
	if err != nil {
		return "", fmt.Errorf("rendering config.yaml: %w", err)
	}
	path := filepath.Join(cfg.WorkDir, "config.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}
