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
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// nodeUnderTest is one node a lab gate run (or the cryptos-lab tooling)
// already installed and handed admin credentials for. The field names and
// shapes mirror internal/config.NodeCfg, the manager's own static inventory
// entry, so the same YAML a human would hand-write for config.yaml works
// here unchanged; spare marks the one node (if any) this run may rekey,
// decommission or import an escrowed identity onto, since those write paths
// are destructive and must never land on a node the gate or another run
// still depends on.
type nodeUnderTest struct {
	Name                   string `yaml:"name"`
	Endpoint               string `yaml:"endpoint"`
	Role                   string `yaml:"role"`
	AdminCertPath          string `yaml:"adminCertPath"`
	AdminKeyPath           string `yaml:"adminKeyPath"`
	CACertPath             string `yaml:"caCertPath"`
	InsecureSkipNodeVerify bool   `yaml:"insecureSkipNodeVerify"`
	Spare                  bool   `yaml:"spare"`
}

// nodesFile is the shape of the file E2E_NODES_FILE names.
type nodesFile struct {
	Nodes []nodeUnderTest `yaml:"nodes"`
}

// config is the run's full configuration, loaded from environment variables
// so the script runs the same way by hand or from a future CI step: source an
// env file, then run it. No field here is ever logged unredacted.
type config struct {
	ManagerBin   string
	DatabaseURL  string
	AdminEmail   string
	Nodes        []nodeUnderTest
	WorkDir      string
	StepTimeout  time.Duration
	ImageURL     string
	ImageSigPath string
	ImageSHA256  string
	// RekeyNode and RekeyProfile opt the rekey step in: RekeyNode must name a
	// configured subordinate CA node, and RekeyProfile the profile its parent
	// signs the new CSR under. Both empty skips the step: rekeying a node is
	// destructive to whatever reused it, so this never runs without an
	// explicit target.
	RekeyNode    string
	RekeyProfile string
	// ScepURL is the primary node's SCEP listener as this script reaches it
	// (http://host:port/scep). It opts the device enrolment step in; empty
	// skips it, since the listener's address is not something the node's
	// own API reports.
	ScepURL string
	// EscrowNode names the node the escrow export runs against. Empty means
	// the primary node. A TPM-held CA key is never exportable, so a run whose
	// primary is a TPM node points this at a software-key node instead.
	EscrowNode string
	// ManagerListen is the loopback address the throwaway manager binds.
	ManagerListen string
	// ResultsFile, when set, is where the step results are written as JSON
	// once the run ends, for a harness that reports them on its own.
	ResultsFile string
}

// requiredEnv names the environment variables loadConfig refuses to start
// without.
var requiredEnv = []string{
	"E2E_MANAGER_BIN",
	"E2E_DATABASE_URL",
	"E2E_ADMIN_EMAIL",
	"E2E_NODES_FILE",
}

const defaultStepTimeout = 2 * time.Minute

// defaultManagerListen is the loopback address the throwaway manager binds
// unless E2E_MANAGER_LISTEN names another, for a host where something else
// already holds the port.
const defaultManagerListen = "127.0.0.1:18443"

// loadConfig reads the run's configuration from the environment, using
// getenv so tests never touch the real process environment. readFile loads
// the nodes file; tests substitute a fake so no real file is needed. It
// returns a clear error naming every missing required variable at once,
// never a value.
func loadConfig(getenv func(string) string, readFile func(string) ([]byte, error)) (config, error) {
	var missing []string
	for _, name := range requiredEnv {
		if getenv(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return config{}, fmt.Errorf("missing required settings: %s (set them in a sourced env file; see docs/e2e-esxi.md)", strings.Join(missing, ", "))
	}

	cfg := config{
		ManagerBin:    getenv("E2E_MANAGER_BIN"),
		DatabaseURL:   getenv("E2E_DATABASE_URL"),
		AdminEmail:    getenv("E2E_ADMIN_EMAIL"),
		WorkDir:       getenv("E2E_WORKDIR"),
		ImageURL:      getenv("E2E_IMAGE_URL"),
		ImageSigPath:  getenv("E2E_IMAGE_SIGNATURE_PATH"),
		ImageSHA256:   getenv("E2E_IMAGE_SHA256"),
		RekeyNode:     getenv("E2E_REKEY_NODE"),
		RekeyProfile:  getenv("E2E_REKEY_PROFILE"),
		ScepURL:       getenv("E2E_SCEP_URL"),
		EscrowNode:    getenv("E2E_ESCROW_NODE"),
		ManagerListen: getenv("E2E_MANAGER_LISTEN"),
		ResultsFile:   getenv("E2E_RESULTS_FILE"),
		StepTimeout:   defaultStepTimeout,
	}
	if cfg.ManagerListen == "" {
		cfg.ManagerListen = defaultManagerListen
	}
	if cfg.WorkDir == "" {
		return config{}, fmt.Errorf("E2E_WORKDIR is required: a tmpfs directory for the run's throwaway config and keys")
	}
	if raw := getenv("E2E_STEP_TIMEOUT"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return config{}, fmt.Errorf("E2E_STEP_TIMEOUT: %w", err)
		}
		cfg.StepTimeout = d
	}

	nodesPath := getenv("E2E_NODES_FILE")
	raw, err := readFile(nodesPath)
	if err != nil {
		return config{}, fmt.Errorf("reading E2E_NODES_FILE: %w", err)
	}
	var nf nodesFile
	if err := yaml.Unmarshal(raw, &nf); err != nil {
		return config{}, fmt.Errorf("parsing E2E_NODES_FILE: %w", err)
	}
	if len(nf.Nodes) == 0 {
		return config{}, fmt.Errorf("E2E_NODES_FILE lists no nodes")
	}
	spares := 0
	for i, n := range nf.Nodes {
		if n.Name == "" || n.Endpoint == "" || n.AdminCertPath == "" || n.AdminKeyPath == "" {
			return config{}, fmt.Errorf("E2E_NODES_FILE: node %d needs name, endpoint, adminCertPath and adminKeyPath", i)
		}
		if n.Spare {
			spares++
		}
	}
	if spares > 1 {
		return config{}, fmt.Errorf("E2E_NODES_FILE: only one node may be marked spare, got %d", spares)
	}
	cfg.Nodes = nf.Nodes
	if cfg.EscrowNode != "" {
		if _, ok := cfg.findNode(cfg.EscrowNode); !ok {
			return config{}, fmt.Errorf("E2E_ESCROW_NODE names %q, which is not in E2E_NODES_FILE", cfg.EscrowNode)
		}
	}
	return cfg, nil
}

// spareNode returns the node marked spare, if any. The destructive steps
// (rekey, escrow import, enrollment link, decommission) only run against it.
func (c config) spareNode() (nodeUnderTest, bool) {
	for _, n := range c.Nodes {
		if n.Spare {
			return n, true
		}
	}
	return nodeUnderTest{}, false
}

// findNode returns the configured node named name.
func (c config) findNode(name string) (nodeUnderTest, bool) {
	for _, n := range c.Nodes {
		if n.Name == name {
			return n, true
		}
	}
	return nodeUnderTest{}, false
}

// secretsToRedact lists every value from cfg that must never reach this
// script's own stdout/stderr unredacted: each node's endpoint and credential
// paths, the database URL (which carries a password) and the SCEP URL.
func (c config) secretsToRedact() []string {
	out := []string{c.DatabaseURL}
	for _, n := range c.Nodes {
		out = append(out, n.Endpoint, n.AdminCertPath, n.AdminKeyPath, n.CACertPath)
	}
	if c.ScepURL != "" {
		out = append(out, c.ScepURL)
	}
	return out
}

// readFileOS adapts os.ReadFile to loadConfig's readFile parameter.
func readFileOS(path string) ([]byte, error) { return os.ReadFile(path) }

// osGetenv adapts os.Getenv to loadConfig's getenv parameter.
func osGetenv(name string) string { return os.Getenv(name) }
