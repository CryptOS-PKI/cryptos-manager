package config

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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_RealExampleConfig(t *testing.T) {
	cfg, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Listen != "127.0.0.1:8080" {
		t.Errorf("Listen = %q, want 127.0.0.1:8080", cfg.Listen)
	}
	if !cfg.AuthBypass {
		t.Errorf("AuthBypass = false, want true")
	}
	if len(cfg.Nodes) != 2 {
		t.Fatalf("len(Nodes) = %d, want 2", len(cfg.Nodes))
	}

	root := cfg.Nodes[0]
	if root.Name != "pki-root" {
		t.Errorf("Nodes[0].Name = %q, want pki-root", root.Name)
	}
	if root.Endpoint != "pki-root.acme.com:4443" {
		t.Errorf("Nodes[0].Endpoint = %q, want pki-root.acme.com:4443", root.Endpoint)
	}
	if root.Role != "root" {
		t.Errorf("Nodes[0].Role = %q, want root", root.Role)
	}

	inter := cfg.Nodes[1]
	if inter.Name != "pki-inter" {
		t.Errorf("Nodes[1].Name = %q, want pki-inter", inter.Name)
	}
	if inter.Endpoint != "pki-inter.acme.com:4444" {
		t.Errorf("Nodes[1].Endpoint = %q, want pki-inter.acme.com:4444", inter.Endpoint)
	}
	if inter.Role != "intermediate" {
		t.Errorf("Nodes[1].Role = %q, want intermediate", inter.Role)
	}
}

func TestLoad_DatabaseURLParses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
listen: "127.0.0.1:8080"
authBypass: true
database_url: "postgres://user:pw@db:5432/manager"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DatabaseURL != "postgres://user:pw@db:5432/manager" {
		t.Errorf("DatabaseURL = %q, want postgres://user:pw@db:5432/manager", cfg.DatabaseURL)
	}
}

func TestLoad_DatabaseURLDefaultsEmpty(t *testing.T) {
	cfg, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DatabaseURL != "" {
		t.Errorf("DatabaseURL = %q, want empty (in-memory default)", cfg.DatabaseURL)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("Load() error = nil, want error for missing file")
	}
}

func TestLoad_NodeMissingEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
listen: "127.0.0.1:8080"
nodes:
  - name: pki-root
    role: root
    adminCertPath: /tmp/admin.crt
    adminKeyPath: /tmp/admin.key
    caCertPath: /tmp/ca.pem
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want error for node missing endpoint")
	}
}

func TestLoad_MissingListen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
nodes:
  - name: pki-root
    endpoint: "pki-root.acme.com:4443"
    role: root
    adminCertPath: /tmp/admin.crt
    adminKeyPath: /tmp/admin.key
    caCertPath: /tmp/ca.pem
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want error for missing listen")
	}
}

// TestValidate_TLSMaterialOptionalWhenNotBypass: omitting the TLS material and
// the operator CA is how FleetOS is brought up from nothing (#78). It used to be
// rejected, which left `authBypass: true` -- plaintext h2c with authentication
// disabled -- as the only way to start a fresh host. The manager now generates a
// self-signed bootstrap certificate and accepts no operator until one is minted.
func TestValidate_TLSMaterialOptionalWhenNotBypass(t *testing.T) {
	c := Config{Listen: "0.0.0.0:8443", AuthBypass: false}
	if err := c.validate(); err != nil {
		t.Fatalf("validate() = %v, want nil for a day-zero config", err)
	}

	c = Config{
		Listen:         "0.0.0.0:8443",
		AuthBypass:     false,
		TLSCert:        "/srv/tls.crt",
		TLSKey:         "/srv/tls.key",
		OperatorCAPath: "/srv/operator-ca.pem",
	}
	if err := c.validate(); err != nil {
		t.Fatalf("validate() = %v, want nil with TLS material present", err)
	}
}

// Half a pair is a typo, not a day-zero choice, and silently generating a
// bootstrap certificate would hide it.
func TestValidate_TLSPairMustBeSetTogether(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"cert without key", Config{Listen: ":8443", TLSCert: "/srv/tls.crt"}},
		{"key without cert", Config{Listen: ":8443", TLSKey: "/srv/tls.key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.validate(); err == nil {
				t.Error("validate() = nil, want an error for half a TLS pair")
			}
		})
	}
}

func TestValidate_TLSOptionalWhenBypass(t *testing.T) {
	c := Config{Listen: "127.0.0.1:8080", AuthBypass: true}
	if err := c.validate(); err != nil {
		t.Fatalf("validate() = %v, want nil (bypass needs no TLS)", err)
	}
}

// TestLoad_HTTPRedirectFields covers the #70 plumbing: the redirect listener and
// the public HTTPS port have to survive the round trip through YAML, and the
// public port is separate from the listener precisely because the container's
// published port differs from the one it binds.
func TestLoad_HTTPRedirectFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `listen: "0.0.0.0:8443"
authBypass: true
httpRedirectListen: "0.0.0.0:8080"
httpsPublicPort: "443"
nodes:
  - name: n1
    endpoint: n1.example:4443
    role: root
    adminCertPath: /tmp/admin.crt
    adminKeyPath: /tmp/admin.key
    caCertPath: /tmp/ca.pem
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPRedirectListen != "0.0.0.0:8080" {
		t.Errorf("HTTPRedirectListen = %q, want 0.0.0.0:8080", cfg.HTTPRedirectListen)
	}
	if cfg.HTTPSPublicPort != "443" {
		t.Errorf("HTTPSPublicPort = %q, want 443", cfg.HTTPSPublicPort)
	}
}

// Omitting the fields disables the redirect rather than failing to start, so a
// bare-host deployment that cannot bind port 80 is unaffected.
func TestLoad_HTTPRedirectOptional(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `listen: "0.0.0.0:8443"
authBypass: true
nodes:
  - name: n1
    endpoint: n1.example:4443
    role: root
    adminCertPath: /tmp/admin.crt
    adminKeyPath: /tmp/admin.key
    caCertPath: /tmp/ca.pem
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPRedirectListen != "" {
		t.Errorf("HTTPRedirectListen = %q, want empty", cfg.HTTPRedirectListen)
	}
}

// TestLoad_DeployExampleConfig keeps the shipped compose example honest. It is
// the file an adopter copies to /etc/cryptos/fleet/config.yaml, so if it stops
// parsing -- or stops matching the listener layout compose publishes -- their
// first deployment fails and ours passes.
func TestLoad_DeployExampleConfig(t *testing.T) {
	cfg, err := Load("../../deploy/config.example.yaml")
	if err != nil {
		t.Fatalf("Load(deploy/config.example.yaml): %v", err)
	}

	// The container binds high ports; compose publishes 443 and 80.
	if cfg.Listen != "0.0.0.0:8443" {
		t.Errorf("Listen = %q, want 0.0.0.0:8443", cfg.Listen)
	}
	if cfg.HTTPRedirectListen != "0.0.0.0:8080" {
		t.Errorf("HTTPRedirectListen = %q, want 0.0.0.0:8080", cfg.HTTPRedirectListen)
	}
	// An example that ships with auth off would be a trap.
	if cfg.AuthBypass {
		t.Error("AuthBypass = true in the shipped example, want false")
	}
	if cfg.DatabaseURL == "" {
		t.Error("DatabaseURL is empty; the compose example runs against Postgres")
	}
	// The DSN host has to be the compose service name, or the manager cannot
	// reach the database it is shipped with.
	if !strings.Contains(cfg.DatabaseURL, "@postgres:5432/") {
		t.Errorf("DatabaseURL = %q, want the compose service name as the host", cfg.DatabaseURL)
	}
	if len(cfg.Nodes) == 0 {
		t.Error("no nodes in the example; the node block is what adopters edit first")
	}
}
