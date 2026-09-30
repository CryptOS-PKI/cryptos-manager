// Package config loads the manager's static node inventory and server
// settings from a YAML file.
package config

/*
Apache License 2.0

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
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the manager's top-level configuration: the address it listens
// on, the CORS origins it allows, whether to bypass auth (dev-only), and
// the static fleet inventory it dials out to.
type Config struct {
	Listen      string   `yaml:"listen"`
	CORSOrigins []string `yaml:"corsOrigins"`
	AuthBypass  bool     `yaml:"authBypass"`

	// HTTPRedirectListen is the plaintext address whose only job is to redirect
	// to HTTPS, so an operator who types a hostname without a scheme reaches the
	// login page instead of a refused connection (#70). Empty disables it.
	// Bare host: ":80". Container: ":8080", published as 80, because the image
	// runs unprivileged and cannot bind a low port.
	HTTPRedirectListen string `yaml:"httpRedirectListen"`

	// HTTPSPublicPort is the HTTPS port clients actually reach, used as the
	// redirect target. It is not the port the manager listens on: the container
	// serves 8443 internally and is published on 443, so the redirect has to
	// name the published port, not the listener's. Empty means 443 and leaves
	// the port implicit in the redirect.
	HTTPSPublicPort string `yaml:"httpsPublicPort"`

	// TLS + client-auth material. Required when AuthBypass is false: the
	// manager then serves HTTPS and verifies a client certificate against
	// OperatorCA when one is presented. Ignored in the AuthBypass dev path
	// (h2c).
	TLSCert        string `yaml:"tlsCert"`
	TLSKey         string `yaml:"tlsKey"`
	OperatorCAPath string `yaml:"operatorCAPath"`

	// DatabaseURL is the Postgres connection DSN for durable state. Empty
	// selects the in-memory store, seeded from the built-in catalog, which
	// stays the default for offline dev and tests.
	DatabaseURL string `yaml:"database_url"`

	// OperatorCANode names the fleet node that acts as the operator CA:
	// operator-credential issuance and revocation (S9) route there, and the
	// manager fetches its revoked serials to enforce operator-cert revocation
	// at the authz middleware. Empty disables operator-credential management
	// and revocation enforcement.
	OperatorCANode string `yaml:"operator_ca_node"`

	// MCP serves the Model Context Protocol endpoint for AI agents at /mcp
	// on the same listener. Off by default.
	MCP MCPConfig `yaml:"mcp"`

	Nodes []NodeCfg `yaml:"nodes"`
}

// MCPConfig switches the MCP endpoint on and names the origin agents and
// browsers reach the manager at.
type MCPConfig struct {
	Enabled bool `yaml:"enabled"`
	// PublicURL is the external https origin, for example
	// https://fleetos.example.org. It is the OAuth issuer and the base of the
	// protected resource URL (PublicURL + "/mcp"), so it must be exactly what
	// clients connect to.
	PublicURL string `yaml:"public_url"`
}

// NodeCfg describes one fleet node: where to dial it, its role, and the
// file paths for the admin mTLS client cert/key and the CA used to pin the
// node's identity.
type NodeCfg struct {
	Name          string `yaml:"name"`
	Endpoint      string `yaml:"endpoint"`
	Role          string `yaml:"role"`
	AdminCertPath string `yaml:"adminCertPath"`
	AdminKeyPath  string `yaml:"adminKeyPath"`
	CACertPath    string `yaml:"caCertPath"`
}

// Load reads the YAML file at path and returns the parsed Config, or an
// error if the file cannot be read, the YAML is malformed, or validation
// fails.
func Load(path string) (Config, error) {
	var cfg Config

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg.MCP.PublicURL = strings.TrimRight(cfg.MCP.PublicURL, "/")

	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", path, err)
	}

	return cfg, nil
}

func (c Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen must not be empty")
	}

	// tlsCert/tlsKey and operatorCAPath are deliberately optional. Omitting
	// them is how FleetOS is brought up from nothing (#78): the manager
	// generates a self-signed bootstrap certificate and accepts no operator
	// until one is minted. Supplying one of a pair is a mistake, though, and
	// is caught here rather than at TLS load.
	if !c.AuthBypass && (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("tlsCert and tlsKey must be set together, or both left unset to generate a bootstrap certificate")
	}

	if c.MCP.Enabled {
		if err := c.validateMCP(); err != nil {
			return err
		}
	}

	for i, n := range c.Nodes {
		if n.Name == "" {
			return fmt.Errorf("nodes[%d]: name must not be empty", i)
		}
		if n.Endpoint == "" {
			return fmt.Errorf("nodes[%d] (%s): endpoint must not be empty", i, n.Name)
		}
		if n.Role == "" {
			return fmt.Errorf("nodes[%d] (%s): role must not be empty", i, n.Name)
		}
		if n.AdminCertPath == "" {
			return fmt.Errorf("nodes[%d] (%s): adminCertPath must not be empty", i, n.Name)
		}
		if n.AdminKeyPath == "" {
			return fmt.Errorf("nodes[%d] (%s): adminKeyPath must not be empty", i, n.Name)
		}
		if n.CACertPath == "" {
			return fmt.Errorf("nodes[%d] (%s): caCertPath must not be empty", i, n.Name)
		}
	}

	return nil
}

// validateMCP refuses any configuration in which an MCP key could not be
// re-validated live on every request. Each key stands for an operator
// certificate, so without the operator CA and its revocation source there is
// nothing to check it against, and under authBypass there is no certificate
// at all.
func (c Config) validateMCP() error {
	if c.AuthBypass {
		return fmt.Errorf("mcp.enabled requires authBypass to be false: MCP keys are bound to operator certificates")
	}
	if c.OperatorCANode == "" {
		return fmt.Errorf("mcp.enabled requires operator_ca_node: without an operator revocation source a revoked operator's keys would keep working")
	}
	if c.OperatorCAPath == "" {
		return fmt.Errorf("mcp.enabled requires operatorCAPath: MCP keys are re-validated against the operator CA on every request")
	}
	u, err := url.Parse(c.MCP.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("mcp.public_url must be the manager's https origin with no path, for example https://fleetos.example.org")
	}
	return nil
}
