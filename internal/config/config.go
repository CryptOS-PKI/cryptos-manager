// Package config loads the manager's static node inventory and server
// settings from a YAML file.
package config

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
	"bytes"
	"errors"
	"fmt"
	"io"
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

	// TLSCert and TLSKey are the HTTPS server certificate and key, set
	// together or not at all. Unset, the manager serves a self-signed
	// bootstrap certificate. Ignored in the AuthBypass dev path (h2c).
	TLSCert string `yaml:"tlsCert"`
	TLSKey  string `yaml:"tlsKey"`

	// OperatorCAPath is a PEM file of operator CA certificates: the external
	// CA that signs operator client certificates. When set it is the only
	// source of operator CA trust and any operator CA registered in the
	// database is ignored. Unset, operator CAs are registered at first run.
	OperatorCAPath string `yaml:"operatorCAPath"`

	// OperatorCRL lists where the CRLs for the operatorCAPath operator CAs
	// come from; each CRL is matched to the CA that signed it. Only with
	// operatorCAPath: a registered operator CA keeps its CRL source on its
	// own record.
	OperatorCRL []CRLSource `yaml:"operatorCRL"`

	// OperatorOCSP says how to find the OCSP responder for the
	// operatorCAPath operator CAs. Only with operatorCAPath.
	OperatorOCSP OCSPConfig `yaml:"operatorOCSP"`

	// OperatorRevocationPolicy is what the web path does when no fresh
	// revocation data is available for a certificate: soft (the default)
	// keeps enforcing the last good CRL and the denylist, with a banner;
	// hard refuses. MCP always refuses.
	OperatorRevocationPolicy string `yaml:"operatorRevocationPolicy"`

	// FirstRun is auto (the default) or disabled. Disabled with no
	// operatorCAPath means no operator CA is trusted and every caller is
	// refused.
	FirstRun string `yaml:"firstRun"`

	// DatabaseURL is the Postgres connection DSN for durable state. Empty
	// selects the in-memory store, seeded from the built-in catalog, which
	// stays the default for offline dev and tests. A non-empty
	// MANAGER_DATABASE_URL (DatabaseURLEnv) overrides it.
	DatabaseURL string `yaml:"database_url"`

	// OperatorCANode is refused at load with OperatorCANodeMigration: a
	// CryptOS node can't be the operator CA. It is parsed only so the refusal
	// can say what to do instead of reporting an unknown key.
	OperatorCANode *string `yaml:"operator_ca_node"`

	// MCP serves the Model Context Protocol endpoint for AI agents at /mcp
	// on the same listener. Off by default.
	MCP MCPConfig `yaml:"mcp"`

	Nodes []NodeCfg `yaml:"nodes"`
}

// CRLSource is one operatorCRL entry: an http or https URL, or a file path,
// never both.
type CRLSource struct {
	URL  string `yaml:"url"`
	Path string `yaml:"path"`
}

// OCSPConfig is the OCSP mode for the operatorCAPath operator CAs: off, aia
// (the responder named in each certificate, the default) or url (the
// responder at URL).
type OCSPConfig struct {
	Mode string `yaml:"mode"`
	URL  string `yaml:"url"`
}

// Values for FirstRun, OperatorRevocationPolicy and OperatorOCSP.Mode.
const (
	FirstRunAuto         = "auto"
	FirstRunDisabled     = "disabled"
	RevocationPolicySoft = "soft"
	RevocationPolicyHard = "hard"
	OCSPModeOff          = "off"
	OCSPModeAIA          = "aia"
	OCSPModeURL          = "url"
)

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
// file paths for the admin mTLS client cert/key and the node's CA chain.
type NodeCfg struct {
	Name          string `yaml:"name"`
	Endpoint      string `yaml:"endpoint"`
	Role          string `yaml:"role"`
	AdminCertPath string `yaml:"adminCertPath"`
	AdminKeyPath  string `yaml:"adminKeyPath"`
	// CACertPath is the node's CA chain, which its management certificate is
	// verified against once the node signs it with its CA. Optional: a node
	// without a CA yet is verified by the server.crt pinned next to its admin
	// certificate.
	CACertPath string `yaml:"caCertPath"`
	// InsecureSkipNodeVerify dials the node without verifying its server
	// certificate, with a warning on every connection. Lab testing only;
	// never in production.
	InsecureSkipNodeVerify bool `yaml:"insecureSkipNodeVerify"`
}

// OperatorCANodeMigration is the load error for a config that still sets
// operator_ca_node.
const OperatorCANodeMigration = "operator_ca_node is no longer supported: CryptOS nodes can't be the operator CA. " +
	"Use an external operator CA (operatorCAPath or first-run registration) and, for revocation, " +
	"operatorCRL and the Fleet Manager denylist. See docs: migrating from operator_ca_node"

// DatabaseURLEnv overrides database_url when set and non-empty. The DSN
// carries the database password, and the loader does no interpolation, so
// this is how a deployment keeps it in a secret store rather than in
// config.yaml.
const DatabaseURLEnv = "MANAGER_DATABASE_URL"

// Load reads the YAML file at path and returns the parsed Config, or an
// error if the file cannot be read, the YAML is malformed, or validation
// fails.
func Load(path string) (Config, error) {
	var cfg Config

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg.MCP.PublicURL = strings.TrimRight(cfg.MCP.PublicURL, "/")
	if v := os.Getenv(DatabaseURLEnv); v != "" {
		cfg.DatabaseURL = v
	}

	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", path, err)
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen must not be empty")
	}
	if c.OperatorCANode != nil {
		return errors.New(OperatorCANodeMigration)
	}

	// tlsCert/tlsKey and operatorCAPath are deliberately optional. Omitting
	// them is how FleetOS is brought up from nothing (#78): the manager
	// generates a self-signed bootstrap certificate and accepts no operator
	// until one is minted. Supplying one of a pair is a mistake, though, and
	// is caught here rather than at TLS load.
	if !c.AuthBypass && (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("tlsCert and tlsKey must be set together, or both left unset to generate a bootstrap certificate")
	}

	if err := c.validateOperatorCA(); err != nil {
		return err
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
	}

	return nil
}

// validateMCP refuses any configuration in which an MCP key could not be
// re-validated live on every request. Each key stands for an operator
// certificate: under authBypass there is no certificate at all, and without
// Postgres there is no denylist, registered operator CA or revocation epoch
// to check it against. Whether the certificate's operator CA has a fresh CRL
// is checked per call, so MCP can be enabled before the CRL is set up.
func (c Config) validateMCP() error {
	if c.AuthBypass {
		return fmt.Errorf("mcp.enabled requires authBypass to be false: MCP keys are bound to operator certificates")
	}
	if c.DatabaseURL == "" {
		return fmt.Errorf("mcp.enabled requires database_url: the operator denylist, operator CAs and revocation epoch MCP keys are checked against live in Postgres")
	}
	u, err := url.Parse(c.MCP.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("mcp.public_url must be the manager's https origin with no path, for example https://fleetos.example.org")
	}
	return nil
}

// validateOperatorCA checks the operator CA trust and revocation keys and
// fills in their defaults.
func (c *Config) validateOperatorCA() error {
	switch c.FirstRun {
	case "":
		c.FirstRun = FirstRunAuto
	case FirstRunAuto, FirstRunDisabled:
	default:
		return fmt.Errorf("firstRun must be auto or disabled, not %q", c.FirstRun)
	}

	switch c.OperatorRevocationPolicy {
	case "":
		c.OperatorRevocationPolicy = RevocationPolicySoft
	case RevocationPolicySoft, RevocationPolicyHard:
	default:
		return fmt.Errorf("operatorRevocationPolicy must be soft or hard, not %q", c.OperatorRevocationPolicy)
	}

	if len(c.OperatorCRL) > 0 && c.OperatorCAPath == "" {
		return fmt.Errorf("operatorCRL needs operatorCAPath: a registered operator CA keeps its CRL source on its own record")
	}
	for i, src := range c.OperatorCRL {
		switch {
		case (src.URL == "") == (src.Path == ""):
			return fmt.Errorf("operatorCRL[%d] must set exactly one of url and path", i)
		case src.URL != "":
			if err := httpURL(src.URL); err != nil {
				return fmt.Errorf("operatorCRL[%d].url: %w", i, err)
			}
		}
	}

	if (c.OperatorOCSP.Mode != "" || c.OperatorOCSP.URL != "") && c.OperatorCAPath == "" {
		return fmt.Errorf("operatorOCSP needs operatorCAPath: a registered operator CA keeps its OCSP settings on its own record")
	}
	switch c.OperatorOCSP.Mode {
	case "":
		c.OperatorOCSP.Mode = OCSPModeAIA
	case OCSPModeOff, OCSPModeAIA, OCSPModeURL:
	default:
		return fmt.Errorf("operatorOCSP.mode must be off, aia or url, not %q", c.OperatorOCSP.Mode)
	}
	if c.OperatorOCSP.Mode == OCSPModeURL {
		if err := httpURL(c.OperatorOCSP.URL); err != nil {
			return fmt.Errorf("operatorOCSP.url is required with mode url: %w", err)
		}
	} else if c.OperatorOCSP.URL != "" {
		return fmt.Errorf("operatorOCSP.url is only used with mode url, not %s", c.OperatorOCSP.Mode)
	}
	return nil
}

// httpURL accepts an absolute http or https URL with a host.
func httpURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%q is not an http or https URL", raw)
	}
	return nil
}
