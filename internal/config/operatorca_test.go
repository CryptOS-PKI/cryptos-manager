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
	"strings"
	"testing"
)

const fileSource = `
listen: ":8443"
operatorCAPath: /etc/fleet/operator-ca.pem
`

func TestLoad_OperatorCADefaults(t *testing.T) {
	cfg, err := loadYAML(t, fileSource)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.FirstRun != FirstRunAuto {
		t.Errorf("FirstRun = %q, want %q", cfg.FirstRun, FirstRunAuto)
	}
	if cfg.OperatorRevocationPolicy != RevocationPolicySoft {
		t.Errorf("OperatorRevocationPolicy = %q, want %q", cfg.OperatorRevocationPolicy, RevocationPolicySoft)
	}
	if cfg.OperatorOCSP.Mode != OCSPModeAIA {
		t.Errorf("OperatorOCSP.Mode = %q, want %q", cfg.OperatorOCSP.Mode, OCSPModeAIA)
	}
}

func TestLoad_FirstRun(t *testing.T) {
	cfg, err := loadYAML(t, "listen: \":8443\"\nfirstRun: disabled\n")
	if err != nil || cfg.FirstRun != FirstRunDisabled {
		t.Fatalf("Load() = %+v, %v; want firstRun disabled", cfg.FirstRun, err)
	}
	if _, err := loadYAML(t, "listen: \":8443\"\nfirstRun: sometimes\n"); err == nil || !strings.Contains(err.Error(), "firstRun") {
		t.Fatalf("Load(firstRun: sometimes) = %v, want a firstRun error", err)
	}
}

func TestLoad_OperatorCRL(t *testing.T) {
	cfg, err := loadYAML(t, fileSource+`operatorCRL:
  - url: http://pki.example.org/op.crl
  - path: /etc/fleet/op.crl
`)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(cfg.OperatorCRL) != 2 || cfg.OperatorCRL[0].URL != "http://pki.example.org/op.crl" || cfg.OperatorCRL[1].Path != "/etc/fleet/op.crl" {
		t.Fatalf("OperatorCRL = %+v", cfg.OperatorCRL)
	}

	for name, c := range map[string]struct{ body, want string }{
		"without operatorCAPath": {"listen: \":8443\"\noperatorCRL:\n  - url: http://pki.example.org/op.crl\n", "operatorCAPath"},
		"url and path":           {fileSource + "operatorCRL:\n  - url: http://pki.example.org/op.crl\n    path: /etc/fleet/op.crl\n", "operatorCRL[0]"},
		"neither":                {fileSource + "operatorCRL:\n  - {}\n", "operatorCRL[0]"},
		"ftp url":                {fileSource + "operatorCRL:\n  - url: ftp://pki.example.org/op.crl\n", "operatorCRL[0]"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, c.body); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Load() = %v, want an error naming %s", err, c.want)
			}
		})
	}
}

func TestLoad_OperatorRevocationPolicy(t *testing.T) {
	cfg, err := loadYAML(t, fileSource+"operatorRevocationPolicy: hard\n")
	if err != nil || cfg.OperatorRevocationPolicy != RevocationPolicyHard {
		t.Fatalf("Load() = %q, %v; want hard", cfg.OperatorRevocationPolicy, err)
	}
	if _, err := loadYAML(t, fileSource+"operatorRevocationPolicy: strict\n"); err == nil || !strings.Contains(err.Error(), "operatorRevocationPolicy") {
		t.Fatalf("Load(strict) = %v, want an operatorRevocationPolicy error", err)
	}
}

// The policy was called operatorCRLPolicy in an earlier design. v0.1.0 is
// unreleased, so the old name is simply an unknown key, like any typo.
func TestLoad_UnknownKeysAreRefused(t *testing.T) {
	for _, key := range []string{"operatorCRLPolicy: soft", "operatorCaPath: /etc/fleet/op.pem"} {
		if _, err := loadYAML(t, fileSource+key+"\n"); err == nil || !strings.Contains(err.Error(), strings.SplitN(key, ":", 2)[0]) {
			t.Fatalf("Load(%s) = %v, want an unknown-key error naming it", key, err)
		}
	}
}

func TestLoad_OperatorOCSP(t *testing.T) {
	cfg, err := loadYAML(t, fileSource+"operatorOCSP:\n  mode: url\n  url: http://ocsp.example.org/\n")
	if err != nil || cfg.OperatorOCSP.Mode != OCSPModeURL || cfg.OperatorOCSP.URL != "http://ocsp.example.org/" {
		t.Fatalf("Load() = %+v, %v", cfg.OperatorOCSP, err)
	}
	for _, mode := range []string{"off", "aia"} {
		if cfg, err := loadYAML(t, fileSource+"operatorOCSP:\n  mode: "+mode+"\n"); err != nil || cfg.OperatorOCSP.Mode != mode {
			t.Fatalf("Load(mode %s) = %+v, %v", mode, cfg.OperatorOCSP, err)
		}
	}
	for name, body := range map[string]string{
		"unknown mode":           fileSource + "operatorOCSP:\n  mode: stapled\n",
		"url mode without a URL": fileSource + "operatorOCSP:\n  mode: url\n",
		"url mode with ldap":     fileSource + "operatorOCSP:\n  mode: url\n  url: ldap://ocsp.example.org/\n",
		"a URL with aia":         fileSource + "operatorOCSP:\n  mode: aia\n  url: http://ocsp.example.org/\n",
		"without operatorCAPath": "listen: \":8443\"\noperatorOCSP:\n  mode: off\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, body); err == nil || !strings.Contains(err.Error(), "operatorOCSP") {
				t.Fatalf("Load() = %v, want an operatorOCSP error", err)
			}
		})
	}
}

// With nothing but a listener and Postgres the manager starts, ready for
// first run: TLS and the operator CA are optional.
func TestLoad_BareConfigWithPostgres(t *testing.T) {
	cfg, err := loadYAML(t, "listen: \":8443\"\ndatabase_url: postgres://manager@db/manager\n")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.OperatorCAPath != "" || cfg.TLSCert != "" || cfg.DatabaseURL == "" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

// A CryptOS node can't be the operator CA any more, so operator_ca_node is
// refused with the migration message rather than silently ignored, with or
// without operatorCAPath.
func TestLoad_OperatorCANodeIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"alone":               "listen: \":8443\"\noperator_ca_node: pki-operator\n",
		"with operatorCAPath": fileSource + "operator_ca_node: pki-operator\n",
		"empty value":         fileSource + "operator_ca_node: \"\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadYAML(t, body)
			if err == nil || !strings.Contains(err.Error(), OperatorCANodeMigration) {
				t.Fatalf("Load() = %v, want the migration message", err)
			}
		})
	}
	if !strings.Contains(OperatorCANodeMigration, "migrating from operator_ca_node") {
		t.Fatalf("the migration message doesn't point at the docs: %q", OperatorCANodeMigration)
	}
}

// MCP needs Postgres (the denylist, the operator CAs and the revocation
// epoch live there) and no longer needs operator_ca_node or operatorCAPath:
// the per-issuer revocation checks run on every call.
func TestLoad_MCPSources(t *testing.T) {
	const mcp = "mcp:\n  enabled: true\n  public_url: \"https://fleetos.example.org\"\n"
	for name, body := range map[string]string{
		"file source":       fileSource + "database_url: postgres://manager@db/manager\n" + mcp,
		"registered source": "listen: \":8443\"\ndatabase_url: postgres://manager@db/manager\n" + mcp,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, body); err != nil {
				t.Fatalf("Load() = %v", err)
			}
		})
	}
	if _, err := loadYAML(t, fileSource+mcp); err == nil || !strings.Contains(err.Error(), "database_url") {
		t.Fatalf("Load() without Postgres = %v, want a database_url error", err)
	}
}
