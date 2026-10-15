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
	"strings"
	"testing"
	"time"
)

// fakeEnv and fakeFile let the tests drive loadConfig without touching the
// real environment or filesystem.
func fakeEnv(vars map[string]string) func(string) string {
	return func(name string) string { return vars[name] }
}

const validNodesYAML = `
nodes:
  - name: pki-root
    endpoint: pki-root.example.org:4443
    role: root
    adminCertPath: /work/pki-root/admin.crt
    adminKeyPath: /work/pki-root/admin.key
  - name: pki-spare
    endpoint: pki-spare.example.org:4443
    role: issuing
    adminCertPath: /work/pki-spare/admin.crt
    adminKeyPath: /work/pki-spare/admin.key
    spare: true
`

func validEnv() map[string]string {
	return map[string]string{
		"E2E_MANAGER_BIN":  "/work/manager",
		"E2E_DATABASE_URL": "postgres://e2e:throwaway@127.0.0.1:5432/e2e",
		"E2E_ADMIN_EMAIL":  "admin@example.org",
		"E2E_NODES_FILE":   "/work/nodes.yaml",
		"E2E_WORKDIR":      "/work",
	}
}

func fakeReadFile(files map[string]string) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		s, ok := files[path]
		if !ok {
			return nil, fmt.Errorf("no such file: %s", path)
		}
		return []byte(s), nil
	}
}

func TestLoadConfigMissingRequiredVars(t *testing.T) {
	_, err := loadConfig(fakeEnv(nil), fakeReadFile(nil))
	if err == nil {
		t.Fatal("loadConfig: want an error with nothing set")
	}
	for _, name := range requiredEnv {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name missing var %s", err, name)
		}
	}
}

func TestLoadConfigValid(t *testing.T) {
	env := validEnv()
	files := map[string]string{"/work/nodes.yaml": validNodesYAML}
	cfg, err := loadConfig(fakeEnv(env), fakeReadFile(files))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ManagerBin != "/work/manager" {
		t.Errorf("ManagerBin = %q", cfg.ManagerBin)
	}
	if len(cfg.Nodes) != 2 {
		t.Fatalf("Nodes = %d, want 2", len(cfg.Nodes))
	}
	if cfg.StepTimeout != defaultStepTimeout {
		t.Errorf("StepTimeout = %v, want the default", cfg.StepTimeout)
	}
	spare, ok := cfg.spareNode()
	if !ok || spare.Name != "pki-spare" {
		t.Errorf("spareNode() = %+v, %v; want pki-spare, true", spare, ok)
	}
}

func TestLoadConfigStepTimeoutOverride(t *testing.T) {
	env := validEnv()
	env["E2E_STEP_TIMEOUT"] = "90s"
	files := map[string]string{"/work/nodes.yaml": validNodesYAML}
	cfg, err := loadConfig(fakeEnv(env), fakeReadFile(files))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.StepTimeout != 90*time.Second {
		t.Errorf("StepTimeout = %v, want 90s", cfg.StepTimeout)
	}
}

func TestLoadConfigRejectsTwoSpares(t *testing.T) {
	env := validEnv()
	files := map[string]string{"/work/nodes.yaml": `
nodes:
  - name: a
    endpoint: a.example.org:4443
    adminCertPath: /a.crt
    adminKeyPath: /a.key
    spare: true
  - name: b
    endpoint: b.example.org:4443
    adminCertPath: /b.crt
    adminKeyPath: /b.key
    spare: true
`}
	if _, err := loadConfig(fakeEnv(env), fakeReadFile(files)); err == nil {
		t.Fatal("loadConfig: want an error with two spare nodes")
	}
}

func TestLoadConfigRejectsIncompleteNode(t *testing.T) {
	env := validEnv()
	files := map[string]string{"/work/nodes.yaml": `
nodes:
  - name: a
    endpoint: a.example.org:4443
`}
	if _, err := loadConfig(fakeEnv(env), fakeReadFile(files)); err == nil {
		t.Fatal("loadConfig: want an error for a node missing admin credentials")
	}
}

func TestLoadConfigRejectsEmptyNodesFile(t *testing.T) {
	env := validEnv()
	files := map[string]string{"/work/nodes.yaml": "nodes: []\n"}
	if _, err := loadConfig(fakeEnv(env), fakeReadFile(files)); err == nil {
		t.Fatal("loadConfig: want an error with no nodes")
	}
}

func TestConfigSecretsToRedactNamesNothingByAccident(t *testing.T) {
	cfg := config{
		DatabaseURL: "postgres://e2e:throwaway@127.0.0.1:5432/e2e",
		Nodes: []nodeUnderTest{
			{Endpoint: "pki-root.example.org:4443", AdminCertPath: "/work/admin.crt", AdminKeyPath: "/work/admin.key", CACertPath: "/work/ca.pem"},
		},
	}
	secrets := cfg.secretsToRedact()
	want := []string{cfg.DatabaseURL, "pki-root.example.org:4443", "/work/admin.crt", "/work/admin.key", "/work/ca.pem"}
	if len(secrets) != len(want) {
		t.Fatalf("secretsToRedact() = %v, want %v", secrets, want)
	}
	for i, w := range want {
		if secrets[i] != w {
			t.Errorf("secretsToRedact()[%d] = %q, want %q", i, secrets[i], w)
		}
	}
}
