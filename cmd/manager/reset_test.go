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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/manager/internal/config"
)

func TestParseFlags_ResetFirstRun(t *testing.T) {
	f, err := parseFlags([]string{"-config", "/etc/fm.yaml", "-reset-first-run"}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if !f.resetFirstRun || f.configPath != "/etc/fm.yaml" {
		t.Errorf("flags = %+v, want the reset with the given config", f)
	}
}

// The FM can't revoke at an external CA, so the reset has no flag for it.
func TestParseFlags_RevokeIssuedIsUnknown(t *testing.T) {
	for _, arg := range []string{"--revoke-issued", "-revoke-issued"} {
		var out strings.Builder
		_, err := parseFlags([]string{"-reset-first-run", arg}, &out)
		if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Errorf("parseFlags(%s) = %v, want an unknown flag error", arg, err)
		}
	}
}

func TestManagerAnswers_HealthzServing(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	cfg := config.Config{Listen: srv.Listener.Addr().String()}

	// A manager whose database is down still answers, and is still running.
	if !managerAnswers(context.Background(), cfg) {
		t.Error("managerAnswers() = false for a listening manager")
	}
}

func TestManagerAnswers_NothingListening(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	if managerAnswers(context.Background(), config.Config{Listen: addr}) {
		t.Error("managerAnswers() = true with nothing listening")
	}
}
