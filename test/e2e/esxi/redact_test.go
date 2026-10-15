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
	"bytes"
	"strings"
	"testing"
)

func TestRedactorLineReplacesSecretsAndIPv4(t *testing.T) {
	r := newRedactor("pki-root.example.org", "/etc/cryptos/fleet/pki-root/admin.key")
	got := r.line("dialing pki-root.example.org (203.0.113.9) with /etc/cryptos/fleet/pki-root/admin.key")
	want := "dialing [redacted] ([ipv4]) with [redacted]"
	if got != want {
		t.Errorf("line() = %q, want %q", got, want)
	}
}

func TestRedactorLongestSecretFirst(t *testing.T) {
	// "pki-root" is a substring of "pki-root.example.org"; the longer value
	// must be replaced whole, not fragmented by the shorter one first.
	r := newRedactor("pki-root", "pki-root.example.org")
	got := r.line("host pki-root.example.org answered")
	if strings.Contains(got, "pki-root") {
		t.Errorf("line() = %q, still contains the short secret", got)
	}
	if got != "host [redacted] answered" {
		t.Errorf("line() = %q, want a single replacement", got)
	}
}

func TestRedactorIgnoresEmptySecrets(t *testing.T) {
	r := newRedactor("", "real-secret", "")
	if len(r.secrets) != 1 {
		t.Fatalf("secrets = %v, want exactly one non-empty entry", r.secrets)
	}
}

func TestRedactingWriterBuffersUntilNewline(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor("acme-corp")
	w := r.writer(&out)

	if _, err := w.Write([]byte("connecting to acme-")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("output before newline = %q, want nothing written yet", out.String())
	}
	if _, err := w.Write([]byte("corp now\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := out.String(), "connecting to [redacted] now\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRedactingWriterCloseFlushesPartialLine(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor("acme-corp")
	w := r.writer(&out)
	if _, err := w.Write([]byte("no trailing newline acme-corp")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got, want := out.String(), "no trailing newline [redacted]"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}
