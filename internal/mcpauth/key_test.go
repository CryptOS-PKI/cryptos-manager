package mcpauth

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
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewKey_ShapeAndUniqueness(t *testing.T) {
	a, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	b, _ := NewKey()
	if a == b {
		t.Fatal("two keys are equal")
	}
	if !strings.HasPrefix(a, "fos_mcp_") {
		t.Fatalf("key %q lacks the fos_mcp_ prefix", a)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(a, "fos_mcp_"))
	if err != nil || len(raw) != 32 {
		t.Fatalf("key body decodes to %d bytes, err %v; want 32", len(raw), err)
	}
	if !WellFormed(a) {
		t.Fatal("a freshly minted key is not well formed")
	}
}

func TestWellFormed_RejectsOtherShapes(t *testing.T) {
	good, _ := NewKey()
	for _, s := range []string{
		"",
		"fos_mcp_",
		strings.TrimPrefix(good, "fos_mcp_"),
		"fos_mcp_" + strings.Repeat("A", 42),
		good + "A",
		"fos_mcp_" + strings.Repeat("+", 43),
		"snk_u_" + strings.TrimPrefix(good, "fos_mcp_"),
	} {
		if WellFormed(s) {
			t.Errorf("WellFormed(%q) = true", s)
		}
	}
}

func TestHashKey_StableHexAndVerifies(t *testing.T) {
	k, _ := NewKey()
	h := HashKey(k)
	if len(h) != 64 || strings.ToLower(h) != h {
		t.Fatalf("hash %q is not lowercase hex SHA-256", h)
	}
	if HashKey(k) != h {
		t.Fatal("hash is not stable")
	}
	if strings.Contains(h, strings.TrimPrefix(k, "fos_mcp_")) {
		t.Fatal("hash contains the key")
	}
	other, _ := NewKey()
	if HashKey(other) == h {
		t.Fatal("different keys hash equal")
	}
}
