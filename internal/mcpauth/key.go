// Package mcpauth mints, stores and verifies the MCP agent keys, and resolves
// each key to the live identity of the operator certificate it is bound to.
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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// KeyPrefix starts every MCP key, so the middleware can reject other bearers
// cheaply and secret scanners can recognise a leaked key.
const KeyPrefix = "fos_mcp_"

const keyBytes = 32

// strictB64 rejects non-canonical encodings, so exactly one string spells
// each key.
var strictB64 = base64.RawURLEncoding.Strict()

// NewKey returns a fresh key: KeyPrefix followed by base64url of 32 random
// bytes.
func NewKey() (string, error) {
	b := make([]byte, keyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return KeyPrefix + strictB64.EncodeToString(b), nil
}

// WellFormed reports whether s has the exact shape NewKey produces.
func WellFormed(s string) bool {
	body, ok := strings.CutPrefix(s, KeyPrefix)
	if !ok || len(body) != strictB64.EncodedLen(keyBytes) {
		return false
	}
	b, err := strictB64.DecodeString(body)
	return err == nil && len(b) == keyBytes
}

// HashKey returns the lowercase hex SHA-256 of key, the only form the store
// keeps. The key has 256 bits of entropy, so a plain hash is enough; a slow
// password hash would only add latency to every request.
func HashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}
