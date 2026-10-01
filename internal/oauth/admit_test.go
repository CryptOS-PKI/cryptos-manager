package oauth

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
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
)

// A certificate the MCP admission check refuses, for example one whose
// operator CA has no CRL, gets invalid_grant and no key.
func TestToken_RefusesACertificateThatCantHoldAKey(t *testing.T) {
	f := newFixture(t)
	f.srv.Keys.Admit = func([]byte) error { return errors.New("no CRL source") }
	redirect := "http://127.0.0.1:33418/callback"
	clientID, verifier, reqID := f.pendingRequest(redirect)
	back := f.approve(reqID, f.operatorCert(0x0abc, authz.LevelAdmin), "")

	rec, out := f.token(url.Values{"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")},
		"redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {verifier}})
	if rec.Code != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("token = %d %v, want 400 invalid_grant", rec.Code, out)
	}
	if len(f.st.McpKeys()) != 0 {
		t.Fatal("a key was stored")
	}
}
