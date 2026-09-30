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
	"net/http"
	"net/http/httptest"
	"testing"
)

// The plaintext listener only redirects page loads. Anything that isn't a
// GET or HEAD gets 405, so a POST (an API call, a form) is never bounced to
// HTTPS with its body, and the listener reaches no other handler.
func TestHTTPSRedirectHandler_RefusesNonGET(t *testing.T) {
	h := httpsRedirectHandler("")
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "http://fleetos.example.org/cryptos.fleet.v1.FleetService/WhoAmI", nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Location") != "" {
			t.Errorf("%s = %d (Location %q), want 405 with no redirect", m, rec.Code, rec.Header().Get("Location"))
		}
		if rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s Allow = %q, want GET, HEAD", m, rec.Header().Get("Allow"))
		}
	}
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "http://fleetos.example.org/", nil))
		if rec.Code != http.StatusTemporaryRedirect {
			t.Errorf("%s = %d, want 307", m, rec.Code)
		}
	}
}
