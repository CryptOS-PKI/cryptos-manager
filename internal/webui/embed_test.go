package webui

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
	"strings"
	"testing"
)

func TestHandler_ServesIndex(t *testing.T) {
	h, err := Handler(Options{})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "CryptOS Fleet Manager") {
		t.Fatalf("GET / = %d %q", rec.Code, rec.Body.String())
	}
}

func TestHandler_SPAFallback(t *testing.T) {
	h, _ := Handler(Options{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fleet", nil)) // no such file
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "CryptOS Fleet Manager") {
		t.Fatalf("GET /fleet (SPA) = %d, want index.html", rec.Code)
	}
}

func TestHandlerInjectsDevUIIssueMetaOnlyWhenEnabled(t *testing.T) {
	for _, tc := range []struct {
		on   bool
		want bool
	}{{false, false}, {true, true}} {
		h, err := Handler(Options{DevUIIssueCopy: tc.on})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fleet", nil))
		got := strings.Contains(rec.Body.String(), `<meta name="cryptos-dev-ui-issue-copy" content="true">`)
		if got != tc.want {
			t.Fatalf("on=%v: meta present=%v, want %v", tc.on, got, tc.want)
		}
	}
}
