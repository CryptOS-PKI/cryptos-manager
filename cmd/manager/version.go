package main

/*
Apache License 2.0

Copyright 2026 Shane

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
	"encoding/json"
	"log"
	"net/http"
)

// Build identity, stamped at link time with -X. Nothing derives these at
// runtime: the image build copies the repo without a usable .git, so
// runtime/debug.ReadBuildInfo cannot report a revision for the one build that
// matters -- the container (#81).
//
// The defaults are deliberately honest rather than plausible. A locally built
// binary reports "dev", not a version it does not have.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
	// webRef is the ref of the web bundle embedded by the image build. "Which
	// web" is half of any UI bug report, and the SPA is baked in, so the binary
	// is the only thing that can answer it.
	webRef = "unknown"
)

// buildInfo is what /version serves and what the startup log prints.
type buildInfo struct {
	BuildDate string `json:"buildDate"`
	Commit    string `json:"commit"`
	Version   string `json:"version"`
	WebRef    string `json:"webRef"`
}

func currentBuild() buildInfo {
	return buildInfo{BuildDate: buildDate, Commit: commit, Version: version, WebRef: webRef}
}

// versionPath is served anonymously, on purpose.
//
// The most valuable alpha reports come from operators who cannot log in: no
// certificate, a certificate the fleet rejects, or a half-started service. If
// build info needed an operator credential it would be missing in exactly the
// cases worth reporting. It carries no secrets -- four strings describing the
// binary -- so there is nothing here to protect.
const versionPath = "/version"

func versionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			return
		}
		if err := json.NewEncoder(w).Encode(currentBuild()); err != nil {
			// The status is already written; log rather than pretend.
			log.Printf("manager: WARNING serving %s: %v", versionPath, err)
		}
	})
}
