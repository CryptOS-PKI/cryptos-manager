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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/config"
)

// healthPath is served by the manager itself, anonymously. The web handler
// answers every unknown path with the SPA and a 200, so probing any other path
// only proves that something is listening.
const healthPath = "/healthz"

// healthTimeout bounds both the store check and the probe. A container health
// check that hangs is reported as a failure anyway, and a slow answer here is
// a symptom worth surfacing.
const healthTimeout = 3 * time.Second

type healthStatus struct {
	Status string `json:"status"`
}

// healthHandler reports whether the manager can serve: it is up, and its
// durable store (when it has one) answers. storeCheck is nil for the in-memory
// store, which cannot be unreachable.
func healthHandler(storeCheck func(context.Context) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		code, body := http.StatusOK, healthStatus{Status: "ok"}
		if storeCheck != nil {
			ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
			defer cancel()
			if err := storeCheck(ctx); err != nil {
				// The endpoint is anonymous and the driver error names the
				// database host, so the detail goes to the log only.
				log.Printf("manager: WARNING health check: store unreachable: %v", err)
				code, body = http.StatusServiceUnavailable, healthStatus{Status: "unavailable"}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		if r.Method == http.MethodHead {
			return
		}
		if err := json.NewEncoder(w).Encode(body); err != nil {
			log.Printf("manager: WARNING serving %s: %v", healthPath, err)
		}
	})
}

// healthMount adds the health endpoint to the root mux.
func healthMount(storeCheck func(context.Context) error) func(*http.ServeMux) {
	return func(mux *http.ServeMux) {
		mux.Handle(healthPath, healthHandler(storeCheck))
	}
}

// healthProbeURL is where the manager's own listener answers from inside its
// container. An unspecified listen host is probed on loopback.
func healthProbeURL(cfg config.Config) (string, error) {
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return "", fmt.Errorf("listen address %q: %w", cfg.Listen, err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	scheme := "https"
	if cfg.AuthBypass {
		scheme = "http"
	}

	return scheme + "://" + net.JoinHostPort(host, port) + healthPath, nil
}

// probeHealth is the client side of the container health check. The image is
// distroless, with no shell or curl, so the binary probes itself.
func probeHealth(url string) error {
	client := &http.Client{
		Timeout: healthTimeout,
		Transport: &http.Transport{
			// The probe dials its own process over loopback, and the server
			// certificate names the public hostname, not 127.0.0.1. There is
			// nothing to authenticate and nothing sent.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // loopback self-probe, see above
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("health probe %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe %s: status %d", url, resp.StatusCode)
	}

	return nil
}
