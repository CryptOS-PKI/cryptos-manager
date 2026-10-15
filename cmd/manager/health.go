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

// storageModePostgres is the health body's storage.mode value for the
// Postgres store. There is no config.StorageModePostgres: Postgres is
// selected by database_url, not by a storage.mode value (config.go), but the
// health body still needs to say which store is live.
const storageModePostgres = "postgres"

type healthStatus struct {
	Status  string        `json:"status"`
	Storage storageStatus `json:"storage"`
}

// storageStatus is the health body's report on the durable store: which mode
// is live, whether it currently answers, and (when known) its version. The
// console banner (#194) reads this to warn when Mode is memory.
type storageStatus struct {
	Mode    string `json:"mode"`
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
}

// Storage states reported in storageStatus.State.
const (
	storageStateOK          = "ok"
	storageStateDegraded    = "degraded"
	storageStateUnavailable = "unavailable"
)

// storeHealth is what healthHandler needs to report on the durable store.
// Check and Version are nil for storage mode memory, which cannot be
// unreachable and has no server version to report.
type storeHealth struct {
	Mode    string
	Check   func(context.Context) error
	Version func(context.Context) (string, error)
}

// healthHandler reports whether the manager can serve: it is up, and its
// durable store answers. Storage mode memory is reported degraded rather than
// checked or failed: it cannot be unreachable, but it is not durable.
func healthHandler(sh storeHealth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

			return
		}

		code := http.StatusOK
		status := "ok"
		storage := storageStatus{Mode: sh.Mode, State: storageStateOK}

		switch {
		case sh.Mode == config.StorageModeMemory:
			storage.State = storageStateDegraded
			status = storageStateDegraded
		case sh.Check != nil:
			ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
			defer cancel()
			if err := sh.Check(ctx); err != nil {
				// The endpoint is anonymous and the driver error names the
				// database host, so the detail goes to the log only.
				log.Printf("manager: WARNING health check: store unreachable: %v", err)
				code, status, storage.State = http.StatusServiceUnavailable, "unavailable", storageStateUnavailable
			} else if sh.Version != nil {
				if v, err := sh.Version(ctx); err == nil {
					storage.Version = v
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		if r.Method == http.MethodHead {
			return
		}
		if err := json.NewEncoder(w).Encode(healthStatus{Status: status, Storage: storage}); err != nil {
			log.Printf("manager: WARNING serving %s: %v", healthPath, err)
		}
	})
}

// healthMount adds the health endpoint to the root mux.
func healthMount(sh storeHealth) func(*http.ServeMux) {
	return func(mux *http.ServeMux) {
		mux.Handle(healthPath, healthHandler(sh))
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
