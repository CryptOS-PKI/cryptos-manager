// Command manager runs the CryptOS Fleet Manager Connect server: it dials
// the configured fleet nodes over mTLS and serves cryptos.fleet.v1.FleetService
// to the web UI.
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
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	fleetv1connect "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/config"
	"github.com/CryptOS-PKI/manager/internal/fleet"
	"github.com/CryptOS-PKI/manager/internal/nodeclient"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"github.com/CryptOS-PKI/manager/internal/store/postgres"
	"github.com/CryptOS-PKI/manager/internal/store/seed"
	"github.com/CryptOS-PKI/manager/internal/webui"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the manager's YAML config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("manager: %v", err)
	}

	nodes := make([]store.Node, len(cfg.Nodes))
	for i, n := range cfg.Nodes {
		nodes[i] = store.Node{
			Name:      n.Name,
			Endpoint:  n.Endpoint,
			Role:      n.Role,
			AdminCert: n.AdminCertPath,
			AdminKey:  n.AdminKeyPath,
			CACert:    n.CACertPath,
		}
	}
	profiles, adapters, audit, enrollments := seed.Catalog()

	// When an operator-CA node is configured, seed the three operator-<level>
	// issuing profiles into the catalog so an admin can push them to that node
	// (via ApplyProfileToNode) and S9 issuance can route to them.
	if cfg.OperatorCANode != "" {
		opProfiles, err := fleet.OperatorProfiles()
		if err != nil {
			log.Fatalf("manager: build operator profiles: %v", err)
		}
		profiles = append(profiles, opProfiles...)
	}

	var st store.Store
	if cfg.DatabaseURL == "" {
		st = memory.NewWithCatalog(nodes, profiles, adapters, audit, enrollments)
		log.Printf("manager: no database_url configured, using in-memory store")
	} else {
		ctx := context.Background()
		pg, err := postgres.New(ctx, cfg.DatabaseURL)
		if err != nil {
			log.Fatalf("manager: connect postgres: %v", err)
		}
		defer pg.Close()
		if err := pg.SeedIfEmpty(ctx, nodes, profiles, adapters, audit, enrollments); err != nil {
			log.Fatalf("manager: seed postgres: %v", err)
		}
		st = pg
		log.Printf("manager: using postgres store")
	}

	dial := func(n store.Node) (fleet.NodeConn, error) {
		c, err := nodeclient.Dial(n)
		if err != nil {
			return nil, err
		}

		return c, nil
	}

	svc := fleet.New(st, dial)

	pemDial := func(endpoint, certPEM, keyPEM, caPEM string) (fleet.NodeConn, error) {
		return nodeclient.DialPEM(endpoint, certPEM, keyPEM, caPEM)
	}
	var operatorCAPEM string
	if cfg.OperatorCAPath != "" {
		b, err := os.ReadFile(cfg.OperatorCAPath)
		if err != nil {
			log.Fatalf("manager: read operator CA: %v", err)
		}
		operatorCAPEM = string(b)
	}
	svc = svc.WithEnrollment(pemDial, operatorCAPEM)

	// S9: route operator-credential issuance/revocation to the configured
	// operator-CA node. S10: supply the TOFU preview + pinned maintenance dial
	// seams for node adoption.
	svc = svc.WithOperatorCA(cfg.OperatorCANode)
	svc = svc.WithAdoption(
		nodeclient.FetchMaintenanceCert,
		func(endpoint, pinnedSHA256, clientCertPEM, clientKeyPEM string) (fleet.NodeConn, error) {
			return nodeclient.DialMaintenance(endpoint, pinnedSHA256, clientCertPEM, clientKeyPEM)
		},
	)

	path, handler := fleetv1connect.NewFleetServiceHandler(svc)

	mux := http.NewServeMux()
	mux.Handle(path, handler)

	web, err := webui.Handler()
	if err != nil {
		log.Fatalf("manager: webui: %v", err)
	}
	mux.Handle("/", web)

	// S9 revocation enforcement: when an operator-CA node is configured, the
	// manager periodically fetches its revoked serials and the mTLS middleware
	// denies a client whose cert serial is revoked. The cache is fail-safe: a
	// failed refresh keeps the last-good set (a transient operator-CA outage
	// never locks everyone out). Enforcement runs only on the real mTLS path,
	// not the h2c dev bypass.
	var revocationCache *authz.RevocationCache
	if !cfg.AuthBypass {
		if src := svc.OperatorRevocationSource(); src != nil {
			revocationCache = authz.NewRevocationCache(src)
			// Prime the cache synchronously before serving so revocation is
			// enforced on the very first request. Without this the initial
			// refresh races the listener and a revoked cert could slip through
			// a cold-start window. A prime failure is non-fatal (fail-safe on a
			// transient operator-CA outage) but loudly warns that enforcement is
			// not yet active until the periodic refresh succeeds.
			if err := revocationCache.Prime(); err != nil {
				log.Printf("manager: WARNING operator-CA revocation NOT YET ENFORCED — priming from node %q failed: %v; revoked operator certs may be accepted until the first successful refresh", cfg.OperatorCANode, err)
			}
			go revocationCache.Run(context.Background(), 60*time.Second)
			log.Printf("manager: enforcing operator-CA revocation via node %q", cfg.OperatorCANode)
		} else {
			log.Printf("manager: no operator_ca_node configured, operator-cert revocation not enforced")
		}
	}

	// Auth is HTTP middleware, not a Connect interceptor: only the HTTP layer
	// sees the TLS peer certificate. Bypass injects a dev identity over h2c;
	// the real path verifies the client cert the TLS listener required and
	// (when configured) denies a revoked serial.
	authMW := authz.ClientCertMiddleware
	if revocationCache != nil {
		authMW = func(next http.Handler) http.Handler {
			return authz.ClientCertMiddlewareWithRevocation(revocationCache, next)
		}
	}
	if cfg.AuthBypass {
		authMW = authz.BypassMiddleware
	}
	// withRecover is the outermost layer so a panic on any path -- including the
	// Postgres store panicking on a query error -- is logged and answered with a
	// 500 instead of a bare aborted stream. The real fix is an error-returning
	// store.Store interface; see #40.
	rootHandler := withRecover(withCORS(cfg.CORSOrigins, authMW(mux)))

	log.Printf("manager: %d node(s) configured, catalog seeded (%d profiles, %d adapters, %d audit events, %d enrollments)",
		len(nodes), len(profiles), len(adapters), len(audit), len(enrollments))

	server := &http.Server{Addr: cfg.Listen}

	if cfg.AuthBypass {
		server.Handler = h2c.NewHandler(rootHandler, &http2.Server{})
		log.Printf("manager: listening on %s (authBypass=true, h2c)", cfg.Listen)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("manager: serve: %v", err)
		}
		return
	}

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		log.Fatalf("manager: tls: %v", err)
	}
	server.Handler = rootHandler // TLS negotiates HTTP/2 via ALPN; no h2c
	server.TLSConfig = tlsCfg
	log.Printf("manager: listening on %s (mTLS client-cert auth)", cfg.Listen)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("manager: serve: %v", err)
	}
}

// buildTLSConfig builds the server TLS config: the adopter-provided server
// cert/key plus RequireAndVerifyClientCert against the operator CA.
func buildTLSConfig(cfg config.Config) (*tls.Config, error) {
	serverCert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.OperatorCAPath)
	if err != nil {
		return nil, fmt.Errorf("read operator CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("operator CA %s contains no PEM certificates", cfg.OperatorCAPath)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// withRecover wraps next so a panic in any downstream handler is caught,
// logged with its value and stack, and turned into a 500 response. It sits at
// the top of the chain so every path is covered: the Postgres store's methods
// satisfy an error-free store.Store interface and so panic on query errors,
// which would otherwise surface to the client as a bare aborted stream. The
// proper fix is an error-returning store.Store interface; see #40.
func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				log.Printf("manager: recovered panic serving %s %s: %v\n%s", r.Method, r.URL.Path, v, debug.Stack())
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withCORS wraps next with a CORS handler that allows the given origins to
// call the Connect/gRPC-Web protocols: it permits POST/GET/OPTIONS, the
// headers Connect and gRPC-Web clients send, and exposes the gRPC status
// trailers so browser clients can read them.
func withCORS(origins []string, next http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		allowed[o] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if _, ok := allowed[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Expose-Headers", "Grpc-Status, Grpc-Message")
		}

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers",
				"Content-Type, Connect-Protocol-Version, Connect-Timeout-Ms, Grpc-Timeout, X-Grpc-Web, X-User-Agent")
			w.WriteHeader(http.StatusNoContent)

			return
		}

		next.ServeHTTP(w, r)
	})
}
