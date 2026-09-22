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
	"net"
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
	// Operator-CA issuing profiles (operator-viewer/operator/admin) are
	// functional config, not demo data: seed them when an operator CA node is
	// configured so S9 issuance can route to them.
	var operatorProfiles []store.Profile
	if cfg.OperatorCANode != "" {
		var err error
		operatorProfiles, err = fleet.OperatorProfiles()
		if err != nil {
			log.Fatalf("manager: build operator profiles: %v", err)
		}
	}

	var st store.Store
	if cfg.DatabaseURL == "" {
		// Dev-only in-memory store: seed the demo catalog so the offline mock UI
		// renders against fixtures. The demo catalog never touches a real store.
		profiles, adapters, audit, enrollments := seed.Catalog()
		profiles = append(profiles, operatorProfiles...)
		st = memory.NewWithCatalog(nodes, profiles, adapters, audit, enrollments)
		log.Printf("manager: no database_url configured, using in-memory store (demo catalog seeded)")
	} else {
		ctx := context.Background()
		// Wait for Postgres rather than exiting if it is not up yet: a
		// restarted container frequently comes back before its database does
		// (see dbConnectWindow).
		pg, err := openWithRetry(
			func() (*postgres.Store, error) { return postgres.New(ctx, cfg.DatabaseURL) },
			dbConnectWindow,
			time.Sleep,
			log.Printf,
		)
		if err != nil {
			log.Fatalf("manager: connect postgres: %v", err)
		}
		defer pg.Close()
		// A live store starts clean: no demo nodes, profiles, adapters, audit,
		// or enrollments. Only configured nodes and the functional operator-CA
		// profiles are seeded.
		if err := pg.SeedIfEmpty(ctx, nodes, operatorProfiles, nil, nil, nil); err != nil {
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

	web, err := webui.Handler()
	if err != nil {
		log.Fatalf("manager: webui: %v", err)
	}

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
	rootHandler := newRootHandler(path, handler, web, authMW, cfg.CORSOrigins)

	b := currentBuild()
	log.Printf("manager: build %s (commit %s, built %s, web %s)", b.Version, b.Commit, b.BuildDate, b.WebRef)
	log.Printf("manager: %d node(s) configured", len(nodes))

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

	// Port 80 exists only to send browsers to HTTPS. An operator types a
	// hostname, not a scheme, and without this they get a connection refused
	// instead of the login page (#70).
	if cfg.HTTPRedirectListen != "" {
		go serveHTTPRedirect(cfg.HTTPRedirectListen, cfg.HTTPSPublicPort)
	}
	server.Handler = rootHandler // TLS negotiates HTTP/2 via ALPN; no h2c
	server.TLSConfig = tlsCfg
	// Say what is actually enforced. Since #68 the handshake no longer requires
	// a client certificate -- the API does -- and a log line claiming otherwise
	// is the kind of thing an operator reads as confirmation that the web
	// surface is locked down when it is deliberately not.
	log.Printf("manager: listening on %s (client-cert auth on the API, web surface anonymous)", cfg.Listen)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("manager: serve: %v", err)
	}
}

// buildTLSConfig builds the server TLS config: the adopter-provided server
// cert/key, and a client certificate that is requested and verified against the
// operator CA when the client presents one.
//
// VerifyClientCertIfGiven rather than RequireAndVerifyClientCert (#68): the
// handshake must succeed without a client certificate so the web surface can
// serve a landing page and say what is missing. A certificate that *is*
// presented still has to verify against the operator CA -- an untrusted one
// fails the handshake exactly as before -- and authorization is unchanged,
// because it never lived in the TLS layer. What moved is where the absence of a
// certificate is answered: newRootHandler gates the API on it, so an
// unauthenticated client gets a 401 from the API instead of a dead connection
// from the whole service.
func buildTLSConfig(cfg config.Config) (*tls.Config, error) {
	// No configured material is a deliberate day-zero choice (#78): generate a
	// throwaway certificate so the site comes up and the operator can be told
	// what to install. A configured path that fails to load is a mistake, and
	// still fatal -- it must not be papered over with a self-signed
	// certificate that looks like it worked.
	var (
		serverCert tls.Certificate
		err        error
	)
	if cfg.TLSCert == "" && cfg.TLSKey == "" {
		serverCert, err = generateServerCert(bootstrapCertHosts(cfg.Listen))
		if err != nil {
			return nil, fmt.Errorf("generate bootstrap server cert: %w", err)
		}
		log.Printf("manager: WARNING no tlsCert/tlsKey configured, serving a SELF-SIGNED " +
			"bootstrap certificate; browsers will warn until real material is installed")
	} else {
		serverCert, err = tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load server cert: %w", err)
		}
	}

	// Without an operator CA nobody can authenticate yet, which is the correct
	// day-zero posture rather than a reason to refuse to start: the listener
	// comes up, the API answers 401 to everyone, and first run opens only its
	// own endpoint. A nil ClientCAs pool means a presented certificate is
	// verified against nothing we trust and is refused.
	var pool *x509.CertPool
	if cfg.OperatorCAPath != "" {
		caPEM, readErr := os.ReadFile(cfg.OperatorCAPath)
		if readErr != nil {
			return nil, fmt.Errorf("read operator CA: %w", readErr)
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("operator CA %s contains no PEM certificates", cfg.OperatorCAPath)
		}
	} else {
		log.Printf("manager: WARNING no operatorCAPath configured, so no operator " +
			"certificate can be accepted; the API will refuse every caller until the fleet is bootstrapped")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// newRootHandler assembles the serving chain. The auth middleware wraps the API
// handler only, so the SPA is reachable without a client certificate while
// every API call still needs one (#68). Wrapping the whole mux -- which is what
// this used to do -- would have meant softening the TLS mode also exposed the
// API to anonymous callers.
//
// withRecover is the outermost layer so a panic on any path -- including the
// Postgres store panicking on a query error -- is logged and answered with a
// 500 instead of a bare aborted stream. The real fix is an error-returning
// store.Store interface; see #40.
func newRootHandler(
	apiPath string,
	apiHandler, webHandler http.Handler,
	authMW func(http.Handler) http.Handler,
	corsOrigins []string,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(apiPath, authMW(apiHandler))
	// Anonymous, like the web surface: an operator who cannot authenticate is
	// exactly who needs to report which build they are on (#81).
	mux.Handle(versionPath, versionHandler())
	mux.Handle("/", webHandler)

	return withRecover(withCORS(corsOrigins, mux))
}

// serveHTTPRedirect runs the plaintext listener whose only job is to redirect to
// HTTPS. A failure here is logged and not fatal: the HTTPS listener is the
// service, and losing the convenience redirect should not take it down.
func serveHTTPRedirect(listen, publicHTTPSPort string) {
	log.Printf("manager: redirecting HTTP on %s to HTTPS", listen)

	srv := &http.Server{
		Addr:              listen,
		Handler:           httpsRedirectHandler(publicHTTPSPort),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("manager: WARNING HTTP redirect listener on %s stopped: %v", listen, err)
	}
}

// httpsRedirectHandler redirects every request to the HTTPS scheme on the same
// host, preserving path and query.
//
// publicHTTPSPort is the port clients reach, which is deliberately not the port
// the manager listens on: the container serves 8443 internally and is published
// on 443, so redirecting to the listener's own port would send the browser
// somewhere it cannot reach. Empty (or 443) leaves the port implicit.
//
// The redirect is temporary, not permanent. A browser caches a 301 or 308 for an
// origin more or less indefinitely, which is painful to undo if the deployment
// ever needs to serve anything else on port 80.
func httpsRedirectHandler(publicHTTPSPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if host == "" {
			// Nothing to redirect to, and guessing would send the client
			// somewhere arbitrary.
			http.Error(w, "missing Host header", http.StatusBadRequest)

			return
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if publicHTTPSPort != "" && publicHTTPSPort != "443" {
			host = net.JoinHostPort(host, publicHTTPSPort)
		}

		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	})
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
