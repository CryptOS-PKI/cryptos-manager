// Command manager runs the CryptOS Fleet Manager Connect server: it dials
// the configured fleet nodes over mTLS and serves cryptos.fleet.v1.FleetService
// to the web UI.
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
	"bytes"
	connect "connectrpc.com/connect"
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
	"strings"
	"time"

	fleetv1connect "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/approval"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/config"
	"github.com/CryptOS-PKI/manager/internal/fleet"
	"github.com/CryptOS-PKI/manager/internal/mcpauth"
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
	healthcheck := flag.Bool("healthcheck", false, "probe the running manager's "+healthPath+" and exit 0 when healthy (the image's HEALTHCHECK)")
	checkNodeTrust := flag.Bool("check-node-trust", false, "list how each node's server certificate is verified and exit 1 if any node would be refused")
	pinNodeName := flag.String("pin-node", "", "pin the server certificate the named node presents, if it matches -expect-sha256, and exit")
	expectSHA256 := flag.String("expect-sha256", "", "with -pin-node: the Mgmt SHA-256 fingerprint shown on the node's console")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("manager: %v", err)
	}

	if *healthcheck {
		url, err := healthProbeURL(cfg)
		if err != nil {
			log.Fatalf("manager: healthcheck: %v", err)
		}
		if err := probeHealth(url); err != nil {
			log.Fatalf("manager: healthcheck: %v", err)
		}
		return
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
	var (
		st         store.Store
		trustStore store.OperatorTrust
		storeCheck func(context.Context) error
	)
	if os.Getenv(config.DatabaseURLEnv) != "" {
		log.Printf("manager: database_url taken from %s", config.DatabaseURLEnv)
	}
	if cfg.DatabaseURL == "" {
		// Dev-only in-memory store: seed the demo catalog so the offline mock UI
		// renders against fixtures. The demo catalog never touches a real store.
		profiles, adapters, audit, enrollments := seed.Catalog()
		mem := memory.NewWithCatalog(nodes, profiles, adapters, audit, enrollments)
		st, trustStore = mem, mem
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
		// or enrollments. Only configured nodes are seeded.
		if err := pg.SeedIfEmpty(ctx, nodes, nil, nil, nil, nil); err != nil {
			log.Fatalf("manager: seed postgres: %v", err)
		}
		st, trustStore = pg, pg
		storeCheck = pg.Ping
		log.Printf("manager: using postgres store")
	}

	insecure := insecureNodes(cfg)
	if *checkNodeTrust {
		if reportNodeTrust(os.Stdout, st.Nodes(), insecure) > 0 {
			os.Exit(1)
		}
		return
	}
	if *pinNodeName != "" {
		path, err := pinNode(st.Nodes(), *pinNodeName, *expectSHA256)
		if err != nil {
			log.Fatalf("manager: pin node: %v", err)
		}
		fmt.Printf("pinned node %s: %s\n", *pinNodeName, path)
		return
	}
	// Every node is verified on every connection; say at startup which ones
	// will be refused and which skip verification.
	var trustReport bytes.Buffer
	refused := reportNodeTrust(&trustReport, st.Nodes(), insecure)
	for _, line := range strings.Split(strings.TrimSpace(trustReport.String()), "\n") {
		if line != "" {
			log.Printf("manager: %s", line)
		}
	}
	if refused > 0 {
		log.Printf("manager: WARNING %d node(s) will be refused until they are pinned or have a recorded CA chain; see docs/node-trust.md", refused)
	}

	dial := func(n store.Node) (fleet.NodeConn, error) {
		c, err := nodeclient.Dial(n, insecure.options(n)...)
		if err != nil {
			return nil, err
		}

		return c, nil
	}

	svc := fleet.New(st, dial).
		WithServerCertCapture(nodeclient.FetchServerCert).
		WithUnverifiedNodes(insecure.skip)

	pemDial := func(endpoint, certPEM, keyPEM, caPEM string) (fleet.NodeConn, error) {
		return nodeclient.DialPEM(endpoint, certPEM, keyPEM, caPEM)
	}
	svc = svc.WithEnrollment(pemDial)

	// S10: supply the TOFU preview + pinned maintenance dial seams for node
	// adoption.
	mcpKeys := &mcpauth.Keys{Store: st}
	svc = svc.WithMCP(mcpKeys, cfg.MCP.Enabled)
	approvals := &approval.Service{Store: st}
	svc = svc.WithApprovals(approvals)
	svc = svc.WithAdoption(
		nodeclient.FetchMaintenanceCert,
		func(endpoint, pinnedSHA256, clientCertPEM, clientKeyPEM string) (fleet.NodeConn, error) {
			return nodeclient.DialMaintenance(endpoint, pinnedSHA256, clientCertPEM, clientKeyPEM)
		},
	)

	// Every error leaving the web-facing API carries a stable numeric code, so
	// the UI branches on a number rather than on message text and an operator
	// has something to quote in a report (#64).
	path, handler := fleetv1connect.NewFleetServiceHandler(svc,
		connect.WithInterceptors(apperr.Interceptor()),
	)

	web, err := webui.Handler()
	if err != nil {
		log.Fatalf("manager: webui: %v", err)
	}

	// Auth is HTTP middleware, not a Connect interceptor: only the HTTP layer
	// sees the TLS peer certificate. Bypass injects a dev identity over h2c;
	// the real path re-checks the client certificate on every request against
	// the operator CAs trusted now and their revocation data.
	authMW := authz.BypassMiddleware
	b := currentBuild()

	var (
		tlsCfg *tls.Config
		trust  *operatorTrust
	)
	if cfg.AuthBypass {
		log.Printf("manager: authBypass is set, so first run is disabled and no operator CA is used")
	} else {
		ctx := context.Background()
		base, err := buildTLSConfig(cfg)
		if err != nil {
			log.Fatalf("manager: tls: %v", err)
		}
		trust, err = setupOperatorTrust(ctx, cfg, st, trustStore, base, log.Printf)
		if err != nil {
			log.Fatalf("manager: operator CA: %v", err)
		}
		trust.refreshCRLs(ctx, log.Printf)
		trust.run(ctx, log.Printf)
		svc = svc.WithOperatorTrust(trust.trust, trust.rev)
		tlsCfg = serverTLSConfig(base, trust.trust)
		authMW = authz.ClientCertMiddlewareWith(trust.auth)
		mcpKeys.Admit = trust.auth.AdmitMCP
	}

	mounts := []func(*http.ServeMux){healthMount(storeCheck)}
	if cfg.MCP.Enabled {
		mount, err := mcpMount(cfg.MCP.PublicURL, svc, st, mcpKeys, approvals, trust.trust.Roots, trust.rev, authMW, b.Version)
		if err != nil {
			log.Fatalf("manager: %v", err)
		}
		mounts = append(mounts, mount)
		log.Printf("manager: MCP endpoint enabled at %s/mcp", cfg.MCP.PublicURL)
	}
	rootHandler := newRootHandler(path, handler, web, authMW, cfg.CORSOrigins, mounts...)

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

// buildTLSConfig builds the base server TLS config: the adopter-provided
// server cert/key, HTTP/2 over ALPN, and a client certificate that is
// requested and verified when the client presents one. The operator CA pool
// is filled per handshake from the trust store (serverTLSConfig).
//
// VerifyClientCertIfGiven rather than RequireAndVerifyClientCert (#68): the
// handshake must succeed without a client certificate so the web surface can
// serve a landing page and say what is missing. A certificate that *is*
// presented still has to verify against a trusted operator CA -- an untrusted
// one fails the handshake -- and authorization never lived in the TLS layer.
// newRootHandler gates the API on the certificate, so an unauthenticated
// client gets a 401 from the API instead of a dead connection.
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

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		// An empty pool, never nil: a nil pool would verify a presented
		// certificate against the system roots.
		ClientCAs:  x509.NewCertPool(),
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}, nil
}

// newRootHandler assembles the serving chain. mounts add optional route sets,
// such as the MCP endpoint and its login, which bring their own auth. The auth
// middleware wraps the API handler only, so the SPA is reachable without a client certificate while
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
	mounts ...func(*http.ServeMux),
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(apiPath, authMW(apiHandler))
	// Anonymous, like the web surface: an operator who cannot authenticate is
	// exactly who needs to report which build they are on (#81).
	mux.Handle(versionPath, versionHandler())
	mux.Handle("/", webHandler)
	for _, mount := range mounts {
		mount(mux)
	}

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
