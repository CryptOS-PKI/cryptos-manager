package singlereplica

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
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeLeaseAPI is a minimal in-memory stand-in for the coordination.k8s.io/v1
// Lease endpoints the manager calls, enough to drive claimLease without a
// real cluster.
type fakeLeaseAPI struct {
	mu   sync.Mutex
	rv   int
	byNS map[string]map[string]leaseObject
}

func newFakeLeaseAPI() *fakeLeaseAPI {
	return &fakeLeaseAPI{byNS: map[string]map[string]leaseObject{}}
}

func (f *fakeLeaseAPI) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(f.handle))
}

func (f *fakeLeaseAPI) handle(w http.ResponseWriter, r *http.Request) {
	const prefix = "/apis/coordination.k8s.io/v1/namespaces/"
	path := r.URL.Path
	if len(path) <= len(prefix) {
		http.NotFound(w, r)
		return
	}
	rest := path[len(prefix):]
	// rest is "<ns>/leases" or "<ns>/leases/<name>"
	var ns, name string
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			ns = rest[:i]
			rest = rest[i+1:]
			break
		}
	}
	if rest == "leases" {
		name = ""
	} else {
		const leasesSeg = "leases/"
		if len(rest) > len(leasesSeg) {
			name = rest[len(leasesSeg):]
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		obj, ok := f.byNS[ns][name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, obj)
	case http.MethodPost:
		var obj leaseObject
		_ = json.NewDecoder(r.Body).Decode(&obj)
		if f.byNS[ns] == nil {
			f.byNS[ns] = map[string]leaseObject{}
		}
		if _, exists := f.byNS[ns][obj.Metadata.Name]; exists {
			w.WriteHeader(http.StatusConflict)
			return
		}
		f.rv++
		obj.Metadata.ResourceVersion = strconv.Itoa(f.rv)
		f.byNS[ns][obj.Metadata.Name] = obj
		writeJSON(w, http.StatusCreated, obj)
	case http.MethodPut:
		var obj leaseObject
		_ = json.NewDecoder(r.Body).Decode(&obj)
		current, ok := f.byNS[ns][name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if obj.Metadata.ResourceVersion != current.Metadata.ResourceVersion {
			w.WriteHeader(http.StatusConflict)
			return
		}
		f.rv++
		obj.Metadata.ResourceVersion = strconv.Itoa(f.rv)
		f.byNS[ns][name] = obj
		writeJSON(w, http.StatusOK, obj)
	case http.MethodDelete:
		if _, ok := f.byNS[ns][name]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.byNS[ns], name)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// put seeds a lease directly, bypassing the HTTP layer, for tests that need
// to start from an existing lease in a specific state.
func (f *fakeLeaseAPI) put(ns string, obj leaseObject) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rv++
	obj.Metadata.ResourceVersion = strconv.Itoa(f.rv)
	if f.byNS[ns] == nil {
		f.byNS[ns] = map[string]leaseObject{}
	}
	f.byNS[ns][obj.Metadata.Name] = obj
}

func TestClaimLease_CreatesWhenAbsent(t *testing.T) {
	api := newFakeLeaseAPI()
	srv := api.server()
	defer srv.Close()
	client := &leaseClient{http: srv.Client(), baseURL: srv.URL, namespace: "fleet"}

	g, err := claimLease(context.Background(), client, Options{Name: "fleet-manager", Holder: "pod-a"})
	if err != nil {
		t.Fatalf("claimLease: %v", err)
	}
	defer func() { _ = g.Release(context.Background()) }()

	lg, ok := g.(*leaseGuard)
	if !ok {
		t.Fatalf("got %T, want *leaseGuard", g)
	}
	if lg.resourceVersion == "" {
		t.Error("resourceVersion is empty after create")
	}
}

func TestClaimLease_RefusesALiveOtherHolder(t *testing.T) {
	api := newFakeLeaseAPI()
	srv := api.server()
	defer srv.Close()
	client := &leaseClient{http: srv.Client(), baseURL: srv.URL, namespace: "fleet"}

	now := time.Now()
	api.put("fleet", leaseObject{
		Metadata: leaseMetadata{Name: "fleet-manager", Namespace: "fleet"},
		Spec: leaseSpec{
			HolderIdentity:       "pod-a",
			LeaseDurationSeconds: 30,
			AcquireTime:          now.UTC().Format(microTimeFormat),
			RenewTime:            now.UTC().Format(microTimeFormat),
		},
	})

	_, err := claimLease(context.Background(), client, Options{Name: "fleet-manager", Holder: "pod-b"})
	if !errors.Is(err, ErrHeld) {
		t.Fatalf("claimLease error = %v, want ErrHeld", err)
	}
}

func TestClaimLease_TakesOverAStaleHolder(t *testing.T) {
	api := newFakeLeaseAPI()
	srv := api.server()
	defer srv.Close()
	client := &leaseClient{http: srv.Client(), baseURL: srv.URL, namespace: "fleet"}

	stale := time.Now().Add(-time.Hour)
	api.put("fleet", leaseObject{
		Metadata: leaseMetadata{Name: "fleet-manager", Namespace: "fleet"},
		Spec: leaseSpec{
			HolderIdentity:       "pod-a",
			LeaseDurationSeconds: 30,
			AcquireTime:          stale.UTC().Format(microTimeFormat),
			RenewTime:            stale.UTC().Format(microTimeFormat),
		},
	})

	g, err := claimLease(context.Background(), client, Options{Name: "fleet-manager", Holder: "pod-b"})
	if err != nil {
		t.Fatalf("claimLease over a stale holder: %v", err)
	}
	_ = g.Release(context.Background())
}

func TestClaimLease_SameHolderReclaimsItsOwnLease(t *testing.T) {
	api := newFakeLeaseAPI()
	srv := api.server()
	defer srv.Close()
	client := &leaseClient{http: srv.Client(), baseURL: srv.URL, namespace: "fleet"}

	now := time.Now()
	api.put("fleet", leaseObject{
		Metadata: leaseMetadata{Name: "fleet-manager", Namespace: "fleet"},
		Spec: leaseSpec{
			HolderIdentity:       "pod-a",
			LeaseDurationSeconds: 30,
			AcquireTime:          now.UTC().Format(microTimeFormat),
			RenewTime:            now.UTC().Format(microTimeFormat),
		},
	})

	// A process restarting with the same holder identity (same pod name,
	// after a crash) reclaims its own lease instead of being refused.
	g, err := claimLease(context.Background(), client, Options{Name: "fleet-manager", Holder: "pod-a"})
	if err != nil {
		t.Fatalf("claimLease as the same holder: %v", err)
	}
	_ = g.Release(context.Background())
}

func TestLeaseGuard_RenewsOnASchedule(t *testing.T) {
	api := newFakeLeaseAPI()
	srv := api.server()
	defer srv.Close()
	client := &leaseClient{http: srv.Client(), baseURL: srv.URL, namespace: "fleet"}

	g, err := claimLease(context.Background(), client, Options{Name: "fleet-manager", Holder: "pod-a"})
	if err != nil {
		t.Fatalf("claimLease: %v", err)
	}
	lg := g.(*leaseGuard)

	if err := lg.renewOnce(context.Background()); err != nil {
		t.Fatalf("renewOnce: %v", err)
	}

	api.mu.Lock()
	obj := api.byNS["fleet"]["fleet-manager"]
	api.mu.Unlock()
	if obj.Spec.HolderIdentity != "pod-a" {
		t.Errorf("holder after renew = %q, want pod-a", obj.Spec.HolderIdentity)
	}

	_ = g.Release(context.Background())
}

func TestLeaseGuard_Release_DeletesTheLease(t *testing.T) {
	api := newFakeLeaseAPI()
	srv := api.server()
	defer srv.Close()
	client := &leaseClient{http: srv.Client(), baseURL: srv.URL, namespace: "fleet"}

	g, err := claimLease(context.Background(), client, Options{Name: "fleet-manager", Holder: "pod-a"})
	if err != nil {
		t.Fatalf("claimLease: %v", err)
	}
	if err := g.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}

	api.mu.Lock()
	_, exists := api.byNS["fleet"]["fleet-manager"]
	api.mu.Unlock()
	if exists {
		t.Error("lease still exists after Release")
	}
}

func TestLeaseSpec_Expired(t *testing.T) {
	now := time.Now()
	fresh := leaseSpec{RenewTime: now.UTC().Format(microTimeFormat), LeaseDurationSeconds: 30}
	if fresh.expired(now.Add(5 * time.Second)) {
		t.Error("a lease renewed 5s ago with a 30s duration reports expired")
	}
	if !fresh.expired(now.Add(31 * time.Second)) {
		t.Error("a lease renewed 31s ago with a 30s duration reports not expired")
	}
	if !(leaseSpec{}).expired(now) {
		t.Error("a lease with no renewTime should report expired")
	}
}

func TestAcquireLease_RequiresServiceAccountFiles(t *testing.T) {
	old := serviceAccountDir
	serviceAccountDir = t.TempDir()
	defer func() { serviceAccountDir = old }()

	if _, err := acquireLease(context.Background(), Options{Name: "fleet-manager", Holder: "pod-a"}); err == nil {
		t.Fatal("want an error with no service account files present")
	}
}

// writeServiceAccountFiles lays down the token, namespace and CA certificate
// files Kubernetes projects into every pod, pointing the CA at srv's own
// certificate so inClusterLeaseClient's TLS client trusts it.
func writeServiceAccountFiles(t *testing.T, dir string, srv *httptest.Server) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "namespace"), []byte("fleet"), 0o600); err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAcquire_InClusterUsesLease(t *testing.T) {
	api := newFakeLeaseAPI()
	srv := httptest.NewTLSServer(http.HandlerFunc(api.handle))
	defer srv.Close()

	dir := t.TempDir()
	writeServiceAccountFiles(t, dir, srv)

	old := serviceAccountDir
	serviceAccountDir = dir
	defer func() { serviceAccountDir = old }()

	addr := srv.Listener.Addr().(*net.TCPAddr)
	t.Setenv("KUBERNETES_SERVICE_HOST", addr.IP.String())
	t.Setenv("KUBERNETES_SERVICE_PORT", strconv.Itoa(addr.Port))

	g, err := Acquire(context.Background(), Options{Name: "fleet-manager", Holder: "pod-a"})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = g.Release(context.Background()) }()

	if _, isLease := g.(*leaseGuard); !isLease {
		t.Fatalf("Acquire returned %T, want *leaseGuard in a cluster", g)
	}
}
