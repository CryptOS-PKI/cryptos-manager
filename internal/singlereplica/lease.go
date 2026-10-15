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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// serviceAccountDir is where Kubernetes projects the pod's token, CA
// certificate and namespace; overridden in tests.
var serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// leaseDuration is how long a Lease is honored without a renewal before
// another replica may take it over. leaseRenewInterval is how often the
// holder refreshes it; a third of the duration leaves two missed renewals of
// slack before the lease is considered stale.
const (
	leaseDuration      = 30 * time.Second
	leaseRenewInterval = leaseDuration / 3
	// microTimeFormat matches metav1.MicroTime's JSON encoding closely enough
	// for this package's own round trip (it parses what it writes); the Lease
	// this guard uses is private to the manager, not read by kube-scheduler
	// style leader election, so exact client-go conformance is not required.
	microTimeFormat = "2006-01-02T15:04:05.000000Z"
)

// leaseClient is a minimal client for the coordination.k8s.io/v1 Lease
// resource, built from the pod's own in-cluster credentials. Taking on
// k8s.io/client-go for one resource type would be a maintenance cost (a large
// dependency tree with its own API-compatibility surface) this package avoids
// by speaking the plain REST API directly.
type leaseClient struct {
	http      *http.Client
	baseURL   string
	token     string
	namespace string
}

// inClusterLeaseClient builds a leaseClient from the standard files
// Kubernetes projects into every pod, and the KUBERNETES_SERVICE_HOST/PORT
// environment variables the kubelet sets. Each is read fresh rather than
// cached, since the token is periodically rotated in place.
func inClusterLeaseClient() (*leaseClient, error) {
	token, err := os.ReadFile(filepath.Join(serviceAccountDir, "token"))
	if err != nil {
		return nil, fmt.Errorf("singlereplica: read service account token: %w", err)
	}
	namespace, err := os.ReadFile(filepath.Join(serviceAccountDir, "namespace"))
	if err != nil {
		return nil, fmt.Errorf("singlereplica: read service account namespace: %w", err)
	}
	caCert, err := os.ReadFile(filepath.Join(serviceAccountDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("singlereplica: read service account CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("singlereplica: %s/ca.crt has no usable certificate", serviceAccountDir)
	}

	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	return &leaseClient{
		http: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
		baseURL:   "https://" + net.JoinHostPort(host, port),
		token:     strings.TrimSpace(string(token)),
		namespace: strings.TrimSpace(string(namespace)),
	}, nil
}

// leaseObject is the subset of a coordination.k8s.io/v1 Lease this package
// reads and writes.
type leaseObject struct {
	Metadata leaseMetadata `json:"metadata"`
	Spec     leaseSpec     `json:"spec"`
}

type leaseMetadata struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace,omitempty"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

type leaseSpec struct {
	HolderIdentity       string `json:"holderIdentity,omitempty"`
	LeaseDurationSeconds int32  `json:"leaseDurationSeconds,omitempty"`
	AcquireTime          string `json:"acquireTime,omitempty"`
	RenewTime            string `json:"renewTime,omitempty"`
}

// expired reports whether the lease's renewal window has passed as of now.
func (s leaseSpec) expired(now time.Time) bool {
	renew, err := time.Parse(microTimeFormat, s.RenewTime)
	if err != nil {
		// An unparsable or absent renewTime cannot prove the holder is alive.
		return true
	}
	dur := leaseDuration
	if s.LeaseDurationSeconds > 0 {
		dur = time.Duration(s.LeaseDurationSeconds) * time.Second
	}
	return now.After(renew.Add(dur))
}

func (c *leaseClient) url(name string) string {
	return c.baseURL + "/apis/coordination.k8s.io/v1/namespaces/" + url.PathEscape(c.namespace) +
		"/leases/" + url.PathEscape(name)
}

func (c *leaseClient) do(ctx context.Context, method, rawURL string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// get fetches the named Lease. ok is false when it does not exist yet.
func (c *leaseClient) get(ctx context.Context, name string) (obj leaseObject, ok bool, err error) {
	resp, err := c.do(ctx, http.MethodGet, c.url(name), nil)
	if err != nil {
		return leaseObject{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
			return leaseObject{}, false, fmt.Errorf("singlereplica: decode lease %s: %w", name, err)
		}
		return obj, true, nil
	case http.StatusNotFound:
		return leaseObject{}, false, nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return leaseObject{}, false, fmt.Errorf("singlereplica: get lease %s: %s: %s", name, resp.Status, string(b))
	}
}

// create makes a new Lease held by holder. It returns an error on a 409 so
// the caller can fall back to the get/update path when it lost the race.
func (c *leaseClient) create(ctx context.Context, name, holder string, now time.Time) (leaseObject, error) {
	obj := leaseObject{
		Metadata: leaseMetadata{Name: name, Namespace: c.namespace},
		Spec: leaseSpec{
			HolderIdentity:       holder,
			LeaseDurationSeconds: int32(leaseDuration / time.Second),
			AcquireTime:          now.UTC().Format(microTimeFormat),
			RenewTime:            now.UTC().Format(microTimeFormat),
		},
	}
	resp, err := c.do(ctx, http.MethodPost,
		c.baseURL+"/apis/coordination.k8s.io/v1/namespaces/"+url.PathEscape(c.namespace)+"/leases", obj)
	if err != nil {
		return leaseObject{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return leaseObject{}, fmt.Errorf("singlereplica: create lease %s: %s: %s", name, resp.Status, string(b))
	}
	var created leaseObject
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return leaseObject{}, fmt.Errorf("singlereplica: decode created lease %s: %w", name, err)
	}
	return created, nil
}

// update replaces the Lease at its current resourceVersion, so a concurrent
// writer is detected as a conflict rather than silently overwritten.
func (c *leaseClient) update(ctx context.Context, obj leaseObject) (leaseObject, error) {
	resp, err := c.do(ctx, http.MethodPut, c.url(obj.Metadata.Name), obj)
	if err != nil {
		return leaseObject{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return leaseObject{}, fmt.Errorf("singlereplica: update lease %s: %s: %s", obj.Metadata.Name, resp.Status, string(b))
	}
	var updated leaseObject
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		return leaseObject{}, fmt.Errorf("singlereplica: decode updated lease %s: %w", obj.Metadata.Name, err)
	}
	return updated, nil
}

func (c *leaseClient) delete(ctx context.Context, name string) error {
	resp, err := c.do(ctx, http.MethodDelete, c.url(name), nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("singlereplica: delete lease %s: %s: %s", name, resp.Status, string(b))
	}
	return nil
}

// acquireLease builds an in-cluster leaseClient and claims the Lease named
// opts.Name.
func acquireLease(ctx context.Context, opts Options) (Guard, error) {
	client, err := inClusterLeaseClient()
	if err != nil {
		return nil, err
	}
	return claimLease(ctx, client, opts)
}

// claimLease is acquireLease's testable core: it takes an already-built
// client so tests can point it at an httptest.Server instead of the real
// Kubernetes API.
func claimLease(ctx context.Context, client *leaseClient, opts Options) (Guard, error) {
	now := time.Now()
	existing, ok, err := client.get(ctx, opts.Name)
	if err != nil {
		return nil, err
	}

	var claimed leaseObject
	switch {
	case !ok:
		claimed, err = client.create(ctx, opts.Name, opts.Holder, now)
		if err != nil {
			// Lost a race to create it; fall through to the update path
			// against whatever is there now.
			existing, ok, err = client.get(ctx, opts.Name)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("singlereplica: lease %s disappeared mid-claim", opts.Name)
			}
			claimed, err = claimExisting(ctx, client, opts, existing, now)
			if err != nil {
				return nil, err
			}
		}
	default:
		claimed, err = claimExisting(ctx, client, opts, existing, now)
		if err != nil {
			return nil, err
		}
	}

	g := &leaseGuard{
		client:          client,
		name:            opts.Name,
		holder:          opts.Holder,
		onLost:          opts.OnLost,
		resourceVersion: claimed.Metadata.ResourceVersion,
	}
	g.startRenewing()
	return g, nil
}

// claimExisting takes over a Lease that is either already ours or has gone
// stale, and refuses one that is live under another holder.
func claimExisting(ctx context.Context, client *leaseClient, opts Options, existing leaseObject, now time.Time) (leaseObject, error) {
	if existing.Spec.HolderIdentity != opts.Holder && !existing.Spec.expired(now) {
		return leaseObject{}, fmt.Errorf("%w: lease %s is held by %q, renewed %s",
			ErrHeld, opts.Name, existing.Spec.HolderIdentity, existing.Spec.RenewTime)
	}

	existing.Spec.HolderIdentity = opts.Holder
	existing.Spec.LeaseDurationSeconds = int32(leaseDuration / time.Second)
	existing.Spec.AcquireTime = now.UTC().Format(microTimeFormat)
	existing.Spec.RenewTime = now.UTC().Format(microTimeFormat)
	return client.update(ctx, existing)
}

// leaseGuard is a held Lease, kept alive by a background renewal loop.
//
// resourceVersion is read and written only by the single renewLoop
// goroutine, set once before it starts and never touched by Release (which
// only stops the loop and deletes the lease), so it needs no synchronization
// of its own.
type leaseGuard struct {
	client *leaseClient
	name   string
	holder string
	onLost OnLost

	resourceVersion string
	stop            chan struct{}
	stopped         sync.WaitGroup
}

func (g *leaseGuard) startRenewing() {
	g.stop = make(chan struct{})
	g.stopped.Add(1)
	go g.renewLoop()
}

func (g *leaseGuard) renewLoop() {
	defer g.stopped.Done()

	ticker := time.NewTicker(leaseRenewInterval)
	defer ticker.Stop()

	var lastSuccess = time.Now()
	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), leaseRenewInterval)
			err := g.renewOnce(ctx)
			cancel()
			if err != nil {
				log.Printf("singlereplica: WARNING renew lease %s: %v", g.name, err)
				if time.Since(lastSuccess) > leaseDuration {
					if g.onLost != nil {
						g.onLost(fmt.Errorf("singlereplica: lost lease %s: %w", g.name, err))
					}
					return
				}
				continue
			}
			lastSuccess = time.Now()
		}
	}
}

func (g *leaseGuard) renewOnce(ctx context.Context) error {
	obj := leaseObject{
		Metadata: leaseMetadata{Name: g.name, Namespace: g.client.namespace, ResourceVersion: g.resourceVersion},
		Spec: leaseSpec{
			HolderIdentity:       g.holder,
			LeaseDurationSeconds: int32(leaseDuration / time.Second),
			RenewTime:            time.Now().UTC().Format(microTimeFormat),
		},
	}
	// AcquireTime is immutable once set; fetch it so the update doesn't wipe
	// it (the API server does not merge, PUT replaces the whole spec).
	current, ok, err := g.client.get(ctx, g.name)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("lease no longer exists")
	}
	if current.Spec.HolderIdentity != g.holder {
		return fmt.Errorf("lease now held by %q", current.Spec.HolderIdentity)
	}
	obj.Spec.AcquireTime = current.Spec.AcquireTime
	obj.Metadata.ResourceVersion = current.Metadata.ResourceVersion

	updated, err := g.client.update(ctx, obj)
	if err != nil {
		return err
	}
	g.resourceVersion = updated.Metadata.ResourceVersion
	return nil
}

func (g *leaseGuard) Release(ctx context.Context) error {
	close(g.stop)
	g.stopped.Wait()
	// Best effort: a failed delete just leaves the lease to expire on its
	// own after leaseDuration, which the next claimant already handles.
	_ = g.client.delete(ctx, g.name)
	return nil
}
