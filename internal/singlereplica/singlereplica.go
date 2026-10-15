// Package singlereplica stops a second manager process from running storage
// mode memory at the same time as one that is already running: two replicas
// would each hold a different, unsynchronized view of the fleet, and nothing
// would reconcile them.
//
// Acquire picks the mechanism by environment: a Kubernetes Lease when running
// in a cluster, an flock otherwise. Both are belt-and-suspenders over the
// chart's own replicaCount guard (#194): this package is what the manager
// enforces on itself, independent of how it was started.
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
	"errors"
	"os"
)

// ErrHeld is returned by Acquire when another replica already holds the
// guard. The error text names the other holder where it is known.
var ErrHeld = errors.New("singlereplica: another replica already holds the memory-mode guard")

// Guard is a held single-replica lock. Release gives it up; a process that
// exits or crashes without calling Release still loses the guard (the flock
// is released by the kernel when the file descriptor closes, and the Lease
// goes stale once its holder stops renewing it).
type Guard interface {
	// Release gives up the guard. It is safe to call once; a Guard that was
	// never successfully acquired is never returned, so Release on the
	// returned value is always meaningful.
	Release(ctx context.Context) error
}

// OnLost is called, at most once, if a held guard is confirmed lost while the
// process is still running (a Lease the process could not renew for a full
// lease period). The caller decides what "lost" means for it; the manager
// treats it as fatal, since storage mode memory depends on exclusivity.
type OnLost func(error)

// Options configures Acquire.
type Options struct {
	// Name identifies the guard, so two independent deployments in the same
	// namespace (or on the same host) don't contend with each other. Required.
	Name string
	// Holder identifies this process to a competing replica, for the message
	// in ErrHeld. Defaults to the hostname.
	Holder string
	// DataDir is where the flock lock file lives, used when the process is
	// not running in a Kubernetes cluster. Required for that path.
	DataDir string
	// OnLost is called if a held Lease is confirmed lost; unused by the flock
	// path, which cannot silently lose its lock while the process runs.
	OnLost OnLost
}

// inCluster reports whether the process is running as a Kubernetes pod, by
// the same signal client-go's in-cluster config uses: the environment
// variables the kubelet sets in every pod's container. It is simpler and
// carries no dependency on a Kubernetes client library, which this package
// otherwise has no reason to take on.
func inCluster() bool {
	return os.Getenv("KUBERNETES_SERVICE_HOST") != "" && os.Getenv("KUBERNETES_SERVICE_PORT") != ""
}

// Acquire takes the single-replica guard, choosing the mechanism by
// environment: a Kubernetes Lease in the pod's namespace when running in a
// cluster (opts.DataDir's local filesystem is private to the pod, so an flock
// there cannot see another pod; a Lease is arbitrated by the API server
// instead), or an flock on a file under opts.DataDir otherwise (a bare host
// or a single Docker Compose node has no API server to ask, and a local
// filesystem lock is enough to see a second process on the same host or
// sharing the same volume).
//
// It returns ErrHeld, wrapped with what is known about the current holder,
// if another replica already holds the guard.
func Acquire(ctx context.Context, opts Options) (Guard, error) {
	if opts.Name == "" {
		return nil, errors.New("singlereplica: Name is required")
	}
	if opts.Holder == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			h = "unknown"
		}
		opts.Holder = h
	}

	if inCluster() {
		return acquireLease(ctx, opts)
	}
	return acquireFlock(opts)
}
