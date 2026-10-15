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
	"testing"
)

func TestAcquireFlock_SecondCallerIsRefused(t *testing.T) {
	dir := t.TempDir()

	g1, err := acquireFlock(Options{Name: "fleet-manager", Holder: "pod-a", DataDir: dir})
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer func() { _ = g1.Release(context.Background()) }()

	if _, err := acquireFlock(Options{Name: "fleet-manager", Holder: "pod-b", DataDir: dir}); !errors.Is(err, ErrHeld) {
		t.Fatalf("second acquire error = %v, want ErrHeld", err)
	}
}

// Releasing frees the lock file for the next holder -- the same recovery path
// a crashed process gets for free from the kernel closing its descriptor.
func TestAcquireFlock_ReleaseLetsAnotherAcquire(t *testing.T) {
	dir := t.TempDir()

	g1, err := acquireFlock(Options{Name: "fleet-manager", Holder: "pod-a", DataDir: dir})
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := g1.Release(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}

	g2, err := acquireFlock(Options{Name: "fleet-manager", Holder: "pod-b", DataDir: dir})
	if err != nil {
		t.Fatalf("second acquire after release: %v", err)
	}
	_ = g2.Release(context.Background())
}

// A different Name is a different deployment, and must not contend with this
// one even in the same DataDir.
func TestAcquireFlock_DifferentNameDoesNotContend(t *testing.T) {
	dir := t.TempDir()

	g1, err := acquireFlock(Options{Name: "fleet-manager-a", Holder: "pod-a", DataDir: dir})
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer func() { _ = g1.Release(context.Background()) }()

	g2, err := acquireFlock(Options{Name: "fleet-manager-b", Holder: "pod-b", DataDir: dir})
	if err != nil {
		t.Fatalf("second acquire (different name): %v", err)
	}
	_ = g2.Release(context.Background())
}

func TestAcquireFlock_RequiresDataDir(t *testing.T) {
	if _, err := acquireFlock(Options{Name: "fleet-manager", Holder: "pod-a"}); err == nil {
		t.Fatal("want an error with no DataDir")
	}
}

func TestAcquire_NonClusterUsesFlock(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	dir := t.TempDir()

	g, err := Acquire(context.Background(), Options{Name: "fleet-manager", DataDir: dir})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer func() { _ = g.Release(context.Background()) }()

	if _, isFlock := g.(*flockGuard); !isFlock {
		t.Fatalf("Acquire returned %T, want *flockGuard outside a cluster", g)
	}
}

func TestAcquire_RequiresName(t *testing.T) {
	if _, err := Acquire(context.Background(), Options{DataDir: t.TempDir()}); err == nil {
		t.Fatal("want an error with no Name")
	}
}
