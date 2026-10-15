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
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// flockGuard holds an exclusive, non-blocking flock on a file. The OS
// releases the lock automatically when the file descriptor closes, including
// on a crash, which is exactly the "a dead replica stops holding the guard"
// behavior wanted here, with no heartbeat of its own to maintain.
type flockGuard struct {
	f *os.File
}

// acquireFlock takes an exclusive, non-blocking flock on a lock file under
// opts.DataDir named for opts.Name, so two different deployments that happen
// to share a host (or a Docker Compose volume) don't contend for the same
// file.
func acquireFlock(opts Options) (Guard, error) {
	if opts.DataDir == "" {
		return nil, errors.New("singlereplica: DataDir is required outside a Kubernetes cluster")
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("singlereplica: create %s: %w", opts.DataDir, err)
	}

	path := filepath.Join(opts.DataDir, "."+opts.Name+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("singlereplica: open %s: %w", path, err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s is held by another process", ErrHeld, path)
		}
		return nil, fmt.Errorf("singlereplica: lock %s: %w", path, err)
	}

	// The holder's identity is written for anyone reading the file while
	// debugging a stuck lock; it plays no role in the lock itself.
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(opts.Holder+"\n"), 0)

	return &flockGuard{f: f}, nil
}

func (g *flockGuard) Release(context.Context) error {
	err := syscall.Flock(int(g.f.Fd()), syscall.LOCK_UN)
	if cerr := g.f.Close(); err == nil {
		err = cerr
	}
	return err
}
