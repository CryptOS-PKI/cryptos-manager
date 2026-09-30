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
	"errors"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store/postgres"
)

// refusedError returns the real error from trying to open a store against a
// port nothing is listening on. Using the genuine error rather than a
// hand-built one is the point: the retry decision has to hold against whatever
// pgx actually wraps, through however many layers it wraps it in.
func refusedError(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Port 1 is reserved and never has a listener.
	_, err := postgres.New(ctx, "postgres://u:p@127.0.0.1:1/db")
	if err == nil {
		t.Fatal("expected opening a store against a dead port to fail")
	}
	return err
}

// TestDatabaseNotReady_ConnectionRefused is the case from the field report: the
// manager comes back before Postgres is accepting connections, because
// `docker compose restart` does not honour depends_on.condition.
func TestDatabaseNotReady_ConnectionRefused(t *testing.T) {
	err := refusedError(t)
	if !databaseNotReady(err) {
		t.Errorf("databaseNotReady(%v) = false, want true", err)
	}
}

// TestDatabaseNotReady_ConfigErrorsFailFast: a DSN that can never work must not
// be retried. Spinning for the whole window on a typo turns a clear error into
// a hang, which is worse than the crash this change is removing.
func TestDatabaseNotReady_ConfigErrorsFailFast(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := postgres.New(ctx, "this is not a dsn")
	if err == nil {
		t.Fatal("expected a malformed DSN to fail")
	}
	if databaseNotReady(err) {
		t.Errorf("databaseNotReady(%v) = true, want false for a malformed DSN", err)
	}
}

func TestDatabaseNotReady_NilAndUnrelated(t *testing.T) {
	if databaseNotReady(nil) {
		t.Error("databaseNotReady(nil) = true, want false")
	}
	if databaseNotReady(errors.New("something else entirely")) {
		t.Error("databaseNotReady(unrelated) = true, want false")
	}
}

// TestOpenWithRetry_SucceedsOnceTheDatabaseIsUp is the behaviour that replaces
// the crash: the manager waits for Postgres instead of exiting and relying on a
// restart policy to paper over it.
func TestOpenWithRetry_SucceedsOnceTheDatabaseIsUp(t *testing.T) {
	notReady := refusedError(t)
	attempts := 0
	var slept time.Duration

	_, err := openWithRetry(
		func() (*postgres.Store, error) {
			attempts++
			if attempts < 3 {
				return nil, notReady
			}
			return nil, nil
		},
		time.Minute,
		func(d time.Duration) { slept += d },
		func(string, ...any) {},
	)
	if err != nil {
		t.Fatalf("openWithRetry: %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
	if slept == 0 {
		t.Error("retried without waiting between attempts, which would spin")
	}
}

// The wait is bounded: a database that never arrives must still fail, and must
// not sleep past the window it was given.
func TestOpenWithRetry_GivesUpAfterTheWindow(t *testing.T) {
	notReady := refusedError(t)
	attempts := 0
	var slept time.Duration
	window := 10 * time.Second

	_, err := openWithRetry(
		func() (*postgres.Store, error) {
			attempts++
			return nil, notReady
		},
		window,
		func(d time.Duration) { slept += d },
		func(string, ...any) {},
	)
	if err == nil {
		t.Fatal("openWithRetry = nil error, want the last failure once the window expired")
	}
	if attempts < 2 {
		t.Errorf("attempts = %d, want more than one before giving up", attempts)
	}
	if slept > window {
		t.Errorf("slept %s, want no more than the %s window", slept, window)
	}
}

// A configuration error is returned on the first attempt, unchanged.
func TestOpenWithRetry_DoesNotRetryAConfigError(t *testing.T) {
	sentinel := errors.New("bad dsn")
	attempts := 0

	_, err := openWithRetry(
		func() (*postgres.Store, error) {
			attempts++
			return nil, sentinel
		},
		time.Minute,
		func(time.Duration) { t.Error("slept on a non-retryable error") },
		func(string, ...any) {},
	)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the original %v", err, sentinel)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want exactly 1", attempts)
	}
}

// Succeeding immediately must not wait at all, so normal startup is unchanged.
func TestOpenWithRetry_NoWaitWhenAvailable(t *testing.T) {
	attempts := 0

	if _, err := openWithRetry(
		func() (*postgres.Store, error) {
			attempts++
			return nil, nil
		},
		time.Minute,
		func(time.Duration) { t.Error("slept even though the first attempt succeeded") },
		func(string, ...any) {},
	); err != nil {
		t.Fatalf("openWithRetry: %v", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
}
