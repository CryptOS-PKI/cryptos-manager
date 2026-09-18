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
	"errors"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/CryptOS-PKI/manager/internal/store/postgres"
)

// dbConnectWindow is how long startup waits for Postgres to start accepting
// connections before giving up.
//
// The manager used to exit immediately, which made it dependent on a restart
// policy to recover: `docker compose restart` does not honour
// `depends_on.condition: service_healthy`, so the manager came back before
// Postgres was listening and died on its first query. A policy does recover it
// a second later, but the crash reads as a real fault in the logs and invites
// debugging a problem that has already fixed itself. Waiting is the honest
// behaviour, and the same race exists on any orchestrator that restarts one
// container without re-evaluating its dependencies.
const dbConnectWindow = 90 * time.Second

// Retry delays grow so a database that is briefly restarting is picked up
// quickly, without hammering one that is going to take a while.
const (
	dbRetryDelayStart = 500 * time.Millisecond
	dbRetryDelayMax   = 5 * time.Second
)

// databaseNotReady reports whether err means Postgres is not accepting
// connections *yet*, as opposed to something that will never succeed.
//
// The distinction matters in both directions. Retrying a genuine
// misconfiguration would turn a clear error into a 90-second hang, which is
// worse than the crash this replaces; not retrying a cold database leaves the
// original bug in place.
func databaseNotReady(err error) bool {
	if err == nil {
		return false
	}

	// pgx wraps the dial failure several layers deep by the time the migrator
	// surfaces it, so match on type rather than on message text.
	var connErr *pgconn.ConnectError
	if errors.As(err, &connErr) {
		return true
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}

	// The server is up but still coming up: it accepts the connection and
	// refuses to serve yet. 57P03 cannot_connect_now covers "the database
	// system is starting up"; 57P01 and 57P02 are shutdown and crash-shutdown,
	// which a restart will clear.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "57P01", "57P02", "57P03":
			return true
		}
	}

	return false
}

// openWithRetry calls open until it succeeds, until the failure is one that
// will not fix itself, or until the cumulative wait reaches window. sleep and
// logf are parameters so the retry loop is testable without a real clock.
func openWithRetry(
	open func() (*postgres.Store, error),
	window time.Duration,
	sleep func(time.Duration),
	logf func(string, ...any),
) (*postgres.Store, error) {
	delay := dbRetryDelayStart

	var waited time.Duration
	for {
		st, err := open()
		if err == nil {
			return st, nil
		}
		if !databaseNotReady(err) {
			return nil, err
		}
		// Waiting any longer would exceed the window, so report the failure
		// with the real error rather than a timeout that hides it.
		if waited+delay > window {
			return nil, err
		}

		logf("manager: postgres is not accepting connections yet, retrying in %s: %v", delay, err)
		sleep(delay)
		waited += delay

		if delay < dbRetryDelayMax {
			delay *= 2
			if delay > dbRetryDelayMax {
				delay = dbRetryDelayMax
			}
		}
	}
}
