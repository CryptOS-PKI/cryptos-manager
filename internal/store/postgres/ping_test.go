package postgres

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
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPing_ReachableDatabase(t *testing.T) {
	s := testStore(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// pgxpool connects lazily, so a pool against a port nothing listens on opens
// fine and only Ping finds out.
func TestPing_UnreachableDatabase(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://manager@127.0.0.1:1/manager?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := (&Store{pool: pool}).Ping(ctx); err == nil {
		t.Fatal("Ping: want an error for an unreachable database")
	}
}
