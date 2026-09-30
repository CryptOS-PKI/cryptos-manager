package postgres

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
	"testing"
)

func TestMigrateIdempotent(t *testing.T) {
	pool := testPool(t) // skips if MANAGER_TEST_DATABASE_URL unset
	ctx := context.Background()

	if err := migrate(ctx, pool); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := migrate(ctx, pool); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	var n int
	if err := pool.QueryRow(ctx, "select count(*) from enrollments").Scan(&n); err != nil {
		t.Fatalf("count enrollments: %v", err)
	}
	if n != 0 {
		t.Fatalf("want empty enrollments, got %d", n)
	}
}
