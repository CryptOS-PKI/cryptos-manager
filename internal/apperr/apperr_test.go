package apperr

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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
)

// A handler's specific code survives to the client, which is the whole point:
// the UI branches on the number.
func TestInterceptor_CarriesTheHandlersCode(t *testing.T) {
	err := run(t, Coded(CodeOperatorCAUnconfigured,
		connect.NewError(connect.CodeFailedPrecondition, errors.New("no operator CA node configured"))))

	if got := metaCode(t, err); got != CodeOperatorCAUnconfigured {
		t.Errorf("code = %d, want %d", got, CodeOperatorCAUnconfigured)
	}
	// The transport code decides how the client treats it, so it must not be
	// flattened into Internal on the way out.
	if c := connect.CodeOf(err); c != connect.CodeFailedPrecondition {
		t.Errorf("connect code = %v, want FailedPrecondition", c)
	}
}

// An unclassified failure still arrives as a code, so the UI always has
// something to show and a report always has something to quote.
func TestInterceptor_DefaultsToUnknown(t *testing.T) {
	err := run(t, errors.New("something nobody classified"))

	if got := metaCode(t, err); got != CodeUnknown {
		t.Errorf("code = %d, want %d", got, CodeUnknown)
	}
	if c := connect.CodeOf(err); c != connect.CodeInternal {
		t.Errorf("connect code = %v, want Internal for a plain error", c)
	}
}

// The internal cause may name a node, a path or a DSN. The client gets the
// registered message and the code, never the cause.
func TestInterceptor_DoesNotLeakTheCause(t *testing.T) {
	secret := "dial 10.0.0.20:443: postgres://manager:hunter2@db"
	err := run(t, Coded(CodeNodeUnreachable, errors.New(secret)))

	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "10.0.0.20") {
		t.Errorf("the client message leaked the internal cause: %q", err.Error())
	}
	if !strings.Contains(err.Error(), strconv.Itoa(CodeNodeUnreachable)) {
		t.Errorf("message %q does not quote the code", err.Error())
	}
}

// A success must pass through untouched.
func TestInterceptor_LeavesSuccessAlone(t *testing.T) {
	next := connect.UnaryFunc(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		return connect.NewResponse(&struct{}{}), nil
	})

	resp, err := Interceptor()(next)(context.Background(), connect.NewRequest(&struct{}{}))
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if resp == nil {
		t.Error("response was dropped")
	}
}

// Every registered code must round-trip through the registry, or a handler
// could tag a failure with a code the client is then told nothing about.
func TestRegistry_DescribesEveryCode(t *testing.T) {
	for _, e := range entries {
		if _, ok := Registry().Describe(e.Code); !ok {
			t.Errorf("code %d is not described by the registry", e.Code)
		}
		if Registry().Message(e.Code) == "" {
			t.Errorf("code %d renders an empty client message", e.Code)
		}
	}
}

// The manager owns the 1xxx block. A code outside it is attributable to the
// wrong service at a glance, which defeats the convention.
func TestCodes_AreInTheManagersBlock(t *testing.T) {
	for _, e := range entries {
		if e.Code < 1000 || e.Code > 1999 {
			t.Errorf("code %d is outside the manager's 1000-1999 block", e.Code)
		}
	}
}

func TestCodes_AreUnique(t *testing.T) {
	seen := make(map[int]string, len(entries))
	for _, e := range entries {
		if prev, dup := seen[e.Code]; dup {
			t.Errorf("code %d is registered twice: %q and %q", e.Code, prev, e.Title)
		}
		seen[e.Code] = e.Title
	}
}

// run puts err through the interceptor and hands back what a client would see.
func run(t *testing.T, err error) error {
	t.Helper()

	next := connect.UnaryFunc(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, err
	})
	_, out := Interceptor()(next)(context.Background(), connect.NewRequest(&struct{}{}))
	if out == nil {
		t.Fatal("interceptor swallowed the error")
	}

	return out
}

func metaCode(t *testing.T, err error) int {
	t.Helper()

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("err is not a *connect.Error: %T", err)
	}
	raw := connectErr.Meta().Get(MetadataKey)
	if raw == "" {
		t.Fatalf("no %s on the error metadata", MetadataKey)
	}
	code, convErr := strconv.Atoi(raw)
	if convErr != nil {
		t.Fatalf("metadata %q is not a number: %v", raw, convErr)
	}

	return code
}

// The committed table is generated. If it drifts, an operator looking up a code
// they were told to quote finds nothing -- which defeats having stable codes at
// all.
func TestErrorCodesDocIsCurrent(t *testing.T) {
	committed, err := os.ReadFile(filepath.Join("..", "..", "docs", "error-codes.md"))
	if err != nil {
		t.Fatalf("reading the committed table: %v", err)
	}

	if string(committed) != Doc() {
		t.Error("docs/error-codes.md is out of date; regenerate with: go run ./tools/errorcodes > docs/error-codes.md")
	}
}
