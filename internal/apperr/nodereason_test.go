package apperr

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
	"errors"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
)

func metaValue(t *testing.T, err error, key string) string {
	t.Helper()
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("err is not a *connect.Error: %T", err)
	}
	return connectErr.Meta().Get(key)
}

// A node's refusal reaches the client with the node's own reason on its own
// metadata key, next to the code, while the message stays the generic one.
func TestInterceptor_CarriesTheNodeReason(t *testing.T) {
	cause := connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: apply config: pki.est: must not be set on a root node"))
	err := run(t, WithNodeReason(Coded(CodeNodeRefused, cause), "pki.est: must not be set on a root node"))

	if got := metaCode(t, err); got != CodeNodeRefused {
		t.Errorf("code = %d, want %d", got, CodeNodeRefused)
	}
	if got := metaValue(t, err, NodeReasonKey); got != "pki.est: must not be set on a root node" {
		t.Errorf("%s = %q, want the node's reason", NodeReasonKey, got)
	}
	if c := connect.CodeOf(err); c != connect.CodeInvalidArgument {
		t.Errorf("connect code = %v, want InvalidArgument", c)
	}
}

func TestInterceptor_NoNodeReasonWithoutOne(t *testing.T) {
	err := run(t, Coded(CodeNodeUnreachable, errors.New("dial failed")))
	if got := metaValue(t, err, NodeReasonKey); got != "" {
		t.Errorf("%s = %q, want none", NodeReasonKey, got)
	}
}

func TestSanitizeNodeReason(t *testing.T) {
	long := strings.Repeat("x", 600)
	for _, tc := range []struct{ in, want string }{
		{"pki.est: must not be set on a root node", "pki.est: must not be set on a root node"},
		{"line one\nline two\t\x1b[31mred\x00", "line one line two [31mred"},
		{"  padded  ", "padded"},
		{long, strings.Repeat("x", maxNodeReason) + "..."},
		{"caf\xe9 bad utf8", "caf bad utf8"},
	} {
		if got := sanitizeNodeReason(tc.in); got != tc.want {
			t.Errorf("sanitizeNodeReason(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
