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
	"unicode"
	"unicode/utf8"
)

// NodeReasonKey carries, next to the code, the reason a node gave when it
// refused a request, so an operator sees why without reading the manager log.
// It is the node's own text, sanitised; nothing from the manager side is
// added to it.
const NodeReasonKey = "x-cryptos-node-reason"

// maxNodeReason caps the reason's length in bytes, before the "..." marker.
const maxNodeReason = 512

type nodeReasoned struct {
	reason string
	err    error
}

func (n *nodeReasoned) Error() string { return n.err.Error() }
func (n *nodeReasoned) Unwrap() error { return n.err }

// WithNodeReason attaches the reason a node gave for refusing to err, which
// should already carry a code. An empty reason leaves err as it is.
func WithNodeReason(err error, reason string) error {
	reason = sanitizeNodeReason(reason)
	if reason == "" {
		return err
	}
	return &nodeReasoned{reason: reason, err: err}
}

// NodeReasonOf recovers the node's reason from an error chain.
func NodeReasonOf(err error) (string, bool) {
	var n *nodeReasoned
	if errors.As(err, &n) {
		return n.reason, true
	}
	return "", false
}

// sanitizeNodeReason makes a node's message safe for a header and a UI:
// invalid UTF-8 and control characters are dropped (line breaks and tabs
// become spaces), runs of whitespace collapse to one space, and the result is
// trimmed and cut to maxNodeReason bytes on a rune boundary.
func sanitizeNodeReason(s string) string {
	var b strings.Builder
	space := false
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		switch {
		case r == utf8.RuneError && size <= 1:
			continue
		case unicode.IsSpace(r):
			space = true
			continue
		case unicode.IsControl(r) || !unicode.IsPrint(r):
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) <= maxNodeReason {
		return out
	}
	cut := maxNodeReason
	for cut > 0 && !utf8.RuneStart(out[cut]) {
		cut--
	}
	return out[:cut] + "..."
}
