package main

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
	"io"
	"regexp"
	"sort"
	"strings"
)

// ipv4Pattern matches a dotted-quad IPv4 address. It is deliberately loose
// (it also matches an out-of-range octet) because this is a redaction filter,
// not a validator: over-matching only hides more text, never leaks it.
var ipv4Pattern = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

// redactor replaces every configured secret (a node endpoint host, an admin
// credential path, the manager's own address) and any IPv4 address with a
// placeholder, mirroring cryptos-appliance's gate_redact: lab values never
// reach this script's own output. Longer secrets are replaced first, so a
// value that contains another is replaced whole.
type redactor struct {
	secrets []string
}

// newRedactor builds a redactor for secrets, dropping empty values and
// sorting the rest longest-first.
func newRedactor(secrets ...string) *redactor {
	out := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if s != "" {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return &redactor{secrets: out}
}

// line redacts one line of text.
func (r *redactor) line(s string) string {
	for _, secret := range r.secrets {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	return ipv4Pattern.ReplaceAllString(s, "[ipv4]")
}

// writer wraps w so every write is redacted first. Writes are line-buffered:
// a line is only redacted, and so only forwarded, once a trailing newline
// arrives, so a secret split across two Write calls is still caught.
func (r *redactor) writer(w io.Writer) io.WriteCloser {
	return &redactingWriter{out: w, r: r}
}

type redactingWriter struct {
	out io.Writer
	r   *redactor
	buf strings.Builder
}

func (w *redactingWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.buf.Write(p)
	for {
		s := w.buf.String()
		idx := strings.IndexByte(s, '\n')
		if idx < 0 {
			break
		}
		if _, err := io.WriteString(w.out, w.r.line(s[:idx+1])); err != nil {
			return n, err
		}
		w.buf.Reset()
		w.buf.WriteString(s[idx+1:])
	}
	return n, nil
}

// Close flushes any unterminated final line.
func (w *redactingWriter) Close() error {
	if w.buf.Len() == 0 {
		return nil
	}
	_, err := io.WriteString(w.out, w.r.line(w.buf.String()))
	w.buf.Reset()
	return err
}
