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
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestWatchManagerOutputForwardsTheNewestToken(t *testing.T) {
	r := strings.NewReader(
		"manager: starting\n" +
			"manager: first run is open; bootstrap token: fos_boot_AAAA-1111\n" +
			"manager: a session started; new token: fos_boot_BBBB-2222\n" +
			"manager: listening\n",
	)
	var out bytes.Buffer
	tokens := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		watchManagerOutput(r, nopCloser{&out}, tokens)
		close(done)
	}()
	<-done

	select {
	case tok := <-tokens:
		if tok != "fos_boot_BBBB-2222" {
			t.Errorf("token = %q, want the newest one", tok)
		}
	default:
		t.Fatal("no token was forwarded")
	}
	if !strings.Contains(out.String(), "manager: listening") {
		t.Errorf("output = %q, missing a non-token line", out.String())
	}
}

func TestWatchManagerOutputRedactsBeforeForwarding(t *testing.T) {
	r := strings.NewReader("manager: dialing 203.0.113.9 now\n")
	var out bytes.Buffer
	red := newRedactor()
	tokens := make(chan string, 1)
	watchManagerOutput(r, red.writer(&out), tokens)
	if strings.Contains(out.String(), "203.0.113.9") {
		t.Errorf("output = %q, address was not redacted", out.String())
	}
}

func TestWaitTokenRespectsContextCancellation(t *testing.T) {
	mp := &managerProcess{tokens: make(chan string)}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := mp.waitToken(ctx); err == nil {
		t.Fatal("waitToken: want an error when no token ever arrives")
	}
}

// nopCloser adapts an io.Writer to io.WriteCloser for tests that don't care
// about Close.
type nopCloser struct{ w *bytes.Buffer }

func (n nopCloser) Write(p []byte) (int, error) { return n.w.Write(p) }
func (n nopCloser) Close() error                { return nil }
