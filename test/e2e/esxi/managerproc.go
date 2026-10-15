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
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"syscall"
	"time"
)

// bootstrapTokenPattern matches the one-time bootstrap token the manager
// prints to its own log when first run is open (internal/bootstrap).
var bootstrapTokenPattern = regexp.MustCompile(`fos_boot_[0-9A-Za-z_-]+`)

// managerProcess is a running manager subprocess: its own config.yaml and TLS
// state live only under the run's tmpfs work directory, never in the repo or
// a durable path. Every line it prints is redacted before this script's own
// stdout ever sees it.
type managerProcess struct {
	cmd     *exec.Cmd
	tokens  chan string
	done    chan struct{}
	exitErr error
}

// startManager runs the manager binary at binPath against configPath,
// redacting its combined output through red before writing it to out. It
// does not wait for readiness; call waitHealthy for that.
func startManager(ctx context.Context, binPath, configPath string, red *redactor, out io.Writer) (*managerProcess, error) {
	cmd := exec.CommandContext(ctx, binPath, "-config", configPath)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }

	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	mp := &managerProcess{tokens: make(chan string, 1), done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting manager: %w", err)
	}
	mp.cmd = cmd

	redacted := red.writer(out)
	go watchManagerOutput(pr, redacted, mp.tokens)
	go func() {
		mp.exitErr = cmd.Wait()
		_ = pw.Close()
		close(mp.done)
	}()
	return mp, nil
}

// watchManagerOutput copies r to out line by line (through the redactor,
// which is itself line-buffered) and forwards every bootstrap token it finds
// to tokens, newest first. It never closes tokens: the reader may see zero,
// one or several (a session is ended and restarted), and nobody but
// bootstrapCeremony ever receives from it.
func watchManagerOutput(r io.Reader, out io.WriteCloser, tokens chan string) {
	defer func() { _ = out.Close() }()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if _, err := out.Write([]byte(line + "\n")); err != nil {
			return
		}
		if m := bootstrapTokenPattern.FindString(line); m != "" {
			select {
			case tokens <- m:
			default:
				// A newer token supersedes an unread older one.
				select {
				case <-tokens:
				default:
				}
				tokens <- m
			}
		}
	}
}

// waitToken blocks for the next bootstrap token the manager prints, or
// returns ctx's error.
func (mp *managerProcess) waitToken(ctx context.Context) (string, error) {
	select {
	case tok := <-mp.tokens:
		return tok, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// waitHealthy polls baseURL+/healthz (served anonymously, even over the
// run's self-signed TLS) until it answers 200 or ctx is done.
func waitHealthy(ctx context.Context, baseURL string) error {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/healthz", nil)
		if err == nil {
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("manager never became healthy: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// stop asks the manager to exit (SIGTERM) and waits up to timeout before
// giving up on a clean shutdown; the caller's context cancellation (via
// exec.CommandContext's Cancel) is the backstop.
func (mp *managerProcess) stop(timeout time.Duration) {
	if mp.cmd.Process != nil {
		_ = mp.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-mp.done:
	case <-time.After(timeout):
		if mp.cmd.Process != nil {
			_ = mp.cmd.Process.Signal(syscall.SIGKILL)
		}
	}
}
