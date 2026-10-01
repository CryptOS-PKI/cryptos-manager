package fleet

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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/nodeclient"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/memory"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// pauseSink records phases and signals when the adoption waits for the
// installed node's fingerprint.
type pauseSink struct {
	mu      sync.Mutex
	phases  []string
	details []string
	paused  chan string
}

func newPauseSink() *pauseSink { return &pauseSink{paused: make(chan string, 1)} }

func (p *pauseSink) send(phase, detail string, _ bool) error {
	p.mu.Lock()
	p.phases = append(p.phases, phase)
	p.details = append(p.details, detail)
	p.mu.Unlock()
	if phase == phaseAwaitingFingerprint {
		p.paused <- detail
	}
	return nil
}

func (p *pauseSink) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.phases...)
}

// confirmFixture is a root adoption whose installed node presents running.
type confirmFixture struct {
	svc     *Service
	st      *memory.Store
	running *x509.Certificate
	dials   *int
	mu      *sync.Mutex
}

func newConfirmFixture(t *testing.T) confirmFixture {
	t.Helper()
	adoptCredsBaseDir = t.TempDir()
	st := memory.New(nil)
	running := fakeRunningCert(t)
	mconn := &fakeConn{applyConfigResp: &nodev1.ApplyConfigResponse{RequiresReboot: true, Generation: 1}}
	runningConn := &fakeConn{
		status:   &nodev1.GetStatusResponse{},
		identity: rootIdentity(t),
		ceremonyStream: &scriptedCeremony{kinds: []nodev1.CeremonyEventKind{
			nodev1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE,
		}},
	}
	dials := 0
	var mu sync.Mutex
	svc := New(st, func(store.Node) (NodeConn, error) {
		mu.Lock()
		dials++
		mu.Unlock()
		return runningConn, nil
	}).
		WithAdoption(nil, func(string, string, string, string) (NodeConn, error) { return mconn, nil }).
		WithServerCertCapture(func(store.Node) (*x509.Certificate, error) { return running, nil })
	t.Cleanup(setRebootTiming(5*time.Millisecond, time.Millisecond, time.Millisecond))
	return confirmFixture{svc: svc, st: st, running: running, dials: &dials, mu: &mu}
}

func (f confirmFixture) dialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.dials
}

func sha256Hex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// colonUpper renders a hex fingerprint the way a console or openssl shows it.
func colonUpper(fp string) string {
	var parts []string
	for i := 0; i < len(fp); i += 2 {
		parts = append(parts, strings.ToUpper(fp[i:i+2]))
	}
	return strings.Join(parts, ":")
}

func startAdoption(f confirmFixture, id string, sink *pauseSink) chan error {
	done := make(chan error, 1)
	go func() {
		done <- f.svc.runAdoptionAs(context.Background(), id, &fleetv1.AdoptNodeRequest{
			Endpoint: "192.0.2.30:4443", PinnedCertSha256: "abc", Config: adoptConfig(),
		}, sink.send)
	}()
	return done
}

func waitPaused(t *testing.T, sink *pauseSink) string {
	t.Helper()
	select {
	case detail := <-sink.paused:
		return detail
	case <-time.After(2 * time.Second):
		t.Fatalf("adoption never paused for the fingerprint; phases = %v", sink.seen())
		return ""
	}
}

func waitDone(t *testing.T, done chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("adoption did not finish")
		return nil
	}
}

func confirm(svc *Service, ctx context.Context, id, sha string) error {
	_, err := svc.ConfirmAdoptionFingerprint(ctx, connect.NewRequest(&fleetv1.ConfirmAdoptionFingerprintRequest{
		AdoptionId: id, CertSha256: sha,
	}))
	return err
}

func pinPath() string {
	return filepath.Join(adoptCredsBaseDir, "new-node", nodeclient.ServerCertFile)
}

func auditByKind(st *memory.Store) map[string]store.AuditEvent {
	out := map[string]store.AuditEvent{}
	for _, e := range st.Audit() {
		out[e.Kind] = e
	}
	return out
}

func TestRunAdoption_PausesUntilTheInstalledFingerprintIsConfirmed(t *testing.T) {
	f := newConfirmFixture(t)
	sink := newPauseSink()
	done := startAdoption(f, "adopt-1", sink)

	detail := waitPaused(t, sink)
	want := sha256Hex(f.running)
	if !strings.Contains(detail, want) {
		t.Errorf("paused detail = %q, want the presented fingerprint %s", detail, want)
	}
	if got := f.svc.adoptions.presented("adopt-1"); got != want {
		t.Errorf("presented fingerprint = %q, want %q", got, want)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := os.Stat(pinPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the running certificate was pinned before the operator confirmed it (stat err = %v)", err)
	}
	if n := f.dialCount(); n != 0 {
		t.Errorf("the node was dialed %d time(s) before its fingerprint was confirmed", n)
	}
	if _, ok := f.st.Node("new-node"); ok {
		t.Error("the node was registered before its fingerprint was confirmed")
	}

	ctx := operatorCtx("admin@example.org", authz.LevelAdmin)
	if err := confirm(f.svc, ctx, "adopt-1", " "+colonUpper(want)+" "); err != nil {
		t.Fatalf("ConfirmAdoptionFingerprint() error = %v", err)
	}
	if err := waitDone(t, done); err != nil {
		t.Fatalf("runAdoption() error = %v", err)
	}

	pins := readPEMCerts(t, pinPath())
	if len(pins) != 1 || string(pins[0]) != string(f.running.Raw) {
		t.Errorf("server.crt = %d cert(s), want exactly the confirmed certificate", len(pins))
	}
	if !containsPhase(sink.seen(), phaseEstablished) {
		t.Errorf("phases = %v, want established", sink.seen())
	}
	kinds := auditByKind(f.st)
	ev, ok := kinds["node-adoption-fingerprint-confirmed"]
	if !ok {
		t.Fatalf("audit = %+v, want a node-adoption-fingerprint-confirmed event", f.st.Audit())
	}
	if ev.ActorCN != "admin@example.org" || ev.Outcome != auditlog.OutcomeOK || !strings.Contains(ev.Summary, want) {
		t.Errorf("confirm audit = %+v, want the admin, outcome ok and the fingerprint", ev)
	}
	if _, ok := kinds["node-adopted"]; !ok {
		t.Error("no node-adopted audit event after a confirmed adoption")
	}
}

func TestRunAdoption_MismatchedFingerprint_FailsAndRecordsNothing(t *testing.T) {
	f := newConfirmFixture(t)
	sink := newPauseSink()
	done := startAdoption(f, "adopt-2", sink)
	waitPaused(t, sink)

	ctx := operatorCtx("admin@example.org", authz.LevelAdmin)
	wrong := strings.Repeat("0", 64)
	requireConnectCode(t, confirm(f.svc, ctx, "adopt-2", wrong), connect.CodeInvalidArgument)

	err := waitDone(t, done)
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error = %q, want it to say the fingerprint does not match", err)
	}
	if !containsPhase(sink.seen(), phaseError) {
		t.Errorf("phases = %v, want a terminal error phase", sink.seen())
	}
	if _, err := os.Stat(pinPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused fingerprint was pinned (stat err = %v)", err)
	}
	if _, err := os.Stat(filepath.Join(adoptCredsBaseDir, "new-node", caChainFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a CA chain was recorded for a refused node (stat err = %v)", err)
	}
	if _, ok := f.st.Node("new-node"); ok {
		t.Error("a refused node was registered")
	}
	if n := f.dialCount(); n != 0 {
		t.Errorf("a refused node was dialed %d time(s)", n)
	}
	kinds := auditByKind(f.st)
	if _, ok := kinds["node-adopted"]; ok {
		t.Error("a refused adoption wrote node-adopted")
	}
	ev, ok := kinds["node-adoption-fingerprint-rejected"]
	if !ok || ev.Outcome != auditlog.OutcomeDenied {
		t.Errorf("audit = %+v, want a denied node-adoption-fingerprint-rejected event", f.st.Audit())
	}
	requireConnectCode(t, confirm(f.svc, ctx, "adopt-2", sha256Hex(f.running)), connect.CodeNotFound)
}

func TestRunAdoption_NoConfirmation_TimesOutAndRecordsNothing(t *testing.T) {
	f := newConfirmFixture(t)
	old := confirmWait
	confirmWait = 20 * time.Millisecond
	t.Cleanup(func() { confirmWait = old })
	sink := newPauseSink()
	done := startAdoption(f, "adopt-3", sink)
	waitPaused(t, sink)

	requireConnectCode(t, waitDone(t, done), connect.CodeDeadlineExceeded)
	if _, err := os.Stat(pinPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an unconfirmed certificate was pinned (stat err = %v)", err)
	}
	if _, ok := f.st.Node("new-node"); ok {
		t.Error("an unconfirmed node was registered")
	}
	ctx := operatorCtx("admin@example.org", authz.LevelAdmin)
	requireConnectCode(t, confirm(f.svc, ctx, "adopt-3", sha256Hex(f.running)), connect.CodeNotFound)
}

func TestRunAdoption_ClientGoneWhileWaiting_RecordsNothing(t *testing.T) {
	f := newConfirmFixture(t)
	sink := newPauseSink()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- f.svc.runAdoptionAs(ctx, "adopt-4", &fleetv1.AdoptNodeRequest{
			Endpoint: "192.0.2.30:4443", PinnedCertSha256: "abc", Config: adoptConfig(),
		}, sink.send)
	}()
	waitPaused(t, sink)
	cancel()

	if err := waitDone(t, done); err == nil {
		t.Fatal("runAdoption() = nil after the client went away, want an error")
	}
	if _, err := os.Stat(pinPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a cancelled adoption pinned the certificate (stat err = %v)", err)
	}
	if _, ok := f.st.Node("new-node"); ok {
		t.Error("a cancelled adoption registered the node")
	}
	if got := f.svc.adoptions.presented("adopt-4"); got != "" {
		t.Error("a cancelled adoption is still waiting for a confirmation")
	}
}

func TestConfirmAdoptionFingerprint_Refusals(t *testing.T) {
	svc := New(memory.New(nil), dialFor(nil))
	admin := operatorCtx("admin@example.org", authz.LevelAdmin)
	requireConnectCode(t, confirm(svc, operatorCtx("op@example.org", authz.LevelOperator), "adopt-x", "ab"), connect.CodePermissionDenied)
	requireConnectCode(t, confirm(svc, admin, "", "ab"), connect.CodeInvalidArgument)
	requireConnectCode(t, confirm(svc, admin, "adopt-x", " : "), connect.CodeInvalidArgument)
	requireConnectCode(t, confirm(svc, admin, "adopt-x", strings.Repeat("a", 64)), connect.CodeNotFound)
}

// Every streamed message names the adoption, and the paused one carries the
// fingerprint the operator compares with the console.
func TestAdoptStreamMessages_CarryAdoptionIDAndPresentedFingerprint(t *testing.T) {
	f := newConfirmFixture(t)
	var got []*fleetv1.AdoptNodeResponse
	var mu sync.Mutex
	paused := make(chan struct{}, 1)
	sink := f.svc.adoptSink("adopt-5", &fleetv1.AdoptNodeRequest{Config: adoptConfig()}, func(m *fleetv1.AdoptNodeResponse) error {
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
		if m.GetPhase() == phaseAwaitingFingerprint {
			paused <- struct{}{}
		}
		return nil
	})
	done := make(chan error, 1)
	go func() {
		done <- f.svc.runAdoptionAs(context.Background(), "adopt-5", &fleetv1.AdoptNodeRequest{
			Endpoint: "192.0.2.30:4443", PinnedCertSha256: "abc", Config: adoptConfig(),
		}, sink)
	}()
	select {
	case <-paused:
	case <-time.After(2 * time.Second):
		t.Fatal("adoption never paused")
	}
	if err := confirm(f.svc, operatorCtx("admin@example.org", authz.LevelAdmin), "adopt-5", sha256Hex(f.running)); err != nil {
		t.Fatal(err)
	}
	if err := waitDone(t, done); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	sawPresented := false
	for _, m := range got {
		if m.GetAdoptionId() != "adopt-5" {
			t.Errorf("phase %s adoption_id = %q, want adopt-5", m.GetPhase(), m.GetAdoptionId())
		}
		switch {
		case m.GetPhase() == phaseAwaitingFingerprint:
			sawPresented = m.GetPresentedCertSha256() == sha256Hex(f.running)
		case m.GetPresentedCertSha256() != "":
			t.Errorf("phase %s carries presented_cert_sha256, want it only on %s", m.GetPhase(), phaseAwaitingFingerprint)
		}
	}
	if !sawPresented {
		t.Error("the awaiting phase did not carry the presented fingerprint")
	}
}
