package fleet

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
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

// scriptedCeremony replays a fixed sequence of ceremony event kinds, then EOF.
type scriptedCeremony struct {
	kinds []cryptosv1.CeremonyEventKind
	i     int
}

func (s *scriptedCeremony) Recv() (*cryptosv1.StartCeremonyResponse, error) {
	if s.i >= len(s.kinds) {
		return nil, io.EOF
	}
	k := s.kinds[s.i]
	s.i++
	return &cryptosv1.StartCeremonyResponse{
		Event: &cryptosv1.CeremonyEvent{Kind: k, Ts: timestamppb.Now()},
	}, nil
}

// collectSink records every streamed phase for assertion.
type collectSink struct {
	phases []string
	done   bool
}

func (c *collectSink) send(phase, _ string, done bool) error {
	c.phases = append(c.phases, phase)
	if done {
		c.done = true
	}
	return nil
}

func adoptConfig() *cryptosv1.MachineConfig {
	return &cryptosv1.MachineConfig{
		Metadata: &cryptosv1.Metadata{Name: "new-node"},
		Role:     &cryptosv1.Role{Kind: "root"},
	}
}

func TestPreviewAdoption_Admin_ReturnsFingerprint(t *testing.T) {
	svc := New(memory.New(nil), dialFor(nil)).WithAdoption(
		func(endpoint string) (string, string, error) {
			return "abc123", "CN=maintenance", nil
		}, nil)

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.PreviewAdoption(ctx, connect.NewRequest(&fleetv1.PreviewAdoptionRequest{Endpoint: "node:4443"}))
	if err != nil {
		t.Fatalf("PreviewAdoption(admin) error = %v", err)
	}
	if resp.Msg.GetCertSha256() != "abc123" || resp.Msg.GetSubject() != "CN=maintenance" {
		t.Errorf("preview = %+v, want abc123 / CN=maintenance", resp.Msg)
	}
}

func TestPreviewAdoption_OperatorDenied(t *testing.T) {
	svc := New(memory.New(nil), dialFor(nil)).WithAdoption(
		func(string) (string, string, error) { return "x", "y", nil }, nil)
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.PreviewAdoption(ctx, connect.NewRequest(&fleetv1.PreviewAdoptionRequest{Endpoint: "n:1"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func TestListInstallDisks_ReturnsNodeDisks(t *testing.T) {
	conn := &fakeConn{disks: &cryptosv1.ListInstallDisksResponse{Disks: []*cryptosv1.InstallDisk{
		{Path: "/dev/nvme0n1", SizeBytes: 1 << 30, Model: "Test SSD"},
	}}}
	svc := New(memory.New(nil), dialFor(nil)).WithAdoption(nil,
		func(endpoint, pin, clientCertPEM, clientKeyPEM string) (NodeConn, error) { return conn, nil })
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.ListInstallDisks(ctx, connect.NewRequest(&fleetv1.ListInstallDisksRequest{
		Endpoint: "node:443", PinnedCertSha256: "abc",
	}))
	if err != nil {
		t.Fatalf("ListInstallDisks(admin) error = %v", err)
	}
	if disks := resp.Msg.GetDisks(); len(disks) != 1 || disks[0].GetPath() != "/dev/nvme0n1" {
		t.Errorf("disks = %+v, want one /dev/nvme0n1", resp.Msg.GetDisks())
	}
}

func TestListInstallDisks_OperatorDenied(t *testing.T) {
	svc := New(memory.New(nil), dialFor(nil)).WithAdoption(nil,
		func(string, string, string, string) (NodeConn, error) { return &fakeConn{}, nil })
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.ListInstallDisks(ctx, connect.NewRequest(&fleetv1.ListInstallDisksRequest{
		Endpoint: "n:1", PinnedCertSha256: "p",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func TestRunAdoption_HappyPath_StreamsPhasesRegistersAndAudits(t *testing.T) {
	adoptCredsBaseDir = t.TempDir()
	st := memory.New(nil)
	// The maintenance dial applies the config (install).
	mconn := &fakeConn{applyConfigResp: &cryptosv1.ApplyConfigResponse{RequiresReboot: true, Generation: 1}}
	// After install + self-reboot the node is dialed in running mode (by name,
	// via s.dial) for the ceremony.
	running := &fakeConn{
		status: &cryptosv1.GetStatusResponse{},
		ceremonyStream: &scriptedCeremony{kinds: []cryptosv1.CeremonyEventKind{
			cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_KEY_CREATED,
			cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_CERT_SIGNED,
			cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE,
		}},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"new-node": running})).WithAdoption(nil,
		func(endpoint, pin, clientCertPEM, clientKeyPEM string) (NodeConn, error) { return mconn, nil })

	// Shrink the reboot timing so the bounded wait is fast in the test.
	restore := setRebootTiming(5*time.Millisecond, 1*time.Millisecond, 1*time.Millisecond)
	defer restore()

	sink := &collectSink{}
	err := svc.runAdoption(context.Background(), &fleetv1.AdoptNodeRequest{
		Endpoint: "node:4443", PinnedCertSha256: "abc", Config: adoptConfig(),
	}, sink.send)
	if err != nil {
		t.Fatalf("runAdoption happy path error = %v", err)
	}

	if !sink.done {
		t.Error("adoption did not stream a terminal done phase")
	}
	if !containsPhase(sink.phases, phaseApplyingConfig) ||
		!containsPhase(sink.phases, phaseAwaitingReboot) ||
		!containsPhase(sink.phases, phaseCeremony) ||
		!containsPhase(sink.phases, phaseEstablished) {
		t.Errorf("phases = %v, want applying-config/awaiting-reboot/ceremony/established", sink.phases)
	}
	if got := running.gotCeremonyYAML; len(got) == 0 {
		t.Error("StartCeremony was not given the config YAML")
	}

	if _, ok := st.Node("new-node"); !ok {
		t.Error("adopted node was not registered in the inventory")
	}
	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "node-adopted" {
		t.Fatalf("audit = %+v, want one node-adopted event", audit)
	}
}

func TestRunAdoption_Subordinate_AwaitsCertificate_NoCeremony(t *testing.T) {
	adoptCredsBaseDir = t.TempDir()
	st := memory.New(nil)
	mconn := &fakeConn{applyConfigResp: &cryptosv1.ApplyConfigResponse{RequiresReboot: true, Generation: 1}}
	// A subordinate node comes back running but has NO ceremony: it staged its
	// own subordinate CSR on boot and awaits a parent-signed chain. The ceremony
	// stream is intentionally absent — running it would be a bug.
	running := &fakeConn{status: &cryptosv1.GetStatusResponse{}}
	svc := New(st, dialFor(map[string]*fakeConn{"sub-node": running})).WithAdoption(nil,
		func(endpoint, pin, clientCertPEM, clientKeyPEM string) (NodeConn, error) { return mconn, nil })

	restore := setRebootTiming(5*time.Millisecond, 1*time.Millisecond, 1*time.Millisecond)
	defer restore()

	cfg := &cryptosv1.MachineConfig{
		Metadata: &cryptosv1.Metadata{Name: "sub-node"},
		Role:     &cryptosv1.Role{Kind: "intermediate"},
	}
	sink := &collectSink{}
	err := svc.runAdoption(context.Background(), &fleetv1.AdoptNodeRequest{
		Endpoint: "node:4443", PinnedCertSha256: "abc", Config: cfg,
	}, sink.send)
	if err != nil {
		t.Fatalf("runAdoption subordinate error = %v", err)
	}

	if !sink.done {
		t.Error("subordinate adoption did not stream a terminal done phase")
	}
	if !containsPhase(sink.phases, phaseAwaitingCertificate) {
		t.Errorf("phases = %v, want a terminal awaiting-certificate", sink.phases)
	}
	if containsPhase(sink.phases, phaseCeremony) || containsPhase(sink.phases, phaseEstablished) {
		t.Errorf("phases = %v, a subordinate must not run the root ceremony or reach established", sink.phases)
	}
	if len(running.gotCeremonyYAML) != 0 {
		t.Error("StartCeremony was called on a subordinate node")
	}
	if _, ok := st.Node("sub-node"); !ok {
		t.Error("adopted subordinate was not registered in the inventory")
	}
}

func TestRunAdoption_RebootNeverReturns_StreamsErrorPhase_NoHang(t *testing.T) {
	adoptCredsBaseDir = t.TempDir()
	st := memory.New(nil)
	// The maintenance dial applies the config (install) fine. After the reboot
	// the node is dialed in running mode (by name, via s.dial), but its
	// GetStatus keeps erroring so the node never confirms it is back. The
	// bounded reboot wait must expire and stream an error phase rather than
	// blocking forever.
	mdial := func(endpoint, pin, clientCertPEM, clientKeyPEM string) (NodeConn, error) {
		return &fakeConn{applyConfigResp: &cryptosv1.ApplyConfigResponse{RequiresReboot: true}}, nil
	}
	down := &fakeConn{err: errors.New("node down")}
	svc := New(st, dialFor(map[string]*fakeConn{"new-node": down})).WithAdoption(nil, mdial)

	restore := setRebootTiming(10*time.Millisecond, 2*time.Millisecond, 1*time.Millisecond)
	defer restore()

	sink := &collectSink{}
	done := make(chan error, 1)
	go func() {
		done <- svc.runAdoption(context.Background(), &fleetv1.AdoptNodeRequest{
			Endpoint: "node:4443", PinnedCertSha256: "abc", Config: adoptConfig(),
		}, sink.send)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("runAdoption returned nil on a node that never rebooted, want an error")
		}
		requireConnectCode(t, err, connect.CodeDeadlineExceeded)
	case <-time.After(2 * time.Second):
		t.Fatal("runAdoption hung waiting for a reboot that never returns")
	}

	if !containsPhase(sink.phases, phaseError) {
		t.Errorf("phases = %v, want a terminal error phase", sink.phases)
	}
	if _, ok := st.Node("new-node"); ok {
		t.Error("a failed adoption registered the node anyway")
	}
	if len(st.Audit()) != 0 {
		t.Error("a failed adoption wrote a node-adopted audit event")
	}
}

func TestRunAdoption_MissingPin_InvalidArgument(t *testing.T) {
	svc := New(memory.New(nil), dialFor(nil)).WithAdoption(nil,
		func(string, string, string, string) (NodeConn, error) { return &fakeConn{}, nil })
	sink := &collectSink{}
	err := svc.runAdoption(context.Background(), &fleetv1.AdoptNodeRequest{
		Endpoint: "node:4443", Config: adoptConfig(),
	}, sink.send)
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestAdoptNode_OperatorDenied(t *testing.T) {
	svc := New(memory.New(nil), dialFor(nil)).WithAdoption(nil,
		func(string, string, string, string) (NodeConn, error) { return &fakeConn{}, nil })
	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	// requireAdmin runs before any streaming, so a nil stream is never touched.
	err := svc.AdoptNode(ctx, connect.NewRequest(&fleetv1.AdoptNodeRequest{
		Endpoint: "n:1", PinnedCertSha256: "p", Config: adoptConfig(),
	}), nil)
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

// nodeConfigMirror mirrors the node's config.Config yaml tags exactly (k8s-style
// apiVersion, snake_case body). Decoding marshalConfigYAML output into it under
// KnownFields(true) reproduces the node's strict StartCeremony parse, so a
// camelCase regression (rootKeyAlg, stateKey, adminCertPem, ...) fails here.
type nodeConfigMirror struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Role struct {
		Kind string `yaml:"kind"`
	} `yaml:"role"`
	Network struct {
		Interface   string   `yaml:"interface"`
		Address     string   `yaml:"address"`
		Gateway     string   `yaml:"gateway"`
		Nameservers []string `yaml:"nameservers"`
		Search      []string `yaml:"search"`
	} `yaml:"network"`
	Bootstrap struct {
		AdminCertPem string `yaml:"admin_cert_pem"`
	} `yaml:"bootstrap"`
	PKI struct {
		RootKeyAlg  string `yaml:"root_key_alg"`
		RootSubject struct {
			CommonName string `yaml:"common_name"`
			Province   string `yaml:"province"`
			Locality   string `yaml:"locality"`
		} `yaml:"root_subject"`
		RootValidityYears int `yaml:"root_validity_years"`
	} `yaml:"pki"`
	Install struct {
		Disk string `yaml:"disk"`
	} `yaml:"install"`
	StateKey struct {
		Mode string `yaml:"mode"`
	} `yaml:"state_key"`
}

func TestMarshalConfigYAML_MatchesNodeStrictSchema(t *testing.T) {
	cfg := &cryptosv1.MachineConfig{
		ApiVersion: "cryptos.dev/v1alpha1",
		Kind:       "MachineConfig",
		Metadata:   &cryptosv1.Metadata{Name: "cryptos-lab-a"},
		Role:       &cryptosv1.Role{Kind: "root"},
		Network:    &cryptosv1.Network{Interface: "eth0", Address: "203.0.113.40/24", Gateway: "203.0.113.1"},
		Bootstrap:  &cryptosv1.Bootstrap{AdminCertPem: "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n"},
		Install:    &cryptosv1.Install{Disk: "/dev/nvme0n1"},
		StateKey:   &cryptosv1.StateKey{Mode: "nodeid"},
		Pki: &cryptosv1.Pki{
			RootKeyAlg:        "ECDSA-P384",
			RootSubject:       &cryptosv1.Subject{CommonName: "CryptOS Lab Root CA"},
			RootValidityYears: 10,
		},
	}

	raw, err := marshalConfigYAML(cfg)
	if err != nil {
		t.Fatalf("marshalConfigYAML: %v", err)
	}

	var got nodeConfigMirror
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // mirror the node's strict decode
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("node-strict decode rejected the marshaled config: %v\n---\n%s", err, raw)
	}

	if got.APIVersion != "cryptos.dev/v1alpha1" {
		t.Errorf("apiVersion = %q, want cryptos.dev/v1alpha1", got.APIVersion)
	}
	if got.PKI.RootKeyAlg != "ECDSA-P384" || got.PKI.RootSubject.CommonName != "CryptOS Lab Root CA" || got.PKI.RootValidityYears != 10 {
		t.Errorf("pki round-trip = %+v", got.PKI)
	}
	if got.StateKey.Mode != "nodeid" || got.Bootstrap.AdminCertPem == "" || got.Install.Disk != "/dev/nvme0n1" {
		t.Errorf("state_key/bootstrap/install round-trip failed: %+v %+v %+v", got.StateKey, got.Bootstrap, got.Install)
	}
}

func containsPhase(phases []string, want string) bool {
	for _, p := range phases {
		if p == want {
			return true
		}
	}
	return false
}

// setRebootTiming overrides the bounded reboot timing for a test and returns a
// restore func.
func setRebootTiming(wait, poll, grace time.Duration) func() {
	ow, op, og := rebootWait, rebootPollGap, rebootPollGrace
	rebootWait, rebootPollGap, rebootPollGrace = wait, poll, grace
	return func() { rebootWait, rebootPollGap, rebootPollGrace = ow, op, og }
}
