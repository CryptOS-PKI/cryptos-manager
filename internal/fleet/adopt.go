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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
)

// Adoption phase tokens streamed on AdoptNodeResponse.phase.
const (
	phaseApplyingConfig = "applying-config"
	phaseInstalling     = "installing"
	phaseAwaitingReboot = "awaiting-reboot"
	phaseCeremony       = "ceremony"
	phaseEstablished    = "established"
	phaseError          = "error"
)

// rebootWait bounds how long AdoptNode waits for a node to install, self-reboot,
// and come back in running mode before streaming an error phase. A real
// bare-disk install plus reboot plus first-boot bring-up runs well past a
// minute, so this is generous; the reboot poll never blocks the stream
// indefinitely. It is a var so tests can shrink it.
var (
	rebootWait      = 180 * time.Second
	rebootPollGap   = 3 * time.Second
	rebootPollGrace = 1 * time.Second
)

// phaseSink receives each streamed adoption phase. The Connect handler sends it
// on the wire; tests collect it in a slice. Returning an error aborts the
// orchestration (e.g. the client hung up).
type phaseSink func(phase, detail string, done bool) error

// PreviewAdoption performs the trust-on-first-use preview: it dials the given
// maintenance endpoint (no pin, no client cert), captures the presented cert,
// and returns its SHA-256 fingerprint and subject for the operator to confirm.
// It is admin-gated and a read, so it dials no inventory node and writes no
// audit event.
func (s *Service) PreviewAdoption(ctx context.Context, req *connect.Request[fleetv1.PreviewAdoptionRequest]) (*connect.Response[fleetv1.PreviewAdoptionResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.previewCert == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("fleet: adoption not configured"))
	}
	endpoint := req.Msg.GetEndpoint()
	if endpoint == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: endpoint is required"))
	}

	sha256Hex, subject, err := s.previewCert(endpoint)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("fleet: preview adoption: %w", err))
	}

	return connect.NewResponse(&fleetv1.PreviewAdoptionResponse{
		CertSha256: sha256Hex,
		Subject:    subject,
	}), nil
}

// AdoptNode provisions a not-yet-adopted maintenance node end to end and streams
// progress. It is admin-gated. Pinned to the fingerprint the operator confirmed
// via PreviewAdoption, it dials the maintenance endpoint (TOFU, no client
// secret to an unpinned endpoint), applies the initial config, waits a bounded
// time for the node to reboot back onto the maintenance endpoint, drives the
// first-boot ceremony while relaying its events, and on COMPLETE registers the
// node in the inventory and audits "node-adopted". Every step is a streamed
// phase so partial progress is visible; a reboot that never returns streams an
// error phase rather than hanging.
func (s *Service) AdoptNode(ctx context.Context, req *connect.Request[fleetv1.AdoptNodeRequest], stream *connect.ServerStream[fleetv1.AdoptNodeResponse]) error {
	if err := requireAdmin(ctx); err != nil {
		return err
	}
	sink := func(phase, detail string, done bool) error {
		return stream.Send(&fleetv1.AdoptNodeResponse{Phase: phase, Detail: detail, Done: done})
	}
	return s.runAdoption(ctx, req.Msg, sink)
}

// runAdoption is the transport-independent adoption orchestration, driving the
// phaseSink so the Connect handler and tests share one code path. A step that
// fails streams an error phase (done) and returns a Connect error; it never
// hangs — the reboot wait is bounded.
func (s *Service) runAdoption(ctx context.Context, msg *fleetv1.AdoptNodeRequest, send phaseSink) error {
	if s.dialMaintenance == nil {
		return connect.NewError(connect.CodeUnimplemented, errors.New("fleet: adoption not configured"))
	}
	endpoint := msg.GetEndpoint()
	pin := msg.GetPinnedCertSha256()
	cfg := msg.GetConfig()
	if endpoint == "" || pin == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: endpoint and pinned_cert_sha256 are required"))
	}
	if cfg == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: config is required"))
	}

	// Option A: the manager mints a bootstrap admin identity, embeds its cert in
	// the config so the node trusts it as admin, and keeps the private key to
	// manage the node over mTLS afterward. Without a bootstrap admin the node's
	// config is invalid; with the manager holding the key, managed operations
	// (issue/revoke/rekey/config) can dial the node once it is established.
	nodeName := adoptedNodeName(cfg, endpoint)
	admin, err := mintBootstrapAdmin("fleet-admin@" + nodeName)
	if err != nil {
		return s.adoptFail(send, connect.CodeInternal, err)
	}
	adminCertPath, adminKeyPath, err := writeAdminCreds(nodeName, admin)
	if err != nil {
		return s.adoptFail(send, connect.CodeInternal, err)
	}
	if cfg.Bootstrap == nil {
		cfg.Bootstrap = &cryptosv1.Bootstrap{}
	}
	cfg.Bootstrap.AdminCertPem = string(admin.certPEM)

	// Apply the initial config on the pinned maintenance endpoint.
	if err := send(phaseApplyingConfig, "dialing maintenance endpoint and applying initial config", false); err != nil {
		return err
	}
	adminCert, adminKey := string(admin.certPEM), string(admin.keyPEM)
	conn, err := s.dialMaintenance(endpoint, pin, adminCert, adminKey)
	if err != nil {
		return s.adoptFail(send, connect.CodeUnavailable, fmt.Errorf("fleet: dial maintenance: %w", err))
	}
	_, err = conn.ApplyConfig(ctx, cfg)
	if err != nil {
		_ = conn.Close()
		return s.adoptFail(send, connect.CodeInternal, fmt.Errorf("fleet: apply config: %w", err))
	}
	_ = conn.Close()

	if err := send(phaseInstalling, "config applied, node installing", false); err != nil {
		return err
	}

	// The node installs to disk, self-reboots, and boots the installed system
	// into RUNNING mode — serving mTLS with the bootstrap admin trust (a fresh
	// identity cert, NOT the maintenance cert), awaiting the first-boot ceremony.
	// Wait for it there, dialing with the admin cert the node now trusts (a
	// managed dial, no maintenance pin — the running server cert differs).
	if err := send(phaseAwaitingReboot, "node installing and rebooting into the installed system", false); err != nil {
		return err
	}
	conn, err = s.awaitRunningNode(ctx, nodeName, endpoint, adminCertPath, adminKeyPath)
	if err != nil {
		return s.adoptFail(send, connect.CodeDeadlineExceeded, err)
	}
	defer func() { _ = conn.Close() }()

	// Drive the first-boot ceremony, relaying each event as a ceremony phase.
	if err := send(phaseCeremony, "starting first-boot ceremony", false); err != nil {
		return err
	}
	yaml, err := marshalConfigYAML(cfg)
	if err != nil {
		return s.adoptFail(send, connect.CodeInternal, fmt.Errorf("fleet: marshal config: %w", err))
	}
	cstream, err := conn.StartCeremony(ctx, cryptosv1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT, yaml)
	if err != nil {
		return s.adoptFail(send, connect.CodeInternal, fmt.Errorf("fleet: start ceremony: %w", err))
	}
	complete, err := relayCeremony(cstream, send)
	if err != nil {
		return s.adoptFail(send, connect.CodeInternal, err)
	}
	if !complete {
		return s.adoptFail(send, connect.CodeInternal, errors.New("fleet: ceremony stream ended before completing"))
	}

	// Register the node with the manager-held bootstrap admin credentials so
	// managed operations can dial its mTLS endpoint immediately (Option A: the
	// manager minted and kept this node's admin key).
	s.registerAdoptedNode(cfg, endpoint, adminCertPath, adminKeyPath)

	s.store.AddAuditEvent(store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-adopted",
		Summary:    fmt.Sprintf("Adopted node %s at %s", adoptedNodeName(cfg, endpoint), endpoint),
		TargetKind: "node",
		TargetPath: "/nodes/" + adoptedNodeName(cfg, endpoint),
	})

	return send(phaseEstablished, "node adopted and established", true)
}

// awaitRunningNode waits for the node to finish installing, self-reboot, and
// come back in RUNNING mode: serving mTLS with the bootstrap admin trust,
// awaiting the first-boot ceremony. It dials with a managed admin-cert dial
// (no maintenance pin — the running server cert differs from the maintenance
// one) and confirms a cheap RPC before returning, bounded by rebootWait so a
// node that never returns streams an error rather than hanging. A grace period
// lets the node begin rebooting before the first poll.
func (s *Service) awaitRunningNode(ctx context.Context, name, endpoint, adminCertPath, adminKeyPath string) (NodeConn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(rebootPollGrace):
	}

	node := store.Node{Name: name, Endpoint: endpoint, AdminCert: adminCertPath, AdminKey: adminKeyPath}
	deadline := time.Now().Add(rebootWait)
	for {
		conn, err := s.dial(node)
		if err == nil {
			// A lazy gRPC client dial can succeed before the server is up;
			// confirm the node answers a cheap RPC before proceeding.
			if _, serr := conn.GetStatus(ctx); serr == nil {
				return conn, nil
			}
			_ = conn.Close()
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("fleet: node did not come back in running mode on %s within %s of install", endpoint, rebootWait)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(rebootPollGap):
		}
	}
}

// adoptFail streams a terminal error phase and returns the Connect error, so a
// failed adoption always leaves a visible last phase instead of a bare aborted
// stream.
func (s *Service) adoptFail(send phaseSink, code connect.Code, cause error) error {
	_ = send(phaseError, cause.Error(), true)
	return connect.NewError(code, cause)
}

// relayCeremony forwards every ceremony event as a ceremony phase and reports
// whether the stream reached COMPLETE. io.EOF ends the stream cleanly.
func relayCeremony(stream interface {
	Recv() (*cryptosv1.StartCeremonyResponse, error)
}, send phaseSink) (complete bool, err error) {
	for {
		msg, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			return complete, nil
		}
		if rerr != nil {
			return complete, fmt.Errorf("fleet: ceremony stream: %w", rerr)
		}
		ev := msg.GetEvent()
		if ev.GetKind() == cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE {
			complete = true
		}
		if serr := send(phaseCeremony, ceremonyEventDetail(ev.GetKind()), false); serr != nil {
			return complete, serr
		}
	}
}

// ceremonyEventDetail renders a ceremony event kind as an operator-facing
// detail string.
func ceremonyEventDetail(kind cryptosv1.CeremonyEventKind) string {
	switch kind {
	case cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_KEY_CREATED:
		return "key created"
	case cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_CERT_SIGNED:
		return "certificate signed"
	case cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_MANIFEST_WRITTEN:
		return "ceremony manifest written"
	case cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_ADMIN_ROTATED:
		return "admin credential rotated"
	case cryptosv1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE:
		return "ceremony complete"
	default:
		return "ceremony in progress"
	}
}

// registerAdoptedNode adds the adopted node to the inventory if it is not
// already present, keyed by the config's metadata name (falling back to the
// endpoint). It carries the endpoint and role; managed mTLS material is
// attached later via the LINK enrollment path.
func (s *Service) registerAdoptedNode(cfg *cryptosv1.MachineConfig, endpoint, adminCertPath, adminKeyPath string) {
	name := adoptedNodeName(cfg, endpoint)
	if _, ok := s.store.Node(name); ok {
		return
	}
	s.store.AddNode(store.Node{
		Name:      name,
		Endpoint:  endpoint,
		Role:      adoptedNodeRole(cfg),
		AdminCert: adminCertPath,
		AdminKey:  adminKeyPath,
	})
}

// adoptedNodeName derives the inventory name for an adopted node from its
// config's metadata name, falling back to the endpoint when the config omits
// it.
func adoptedNodeName(cfg *cryptosv1.MachineConfig, endpoint string) string {
	if n := cfg.GetMetadata().GetName(); n != "" {
		return n
	}
	return endpoint
}

// adoptedNodeRole derives a display role from the config's role kind, defaulting
// to "node" when the config omits it.
func adoptedNodeRole(cfg *cryptosv1.MachineConfig) string {
	if r := cfg.GetRole().GetKind(); r != "" {
		return r
	}
	return "node"
}

// marshalConfigYAML renders a MachineConfig for the node's StartCeremony, which
// parses the bytes with a strict (KnownFields) YAML decoder. JSON is valid
// YAML, so protojson output parses server-side — but the node's config keys are
// snake_case (state_key, root_key_alg, root_subject, admin_cert_pem, ...), and
// protojson's default camelCase is rejected as unknown fields. UseProtoNames
// emits the proto's snake_case names, which match the node's yaml tags for every
// field except the k8s-style apiVersion, whose proto name is api_version; we
// rename that single top-level key so the whole document matches the node schema.
func marshalConfigYAML(cfg *cryptosv1.MachineConfig) ([]byte, error) {
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("marshal config yaml: %w", err)
	}
	if v, ok := m["api_version"]; ok {
		delete(m, "api_version")
		m["apiVersion"] = v
	}
	return json.Marshal(m)
}
