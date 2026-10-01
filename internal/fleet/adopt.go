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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/nodeclient"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// Adoption phase tokens streamed on AdoptNodeResponse.phase.
const (
	phaseApplyingConfig = "applying-config"
	phaseInstalling     = "installing"
	phaseAwaitingReboot = "awaiting-reboot"
	phaseCeremony       = "ceremony"
	phaseEstablished    = "established"
	// phaseAwaitingCertificate is the terminal phase for a subordinate
	// (intermediate/issuing) adoption: the node is provisioned and awaiting a
	// parent-signed certificate, delivered separately by a SUBORDINATE enrollment.
	phaseAwaitingCertificate = "awaiting-certificate"
	phaseError               = "error"
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

// ListInstallDisks returns the candidate install disks a maintenance node
// reports, so the adopt wizard offers real devices instead of a free-text
// guess. Pinned to the fingerprint confirmed via PreviewAdoption; maintenance
// mode is client-auth off, so no client cert is presented. Admin-gated read.
func (s *Service) ListInstallDisks(ctx context.Context, req *connect.Request[fleetv1.ListInstallDisksRequest]) (*connect.Response[fleetv1.ListInstallDisksResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.dialMaintenance == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("fleet: adoption not configured"))
	}
	endpoint := req.Msg.GetEndpoint()
	pin := req.Msg.GetPinnedCertSha256()
	if endpoint == "" || pin == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: endpoint and pinned_cert_sha256 are required"))
	}
	conn, err := s.dialMaintenance(endpoint, pin, "", "")
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("fleet: dial maintenance: %w", err))
	}
	defer func() { _ = conn.Close() }()
	resp, err := conn.ListInstallDisks(ctx)
	if err != nil {
		return nil, nodeError("list install disks", err)
	}
	return connect.NewResponse(&fleetv1.ListInstallDisksResponse{Disks: resp.GetDisks()}), nil
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
//
// Adoption is safe to retry. A retry for the same node name reuses the
// bootstrap admin the earlier attempt stored, and when the node reports that it
// already booted its installed system it skips the install, runs the ceremony
// only if the root has not completed it, and registers the node. For a root,
// the ceremony writes the requested config over the staged one; a subordinate
// keeps the config it was installed with.
func (s *Service) AdoptNode(ctx context.Context, req *connect.Request[fleetv1.AdoptNodeRequest], stream *connect.ServerStream[fleetv1.AdoptNodeResponse]) error {
	if err := requireAdmin(ctx); err != nil {
		return err
	}
	id := newAdoptionID()
	return s.runAdoptionAs(ctx, id, req.Msg, s.adoptSink(id, req.Msg, stream.Send))
}

// adoptResponse builds one streamed adoption message. The final message of a
// successful adoption carries the ID of the node it registered.
func (s *Service) adoptResponse(msg *fleetv1.AdoptNodeRequest, phase, detail string, done bool) *fleetv1.AdoptNodeResponse {
	resp := &fleetv1.AdoptNodeResponse{Phase: phase, Detail: detail, Done: done}
	if done && phase != phaseError {
		if n, ok := s.store.Node(adoptedNodeName(msg.GetConfig(), msg.GetEndpoint())); ok {
			resp.NodeId = n.ID
		}
	}
	return resp
}

// runAdoption runs an adoption under a new adoption ID.
func (s *Service) runAdoption(ctx context.Context, msg *fleetv1.AdoptNodeRequest, send phaseSink) error {
	return s.runAdoptionAs(ctx, newAdoptionID(), msg, send)
}

// runAdoptionAs is the transport-independent adoption orchestration, driving
// the phaseSink so the Connect handler and tests share one code path. id names
// the adoption for ConfirmAdoptionFingerprint. A step that fails streams an
// error phase (done) and returns a Connect error; it never hangs — the reboot
// and confirmation waits are bounded.
func (s *Service) runAdoptionAs(ctx context.Context, id string, msg *fleetv1.AdoptNodeRequest, send phaseSink) error {
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
	// (issue/revoke/rekey/config) can dial the node once it is established. A
	// retry reuses the admin an earlier attempt stored, which is the one an
	// installed node's staged config pins.
	nodeName := adoptedNodeName(cfg, endpoint)
	admin, adminCertPath, adminKeyPath, reused, err := loadOrMintAdmin(nodeName)
	if err != nil {
		return s.adoptFail(send, connect.CodeInternal, err)
	}
	if cfg.Bootstrap == nil {
		cfg.Bootstrap = &nodev1.Bootstrap{}
	}
	cfg.Bootstrap.AdminCertPem = string(admin.certPEM)
	log.Printf("fleet: adopt %s at %s: start (reused admin: %t)", nodeName, endpoint, reused)

	if err := send(phaseApplyingConfig, "dialing the node and checking whether it is already installed", false); err != nil {
		return err
	}
	adminCert, adminKey := string(admin.certPEM), string(admin.keyPEM)
	conn, err := s.dialMaintenance(endpoint, pin, adminCert, adminKey)
	if err != nil {
		return s.adoptFail(send, connect.CodeUnavailable, fmt.Errorf("fleet: dial maintenance: %w", err))
	}
	// Maintenance mode leaves identity_state unset; an installed system always
	// reports one. That is how a retry after a partial apply tells a node that
	// still needs installing from one that already booted its staged config.
	status, err := conn.GetStatus(ctx)
	if err != nil {
		_ = conn.Close()
		log.Printf("fleet: adopt %s: status probe failed: %v", nodeName, err)
		return s.adoptFail(send, connect.CodeUnavailable, fmt.Errorf(
			"fleet: node status: %w (an installed node only accepts the admin credential minted by the adoption that installed it; if this manager no longer holds it, reset the node from its console and adopt again)", err))
	}
	identity := status.GetStatus().GetIdentityState()
	installed := identity != nodev1.IdentityState_IDENTITY_STATE_UNSPECIFIED
	log.Printf("fleet: adopt %s: node identity state %s, installed: %t", nodeName, identity, installed)

	if installed {
		_ = conn.Close()
		if err := send(phaseAwaitingReboot, "node already installed by an earlier adoption attempt; resuming", false); err != nil {
			return err
		}
	} else {
		if _, err := conn.ApplyConfig(ctx, cfg); err != nil {
			_ = conn.Close()
			return s.adoptFail(send, connect.CodeInternal, fmt.Errorf("fleet: apply config: %w", err))
		}
		_ = conn.Close()
		log.Printf("fleet: adopt %s: config applied, node installing", nodeName)

		if err := send(phaseInstalling, "config applied, node installing", false); err != nil {
			return err
		}
		// The node installs to disk, self-reboots, and boots the installed
		// system into RUNNING mode, serving mTLS with the bootstrap admin trust
		// (a fresh identity cert, NOT the maintenance cert) and awaiting the
		// first-boot ceremony.
		if err := send(phaseAwaitingReboot, "node installing and rebooting into the installed system", false); err != nil {
			return err
		}
	}

	// Wait for the running node. The certificate it comes back with has no
	// link to the maintenance certificate the operator confirmed, so the
	// adoption pauses until the operator confirms it from the node's console;
	// only then is it pinned and the node dialed with the admin cert it trusts
	// (a managed dial, verified against the pin).
	node := store.Node{Name: nodeName, Endpoint: endpoint, AdminCert: adminCertPath, AdminKey: adminKeyPath}
	running, err := s.awaitRunningCert(ctx, node)
	if err != nil {
		return s.adoptFail(send, connect.CodeDeadlineExceeded, err)
	}
	if running != nil {
		sum := sha256.Sum256(running.Raw)
		presented := hex.EncodeToString(sum[:])
		if err := s.awaitFingerprintConfirm(ctx, id, nodeName, endpoint, presented, send); err != nil {
			return s.adoptFailErr(send, err)
		}
		path, err := nodeclient.WritePin(node, running)
		if err != nil {
			return s.adoptFail(send, connect.CodeInternal, err)
		}
		log.Printf("fleet: adopt %s: pinned the confirmed management certificate sha256 %s at %s", nodeName, presented, path)
	}
	conn, err = s.awaitRunningNode(ctx, node)
	if err != nil {
		return s.adoptFail(send, connect.CodeDeadlineExceeded, err)
	}
	defer func() { _ = conn.Close() }()

	// A root self-signs its CA via the first-boot ceremony. A subordinate
	// (intermediate/issuing) node cannot: the node has already staged its own
	// subordinate CSR on boot and is awaiting a parent-signed chain, which a
	// SUBORDINATE enrollment delivers as a separate admin-approved step. Only a
	// root reaches "established" during adoption.
	switch {
	case isRootRole(cfg) && identity == nodev1.IdentityState_IDENTITY_STATE_ESTABLISHED:
		log.Printf("fleet: adopt %s: ceremony already completed on an earlier attempt, skipping it", nodeName)
	case isRootRole(cfg):
		if err := send(phaseCeremony, "starting first-boot ceremony", false); err != nil {
			return err
		}
		yaml, err := marshalConfigYAML(cfg)
		if err != nil {
			return s.adoptFail(send, connect.CodeInternal, fmt.Errorf("fleet: marshal config: %w", err))
		}
		cstream, err := conn.StartCeremony(ctx, nodev1.CeremonyKind_CEREMONY_KIND_FIRST_BOOT_ROOT, yaml)
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
		log.Printf("fleet: adopt %s: ceremony complete", nodeName)
	}

	// A root has its CA now. Record the chain so the manager verifies the node
	// against it once the node presents a CA-signed management certificate,
	// which no longer matches the pin. A failure here fails the adoption: a
	// retry skips the finished ceremony and records the chain again.
	caCertPath := ""
	if isRootRole(cfg) {
		idResp, err := conn.GetIdentity(ctx)
		if err != nil {
			return s.adoptFail(send, connect.CodeUnavailable, fmt.Errorf("fleet: read the node's CA chain: %w", err))
		}
		recorded, _, err := recordCAChain(store.Node{Name: nodeName, AdminCert: adminCertPath}, idResp.GetIdentity().GetChainDer())
		if err != nil {
			return s.adoptFail(send, connect.CodeInternal, err)
		}
		caCertPath = recorded.CACert
	}

	// Register the node with the manager-held bootstrap admin credentials so
	// managed operations can dial its mTLS endpoint immediately (Option A: the
	// manager minted and kept this node's admin key).
	adopted := s.registerAdoptedNode(cfg, endpoint, adminCertPath, adminKeyPath, caCertPath)
	log.Printf("fleet: adopt %s: registered in the inventory as node %s", nodeName, adopted.ID)

	summary := fmt.Sprintf("Adopted node %s at %s", nodeName, endpoint)
	if installed {
		summary += " (resumed an earlier partial adoption)"
	}
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-adopted",
		Summary:    summary,
		TargetKind: "node",
		TargetPath: nodeTarget(adopted),
	})

	if !isRootRole(cfg) {
		return send(phaseAwaitingCertificate,
			"subordinate node provisioned and awaiting a parent-signed certificate (complete via a subordinate enrollment)", true)
	}
	return send(phaseEstablished, "node adopted and established", true)
}

// awaitRunningCert waits for the node to finish installing, self-reboot and
// come back in RUNNING mode, and returns the certificate it presents there.
// Nothing is pinned: the caller has the operator confirm it first. Without a
// capture seam it returns nil and the caller dials as before. Bounded by
// rebootWait after a grace period that lets the node begin rebooting.
func (s *Service) awaitRunningCert(ctx context.Context, node store.Node) (*x509.Certificate, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(rebootPollGrace):
	}
	if s.captureServerCert == nil {
		return nil, nil
	}
	deadline := time.Now().Add(rebootWait)
	for {
		cert, err := s.captureServerCert(node)
		if err == nil {
			return cert, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("fleet: node did not come back in running mode on %s within %s of install: %w", node.Endpoint, rebootWait, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(rebootPollGap):
		}
	}
}

// awaitRunningNode dials the running node with a managed admin-cert dial
// (verified against the confirmed pin) and confirms a cheap RPC before
// returning, bounded by rebootWait so a node that never answers streams an
// error rather than hanging.
func (s *Service) awaitRunningNode(ctx context.Context, node store.Node) (NodeConn, error) {
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
			return nil, fmt.Errorf("fleet: node did not come back in running mode on %s within %s of install", node.Endpoint, rebootWait)
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

// adoptFailErr is adoptFail for an error that already carries its Connect
// code.
func (s *Service) adoptFailErr(send phaseSink, err error) error {
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		_ = send(phaseError, cerr.Message(), true)
		return err
	}
	return s.adoptFail(send, connect.CodeInternal, err)
}

// relayCeremony forwards every ceremony event as a ceremony phase and reports
// whether the stream reached COMPLETE. io.EOF ends the stream cleanly.
func relayCeremony(stream interface {
	Recv() (*nodev1.StartCeremonyResponse, error)
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
		if ev.GetKind() == nodev1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE {
			complete = true
		}
		if serr := send(phaseCeremony, ceremonyEventDetail(ev.GetKind()), false); serr != nil {
			return complete, serr
		}
	}
}

// ceremonyEventDetail renders a ceremony event kind as an operator-facing
// detail string.
func ceremonyEventDetail(kind nodev1.CeremonyEventKind) string {
	switch kind {
	case nodev1.CeremonyEventKind_CEREMONY_EVENT_KIND_KEY_CREATED:
		return "key created"
	case nodev1.CeremonyEventKind_CEREMONY_EVENT_KIND_CERT_SIGNED:
		return "certificate signed"
	case nodev1.CeremonyEventKind_CEREMONY_EVENT_KIND_MANIFEST_WRITTEN:
		return "ceremony manifest written"
	case nodev1.CeremonyEventKind_CEREMONY_EVENT_KIND_ADMIN_ROTATED:
		return "admin credential rotated"
	case nodev1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE:
		return "ceremony complete"
	default:
		return "ceremony in progress"
	}
}

// registerAdoptedNode adds the adopted node to the inventory under a new ID
// if it is not already present, keyed by the config's metadata name (falling
// back to the endpoint), and returns the inventory node. It carries the
// endpoint, role, admin credentials and, for a root, the recorded CA chain. A
// retried adoption finds the node already registered and keeps its ID, taking
// a newly recorded CA chain.
func (s *Service) registerAdoptedNode(cfg *nodev1.MachineConfig, endpoint, adminCertPath, adminKeyPath, caCertPath string) store.Node {
	name := adoptedNodeName(cfg, endpoint)
	if n, ok := s.store.Node(name); ok {
		log.Printf("fleet: adopt %s: already in the inventory as node %s", name, n.ID)
		if caCertPath != "" && n.CACert != caCertPath {
			n.CACert = caCertPath
			s.store.AddNode(n)
			n, _ = s.store.Node(name)
		}
		return n
	}
	id := store.NewNodeID()
	log.Printf("fleet: adopt %s: assigning node id %s", name, id)
	s.store.AddNode(store.Node{
		ID:        id,
		Name:      name,
		Endpoint:  endpoint,
		Role:      adoptedNodeRole(cfg),
		AdminCert: adminCertPath,
		AdminKey:  adminKeyPath,
		CACert:    caCertPath,
	})
	n, _ := s.store.Node(name)
	return n
}

// adoptedNodeName derives the inventory name for an adopted node from its
// config's metadata name, falling back to the endpoint when the config omits
// it.
func adoptedNodeName(cfg *nodev1.MachineConfig, endpoint string) string {
	if n := cfg.GetMetadata().GetName(); n != "" {
		return n
	}
	return endpoint
}

// adoptedNodeRole derives a display role from the config's role kind, defaulting
// to "node" when the config omits it.
func adoptedNodeRole(cfg *nodev1.MachineConfig) string {
	if r := cfg.GetRole().GetKind(); r != "" {
		return r
	}
	return "node"
}

// isRootRole reports whether the config declares a root CA node — the only role
// that self-signs via the first-boot ceremony. Intermediate and issuing nodes
// are subordinates, established later by a parent-signed enrollment. An omitted
// role is treated as root, matching the adopt wizard's default.
func isRootRole(cfg *nodev1.MachineConfig) bool {
	kind := cfg.GetRole().GetKind()
	return kind == "" || strings.EqualFold(kind, "root")
}

// marshalConfigYAML renders a MachineConfig for the node's StartCeremony, which
// parses the bytes with a strict (KnownFields) YAML decoder. JSON is valid
// YAML, so protojson output parses server-side — but the node's config keys are
// snake_case (state_key, root_key_alg, root_subject, admin_cert_pem, ...), and
// protojson's default camelCase is rejected as unknown fields. UseProtoNames
// emits the proto's snake_case names, which match the node's yaml tags for every
// field except the k8s-style apiVersion, whose proto name is api_version; we
// rename that single top-level key so the whole document matches the node schema.
func marshalConfigYAML(cfg *nodev1.MachineConfig) ([]byte, error) {
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
