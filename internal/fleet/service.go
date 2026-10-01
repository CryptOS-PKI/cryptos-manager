// Package fleet implements the manager's cryptos.fleet.v1.FleetService
// Connect handler: it fans out to each fleet node over nodeclient and
// reports per-node health without failing the whole request when one node
// is unreachable.
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
	"crypto/x509"

	log "github.com/Bugs5382/go-log"
	fleetv1connect "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/cryptos-manager/internal/approval"
	"github.com/CryptOS-PKI/cryptos-manager/internal/mcpauth"
	"github.com/CryptOS-PKI/cryptos-manager/internal/nodeclient"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// NodeConn is the manager's-eye view of a per-node connection: just enough
// to serve FleetService. nodeclient.Client satisfies it; tests inject a
// fake instead of dialing a real node.
type NodeConn interface {
	GetStatus(ctx context.Context) (*nodev1.GetStatusResponse, error)
	ListInstallDisks(ctx context.Context) (*nodev1.ListInstallDisksResponse, error)
	GetIdentity(ctx context.Context) (*nodev1.GetIdentityResponse, error)
	ListIssued(ctx context.Context) (*nodev1.ListIssuedResponse, error)
	GetIssuedCertificate(ctx context.Context, serialHex string) (*nodev1.GetIssuedCertificateResponse, error)
	ListRevocations(ctx context.Context) (*nodev1.ListRevocationsResponse, error)
	Attest(ctx context.Context, nonce []byte) (*nodev1.AttestResponse, error)
	GetSubordinateCSR(ctx context.Context) (*nodev1.GetSubordinateCSRResponse, error)
	SignSubordinateCSR(ctx context.Context, csrDER []byte, profile string) (*nodev1.SignSubordinateCSRResponse, error)
	SubmitSubordinateCertificate(ctx context.Context, chainDER [][]byte, chainPEM string) (*nodev1.SubmitSubordinateCertificateResponse, error)
	ApplyConfig(ctx context.Context, cfg *nodev1.MachineConfig) (*nodev1.ApplyConfigResponse, error)
	GetConfig(ctx context.Context) (*nodev1.GetConfigResponse, error)
	SetManagement(ctx context.Context, m *nodev1.Management) (*nodev1.SetManagementResponse, error)
	RevokeCertificate(ctx context.Context, serialHex string, reasonCode int32) (*nodev1.RevokeCertificateResponse, error)
	IssueLeaf(ctx context.Context, csrDER []byte, profileName string) (*nodev1.IssueLeafResponse, error)
	BeginKeyRotation(ctx context.Context) (*nodev1.BeginKeyRotationResponse, error)
	CompleteKeyRotation(ctx context.Context, chainDER [][]byte, chainPEM string) (*nodev1.CompleteKeyRotationResponse, error)
	ExportCAKey(ctx context.Context, passphrase []byte) (*nodev1.ExportCAKeyResponse, error)
	ImportCAKey(ctx context.Context, envelope, passphrase []byte) (*nodev1.ImportCAKeyResponse, error)
	RemoteReset(ctx context.Context, confirmCN string) (*nodev1.RemoteResetResponse, error)
	StartCeremony(ctx context.Context, kind nodev1.CeremonyKind, machineConfigYAML []byte) (nodeclient.CeremonyStream, error)
	Close() error
}

// Service implements fleetv1connect.FleetServiceHandler over a fleet
// inventory Store, dialing each node on demand via dial.
type Service struct {
	store store.Store
	dial  func(store.Node) (NodeConn, error)

	dialPEM func(endpoint, certPEM, keyPEM, caPEM string) (NodeConn, error)

	// trust and revocations are the operator CA trust and revocation state;
	// the operator credential handlers read and deny through them.
	trust       *operatorca.TrustStore
	revocations *operatorca.Revocations

	// caAdmin backs the operator CA admin RPCs.
	caAdmin OperatorCAAdmin

	// previewCert fetches a not-yet-adopted node's maintenance cert
	// fingerprint + subject (TOFU preview). dialMaintenance opens a
	// TOFU-pinned maintenance connection. Both are seams so tests inject fakes
	// instead of reaching a real node; production wires nodeclient.
	previewCert     func(endpoint string) (certSHA256, subject string, err error)
	dialMaintenance func(endpoint, pinnedSHA256, clientCertPEM, clientKeyPEM string) (NodeConn, error)

	// captureServerCert reads the certificate an installed node presents, so
	// adoption can pin it before dialing the node. unverified names the nodes
	// dialed with insecureSkipNodeVerify.
	captureServerCert func(store.Node) (*x509.Certificate, error)
	unverified        func(store.Node) bool

	// mcpKeys backs the MCP key management RPCs. mcpEnabled gates minting:
	// listing and revoking keep working with the endpoint switched off, so an
	// operator can still clean up.
	mcpKeys    *mcpauth.Keys
	mcpEnabled bool

	// approvals backs the step-up approval RPCs the web UI decides with.
	approvals *approval.Service

	// reboots records protocol switches a node accepted with requires_reboot
	// until the node reports them running.
	reboots *rebootTracker

	// adoptions holds the adoptions waiting for the operator to confirm the
	// installed node's fingerprint.
	adoptions adoptionWaits

	// nodeCAWatch sees every CA chain a node reports.
	nodeCAWatch *operatorca.NodeCAWatch

	log log.Logger
}

// New builds a Service backed by st, dialing nodes with dial. Callers in
// production pass an adapter over nodeclient.Dial; tests pass a fake.
func New(st store.Store, dial func(store.Node) (NodeConn, error)) *Service {
	return &Service{store: st, dial: dial, reboots: newRebootTracker(), log: log.NewLogger("fleet-manager")}
}

// WithEnrollment supplies the PEM dial seam for LINK, which reaches a
// not-yet-inventoried node. Returns s for chaining.
func (s *Service) WithEnrollment(dialPEM func(endpoint, certPEM, keyPEM, caPEM string) (NodeConn, error)) *Service {
	s.dialPEM = dialPEM

	return s
}

// WithOperatorTrust supplies the operator CA trust and revocation state the
// operator credential handlers use. Returns s for chaining.
func (s *Service) WithOperatorTrust(trust *operatorca.TrustStore, rev *operatorca.Revocations) *Service {
	s.trust = trust
	s.revocations = rev

	return s
}

// WithNodeCAWatch supplies the watch that flags a trusted operator CA a
// node's reported chain shows to be that node's CA. Returns s for chaining.
func (s *Service) WithNodeCAWatch(w *operatorca.NodeCAWatch) *Service {
	s.nodeCAWatch = w

	return s
}

// WithAdoption supplies the S10 adoption seams: previewCert fetches a
// maintenance node's TOFU fingerprint, and dialMaintenance opens a pinned
// maintenance connection. Returns s for chaining.
func (s *Service) WithAdoption(previewCert func(endpoint string) (certSHA256, subject string, err error), dialMaintenance func(endpoint, pinnedSHA256, clientCertPEM, clientKeyPEM string) (NodeConn, error)) *Service {
	s.previewCert = previewCert
	s.dialMaintenance = dialMaintenance

	return s
}

// WithMCP supplies the MCP key store and whether the MCP endpoint is enabled.
// Returns s for chaining.
func (s *Service) WithMCP(keys *mcpauth.Keys, enabled bool) *Service {
	s.mcpKeys = keys
	s.mcpEnabled = enabled

	return s
}

// WithApprovals supplies the step-up approval service. Returns s for
// chaining.
func (s *Service) WithApprovals(a *approval.Service) *Service {
	s.approvals = a

	return s
}

var _ fleetv1connect.FleetServiceHandler = (*Service)(nil)
