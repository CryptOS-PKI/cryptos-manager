// Package nodeclient dials a fleet node's mTLS gRPC endpoint and wraps the
// generated NodeService client with the manager's admin-cert-only trust
// model.
package nodeclient

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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client is a per-node mTLS gRPC connection to a fleet node's NodeService.
type Client struct {
	conn *grpc.ClientConn
	node cryptosv1.NodeServiceClient
}

// Dial opens a gRPC connection to node's endpoint, presenting node's admin
// client certificate for mTLS.
//
// The node's server certificate is ephemeral and self-signed per boot, so it
// cannot be verified against a pinned CA or hostname/SAN. Dial therefore
// relaxes server verification (InsecureSkipVerify) while still presenting
// the admin client certificate, which is the credential the node actually
// enforces via client authentication. Server-identity pinning is future
// hardening, not this dev slice.
func Dial(node store.Node) (*Client, error) {
	adminCert, err := tls.LoadX509KeyPair(node.AdminCert, node.AdminKey)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: load admin cert/key for %s: %w", node.Name, err)
	}

	tlsCfg := &tls.Config{
		// GetClientCertificate (not Certificates) presents the admin cert
		// unconditionally, even when the node advertises acceptable-CA hints its
		// issuer does not match; Go's default selection would otherwise send no
		// cert and the node answers "tls: certificate required".
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &adminCert, nil
		},
		InsecureSkipVerify: true, //nolint:gosec // node's server cert is ephemeral self-signed; client-cert auth is the trust boundary here.
	}

	conn, err := grpc.NewClient(node.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("nodeclient: dial %s (%s): %w", node.Name, node.Endpoint, err)
	}

	return &Client{
		conn: conn,
		node: cryptosv1.NewNodeServiceClient(conn),
	}, nil
}

// DialPEM dials a node presenting the given admin client cert/key (PEM), for
// operator-initiated enrollment where the material is supplied at request
// time rather than from the node inventory. Server verification is relaxed
// (the node enforces client-auth); caPEM is accepted for future server
// pinning.
func DialPEM(endpoint, certPEM, keyPEM, caPEM string) (*Client, error) {
	adminCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("nodeclient: parse admin cert/key PEM: %w", err)
	}

	_ = caPEM // reserved for future server-cert pinning (Dial also relaxes server verify today)

	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{adminCert},
		InsecureSkipVerify: true, //nolint:gosec // node's server cert is ephemeral self-signed; client-cert auth is the trust boundary here.
	}

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("nodeclient: dial %s: %w", endpoint, err)
	}

	return &Client{
		conn: conn,
		node: cryptosv1.NewNodeServiceClient(conn),
	}, nil
}

// FetchMaintenanceCert performs a bare TLS handshake against a not-yet-adopted
// node's maintenance endpoint and returns the presented leaf certificate's
// SHA-256 (lowercase hex) and subject. It is the trust-on-first-use preview:
// server verification is skipped because the operator will confirm the
// fingerprint out of band; nothing is sent to the endpoint beyond the
// handshake, and no client cert is presented.
func FetchMaintenanceCert(endpoint string) (certSHA256, subject string, err error) {
	conn, err := tls.Dial("tcp", endpoint, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // TOFU preview: the operator confirms the returned fingerprint out of band.
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return "", "", fmt.Errorf("nodeclient: preview dial %s: %w", endpoint, err)
	}
	defer func() { _ = conn.Close() }()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", "", fmt.Errorf("nodeclient: preview %s presented no certificate", endpoint)
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:]), certs[0].Subject.String(), nil
}

// DialMaintenance opens a gRPC connection to a not-yet-adopted node's
// maintenance endpoint, trust-on-first-use pinned to pinnedSHA256. The
// maintenance surface is unauthenticated (no client cert) and serves an
// ephemeral self-signed cert, so this relaxes the CA/hostname check
// (InsecureSkipVerify) but installs a VerifyConnection callback that fails the
// handshake unless the presented leaf certificate's SHA-256 equals the
// operator-confirmed pin. That is the whole trust boundary for adoption: no
// admin or client secret is ever presented to an unpinned endpoint.
func DialMaintenance(endpoint, pinnedSHA256, clientCertPEM, clientKeyPEM string) (*Client, error) {
	pin := normalizeFingerprint(pinnedSHA256)
	if pin == "" {
		return nil, fmt.Errorf("nodeclient: maintenance dial requires a non-empty pinned SHA-256")
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // TOFU: the VerifyConnection callback below pins the exact leaf cert by SHA-256.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("nodeclient: maintenance endpoint presented no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(got[:]) != pin {
				return fmt.Errorf("nodeclient: maintenance cert fingerprint does not match the pinned value")
			}
			return nil
		},
		MinVersion: tls.VersionTLS12,
	}
	// The maintenance server requires a client certificate (mirrors cryptosctl,
	// which always presents its bootstrap admin identity). We present the admin
	// cert the manager minted for this node; the node accepts it and the applied
	// config's bootstrap.admin_cert_pem then pins it.
	if clientCertPEM != "" {
		cert, err := tls.X509KeyPair([]byte(clientCertPEM), []byte(clientKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("nodeclient: maintenance client cert: %w", err)
		}
		// GetClientCertificate (not Certificates) so we ALWAYS present this cert,
		// even when the maintenance server advertises acceptable-CA hints that our
		// self-signed admin cert does not chain to. Go's default cert selection
		// filters by those hints and would send no cert (openssl always sends).
		tlsCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		}
	}

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("nodeclient: dial maintenance %s: %w", endpoint, err)
	}

	return &Client{
		conn: conn,
		node: cryptosv1.NewNodeServiceClient(conn),
	}, nil
}

// normalizeFingerprint folds a SHA-256 hex fingerprint to a comparable form:
// lowercase with any colon separators and surrounding whitespace stripped.
func normalizeFingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.ReplaceAll(s, ":", "")
}

// GetStatus returns the node's current status.
func (c *Client) GetStatus(ctx context.Context) (*cryptosv1.GetStatusResponse, error) {
	return c.node.GetStatus(ctx, &cryptosv1.GetStatusRequest{})
}

// GetIdentity returns the node's current certificate identity.
func (c *Client) GetIdentity(ctx context.Context) (*cryptosv1.GetIdentityResponse, error) {
	return c.node.GetIdentity(ctx, &cryptosv1.GetIdentityRequest{})
}

// ListIssued returns the certificates this node has issued.
func (c *Client) ListIssued(ctx context.Context) (*cryptosv1.ListIssuedResponse, error) {
	return c.node.ListIssued(ctx, &cryptosv1.ListIssuedRequest{})
}

// ListRevocations returns this node's revoked certificates.
func (c *Client) ListRevocations(ctx context.Context) (*cryptosv1.ListRevocationsResponse, error) {
	return c.node.ListRevocations(ctx, &cryptosv1.ListRevocationsRequest{})
}

// Attest asks the node to sign nonce with its identity key, proving
// possession of the private key behind its current certificate.
func (c *Client) Attest(ctx context.Context, nonce []byte) (*cryptosv1.AttestResponse, error) {
	return c.node.Attest(ctx, &cryptosv1.AttestRequest{Nonce: nonce})
}

// GetSubordinateCSR returns the node's own DER-encoded PKCS#10 CSR, generated
// when it is provisioning as a subordinate awaiting a parent's signature.
func (c *Client) GetSubordinateCSR(ctx context.Context) (*cryptosv1.GetSubordinateCSRResponse, error) {
	return c.node.GetSubordinateCSR(ctx, &cryptosv1.GetSubordinateCSRRequest{})
}

// SignSubordinateCSR asks a parent node to sign a child's DER CSR under the
// named certificate profile (which sets CA:TRUE + pathLen), returning the
// signed cert and full issuing chain.
func (c *Client) SignSubordinateCSR(ctx context.Context, csrDER []byte, profile string) (*cryptosv1.SignSubordinateCSRResponse, error) {
	return c.node.SignSubordinateCSR(ctx, &cryptosv1.SignSubordinateCSRRequest{
		CsrDer:      csrDER,
		ProfileName: profile,
	})
}

// SubmitSubordinateCertificate delivers a parent-signed chain (leaf-first:
// this node's cert, parent, ..., root) back to the subordinate node so it
// can adopt its new identity.
func (c *Client) SubmitSubordinateCertificate(ctx context.Context, chainDER [][]byte, chainPEM string) (*cryptosv1.SubmitSubordinateCertificateResponse, error) {
	return c.node.SubmitSubordinateCertificate(ctx, &cryptosv1.SubmitSubordinateCertificateRequest{
		ChainDer: chainDER,
		ChainPem: chainPEM,
	})
}

// ApplyConfig pushes a machine configuration to the node.
func (c *Client) ApplyConfig(ctx context.Context, cfg *cryptosv1.MachineConfig) (*cryptosv1.ApplyConfigResponse, error) {
	return c.node.ApplyConfig(ctx, &cryptosv1.ApplyConfigRequest{Config: cfg})
}

// GetConfig fetches the dialed node's current machine configuration, so a
// caller can read the full config before editing a subset and applying the
// whole config back via ApplyConfig.
func (c *Client) GetConfig(ctx context.Context) (*cryptosv1.GetConfigResponse, error) {
	return c.node.GetConfig(ctx, &cryptosv1.GetConfigRequest{})
}

// SetManagement merges Fleet-Manager managed-state into the node's persisted
// config: it marks the node as managed by this operator CN, adds the
// operator CA as a trusted client CA, and optionally makes the node's own
// operator surface read-only.
func (c *Client) SetManagement(ctx context.Context, m *cryptosv1.Management) (*cryptosv1.SetManagementResponse, error) {
	return c.node.SetManagement(ctx, &cryptosv1.SetManagementRequest{Management: m})
}

// RevokeCertificate revokes an issued certificate on the dialed node,
// identified by its hex serial, recording the RFC 5280 reason code.
func (c *Client) RevokeCertificate(ctx context.Context, serialHex string, reasonCode int32) (*cryptosv1.RevokeCertificateResponse, error) {
	return c.node.RevokeCertificate(ctx, &cryptosv1.RevokeCertificateRequest{
		SerialHex:  serialHex,
		ReasonCode: reasonCode,
	})
}

// IssueLeaf signs a leaf certificate on the dialed node from a DER PKCS#10
// CSR under the named issuance profile, returning the signed leaf in DER.
func (c *Client) IssueLeaf(ctx context.Context, csrDER []byte, profileName string) (*cryptosv1.IssueLeafResponse, error) {
	return c.node.IssueLeaf(ctx, &cryptosv1.IssueLeafRequest{
		CsrDer:      csrDER,
		ProfileName: profileName,
	})
}

// RemoteReset asks the dialed node to perform the destructive decommission
// wipe over its mTLS surface. confirmCN must equal the node's current Root CA
// CN or the node refuses (PermissionDenied); on success the node wipes its
// identity and data and reboots into maintenance.
func (c *Client) RemoteReset(ctx context.Context, confirmCN string) (*cryptosv1.RemoteResetResponse, error) {
	return c.node.RemoteReset(ctx, &cryptosv1.RemoteResetRequest{ConfirmCommonName: confirmCN})
}

// CeremonyStream is the receive side of a StartCeremony server stream, narrowed
// to what the adoption orchestrator consumes so it can be faked in tests.
type CeremonyStream interface {
	Recv() (*cryptosv1.StartCeremonyResponse, error)
}

// StartCeremony drives the node's first-boot ceremony, applying the operator's
// machine config (YAML) and streaming the ceremony events back. It is used
// during adoption once the node is reachable on the maintenance endpoint.
func (c *Client) StartCeremony(ctx context.Context, kind cryptosv1.CeremonyKind, machineConfigYAML []byte) (CeremonyStream, error) {
	return c.node.StartCeremony(ctx, &cryptosv1.StartCeremonyRequest{
		Kind:              kind,
		MachineConfigYaml: machineConfigYAML,
	})
}

// BeginKeyRotation starts a CA key rotation on the dialed node and returns the
// DER CSR for the newly generated key, to be ferried to the parent's
// SignSubordinateCSR.
func (c *Client) BeginKeyRotation(ctx context.Context) (*cryptosv1.BeginKeyRotationResponse, error) {
	return c.node.BeginKeyRotation(ctx, &cryptosv1.BeginKeyRotationRequest{})
}

// CompleteKeyRotation delivers the parent-signed chain (leaf-first: the node's
// new cert, parent, ..., root) back to the dialed node so it adopts the rotated
// key as its new identity.
func (c *Client) CompleteKeyRotation(ctx context.Context, chainDER [][]byte, chainPEM string) (*cryptosv1.CompleteKeyRotationResponse, error) {
	return c.node.CompleteKeyRotation(ctx, &cryptosv1.CompleteKeyRotationRequest{
		ChainDer: chainDER,
		ChainPem: chainPEM,
	})
}

// ExportCAKey asks the dialed node to seal its CA private key into an
// encrypted backup envelope using the operator passphrase. The node performs
// the encryption; the passphrase is relayed in transit only and never
// persisted by the manager.
func (c *Client) ExportCAKey(ctx context.Context, passphrase []byte) (*cryptosv1.ExportCAKeyResponse, error) {
	return c.node.ExportCAKey(ctx, &cryptosv1.ExportCAKeyRequest{Passphrase: passphrase})
}

// ImportCAKey delivers an encrypted backup envelope and its passphrase to the
// dialed node so it can decrypt and adopt the restored CA identity. The
// passphrase is relayed in transit only and never persisted by the manager.
func (c *Client) ImportCAKey(ctx context.Context, envelope, passphrase []byte) (*cryptosv1.ImportCAKeyResponse, error) {
	return c.node.ImportCAKey(ctx, &cryptosv1.ImportCAKeyRequest{Envelope: envelope, Passphrase: passphrase})
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
