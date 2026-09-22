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
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"google.golang.org/protobuf/proto"
)

// operatorLevels is the set of valid operator credential levels; the handler
// routes each to the matching operator-<level> profile on the operator-CA node.
var operatorLevels = map[string]struct{}{
	"viewer":   {},
	"operator": {},
	"admin":    {},
}

// IssueOperatorCredential signs an operator client certificate on the
// operator-CA node from a browser-generated CSR. It is admin-gated: it verifies
// the caller is admin, validates the requested level and a non-empty CSR,
// requires an operator-CA node to be configured, dials it, and calls IssueLeaf
// under the operator-<level> profile that carries the access-level extension.
// On success it records the credential metadata in the store (never the CSR or
// cert bytes), appends an "operator-issued" audit event that names only the CN,
// level, and serial, and returns the signed cert plus its hex serial. A denied
// caller, an invalid level/CSR, a missing operator-CA node, or a node error
// never writes an audit event or a store row.
func (s *Service) IssueOperatorCredential(ctx context.Context, req *connect.Request[fleetv1.IssueOperatorCredentialRequest]) (*connect.Response[fleetv1.IssueOperatorCredentialResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	level := req.Msg.GetLevel()
	if _, ok := operatorLevels[level]; !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("fleet: unknown operator level %q", level))
	}
	csrDER := req.Msg.GetCsrDer()
	if len(csrDER) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: csr_der is required"))
	}
	cn := req.Msg.GetCommonName()
	if cn == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: common_name is required"))
	}

	node, err := s.operatorCANode()
	if err != nil {
		return nil, err
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial operator CA: %w", err))
	}
	defer func() { _ = conn.Close() }()

	profile := "operator-" + level
	issued, err := conn.IssueLeaf(ctx, csrDER, profile)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: issue operator credential: %w", err))
	}

	serialHex, notAfter, err := certSerialAndExpiry(issued.GetCertDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: parse issued operator cert: %w", err))
	}

	s.store.AddOperatorCredential(store.OperatorCredential{
		CommonName: cn,
		SerialHex:  serialHex,
		Level:      level,
		NotAfter:   notAfter,
	})

	s.store.AddAuditEvent(store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "operator-issued",
		Summary:    fmt.Sprintf("Issued operator credential for %s (level %s, serial %s)", cn, level, serialHex),
		TargetKind: "operator-credential",
		TargetPath: "/operators/" + serialHex,
	})

	return connect.NewResponse(&fleetv1.IssueOperatorCredentialResponse{
		CertDer:   issued.GetCertDer(),
		SerialHex: serialHex,
	}), nil
}

// RevokeOperatorCredential revokes an operator credential on the operator-CA
// node and marks the store row revoked. It is admin-gated: it verifies the
// caller is admin, rejects an empty serial, requires an operator-CA node, dials
// it, and calls RevokeCertificate with the serial and RFC 5280 reason. On
// success it flags the store row revoked and appends an "operator-revoked"
// audit event. A denied caller, an empty serial, a missing operator-CA node, or
// a node error never writes an audit event.
func (s *Service) RevokeOperatorCredential(ctx context.Context, req *connect.Request[fleetv1.RevokeOperatorCredentialRequest]) (*connect.Response[fleetv1.RevokeOperatorCredentialResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	serialHex := req.Msg.GetSerialHex()
	if serialHex == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: serial_hex is required"))
	}

	node, err := s.operatorCANode()
	if err != nil {
		return nil, err
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial operator CA: %w", err))
	}
	defer func() { _ = conn.Close() }()

	rev, err := conn.RevokeCertificate(ctx, serialHex, req.Msg.GetReasonCode())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: revoke operator credential: %w", err))
	}

	// The store row is best-effort: the operator CA is the authority for
	// revocation (and drives the enforced CRL), so a serial the manager never
	// recorded still revokes at the node. A missing row is not an error.
	_ = s.store.MarkOperatorCredentialRevoked(serialHex)

	revokedAt := ""
	if r := rev.GetRevocation(); r != nil && r.GetRevokedAt() != nil {
		revokedAt = r.GetRevokedAt().AsTime().UTC().Format(time.RFC3339)
	}

	s.store.AddAuditEvent(store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "operator-revoked",
		Summary:    fmt.Sprintf("Revoked operator credential %s (reason %d)", serialHex, req.Msg.GetReasonCode()),
		TargetKind: "operator-credential",
		TargetPath: "/operators/" + serialHex,
	})

	return connect.NewResponse(&fleetv1.RevokeOperatorCredentialResponse{
		SerialHex: serialHex,
		RevokedAt: revokedAt,
	}), nil
}

// ListOperatorCredentials returns the operator credentials the manager has
// issued. It is operator-readable and a pure store read, so it dials no node
// and writes no audit event.
func (s *Service) ListOperatorCredentials(ctx context.Context, _ *connect.Request[fleetv1.ListOperatorCredentialsRequest]) (*connect.Response[fleetv1.ListOperatorCredentialsResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	creds := s.store.OperatorCredentials()
	items := make([]*fleetv1.OperatorCredential, len(creds))
	for i, c := range creds {
		items[i] = &fleetv1.OperatorCredential{
			CommonName: c.CommonName,
			SerialHex:  c.SerialHex,
			Level:      c.Level,
			NotAfter:   c.NotAfter,
			Revoked:    c.Revoked,
		}
	}

	return connect.NewResponse(&fleetv1.ListOperatorCredentialsResponse{Items: items}), nil
}

// operatorCANode resolves the configured operator-CA node from the inventory.
// It maps an unconfigured operator CA to FailedPrecondition (the deployment
// must set operator_ca_node) and an unknown node name to NotFound.
func (s *Service) operatorCANode() (store.Node, error) {
	if s.operatorCANodeName == "" {
		return store.Node{}, apperr.Coded(apperr.CodeOperatorCAUnconfigured,
			connect.NewError(connect.CodeFailedPrecondition,
				errors.New("fleet: no operator CA node configured (set operator_ca_node)")))
	}
	node, ok := s.store.Node(s.operatorCANodeName)
	if !ok {
		return store.Node{}, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("fleet: operator CA node %q not in inventory", s.operatorCANodeName))
	}
	return node, nil
}

// OperatorProfiles builds the three operator-<level> issuing profiles the
// operator-CA node must carry: operator-viewer, operator-operator, and
// operator-admin. Each stamps the access-level X.509 extension (the single
// encoding shared with cmd/opext via authz.MarshalLevelExtension) so that a
// leaf issued under the profile is a valid operator client cert at that level.
// The profiles are seeded into the catalog on startup so an admin can push them
// to the operator-CA node with ApplyProfileToNode (S6); IssueOperatorCredential
// then routes each level to its matching profile. It errors only if the level
// encoding fails, which is a programming error.
func OperatorProfiles() ([]store.Profile, error) {
	levels := []string{"viewer", "operator", "admin"}
	out := make([]store.Profile, 0, len(levels))
	for _, level := range levels {
		oid, der, err := authz.MarshalLevelExtension(level)
		if err != nil {
			return nil, fmt.Errorf("fleet: encode operator-%s extension: %w", level, err)
		}
		cp := &cryptosv1.CertificateProfile{
			Name:             "operator-" + level,
			KeyAlg:           "ECDSA-P384",
			ValidityDays:     365,
			BasicConstraints: &cryptosv1.BasicConstraints{IsCa: false},
			KeyUsage:         []string{"digital_signature"},
			ExtKeyUsage:      []string{"client_auth"},
			ExtraExtensions: []*cryptosv1.X509Extension{
				{Oid: oid, Critical: false, Value: der},
			},
		}
		raw, err := proto.Marshal(cp)
		if err != nil {
			return nil, fmt.Errorf("fleet: marshal operator-%s profile: %w", level, err)
		}
		out = append(out, store.Profile{Name: cp.GetName(), Spec: raw})
	}
	return out, nil
}

// OperatorRevocationSource returns an authz.RevocationSource that fetches the
// operator-CA node's revoked serials, so the manager can enforce operator-cert
// revocation at the authz middleware. It returns nil when no operator-CA node
// is configured (revocation enforcement is then disabled). The source dials the
// operator-CA node on each refresh and lists its revocations; a dial/list error
// is surfaced so the cache keeps its last-good set (fail-safe).
func (s *Service) OperatorRevocationSource() *OperatorCARevocationSource {
	if s.operatorCANodeName == "" {
		return nil
	}
	return &OperatorCARevocationSource{svc: s}
}

// OperatorCARevocationSource is the authz.RevocationSource backed by the
// operator-CA node's ListRevocations.
type OperatorCARevocationSource struct {
	svc *Service
}

// RevokedSerials dials the operator-CA node and returns its revoked serials in
// hex. A dial or list failure is returned as an error; the caller (the cache)
// keeps its last-good set rather than clearing it.
func (r *OperatorCARevocationSource) RevokedSerials() ([]string, error) {
	node, err := r.svc.operatorCANode()
	if err != nil {
		return nil, err
	}
	conn, err := r.svc.dial(node)
	if err != nil {
		return nil, fmt.Errorf("fleet: dial operator CA for revocations: %w", err)
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.ListRevocations(context.Background())
	if err != nil {
		return nil, fmt.Errorf("fleet: list operator CA revocations: %w", err)
	}
	serials := make([]string, 0, len(resp.GetRevocations()))
	for _, rv := range resp.GetRevocations() {
		serials = append(serials, rv.GetSerialHex())
	}
	return serials, nil
}

// certSerialAndExpiry parses a DER certificate and returns its serial as
// lowercase hex and its not_after as RFC3339 UTC. The serial is the record key
// the store and the enforced CRL share.
func certSerialAndExpiry(der []byte) (serialHex, notAfter string, err error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("%x", cert.SerialNumber), cert.NotAfter.UTC().Format(time.RFC3339), nil
}
