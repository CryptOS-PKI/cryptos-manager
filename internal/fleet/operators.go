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
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// denylistWarning is the reminder every revoke carries: the manager's
// denylist stops the credential here and nowhere else.
const denylistWarning = "The Fleet Manager's denylist stops this credential at the Fleet Manager only. " +
	"Revoke it at your operator CA too and publish a new CRL."

// RevokeOperatorCredential puts an operator credential on the manager's
// denylist, keyed by the operator CA and the serial. It is admin-gated and
// calls no node: the operator CA is external, so the manager can't revoke
// there. The issuer defaults to the recorded credential's operator CA, else
// the active one. A serial the manager never recorded can be denied too. The
// writing replica enforces the entry at once and the others on their next
// poll. Without Postgres there is no denylist (1603 DATABASE_REQUIRED).
func (s *Service) RevokeOperatorCredential(ctx context.Context, req *connect.Request[fleetv1.RevokeOperatorCredentialRequest]) (*connect.Response[fleetv1.RevokeOperatorCredentialResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	serial := operatorca.NormalizeSerial(req.Msg.GetSerialHex())
	if req.Msg.GetSerialHex() == "" || !isHex(serial, 1, maxSerialHex) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: serial_hex must be a hex certificate serial"))
	}
	if !validReasonCode(req.Msg.GetReasonCode()) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("fleet: reason_code %d is not an RFC 5280 CRL reason (0-10, except 7)", req.Msg.GetReasonCode()))
	}
	issuer := strings.ToLower(req.Msg.GetIssuerSha256())
	if issuer != "" && !isHex(issuer, 64, 64) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: issuer_sha256 must be a SHA-256 fingerprint in hex"))
	}
	if !s.hasOperatorCA() {
		return nil, errOperatorCAUnconfigured("RevokeOperatorCredential")
	}

	if issuer == "" {
		issuer = s.recordedIssuer(serial)
	}
	if issuer == "" {
		issuer = s.activeOperatorCA()
	}
	if issuer == "" {
		return nil, errOperatorCAUnconfigured("RevokeOperatorCredential")
	}

	at := time.Now().UTC()
	if err := s.revocations.Deny(ctx, store.DenylistEntry{
		IssuerSHA256: issuer, SerialHex: serial, Reason: int(req.Msg.GetReasonCode()), RevokedAt: at,
		RevokedByCN: id.CN, RevokedBySerial: id.Serial, Note: req.Msg.GetNote(),
	}); err != nil {
		if _, coded := apperr.Code(err); coded {
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         at.Format(time.RFC3339),
		Kind:       "operator-revoked",
		Summary:    fmt.Sprintf("Denied operator credential %s under operator CA %s on the Fleet Manager denylist (reason %d); it is not revoked at the operator CA", serial, issuer, req.Msg.GetReasonCode()),
		TargetKind: "operator-credential",
		TargetPath: "/operators/" + serial,
	})

	return connect.NewResponse(&fleetv1.RevokeOperatorCredentialResponse{
		SerialHex:    serial,
		RevokedAt:    at.Format(time.RFC3339),
		IssuerSha256: issuer,
		Warnings:     []string{denylistWarning},
	}), nil
}

// ListOperatorCredentials returns the operator credentials the manager knows,
// with their revocation state. It is operator-readable and a pure store read.
// It fails with the operator-CA-unconfigured code only when no operator CA
// source exists at all.
func (s *Service) ListOperatorCredentials(ctx context.Context, _ *connect.Request[fleetv1.ListOperatorCredentialsRequest]) (*connect.Response[fleetv1.ListOperatorCredentialsResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}
	if !s.hasOperatorCA() {
		return nil, errOperatorCAUnconfigured("ListOperatorCredentials")
	}

	creds := s.store.OperatorCredentials()
	items := make([]*fleetv1.OperatorCredential, len(creds))
	for i, c := range creds {
		items[i] = s.credentialToProto(c)
	}

	return connect.NewResponse(&fleetv1.ListOperatorCredentialsResponse{Items: items}), nil
}

// credentialToProto renders a stored credential with its revocation state on
// this replica.
func (s *Service) credentialToProto(c store.OperatorCredential) *fleetv1.OperatorCredential {
	serial := operatorca.NormalizeSerial(c.SerialHex)
	denied := c.IssuerSHA256 != "" && s.revocations.Denylisted(c.IssuerSHA256, serial)
	crlRevoked := c.IssuerSHA256 != "" && s.revocations.CRLRevoked(c.IssuerSHA256, serial)
	return &fleetv1.OperatorCredential{
		CommonName:   c.CommonName,
		SerialHex:    c.SerialHex,
		Level:        c.Level,
		NotAfter:     c.NotAfter,
		Revoked:      c.Revoked || denied || crlRevoked,
		Kind:         c.Kind,
		IssuerSha256: c.IssuerSHA256,
		Email:        c.Email,
		FullName:     c.FullName,
		Denylisted:   denied,
		CrlRevoked:   crlRevoked,
		FirstSeenAt:  rfc3339(c.FirstSeenAt),
		LastSeenAt:   rfc3339(c.LastSeenAt),
	}
}

// maxSerialHex bounds a serial: RFC 5280 allows 20 octets, and some CAs
// overshoot, so twice that is still refused as nonsense.
const maxSerialHex = 80

func isHex(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// validReasonCode accepts the RFC 5280 CRLReason values; 7 is unused.
func validReasonCode(c int32) bool {
	return c >= 0 && c <= 10 && c != 7
}

// hasOperatorCA reports whether an operator CA source is configured.
func (s *Service) hasOperatorCA() bool {
	if s.trust == nil || s.revocations == nil {
		return false
	}
	k := s.trust.Source().Kind
	return k == operatorca.KindFile || k == operatorca.KindRegistered
}

func (s *Service) recordedIssuer(serial string) string {
	for _, c := range s.store.OperatorCredentials() {
		if c.IssuerSHA256 != "" && operatorca.NormalizeSerial(c.SerialHex) == serial {
			return c.IssuerSHA256
		}
	}
	return ""
}

func (s *Service) activeOperatorCA() string {
	for _, a := range s.trust.Anchors() {
		if a.State == store.OperatorCAActive {
			return a.SHA256
		}
	}
	return ""
}

// errOperatorCAUnconfigured is the one error every operator-credential path
// returns when no operator CA is configured, so the UI can branch on its code.
func errOperatorCAUnconfigured(op string) error {
	log.Printf("fleet: %s: no operator CA configured, refusing with code %d", op, apperr.CodeOperatorCAUnconfigured)
	return apperr.Coded(apperr.CodeOperatorCAUnconfigured,
		connect.NewError(connect.CodeFailedPrecondition,
			errors.New("fleet: no operator CA configured (set operatorCAPath, or register one at first run)")))
}
