package bootstrap

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
	"errors"
	"fmt"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/operatorca"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// reasonSuperseded is the RFC 5280 CRLReason superseded(4), recorded on the
// denylist entry of a first-admin certificate a later one replaced.
const reasonSuperseded = 4

func certRejected(reason fleetv1.ErrorReason, format string, args ...any) error {
	cause := fmt.Errorf("bootstrap: "+format, args...)
	if reason == fleetv1.ErrorReason_ERROR_REASON_UNSPECIFIED {
		return connect.NewError(connect.CodeInvalidArgument, apperr.Coded(apperr.CodeCertRejected, cause))
	}
	return connect.NewError(connect.CodeInvalidArgument, apperr.Reasoned(apperr.CodeCertRejected, reason, cause))
}

// parseLeaf reads exactly one DER certificate of at most MaxCertSize bytes.
func parseLeaf(der []byte) (*x509.Certificate, error) {
	if len(der) == 0 || len(der) > operatorca.MaxCertSize {
		return nil, certRejected(0, "the certificate is %d bytes; send one DER certificate of at most %d bytes", len(der), operatorca.MaxCertSize)
	}
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, certRejected(0, "the certificate doesn't parse: %v", err)
	}
	if len(certs) != 1 {
		return nil, certRejected(0, "%d certificates; send exactly one", len(certs))
	}
	return certs[0], nil
}

// SubmitFirstAdminCertificate checks and records the first admin's
// certificate, which the external operator CA signed out of band. The
// manager signs nothing and dials no node.
func (s *Service) SubmitFirstAdminCertificate(ctx context.Context, req *connect.Request[fleetv1.SubmitFirstAdminCertificateRequest]) (*connect.Response[fleetv1.SubmitFirstAdminCertificateResponse], error) {
	if err := s.admit(ctx); err != nil {
		return nil, err
	}
	sessionHash, err := s.session(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	// Another replica may have registered the CA a moment ago.
	if err := s.trust.Rebuild(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap: refresh the trusted operator CAs: %w", err)
	}
	row := s.activeCA(ctx)
	if row == nil {
		return nil, s.fail(ctx, caRejected(connect.CodeFailedPrecondition, fleetv1.ErrorReason_ERROR_REASON_NOT_CONFIRMED,
			"no operator CA is registered yet"))
	}
	by, err := s.st.OperatorCAConfirmedBy(ctx, row.SHA256)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read the operator CA confirmation: %w", err)
	}
	if by != sessionHash {
		return nil, s.fail(ctx, caRejected(connect.CodeFailedPrecondition, fleetv1.ErrorReason_ERROR_REASON_NOT_CONFIRMED,
			"this session hasn't confirmed the registered operator CA; confirm its fingerprint first"))
	}
	anchor, err := x509.ParseCertificate(row.CertDER)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: the registered operator CA %s doesn't parse: %w", row.SHA256, err)
	}

	m := req.Msg
	res, cert, err := s.checkFirstAdmin(m, anchor)
	if err != nil {
		// No fresh revocation data under a hard policy is the deployment's
		// state, not the caller's mistake, so it isn't counted as a failure.
		if code, _ := apperr.Code(err); code == apperr.CodeNoRevocationSource {
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		}
		return nil, s.fail(ctx, rejected(err))
	}

	now := s.now().UTC()
	if err := s.supersede(ctx, row.SHA256, res.Serial, res.Email); err != nil {
		return nil, err
	}
	cred := store.OperatorCredential{
		IssuerSHA256: row.SHA256, SerialHex: res.Serial, CommonName: res.Email, Email: res.Email, FullName: m.GetFullName(),
		Level: res.Level.Token(), NotAfter: cert.NotAfter.UTC().Format(time.RFC3339), LeafSHA256: operatorca.Fingerprint(cert),
	}
	if err := s.st.RecordFirstAdmin(ctx, cred, now); err != nil {
		return nil, fmt.Errorf("bootstrap: record the first admin: %w", err)
	}
	ip := clientIP(ctx)
	s.logf("manager: first admin certificate recorded for %s (serial %s, expires %s) from %s", res.Email, res.Serial, cred.NotAfter, ip)
	s.record(ctx, store.AuditEvent{
		Kind: KindFirstAdminRecorded,
		Summary: fmt.Sprintf("Recorded the first admin certificate CN=%s, serial %s, expires %s, issued by operator CA %s, from %s",
			res.Email, res.Serial, cred.NotAfter, row.SHA256, ip),
		TargetKind: "operator-credential",
		TargetPath: "/operators/" + res.Serial,
	})
	return connect.NewResponse(&fleetv1.SubmitFirstAdminCertificateResponse{
		SerialHex:    res.Serial,
		NotAfter:     cred.NotAfter,
		Email:        res.Email,
		IssuerSha256: row.SHA256,
		Warnings:     res.Warnings,
	}), nil
}

// checkFirstAdmin checks the inputs and the certificate profile: the name,
// the upload, the CSR when there is one, and the admin profile against the
// active anchor.
func (s *Service) checkFirstAdmin(m *fleetv1.SubmitFirstAdminCertificateRequest, anchor *x509.Certificate) (operatorca.CertResult, *x509.Certificate, error) {
	if err := operatorca.ValidateFullName(m.GetFullName()); err != nil {
		return operatorca.CertResult{}, nil, certRejected(0, "full_name: %v", err)
	}
	cert, err := parseLeaf(m.GetCertDer())
	if err != nil {
		return operatorca.CertResult{}, nil, err
	}
	var csr *operatorca.CSRResult
	if len(m.GetCsrDer()) > 0 {
		c, err := operatorca.CheckCSR(m.GetCsrDer())
		if err != nil {
			return operatorca.CertResult{}, nil, err
		}
		csr = &c
	}
	check := operatorca.CertCheck{Now: s.now(), WantLevel: "admin", Revoked: s.rev.IsRevoked, CheckRevocation: s.rev.CheckWebCert}
	if csr != nil {
		check.CSR = csr.CSR
	}
	res, err := operatorca.CheckOperatorCert(cert, anchor, check)
	if err != nil {
		return operatorca.CertResult{}, nil, err
	}
	if csr != nil && csr.Email != res.Email {
		return operatorca.CertResult{}, nil, certRejected(fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH,
			"the certificate is for %s but the CSR is for %s", res.Email, csr.Email)
	}
	return res, cert, nil
}

// supersede denylists every earlier first-admin certificate with another
// issuer or serial, so only the newest one submitted in first run can sign
// in. The denylist write reloads this replica at once and moves the
// revocation epoch for the others.
func (s *Service) supersede(ctx context.Context, issuer, serial, email string) error {
	earlier, err := s.st.FirstAdminCredentials(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap: read earlier first-admin records: %w", err)
	}
	for _, c := range earlier {
		if c.IssuerSHA256 == issuer && operatorca.NormalizeSerial(c.SerialHex) == operatorca.NormalizeSerial(serial) {
			continue
		}
		if s.rev.Denylisted(c.IssuerSHA256, c.SerialHex) {
			continue
		}
		err := s.rev.Deny(ctx, store.DenylistEntry{
			IssuerSHA256: c.IssuerSHA256, SerialHex: c.SerialHex, Reason: reasonSuperseded,
			RevokedByCN: registeredBy, Note: fmt.Sprintf("superseded by first-admin certificate %s for %s", serial, email),
		})
		if err != nil && !errors.Is(err, operatorca.ErrUnknownAnchor) {
			return fmt.Errorf("bootstrap: denylist the superseded first admin %s: %w", c.SerialHex, err)
		}
		s.logf("manager: first admin certificate %s (%s) superseded by %s and put on the denylist", c.SerialHex, c.Email, serial)
		s.record(ctx, store.AuditEvent{
			Kind: KindFirstAdminSuperseded,
			Summary: fmt.Sprintf("Put the earlier first admin certificate CN=%s, serial %s (operator CA %s) on the denylist: superseded by serial %s",
				c.Email, c.SerialHex, c.IssuerSHA256, serial),
			TargetKind: "operator-credential",
			TargetPath: "/operators/" + c.SerialHex,
		})
	}
	return nil
}
