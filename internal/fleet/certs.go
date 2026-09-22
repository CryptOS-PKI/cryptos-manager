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
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// rfc5280CRLReasons maps the RFC 5280 CRLReason codes the node reports on a
// Revocation to a short display string. Codes outside this table (including
// the reserved value 7) fall back to their numeric text.
var rfc5280CRLReasons = map[int32]string{
	0:  "UNSPECIFIED",
	1:  "KEY_COMPROMISE",
	2:  "CA_COMPROMISE",
	3:  "AFFILIATION_CHANGED",
	4:  "SUPERSEDED",
	5:  "CESSATION_OF_OPERATION",
	6:  "CERTIFICATE_HOLD",
	8:  "REMOVE_FROM_CRL",
	9:  "PRIVILEGE_WITHDRAWN",
	10: "AA_COMPROMISE",
}

// ListCertificates returns the aggregated certificate set across nodes,
// optionally scoped to a single node by req.Msg.Node. A node that fails to
// dial or list is skipped and logged rather than failing the whole request;
// the one exception is an explicitly named node that the store does not
// know about, which is a NotFound error.
func (s *Service) ListCertificates(ctx context.Context, req *connect.Request[fleetv1.ListCertificatesRequest]) (*connect.Response[fleetv1.ListCertificatesResponse], error) {
	name := req.Msg.GetNode()

	var nodes []store.Node
	if name != "" {
		n, ok := s.store.Node(name)
		if !ok {
			return nil, apperr.Coded(apperr.CodeNodeNotFound,
				connect.NewError(connect.CodeNotFound, errors.New("fleet: node not found: "+name)))
		}
		nodes = []store.Node{n}
	} else {
		nodes = s.store.Nodes()
	}

	perNode := make([][]*fleetv1.Certificate, len(nodes))

	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n store.Node) {
			defer wg.Done()
			certs, err := s.certsForNode(ctx, n)
			if err != nil {
				log.Printf("fleet: ListCertificates: skipping node %s: %v", n.Name, err)
				return
			}
			perNode[i] = certs
		}(i, n)
	}
	wg.Wait()

	var out []*fleetv1.Certificate
	for _, certs := range perNode {
		out = append(out, certs...)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].GetIssuerNode() != out[j].GetIssuerNode() {
			return out[i].GetIssuerNode() < out[j].GetIssuerNode()
		}
		return out[i].GetSerial() < out[j].GetSerial()
	})

	return connect.NewResponse(&fleetv1.ListCertificatesResponse{Certificates: out}), nil
}

// RevokeCertificate revokes an issued certificate on the node that issued it.
// It is operator-gated: it verifies the caller is at least operator level,
// resolves the named node, dials it, forwards the serial and RFC 5280 reason
// code to the node's RevokeCertificate, and appends a single "revoked" audit
// event. A denied caller or an unknown node never reaches the node and never
// writes an audit event.
func (s *Service) RevokeCertificate(ctx context.Context, req *connect.Request[fleetv1.RevokeCertificateRequest]) (*connect.Response[fleetv1.RevokeCertificateResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	name := req.Msg.GetNodeName()
	node, ok := s.store.Node(name)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: node %q not found", name))
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	rev, err := conn.RevokeCertificate(ctx, req.Msg.GetSerialHex(), req.Msg.GetReasonCode())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: revoke: %w", err))
	}

	revokedAt := ""
	if r := rev.GetRevocation(); r != nil && r.GetRevokedAt() != nil {
		revokedAt = r.GetRevokedAt().AsTime().UTC().Format(time.RFC3339)
	}

	s.store.AddAuditEvent(store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "revoked",
		Summary:    fmt.Sprintf("Revoked %s on %s (reason %d)", req.Msg.GetSerialHex(), name, req.Msg.GetReasonCode()),
		TargetKind: "cert",
		TargetPath: "/nodes/" + name + "/certs/" + req.Msg.GetSerialHex(),
	})

	return connect.NewResponse(&fleetv1.RevokeCertificateResponse{
		SerialHex:  req.Msg.GetSerialHex(),
		RevokedAt:  revokedAt,
		ReasonCode: req.Msg.GetReasonCode(),
	}), nil
}

// IssueLeaf signs a leaf certificate on the named issuing node from a
// browser-generated PKCS#10 CSR. It is operator-gated: it verifies the caller
// is at least operator level, rejects an empty CSR, resolves the named node,
// dials it, forwards the CSR and profile to the node's IssueLeaf, and appends
// a single "issued" audit event. A denied caller, an empty CSR, or an unknown
// node never reaches the node and never writes an audit event.
func (s *Service) IssueLeaf(ctx context.Context, req *connect.Request[fleetv1.IssueLeafRequest]) (*connect.Response[fleetv1.IssueLeafResponse], error) {
	id, err := operatorLevel(ctx)
	if err != nil {
		return nil, err
	}
	if id.Level < authz.LevelOperator {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("fleet: operator level required"))
	}

	csrDER := req.Msg.GetCsrDer()
	if len(csrDER) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: csr_der is required"))
	}

	name := req.Msg.GetNodeName()
	node, ok := s.store.Node(name)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: node %q not found", name))
	}

	profile := req.Msg.GetProfileName()

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	issued, err := conn.IssueLeaf(ctx, csrDER, profile)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: issue leaf: %w", err))
	}

	s.store.AddAuditEvent(store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "issued",
		Summary:    fmt.Sprintf("Issued leaf via %s on %s", profile, name),
		TargetKind: "cert",
		TargetPath: "/nodes/" + name + "/certs",
	})

	return connect.NewResponse(&fleetv1.IssueLeafResponse{CertDer: issued.GetCertDer()}), nil
}

// certsForNode dials n and merges its issued certificates with its
// revocations into the FleetService's Certificate shape. Any dial/list
// failure is returned to the caller, which skips this node rather than
// failing the whole request.
func (s *Service) certsForNode(ctx context.Context, n store.Node) ([]*fleetv1.Certificate, error) {
	conn, err := s.dial(n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	issuedResp, err := conn.ListIssued(ctx)
	if err != nil {
		return nil, err
	}

	revocationsResp, err := conn.ListRevocations(ctx)
	if err != nil {
		return nil, err
	}

	bySerial := make(map[string]*fleetv1.Certificate, len(issuedResp.GetIssued()))
	for _, ic := range issuedResp.GetIssued() {
		bySerial[ic.GetSerialHex()] = &fleetv1.Certificate{
			Serial:     ic.GetSerialHex(),
			SubjectCn:  ic.GetSubjectDn(),
			IssuerNode: n.Name,
			Kind:       certKind(ic.GetProfileName()),
			Status:     statusForNotAfter(ic.GetNotAfter().AsTime()),
			NotBefore:  formatTimestamp(ic.GetNotBefore()),
			NotAfter:   formatTimestamp(ic.GetNotAfter()),
			Profile:    ic.GetProfileName(),
		}
	}

	for _, rv := range revocationsResp.GetRevocations() {
		c, ok := bySerial[rv.GetSerialHex()]
		if !ok {
			// A revocation with no matching issued entry: still worth
			// surfacing, so keep the fields we have.
			c = &fleetv1.Certificate{
				Serial:     rv.GetSerialHex(),
				IssuerNode: n.Name,
				Kind:       certKind(""),
			}
			bySerial[rv.GetSerialHex()] = c
		}
		c.Status = "REVOKED"
		c.RevokedAt = formatTimestamp(rv.GetRevokedAt())
		c.Reason = reasonText(rv.GetReasonCode())
	}

	out := make([]*fleetv1.Certificate, 0, len(bySerial))
	for _, c := range bySerial {
		out = append(out, c)
	}

	return out, nil
}

// certKind derives the FleetService's leaf|subordinate-ca Kind from a
// node's profile name.
func certKind(profile string) string {
	lower := strings.ToLower(profile)
	if strings.Contains(lower, "sub-ca") || strings.Contains(lower, "subordinate") {
		return "subordinate-ca"
	}
	return "leaf"
}

// statusForNotAfter reports EXPIRED for a certificate whose not_after has
// already passed, VALID otherwise. Revocation overrides this afterward.
func statusForNotAfter(notAfter time.Time) string {
	if notAfter.Before(time.Now()) {
		return "EXPIRED"
	}
	return "VALID"
}

// formatTimestamp renders a protobuf timestamp as RFC3339, or "" for a nil
// timestamp.
func formatTimestamp(ts interface{ AsTime() time.Time }) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().Format(time.RFC3339)
}

// reasonText maps an RFC 5280 CRLReason code to a short display string.
func reasonText(code int32) string {
	if text, ok := rfc5280CRLReasons[code]; ok {
		return text
	}
	return strconv.Itoa(int(code))
}
