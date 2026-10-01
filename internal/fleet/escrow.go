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
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// minPassphraseLen is the minimum operator passphrase length the manager
// enforces for CA key escrow, matching the web's client-side guard. It is a
// defense-in-depth floor: the node performs the actual sealing/unsealing, but
// the manager rejects a too-short passphrase before it ever dials a node.
const minPassphraseLen = 18

// ExportCAKey backs up a managed node's CA key to an encrypted envelope. It is
// admin-gated and rejects a passphrase shorter than minPassphraseLen before any
// dial or audit; the rejection never echoes the passphrase. On success it
// relays the node's encrypted envelope straight back to the caller and appends
// a single "ca-key-exported" audit event that names the node only. A TPM-backed
// node refuses export (FailedPrecondition); that is mapped through with a
// secret-free message and writes no audit event. The passphrase and envelope
// are never logged.
func (s *Service) ExportCAKey(ctx context.Context, req *connect.Request[fleetv1.ExportCAKeyRequest]) (*connect.Response[fleetv1.ExportCAKeyResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if err := checkPassphrase(req.Msg.GetPassphrase()); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("ExportCAKey", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}
	name := node.Name

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	// Do not log the passphrase or the resulting envelope anywhere.
	resp, err := conn.ExportCAKey(ctx, req.Msg.GetPassphrase())
	if err != nil {
		return nil, mapNodeEscrowError(name, "export", err)
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "ca-key-exported",
		Summary:    fmt.Sprintf("Exported CA key from %s", name),
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})

	return connect.NewResponse(&fleetv1.ExportCAKeyResponse{Envelope: resp.GetEnvelope()}), nil
}

// ImportCAKey restores a CA identity onto a fresh managed node from an encrypted
// envelope. It is admin-gated and rejects an empty envelope or a passphrase
// shorter than minPassphraseLen before any dial or audit; the rejection never
// echoes the passphrase. On success it returns the restored identity's
// subject/issuer CN summary and appends a single "ca-key-imported" audit event
// naming the node and restored subject. A node that already holds an identity
// refuses the import (FailedPrecondition); that is mapped through with a clear,
// secret-free message and writes no audit event. The passphrase and envelope
// are never logged.
func (s *Service) ImportCAKey(ctx context.Context, req *connect.Request[fleetv1.ImportCAKeyRequest]) (*connect.Response[fleetv1.ImportCAKeyResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	if len(req.Msg.GetEnvelope()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: envelope is required"))
	}
	if err := checkPassphrase(req.Msg.GetPassphrase()); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("ImportCAKey", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}
	name := node.Name

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	// Do not log the passphrase or the envelope anywhere.
	resp, err := conn.ImportCAKey(ctx, req.Msg.GetEnvelope(), req.Msg.GetPassphrase())
	if err != nil {
		return nil, mapNodeEscrowError(name, "import", err)
	}

	subjectCN, issuerCN := leafCNs(resp.GetIdentity())

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "ca-key-imported",
		Summary:    fmt.Sprintf("Imported CA key onto %s (%s)", name, subjectCN),
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})

	return connect.NewResponse(&fleetv1.ImportCAKeyResponse{
		SubjectCn: subjectCN,
		IssuerCn:  issuerCN,
	}), nil
}

// checkPassphrase enforces the minimum passphrase length without ever echoing
// the passphrase in the error message.
func checkPassphrase(passphrase []byte) error {
	if len(passphrase) < minPassphraseLen {
		return connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("fleet: passphrase must be at least %d bytes", minPassphraseLen))
	}
	return nil
}

// mapNodeEscrowError maps a node's escrow error to a clear, secret-free Connect
// error. A node's FailedPrecondition means the operation is not allowed in the
// node's current state (a TPM node cannot export; a node that already holds an
// identity cannot import), so it maps to a guidance message that never contains
// the passphrase or envelope. Other node errors surface as Internal without the
// node's raw message so no secret can leak through it.
func mapNodeEscrowError(node, op string, err error) *connect.Error {
	if status.Code(err) == codes.FailedPrecondition {
		switch op {
		case "export":
			return connect.NewError(connect.CodeFailedPrecondition,
				fmt.Errorf("fleet: node %q refused export; its CA key is non-exportable (for example a TPM-backed key)", node))
		case "import":
			return connect.NewError(connect.CodeFailedPrecondition,
				fmt.Errorf("fleet: node %q already has a CA identity; import only onto a fresh node", node))
		}
	}
	if status.Code(err) == codes.InvalidArgument {
		// The node validated the request (for example a passphrase that does
		// not unseal the envelope). Do not relay the node's raw message.
		return connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("fleet: node %q rejected the %s request", node, op))
	}
	return connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: %s on node %q failed", op, node))
}
