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
	"errors"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// escrowTestStore is a two-node inventory for the escrow handler tests.
func escrowTestStore() store.Store {
	return memory.New([]store.Node{
		{Name: "A", Endpoint: "a.acme.com:4443", Role: "root"},
		{Name: "B", Endpoint: "b.acme.com:4444", Role: "intermediate"},
	})
}

// strongPassphrase is an example passphrase at the enforced minimum length.
const strongPassphrase = "correct-horse-battery-staple" // >= 18 bytes

func connErr(t *testing.T, err error) *connect.Error {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	return ce
}

// --- ExportCAKey ---

func TestExportCAKey_ViewerDenied_NoDialNoAudit(t *testing.T) {
	st := escrowTestStore()
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.ExportCAKey(ctx, connect.NewRequest(&fleetv1.ExportCAKeyRequest{
		NodeName:   "A",
		Passphrase: []byte(strongPassphrase),
	}))
	if err == nil {
		t.Fatal("ExportCAKey(viewer) error = nil, want PermissionDenied")
	}
	if code := connErr(t, err).Code(); code != connect.CodePermissionDenied {
		t.Errorf("code = %v, want CodePermissionDenied", code)
	}
	if connA.gotExportPassphrase != nil {
		t.Error("node was dialed and export called, want no call on denial")
	}
	if connA.closed {
		t.Error("node connection was opened, want no dial")
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event on denial)", len(st.Audit()), before)
	}
}

func TestExportCAKey_OperatorDenied(t *testing.T) {
	st := escrowTestStore()
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.ExportCAKey(ctx, connect.NewRequest(&fleetv1.ExportCAKeyRequest{
		NodeName:   "A",
		Passphrase: []byte(strongPassphrase),
	}))
	if err == nil {
		t.Fatal("ExportCAKey(operator) error = nil, want PermissionDenied (admin required)")
	}
	if code := connErr(t, err).Code(); code != connect.CodePermissionDenied {
		t.Errorf("code = %v, want CodePermissionDenied", code)
	}
	if connA.gotExportPassphrase != nil {
		t.Error("node was dialed, want no call on denial")
	}
}

func TestExportCAKey_ShortPassphrase_InvalidArgument_NoDialNoAudit(t *testing.T) {
	st := escrowTestStore()
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	short := []byte("short-secret") // < 18 bytes
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ExportCAKey(ctx, connect.NewRequest(&fleetv1.ExportCAKeyRequest{
		NodeName:   "A",
		Passphrase: short,
	}))
	if err == nil {
		t.Fatal("ExportCAKey(short passphrase) error = nil, want InvalidArgument")
	}
	ce := connErr(t, err)
	if ce.Code() != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want CodeInvalidArgument", ce.Code())
	}
	if strings.Contains(ce.Message(), string(short)) {
		t.Errorf("error message %q echoes the passphrase", ce.Message())
	}
	if connA.gotExportPassphrase != nil {
		t.Error("node was dialed on a short passphrase, want no dial before validation")
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event on validation failure)", len(st.Audit()), before)
	}
}

func TestExportCAKey_UnknownNode_NotFound(t *testing.T) {
	st := escrowTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{}))

	before := len(st.Audit())
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ExportCAKey(ctx, connect.NewRequest(&fleetv1.ExportCAKeyRequest{
		NodeName:   "missing",
		Passphrase: []byte(strongPassphrase),
	}))
	if err == nil {
		t.Fatal("ExportCAKey(unknown node) error = nil, want NotFound")
	}
	if code := connErr(t, err).Code(); code != connect.CodeNotFound {
		t.Errorf("code = %v, want CodeNotFound", code)
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event when node unknown)", len(st.Audit()), before)
	}
}

func TestExportCAKey_Admin_ReturnsEnvelopeAndAudits(t *testing.T) {
	st := escrowTestStore()
	connA := &fakeConn{
		exportResp: &cryptosv1.ExportCAKeyResponse{Envelope: []byte("ENCRYPTED-ENVELOPE-BYTES")},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.ExportCAKey(ctx, connect.NewRequest(&fleetv1.ExportCAKeyRequest{
		NodeName:   "A",
		Passphrase: []byte(strongPassphrase),
	}))
	if err != nil {
		t.Fatalf("ExportCAKey(admin) error = %v, want nil", err)
	}

	if string(connA.gotExportPassphrase) != strongPassphrase {
		t.Errorf("node received passphrase %q, want it relayed unchanged", connA.gotExportPassphrase)
	}
	if got := string(resp.Msg.GetEnvelope()); got != "ENCRYPTED-ENVELOPE-BYTES" {
		t.Errorf("response envelope = %q, want the node's envelope relayed", got)
	}
	if !connA.closed {
		t.Error("node connection was not closed")
	}

	audit := st.Audit()
	if len(audit) != 1 {
		t.Fatalf("audit len = %d, want 1", len(audit))
	}
	ev := audit[0]
	if ev.Kind != "ca-key-exported" {
		t.Errorf("audit kind = %q, want ca-key-exported", ev.Kind)
	}
	if !strings.Contains(ev.Summary, "A") {
		t.Errorf("audit summary %q does not name the node", ev.Summary)
	}
	if strings.Contains(ev.Summary, strongPassphrase) || strings.Contains(ev.Summary, "ENCRYPTED-ENVELOPE-BYTES") {
		t.Errorf("audit summary %q leaks the passphrase or envelope", ev.Summary)
	}
	if ev.TargetKind != "node" || ev.TargetPath != "/nodes/A" {
		t.Errorf("audit target = (%q, %q), want (node, /nodes/A)", ev.TargetKind, ev.TargetPath)
	}
}

func TestExportCAKey_TPMNonExportable_MappedNoAudit(t *testing.T) {
	st := escrowTestStore()
	connA := &fakeConn{
		err: status.Error(codes.FailedPrecondition, "node: CA key is TPM-backed and non-exportable"),
	}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ExportCAKey(ctx, connect.NewRequest(&fleetv1.ExportCAKeyRequest{
		NodeName:   "A",
		Passphrase: []byte(strongPassphrase),
	}))
	if err == nil {
		t.Fatal("ExportCAKey(TPM node) error = nil, want FailedPrecondition")
	}
	ce := connErr(t, err)
	if ce.Code() != connect.CodeFailedPrecondition {
		t.Errorf("code = %v, want CodeFailedPrecondition", ce.Code())
	}
	if strings.Contains(ce.Message(), strongPassphrase) {
		t.Errorf("error message %q leaks the passphrase", ce.Message())
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event when export refused)", len(st.Audit()), before)
	}
}

// --- ImportCAKey ---

func TestImportCAKey_ViewerDenied_NoDialNoAudit(t *testing.T) {
	st := escrowTestStore()
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.ImportCAKey(ctx, connect.NewRequest(&fleetv1.ImportCAKeyRequest{
		NodeName:   "A",
		Envelope:   []byte("env"),
		Passphrase: []byte(strongPassphrase),
	}))
	if err == nil {
		t.Fatal("ImportCAKey(viewer) error = nil, want PermissionDenied")
	}
	if code := connErr(t, err).Code(); code != connect.CodePermissionDenied {
		t.Errorf("code = %v, want CodePermissionDenied", code)
	}
	if connA.gotImportEnvelope != nil {
		t.Error("node was dialed, want no call on denial")
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event on denial)", len(st.Audit()), before)
	}
}

func TestImportCAKey_EmptyEnvelope_InvalidArgument(t *testing.T) {
	st := escrowTestStore()
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ImportCAKey(ctx, connect.NewRequest(&fleetv1.ImportCAKeyRequest{
		NodeName:   "A",
		Envelope:   nil,
		Passphrase: []byte(strongPassphrase),
	}))
	if err == nil {
		t.Fatal("ImportCAKey(empty envelope) error = nil, want InvalidArgument")
	}
	if code := connErr(t, err).Code(); code != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want CodeInvalidArgument", code)
	}
	if connA.gotImportEnvelope != nil {
		t.Error("node was dialed on empty envelope, want no dial")
	}
}

func TestImportCAKey_ShortPassphrase_InvalidArgument(t *testing.T) {
	st := escrowTestStore()
	connA := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	short := []byte("short-secret")
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ImportCAKey(ctx, connect.NewRequest(&fleetv1.ImportCAKeyRequest{
		NodeName:   "A",
		Envelope:   []byte("env"),
		Passphrase: short,
	}))
	if err == nil {
		t.Fatal("ImportCAKey(short passphrase) error = nil, want InvalidArgument")
	}
	ce := connErr(t, err)
	if ce.Code() != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want CodeInvalidArgument", ce.Code())
	}
	if strings.Contains(ce.Message(), string(short)) {
		t.Errorf("error message %q echoes the passphrase", ce.Message())
	}
	if connA.gotImportEnvelope != nil {
		t.Error("node was dialed on a short passphrase, want no dial")
	}
}

func TestImportCAKey_UnknownNode_NotFound(t *testing.T) {
	st := escrowTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ImportCAKey(ctx, connect.NewRequest(&fleetv1.ImportCAKeyRequest{
		NodeName:   "missing",
		Envelope:   []byte("env"),
		Passphrase: []byte(strongPassphrase),
	}))
	if err == nil {
		t.Fatal("ImportCAKey(unknown node) error = nil, want NotFound")
	}
	if code := connErr(t, err).Code(); code != connect.CodeNotFound {
		t.Errorf("code = %v, want CodeNotFound", code)
	}
}

func TestImportCAKey_Admin_ReturnsCNsAndAudits(t *testing.T) {
	rootDER, rootCert, rootKey := signCert(t, "ACME Root CA", nil, nil)
	interDER, _, _ := signCert(t, "ACME Intermediate CA", rootCert, rootKey)

	st := escrowTestStore()
	connA := &fakeConn{
		importResp: &cryptosv1.ImportCAKeyResponse{
			Identity: &cryptosv1.Identity{ChainDer: [][]byte{interDER, rootDER}},
		},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.ImportCAKey(ctx, connect.NewRequest(&fleetv1.ImportCAKeyRequest{
		NodeName:   "A",
		Envelope:   []byte("ENCRYPTED-ENVELOPE-BYTES"),
		Passphrase: []byte(strongPassphrase),
	}))
	if err != nil {
		t.Fatalf("ImportCAKey(admin) error = %v, want nil", err)
	}

	if string(connA.gotImportEnvelope) != "ENCRYPTED-ENVELOPE-BYTES" {
		t.Errorf("node received envelope %q, want it relayed unchanged", connA.gotImportEnvelope)
	}
	if string(connA.gotImportPassphrase) != strongPassphrase {
		t.Errorf("node received passphrase %q, want it relayed unchanged", connA.gotImportPassphrase)
	}
	if resp.Msg.GetSubjectCn() != "ACME Intermediate CA" {
		t.Errorf("response subject CN = %q, want ACME Intermediate CA", resp.Msg.GetSubjectCn())
	}
	if resp.Msg.GetIssuerCn() != "ACME Root CA" {
		t.Errorf("response issuer CN = %q, want ACME Root CA", resp.Msg.GetIssuerCn())
	}
	if !connA.closed {
		t.Error("node connection was not closed")
	}

	audit := st.Audit()
	if len(audit) != 1 {
		t.Fatalf("audit len = %d, want 1", len(audit))
	}
	ev := audit[0]
	if ev.Kind != "ca-key-imported" {
		t.Errorf("audit kind = %q, want ca-key-imported", ev.Kind)
	}
	if !strings.Contains(ev.Summary, "A") || !strings.Contains(ev.Summary, "ACME Intermediate CA") {
		t.Errorf("audit summary %q should name the node and restored subject", ev.Summary)
	}
	if strings.Contains(ev.Summary, strongPassphrase) || strings.Contains(ev.Summary, "ENCRYPTED-ENVELOPE-BYTES") {
		t.Errorf("audit summary %q leaks the passphrase or envelope", ev.Summary)
	}
	if ev.TargetKind != "node" || ev.TargetPath != "/nodes/A" {
		t.Errorf("audit target = (%q, %q), want (node, /nodes/A)", ev.TargetKind, ev.TargetPath)
	}
}

func TestImportCAKey_IdentityExists_MappedNoAudit(t *testing.T) {
	st := escrowTestStore()
	connA := &fakeConn{
		err: status.Error(codes.FailedPrecondition, "node: target already holds a CA identity"),
	}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA}))

	before := len(st.Audit())
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ImportCAKey(ctx, connect.NewRequest(&fleetv1.ImportCAKeyRequest{
		NodeName:   "A",
		Envelope:   []byte("env"),
		Passphrase: []byte(strongPassphrase),
	}))
	if err == nil {
		t.Fatal("ImportCAKey(identity exists) error = nil, want FailedPrecondition")
	}
	ce := connErr(t, err)
	if ce.Code() != connect.CodeFailedPrecondition {
		t.Errorf("code = %v, want CodeFailedPrecondition", ce.Code())
	}
	if !strings.Contains(ce.Message(), "fresh") {
		t.Errorf("error message %q should guide the operator to a fresh node", ce.Message())
	}
	if strings.Contains(ce.Message(), strongPassphrase) {
		t.Errorf("error message %q leaks the passphrase", ce.Message())
	}
	if len(st.Audit()) != before {
		t.Errorf("audit len = %d, want %d (no event when import refused)", len(st.Audit()), before)
	}
}

// TestEscrow_AuditNeverContainsPassphrase drives both operations end to end and
// asserts no audit summary contains the passphrase.
func TestEscrow_AuditNeverContainsPassphrase(t *testing.T) {
	rootDER, _, _ := signCert(t, "ACME Root CA", nil, nil)

	st := escrowTestStore()
	connA := &fakeConn{exportResp: &cryptosv1.ExportCAKeyResponse{Envelope: []byte("env")}}
	connB := &fakeConn{importResp: &cryptosv1.ImportCAKeyResponse{
		Identity: &cryptosv1.Identity{ChainDer: [][]byte{rootDER}},
	}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": connA, "B": connB}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	if _, err := svc.ExportCAKey(ctx, connect.NewRequest(&fleetv1.ExportCAKeyRequest{
		NodeName: "A", Passphrase: []byte(strongPassphrase),
	})); err != nil {
		t.Fatalf("ExportCAKey error = %v", err)
	}
	if _, err := svc.ImportCAKey(ctx, connect.NewRequest(&fleetv1.ImportCAKeyRequest{
		NodeName: "B", Envelope: []byte("env"), Passphrase: []byte(strongPassphrase),
	})); err != nil {
		t.Fatalf("ImportCAKey error = %v", err)
	}

	for _, ev := range st.Audit() {
		if strings.Contains(ev.Summary, strongPassphrase) {
			t.Errorf("audit summary %q contains the passphrase", ev.Summary)
		}
	}
}
