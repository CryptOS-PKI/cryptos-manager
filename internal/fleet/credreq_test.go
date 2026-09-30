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
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/operatorca"
	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"github.com/google/uuid"
)

func adminCtx() context.Context { return operatorCtx("admin@example.org", authz.LevelAdmin) }

func requireReason(t *testing.T, err error, code int, reason fleetv1.ErrorReason) {
	t.Helper()
	if got, ok := apperr.Code(err); !ok || got != code {
		t.Fatalf("error = %v, want code %d", err, code)
	}
	if got, _ := apperr.ReasonOf(err); got != reason {
		t.Fatalf("reason = %v, want %v (%v)", got, reason, err)
	}
}

func auditKinds(st interface{ Audit() []store.AuditEvent }) []string {
	var out []string
	for _, e := range st.Audit() {
		out = append(out, e.Kind)
	}
	return out
}

// credFixture is a manager with one active operator CA over a store that
// supports credential requests.
type credFixture struct {
	st   *credStore
	ca   testCA
	svc  *Service
	auth operatorca.PeerAuthorizer
}

func newCredFixture(t *testing.T, extra ...operatorca.Anchor) credFixture {
	t.Helper()
	st := newCredStore()
	ca := newTestCA(t, "Example Operator CA")
	svc, auth := withAnchors(t, New(st, noDial(t)), st, append([]operatorca.Anchor{ca.anchor(store.OperatorCAActive)}, extra...)...)
	return credFixture{st: st, ca: ca, svc: svc, auth: auth}
}

func (f credFixture) create(t *testing.T, level, email string) (*fleetv1.CreateOperatorCredentialRequestResponse, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	csr, key := newCSR(t, email, false)
	resp, err := f.svc.CreateOperatorCredentialRequest(adminCtx(), connect.NewRequest(&fleetv1.CreateOperatorCredentialRequestRequest{
		Level: level, Email: email, FullName: "Alice Example", CsrDer: csr,
	}))
	if err != nil {
		t.Fatalf("CreateOperatorCredentialRequest: %v", err)
	}
	return resp.Msg, csr, key
}

// A credential request checks the CSR, is stored pending for 30 days, and
// hands back the CSR, the level's extension section and the signing command.
func TestCreateOperatorCredentialRequest_StoresPendingAndReturnsTheRecipe(t *testing.T) {
	f := newCredFixture(t)
	before := time.Now()
	resp, csr, _ := f.create(t, "operator", "alice@example.org")

	if _, err := uuid.Parse(resp.GetRequestId()); err != nil {
		t.Fatalf("request_id %q is not a UUID", resp.GetRequestId())
	}
	block, _ := pem.Decode([]byte(resp.GetCsrPem()))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || string(block.Bytes) != string(csr) {
		t.Fatalf("csr_pem = %q, want the CSR", resp.GetCsrPem())
	}
	wantSection, _ := operatorca.ExtfileSection("operator")
	if resp.GetExtfileSection() != wantSection {
		t.Fatalf("extfile_section = %q, want %q", resp.GetExtfileSection(), wantSection)
	}
	if resp.GetOpensslCommand() != operatorca.SignCommand("operator", "alice@example.org") {
		t.Fatalf("openssl_command = %q", resp.GetOpensslCommand())
	}
	exp, err := time.Parse(time.RFC3339, resp.GetExpiresAt())
	if err != nil || exp.Before(before.Add(30*24*time.Hour-time.Minute)) || exp.After(time.Now().Add(30*24*time.Hour+time.Minute)) {
		t.Fatalf("expires_at = %q, want 30 days out", resp.GetExpiresAt())
	}

	r, err := f.st.OperatorCredentialRequest(context.Background(), resp.GetRequestId(), time.Now())
	if err != nil || r.State != store.RequestPending || r.Level != "operator" || r.Email != "alice@example.org" ||
		r.FullName != "Alice Example" || string(r.CSRDER) != string(csr) || r.CreatedByCN != "admin@example.org" {
		t.Fatalf("stored request = %+v, %v", r, err)
	}
	if kinds := auditKinds(f.st); len(kinds) != 1 || kinds[0] != "operator-credential-requested" {
		t.Fatalf("audit = %v", kinds)
	}
}

// Only an admin may request a credential.
func TestCreateOperatorCredentialRequest_AdminOnly(t *testing.T) {
	f := newCredFixture(t)
	csr, _ := newCSR(t, "alice@example.org", false)
	_, err := f.svc.CreateOperatorCredentialRequest(operatorCtx("op@example.org", authz.LevelOperator),
		connect.NewRequest(&fleetv1.CreateOperatorCredentialRequestRequest{Level: "viewer", Email: "alice@example.org", FullName: "Alice", CsrDer: csr}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if reqs, _ := f.st.OperatorCredentialRequests(context.Background(), "", time.Now()); len(reqs) != 0 {
		t.Fatalf("a refused request was stored: %+v", reqs)
	}
}

func TestCreateOperatorCredentialRequest_Refusals(t *testing.T) {
	f := newCredFixture(t)
	good, _ := newCSR(t, "alice@example.org", false)
	weak, _ := newCSR(t, "alice@example.org", true)
	call := func(level, email, name string, csr []byte) error {
		_, err := f.svc.CreateOperatorCredentialRequest(adminCtx(), connect.NewRequest(&fleetv1.CreateOperatorCredentialRequestRequest{
			Level: level, Email: email, FullName: name, CsrDer: csr,
		}))
		return err
	}

	requireReason(t, call("operator", "alice@example.org", "Alice", weak), apperr.CodeCSRRejected, fleetv1.ErrorReason_ERROR_REASON_KEY_TYPE)
	requireReason(t, call("operator", "bob@example.org", "Bob", good), apperr.CodeCSRRejected, fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH)
	requireReason(t, call("operator", "alice@example.org", "Alice", []byte("junk")), apperr.CodeCSRRejected, fleetv1.ErrorReason_ERROR_REASON_SIGNATURE)
	requireConnectCode(t, call("root", "alice@example.org", "Alice", good), connect.CodeInvalidArgument)
	requireConnectCode(t, call("operator", "alice@example.org", "", good), connect.CodeInvalidArgument)
	requireConnectCode(t, call("operator", "alice@example.org", "Alice\x07", good), connect.CodeInvalidArgument)
	requireConnectCode(t, call("operator", "alice@example.org", strings.Repeat("a", 129), good), connect.CodeInvalidArgument)
	if err := call("operator", "Alice@Example.org", "Alice", good); err != nil {
		t.Fatalf("the email is compared case-insensitively: %v", err)
	}
}

func TestCreateOperatorCredentialRequest_NeedsASourceAndPostgres(t *testing.T) {
	csr, _ := newCSR(t, "alice@example.org", false)
	req := &fleetv1.CreateOperatorCredentialRequestRequest{Level: "viewer", Email: "alice@example.org", FullName: "Alice", CsrDer: csr}

	_, err := New(operatorsStore(), noDial(t)).CreateOperatorCredentialRequest(adminCtx(), connect.NewRequest(req))
	if code, _ := apperr.Code(err); code != apperr.CodeOperatorCAUnconfigured {
		t.Fatalf("no operator CA: error = %v, want 1400", err)
	}

	st := memory.New(nil)
	svc, _ := withAnchors(t, New(st, noDial(t)), st, newTestCA(t, "Example Operator CA").anchor(store.OperatorCAActive))
	_, err = svc.CreateOperatorCredentialRequest(adminCtx(), connect.NewRequest(req))
	requireReason(t, err, apperr.CodeUnavailable, fleetv1.ErrorReason_ERROR_REASON_DATABASE_REQUIRED)
}

// Listing requests is operator-readable, newest first, filterable by state.
func TestListOperatorCredentialRequests(t *testing.T) {
	f := newCredFixture(t)
	first, _, _ := f.create(t, "viewer", "alice@example.org")
	second, _, _ := f.create(t, "admin", "bob@example.org")
	if _, err := f.svc.CancelOperatorCredentialRequest(adminCtx(), connect.NewRequest(&fleetv1.CancelOperatorCredentialRequestRequest{RequestId: first.GetRequestId()})); err != nil {
		t.Fatal(err)
	}

	opCtx := operatorCtx("op@example.org", authz.LevelOperator)
	resp, err := f.svc.ListOperatorCredentialRequests(opCtx, connect.NewRequest(&fleetv1.ListOperatorCredentialRequestsRequest{}))
	if err != nil {
		t.Fatalf("ListOperatorCredentialRequests: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 2 || items[0].GetId() != second.GetRequestId() || items[1].GetId() != first.GetRequestId() {
		t.Fatalf("items = %+v, want newest first", items)
	}
	if p := items[0]; p.GetState() != store.RequestPending || p.GetLevel() != "admin" || p.GetEmail() != "bob@example.org" ||
		p.GetFullName() != "Alice Example" || !strings.Contains(p.GetCsrPem(), "CERTIFICATE REQUEST") || p.GetCreatedByCn() != "admin@example.org" ||
		p.GetCreatedAt() == "" || p.GetExpiresAt() == "" {
		t.Fatalf("pending item = %+v", p)
	}
	if c := items[1]; c.GetState() != store.RequestCancelled || c.GetCsrPem() != "" {
		t.Fatalf("cancelled item = %+v, want no CSR", c)
	}

	resp, err = f.svc.ListOperatorCredentialRequests(opCtx, connect.NewRequest(&fleetv1.ListOperatorCredentialRequestsRequest{State: "pending"}))
	if err != nil || len(resp.Msg.GetItems()) != 1 || resp.Msg.GetItems()[0].GetId() != second.GetRequestId() {
		t.Fatalf("pending filter = %+v, %v", resp, err)
	}
	_, err = f.svc.ListOperatorCredentialRequests(opCtx, connect.NewRequest(&fleetv1.ListOperatorCredentialRequestsRequest{State: "bogus"}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	_, err = f.svc.ListOperatorCredentialRequests(operatorCtx("v@example.org", authz.LevelViewer), connect.NewRequest(&fleetv1.ListOperatorCredentialRequestsRequest{}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

// Cancelling is admin-only, audited, and refuses a request that isn't
// pending.
func TestCancelOperatorCredentialRequest(t *testing.T) {
	f := newCredFixture(t)
	created, _, _ := f.create(t, "viewer", "alice@example.org")
	req := connect.NewRequest(&fleetv1.CancelOperatorCredentialRequestRequest{RequestId: created.GetRequestId()})

	_, err := f.svc.CancelOperatorCredentialRequest(operatorCtx("op@example.org", authz.LevelOperator), req)
	requireConnectCode(t, err, connect.CodePermissionDenied)

	resp, err := f.svc.CancelOperatorCredentialRequest(adminCtx(), req)
	if err != nil || resp.Msg.GetRequest().GetState() != store.RequestCancelled || resp.Msg.GetRequest().GetCsrPem() != "" {
		t.Fatalf("CancelOperatorCredentialRequest = %+v, %v", resp, err)
	}
	if kinds := auditKinds(f.st); len(kinds) != 2 || kinds[1] != "operator-credential-request-cancelled" {
		t.Fatalf("audit = %v", kinds)
	}
	_, err = f.svc.CancelOperatorCredentialRequest(adminCtx(), req)
	requireReason(t, err, apperr.CodeRequestInvalid, fleetv1.ErrorReason_ERROR_REASON_NOT_PENDING)
	_, err = f.svc.CancelOperatorCredentialRequest(adminCtx(), connect.NewRequest(&fleetv1.CancelOperatorCredentialRequestRequest{RequestId: uuid.NewString()}))
	requireReason(t, err, apperr.CodeRequestInvalid, fleetv1.ErrorReason_ERROR_REASON_NOT_FOUND)
}

// Recording against a request checks the certificate against it, records it
// as requested, completes the request and drops its CSR.
func TestRecordOperatorCredential_CompletesTheRequest(t *testing.T) {
	f := newCredFixture(t)
	created, _, key := f.create(t, "operator", "alice@example.org")
	cert := f.ca.leaf(t, &key.PublicKey, "alice@example.org", "operator", 0x51)

	resp, err := f.svc.RecordOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{
		CertDer: cert.Raw, RequestId: created.GetRequestId(),
	}))
	if err != nil {
		t.Fatalf("RecordOperatorCredential: %v", err)
	}
	fp := operatorca.Fingerprint(f.ca.cert)
	sum := sha256.Sum256(cert.Raw)
	got := resp.Msg.GetCredential()
	if got.GetKind() != store.OperatorCredentialRequested || got.GetIssuerSha256() != fp || got.GetSerialHex() != "51" ||
		got.GetLevel() != "operator" || got.GetEmail() != "alice@example.org" || got.GetCommonName() != "alice@example.org" ||
		got.GetFullName() != "Alice Example" || got.GetNotAfter() != cert.NotAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("credential = %+v", got)
	}

	r, _ := f.st.OperatorCredentialRequest(context.Background(), created.GetRequestId(), time.Now())
	if r.State != store.RequestCompleted || r.CSRDER != nil || r.CompletedSerial != "51" {
		t.Fatalf("request after record = %+v", r)
	}
	rows := f.st.OperatorCredentials()
	if len(rows) != 1 || rows[0].LeafSHA256 != hex.EncodeToString(sum[:]) || rows[0].RequestID != created.GetRequestId() {
		t.Fatalf("stored credential = %+v", rows)
	}
	if kinds := auditKinds(f.st); kinds[len(kinds)-1] != "operator-credential-recorded" {
		t.Fatalf("audit = %v", kinds)
	}
}

func TestRecordOperatorCredential_MustMatchTheRequest(t *testing.T) {
	f := newCredFixture(t)
	created, _, key := f.create(t, "operator", "alice@example.org")
	_, otherKey := newCSR(t, "alice@example.org", false)
	_, bobKey := newCSR(t, "bob@example.org", false)
	record := func(certDER []byte) error {
		_, err := f.svc.RecordOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{
			CertDer: certDER, RequestId: created.GetRequestId(),
		}))
		return err
	}

	requireReason(t, record(f.ca.leaf(t, &key.PublicKey, "alice@example.org", "admin", 1).Raw),
		apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_WRONG_LEVEL)
	requireReason(t, record(f.ca.leaf(t, &bobKey.PublicKey, "bob@example.org", "operator", 2).Raw),
		apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_SUBJECT_MISMATCH)
	requireReason(t, record(f.ca.leaf(t, &otherKey.PublicKey, "alice@example.org", "operator", 3).Raw),
		apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_KEY_MISMATCH)
	if rows := f.st.OperatorCredentials(); len(rows) != 0 {
		t.Fatalf("a mismatched certificate was recorded: %+v", rows)
	}
}

// A request that is expired, cancelled or completed can't be recorded
// against (1611), and an unknown one is NOT_FOUND.
func TestRecordOperatorCredential_RequestNotUsable(t *testing.T) {
	f := newCredFixture(t)
	record := func(id string, certDER []byte) error {
		_, err := f.svc.RecordOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{CertDer: certDER, RequestId: id}))
		return err
	}

	done, _, doneKey := f.create(t, "viewer", "alice@example.org")
	if err := record(done.GetRequestId(), f.ca.leaf(t, &doneKey.PublicKey, "alice@example.org", "viewer", 10).Raw); err != nil {
		t.Fatal(err)
	}
	requireReason(t, record(done.GetRequestId(), f.ca.leaf(t, &doneKey.PublicKey, "alice@example.org", "viewer", 11).Raw),
		apperr.CodeRequestInvalid, fleetv1.ErrorReason_ERROR_REASON_NOT_PENDING)

	cancelled, _, cKey := f.create(t, "viewer", "alice@example.org")
	if _, err := f.svc.CancelOperatorCredentialRequest(adminCtx(), connect.NewRequest(&fleetv1.CancelOperatorCredentialRequestRequest{RequestId: cancelled.GetRequestId()})); err != nil {
		t.Fatal(err)
	}
	requireReason(t, record(cancelled.GetRequestId(), f.ca.leaf(t, &cKey.PublicKey, "alice@example.org", "viewer", 12).Raw),
		apperr.CodeRequestInvalid, fleetv1.ErrorReason_ERROR_REASON_NOT_PENDING)

	expired, _, eKey := f.create(t, "viewer", "alice@example.org")
	f.st.mu.Lock()
	r := f.st.requests[expired.GetRequestId()]
	r.ExpiresAt = time.Now().Add(-time.Second)
	f.st.requests[expired.GetRequestId()] = r
	f.st.mu.Unlock()
	requireReason(t, record(expired.GetRequestId(), f.ca.leaf(t, &eKey.PublicKey, "alice@example.org", "viewer", 13).Raw),
		apperr.CodeRequestInvalid, fleetv1.ErrorReason_ERROR_REASON_EXPIRED)

	requireReason(t, record(uuid.NewString(), f.ca.leaf(t, &eKey.PublicKey, "alice@example.org", "viewer", 14).Raw),
		apperr.CodeRequestInvalid, fleetv1.ErrorReason_ERROR_REASON_NOT_FOUND)
}

// Without a request an out-of-band certificate is imported, with the level
// read from its extension. It must come from the active operator CA and not
// be recorded already.
func TestRecordOperatorCredential_ImportsOutOfBand(t *testing.T) {
	retiring := newTestCA(t, "Example Old Operator CA")
	f := newCredFixture(t, retiring.anchor(store.OperatorCARetiring))
	_, key := newCSR(t, "carol@example.org", false)
	cert := f.ca.leaf(t, &key.PublicKey, "carol@example.org", "admin", 0x77)
	req := connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{CertDer: cert.Raw, FullName: "Carol Example"})

	resp, err := f.svc.RecordOperatorCredential(adminCtx(), req)
	if err != nil {
		t.Fatalf("RecordOperatorCredential: %v", err)
	}
	if c := resp.Msg.GetCredential(); c.GetKind() != store.OperatorCredentialRecorded || c.GetLevel() != "admin" ||
		c.GetFullName() != "Carol Example" || c.GetIssuerSha256() != operatorca.Fingerprint(f.ca.cert) {
		t.Fatalf("credential = %+v", c)
	}

	_, err = f.svc.RecordOperatorCredential(adminCtx(), req)
	requireReason(t, err, apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_DUPLICATE)

	old := retiring.leaf(t, &key.PublicKey, "carol@example.org", "admin", 0x78)
	_, err = f.svc.RecordOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{CertDer: old.Raw}))
	requireReason(t, err, apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_NOT_ACTIVE_ANCHOR)

	stranger := newTestCA(t, "Example Unknown CA").leaf(t, &key.PublicKey, "carol@example.org", "admin", 0x79)
	_, err = f.svc.RecordOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{CertDer: stranger.Raw}))
	requireReason(t, err, apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_NOT_CHAINED)
}

// A certificate on the denylist can't be recorded.
func TestRecordOperatorCredential_RefusesADeniedCertificate(t *testing.T) {
	f := newCredFixture(t)
	_, key := newCSR(t, "dave@example.org", false)
	cert := f.ca.leaf(t, &key.PublicKey, "dave@example.org", "viewer", 0x99)
	if _, err := f.svc.RevokeOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RevokeOperatorCredentialRequest{SerialHex: "99"})); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.RecordOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{CertDer: cert.Raw}))
	requireReason(t, err, apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED)
}

func TestRecordOperatorCredential_InputBounds(t *testing.T) {
	f := newCredFixture(t)
	_, key := newCSR(t, "erin@example.org", false)
	cert := f.ca.leaf(t, &key.PublicKey, "erin@example.org", "viewer", 0x21)
	for name, der := range map[string][]byte{
		"empty":      nil,
		"not a cert": []byte("junk"),
		"two certs":  append(append([]byte{}, cert.Raw...), cert.Raw...),
		"oversized":  make([]byte, 8<<10+1),
	} {
		_, err := f.svc.RecordOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{CertDer: der}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: error = %v, want InvalidArgument", name, err)
		}
	}
	_, err := f.svc.RecordOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{CertDer: cert.Raw, FullName: "Erin\n"}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	_, err = f.svc.RecordOperatorCredential(operatorCtx("op@example.org", authz.LevelOperator), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{CertDer: cert.Raw}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

func TestRecordOperatorCredential_NeedsPostgres(t *testing.T) {
	st := memory.New(nil)
	ca := newTestCA(t, "Example Operator CA")
	svc, _ := withAnchors(t, New(st, noDial(t)), st, ca.anchor(store.OperatorCAActive))
	_, key := newCSR(t, "erin@example.org", false)
	_, err := svc.RecordOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{
		CertDer: ca.leaf(t, &key.PublicKey, "erin@example.org", "viewer", 5).Raw,
	}))
	requireReason(t, err, apperr.CodeUnavailable, fleetv1.ErrorReason_ERROR_REASON_DATABASE_REQUIRED)
}

// Revoking a recorded credential denies it under its issuer, keeps the note,
// and the next request with the certificate is refused.
func TestRevokeOperatorCredential_RefusesTheNextRequest(t *testing.T) {
	f := newCredFixture(t)
	_, key := newCSR(t, "frank@example.org", false)
	cert := f.ca.leaf(t, &key.PublicKey, "frank@example.org", "operator", 0x3c)
	if _, err := f.svc.RecordOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{CertDer: cert.Raw})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.auth.AuthorizePeer(cert, nil); err != nil {
		t.Fatalf("before revoking: %v", err)
	}

	resp, err := f.svc.RevokeOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RevokeOperatorCredentialRequest{
		SerialHex: "3C", ReasonCode: 1, Note: "laptop lost",
	}))
	if err != nil {
		t.Fatalf("RevokeOperatorCredential: %v", err)
	}
	if resp.Msg.GetIssuerSha256() != operatorca.Fingerprint(f.ca.cert) || len(resp.Msg.GetWarnings()) != 1 ||
		!strings.Contains(resp.Msg.GetWarnings()[0], "operator CA") {
		t.Fatalf("response = %+v", resp.Msg)
	}
	if e := f.st.entries; len(e) != 1 || e[0].Note != "laptop lost" || e[0].Reason != 1 {
		t.Fatalf("denylist = %+v", e)
	}
	_, err = f.auth.AuthorizePeer(cert, nil)
	requireReason(t, err, apperr.CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED)
}

func TestRevokeOperatorCredential_ValidatesInput(t *testing.T) {
	f := newCredFixture(t)
	for name, req := range map[string]*fleetv1.RevokeOperatorCredentialRequest{
		"not hex":        {SerialHex: "xyz"},
		"reason 7":       {SerialHex: "01", ReasonCode: 7},
		"reason 11":      {SerialHex: "01", ReasonCode: 11},
		"negative":       {SerialHex: "01", ReasonCode: -1},
		"issuer not hex": {SerialHex: "01", IssuerSha256: "not-a-fingerprint"},
	} {
		_, err := f.svc.RevokeOperatorCredential(adminCtx(), connect.NewRequest(req))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: error = %v, want InvalidArgument", name, err)
		}
	}
	if len(f.st.entries) != 0 {
		t.Fatalf("an invalid revoke was written: %+v", f.st.entries)
	}
}

// The list carries when a credential was first and last seen in use.
func TestListOperatorCredentials_SeenTimes(t *testing.T) {
	f := newCredFixture(t)
	first := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	f.st.AddOperatorCredential(store.OperatorCredential{
		CommonName: "gina@example.org", SerialHex: "7", Level: "viewer", NotAfter: "2027-01-01T00:00:00Z",
		IssuerSHA256: operatorca.Fingerprint(f.ca.cert), Kind: store.OperatorCredentialObserved,
		FirstSeenAt: first, LastSeenAt: first.Add(time.Hour),
	})
	resp, err := f.svc.ListOperatorCredentials(operatorCtx("op@example.org", authz.LevelOperator), connect.NewRequest(&fleetv1.ListOperatorCredentialsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if c := resp.Msg.GetItems()[0]; c.GetKind() != store.OperatorCredentialObserved || c.GetFirstSeenAt() != "2026-09-30T12:00:00Z" || c.GetLastSeenAt() != "2026-09-30T13:00:00Z" {
		t.Fatalf("item = %+v", c)
	}
}
