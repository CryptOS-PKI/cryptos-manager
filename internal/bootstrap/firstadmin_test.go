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
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/operatorca"
	"github.com/CryptOS-PKI/manager/internal/store"
)

// registered is a harness with a session that registered and confirmed ca.
func registered(t *testing.T) (*harness, string, testCA) {
	t.Helper()
	h := newHarness(t)
	secret := h.startSession()
	ca := newCA(t, "Example Operator CA")
	h.registerCA(secret, ca)
	return h, secret, ca
}

func TestSubmit_WithACSR(t *testing.T) {
	h, secret, ca := registered(t)
	key := p384(t)
	cert := ca.leaf(t, leafOpts{key: key})

	t.Run("key mismatch", func(t *testing.T) {
		_, err := h.clientFrom("192.0.2.21:1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
			&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: cert.Raw, CsrDer: csrDER(t, p384(t), "admin@example.org"), FullName: "Ada Example"}))
		wantCode(t, err, apperr.CodeCertRejected, "KEY_MISMATCH")
	})
	t.Run("CSR subject", func(t *testing.T) {
		_, err := h.clientFrom("192.0.2.22:1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
			&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: cert.Raw, CsrDer: csrDER(t, key, "Ada Example"), FullName: "Ada Example"}))
		wantCode(t, err, apperr.CodeCSRRejected, "SUBJECT_MISMATCH")
	})
	t.Run("P-256 CSR", func(t *testing.T) {
		_, err := h.clientFrom("192.0.2.23:1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
			&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: cert.Raw, CsrDer: csrDER(t, p256(t), "admin@example.org"), FullName: "Ada Example"}))
		wantCode(t, err, apperr.CodeCSRRejected, "KEY_TYPE")
	})
	t.Run("CSR for another email", func(t *testing.T) {
		_, err := h.clientFrom("192.0.2.24:1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
			&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: cert.Raw, CsrDer: csrDER(t, key, "other@example.org"), FullName: "Ada Example"}))
		wantCode(t, err, apperr.CodeCertRejected, "SUBJECT_MISMATCH")
	})
	t.Run("matching", func(t *testing.T) {
		resp, err := h.clientFrom("192.0.2.25:1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
			&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: cert.Raw, CsrDer: csrDER(t, key, "admin@example.org"), FullName: "Ada Example"}))
		if err != nil {
			t.Fatalf("a matching certificate and CSR were refused: %v", err)
		}
		if resp.Msg.GetEmail() != "admin@example.org" || resp.Msg.GetIssuerSha256() != operatorca.Fingerprint(ca.cert) ||
			resp.Msg.GetSerialHex() != operatorca.SerialKey(cert.SerialNumber) || resp.Msg.GetNotAfter() == "" {
			t.Fatalf("response = %+v", resp.Msg)
		}
	})
}

func TestSubmit_PathBPreflightRunsTheSameChecks(t *testing.T) {
	h, secret, ca := registered(t)
	for i, tc := range []struct {
		name   string
		opts   leafOpts
		reason string
	}{
		{"operator level", leafOpts{level: "operator"}, "WRONG_LEVEL"},
		{"critical level", leafOpts{critical: true}, "LEVEL_EXT_CRITICAL"},
		{"P-256 key", leafOpts{key: p256(t)}, "KEY_TYPE"},
		{"not an email", leafOpts{cn: "Ada Example"}, "SUBJECT_MISMATCH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.clientFrom("192.0.2.3"+strconv.Itoa(i)+":1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
				&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: ca.leaf(t, tc.opts).Raw, FullName: "Ada Example"}))
			wantCode(t, err, apperr.CodeCertRejected, tc.reason)
		})
	}
	other := newCA(t, "Example Other CA")
	_, err := h.clientFrom("192.0.2.39:1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
		&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: other.leaf(t, leafOpts{}).Raw, FullName: "Ada Example"}))
	wantCode(t, err, apperr.CodeCertRejected, "NOT_CHAINED")

	if _, err := h.submit(secret, &fleetv1.SubmitFirstAdminCertificateRequest{CertDer: ca.leaf(t, leafOpts{}).Raw, FullName: "Ada Example"}); err != nil {
		t.Fatalf("a good certificate with no CSR was refused: %v", err)
	}
}

func TestSubmit_RecordsTheFirstAdminAndAudits(t *testing.T) {
	h, secret, ca := registered(t)
	cert := ca.leaf(t, leafOpts{cn: "admin@example.org"})
	if _, err := h.submit(secret, &fleetv1.SubmitFirstAdminCertificateRequest{CertDer: cert.Raw, FullName: "Ada Example"}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	creds, _ := h.st.FirstAdminCredentials(h.ctx)
	if len(creds) != 1 {
		t.Fatalf("first admin records = %+v", creds)
	}
	c := creds[0]
	if c.Kind != store.OperatorCredentialFirstAdmin || c.IssuerSHA256 != operatorca.Fingerprint(ca.cert) || c.Email != "admin@example.org" ||
		c.FullName != "Ada Example" || c.CommonName != "admin@example.org" || c.Level != "admin" || c.LeafSHA256 != operatorca.Fingerprint(cert) ||
		c.SerialHex != operatorca.SerialKey(cert.SerialNumber) || c.NotAfter == "" {
		t.Fatalf("record = %+v", c)
	}
	rows := h.auditKinds(KindFirstAdminRecorded)
	if len(rows) != 1 || rows[0].ActorKind != ActorBootstrapSession || !strings.Contains(rows[0].Summary, "admin@example.org") ||
		!strings.Contains(rows[0].Summary, c.SerialHex) || !strings.Contains(rows[0].Summary, "192.0.2.10") {
		t.Fatalf("audit = %+v", rows)
	}
}

// The first-run code has no way to reach a node: it never imports the node
// client or the fleet service that dials nodes.
func TestPackage_NeverDialsANode(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.HasSuffix(p, "/internal/nodeclient") || strings.HasSuffix(p, "/internal/fleet") {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
}

func TestSubmit_SupersedeDenylistsTheEarlierFirstAdmin(t *testing.T) {
	h, secret, ca := registered(t)
	first := ca.leaf(t, leafOpts{})
	second := ca.leaf(t, leafOpts{})
	if _, err := h.submit(secret, &fleetv1.SubmitFirstAdminCertificateRequest{CertDer: first.Raw, FullName: "Ada Example"}); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	// The same certificate again is not a supersede.
	if _, err := h.submit(secret, &fleetv1.SubmitFirstAdminCertificateRequest{CertDer: first.Raw, FullName: "Ada Example"}); err != nil {
		t.Fatalf("repeat submit: %v", err)
	}
	if h.rev.Denylisted(operatorca.Fingerprint(ca.cert), operatorca.SerialKey(first.SerialNumber)) {
		t.Fatal("submitting the same certificate twice denylisted it")
	}
	if _, err := h.submit(secret, &fleetv1.SubmitFirstAdminCertificateRequest{CertDer: second.Raw, FullName: "Ada Example"}); err != nil {
		t.Fatalf("second submit: %v", err)
	}
	if !h.rev.Denylisted(operatorca.Fingerprint(ca.cert), operatorca.SerialKey(first.SerialNumber)) {
		t.Fatal("the superseded first-admin certificate isn't on the denylist")
	}
	entries, _ := h.st.OperatorDenylist(h.ctx)
	if len(entries) != 1 || entries[0].Reason != 4 {
		t.Fatalf("denylist = %+v; want one entry with reason 4 (superseded)", entries)
	}
	auth := operatorca.PeerAuthorizer{Trust: h.trust, Rev: h.rev}
	if _, err := auth.AuthorizePeer(first, nil); err == nil {
		t.Fatal("the superseded certificate still authenticates on its next request")
	} else if apperr.ReasonName(mustReason(err)) != "REVOKED" {
		t.Fatalf("refusal = %v; want REVOKED", err)
	}
	if _, err := auth.AuthorizePeer(second, nil); err != nil {
		t.Fatalf("the newer first-admin certificate was refused: %v", err)
	}
	if len(h.auditKinds(KindFirstAdminSuperseded)) != 1 {
		t.Fatal("the supersede wasn't audited")
	}
}

func mustReason(err error) fleetv1.ErrorReason {
	r, _ := apperr.ReasonOf(err)
	return r
}

func TestSubmit_NameAndEmailValidation(t *testing.T) {
	h, secret, ca := registered(t)
	cert := ca.leaf(t, leafOpts{cn: "Admin@Example.org"})
	for i, tc := range []struct {
		name string
		full string
		ok   bool
	}{
		{"empty", "", false},
		{"too long", strings.Repeat("a", 129), false},
		{"control character", "Ada\u0007Example", false},
		{"newline", "Ada\nExample", false},
		{"128 characters", strings.Repeat("é", 128), true},
		{"plain", "Ada Example", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := h.clientFrom("192.0.2.4"+strconv.Itoa(i)+":1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
				&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: cert.Raw, FullName: tc.full}))
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if resp.Msg.GetEmail() != "admin@example.org" {
					t.Fatalf("email = %q, want the CN lower-cased", resp.Msg.GetEmail())
				}
				return
			}
			wantCode(t, err, apperr.CodeCertRejected, "")
		})
	}
	for i, cn := range []string{"Ada <admin@example.org>", "not-an-email", strings.Repeat("a", 250) + "@example.org"} {
		_, err := h.clientFrom("192.0.2.5"+strconv.Itoa(i)+":1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
			&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: ca.leaf(t, leafOpts{cn: cn}).Raw, FullName: "Ada Example"}))
		wantCode(t, err, apperr.CodeCertRejected, "SUBJECT_MISMATCH")
	}
}

func TestSubmit_RefusesAMalformedUpload(t *testing.T) {
	h, secret, ca := registered(t)
	two := append(append([]byte{}, ca.leaf(t, leafOpts{}).Raw...), ca.leaf(t, leafOpts{}).Raw...)
	for i, der := range [][]byte{nil, []byte("junk"), two, make([]byte, 8<<10+1)} {
		_, err := h.clientFrom("192.0.2.6"+strconv.Itoa(i)+":1", true).SubmitFirstAdminCertificate(h.ctx, withSession(secret,
			&fleetv1.SubmitFirstAdminCertificateRequest{CertDer: der, FullName: "Ada Example"}))
		wantCode(t, err, apperr.CodeCertRejected, "")
	}
}

// Protobuf refuses invalid UTF-8 in a string field before the handler runs,
// so the name check's UTF-8 rule is exercised directly.
func TestValidFullName(t *testing.T) {
	for s, want := range map[string]bool{
		"Ada Example": true, "": false, string([]byte{0xff, 0xfe}): false, "Ada\tExample": false,
		strings.Repeat("a", 128): true, strings.Repeat("a", 129): false,
	} {
		if got := validFullName(s); got != want {
			t.Errorf("validFullName(%q) = %v, want %v", s, got, want)
		}
	}
}
