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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/approval"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// requestableProfile stores cp in the catalog, marks it requestable, and
// returns a store with one node, "pki-issuing".
func requestableProfile(t *testing.T, cp *nodev1.CertificateProfile) store.Store {
	t.Helper()
	st := nodeStore("pki-issuing")
	if err := st.CreateProfile(storeProfile(t, cp)); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	if _, err := st.SetProfileRequestable(cp.GetName(), true); err != nil {
		t.Fatalf("SetProfileRequestable: %v", err)
	}
	return st
}

// fixedCNProfile is a leaf profile whose subject common name is fixed by the
// profile, so a CSR with no common name of its own still matches.
func fixedCNProfile(name string) *nodev1.CertificateProfile {
	return &nodev1.CertificateProfile{
		Name: name, KeyAlg: "ECDSA-P384",
		Subject: &nodev1.Subject{CommonName: "fixed." + name + ".example"},
	}
}

// newCSRWithSANs builds a CSR signed with an ECDSA P-384 key, carrying cn and
// optionally dns SANs.
func newCSRWithSANs(t *testing.T, cn string, dns []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCreateCertificateRequest_StoresPendingAndRaisesApproval(t *testing.T) {
	cp := fixedCNProfile("web-tls")
	st := requestableProfile(t, cp)
	svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})
	csr := newCSRWithSANs(t, "", nil)

	resp, err := svc.CreateCertificateRequest(operatorCtx("alice@example.org", authz.LevelViewer),
		connect.NewRequest(&fleetv1.CreateCertificateRequestRequest{ProfileName: "web-tls", CsrDer: csr, Note: "for the new intranet box"}))
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	r := resp.Msg.GetRequest()
	if r.GetId() == "" || r.GetProfileName() != "web-tls" || r.GetState() != store.CertRequestPending ||
		r.GetNote() != "for the new intranet box" || r.GetRequestedByCn() != "alice@example.org" ||
		r.GetApprovalId() == "" || r.GetCsrPem() == "" || r.GetExpiresAt() == "" {
		t.Fatalf("request = %+v", r)
	}

	a, ok := st.Approval(r.GetApprovalId())
	if !ok || a.Kind != store.ApprovalKindCertificateRequest || a.RequestedByCN != "alice@example.org" ||
		a.RequestDigest != r.GetId() || a.RequiredLevel != "operator" {
		t.Fatalf("approval = %+v, ok %v", a, ok)
	}

	kinds := auditKinds(st)
	if kinds[len(kinds)-1] != "certificate-request-created" {
		t.Fatalf("audit = %v", kinds)
	}
}

func TestCreateCertificateRequest_RefusesUnknownProfile(t *testing.T) {
	st := nodeStore("pki-issuing")
	svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})

	_, err := svc.CreateCertificateRequest(operatorCtx("alice@example.org", authz.LevelViewer),
		connect.NewRequest(&fleetv1.CreateCertificateRequestRequest{ProfileName: "missing", CsrDer: newCSRWithSANs(t, "x", nil)}))
	requireConnectCode(t, err, connect.CodeNotFound)
	requireAppCode(t, err, apperr.CodeProfileNotFound)
}

func TestCreateCertificateRequest_RefusesNotRequestableProfile(t *testing.T) {
	cp := fixedCNProfile("web-tls")
	st := nodeStore("pki-issuing")
	if err := st.CreateProfile(storeProfile(t, cp)); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})

	_, err := svc.CreateCertificateRequest(operatorCtx("alice@example.org", authz.LevelViewer),
		connect.NewRequest(&fleetv1.CreateCertificateRequestRequest{ProfileName: "web-tls", CsrDer: newCSRWithSANs(t, "x", nil)}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
	requireAppCode(t, err, apperr.CodeProfileNotRequestable)
}

func TestCreateCertificateRequest_RefusesABadCSR(t *testing.T) {
	cp := fixedCNProfile("web-tls")
	st := requestableProfile(t, cp)
	svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})

	t.Run("empty", func(t *testing.T) {
		_, err := svc.CreateCertificateRequest(operatorCtx("alice@example.org", authz.LevelViewer),
			connect.NewRequest(&fleetv1.CreateCertificateRequestRequest{ProfileName: "web-tls"}))
		requireConnectCode(t, err, connect.CodeInvalidArgument)
	})
	t.Run("not a CSR", func(t *testing.T) {
		_, err := svc.CreateCertificateRequest(operatorCtx("alice@example.org", authz.LevelViewer),
			connect.NewRequest(&fleetv1.CreateCertificateRequestRequest{ProfileName: "web-tls", CsrDer: []byte("bogus")}))
		requireConnectCode(t, err, connect.CodeInvalidArgument)
		requireAppCode(t, err, apperr.CodeCSRRejected)
	})
}

func TestCreateCertificateRequest_RefusesCSRProfileMismatch(t *testing.T) {
	t.Run("subject", func(t *testing.T) {
		// The profile fixes no common name, and the CSR supplies none either.
		cp := &nodev1.CertificateProfile{Name: "no-cn", KeyAlg: "ECDSA-P384"}
		st := requestableProfile(t, cp)
		svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})

		_, err := svc.CreateCertificateRequest(operatorCtx("alice@example.org", authz.LevelViewer),
			connect.NewRequest(&fleetv1.CreateCertificateRequestRequest{ProfileName: "no-cn", CsrDer: newCSRWithSANs(t, "", nil)}))
		requireConnectCode(t, err, connect.CodeInvalidArgument)
		requireAppCode(t, err, apperr.CodeCsrProfileMismatch)
	})
	t.Run("sans", func(t *testing.T) {
		// The profile does not allow request SANs, but the CSR carries one.
		cp := fixedCNProfile("no-sans")
		st := requestableProfile(t, cp)
		svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})

		_, err := svc.CreateCertificateRequest(operatorCtx("alice@example.org", authz.LevelViewer),
			connect.NewRequest(&fleetv1.CreateCertificateRequestRequest{ProfileName: "no-sans", CsrDer: newCSRWithSANs(t, "", []string{"host.example"})}))
		requireConnectCode(t, err, connect.CodeInvalidArgument)
		requireAppCode(t, err, apperr.CodeCsrProfileMismatch)
	})
	t.Run("key type", func(t *testing.T) {
		cp := fixedCNProfile("weak-key")
		st := requestableProfile(t, cp)
		svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})
		csr, _ := newCSR(t, "", true) // P-256, too weak

		_, err := svc.CreateCertificateRequest(operatorCtx("alice@example.org", authz.LevelViewer),
			connect.NewRequest(&fleetv1.CreateCertificateRequestRequest{ProfileName: "weak-key", CsrDer: csr}))
		requireConnectCode(t, err, connect.CodeInvalidArgument)
		requireAppCode(t, err, apperr.CodeCsrProfileMismatch)
	})
}

// createRequest is a test helper that files a request and returns it.
func createRequest(t *testing.T, svc *Service, requesterCN, profile string) *fleetv1.CertificateRequest {
	t.Helper()
	resp, err := svc.CreateCertificateRequest(operatorCtx(requesterCN, authz.LevelViewer),
		connect.NewRequest(&fleetv1.CreateCertificateRequestRequest{ProfileName: profile, CsrDer: newCSRWithSANs(t, "", nil)}))
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return resp.Msg.GetRequest()
}

func TestListCertificateRequests_RequesterSeesOwnOperatorSeesAll(t *testing.T) {
	cp := fixedCNProfile("web-tls")
	st := requestableProfile(t, cp)
	svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})
	createRequest(t, svc, "alice@example.org", "web-tls")
	createRequest(t, svc, "bob@example.org", "web-tls")

	alice, err := svc.ListCertificateRequests(operatorCtx("alice@example.org", authz.LevelViewer),
		connect.NewRequest(&fleetv1.ListCertificateRequestsRequest{}))
	if err != nil || len(alice.Msg.GetItems()) != 1 || alice.Msg.GetItems()[0].GetRequestedByCn() != "alice@example.org" {
		t.Fatalf("alice's list = %v, %v", alice, err)
	}

	ops, err := svc.ListCertificateRequests(operatorCtx("ops@example.org", authz.LevelOperator),
		connect.NewRequest(&fleetv1.ListCertificateRequestsRequest{}))
	if err != nil || len(ops.Msg.GetItems()) != 2 {
		t.Fatalf("operator's list = %v, %v", ops, err)
	}

	// mine_only=false from a viewer is still forced to their own.
	aliceAll, err := svc.ListCertificateRequests(operatorCtx("alice@example.org", authz.LevelViewer),
		connect.NewRequest(&fleetv1.ListCertificateRequestsRequest{MineOnly: false}))
	if err != nil || len(aliceAll.Msg.GetItems()) != 1 {
		t.Fatalf("alice's forced list = %v, %v", aliceAll, err)
	}
}

func TestListCertificateRequests_InvalidState(t *testing.T) {
	st := nodeStore("pki-issuing")
	svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})

	_, err := svc.ListCertificateRequests(operatorCtx("ops@example.org", authz.LevelOperator),
		connect.NewRequest(&fleetv1.ListCertificateRequestsRequest{State: "bogus"}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestGetCertificateRequestByID_RightsAndNotFound(t *testing.T) {
	cp := fixedCNProfile("web-tls")
	st := requestableProfile(t, cp)
	svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})
	r := createRequest(t, svc, "alice@example.org", "web-tls")

	if _, err := svc.GetCertificateRequestByID(operatorCtx("alice@example.org", authz.LevelViewer),
		connect.NewRequest(&fleetv1.GetCertificateRequestByIDRequest{Id: r.GetId()})); err != nil {
		t.Fatalf("requester's own get: %v", err)
	}
	if _, err := svc.GetCertificateRequestByID(operatorCtx("ops@example.org", authz.LevelOperator),
		connect.NewRequest(&fleetv1.GetCertificateRequestByIDRequest{Id: r.GetId()})); err != nil {
		t.Fatalf("operator's get: %v", err)
	}
	_, err := svc.GetCertificateRequestByID(operatorCtx("bob@example.org", authz.LevelViewer),
		connect.NewRequest(&fleetv1.GetCertificateRequestByIDRequest{Id: r.GetId()}))
	requireConnectCode(t, err, connect.CodePermissionDenied)

	_, err = svc.GetCertificateRequestByID(operatorCtx("ops@example.org", authz.LevelOperator),
		connect.NewRequest(&fleetv1.GetCertificateRequestByIDRequest{Id: "missing"}))
	requireConnectCode(t, err, connect.CodeNotFound)
	requireAppCode(t, err, apperr.CodeRequestNotFound)
}

func TestCancelCertificateRequest_RightsAndState(t *testing.T) {
	cp := fixedCNProfile("web-tls")

	t.Run("the requester cancels their own", func(t *testing.T) {
		st := requestableProfile(t, cp)
		svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})
		r := createRequest(t, svc, "alice@example.org", "web-tls")

		resp, err := svc.CancelCertificateRequest(operatorCtx("alice@example.org", authz.LevelViewer),
			connect.NewRequest(&fleetv1.CancelCertificateRequestRequest{Id: r.GetId()}))
		if err != nil || resp.Msg.GetRequest().GetState() != store.CertRequestCancelled {
			t.Fatalf("cancel = %v, %v", resp, err)
		}
	})
	t.Run("an admin cancels someone else's", func(t *testing.T) {
		st := requestableProfile(t, cp)
		svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})
		r := createRequest(t, svc, "alice@example.org", "web-tls")

		resp, err := svc.CancelCertificateRequest(operatorCtx("admin@example.org", authz.LevelAdmin),
			connect.NewRequest(&fleetv1.CancelCertificateRequestRequest{Id: r.GetId()}))
		if err != nil || resp.Msg.GetRequest().GetState() != store.CertRequestCancelled {
			t.Fatalf("cancel = %v, %v", resp, err)
		}
	})
	t.Run("an operator who isn't the requester or an admin cannot", func(t *testing.T) {
		st := requestableProfile(t, cp)
		svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})
		r := createRequest(t, svc, "alice@example.org", "web-tls")

		_, err := svc.CancelCertificateRequest(operatorCtx("ops@example.org", authz.LevelOperator),
			connect.NewRequest(&fleetv1.CancelCertificateRequestRequest{Id: r.GetId()}))
		requireConnectCode(t, err, connect.CodePermissionDenied)
	})
	t.Run("a decided request cannot be cancelled", func(t *testing.T) {
		st := requestableProfile(t, cp)
		svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})
		r := createRequest(t, svc, "alice@example.org", "web-tls")
		if _, err := svc.DecideApproval(operatorCtx("ops@example.org", authz.LevelOperator),
			connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: r.GetApprovalId(), Approve: false})); err != nil {
			t.Fatalf("deny: %v", err)
		}

		_, err := svc.CancelCertificateRequest(operatorCtx("alice@example.org", authz.LevelViewer),
			connect.NewRequest(&fleetv1.CancelCertificateRequestRequest{Id: r.GetId()}))
		requireConnectCode(t, err, connect.CodeFailedPrecondition)
		requireAppCode(t, err, apperr.CodeRequestNotPending)
	})
}

func TestDecideApproval_CertificateRequest_ApprovalIssuesTheCertificate(t *testing.T) {
	cp := fixedCNProfile("web-tls")
	st := requestableProfile(t, cp)
	conn := &fakeConn{
		getConfigResp: nodeConfigWith("web-tls"),
		issueResp:     &nodev1.IssueLeafResponse{CertDer: []byte("leaf-der")},
	}
	svc := New(st, dialFor(map[string]*fakeConn{"pki-issuing": conn})).WithApprovals(&approval.Service{Store: st})
	r := createRequest(t, svc, "alice@example.org", "web-tls")

	resp, err := svc.DecideApproval(operatorCtx("ops@example.org", authz.LevelOperator),
		connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: r.GetApprovalId(), Approve: true}))
	if err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	if resp.Msg.GetApproval().GetStatus() != store.ApprovalApproved {
		t.Fatalf("approval = %v", resp.Msg.GetApproval())
	}

	got, ok := st.CertificateRequest(r.GetId(), time.Now().UTC())
	if !ok || got.State != store.CertRequestIssued || string(got.CertDER) != "leaf-der" || got.IssuedAt.IsZero() {
		t.Fatalf("request = %+v, ok %v", got, ok)
	}
	if conn.gotIssueCSR == nil || conn.gotIssueProfile != "web-tls" {
		t.Fatalf("IssueLeaf wasn't called with the request's CSR and profile: %+v", conn)
	}

	kinds := auditKinds(st)
	last3 := kinds[len(kinds)-3:]
	if last3[0] != "approval-approved" || last3[1] != "certificate-request-approved" || last3[2] != "certificate-request-issued" {
		t.Fatalf("audit tail = %v", kinds)
	}
}

func TestDecideApproval_CertificateRequest_DenialMarksDenied(t *testing.T) {
	cp := fixedCNProfile("web-tls")
	st := requestableProfile(t, cp)
	svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})
	r := createRequest(t, svc, "alice@example.org", "web-tls")

	if _, err := svc.DecideApproval(operatorCtx("ops@example.org", authz.LevelOperator),
		connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: r.GetApprovalId(), Approve: false})); err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}

	got, ok := st.CertificateRequest(r.GetId(), time.Now().UTC())
	if !ok || got.State != store.CertRequestDenied {
		t.Fatalf("request = %+v, ok %v", got, ok)
	}
}

func TestDecideApproval_CertificateRequest_RefusesSelfApproval(t *testing.T) {
	cp := fixedCNProfile("web-tls")
	st := requestableProfile(t, cp)
	svc := New(st, dialFor(nil)).WithApprovals(&approval.Service{Store: st})
	r := createRequest(t, svc, "alice@example.org", "web-tls")

	_, err := svc.DecideApproval(operatorCtx("alice@example.org", authz.LevelOperator),
		connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: r.GetApprovalId(), Approve: true}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	requireAppCode(t, err, apperr.CodeRequestSelfApproval)

	got, ok := st.CertificateRequest(r.GetId(), time.Now().UTC())
	if !ok || got.State != store.CertRequestPending {
		t.Fatalf("a refused self-approval must leave the request pending: %+v", got)
	}
}

func TestDecideApproval_CertificateRequest_NodeRefusalFailsTheRequest(t *testing.T) {
	cp := fixedCNProfile("web-tls")
	st := requestableProfile(t, cp)
	conn := &fakeConn{getConfigResp: nodeConfigWith("web-tls"), issueErr: connect.NewError(connect.CodeInvalidArgument, errors.New("profile rejected"))}
	svc := New(st, dialFor(map[string]*fakeConn{"pki-issuing": conn})).WithApprovals(&approval.Service{Store: st})
	r := createRequest(t, svc, "alice@example.org", "web-tls")

	if _, err := svc.DecideApproval(operatorCtx("ops@example.org", authz.LevelOperator),
		connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: r.GetApprovalId(), Approve: true})); err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}

	got, ok := st.CertificateRequest(r.GetId(), time.Now().UTC())
	if !ok || got.State != store.CertRequestFailed || got.FailureReason == "" {
		t.Fatalf("request = %+v, ok %v", got, ok)
	}

	kinds := auditKinds(st)
	if kinds[len(kinds)-1] != "certificate-request-failed" {
		t.Fatalf("audit = %v", kinds)
	}
}

func TestSetProfileRequestable_AdminGatedAndNotFound(t *testing.T) {
	cp := fixedCNProfile("web-tls")
	st := nodeStore("pki-issuing")
	if err := st.CreateProfile(storeProfile(t, cp)); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	svc := New(st, dialFor(nil))

	_, err := svc.SetProfileRequestable(operatorCtx("ops@example.org", authz.LevelOperator),
		connect.NewRequest(&fleetv1.SetProfileRequestableRequest{Name: "web-tls", Requestable: true}))
	requireConnectCode(t, err, connect.CodePermissionDenied)

	if _, err := svc.SetProfileRequestable(operatorCtx("admin@example.org", authz.LevelAdmin),
		connect.NewRequest(&fleetv1.SetProfileRequestableRequest{Name: "web-tls", Requestable: true})); err != nil {
		t.Fatalf("SetProfileRequestable: %v", err)
	}
	p, _ := st.Profile("web-tls")
	if !p.Requestable {
		t.Fatal("profile wasn't marked requestable")
	}

	_, err = svc.SetProfileRequestable(operatorCtx("admin@example.org", authz.LevelAdmin),
		connect.NewRequest(&fleetv1.SetProfileRequestableRequest{Name: "missing", Requestable: true}))
	requireConnectCode(t, err, connect.CodeNotFound)
	requireAppCode(t, err, apperr.CodeProfileNotFound)
}

func TestListRequestableProfiles_OnlyRequestableAndAnySignedInIdentity(t *testing.T) {
	st := nodeStore("pki-issuing")
	if err := st.CreateProfile(storeProfile(t, fixedCNProfile("a"))); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateProfile(storeProfile(t, fixedCNProfile("b"))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetProfileRequestable("a", true); err != nil {
		t.Fatal(err)
	}
	svc := New(st, dialFor(nil))

	resp, err := svc.ListRequestableProfiles(operatorCtx("alice@example.org", authz.LevelViewer),
		connect.NewRequest(&fleetv1.ListRequestableProfilesRequest{}))
	if err != nil {
		t.Fatalf("ListRequestableProfiles: %v", err)
	}
	if got := resp.Msg.GetItems(); len(got) != 1 || got[0].GetName() != "a" {
		t.Fatalf("items = %v", got)
	}
}
