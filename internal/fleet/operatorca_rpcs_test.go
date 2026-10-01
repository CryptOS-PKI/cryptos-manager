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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/memory"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/storetest"
)

// rotationStore is the in-memory inventory with the shared operator trust
// fake, which behaves like Postgres, so the registered source can run here.
type rotationStore struct {
	*memory.Store
	trust *storetest.MemoryTrust
}

func (r *rotationStore) OperatorCAs(ctx context.Context) ([]store.OperatorCA, error) {
	return r.trust.OperatorCAs(ctx)
}
func (r *rotationStore) AddOperatorCA(ctx context.Context, ca store.OperatorCA) error {
	return r.trust.AddOperatorCA(ctx, ca)
}
func (r *rotationStore) SetOperatorCAState(ctx context.Context, sha, state, reason string, at time.Time) error {
	return r.trust.SetOperatorCAState(ctx, sha, state, reason, at)
}
func (r *rotationStore) RotateOperatorCA(ctx context.Context, ca store.OperatorCA, crl *store.OperatorCRL, decide store.DecideCRL) error {
	return r.trust.RotateOperatorCA(ctx, ca, crl, decide)
}
func (r *rotationStore) SetOperatorCACRLSource(ctx context.Context, sha, source, url string, acks []string, crl *store.OperatorCRL, decide store.DecideCRL) error {
	return r.trust.SetOperatorCACRLSource(ctx, sha, source, url, acks, crl, decide)
}
func (r *rotationStore) SetOperatorCAOCSP(ctx context.Context, sha, mode, url string) error {
	return r.trust.SetOperatorCAOCSP(ctx, sha, mode, url)
}
func (r *rotationStore) OperatorCRLs(ctx context.Context) ([]store.OperatorCRL, error) {
	return r.trust.OperatorCRLs(ctx)
}
func (r *rotationStore) PutOperatorCRL(ctx context.Context, c store.OperatorCRL, decide store.DecideCRL) (bool, error) {
	return r.trust.PutOperatorCRL(ctx, c, decide)
}
func (r *rotationStore) RecordOperatorCRLAttempt(ctx context.Context, issuer, msg string, at time.Time) error {
	return r.trust.RecordOperatorCRLAttempt(ctx, issuer, msg, at)
}
func (r *rotationStore) OperatorDenylist(ctx context.Context) ([]store.DenylistEntry, error) {
	return r.trust.OperatorDenylist(ctx)
}
func (r *rotationStore) AddOperatorDenylistEntry(ctx context.Context, e store.DenylistEntry) (bool, error) {
	return r.trust.AddOperatorDenylistEntry(ctx, e)
}
func (r *rotationStore) OperatorTrustVersion(ctx context.Context) (store.TrustVersion, error) {
	return r.trust.OperatorTrustVersion(ctx)
}
func (r *rotationStore) TryAdvisoryLock(ctx context.Context, name string) (func(), bool, error) {
	return r.trust.TryAdvisoryLock(ctx, name)
}

// replica is one manager process over the shared store.
type replica struct {
	svc    *Service
	trust  *operatorca.TrustStore
	rev    *operatorca.Revocations
	auth   operatorca.PeerAuthorizer
	poller *operatorca.Poller
}

// rotationFixture is a registered-source manager whose first operator CA,
// ca, is active with no CRL and OCSP off. CRL URLs are served from crls and
// OCSP probes answered by probe.
type rotationFixture struct {
	st     *rotationStore
	ca     testCA
	policy string

	mu        sync.Mutex
	crls      map[string][]byte
	probeErr  error
	probeURLs []string

	replica
}

func newRotationFixture(t *testing.T, policy string) *rotationFixture {
	t.Helper()
	f := &rotationFixture{
		st:     &rotationStore{Store: memory.New(nil), trust: storetest.NewMemoryTrust()},
		ca:     newTestCA(t, "Example Operator CA G1"),
		policy: policy,
		crls:   map[string][]byte{},
	}
	if err := f.st.AddOperatorCA(context.Background(), store.OperatorCA{
		SHA256: operatorca.Fingerprint(f.ca.cert), CertDER: f.ca.cert.Raw, State: store.OperatorCAActive,
		CRLSource: store.CRLSourceNone, OCSPMode: store.OCSPModeOff, Acknowledgements: []string{"NO_CRL"},
	}); err != nil {
		t.Fatal(err)
	}
	f.replica = f.newReplica(t)
	return f
}

func (f *rotationFixture) newReplica(t *testing.T) replica {
	t.Helper()
	ctx := context.Background()
	rev := operatorca.NewRevocations(operatorca.RevocationOptions{Store: f.st, Policy: f.policy, OCSPFetcher: operatorca.NewOCSPFetcher()})
	trust, err := operatorca.NewTrustStore(ctx, operatorca.Source{Kind: operatorca.KindRegistered, Policy: f.policy}, f.st, rev, &tls.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rev.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	svc := New(f.st, noDial(t)).WithOperatorTrust(trust, rev).WithOperatorCAAdmin(OperatorCAAdmin{
		FetchCRL: f.fetch,
		Probe:    f.probe,
	})
	return replica{svc: svc, trust: trust, rev: rev, auth: operatorca.PeerAuthorizer{Trust: trust, Rev: rev},
		poller: operatorca.NewPoller(f.st, trust, rev, nil)}
}

func (f *rotationFixture) fetch(_ context.Context, url string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.crls[url]
	if !ok {
		return nil, errors.New("connection refused")
	}
	return b, nil
}

func (f *rotationFixture) probe(_ context.Context, anchor *x509.Certificate, url string) (operatorca.OCSPResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probeURLs = append(f.probeURLs, url)
	if f.probeErr != nil {
		return operatorca.OCSPResult{}, f.probeErr
	}
	return operatorca.OCSPResult{Status: operatorca.OCSPUnknown, Signer: anchor}, nil
}

func (f *rotationFixture) serveCRL(url string, der []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.crls[url] = der
}

func (f *rotationFixture) states(t *testing.T) map[string]string {
	t.Helper()
	cas, err := f.st.OperatorCAs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, c := range cas {
		out[c.SHA256] = c.State
	}
	return out
}

func (f *rotationFixture) row(t *testing.T, sha string) store.OperatorCA {
	t.Helper()
	cas, _ := f.st.OperatorCAs(context.Background())
	for _, c := range cas {
		if c.SHA256 == sha {
			return c
		}
	}
	t.Fatalf("no operator CA %s", sha)
	return store.OperatorCA{}
}

func (f *rotationFixture) version(t *testing.T) store.TrustVersion {
	t.Helper()
	v, err := f.st.OperatorTrustVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *rotationFixture) auditKinds() []string {
	var out []string
	for _, e := range f.st.Audit() {
		out = append(out, e.Kind)
	}
	return out
}

// register previews and then confirms ca as the next operator CA.
func (f *rotationFixture) register(t *testing.T, ca testCA, req *fleetv1.RegisterOperatorCARequest) *fleetv1.RegisterOperatorCAResponse {
	t.Helper()
	req.CaCertDer = ca.cert.Raw
	preview, err := f.svc.RegisterOperatorCA(adminCtx(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("RegisterOperatorCA preview: %v", err)
	}
	req.ConfirmSha256 = preview.Msg.GetOperatorCa().GetSha256()
	resp, err := f.svc.RegisterOperatorCA(adminCtx(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("RegisterOperatorCA confirm: %v", err)
	}
	return resp.Msg
}

func noCRL() *fleetv1.RegisterOperatorCARequest {
	return &fleetv1.RegisterOperatorCARequest{
		CrlSource:        &fleetv1.RegisterOperatorCARequest_None{None: true},
		OcspMode:         fleetv1.OcspMode_OCSP_MODE_OFF,
		Acknowledgements: []fleetv1.OperatorCAAcknowledgement{fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_NO_CRL},
	}
}

// crl signs a CRL from ca with the given number, listing revoked.
func (ca testCA) crl(t *testing.T, number int64, revoked ...int64) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{
		Number: big.NewInt(number), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(24 * time.Hour),
	}
	for _, s := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: time.Now().Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func leafKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func wantRefusal(t *testing.T, err error, code int, reason fleetv1.ErrorReason) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %d/%s", code, apperr.ReasonName(reason))
	}
	if got, ok := apperr.Code(err); !ok || got != code {
		t.Fatalf("code = %d (ok %v), want %d; error %v", got, ok, code, err)
	}
	if reason == fleetv1.ErrorReason_ERROR_REASON_UNSPECIFIED {
		return
	}
	if got, ok := apperr.ReasonOf(err); !ok || got != reason {
		t.Fatalf("reason = %s, want %s; error %v", apperr.ReasonName(got), apperr.ReasonName(reason), err)
	}
}

// An admin registration after first run makes the new CA active and the old
// one retiring. Both stay trusted, without a restart, and both stay
// revocation-checked: the old CA's denylist and the new CA's CRL apply.
func TestRegisterOperatorCA_RotatesTheActiveCAToRetiring(t *testing.T) {
	f := newRotationFixture(t, operatorca.PolicySoft)
	next := newTestCA(t, "Example Operator CA G2")
	f.serveCRL("http://pki.example.org/g2.crl", next.crl(t, 10, 99))
	oldFP, newFP := operatorca.Fingerprint(f.ca.cert), operatorca.Fingerprint(next.cert)

	preview, err := f.svc.RegisterOperatorCA(adminCtx(), connect.NewRequest(&fleetv1.RegisterOperatorCARequest{
		CaCertDer: next.cert.Raw,
		CrlSource: &fleetv1.RegisterOperatorCARequest_Url{Url: "http://pki.example.org/g2.crl"},
	}))
	if err != nil {
		t.Fatalf("RegisterOperatorCA preview: %v", err)
	}
	p := preview.Msg
	if p.GetConfirmed() || p.GetOperatorCa().GetSha256() != newFP || p.GetOperatorCa().GetState() != fleetv1.OperatorCAState_OPERATOR_CA_STATE_UNSPECIFIED ||
		p.GetOperatorCa().GetCrl().GetCrlNumber() != "10" || p.GetOperatorCa().GetOcspMode() != fleetv1.OcspMode_OCSP_MODE_AIA ||
		!strings.Contains(p.GetAdminExtfile(), "1.3.6.1.4.1.59999.1.1") {
		t.Fatalf("preview = %+v", p)
	}
	if states := f.states(t); len(states) != 1 {
		t.Fatalf("a preview stored something: %v", states)
	}

	resp := f.register(t, next, &fleetv1.RegisterOperatorCARequest{CrlSource: &fleetv1.RegisterOperatorCARequest_Url{Url: "http://pki.example.org/g2.crl"}})
	if !resp.GetConfirmed() || resp.GetOperatorCa().GetState() != fleetv1.OperatorCAState_OPERATOR_CA_STATE_ACTIVE || resp.GetOperatorCa().GetRegisteredAt() == "" {
		t.Fatalf("confirm = %+v", resp)
	}
	if states := f.states(t); states[oldFP] != store.OperatorCARetiring || states[newFP] != store.OperatorCAActive {
		t.Fatalf("states = %v", states)
	}
	if got := f.row(t, newFP).RegisteredBy; got != "admin@example.org" {
		t.Fatalf("registered_by = %q", got)
	}

	oldLeaf := f.ca.leaf(t, &leafKey(t).PublicKey, "old@example.org", "admin", 5)
	newLeaf := next.leaf(t, &leafKey(t).PublicKey, "new@example.org", "admin", 6)
	listed := next.leaf(t, &leafKey(t).PublicKey, "gone@example.org", "admin", 99)
	if _, err := f.auth.AuthorizePeer(oldLeaf, nil); err != nil {
		t.Fatalf("a certificate from the retiring CA = %v, want trusted", err)
	}
	if _, err := f.auth.AuthorizePeer(newLeaf, nil); err != nil {
		t.Fatalf("a certificate from the new CA = %v, want trusted", err)
	}
	if _, err := f.auth.AuthorizePeer(listed, nil); err == nil {
		t.Fatal("a certificate in the new CA's CRL was accepted")
	}
	if _, err := f.svc.RevokeOperatorCredential(adminCtx(), connect.NewRequest(&fleetv1.RevokeOperatorCredentialRequest{
		SerialHex: "05", IssuerSha256: oldFP, ReasonCode: 4,
	})); err != nil {
		t.Fatalf("deny under the retiring CA: %v", err)
	}
	if _, err := f.auth.AuthorizePeer(oldLeaf, nil); err == nil {
		t.Fatal("a denied certificate from the retiring CA was accepted")
	}
	if kinds := strings.Join(f.auditKinds(), ","); !strings.Contains(kinds, "operator-ca-registered") {
		t.Fatalf("audit = %s", kinds)
	}
}

// At most one CA can be retiring, so a second rotation waits until the
// first one's old CA is retired.
func TestRegisterOperatorCA_SecondRotationIsRefused(t *testing.T) {
	f := newRotationFixture(t, operatorca.PolicySoft)
	f.register(t, newTestCA(t, "Example Operator CA G2"), noCRL())
	before := f.version(t)

	req := noCRL()
	req.CaCertDer = newTestCA(t, "Example Operator CA G3").cert.Raw
	_, err := f.svc.RegisterOperatorCA(adminCtx(), connect.NewRequest(req))
	wantRefusal(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_ROTATION_IN_PROGRESS)
	if after := f.version(t); after != before {
		t.Fatalf("trust version moved: %+v -> %+v", before, after)
	}
}

// The admin registration runs the first-run checks: the fingerprint must be
// confirmed, no CRL needs NO_CRL, a CRL must fetch and verify against the
// CA, and an OCSP url must answer the probe, which the preview reports.
func TestRegisterOperatorCA_ChecksLikeFirstRun(t *testing.T) {
	f := newRotationFixture(t, operatorca.PolicySoft)
	next := newTestCA(t, "Example Operator CA G2")
	other := newTestCA(t, "Example Other CA")
	call := func(req *fleetv1.RegisterOperatorCARequest) (*fleetv1.RegisterOperatorCAResponse, error) {
		req.CaCertDer = next.cert.Raw
		resp, err := f.svc.RegisterOperatorCA(adminCtx(), connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}

	req := noCRL()
	req.ConfirmSha256 = strings.Repeat("ab", 32)
	_, err := call(req)
	wantRefusal(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_NOT_CONFIRMED)

	req = noCRL()
	req.Acknowledgements = nil
	_, err = call(req)
	wantRefusal(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_NO_CRL_NOT_ACKNOWLEDGED)

	_, err = call(&fleetv1.RegisterOperatorCARequest{CrlSource: &fleetv1.RegisterOperatorCARequest_Url{Url: "http://pki.example.org/missing.crl"}})
	wantRefusal(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_UNREACHABLE)

	_, err = call(&fleetv1.RegisterOperatorCARequest{CrlSource: &fleetv1.RegisterOperatorCARequest_CrlDer{CrlDer: other.crl(t, 1)}})
	wantRefusal(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_INVALID)

	req = noCRL()
	req.OcspMode, req.OcspUrl = fleetv1.OcspMode_OCSP_MODE_URL, "http://ocsp.example.org/"
	resp, err := call(req)
	if err != nil {
		t.Fatalf("preview with an OCSP url: %v", err)
	}
	if pr := resp.GetOcspProbe(); pr.GetSigner() != fleetv1.OcspSigner_OCSP_SIGNER_ANCHOR || pr.GetCertStatus() != "unknown" || pr.GetSignerSubject() == "" {
		t.Fatalf("probe = %+v", pr)
	}
	f.probeErr = apperr.Reasoned(apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE, errors.New("down"))
	_, err = call(req)
	wantRefusal(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_UNREACHABLE)

	if states := f.states(t); len(states) != 1 {
		t.Fatalf("a refused registration stored something: %v", states)
	}
}

// Retiring refuses the last active CA and the caller's own CA unless the
// caller says they understand. A retired CA's certificates stop on their
// next request.
func TestRetireOperatorCA_GuardsAndStopsTrust(t *testing.T) {
	f := newRotationFixture(t, operatorca.PolicySoft)
	oldFP := operatorca.Fingerprint(f.ca.cert)
	retire := func(ctx context.Context, sha string, flag bool) (*fleetv1.RetireOperatorCAResponse, error) {
		resp, err := f.svc.RetireOperatorCA(ctx, connect.NewRequest(&fleetv1.RetireOperatorCARequest{Sha256: sha, IUnderstandSelfLockout: flag}))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}

	_, err := retire(adminCtx(), oldFP, true)
	wantRefusal(t, err, apperr.CodeOperatorCAInUse, fleetv1.ErrorReason_ERROR_REASON_UNSPECIFIED)

	next := newTestCA(t, "Example Operator CA G2")
	f.register(t, next, noCRL())
	newFP := operatorca.Fingerprint(next.cert)
	_, err = retire(adminCtx(), newFP, true)
	wantRefusal(t, err, apperr.CodeOperatorCAInUse, fleetv1.ErrorReason_ERROR_REASON_UNSPECIFIED)

	mine := authz.NewContext(context.Background(), authz.Identity{CN: "admin@example.org", Level: authz.LevelAdmin, IssuerSHA256: oldFP})
	_, err = retire(mine, oldFP, false)
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "i_understand_self_lockout") {
		t.Fatalf("self-lockout refusal = %v, want it to name the flag", err)
	}
	if f.states(t)[oldFP] != store.OperatorCARetiring {
		t.Fatal("a refused retirement changed the CA")
	}

	oldLeaf := f.ca.leaf(t, &leafKey(t).PublicKey, "old@example.org", "admin", 5)
	if _, err := f.auth.AuthorizePeer(oldLeaf, nil); err != nil {
		t.Fatalf("before retiring: %v", err)
	}
	resp, err := retire(mine, oldFP, true)
	if err != nil {
		t.Fatalf("RetireOperatorCA: %v", err)
	}
	if ca := resp.GetOperatorCa(); ca.GetState() != fleetv1.OperatorCAState_OPERATOR_CA_STATE_RETIRED || ca.GetRetiredReason() != "retired" || ca.GetRetiredAt() == "" {
		t.Fatalf("response = %+v", ca)
	}
	if _, err := f.auth.AuthorizePeer(oldLeaf, nil); err == nil {
		t.Fatal("a certificate from the retired CA was accepted on its next request")
	}
	if kinds := strings.Join(f.auditKinds(), ","); !strings.Contains(kinds, "operator-ca-retired") {
		t.Fatalf("audit = %s", kinds)
	}

	_, err = retire(adminCtx(), oldFP, true)
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
	_, err = retire(adminCtx(), strings.Repeat("0", 64), true)
	requireConnectCode(t, err, connect.CodeNotFound)
}

// A new CRL source must verify first, switching to none needs NO_CRL, and
// a change moves the revocation epoch and is audited.
func TestSetOperatorCACRLSource(t *testing.T) {
	f := newRotationFixture(t, operatorca.PolicySoft)
	fp := operatorca.Fingerprint(f.ca.cert)
	set := func(req *fleetv1.SetOperatorCACRLSourceRequest) (*fleetv1.SetOperatorCACRLSourceResponse, error) {
		req.Sha256 = fp
		resp, err := f.svc.SetOperatorCACRLSource(adminCtx(), connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}

	f.serveCRL("http://pki.example.org/bad.crl", newTestCA(t, "Example Other CA").crl(t, 1))
	_, err := set(&fleetv1.SetOperatorCACRLSourceRequest{CrlSource: &fleetv1.SetOperatorCACRLSourceRequest_Url{Url: "http://pki.example.org/bad.crl"}})
	wantRefusal(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_INVALID)
	if f.row(t, fp).CRLSource != store.CRLSourceNone {
		t.Fatal("a refused CRL source was stored")
	}

	before := f.version(t)
	f.serveCRL("http://pki.example.org/g1.crl", f.ca.crl(t, 3, 77))
	resp, err := set(&fleetv1.SetOperatorCACRLSourceRequest{CrlSource: &fleetv1.SetOperatorCACRLSourceRequest_Url{Url: "http://pki.example.org/g1.crl"}})
	if err != nil {
		t.Fatalf("SetOperatorCACRLSource(url): %v", err)
	}
	if ca := resp.GetOperatorCa(); ca.GetCrlSource() != fleetv1.CrlSource_CRL_SOURCE_URL || ca.GetCrlLocation() != "http://pki.example.org/g1.crl" ||
		ca.GetCrl().GetCrlNumber() != "3" || ca.GetCrl().GetRevokedCount() != 1 {
		t.Fatalf("response = %+v", ca)
	}
	if after := f.version(t); after.Epoch <= before.Epoch || after.CAs == before.CAs {
		t.Fatalf("trust version %+v -> %+v", before, after)
	}
	if _, err := f.auth.AuthorizePeer(f.ca.leaf(t, &leafKey(t).PublicKey, "x@example.org", "admin", 77), nil); err == nil {
		t.Fatal("a certificate in the new CRL was accepted")
	}

	_, err = set(&fleetv1.SetOperatorCACRLSourceRequest{CrlSource: &fleetv1.SetOperatorCACRLSourceRequest_None{None: true}})
	wantRefusal(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_NO_CRL_NOT_ACKNOWLEDGED)
	resp, err = set(&fleetv1.SetOperatorCACRLSourceRequest{
		CrlSource:        &fleetv1.SetOperatorCACRLSourceRequest_None{None: true},
		Acknowledgements: []fleetv1.OperatorCAAcknowledgement{fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_NO_CRL},
	})
	if err != nil {
		t.Fatalf("SetOperatorCACRLSource(none): %v", err)
	}
	if resp.GetOperatorCa().GetCrlSource() != fleetv1.CrlSource_CRL_SOURCE_NONE {
		t.Fatalf("response = %+v", resp.GetOperatorCa())
	}
	if kinds := strings.Join(f.auditKinds(), ","); strings.Count(kinds, "operator-ca-crl-source-changed") != 2 {
		t.Fatalf("audit = %s", kinds)
	}

	_, err = set(&fleetv1.SetOperatorCACRLSourceRequest{})
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

// With a hard revocation policy an upload source is refused: an expired CRL
// would lock out the admins who upload the next one.
func TestSetOperatorCACRLSource_HardPolicyRefusesUpload(t *testing.T) {
	f := newRotationFixture(t, operatorca.PolicyHard)
	_, err := f.svc.SetOperatorCACRLSource(adminCtx(), connect.NewRequest(&fleetv1.SetOperatorCACRLSourceRequest{
		Sha256: operatorca.Fingerprint(f.ca.cert), CrlSource: &fleetv1.SetOperatorCACRLSourceRequest_CrlDer{CrlDer: f.ca.crl(t, 1)},
	}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)

	req := noCRL()
	req.CrlSource = &fleetv1.RegisterOperatorCARequest_CrlDer{CrlDer: f.ca.crl(t, 1)}
	req.CaCertDer = newTestCA(t, "Example Operator CA G2").cert.Raw
	_, err = f.svc.RegisterOperatorCA(adminCtx(), connect.NewRequest(req))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
}

// An uploaded CRL is verified against the CA, refused when older than the
// stored one, stored with an epoch bump, and audited.
func TestUploadOperatorCRL(t *testing.T) {
	f := newRotationFixture(t, operatorca.PolicySoft)
	fp := operatorca.Fingerprint(f.ca.cert)
	upload := func(der []byte) (*fleetv1.UploadOperatorCRLResponse, error) {
		resp, err := f.svc.UploadOperatorCRL(adminCtx(), connect.NewRequest(&fleetv1.UploadOperatorCRLRequest{Sha256: fp, CrlDer: der}))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}

	_, err := upload(f.ca.crl(t, 1))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)

	if _, err := f.svc.SetOperatorCACRLSource(adminCtx(), connect.NewRequest(&fleetv1.SetOperatorCACRLSourceRequest{
		Sha256: fp, CrlSource: &fleetv1.SetOperatorCACRLSourceRequest_CrlDer{CrlDer: f.ca.crl(t, 5)},
	})); err != nil {
		t.Fatalf("switch to upload: %v", err)
	}

	before := f.version(t)
	resp, err := upload(f.ca.crl(t, 6, 42))
	if err != nil {
		t.Fatalf("UploadOperatorCRL: %v", err)
	}
	if c := resp.GetOperatorCa().GetCrl(); c.GetCrlNumber() != "6" || c.GetRevokedCount() != 1 {
		t.Fatalf("CRL status = %+v", c)
	}
	if after := f.version(t); after.Epoch <= before.Epoch {
		t.Fatalf("epoch %d -> %d, want a bump", before.Epoch, after.Epoch)
	}
	if _, err := f.auth.AuthorizePeer(f.ca.leaf(t, &leafKey(t).PublicKey, "x@example.org", "admin", 42), nil); err == nil {
		t.Fatal("a certificate in the uploaded CRL was accepted")
	}

	_, err = upload(f.ca.crl(t, 4))
	wantRefusal(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_ROLLBACK)
	_, err = upload(newTestCA(t, "Example Other CA").crl(t, 9))
	wantRefusal(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_INVALID)

	if kinds := strings.Join(f.auditKinds(), ","); strings.Count(kinds, "operator-crl-uploaded") != 1 {
		t.Fatalf("audit = %s", kinds)
	}
}

// An OCSP change probes a url responder first, and another replica takes
// the new mode within one poll.
func TestSetOperatorCAOCSP(t *testing.T) {
	f := newRotationFixture(t, operatorca.PolicySoft)
	other := f.newReplica(t)
	fp := operatorca.Fingerprint(f.ca.cert)
	set := func(mode fleetv1.OcspMode, url string) (*fleetv1.SetOperatorCAOCSPResponse, error) {
		resp, err := f.svc.SetOperatorCAOCSP(adminCtx(), connect.NewRequest(&fleetv1.SetOperatorCAOCSPRequest{Sha256: fp, OcspMode: mode, OcspUrl: url}))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}

	_, err := set(fleetv1.OcspMode_OCSP_MODE_URL, "")
	requireConnectCode(t, err, connect.CodeInvalidArgument)

	f.probeErr = apperr.Reasoned(apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_INVALID, errors.New("bad signature"))
	_, err = set(fleetv1.OcspMode_OCSP_MODE_URL, "http://ocsp.example.org/")
	wantRefusal(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_OCSP_INVALID)
	if f.row(t, fp).OCSPMode != store.OCSPModeOff {
		t.Fatal("a refused OCSP change was stored")
	}

	f.probeErr = nil
	resp, err := set(fleetv1.OcspMode_OCSP_MODE_URL, "http://ocsp.example.org/")
	if err != nil {
		t.Fatalf("SetOperatorCAOCSP: %v", err)
	}
	if resp.GetOcspProbe().GetSigner() != fleetv1.OcspSigner_OCSP_SIGNER_ANCHOR || resp.GetOperatorCa().GetOcspMode() != fleetv1.OcspMode_OCSP_MODE_URL ||
		resp.GetOperatorCa().GetOcspUrl() != "http://ocsp.example.org/" {
		t.Fatalf("response = %+v", resp)
	}
	if got := f.probeURLs; len(got) != 2 || got[1] != "http://ocsp.example.org/" {
		t.Fatalf("probes = %v", got)
	}
	if err := other.poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, a := range other.trust.Anchors() {
		if a.SHA256 == fp && (a.OCSPMode != store.OCSPModeURL || a.OCSPURL != "http://ocsp.example.org/") {
			t.Fatalf("the other replica has %+v after one poll", a)
		}
	}

	resp, err = set(fleetv1.OcspMode_OCSP_MODE_AIA, "")
	if err != nil {
		t.Fatalf("SetOperatorCAOCSP(aia): %v", err)
	}
	if resp.GetOcspProbe() != nil || len(f.probeURLs) != 2 {
		t.Fatalf("aia mode probed: %+v, %v", resp.GetOcspProbe(), f.probeURLs)
	}
	if kinds := strings.Join(f.auditKinds(), ","); strings.Count(kinds, "operator-ca-ocsp-changed") != 2 {
		t.Fatalf("audit = %s", kinds)
	}
}

// The list shows every row, trusted ones first, with its CRL and OCSP
// state; it is operator-readable.
func TestListOperatorCAs_Registered(t *testing.T) {
	f := newRotationFixture(t, operatorca.PolicySoft)
	g2 := newTestCA(t, "Example Operator CA G2")
	f.register(t, g2, &fleetv1.RegisterOperatorCARequest{CrlSource: &fleetv1.RegisterOperatorCARequest_CrlDer{CrlDer: g2.crl(t, 2)}})
	if _, err := f.svc.RetireOperatorCA(adminCtx(), connect.NewRequest(&fleetv1.RetireOperatorCARequest{Sha256: operatorca.Fingerprint(f.ca.cert)})); err != nil {
		t.Fatal(err)
	}
	g3 := newTestCA(t, "Example Operator CA G3")
	f.register(t, g3, noCRL())

	resp, err := f.svc.ListOperatorCAs(operatorCtx("op@example.org", authz.LevelOperator), connect.NewRequest(&fleetv1.ListOperatorCAsRequest{}))
	if err != nil {
		t.Fatalf("ListOperatorCAs: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 3 {
		t.Fatalf("items = %+v", items)
	}
	want := []struct {
		sha   string
		state fleetv1.OperatorCAState
	}{
		{operatorca.Fingerprint(g3.cert), fleetv1.OperatorCAState_OPERATOR_CA_STATE_ACTIVE},
		{operatorca.Fingerprint(g2.cert), fleetv1.OperatorCAState_OPERATOR_CA_STATE_RETIRING},
		{operatorca.Fingerprint(f.ca.cert), fleetv1.OperatorCAState_OPERATOR_CA_STATE_RETIRED},
	}
	for i, w := range want {
		if items[i].GetSha256() != w.sha || items[i].GetState() != w.state || items[i].GetManagedByConfig() {
			t.Fatalf("items[%d] = %+v, want %s %v", i, items[i], w.sha, w.state)
		}
	}
	if c := items[1].GetCrl(); items[1].GetCrlSource() != fleetv1.CrlSource_CRL_SOURCE_UPLOAD || c.GetCrlNumber() != "2" || c.GetStale() || c.GetNextUpdate() == "" {
		t.Fatalf("the retiring CA's CRL = %+v", items[1])
	}
	if items[0].GetCrlSource() != fleetv1.CrlSource_CRL_SOURCE_NONE || items[0].GetOcspMode() != fleetv1.OcspMode_OCSP_MODE_OFF ||
		len(items[0].GetAcknowledgements()) != 1 || items[0].GetSubject() == "" || items[0].GetNotAfter() == "" {
		t.Fatalf("the active CA = %+v", items[0])
	}
	if items[2].GetRetiredReason() != "retired" || items[2].GetRetiredAt() == "" {
		t.Fatalf("the retired CA = %+v", items[2])
	}

	_, err = f.svc.ListOperatorCAs(operatorCtx("v@example.org", authz.LevelViewer), connect.NewRequest(&fleetv1.ListOperatorCAsRequest{}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
}

// A config-file operator CA is listed read-only, and every write answers
// 1607 so the UI can say to change the config instead.
func TestOperatorCAs_FileSourceIsManagedByConfig(t *testing.T) {
	st := newCredStore()
	ca := newTestCA(t, "Example Operator CA")
	svc, _ := withAnchors(t, New(st, noDial(t)), st, ca.anchor(store.OperatorCAActive))
	fp := operatorca.Fingerprint(ca.cert)

	resp, err := svc.ListOperatorCAs(adminCtx(), connect.NewRequest(&fleetv1.ListOperatorCAsRequest{}))
	if err != nil {
		t.Fatalf("ListOperatorCAs: %v", err)
	}
	if items := resp.Msg.GetItems(); len(items) != 1 || !items[0].GetManagedByConfig() || items[0].GetSha256() != fp ||
		items[0].GetState() != fleetv1.OperatorCAState_OPERATOR_CA_STATE_ACTIVE {
		t.Fatalf("items = %+v", items)
	}

	for name, call := range writeCalls(svc, fp, ca.cert.Raw) {
		wantRefusal(t, call(adminCtx()), apperr.CodeOperatorCAManagedByConfig, fleetv1.ErrorReason_ERROR_REASON_UNSPECIFIED)
		_ = name
	}
}

// Every write is admin-only.
func TestOperatorCAs_WritesNeedAdmin(t *testing.T) {
	f := newRotationFixture(t, operatorca.PolicySoft)
	for name, call := range writeCalls(f.svc, operatorca.Fingerprint(f.ca.cert), newTestCA(t, "Example Operator CA G2").cert.Raw) {
		if got := connect.CodeOf(call(operatorCtx("op@example.org", authz.LevelOperator))); got != connect.CodePermissionDenied {
			t.Errorf("%s as an operator: code = %v, want PermissionDenied", name, got)
		}
	}
}

func writeCalls(svc *Service, sha string, certDER []byte) map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"RegisterOperatorCA": func(ctx context.Context) error {
			req := noCRL()
			req.CaCertDer = certDER
			_, err := svc.RegisterOperatorCA(ctx, connect.NewRequest(req))
			return err
		},
		"RetireOperatorCA": func(ctx context.Context) error {
			_, err := svc.RetireOperatorCA(ctx, connect.NewRequest(&fleetv1.RetireOperatorCARequest{Sha256: sha}))
			return err
		},
		"SetOperatorCACRLSource": func(ctx context.Context) error {
			_, err := svc.SetOperatorCACRLSource(ctx, connect.NewRequest(&fleetv1.SetOperatorCACRLSourceRequest{
				Sha256: sha, CrlSource: &fleetv1.SetOperatorCACRLSourceRequest_None{None: true},
				Acknowledgements: []fleetv1.OperatorCAAcknowledgement{fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_NO_CRL},
			}))
			return err
		},
		"UploadOperatorCRL": func(ctx context.Context) error {
			_, err := svc.UploadOperatorCRL(ctx, connect.NewRequest(&fleetv1.UploadOperatorCRLRequest{Sha256: sha, CrlDer: []byte{1}}))
			return err
		},
		"SetOperatorCAOCSP": func(ctx context.Context) error {
			_, err := svc.SetOperatorCAOCSP(ctx, connect.NewRequest(&fleetv1.SetOperatorCAOCSPRequest{Sha256: sha, OcspMode: fleetv1.OcspMode_OCSP_MODE_OFF}))
			return err
		},
	}
}
