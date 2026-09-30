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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/operatorca"
	"github.com/CryptOS-PKI/manager/internal/store"
)

func noCRL(ca testCA) *fleetv1.BootstrapServiceRegisterOperatorCARequest {
	return &fleetv1.BootstrapServiceRegisterOperatorCARequest{
		CaCertDer:        ca.cert.Raw,
		CrlSource:        &fleetv1.BootstrapServiceRegisterOperatorCARequest_None{None: true},
		Acknowledgements: []fleetv1.OperatorCAAcknowledgement{fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_NO_CRL},
	}
}

func TestRegister_PreviewThenConfirmWithTheFingerprint(t *testing.T) {
	h := newHarness(t)
	secret := h.startSession()
	ca := newCA(t, "Example Operator CA")

	preview, err := h.register(secret, noCRL(ca))
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	oc := preview.GetOperatorCa()
	if preview.GetConfirmed() || oc.GetSha256() != operatorca.Fingerprint(ca.cert) ||
		!strings.Contains(oc.GetSubject(), "Example Operator CA") || oc.GetNotAfter() == "" {
		t.Fatalf("preview = %+v", preview)
	}
	if cas, _ := h.st.OperatorCAs(h.ctx); len(cas) != 0 {
		t.Fatal("a preview stored the operator CA")
	}
	_, der, _ := authz.MarshalLevelExtension("admin")
	if want := colonHex(der); !strings.Contains(preview.GetAdminExtfile(), "1.3.6.1.4.1.59999.1.1") || !strings.Contains(preview.GetAdminExtfile(), "DER:"+want) {
		t.Fatalf("admin_extfile = %q; want the level extension DER:%s from MarshalLevelExtension", preview.GetAdminExtfile(), want)
	}

	wrong := noCRL(ca)
	wrong.ConfirmSha256 = strings.Repeat("ab", 32)
	_, err = h.register(secret, wrong)
	wantCode(t, err, apperr.CodeOperatorCARejected, "NOT_CONFIRMED")

	ok := noCRL(ca)
	ok.ConfirmSha256 = operatorca.ColonFingerprint(ca.cert.Raw) // pasted from openssl, colons and upper case
	done, err := h.register(secret, ok)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !done.GetConfirmed() || done.GetOperatorCa().GetState() != fleetv1.OperatorCAState_OPERATOR_CA_STATE_ACTIVE {
		t.Fatalf("confirm response = %+v", done)
	}
	anchors := h.trust.Anchors()
	if len(anchors) != 1 || anchors[0].SHA256 != operatorca.Fingerprint(ca.cert) {
		t.Fatalf("trusted anchors after confirm = %+v; want the registered CA with no restart", anchors)
	}
	rows := h.auditKinds(KindOperatorCARegistered)
	if len(rows) != 1 || rows[0].ActorKind != ActorBootstrapSession || !strings.Contains(rows[0].Summary, operatorca.Fingerprint(ca.cert)) ||
		!strings.Contains(rows[0].Summary, "192.0.2.10") || !strings.Contains(rows[0].Summary, "NO_CRL") {
		t.Fatalf("registration audit = %+v", rows)
	}
	if h.state().GetState() != fleetv1.BootstrapState_BOOTSTRAP_STATE_OPEN_IN_PROGRESS {
		t.Fatal("a registration didn't make first run in progress")
	}
}

func TestRegister_RefusesABadAnchor(t *testing.T) {
	h := newHarness(t)
	secret := h.startSession()
	node := newCA(t, "Example Node CA")
	h.nodeCA = []testCA{node}

	notCA := node.leaf(t, leafOpts{})
	_, err := h.register(secret, &fleetv1.BootstrapServiceRegisterOperatorCARequest{CaCertDer: notCA.Raw,
		CrlSource:        &fleetv1.BootstrapServiceRegisterOperatorCARequest_None{None: true},
		Acknowledgements: []fleetv1.OperatorCAAcknowledgement{fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_NO_CRL}})
	wantCode(t, err, apperr.CodeOperatorCARejected, "NOT_A_CA")

	_, err = h.clientFrom("192.0.2.11:1", true).RegisterOperatorCA(h.ctx, withSession(secret, noCRL(node)))
	wantCode(t, err, apperr.CodeOperatorCARejected, "IS_NODE_CA")

	sub := newCAWith(t, "Example Sub CA", x509.KeyUsageCertSign|x509.KeyUsageCRLSign, &node)
	resp, err := h.clientFrom("192.0.2.12:1", true).RegisterOperatorCA(h.ctx, withSession(secret, noCRL(sub)))
	if err != nil {
		t.Fatalf("a sub-CA of a node CA was refused: %v", err)
	}
	if len(resp.Msg.GetOperatorCa().GetWarnings()) == 0 {
		t.Fatal("a sub-CA of a node CA carries no warning")
	}
}

func TestRegister_CRLSources(t *testing.T) {
	ca := newCA(t, "Example Operator CA")
	other := newCA(t, "Example Other CA")
	good := ca.crl(t, 10)
	foreign := other.crl(t, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/good.crl":
			_, _ = w.Write(good)
		case "/foreign.crl":
			_, _ = w.Write(foreign)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	withURL := func(u string) *fleetv1.BootstrapServiceRegisterOperatorCARequest {
		return &fleetv1.BootstrapServiceRegisterOperatorCARequest{CaCertDer: ca.cert.Raw, CrlSource: &fleetv1.BootstrapServiceRegisterOperatorCARequest_Url{Url: u}}
	}
	withDER := func(der []byte) *fleetv1.BootstrapServiceRegisterOperatorCARequest {
		return &fleetv1.BootstrapServiceRegisterOperatorCARequest{CaCertDer: ca.cert.Raw, CrlSource: &fleetv1.BootstrapServiceRegisterOperatorCARequest_CrlDer{CrlDer: der}}
	}

	cases := []struct {
		name   string
		msg    *fleetv1.BootstrapServiceRegisterOperatorCARequest
		reason string
	}{
		{"url unreachable", withURL(srv.URL + "/missing.crl"), "CRL_UNREACHABLE"},
		{"url not http", withURL("file:///etc/passwd"), "CRL_UNREACHABLE"},
		{"url from another CA", withURL(srv.URL + "/foreign.crl"), "CRL_INVALID"},
		{"upload from another CA", withDER(foreign), "CRL_INVALID"},
		{"none without the acknowledgement", &fleetv1.BootstrapServiceRegisterOperatorCARequest{CaCertDer: ca.cert.Raw,
			CrlSource: &fleetv1.BootstrapServiceRegisterOperatorCARequest_None{None: true}}, "NO_CRL_NOT_ACKNOWLEDGED"},
		{"no CRL source at all", &fleetv1.BootstrapServiceRegisterOperatorCARequest{CaCertDer: ca.cert.Raw}, "NO_CRL_NOT_ACKNOWLEDGED"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			secret := h.startSession()
			_, err := h.clientFrom("192.0.2."+string(rune('a'+i))+":1", true).RegisterOperatorCA(h.ctx, withSession(secret, tc.msg))
			wantCode(t, err, apperr.CodeOperatorCARejected, tc.reason)
			if strings.Contains(err.Error(), string(foreign)) {
				t.Fatal("the refusal echoes the fetched body")
			}
		})
	}

	t.Run("CRL signing missing", func(t *testing.T) {
		h := newHarness(t)
		secret := h.startSession()
		noSign := newCAWith(t, "Example No-CRL CA", x509.KeyUsageCertSign, nil)
		_, err := h.register(secret, &fleetv1.BootstrapServiceRegisterOperatorCARequest{CaCertDer: noSign.cert.Raw,
			CrlSource: &fleetv1.BootstrapServiceRegisterOperatorCARequest_Url{Url: srv.URL + "/good.crl"}})
		wantCode(t, err, apperr.CodeOperatorCARejected, "CRL_SIGN_MISSING")
	})

	t.Run("url stores the CRL and the OCSP settings", func(t *testing.T) {
		h := newHarness(t)
		secret := h.startSession()
		msg := withURL(srv.URL + "/good.crl")
		msg.OcspMode = fleetv1.OcspMode_OCSP_MODE_URL
		msg.OcspUrl = "http://ocsp.example.org/"
		preview, err := h.register(secret, msg)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if st := preview.GetOperatorCa().GetCrl(); st.GetNextUpdate() == "" || st.GetCrlNumber() != "10" {
			t.Fatalf("preview CRL status = %+v", st)
		}
		msg.ConfirmSha256 = preview.GetOperatorCa().GetSha256()
		if _, err := h.register(secret, msg); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		cas, _ := h.st.OperatorCAs(h.ctx)
		if len(cas) != 1 || cas[0].CRLSource != store.CRLSourceURL || cas[0].CRLURL != srv.URL+"/good.crl" ||
			cas[0].OCSPMode != store.OCSPModeURL || cas[0].OCSPURL != "http://ocsp.example.org/" {
			t.Fatalf("stored row = %+v", cas)
		}
		if crl, ok := h.rev.CRL(cas[0].SHA256); !ok || crl.Number.Int64() != 10 {
			t.Fatal("the registered CRL isn't enforced at once")
		}
	})

	t.Run("upload is verified and stored", func(t *testing.T) {
		h := newHarness(t)
		secret := h.startSession()
		msg := withDER(good)
		preview, err := h.register(secret, msg)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		msg.ConfirmSha256 = preview.GetOperatorCa().GetSha256()
		if _, err := h.register(secret, msg); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		cas, _ := h.st.OperatorCAs(h.ctx)
		if len(cas) != 1 || cas[0].CRLSource != store.CRLSourceUpload || cas[0].OCSPMode != store.OCSPModeAIA {
			t.Fatalf("stored row = %+v; want the upload source and the default OCSP mode aia", cas)
		}
	})

	t.Run("OCSP url mode needs an http URL", func(t *testing.T) {
		h := newHarness(t)
		secret := h.startSession()
		msg := noCRL(ca)
		msg.OcspMode = fleetv1.OcspMode_OCSP_MODE_URL
		msg.OcspUrl = "ldap://ocsp.example.org/"
		_, err := h.register(secret, msg)
		wantCode(t, err, apperr.CodeOperatorCARejected, "OCSP_UNREACHABLE")
	})

	t.Run("OCSP url mode runs the probe", func(t *testing.T) {
		probed := ""
		h := newHarness(t, func(o *Options) {
			o.OCSPProbe = func(_ context.Context, anchor *x509.Certificate, url string) (*fleetv1.OcspProbeResult, error) {
				probed = url
				return &fleetv1.OcspProbeResult{Signer: fleetv1.OcspSigner_OCSP_SIGNER_ANCHOR, CertStatus: "unknown"}, nil
			}
		})
		secret := h.startSession()
		msg := noCRL(ca)
		msg.OcspMode = fleetv1.OcspMode_OCSP_MODE_URL
		msg.OcspUrl = "http://ocsp.example.org/"
		resp, err := h.register(secret, msg)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if probed != "http://ocsp.example.org/" || resp.GetOcspProbe().GetSigner() != fleetv1.OcspSigner_OCSP_SIGNER_ANCHOR {
			t.Fatalf("probe url %q, result %+v", probed, resp.GetOcspProbe())
		}

		aia := noCRL(ca)
		probed = ""
		if _, err := h.register(secret, aia); err != nil || probed != "" {
			t.Fatalf("aia mode: err %v, probed %q; want no probe", err, probed)
		}
	})
}

func TestRegister_LaterSessionRetiresTheEarlierAndMustReconfirm(t *testing.T) {
	h := newHarness(t)
	rogue := newCA(t, "Example Rogue CA")
	genuine := newCA(t, "Example Operator CA")

	a := h.startSession()
	h.registerCA(a, rogue)
	rogueAdmin := rogue.leaf(t, leafOpts{})
	auth := operatorca.PeerAuthorizer{Trust: h.trust, Rev: h.rev}
	if _, err := auth.AuthorizePeer(rogueAdmin, nil); err != nil {
		t.Fatalf("the registered CA's admin was refused: %v", err)
	}

	b := h.startSession()
	// A new session sees the current registration and must confirm it again.
	cur, err := h.register(b, &fleetv1.BootstrapServiceRegisterOperatorCARequest{})
	if err != nil {
		t.Fatalf("preview of the current registration: %v", err)
	}
	if cur.GetConfirmed() || cur.GetOperatorCa().GetSha256() != operatorca.Fingerprint(rogue.cert) {
		t.Fatalf("current registration preview = %+v", cur)
	}
	_, err = h.submit(b, &fleetv1.SubmitFirstAdminCertificateRequest{CertDer: rogueAdmin.Raw, FullName: "Ada Example"})
	wantCode(t, err, apperr.CodeOperatorCARejected, "NOT_CONFIRMED")

	h.registerCA(b, genuine)
	cas, _ := h.st.OperatorCAs(h.ctx)
	for _, c := range cas {
		if c.SHA256 == operatorca.Fingerprint(rogue.cert) && (c.State != store.OperatorCARetired || c.RetiredReason != store.RetiredSuperseded) {
			t.Fatalf("the earlier registration = %+v; want retired at once", c)
		}
	}
	if _, err := auth.AuthorizePeer(rogueAdmin, nil); err == nil {
		t.Fatal("a certificate from the replaced CA still authenticates")
	}

	// Re-confirming the current registration without changing it.
	c := h.startSession()
	again := &fleetv1.BootstrapServiceRegisterOperatorCARequest{ConfirmSha256: operatorca.Fingerprint(genuine.cert)}
	resp, err := h.register(c, again)
	if err != nil || !resp.GetConfirmed() {
		t.Fatalf("re-confirm = %+v, %v", resp, err)
	}
	if by, _ := h.st.OperatorCAConfirmedBy(h.ctx, operatorca.Fingerprint(genuine.cert)); by != HashSecret(c) {
		t.Fatal("the re-confirmation wasn't recorded for the new session")
	}
}

func TestRegister_NothingRegisteredToPreview(t *testing.T) {
	h := newHarness(t)
	secret := h.startSession()
	_, err := h.register(secret, &fleetv1.BootstrapServiceRegisterOperatorCARequest{})
	wantCode(t, err, apperr.CodeOperatorCARejected, "NOT_CONFIRMED")
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("Connect code %v, want FailedPrecondition", connect.CodeOf(err))
	}
}

func colonHex(b []byte) string {
	const digits = "0123456789ABCDEF"
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = string([]byte{digits[c>>4], digits[c&0x0f]})
	}
	return strings.Join(parts, ":")
}
