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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// testCertDER returns a throwaway self-signed certificate's DER.
func testCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemBlocks(t *testing.T, s string) [][]byte {
	t.Helper()
	var out [][]byte
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		if b.Type != "CERTIFICATE" {
			t.Fatalf("PEM block type %q", b.Type)
		}
		out = append(out, b.Bytes)
	}
}

func TestGetCertificate_ReturnsPEMAndChainToAViewer(t *testing.T) {
	leaf, issuer, root := testCertDER(t, "svc.example.org"), testCertDER(t, "Example Issuing CA"), testCertDER(t, "Example Root CA G1")
	connB := &fakeConn{getIssued: &cryptosv1.GetIssuedCertificateResponse{CertificateDer: leaf, ChainDer: [][]byte{issuer, root}, Status: "valid"}}
	st := certsTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{"B": connB}))
	before := len(st.Audit())

	resp, err := svc.GetCertificate(operatorCtx("viewer@example.org", authz.LevelViewer), connect.NewRequest(&fleetv1.GetCertificateRequest{NodeName: "B", SerialHex: "0a1b"}))
	if err != nil {
		t.Fatalf("GetCertificate(viewer) error = %v", err)
	}
	if connB.gotGetSerial != "0a1b" || !connB.closed {
		t.Errorf("node asked for %q (closed %v)", connB.gotGetSerial, connB.closed)
	}
	if got := pemBlocks(t, resp.Msg.GetCertificatePem()); len(got) != 1 || string(got[0]) != string(leaf) {
		t.Errorf("certificate_pem does not hold the leaf")
	}
	if got := pemBlocks(t, resp.Msg.GetChainPem()); len(got) != 2 || string(got[0]) != string(issuer) || string(got[1]) != string(root) {
		t.Errorf("chain_pem does not hold issuer then root")
	}
	if resp.Msg.GetStatus() != "valid" || resp.Msg.GetRevokedAt() != "" {
		t.Errorf("status = %q, revoked_at = %q", resp.Msg.GetStatus(), resp.Msg.GetRevokedAt())
	}
	if len(st.Audit()) != before {
		t.Error("a web read wrote an audit row")
	}
}

func TestGetCertificate_RevokedIsReturnedWithItsStatus(t *testing.T) {
	connB := &fakeConn{getIssued: &cryptosv1.GetIssuedCertificateResponse{
		CertificateDer: testCertDER(t, "svc.example.org"), Status: "revoked", RevokedAt: "2026-09-01T00:00:00Z",
	}}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"B": connB}))

	resp, err := svc.GetCertificate(operatorCtx("viewer@example.org", authz.LevelViewer), connect.NewRequest(&fleetv1.GetCertificateRequest{NodeName: "B", SerialHex: "0a1b"}))
	if err != nil {
		t.Fatalf("GetCertificate error = %v", err)
	}
	if resp.Msg.GetStatus() != "revoked" || resp.Msg.GetRevokedAt() != "2026-09-01T00:00:00Z" || resp.Msg.GetCertificatePem() == "" {
		t.Errorf("response = %v", resp.Msg)
	}
}

func TestGetCertificate_Refusals(t *testing.T) {
	viewer := operatorCtx("viewer@example.org", authz.LevelViewer)
	t.Run("unknown serial", func(t *testing.T) {
		connB := &fakeConn{getIssuedErr: status.Error(codes.NotFound, "no such serial")}
		svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"B": connB}))
		_, err := svc.GetCertificate(viewer, connect.NewRequest(&fleetv1.GetCertificateRequest{NodeName: "B", SerialHex: "ffff"}))
		requireConnectCode(t, err, connect.CodeNotFound)
		requireAppCode(t, err, apperr.CodeCertificateNotFound)
	})
	t.Run("unknown node", func(t *testing.T) {
		svc := New(certsTestStore(), dialFor(map[string]*fakeConn{}))
		_, err := svc.GetCertificate(viewer, connect.NewRequest(&fleetv1.GetCertificateRequest{NodeName: "Z", SerialHex: "0a"}))
		requireConnectCode(t, err, connect.CodeNotFound)
		requireAppCode(t, err, apperr.CodeNodeNotFound)
	})
	t.Run("empty serial", func(t *testing.T) {
		connB := &fakeConn{}
		svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"B": connB}))
		_, err := svc.GetCertificate(viewer, connect.NewRequest(&fleetv1.GetCertificateRequest{NodeName: "B"}))
		requireConnectCode(t, err, connect.CodeInvalidArgument)
		if connB.gotGetSerial != "" {
			t.Error("the node was asked")
		}
	})
	t.Run("no identity", func(t *testing.T) {
		connB := &fakeConn{}
		svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"B": connB}))
		_, err := svc.GetCertificate(context.Background(), connect.NewRequest(&fleetv1.GetCertificateRequest{NodeName: "B", SerialHex: "0a"}))
		requireConnectCode(t, err, connect.CodeUnauthenticated)
		if connB.gotGetSerial != "" {
			t.Error("the node was asked")
		}
	})
	t.Run("node error", func(t *testing.T) {
		connB := &fakeConn{getIssuedErr: status.Error(codes.Unavailable, "down")}
		svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"B": connB}))
		_, err := svc.GetCertificate(viewer, connect.NewRequest(&fleetv1.GetCertificateRequest{NodeName: "B", SerialHex: "0a"}))
		requireConnectCode(t, err, connect.CodeInternal)
	})
}
