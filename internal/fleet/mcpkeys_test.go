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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/mcpauth"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
)

// certCtx returns the context the client-cert middleware builds for a
// self-signed operator certificate at level with the given serial.
func certCtx(t *testing.T, serial int64, level authz.Level) context.Context {
	t.Helper()
	value, _ := asn1.Marshal(level.Token())
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(serial),
		Subject:         pkix.Name{CommonName: "operator@example.org"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 1}, Value: value}},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	var ctx context.Context
	req := httptest.NewRequest(http.MethodPost, "/rpc", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	authz.ClientCertMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
	})).ServeHTTP(httptest.NewRecorder(), req)
	return ctx
}

func mcpService(enabled bool) (*Service, *memory.Store) {
	st := memory.New(nil)
	return New(st, nil).WithMCP(&mcpauth.Keys{Store: st}, enabled), st
}

func requireAppCode(t *testing.T, err error, code int) {
	t.Helper()
	if got, ok := apperr.Code(err); !ok || got != code {
		t.Fatalf("app code = %d (%v), want %d; err %v", got, ok, code, err)
	}
}

func TestCreateMcpKey_ReturnsPlaintextOnceAndStoresHash(t *testing.T) {
	svc, st := mcpService(true)
	resp, err := svc.CreateMcpKey(certCtx(t, 0x0abc, authz.LevelOperator), connect.NewRequest(&fleetv1.CreateMcpKeyRequest{
		Label: "ci", LevelCeiling: "viewer",
	}))
	if err != nil {
		t.Fatalf("CreateMcpKey: %v", err)
	}
	plain := resp.Msg.GetPlaintextKey()
	if !mcpauth.WellFormed(plain) {
		t.Fatalf("plaintext %q is not an MCP key", plain)
	}
	k := resp.Msg.GetMcpKey()
	if k.GetLabel() != "ci" || k.GetLevelCeiling() != "viewer" || k.GetOperatorSerial() != "0A:BC" ||
		k.GetOperatorCn() != "operator@example.org" || k.GetClientName() != "" || k.GetRevokedAt() != "" || k.GetLastUsedAt() != "" {
		t.Fatalf("McpKey = %+v", k)
	}
	if _, err := time.Parse(time.RFC3339, k.GetCreatedAt()); err != nil {
		t.Fatalf("created_at %q is not RFC3339", k.GetCreatedAt())
	}
	stored, ok := st.McpKeyByHash(mcpauth.HashKey(plain))
	if !ok || len(stored.OperatorCertDER) == 0 {
		t.Fatalf("stored = %+v, %v; want the key hash and the operator cert", stored, ok)
	}
}

func TestCreateMcpKey_Refusals(t *testing.T) {
	t.Run("mcp disabled", func(t *testing.T) {
		svc, _ := mcpService(false)
		_, err := svc.CreateMcpKey(certCtx(t, 1, authz.LevelAdmin), connect.NewRequest(&fleetv1.CreateMcpKeyRequest{}))
		requireConnectCode(t, err, connect.CodeFailedPrecondition)
		requireAppCode(t, err, apperr.CodeMcpDisabled)
	})
	t.Run("no client certificate", func(t *testing.T) {
		svc, _ := mcpService(true)
		_, err := svc.CreateMcpKey(authz.NewContext(context.Background(), authz.DevIdentity), connect.NewRequest(&fleetv1.CreateMcpKeyRequest{}))
		requireConnectCode(t, err, connect.CodePermissionDenied)
		requireAppCode(t, err, apperr.CodeMcpKeyNeedsCert)
	})
	t.Run("ceiling above level", func(t *testing.T) {
		svc, _ := mcpService(true)
		_, err := svc.CreateMcpKey(certCtx(t, 1, authz.LevelViewer), connect.NewRequest(&fleetv1.CreateMcpKeyRequest{LevelCeiling: "operator"}))
		requireConnectCode(t, err, connect.CodeInvalidArgument)
		requireAppCode(t, err, apperr.CodeMcpCeilingTooHigh)
	})
}

// An MCP key can never manage keys, even if a key-authenticated context
// reached the handler.
func TestMcpKeyRPCs_RefuseKeyAuthenticatedCallers(t *testing.T) {
	svc, _ := mcpService(true)
	ctx := authz.NewContext(context.Background(), authz.Identity{CN: "operator@example.org", Serial: "01", Level: authz.LevelAdmin, Via: authz.ViaMCP, KeyID: "mk-1"})

	_, err := svc.CreateMcpKey(ctx, connect.NewRequest(&fleetv1.CreateMcpKeyRequest{}))
	requireAppCode(t, err, apperr.CodeMcpKeyNeedsCert)
	_, err = svc.ListMcpKeys(ctx, connect.NewRequest(&fleetv1.ListMcpKeysRequest{}))
	requireAppCode(t, err, apperr.CodeMcpKeyNeedsCert)
	_, err = svc.RevokeMcpKey(ctx, connect.NewRequest(&fleetv1.RevokeMcpKeyRequest{Id: "mk-1"}))
	requireAppCode(t, err, apperr.CodeMcpKeyNeedsCert)
}

func TestListAndRevokeMcpKeys(t *testing.T) {
	svc, _ := mcpService(true)
	mine := certCtx(t, 1, authz.LevelOperator)
	theirs := certCtx(t, 2, authz.LevelOperator)
	admin := certCtx(t, 3, authz.LevelAdmin)

	created, _ := svc.CreateMcpKey(mine, connect.NewRequest(&fleetv1.CreateMcpKeyRequest{Label: "a"}))
	_, _ = svc.CreateMcpKey(theirs, connect.NewRequest(&fleetv1.CreateMcpKeyRequest{Label: "b"}))
	id := created.Msg.GetMcpKey().GetId()

	own, err := svc.ListMcpKeys(mine, connect.NewRequest(&fleetv1.ListMcpKeysRequest{}))
	if err != nil || len(own.Msg.GetItems()) != 1 || own.Msg.GetItems()[0].GetLabel() != "a" {
		t.Fatalf("own list = %v, %v", own, err)
	}
	_, err = svc.ListMcpKeys(mine, connect.NewRequest(&fleetv1.ListMcpKeysRequest{All: true}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	all, err := svc.ListMcpKeys(admin, connect.NewRequest(&fleetv1.ListMcpKeysRequest{All: true}))
	if err != nil || len(all.Msg.GetItems()) != 2 {
		t.Fatalf("admin list = %v, %v", all, err)
	}

	_, err = svc.RevokeMcpKey(theirs, connect.NewRequest(&fleetv1.RevokeMcpKeyRequest{Id: id}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	_, err = svc.RevokeMcpKey(mine, connect.NewRequest(&fleetv1.RevokeMcpKeyRequest{Id: "mk-missing"}))
	requireConnectCode(t, err, connect.CodeNotFound)
	requireAppCode(t, err, apperr.CodeMcpKeyNotFound)

	rev, err := svc.RevokeMcpKey(mine, connect.NewRequest(&fleetv1.RevokeMcpKeyRequest{Id: id}))
	if err != nil || rev.Msg.GetMcpKey().GetRevokedAt() == "" {
		t.Fatalf("revoke = %v, %v", rev, err)
	}
	again, err := svc.RevokeMcpKey(admin, connect.NewRequest(&fleetv1.RevokeMcpKeyRequest{Id: id}))
	if err != nil || again.Msg.GetMcpKey().GetRevokedAt() != rev.Msg.GetMcpKey().GetRevokedAt() {
		t.Fatalf("idempotent revoke = %v, %v", again, err)
	}
	if strings.Contains(strconv.Quote(rev.Msg.String()), "fos_mcp_") {
		t.Fatal("revoke response carries a key")
	}
}
