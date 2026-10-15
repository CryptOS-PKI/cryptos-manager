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
	"encoding/pem"
	"errors"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

func pemCert(t *testing.T, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestValidateCertificateChain_Operator_ValidChain(t *testing.T) {
	nodeRoot := newTestCA(t, "node-root")
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := nodeRoot.leaf(t, &key.PublicKey, "leaf.acme.example", "viewer", 1)

	connA := &fakeConn{
		identity: &nodev1.GetIdentityResponse{
			Identity: &nodev1.Identity{ChainDer: [][]byte{nodeRoot.cert.Raw}},
		},
	}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.ValidateCertificateChain(ctx, connect.NewRequest(&fleetv1.ValidateCertificateChainRequest{
		NodeName:       "A",
		CertificatePem: pemCert(t, leaf.Raw),
	}))
	if err != nil {
		t.Fatalf("ValidateCertificateChain() error = %v, want nil", err)
	}
	if !resp.Msg.GetValid() {
		t.Errorf("Valid = false, reason %q, want true", resp.Msg.GetReason())
	}
	if resp.Msg.GetReason() != "" {
		t.Errorf("Reason = %q, want empty for a valid chain", resp.Msg.GetReason())
	}
	if resp.Msg.GetSubject() != leaf.Subject.String() {
		t.Errorf("Subject = %q, want %q", resp.Msg.GetSubject(), leaf.Subject.String())
	}
	if resp.Msg.GetNodeCaSubject() != nodeRoot.cert.Subject.String() {
		t.Errorf("NodeCaSubject = %q, want %q", resp.Msg.GetNodeCaSubject(), nodeRoot.cert.Subject.String())
	}
}

func TestValidateCertificateChain_Operator_WrongCA_InvalidWithReason(t *testing.T) {
	nodeRoot := newTestCA(t, "node-root")
	otherRoot := newTestCA(t, "unrelated-root")
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := otherRoot.leaf(t, &key.PublicKey, "leaf.acme.example", "viewer", 1)

	connA := &fakeConn{
		identity: &nodev1.GetIdentityResponse{
			Identity: &nodev1.Identity{ChainDer: [][]byte{nodeRoot.cert.Raw}},
		},
	}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	resp, err := svc.ValidateCertificateChain(ctx, connect.NewRequest(&fleetv1.ValidateCertificateChainRequest{
		NodeName:       "A",
		CertificatePem: pemCert(t, leaf.Raw),
	}))
	if err != nil {
		t.Fatalf("ValidateCertificateChain() error = %v, want nil (a bad chain is a result, not an error)", err)
	}
	if resp.Msg.GetValid() {
		t.Error("Valid = true, want false for a certificate from an unrelated CA")
	}
	if resp.Msg.GetReason() == "" {
		t.Error("Reason is empty, want an explanation")
	}
}

func TestValidateCertificateChain_ViewerDenied_NoDial(t *testing.T) {
	connA := &fakeConn{}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.ValidateCertificateChain(ctx, connect.NewRequest(&fleetv1.ValidateCertificateChainRequest{
		NodeName:       "A",
		CertificatePem: "garbage",
	}))
	if err == nil {
		t.Fatal("ValidateCertificateChain(viewer) error = nil, want PermissionDenied")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodePermissionDenied {
		t.Errorf("code = %v, want CodePermissionDenied", connectErr.Code())
	}
	if connA.closed {
		t.Error("node connection was opened, want no dial")
	}
}

func TestValidateCertificateChain_UnknownNode_NotFound(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{}))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.ValidateCertificateChain(ctx, connect.NewRequest(&fleetv1.ValidateCertificateChainRequest{
		NodeName:       "missing",
		CertificatePem: "garbage",
	}))
	if err == nil {
		t.Fatal("ValidateCertificateChain(unknown node) error = nil, want NotFound")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeNotFound {
		t.Errorf("code = %v, want CodeNotFound", connectErr.Code())
	}
}

func TestValidateCertificateChain_MalformedPEM_InvalidArgument(t *testing.T) {
	connA := &fakeConn{}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("op@acme.example", authz.LevelOperator)
	_, err := svc.ValidateCertificateChain(ctx, connect.NewRequest(&fleetv1.ValidateCertificateChainRequest{
		NodeName:       "A",
		CertificatePem: "not a certificate",
	}))
	if err == nil {
		t.Fatal("ValidateCertificateChain(malformed PEM) error = nil, want InvalidArgument")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want CodeInvalidArgument", connectErr.Code())
	}
	if connA.closed {
		t.Error("node connection was opened, want no dial for a PEM that fails to parse")
	}
}
