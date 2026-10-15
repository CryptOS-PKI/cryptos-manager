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
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestListNodeTsaCertificates_Viewer_ReturnsCertificates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	connA := &fakeConn{
		listTsaCertificatesResp: &nodev1.ListTsaCertificatesResponse{
			Certificates: []*nodev1.TsaCertificate{
				{
					CertPem:   "-----BEGIN CERTIFICATE-----\ntsa\n-----END CERTIFICATE-----\n",
					SerialHex: "0a1b",
					Sha256Hex: "deadbeef",
					NotBefore: timestamppb.New(now.Add(-time.Hour)),
					NotAfter:  timestamppb.New(now.Add(time.Hour)),
					Current:   true,
				},
			},
		},
	}

	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	resp, err := svc.ListNodeTsaCertificates(ctx, connect.NewRequest(&fleetv1.ListNodeTsaCertificatesRequest{NodeName: "A"}))
	if err != nil {
		t.Fatalf("ListNodeTsaCertificates() error = %v, want nil", err)
	}

	certs := resp.Msg.GetCertificates()
	if len(certs) != 1 {
		t.Fatalf("len(certificates) = %d, want 1", len(certs))
	}
	c := certs[0]
	if c.GetSerialHex() != "0a1b" || c.GetSha256Hex() != "deadbeef" || !c.GetCurrent() {
		t.Errorf("certificate = %+v, want the node's fields flattened through", c)
	}
	if c.GetNotBefore() != now.Add(-time.Hour).Format(time.RFC3339) {
		t.Errorf("NotBefore = %q, want %q", c.GetNotBefore(), now.Add(-time.Hour).Format(time.RFC3339))
	}
}

func TestListNodeTsaCertificates_TsaOff_EmptyList(t *testing.T) {
	connA := &fakeConn{listTsaCertificatesResp: &nodev1.ListTsaCertificatesResponse{}}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	resp, err := svc.ListNodeTsaCertificates(ctx, connect.NewRequest(&fleetv1.ListNodeTsaCertificatesRequest{NodeName: "A"}))
	if err != nil {
		t.Fatalf("ListNodeTsaCertificates() error = %v, want nil", err)
	}
	if len(resp.Msg.GetCertificates()) != 0 {
		t.Errorf("certificates = %v, want empty", resp.Msg.GetCertificates())
	}
}

func TestListNodeTsaCertificates_UnknownNode_NotFound(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.ListNodeTsaCertificates(ctx, connect.NewRequest(&fleetv1.ListNodeTsaCertificatesRequest{NodeName: "missing"}))
	if err == nil {
		t.Fatal("ListNodeTsaCertificates(unknown node) error = nil, want NotFound")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeNotFound {
		t.Errorf("code = %v, want CodeNotFound", connectErr.Code())
	}
}

func TestListNodeTsaCertificates_Unauthenticated_Refused(t *testing.T) {
	connA := &fakeConn{}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))

	_, err := svc.ListNodeTsaCertificates(context.Background(), connect.NewRequest(&fleetv1.ListNodeTsaCertificatesRequest{NodeName: "A"}))
	if err == nil {
		t.Fatal("ListNodeTsaCertificates(no identity) error = nil, want Unauthenticated")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error is not a *connect.Error: %v", err)
	}
	if connectErr.Code() != connect.CodeUnauthenticated {
		t.Errorf("code = %v, want CodeUnauthenticated", connectErr.Code())
	}
}
