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
	"errors"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
	"github.com/CryptOS-PKI/manager/internal/authz"
	"github.com/CryptOS-PKI/manager/internal/store/memory"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func requireNodeReason(t *testing.T, err error, want string) {
	t.Helper()
	got, ok := apperr.NodeReasonOf(err)
	if !ok || got != want {
		t.Fatalf("node reason = %q (found %t), want %q", got, ok, want)
	}
}

// The lab case: a node refusing a protocol switch (there, EST on a root
// node). The client gets the config-rejected code with the node's reason, not
// 1900.
func TestSetNodeProtocol_NodeRefusal_CarriesTheNodeReason(t *testing.T) {
	st := protocolTestStore()
	conn := &fakeConn{
		getConfigResp:  &cryptosv1.GetConfigResponse{Config: protocolConfigFixture()},
		applyConfigErr: status.Error(codes.InvalidArgument, "pki.est: must not be set on a root node"),
	}
	svc := New(st, dialFor(map[string]*fakeConn{"issuing-1": conn}))

	_, err := setProtocol(t, svc, authz.LevelAdmin, acme, true)
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	requireAppCode(t, err, apperr.CodeConfigRejected)
	requireNodeReason(t, err, "pki.est: must not be set on a root node")
}

func TestNodeError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		op         string
		err        error
		code       connect.Code
		appCode    int
		nodeReason string
	}{
		{"config refused", "apply config", status.Error(codes.InvalidArgument, "pki.acme: profile missing"), connect.CodeInvalidArgument, apperr.CodeConfigRejected, "pki.acme: profile missing"},
		{"precondition", "apply config", status.Error(codes.FailedPrecondition, "node is in root mode"), connect.CodeFailedPrecondition, apperr.CodeNodeRefused, "node is in root mode"},
		{"permission", "get config", status.Error(codes.PermissionDenied, "operator surface is read-only"), connect.CodePermissionDenied, apperr.CodeNodeRefused, "operator surface is read-only"},
		{"unreachable", "get config", status.Error(codes.Unavailable, "connection error: dial tcp 192.0.2.10:443: connect: connection refused"), connect.CodeUnavailable, apperr.CodeNodeUnreachable, ""},
		{"untrusted", "get config", status.Error(codes.Unavailable, "connection error: nodeclient: node pki-root refused: its server certificate (sha256 ab12cd) does not verify against the recorded CA chain /var/lib/x/ca.crt"), connect.CodeFailedPrecondition, apperr.CodeNodeUntrusted, "the node's server certificate (sha256 ab12cd) did not verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := nodeError(tc.op, tc.err)
			requireConnectCode(t, err, tc.code)
			requireAppCode(t, err, tc.appCode)
			got, _ := apperr.NodeReasonOf(err)
			if got != tc.nodeReason {
				t.Errorf("node reason = %q, want %q", got, tc.nodeReason)
			}
		})
	}
}

func TestNodeError_PlainErrorStaysUnclassified(t *testing.T) {
	err := nodeError("apply config", errors.New("boom"))
	requireConnectCode(t, err, connect.CodeInternal)
	if _, ok := apperr.Code(err); ok {
		t.Errorf("a plain error got a code: %v", err)
	}
}

// A wrong maintenance pin is a refused certificate, not an unclassified
// failure.
func TestListInstallDisks_WrongPinIsUntrusted(t *testing.T) {
	conn := &fakeConn{err: status.Error(codes.Unavailable, "connection error: nodeclient: maintenance endpoint 192.0.2.60:443 refused: its server certificate (sha256 10e470cc) does not match the pinned value")}
	svc := New(memory.New(nil), dialFor(nil)).WithAdoption(nil,
		func(string, string, string, string) (NodeConn, error) { return conn, nil })
	_, err := svc.ListInstallDisks(operatorCtx("admin@example.org", authz.LevelAdmin), connect.NewRequest(&fleetv1.ListInstallDisksRequest{
		Endpoint: "192.0.2.60:443", PinnedCertSha256: "abc",
	}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
	requireAppCode(t, err, apperr.CodeNodeUntrusted)
	requireNodeReason(t, err, "the node's server certificate (sha256 10e470cc) did not verify")
}
