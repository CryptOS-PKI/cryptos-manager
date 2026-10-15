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
	"io"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeImageFetch returns body (and its length) for any URL, recording the
// last URL it was asked for.
func fakeImageFetch(body string, gotURL *string) func(context.Context, string) (io.ReadCloser, int64, error) {
	return func(_ context.Context, url string) (io.ReadCloser, int64, error) {
		if gotURL != nil {
			*gotURL = url
		}
		return io.NopCloser(strings.NewReader(body)), int64(len(body)), nil
	}
}

func TestGetNodeImageStatus_Viewer_ReturnsStatus(t *testing.T) {
	conn := &fakeConn{imageStatusResp: &nodev1.GetImageStatusResponse{
		Status: &nodev1.ImageStatus{
			RunningSha256: "aaaa", ActiveSha256: "aaaa", RunningVersion: "0.1.0",
		},
	}}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	resp, err := svc.GetNodeImageStatus(ctx, connect.NewRequest(&fleetv1.GetNodeImageStatusRequest{NodeName: "A"}))
	if err != nil {
		t.Fatalf("GetNodeImageStatus() error = %v, want nil", err)
	}
	st := resp.Msg.GetStatus()
	if st.GetRunningSha256() != "aaaa" || st.GetRunningVersion() != "0.1.0" || st.GetRebootPending() {
		t.Errorf("status = %+v, want the node's fields flattened through", st)
	}
}

func TestGetNodeImageStatus_Unauthenticated_Refused(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}}))
	_, err := svc.GetNodeImageStatus(context.Background(), connect.NewRequest(&fleetv1.GetNodeImageStatusRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodeUnauthenticated)
}

func TestGetNodeImageStatus_UnknownNode_NotFound(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{}))
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.GetNodeImageStatus(ctx, connect.NewRequest(&fleetv1.GetNodeImageStatusRequest{NodeName: "missing"}))
	requireConnectCode(t, err, connect.CodeNotFound)
}

func TestStageNodeImage_Admin_FetchesAndStreamsToNode_Audits(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{stageImageResp: &nodev1.StageImageResponse{
		Status:         &nodev1.ImageStatus{ActiveSha256: "deadbeef"},
		RequiresReboot: true,
	}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))
	var gotURL string
	svc = svc.WithImageFetch(fakeImageFetch("the image bytes", &gotURL))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.StageNodeImage(ctx, connect.NewRequest(&fleetv1.StageNodeImageRequest{
		NodeName:  "A",
		ImageUrl:  "https://example.org/images/cryptos.img",
		Signature: []byte{1, 2, 3},
		Sha256:    "abc123",
	}))
	if err != nil {
		t.Fatalf("StageNodeImage(admin) error = %v, want nil", err)
	}
	if gotURL != "https://example.org/images/cryptos.img" {
		t.Errorf("fetched URL = %q, want the request's image_url", gotURL)
	}
	if string(conn.gotStageBytes) != "the image bytes" {
		t.Errorf("node received %q, want the fetched body", conn.gotStageBytes)
	}
	if conn.gotStageSize != uint64(len("the image bytes")) {
		t.Errorf("node StageImage size = %d, want %d", conn.gotStageSize, len("the image bytes"))
	}
	if string(conn.gotStageSignature) != "\x01\x02\x03" || conn.gotStageSha256 != "abc123" {
		t.Errorf("node StageImage signature/sha256 = %v/%q, want the request's", conn.gotStageSignature, conn.gotStageSha256)
	}
	if !resp.Msg.GetRequiresReboot() || resp.Msg.GetStatus().GetActiveSha256() != "deadbeef" {
		t.Errorf("response = %+v, want the node's reply flattened through", resp.Msg)
	}

	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "node-image-staged" {
		t.Fatalf("audit = %+v, want one node-image-staged event", audit)
	}
	if !strings.Contains(audit[0].Summary, "A") {
		t.Errorf("audit summary %q does not name the node", audit[0].Summary)
	}
}

func TestStageNodeImage_ViewerDenied_NoFetchNoDialNoAudit(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))
	fetchCalled := false
	svc = svc.WithImageFetch(func(context.Context, string) (io.ReadCloser, int64, error) {
		fetchCalled = true
		return io.NopCloser(strings.NewReader("")), 0, nil
	})

	ctx := operatorCtx("operator@acme.example", authz.LevelOperator)
	_, err := svc.StageNodeImage(ctx, connect.NewRequest(&fleetv1.StageNodeImageRequest{
		NodeName: "A", ImageUrl: "https://example.org/img", Signature: []byte{1},
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if fetchCalled || conn.closed {
		t.Error("image was fetched or node was dialed on a denied request")
	}
	if len(st.Audit()) != 0 {
		t.Error("denied request wrote an audit event")
	}
}

func TestStageNodeImage_MissingImageURL_InvalidArgument(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}})).WithImageFetch(fakeImageFetch("x", nil))
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.StageNodeImage(ctx, connect.NewRequest(&fleetv1.StageNodeImageRequest{
		NodeName: "A", Signature: []byte{1},
	}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestStageNodeImage_MissingSignature_InvalidArgument(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}})).WithImageFetch(fakeImageFetch("x", nil))
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.StageNodeImage(ctx, connect.NewRequest(&fleetv1.StageNodeImageRequest{
		NodeName: "A", ImageUrl: "https://example.org/img",
	}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestStageNodeImage_NoFetchSeam_Unimplemented(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}}))
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.StageNodeImage(ctx, connect.NewRequest(&fleetv1.StageNodeImageRequest{
		NodeName: "A", ImageUrl: "https://example.org/img", Signature: []byte{1},
	}))
	requireConnectCode(t, err, connect.CodeUnimplemented)
}

func TestStageNodeImage_NodeRefusesConcurrentUpgrade_FailedPrecondition_NoAudit(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{stageImageErr: status.Error(codes.FailedPrecondition, "cryptos: an image transfer is already in progress")}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn})).WithImageFetch(fakeImageFetch("x", nil))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.StageNodeImage(ctx, connect.NewRequest(&fleetv1.StageNodeImageRequest{
		NodeName: "A", ImageUrl: "https://example.org/img", Signature: []byte{1},
	}))
	requireConnectCode(t, err, connect.CodeFailedPrecondition)
	requireAppCode(t, err, apperr.CodeNodeRefused)
	requireNodeReason(t, err, "cryptos: an image transfer is already in progress")
	if len(st.Audit()) != 0 {
		t.Error("a node refusal wrote an audit event")
	}
}

func TestStageNodeImage_NodeRefusesBadSignature_NoAudit(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{stageImageErr: status.Error(codes.InvalidArgument, "cryptos: image signature did not verify")}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn})).WithImageFetch(fakeImageFetch("x", nil))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.StageNodeImage(ctx, connect.NewRequest(&fleetv1.StageNodeImageRequest{
		NodeName: "A", ImageUrl: "https://example.org/img", Signature: []byte{1},
	}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
	requireNodeReason(t, err, "cryptos: image signature did not verify")
	if len(st.Audit()) != 0 {
		t.Error("a node refusal wrote an audit event")
	}
}

func TestActivateNodeImage_Admin_ActivatesAndAudits(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{activateImageResp: &nodev1.ActivateImageResponse{Rebooting: true}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.ActivateNodeImage(ctx, connect.NewRequest(&fleetv1.ActivateNodeImageRequest{
		NodeName: "A", ConfirmCaCn: "Root CA A",
	}))
	if err != nil {
		t.Fatalf("ActivateNodeImage(admin) error = %v", err)
	}
	if conn.gotActivateCN != "Root CA A" {
		t.Errorf("node ActivateImage CN = %q, want Root CA A", conn.gotActivateCN)
	}
	if !resp.Msg.GetRebooting() {
		t.Error("response Rebooting = false, want true")
	}
	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "node-image-activated" {
		t.Fatalf("audit = %+v, want one node-image-activated event", audit)
	}
}

func TestActivateNodeImage_MissingConfirmCN_InvalidArgument(t *testing.T) {
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": {}}))
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ActivateNodeImage(ctx, connect.NewRequest(&fleetv1.ActivateNodeImageRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodeInvalidArgument)
}

func TestActivateNodeImage_OperatorDenied_NoAudit(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))
	ctx := operatorCtx("operator@acme.example", authz.LevelOperator)
	_, err := svc.ActivateNodeImage(ctx, connect.NewRequest(&fleetv1.ActivateNodeImageRequest{
		NodeName: "A", ConfirmCaCn: "Root CA A",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if conn.gotActivateCN != "" || conn.closed {
		t.Error("node was dialed/activated on a denied request")
	}
	if len(st.Audit()) != 0 {
		t.Error("denied request wrote an audit event")
	}
}

func TestActivateNodeImage_CNMismatch_MappedToNodeRefused(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{activateImageErr: status.Error(codes.PermissionDenied, "cryptos: confirmation CN does not match the CA CN")}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.ActivateNodeImage(ctx, connect.NewRequest(&fleetv1.ActivateNodeImageRequest{
		NodeName: "A", ConfirmCaCn: "wrong",
	}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	requireAppCode(t, err, apperr.CodeNodeRefused)
	if len(st.Audit()) != 0 {
		t.Error("a CN mismatch wrote an audit event")
	}
}

func TestRollbackNodeImage_Admin_RollsBackAndAudits(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{rollbackImageResp: &nodev1.RollbackImageResponse{
		Status:         &nodev1.ImageStatus{ActiveSha256: "old"},
		RequiresReboot: true,
	}}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))

	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	resp, err := svc.RollbackNodeImage(ctx, connect.NewRequest(&fleetv1.RollbackNodeImageRequest{NodeName: "A"}))
	if err != nil {
		t.Fatalf("RollbackNodeImage(admin) error = %v", err)
	}
	if resp.Msg.GetStatus().GetActiveSha256() != "old" || !resp.Msg.GetRequiresReboot() {
		t.Errorf("response = %+v, want the node's reply flattened through", resp.Msg)
	}
	audit := st.Audit()
	if len(audit) != 1 || audit[0].Kind != "node-image-rolled-back" {
		t.Fatalf("audit = %+v, want one node-image-rolled-back event", audit)
	}
}

func TestRollbackNodeImage_ViewerDenied_NoAudit(t *testing.T) {
	st := certsTestStore()
	conn := &fakeConn{}
	svc := New(st, dialFor(map[string]*fakeConn{"A": conn}))
	ctx := operatorCtx("viewer@acme.example", authz.LevelViewer)
	_, err := svc.RollbackNodeImage(ctx, connect.NewRequest(&fleetv1.RollbackNodeImageRequest{NodeName: "A"}))
	requireConnectCode(t, err, connect.CodePermissionDenied)
	if conn.closed {
		t.Error("node was dialed on a denied request")
	}
	if len(st.Audit()) != 0 {
		t.Error("denied request wrote an audit event")
	}
}

func TestRollbackNodeImage_UnknownNode_NotFound_NoAudit(t *testing.T) {
	st := certsTestStore()
	svc := New(st, dialFor(map[string]*fakeConn{}))
	ctx := operatorCtx("admin@acme.example", authz.LevelAdmin)
	_, err := svc.RollbackNodeImage(ctx, connect.NewRequest(&fleetv1.RollbackNodeImageRequest{NodeName: "missing"}))
	requireConnectCode(t, err, connect.CodeNotFound)
	if len(st.Audit()) != 0 {
		t.Error("unknown node wrote an audit event")
	}
}
