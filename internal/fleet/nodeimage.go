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
	"fmt"
	"io"
	"net/http"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// MaxNodeImageBytes bounds a CryptOS image StageNodeImage will fetch and
// stream to a node: generous for a UKI, small enough that a misbehaving
// image_url can't exhaust the manager.
const MaxNodeImageBytes = 2 << 30 // 2 GiB

// ImageFetchTimeout bounds the whole image_url fetch StageNodeImage makes
// before it starts streaming to the node.
const ImageFetchTimeout = 30 * time.Minute

// WithImageFetch supplies the seam StageNodeImage uses to retrieve an image
// from a URL: the browser never carries the image itself. Returns s for
// chaining.
func (s *Service) WithImageFetch(fetch func(ctx context.Context, url string) (io.ReadCloser, int64, error)) *Service {
	s.imageFetch = fetch

	return s
}

// NewHTTPImageFetch builds the production image_url fetch seam: an http or
// https GET, no proxy from the environment, at most maxBytes, reporting the
// response's Content-Length as the size the node's StageImageBegin expects.
// A response with no Content-Length is refused, since the node needs the
// size up front to check the transfer will fit before it spends the upload.
func NewHTTPImageFetch(timeout time.Duration, maxBytes int64) func(ctx context.Context, url string) (io.ReadCloser, int64, error) {
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	return func(ctx context.Context, rawURL string) (io.ReadCloser, int64, error) {
		if err := operatorca.ValidateFetchURL(rawURL); err != nil {
			return nil, 0, fmt.Errorf("refused: %w", err)
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			cancel()
			return nil, 0, err
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			cancel()
			return nil, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if resp.ContentLength <= 0 {
			_ = resp.Body.Close()
			cancel()
			return nil, 0, errors.New("response did not report Content-Length")
		}
		if resp.ContentLength > maxBytes {
			_ = resp.Body.Close()
			cancel()
			return nil, 0, fmt.Errorf("response is %d bytes, more than the %d byte limit", resp.ContentLength, maxBytes)
		}
		return &cancelOnCloseReader{ReadCloser: resp.Body, cancel: cancel}, resp.ContentLength, nil
	}
}

// cancelOnCloseReader cancels its context's timeout once the body is closed,
// so a fetch that completes well inside ImageFetchTimeout doesn't hold the
// timer open for the rest of it.
type cancelOnCloseReader struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *cancelOnCloseReader) Close() error {
	defer r.cancel()
	return r.ReadCloser.Close()
}

// GetNodeImageStatus reports what CryptOS image a managed node is running,
// what it will boot next, and what it could roll back to. Any level may
// read it; a read, so it is not audited.
func (s *Service) GetNodeImageStatus(ctx context.Context, req *connect.Request[fleetv1.GetNodeImageStatusRequest]) (*connect.Response[fleetv1.GetNodeImageStatusResponse], error) {
	if _, err := operatorLevel(ctx); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("GetNodeImageStatus", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.GetImageStatus(ctx)
	if err != nil {
		return nil, nodeError("get image status", err)
	}

	return connect.NewResponse(&fleetv1.GetNodeImageStatusResponse{
		Status: nodeImageStatusFromProto(resp.GetStatus()),
	}), nil
}

// StageNodeImage fetches image_url itself (the browser never carries the
// image) and streams it to a managed node's spare ESP slot, the same way
// `cryptosctl image stage` does. Admin-gated (an unreviewed image on a trust
// anchor) and audited; the node's own refusals (a bad signature, or
// FailedPrecondition when another upgrade is already running) are surfaced
// unchanged.
func (s *Service) StageNodeImage(ctx context.Context, req *connect.Request[fleetv1.StageNodeImageRequest]) (*connect.Response[fleetv1.StageNodeImageResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("StageNodeImage", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	imageURL := req.Msg.GetImageUrl()
	if imageURL == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: image_url is required"))
	}
	if len(req.Msg.GetSignature()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: signature is required"))
	}
	if s.imageFetch == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("fleet: image staging not configured (no image fetch seam)"))
	}

	body, size, err := s.imageFetch(ctx, imageURL)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("fleet: fetch image_url: %w", err))
	}
	defer func() { _ = body.Close() }()

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.StageImage(ctx, req.Msg.GetSignature(), uint64(size), req.Msg.GetSha256(), body)
	if err != nil {
		return nil, nodeError("stage image", err)
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-image-staged",
		Summary:    fmt.Sprintf("Staged a new CryptOS image on %s", node.Name),
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})

	return connect.NewResponse(&fleetv1.StageNodeImageResponse{
		Status:         nodeImageStatusFromProto(resp.GetStatus()),
		RequiresReboot: resp.GetRequiresReboot(),
	}), nil
}

// ActivateNodeImage reboots a managed node so a staged image starts running.
// confirm_ca_cn must equal the node's current CA common name, the same
// confirmation RebootNode requires, because activating is itself a reboot.
// Admin-gated and audited.
func (s *Service) ActivateNodeImage(ctx context.Context, req *connect.Request[fleetv1.ActivateNodeImageRequest]) (*connect.Response[fleetv1.ActivateNodeImageResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("ActivateNodeImage", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	confirmCN := req.Msg.GetConfirmCaCn()
	if confirmCN == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: confirm_ca_cn is required"))
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.ActivateImage(ctx, confirmCN)
	if err != nil {
		return nil, nodeError("activate image", err)
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-image-activated",
		Summary:    fmt.Sprintf("Activated the staged CryptOS image on %s", node.Name),
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})

	return connect.NewResponse(&fleetv1.ActivateNodeImageResponse{
		Rebooting: resp.GetRebooting(),
	}), nil
}

// RollbackNodeImage puts a managed node's previously running image back on
// the boot path. ActivateNodeImage (or a reboot) is still needed to actually
// boot it. Admin-gated and audited.
func (s *Service) RollbackNodeImage(ctx context.Context, req *connect.Request[fleetv1.RollbackNodeImageRequest]) (*connect.Response[fleetv1.RollbackNodeImageResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	node, err := s.resolveNode("RollbackNodeImage", req.Msg.GetNodeId(), req.Msg.GetNodeName(), currentNames)
	if err != nil {
		return nil, err
	}

	conn, err := s.dial(node)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("fleet: dial node: %w", err))
	}
	defer func() { _ = conn.Close() }()

	resp, err := conn.RollbackImage(ctx)
	if err != nil {
		return nil, nodeError("rollback image", err)
	}

	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		At:         time.Now().UTC().Format(time.RFC3339),
		Kind:       "node-image-rolled-back",
		Summary:    fmt.Sprintf("Rolled back the CryptOS image on %s", node.Name),
		TargetKind: "node",
		TargetPath: nodeTarget(node),
	})

	return connect.NewResponse(&fleetv1.RollbackNodeImageResponse{
		Status:         nodeImageStatusFromProto(resp.GetStatus()),
		RequiresReboot: resp.GetRequiresReboot(),
	}), nil
}

// nodeImageStatusFromProto flattens a node's ImageStatus into the fleet
// API's display shape; the node's fields are already plain strings and
// booleans, so this is a 1:1 copy that keeps the two protos independent.
func nodeImageStatusFromProto(s *nodev1.ImageStatus) *fleetv1.NodeImageStatus {
	return &fleetv1.NodeImageStatus{
		RunningSha256:  s.GetRunningSha256(),
		ActiveSha256:   s.GetActiveSha256(),
		PreviousSha256: s.GetPreviousSha256(),
		RebootPending:  s.GetRebootPending(),
		RunningVersion: s.GetRunningVersion(),
	}
}
