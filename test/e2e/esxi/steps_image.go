package main

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
	"fmt"
	"os"

	connect "connectrpc.com/connect"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
)

// imageStep always proves GetNodeImageStatus. Staging, activating and rolling
// back a real image needs a signed CryptOS release image reachable over
// http(s) and the detached release signature over it (StageNodeImageRequest):
// that is release-pipeline material this lab-gate run does not hand this
// script, so those three write paths only run when E2E_IMAGE_URL and
// E2E_IMAGE_SIGNATURE_PATH are set; otherwise this step says so and stops
// there rather than failing.
func (s *scenario) imageStep(cfg config) step {
	return step{name: "image/status-stage-activate-rollback", run: func(ctx context.Context) (string, error) {
		primary, err := s.primary()
		if err != nil {
			return "", err
		}
		id, name := s.nodeRef(primary)

		status, err := s.fleet.GetNodeImageStatus(ctx, connect.NewRequest(&fleetv1.GetNodeImageStatusRequest{NodeId: id, NodeName: name}))
		if err != nil {
			return "", fmt.Errorf("GetNodeImageStatus: %w", err)
		}
		running := status.Msg.GetStatus().GetRunningSha256()

		if cfg.ImageURL == "" || cfg.ImageSigPath == "" {
			return "", skip("no E2E_IMAGE_URL/E2E_IMAGE_SIGNATURE_PATH configured; GetNodeImageStatus alone was proved (running " + running + ")")
		}
		sig, err := os.ReadFile(cfg.ImageSigPath)
		if err != nil {
			return "", fmt.Errorf("reading E2E_IMAGE_SIGNATURE_PATH: %w", err)
		}

		node, err := s.fleet.GetNode(ctx, connect.NewRequest(&fleetv1.GetNodeRequest{NodeId: id, Name: name}))
		if err != nil {
			return "", fmt.Errorf("GetNode: %w", err)
		}
		confirmCN := node.Msg.GetNode().GetSummary().GetCn()

		staged, err := s.fleet.StageNodeImage(ctx, connect.NewRequest(&fleetv1.StageNodeImageRequest{
			NodeId: id, NodeName: name, ImageUrl: cfg.ImageURL, Signature: sig, Sha256: cfg.ImageSHA256,
		}))
		if err != nil {
			return "", fmt.Errorf("StageNodeImage: %w", err)
		}
		activeAfterStage := staged.Msg.GetStatus().GetActiveSha256()

		if _, err := s.fleet.ActivateNodeImage(ctx, connect.NewRequest(&fleetv1.ActivateNodeImageRequest{
			NodeId: id, NodeName: name, ConfirmCaCn: confirmCN,
		})); err != nil {
			return "", fmt.Errorf("ActivateNodeImage: %w", err)
		}

		rolled, err := s.fleet.RollbackNodeImage(ctx, connect.NewRequest(&fleetv1.RollbackNodeImageRequest{NodeId: id, NodeName: name}))
		if err != nil {
			return "", fmt.Errorf("RollbackNodeImage: %w", err)
		}
		return fmt.Sprintf("staged %s, activated it, then rolled %s back to %s", activeAfterStage, primary.Name, rolled.Msg.GetStatus().GetRunningSha256()), nil
	}}
}
