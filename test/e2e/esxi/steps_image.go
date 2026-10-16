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
	"strings"
	"time"

	connect "connectrpc.com/connect"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
)

// imageStep always proves GetNodeImageStatus. Staging, activating and rolling
// back a real image needs an image signed by the key the node's running image
// trusts, reachable over http(s), and the detached signature over it
// (StageNodeImageRequest), so those write paths only run when E2E_IMAGE_URL
// and E2E_IMAGE_SIGNATURE_PATH are set; otherwise this step says so and stops
// there rather than failing.
//
// With an image it runs the whole lifecycle and leaves the node where it
// found it: stage the image, activate it and wait until the node is back up
// running it, roll back, then activate again and wait until the node is back
// on the image it started on. Every wait reads the node's own image status
// through the manager, so a node that answered before its reboot finished is
// not mistaken for one running the new image.
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
		original := status.Msg.GetStatus().GetRunningSha256()

		if cfg.ImageURL == "" || cfg.ImageSigPath == "" {
			return "", skip("no E2E_IMAGE_URL/E2E_IMAGE_SIGNATURE_PATH configured; GetNodeImageStatus alone was proved (running " + original + ")")
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
		next := staged.Msg.GetStatus().GetActiveSha256()
		if next == "" || next == original || !staged.Msg.GetStatus().GetRebootPending() {
			return "", fmt.Errorf("after StageNodeImage %s's active image is %q with reboot pending %t; want a different image waiting for a reboot (running %s)",
				primary.Name, next, staged.Msg.GetStatus().GetRebootPending(), original)
		}
		if cfg.ImageSHA256 != "" && !strings.EqualFold(next, cfg.ImageSHA256) {
			return "", fmt.Errorf("after StageNodeImage %s's active image is %s, want E2E_IMAGE_SHA256 %s", primary.Name, next, cfg.ImageSHA256)
		}

		if err := s.activateAndWait(ctx, id, name, confirmCN, next); err != nil {
			return "", fmt.Errorf("activating the staged image: %w", err)
		}

		rolled, err := s.fleet.RollbackNodeImage(ctx, connect.NewRequest(&fleetv1.RollbackNodeImageRequest{NodeId: id, NodeName: name}))
		if err != nil {
			return "", fmt.Errorf("RollbackNodeImage: %w", err)
		}
		if got := rolled.Msg.GetStatus().GetActiveSha256(); got != original || !rolled.Msg.GetStatus().GetRebootPending() {
			return "", fmt.Errorf("after RollbackNodeImage %s's active image is %q with reboot pending %t; want %s waiting for a reboot",
				primary.Name, got, rolled.Msg.GetStatus().GetRebootPending(), original)
		}
		if err := s.activateAndWait(ctx, id, name, confirmCN, original); err != nil {
			return "", fmt.Errorf("activating the rolled-back image: %w", err)
		}
		return fmt.Sprintf("staged %s on %s, booted it, rolled back and booted %s again", next, primary.Name, original), nil
	}}
}

// imageWaitPoll is how often activateAndWait reads the node's image status
// while it reboots.
const imageWaitPoll = 3 * time.Second

// activateAndWait activates the image the node has waiting, then waits until
// the node reports it is running want with nothing left pending. Errors while
// the node is down are expected and retried until ctx ends.
func (s *scenario) activateAndWait(ctx context.Context, id, name, confirmCN, want string) error {
	if _, err := s.fleet.ActivateNodeImage(ctx, connect.NewRequest(&fleetv1.ActivateNodeImageRequest{
		NodeId: id, NodeName: name, ConfirmCaCn: confirmCN,
	})); err != nil {
		return fmt.Errorf("ActivateNodeImage: %w", err)
	}
	last := "no answer yet"
	for {
		resp, err := s.fleet.GetNodeImageStatus(ctx, connect.NewRequest(&fleetv1.GetNodeImageStatusRequest{NodeId: id, NodeName: name}))
		if err == nil {
			st := resp.Msg.GetStatus()
			if st.GetRunningSha256() == want && !st.GetRebootPending() {
				return nil
			}
			last = fmt.Sprintf("running %s, reboot pending %t", st.GetRunningSha256(), st.GetRebootPending())
		} else {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the node was not back running %s before the step timed out (last: %s)", want, last)
		case <-time.After(imageWaitPoll):
		}
	}
}
