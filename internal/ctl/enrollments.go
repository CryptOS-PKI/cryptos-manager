package ctl

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
	"io"
	"os"

	"connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/spf13/cobra"
)

func enrollmentRow(w io.Writer, e *fleetv1.EnrollmentRequest) error {
	return rows(w, []string{"ID", "STATUS"}, [][]string{{e.GetId(), e.GetStatus()}})
}

// readOptional loads a file a flag names, or nothing when it names none.
func readOptional(path, what string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the %s: %w", what, err)
	}
	return string(b), nil
}

func (o *options) enrollmentsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "enrollments", Short: "Review nodes asking to join the fleet"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List enrollment requests",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.call(cmd, "ListEnrollments", func(ctx context.Context, c *client) error {
				resp, err := c.fleet.ListEnrollments(ctx, connect.NewRequest(&fleetv1.ListEnrollmentsRequest{}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error {
					body := make([][]string, 0, len(resp.Msg.GetItems()))
					for _, e := range resp.Msg.GetItems() {
						body = append(body, []string{e.GetId(), e.GetProposedName(), e.GetKind(), e.GetRole(), e.GetStatus(), e.GetAddress(), e.GetRequestedAt()})
					}
					return rows(w, []string{"ID", "NAME", "KIND", "ROLE", "STATUS", "ADDRESS", "REQUESTED"}, body)
				})
			})
		},
	}, o.enrollmentsApproveCommand(), o.enrollmentsRejectCommand())
	return cmd
}

func (o *options) enrollmentsApproveCommand() *cobra.Command {
	var endpoint, adminCert, adminKey, nodeCA string
	cmd := &cobra.Command{
		Use:   "approve ID",
		Short: "Approve an enrollment request",
		Long:  "Approve an enrollment request. A LINK request also takes the node's endpoint and the admin credential the manager will use on it; a SUBORDINATE request takes neither.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			certPEM, err := readOptional(adminCert, "admin certificate")
			if err != nil {
				return err
			}
			keyPEM, err := readOptional(adminKey, "admin key")
			if err != nil {
				return err
			}
			caPEM, err := readOptional(nodeCA, "node CA")
			if err != nil {
				return err
			}
			return o.call(cmd, "ApproveEnrollment", func(ctx context.Context, c *client) error {
				resp, err := c.fleet.ApproveEnrollment(ctx, connect.NewRequest(&fleetv1.ApproveEnrollmentRequest{
					Id: args[0], NodeEndpoint: endpoint, AdminCertPem: certPEM, AdminKeyPem: keyPEM, CaPem: caPEM,
				}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error { return enrollmentRow(w, resp.Msg.GetEnrollment()) })
			})
		},
	}
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "the node's API endpoint (LINK)")
	cmd.Flags().StringVar(&adminCert, "admin-cert", "", "the node admin certificate file (LINK)")
	cmd.Flags().StringVar(&adminKey, "admin-key", "", "the node admin key file (LINK)")
	cmd.Flags().StringVar(&nodeCA, "node-ca", "", "the node's CA file (LINK)")
	return cmd
}

func (o *options) enrollmentsRejectCommand() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "reject ID",
		Short: "Reject an enrollment request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.call(cmd, "RejectEnrollment", func(ctx context.Context, c *client) error {
				resp, err := c.fleet.RejectEnrollment(ctx, connect.NewRequest(&fleetv1.RejectEnrollmentRequest{Id: args[0], Reason: reason}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error { return enrollmentRow(w, resp.Msg.GetEnrollment()) })
			})
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "why, for the record")
	return cmd
}

func (o *options) approvalsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "approvals", Short: "Decide requests waiting for an approver"}
	var status string
	list := &cobra.Command{
		Use:   "list",
		Short: "List approvals",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.call(cmd, "ListApprovals", func(ctx context.Context, c *client) error {
				resp, err := c.fleet.ListApprovals(ctx, connect.NewRequest(&fleetv1.ListApprovalsRequest{Status: status}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error {
					body := make([][]string, 0, len(resp.Msg.GetItems()))
					for _, a := range resp.Msg.GetItems() {
						body = append(body, []string{a.GetId(), a.GetStatus(), a.GetTool(), a.GetRequestedByCn(), a.GetExpiresAt(), a.GetSummary()})
					}
					return rows(w, []string{"ID", "STATUS", "TOOL", "REQUESTED BY", "EXPIRES", "SUMMARY"}, body)
				})
			})
		},
	}
	list.Flags().StringVar(&status, "status", "", "only this status, such as pending")
	cmd.AddCommand(list, o.decideCommand("approve", "Approve a request", true), o.decideCommand("deny", "Deny a request", false))
	return cmd
}

func (o *options) decideCommand(use, short string, approve bool) *cobra.Command {
	return &cobra.Command{
		Use:   use + " ID",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.call(cmd, "DecideApproval", func(ctx context.Context, c *client) error {
				resp, err := c.fleet.DecideApproval(ctx, connect.NewRequest(&fleetv1.DecideApprovalRequest{Id: args[0], Approve: approve}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error {
					a := resp.Msg.GetApproval()
					return rows(w, []string{"ID", "STATUS"}, [][]string{{a.GetId(), a.GetStatus()}})
				})
			})
		},
	}
}
