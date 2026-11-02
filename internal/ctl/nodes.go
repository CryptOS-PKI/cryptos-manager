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
	"strings"

	"connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/spf13/cobra"
)

func (o *options) whoamiCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the operator your certificate signs you in as",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.call(cmd, "WhoAmI", func(ctx context.Context, c *client) error {
				resp, err := c.fleet.WhoAmI(ctx, connect.NewRequest(&fleetv1.WhoAmIRequest{}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error {
					op := resp.Msg.GetOperator()
					return rows(w, []string{"CN", "SERIAL", "LEVEL"}, [][]string{{op.GetCn(), op.GetSerial(), op.GetLevel()}})
				})
			})
		},
	}
}

func healthName(h fleetv1.Health) string {
	return strings.TrimPrefix(h.String(), "HEALTH_")
}

func (o *options) nodesCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "nodes", Short: "List nodes and read their status"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the fleet's nodes and their health",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.call(cmd, "ListNodes", func(ctx context.Context, c *client) error {
				resp, err := c.fleet.ListNodes(ctx, connect.NewRequest(&fleetv1.ListNodesRequest{}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error {
					body := make([][]string, 0, len(resp.Msg.GetNodes()))
					for _, n := range resp.Msg.GetNodes() {
						body = append(body, []string{
							n.GetName(), n.GetId(), n.GetRole(), healthName(n.GetHealth()), n.GetAddress(),
							fmt.Sprint(n.GetRebootRequired()),
						})
					}
					return rows(w, []string{"NAME", "ID", "ROLE", "HEALTH", "ADDRESS", "REBOOT REQUIRED"}, body)
				})
			})
		},
	}, &cobra.Command{
		Use:   "get NODE",
		Short: "Show one node, by name or ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.call(cmd, "GetNode", func(ctx context.Context, c *client) error {
				name, id := nodeRef(args[0])
				resp, err := c.fleet.GetNode(ctx, connect.NewRequest(&fleetv1.GetNodeRequest{Name: name, NodeId: id}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, nil)
			})
		},
	})
	return cmd
}

func (o *options) profilesCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "profiles", Short: "Read the certificate profile catalog"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the certificate profiles you can issue under",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.call(cmd, "ListProfiles", func(ctx context.Context, c *client) error {
				resp, err := c.fleet.ListProfiles(ctx, connect.NewRequest(&fleetv1.ListProfilesRequest{}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error {
					body := make([][]string, 0, len(resp.Msg.GetItems()))
					for _, p := range resp.Msg.GetItems() {
						body = append(body, []string{p.GetName()})
					}
					return rows(w, []string{"NAME"}, body)
				})
			})
		},
	})
	return cmd
}
