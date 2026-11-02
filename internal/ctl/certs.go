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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/spf13/cobra"
)

// readCSR loads a PKCS#10 request, PEM or DER, and checks its signature, so a
// wrong file is caught here and not on the issuing node.
func readCSR(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the CSR: %w", err)
	}
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		der = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("%s isn't a CSR: %w", path, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%s has a bad signature: %w", path, err)
	}
	return der, nil
}

func (o *options) certsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "certs", Short: "List, issue and revoke certificates"}
	cmd.AddCommand(o.certsListCommand(), o.certsGetCommand(), o.certsIssueCommand(), o.certsRevokeCommand())
	return cmd
}

func (o *options) certsListCommand() *cobra.Command {
	var node string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List issued certificates, across the fleet or for one node",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.call(cmd, "ListCertificates", func(ctx context.Context, c *client) error {
				name, id := nodeRef(node)
				resp, err := c.fleet.ListCertificates(ctx, connect.NewRequest(&fleetv1.ListCertificatesRequest{Node: name, NodeId: id}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error {
					body := make([][]string, 0, len(resp.Msg.GetCertificates()))
					for _, x := range resp.Msg.GetCertificates() {
						body = append(body, []string{x.GetSerial(), x.GetSubjectCn(), x.GetIssuerNode(), x.GetStatus(), x.GetProfile(), x.GetNotAfter()})
					}
					return rows(w, []string{"SERIAL", "SUBJECT", "NODE", "STATUS", "PROFILE", "NOT AFTER"}, body)
				})
			})
		},
	}
	cmd.Flags().StringVar(&node, "node", "", "only this node, by name or ID")
	return cmd
}

func (o *options) certsGetCommand() *cobra.Command {
	var node, serial string
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Fetch an issued certificate and its chain as PEM",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.call(cmd, "GetCertificate", func(ctx context.Context, c *client) error {
				resp, err := c.fleet.GetCertificate(ctx, connect.NewRequest(&fleetv1.GetCertificateRequest{NodeName: node, SerialHex: serial}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error {
					_, err := fmt.Fprint(w, resp.Msg.GetCertificatePem(), resp.Msg.GetChainPem())
					return err
				})
			})
		},
	}
	cmd.Flags().StringVar(&node, "node", "", "the node that issued it, by name")
	cmd.Flags().StringVar(&serial, "serial", "", "its serial, in hex")
	mustRequire(cmd, "node", "serial")
	return cmd
}

func (o *options) certsIssueCommand() *cobra.Command {
	var node, profile, csrPath string
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a certificate from a CSR",
		Long:  "Issue a certificate from a CSR you made yourself, so the private key never leaves your machine. The certificate is printed as PEM.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			der, err := readCSR(csrPath)
			if err != nil {
				return err
			}
			return o.call(cmd, "IssueLeaf", func(ctx context.Context, c *client) error {
				name, id := nodeRef(node)
				resp, err := c.fleet.IssueLeaf(ctx, connect.NewRequest(&fleetv1.IssueLeafRequest{
					NodeName: name, NodeId: id, ProfileName: profile, CsrDer: der,
				}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error {
					return pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: resp.Msg.GetCertDer()})
				})
			})
		},
	}
	cmd.Flags().StringVar(&node, "node", "", "the issuing node, by name or ID")
	cmd.Flags().StringVar(&profile, "profile", "", "the certificate profile")
	cmd.Flags().StringVar(&csrPath, "csr", "", "the CSR file, PEM or DER")
	mustRequire(cmd, "node", "profile", "csr")
	return cmd
}

func (o *options) certsRevokeCommand() *cobra.Command {
	var (
		node, serial string
		reason       int32
		yes          bool
	)
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an issued certificate",
		Long:  "Revoke a certificate on the node that issued it. Revocation can't be undone, so the command needs --yes. --reason is an RFC 5280 reason code.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !yes {
				return errors.New("revocation can't be undone: add --yes to go ahead")
			}
			return o.call(cmd, "RevokeCertificate", func(ctx context.Context, c *client) error {
				name, id := nodeRef(node)
				resp, err := c.fleet.RevokeCertificate(ctx, connect.NewRequest(&fleetv1.RevokeCertificateRequest{
					NodeName: name, NodeId: id, SerialHex: serial, ReasonCode: reason,
				}))
				if err != nil {
					return err
				}
				return o.render(resp.Msg, func(w io.Writer) error {
					return rows(w, []string{"SERIAL", "REVOKED AT", "REASON"}, [][]string{{resp.Msg.GetSerialHex(), resp.Msg.GetRevokedAt(), fmt.Sprint(resp.Msg.GetReasonCode())}})
				})
			})
		},
	}
	cmd.Flags().StringVar(&node, "node", "", "the node that issued it, by name or ID")
	cmd.Flags().StringVar(&serial, "serial", "", "its serial, in hex")
	cmd.Flags().Int32Var(&reason, "reason", 0, "RFC 5280 reason code")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the revocation")
	mustRequire(cmd, "node", "serial")
	return cmd
}

// mustRequire marks flags required. It only fails on a flag name that doesn't
// exist, which is a mistake in this package.
func mustRequire(cmd *cobra.Command, names ...string) {
	for _, n := range names {
		if err := cmd.MarkFlagRequired(n); err != nil {
			panic(err)
		}
	}
}
