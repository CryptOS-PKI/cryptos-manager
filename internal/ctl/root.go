// Package ctl is cryptos-managerctl: an operator CLI over the manager's
// fleet API, authenticated with an operator certificate.
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
	"time"

	golog "github.com/Bugs5382/go-log"
	"github.com/spf13/cobra"
)

// Environment variables that stand in for the connection flags.
const (
	EnvServer = "CRYPTOS_MANAGER_SERVER"
	EnvCert   = "CRYPTOS_MANAGER_CERT"
	EnvKey    = "CRYPTOS_MANAGER_KEY"
	EnvCA     = "CRYPTOS_MANAGER_CA"
)

// defaultTimeout bounds one command. Issuing and revoking wait on a node.
const defaultTimeout = 60 * time.Second

// Build identity, stamped at link time with -X. The defaults are what an
// unstamped local build honestly is.
var (
	Version = "dev"
	Commit  = "unknown"
)

// Streams is where a command reads and writes.
type Streams struct {
	Out io.Writer
	Err io.Writer
}

// options are the root flags every command shares.
type options struct {
	streams Streams
	log     golog.Logger

	server  string
	cert    string
	key     string
	ca      string
	output  string
	timeout time.Duration
}

// flagOrEnv defaults a flag to its environment variable, so scripts can set
// the connection once.
func flagOrEnv(cmd *cobra.Command, target *string, name, env, usage string) {
	cmd.PersistentFlags().StringVar(target, name, os.Getenv(env), usage+" (or "+env+")")
}

// NewRootCommand builds the command tree.
func NewRootCommand(s Streams) *cobra.Command {
	o := &options{
		streams: s,
		// Stderr, so a raised LOG_LEVEL can't get into JSON a script is reading.
		log: golog.NewLoggerWithOptions("cryptos-managerctl",
			golog.WithOutput(s.Err), golog.WithDefaultLevel(golog.LevelError), golog.WithDefaultFormat(golog.FormatConsole)),
	}
	root := &cobra.Command{
		Use:           "cryptos-managerctl",
		Short:         "Operate a FleetOS Manager from the command line",
		Long:          "cryptos-managerctl talks to a FleetOS Manager's API with an operator certificate, the same one that signs you in to the web console.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(s.Out)
	root.SetErr(s.Err)

	flagOrEnv(root, &o.server, "server", EnvServer, "the manager's https URL")
	flagOrEnv(root, &o.cert, "cert", EnvCert, "operator certificate file (PEM)")
	flagOrEnv(root, &o.key, "key", EnvKey, "operator private key file (PEM)")
	flagOrEnv(root, &o.ca, "ca", EnvCA, "CA bundle to verify the manager against (PEM); empty uses the system roots")
	root.PersistentFlags().StringVarP(&o.output, "output", "o", formatTable, "output format: table, json or yaml")
	root.PersistentFlags().DurationVar(&o.timeout, "timeout", defaultTimeout, "how long a command may take")

	root.AddCommand(
		o.whoamiCommand(),
		o.nodesCommand(),
		o.certsCommand(),
		o.profilesCommand(),
		o.enrollmentsCommand(),
		o.approvalsCommand(),
		versionCommand(s),
	)
	return root
}

func versionCommand(s Streams) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the CLI's version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, err := fmt.Fprintf(s.Out, "cryptos-managerctl %s (%s)\n", Version, Commit)
			return err
		},
	}
}

// call runs one API call with the command's deadline and logs how it went.
func (o *options) call(cmd *cobra.Command, name string, fn func(context.Context, *client) error) error {
	if err := checkFormat(o.output); err != nil {
		return err
	}
	c, err := o.dial()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
	defer cancel()

	start := time.Now()
	o.log.Debug("api call", golog.F("call", name), golog.F("server", o.server))
	err = fn(ctx, c)
	if err != nil {
		o.log.Debug("api call failed", golog.F("call", name), golog.F("took", time.Since(start)), golog.F("err", err.Error()))
		return fmt.Errorf("%s: %w", name, err)
	}
	o.log.Debug("api call done", golog.F("call", name), golog.F("took", time.Since(start)))
	return nil
}
