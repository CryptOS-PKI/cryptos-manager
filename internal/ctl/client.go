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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// client is the fleet API on one connection.
type client struct {
	fleet fleetv1connect.FleetServiceClient
}

// dial builds the client. There is no way to turn server verification off:
// an operator certificate is admin access, so a self-signed manager gets
// --ca, the same fingerprint check a first run asks for.
func (o *options) dial() (*client, error) {
	if o.server == "" {
		return nil, fmt.Errorf("no manager: set --server or %s", EnvServer)
	}
	u, err := url.Parse(o.server)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("--server must be an https URL, such as https://fleetos.example.org")
	}
	if o.cert == "" || o.key == "" {
		return nil, fmt.Errorf("no operator certificate: set --cert and --key, or %s and %s", EnvCert, EnvKey)
	}
	pair, err := tls.LoadX509KeyPair(o.cert, o.key)
	if err != nil {
		return nil, fmt.Errorf("load the operator certificate: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	if o.ca != "" {
		pem, err := os.ReadFile(o.ca)
		if err != nil {
			return nil, fmt.Errorf("read the CA bundle: %w", err)
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("no certificates in the CA bundle")
		}
	}
	h := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}}
	return &client{fleet: fleetv1connect.NewFleetServiceClient(h, strings.TrimRight(o.server, "/"))}, nil
}

// nodeRef splits a node argument into the name and ID request fields: the API
// takes either, and a node's stable ID looks like nothing a name is.
func nodeRef(arg string) (name, id string) {
	if store.IsNodeID(arg) {
		return "", arg
	}
	return arg, ""
}
