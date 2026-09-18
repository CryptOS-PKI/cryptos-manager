package main

/*
Apache License 2.0

Copyright 2026 Shane

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// selfSignedValidity is the lifetime of a generated bootstrap certificate. It
// is regenerated on every start, so this only has to outlast the window between
// first boot and an operator installing real material.
const selfSignedValidity = 90 * 24 * time.Hour

// generateServerCert mints an ephemeral self-signed server certificate so the
// site can be served before any certificate material exists (#78).
//
// This is the same move the CryptOS nodes make in internal/init: a listener has
// to exist before there is a CA identity to sign its certificate, and an
// operator cannot be told what to install if they cannot load the page. The
// certificate is deliberately throwaway -- a browser will warn on it, and that
// warning is the correct signal that real material is still missing.
func generateServerCert(hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate bootstrap key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate bootstrap serial: %w", err)
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		NotAfter:              now.Add(selfSignedValidity),
		NotBefore:             now.Add(-time.Minute),
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName:   hosts[0],
			Organization: []string{"CryptOS Fleet Manager (bootstrap)"},
		},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)

			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create bootstrap certificate: %w", err)
	}
	// Parse it back so Leaf carries Raw, which callers need to fingerprint it.
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse bootstrap certificate: %w", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, Leaf: leaf, PrivateKey: key}, nil
}

// bootstrapCertHosts returns the names a bootstrap certificate should cover:
// the names an operator plausibly types at bring-up. The listen address is
// included when it names a concrete interface, since that is often the only
// way in on a headless host; a wildcard bind says nothing about reachability
// and is skipped.
func bootstrapCertHosts(listen string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}

	if name, err := os.Hostname(); err == nil && name != "" {
		hosts = append(hosts, name)
	}
	if host, _, err := net.SplitHostPort(listen); err == nil && host != "" {
		switch host {
		case "0.0.0.0", "::", "[::]":
		default:
			hosts = append(hosts, host)
		}
	}

	return dedupe(hosts)
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	return out
}
