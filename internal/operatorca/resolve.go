package operatorca

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
	"fmt"
	"os"

	"github.com/CryptOS-PKI/cryptos-manager/internal/config"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// Kind is where the operator CA trust anchors come from.
type Kind string

// Operator CA sources. The source is chosen only by what is configured, so
// there is no mode switch to get wrong.
const (
	// KindFile is operatorCAPath: the PEM file is the whole trust, and
	// registered rows are ignored.
	KindFile Kind = "file"
	// KindRegistered is the active and retiring rows in Postgres.
	KindRegistered Kind = "registered"
	// KindNone trusts nothing: no operatorCAPath, and no Postgres or first
	// run disabled. Every caller is refused.
	KindNone Kind = "none"
	// KindDev is authBypass: no certificates at all.
	KindDev Kind = "dev"
)

// Source is the resolved operator CA source. For KindFile it carries the
// anchors and the CRL targets from the config; a registered source loads
// its anchors from the store on every trust generation.
type Source struct {
	Kind       Kind
	Path       string
	File       []Anchor
	CRLTargets []CRLTarget
	Policy     string
}

// Resolve applies the source precedence every consumer shares: authBypass is
// dev; operatorCAPath wins over anything in the database; otherwise the
// registered rows, when Postgres is configured and first run isn't disabled;
// otherwise nothing is trusted. A config-file anchor that is a CryptOS node's
// CA (nodeCAs, by certificate or key) is refused, and so is a hard
// revocation policy over a registered CA whose CRL source is upload.
func Resolve(ctx context.Context, cfg config.Config, st store.OperatorTrust, nodeCAs []*x509.Certificate, logf func(string, ...any)) (Source, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	policy := cfg.OperatorRevocationPolicy
	if policy == "" {
		policy = PolicySoft
	}
	switch {
	case cfg.AuthBypass:
		return Source{Kind: KindDev, Policy: policy}, nil
	case cfg.OperatorCAPath != "":
		return resolveFile(ctx, cfg, st, nodeCAs, policy, logf)
	case cfg.DatabaseURL == "" || cfg.FirstRun == config.FirstRunDisabled:
		return Source{Kind: KindNone, Policy: policy}, nil
	}

	if policy == PolicyHard {
		rows, err := st.OperatorCAs(ctx)
		if err != nil {
			return Source{}, fmt.Errorf("operatorca: read operator CAs: %w", err)
		}
		for _, row := range rows {
			if row.State != store.OperatorCARetired && row.CRLSource == store.CRLSourceUpload {
				return Source{}, fmt.Errorf("operatorca: operatorRevocationPolicy hard can't be used while operator CA %s takes its CRL by upload: "+
					"an expired CRL would lock out the admins who upload the next one; use soft, or switch that CA to a CRL URL", row.SHA256)
			}
		}
	}
	return Source{Kind: KindRegistered, Policy: policy}, nil
}

func resolveFile(ctx context.Context, cfg config.Config, st store.OperatorTrust, nodeCAs []*x509.Certificate, policy string, logf func(string, ...any)) (Source, error) {
	b, err := os.ReadFile(cfg.OperatorCAPath)
	if err != nil {
		return Source{}, fmt.Errorf("operatorca: read operator CA: %w", err)
	}
	var certs []*x509.Certificate
	for rest := b; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return Source{}, fmt.Errorf("operatorca: parse operator CA in %s: %w", cfg.OperatorCAPath, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return Source{}, fmt.Errorf("operatorca: operator CA %s contains no PEM certificates", cfg.OperatorCAPath)
	}
	if err := CheckNotNodeCA(certs, nodeCAs); err != nil {
		return Source{}, err
	}

	var targets []CRLTarget
	crlSource := store.CRLSourceNone
	for _, e := range cfg.OperatorCRL {
		t := CRLTarget{Source: store.CRLSourceURL, Location: e.URL}
		if e.Path != "" {
			t = CRLTarget{Source: store.CRLSourcePath, Location: e.Path}
		}
		if crlSource == store.CRLSourceNone {
			crlSource = t.Source
		}
		targets = append(targets, t)
	}
	anchors := make([]Anchor, 0, len(certs))
	for _, c := range certs {
		anchors = append(anchors, Anchor{
			Cert: c, SHA256: Fingerprint(c), State: store.OperatorCAActive, FromConfig: true,
			CRLSource: crlSource, OCSPMode: cfg.OperatorOCSP.Mode, OCSPURL: cfg.OperatorOCSP.URL,
		})
	}

	rows, err := st.OperatorCAs(ctx)
	if err != nil {
		return Source{}, fmt.Errorf("operatorca: read operator CAs: %w", err)
	}
	logf("operatorca: operator CA from config file %s; %d registered operator CA(s) in the database are ignored while operatorCAPath is set",
		cfg.OperatorCAPath, len(rows))
	return Source{Kind: KindFile, Path: cfg.OperatorCAPath, File: anchors, CRLTargets: targets, Policy: policy}, nil
}
