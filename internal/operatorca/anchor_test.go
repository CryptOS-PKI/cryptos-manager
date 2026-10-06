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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
)

func wantReason(t *testing.T, err error, code int, reason fleetv1.ErrorReason) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %d/%s", code, apperr.ReasonName(reason))
	}
	if got, ok := apperr.Code(err); !ok || got != code {
		t.Fatalf("code = %d (ok %v), want %d; error %v", got, ok, code, err)
	}
	if got, ok := apperr.ReasonOf(err); !ok || got != reason {
		t.Fatalf("reason = %s (ok %v), want %s; error %v", apperr.ReasonName(got), ok, apperr.ReasonName(reason), err)
	}
}

func TestValidateAnchor_AcceptsAnOperatorCA(t *testing.T) {
	for name, kind := range map[string]keyKind{"P-384": keyP384, "P-256": keyP256, "RSA-3072": keyRSA3072} {
		t.Run(name, func(t *testing.T) {
			ca := newCA(t, caOpts{keyKind: kind})
			warnings, err := ValidateAnchor(ca.cert, AnchorOptions{Now: testNow, CRLSource: true})
			if err != nil || len(warnings) != 0 {
				t.Fatalf("ValidateAnchor = %v, %v; want accepted with no warnings", warnings, err)
			}
		})
	}
}

func TestValidateAnchor_Rejections(t *testing.T) {
	node := newCA(t, caOpts{cn: "Example Workload Intermediate"})
	cases := map[string]struct {
		cert   *x509.Certificate
		opts   AnchorOptions
		reason fleetv1.ErrorReason
	}{
		"not a CA": {
			cert:   newCA(t, caOpts{notCA: true, keyUsage: x509.KeyUsageDigitalSignature}).cert,
			reason: fleetv1.ErrorReason_ERROR_REASON_NOT_A_CA,
		},
		"no keyCertSign": {
			cert:   newCA(t, caOpts{keyUsage: x509.KeyUsageCRLSign}).cert,
			reason: fleetv1.ErrorReason_ERROR_REASON_NOT_A_CA,
		},
		"expiring within 30 days": {
			cert:   newCA(t, caOpts{notAfter: testNow.Add(29 * 24 * time.Hour)}).cert,
			reason: fleetv1.ErrorReason_ERROR_REASON_EXPIRING,
		},
		"RSA-2048": {
			cert:   newCA(t, caOpts{keyKind: keyRSA2048}).cert,
			reason: fleetv1.ErrorReason_ERROR_REASON_KEY_TYPE,
		},
		"a node's CA": {
			cert:   node.cert,
			opts:   AnchorOptions{NodeCAs: []*x509.Certificate{node.cert}},
			reason: fleetv1.ErrorReason_ERROR_REASON_IS_NODE_CA,
		},
		"a re-issued node CA with the same key": {
			cert:   newCA(t, caOpts{cn: "Example Workload Intermediate G2", key: node.key}).cert,
			opts:   AnchorOptions{NodeCAs: []*x509.Certificate{node.cert}},
			reason: fleetv1.ErrorReason_ERROR_REASON_IS_NODE_CA,
		},
		"no cRLSign with a CRL source": {
			cert:   newCA(t, caOpts{keyUsage: x509.KeyUsageCertSign}).cert,
			opts:   AnchorOptions{CRLSource: true},
			reason: fleetv1.ErrorReason_ERROR_REASON_CRL_SIGN_MISSING,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			c.opts.Now = testNow
			_, err := ValidateAnchor(c.cert, c.opts)
			wantReason(t, err, apperr.CodeOperatorCARejected, c.reason)
		})
	}
}

// Without a CRL source a CA whose key usage lacks cRLSign is fine: nothing
// has to be verified against it.
func TestValidateAnchor_NoCRLSignIsFineWithoutACRL(t *testing.T) {
	ca := newCA(t, caOpts{keyUsage: x509.KeyUsageCertSign})
	if _, err := ValidateAnchor(ca.cert, AnchorOptions{Now: testNow}); err != nil {
		t.Fatalf("ValidateAnchor = %v", err)
	}
}

// A sub-CA signed by a fleet node's CA is allowed, with a warning that
// names the weakening: relying parties that trust the fleet for clientAuth
// would accept operator certificates too.
func TestValidateAnchor_WarnsWhenIssuedByANodeCA(t *testing.T) {
	root := newCA(t, caOpts{cn: "Example Fleet Root"})
	sub := newCA(t, caOpts{cn: "Example Operator CA", parent: &root})

	warnings, err := ValidateAnchor(sub.cert, AnchorOptions{Now: testNow, NodeCAs: []*x509.Certificate{root.cert}})
	if err != nil {
		t.Fatalf("ValidateAnchor = %v, want accepted", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "Example Fleet Root") {
		t.Fatalf("warnings = %q, want one naming the node CA", warnings)
	}
}

// NodeCAWarning catches what ValidateAnchor cannot: a CA registered before a
// matching node existed, which only becomes a node's CA once that node is
// linked.
func TestNodeCAWarning_MatchByCertificateOrKey(t *testing.T) {
	node := newCA(t, caOpts{cn: "Example Workload Intermediate"})
	reissued := newCA(t, caOpts{cn: "Example Workload Intermediate G2", key: node.key})
	other := newCA(t, caOpts{cn: "Example Other CA"})

	cases := map[string]struct {
		cert    *x509.Certificate
		nodeCAs []*x509.Certificate
		want    string
	}{
		"same certificate":            {cert: node.cert, nodeCAs: []*x509.Certificate{node.cert}, want: "Example Workload Intermediate"},
		"re-issued with the same key": {cert: reissued.cert, nodeCAs: []*x509.Certificate{node.cert}, want: "Example Workload Intermediate"},
		"no match":                    {cert: other.cert, nodeCAs: []*x509.Certificate{node.cert}},
		"no nodes at all":             {cert: other.cert},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := NodeCAWarning(c.cert, c.nodeCAs)
			if c.want == "" {
				if got != "" {
					t.Fatalf("NodeCAWarning = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, c.want) {
				t.Fatalf("NodeCAWarning = %q, want it to name %q", got, c.want)
			}
		})
	}
}

func TestParseAnchorUpload(t *testing.T) {
	ca := newCA(t, caOpts{})
	other := newCA(t, caOpts{cn: "Example Other CA"})
	onePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	twoPEM := append(append([]byte{}, onePEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.cert.Raw})...)

	for name, in := range map[string][]byte{"DER": ca.cert.Raw, "PEM": onePEM} {
		got, err := ParseAnchorUpload(in)
		if err != nil || !got.Equal(ca.cert) {
			t.Fatalf("%s: ParseAnchorUpload = %v, %v", name, got, err)
		}
	}
	for name, in := range map[string][]byte{
		"two certificates": twoPEM,
		"garbage":          []byte("not a certificate"),
		"over 8 KiB":       append(onePEM, make([]byte, 8<<10)...),
		"empty":            nil,
	} {
		_, err := ParseAnchorUpload(in)
		if code, ok := apperr.Code(err); !ok || code != apperr.CodeOperatorCARejected {
			t.Errorf("%s: ParseAnchorUpload error = %v, want a 1605", name, err)
		}
	}
}

// The config-file source refuses at start any anchor that is a node's CA,
// by certificate or by public key.
func TestCheckNotNodeCA(t *testing.T) {
	node := newCA(t, caOpts{cn: "Example Workload Intermediate"})
	sameKey := newCA(t, caOpts{cn: "Example Workload Intermediate G2", key: node.key})
	operator := newCA(t, caOpts{})

	if err := CheckNotNodeCA([]*x509.Certificate{operator.cert}, []*x509.Certificate{node.cert}); err != nil {
		t.Fatalf("CheckNotNodeCA(operator CA) = %v", err)
	}
	for name, anchor := range map[string]*x509.Certificate{"same cert": node.cert, "same key": sameKey.cert} {
		err := CheckNotNodeCA([]*x509.Certificate{operator.cert, anchor}, []*x509.Certificate{node.cert})
		wantReason(t, err, apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_IS_NODE_CA)
		if !strings.Contains(err.Error(), "Example Workload Intermediate") {
			t.Errorf("%s: error %q doesn't name the anchor", name, err)
		}
	}
	if !errors.Is(CheckNotNodeCA(nil, nil), nil) {
		t.Fatal("CheckNotNodeCA with nothing to check failed")
	}
}
