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
	"errors"
	"fmt"
	"slices"
	"time"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/apperr"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// AckNoCRL is the acknowledgement that an operator CA has no CRL source:
// revocations made at the CA aren't seen, and MCP is refused under it.
const AckNoCRL = "NO_CRL"

// CRLChoice is the CRL source chosen for an operator CA when it is
// registered or changed: none, url or upload.
type CRLChoice struct {
	Source           string
	URL              string
	DER              []byte
	Acknowledgements []string
}

// CheckCRLChoice checks a CRL source against anchor before it is stored:
// none needs the NO_CRL acknowledgement; url and upload need cRLSign on the
// anchor, and the CRL, fetched with fetch for url, must verify against the
// anchor. It returns the verified CRL, nil for none.
func CheckCRLChoice(ctx context.Context, anchor *x509.Certificate, c CRLChoice, now time.Time, fetch func(context.Context, string) ([]byte, error)) (*VerifiedCRL, error) {
	switch c.Source {
	case store.CRLSourceNone:
		if !slices.Contains(c.Acknowledgements, AckNoCRL) {
			return nil, rejectAnchor(fleetv1.ErrorReason_ERROR_REASON_NO_CRL_NOT_ACKNOWLEDGED,
				"no CRL source was chosen and NO_CRL wasn't acknowledged")
		}
		return nil, nil
	case store.CRLSourceURL, store.CRLSourceUpload:
	default:
		return nil, fmt.Errorf("operatorca: unknown CRL source %q", c.Source)
	}
	if anchor.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, rejectAnchor(fleetv1.ErrorReason_ERROR_REASON_CRL_SIGN_MISSING,
			"%s has no cRLSign key usage, so no CRL can be verified against it", anchor.Subject)
	}
	der := c.DER
	if c.Source == store.CRLSourceURL {
		if err := ValidateFetchURL(c.URL); err != nil {
			return nil, crlUnreachable("refused the URL: %v", err)
		}
		if fetch == nil {
			return nil, crlUnreachable("isn't available in this process")
		}
		b, err := fetch(ctx, c.URL)
		if err != nil {
			if _, ok := apperr.ReasonOf(err); ok {
				return nil, err
			}
			return nil, crlUnreachable("from %s failed: %v", redact(c.URL), err)
		}
		der = b
	}
	if len(der) == 0 {
		return nil, crlInvalid("is empty")
	}
	return VerifyCRL(der, anchor, now)
}

// ErrOCSPURL is returned by CheckOCSPChoice for a URL that doesn't fit the
// mode: missing in url mode, or set in any other.
var ErrOCSPURL = errors.New("operatorca: ocsp_url is required for OCSP mode url and only allowed with it")

// CheckOCSPChoice checks an OCSP mode and URL before they are stored. In url
// mode the URL must be an http or https URL and the responder must answer
// probe with a validly signed response, which is returned; the other modes
// send nothing. probe may be nil when OCSP is off in this process.
func CheckOCSPChoice(ctx context.Context, anchor *x509.Certificate, mode, url string, probe func(context.Context, *x509.Certificate, string) (OCSPResult, error)) (*OCSPResult, error) {
	switch mode {
	case store.OCSPModeOff, store.OCSPModeAIA:
		if url != "" {
			return nil, ErrOCSPURL
		}
		return nil, nil
	case store.OCSPModeURL:
	default:
		return nil, fmt.Errorf("operatorca: unknown OCSP mode %q", mode)
	}
	if url == "" {
		return nil, ErrOCSPURL
	}
	if err := ValidateFetchURL(url); err != nil {
		return nil, ocspUnreachable("URL refused: %v", err)
	}
	if probe == nil {
		return nil, nil
	}
	res, err := probe(ctx, anchor, url)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
