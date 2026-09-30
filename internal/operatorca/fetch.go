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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/manager/internal/apperr"
)

// Limits on the manager's outbound fetches of CRLs and OCSP responses.
const (
	DefaultFetchTimeout = 10 * time.Second
	maxRedirects        = 3
	maxURLLength        = 2 << 10
)

// FetchLimits bounds one fetch.
type FetchLimits struct {
	Timeout  time.Duration
	MaxBytes int64
}

// Fetcher gets a CRL over http or https with fixed limits: a timeout, at
// most three redirects and only to http or https, no proxy from the
// environment, and a body cap. Errors never carry the response body. The URL
// is set only by an admin or the bootstrap session holder; the limited SSRF
// that allows is accepted.
type Fetcher struct {
	client   *http.Client
	maxBytes int64
}

// NewFetcher builds a Fetcher with an explicit transport, so proxy settings
// in the environment don't change where the manager connects.
func NewFetcher(l FetchLimits) *Fetcher {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: l.Timeout}).DialContext,
		TLSHandshakeTimeout:   l.Timeout,
		ResponseHeaderTimeout: l.Timeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &Fetcher{
		maxBytes: l.MaxBytes,
		client: &http.Client{
			Transport: transport,
			Timeout:   l.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > maxRedirects {
					return fmt.Errorf("more than %d redirects", maxRedirects)
				}
				if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
					return fmt.Errorf("redirect to a %q URL", req.URL.Scheme)
				}
				return nil
			},
		},
	}
}

func crlUnreachable(format string, args ...any) error {
	return apperr.Reasoned(apperr.CodeOperatorCARejected, fleetv1.ErrorReason_ERROR_REASON_CRL_UNREACHABLE,
		fmt.Errorf("operatorca: CRL fetch "+format, args...))
}

// ValidateFetchURL accepts an absolute http or https URL with a host, at
// most 2 KiB long.
func ValidateFetchURL(raw string) error {
	if len(raw) > maxURLLength {
		return fmt.Errorf("the URL is %d characters, more than %d", len(raw), maxURLLength)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("the URL doesn't parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("the URL must be http or https, not %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("the URL has no host")
	}
	return nil
}

// Fetch GETs rawURL and returns the body.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	return f.do(ctx, http.MethodGet, rawURL, "", nil)
}

func (f *Fetcher) do(ctx context.Context, method, rawURL, contentType string, body io.Reader) ([]byte, error) {
	b, err := f.request(ctx, method, rawURL, contentType, body)
	if err != nil {
		return nil, crlUnreachable("%s %s: %v", method, redact(rawURL), err)
	}
	return b, nil
}

// httpStatusError is a response other than 200 OK.
type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return fmt.Sprintf("HTTP %d", e.code) }

var errBodyTooLarge = errors.New("the response is over the size cap")

// request does one fetch with the limits. Its errors carry no response
// body and no query string.
func (f *Fetcher) request(ctx context.Context, method, rawURL, contentType string, body io.Reader) ([]byte, error) {
	if err := ValidateFetchURL(rawURL); err != nil {
		return nil, fmt.Errorf("refused: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("refused: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, unwrapURLError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{code: resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(b)) > f.maxBytes {
		return nil, fmt.Errorf("%w (%d bytes)", errBodyTooLarge, f.maxBytes)
	}
	return b, nil
}

// unwrapURLError drops the *url.Error wrapper, which repeats the URL.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// redact keeps the scheme, host and path of a URL for logs and errors, and
// drops any query or user information.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable URL)"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}
