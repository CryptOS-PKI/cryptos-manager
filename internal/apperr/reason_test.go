package apperr

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
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
)

// The 16xx block is part of the api contract, so every value of the
// generated ErrorCode enum is registered here with the same number.
func TestCodes_RegisterEveryContractCode(t *testing.T) {
	registered := map[int]bool{}
	for _, e := range entries {
		registered[e.Code] = true
	}
	for n := range fleetv1.ErrorCode_name {
		if n == 0 {
			continue
		}
		if !registered[int(n)] {
			t.Errorf("contract code %d (%s) is not registered", n, fleetv1.ErrorCode(n))
		}
	}
	if CodeNoRevocationSource != 1608 || CodeCertRejected != 1610 || CodeUnavailable != 1603 {
		t.Fatalf("contract codes renumbered: 1608=%d 1610=%d 1603=%d", CodeNoRevocationSource, CodeCertRejected, CodeUnavailable)
	}
}

// A sub-reason travels next to the code as the ErrorReason name without its
// prefix, so the web can tell STALE_CRL from NO_CRL under the same 1608.
func TestInterceptor_CarriesTheReason(t *testing.T) {
	err := run(t, Reasoned(CodeNoRevocationSource, fleetv1.ErrorReason_ERROR_REASON_STALE_CRL,
		connect.NewError(connect.CodePermissionDenied, errors.New("the CRL for CN=Example Operator CA is past nextUpdate"))))

	if got := metaCode(t, err); got != CodeNoRevocationSource {
		t.Errorf("code = %d, want %d", got, CodeNoRevocationSource)
	}
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("not a connect error: %v", err)
	}
	if got := ce.Meta().Get(ReasonKey); got != "STALE_CRL" {
		t.Errorf("%s = %q, want STALE_CRL", ReasonKey, got)
	}
	if ce.Code() != connect.CodePermissionDenied {
		t.Errorf("connect code = %v, want PermissionDenied", ce.Code())
	}
}

func TestReasonOf(t *testing.T) {
	err := Reasoned(CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED, errors.New("denylisted"))
	if r, ok := ReasonOf(err); !ok || r != fleetv1.ErrorReason_ERROR_REASON_REVOKED {
		t.Fatalf("ReasonOf() = %v, %v", r, ok)
	}
	if _, ok := ReasonOf(errors.New("plain")); ok {
		t.Fatal("ReasonOf found a reason on a plain error")
	}
}

// A refusal answered by HTTP middleware, outside Connect, carries the same
// two headers and never the cause.
func TestWriteHTTP_CarriesCodeAndReasonAsHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTP(rec, 403, Reasoned(CodeCertRejected, fleetv1.ErrorReason_ERROR_REASON_REVOKED,
		errors.New("serial 1f under CN=Example Operator CA is denylisted")))

	if rec.Code != 403 {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get(MetadataKey); got != "1610" {
		t.Errorf("%s = %q, want 1610", MetadataKey, got)
	}
	if got := rec.Header().Get(ReasonKey); got != "REVOKED" {
		t.Errorf("%s = %q, want REVOKED", ReasonKey, got)
	}
	if body := rec.Body.String(); body == "" || strings.Contains(body, "denylisted") || strings.Contains(body, "Example Operator CA") {
		t.Errorf("body = %q, want the sanitised message only", body)
	}
}
