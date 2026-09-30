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
	"net/http"
	"strconv"
	"strings"

	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
)

// ReasonKey carries a failure's sub-reason next to its code: the api's
// ErrorReason value name without the ERROR_REASON_ prefix, for example
// "STALE_CRL".
const ReasonKey = "x-cryptos-error-reason"

type reasoned struct {
	reason fleetv1.ErrorReason
	err    error
}

func (r *reasoned) Error() string { return r.err.Error() }
func (r *reasoned) Unwrap() error { return r.err }

// Reasoned tags cause with a code and a sub-reason. Both reach the client;
// the cause doesn't.
func Reasoned(code int, reason fleetv1.ErrorReason, cause error) error {
	return Coded(code, &reasoned{reason: reason, err: cause})
}

// ReasonOf recovers the sub-reason from an error chain.
func ReasonOf(err error) (fleetv1.ErrorReason, bool) {
	var r *reasoned
	if errors.As(err, &r) {
		return r.reason, true
	}
	return fleetv1.ErrorReason_ERROR_REASON_UNSPECIFIED, false
}

// ReasonName is the wire form of a sub-reason.
func ReasonName(r fleetv1.ErrorReason) string {
	return strings.TrimPrefix(r.String(), "ERROR_REASON_")
}

// WriteHTTP answers a refusal made outside Connect, such as in the
// client-certificate middleware, with status and the same code and reason
// headers the interceptor sets. The body is the sanitised message; the cause
// stays in the log.
func WriteHTTP(w http.ResponseWriter, status int, err error) {
	msg, code := registry.Present(err, CodeUnknown)
	w.Header().Set(MetadataKey, strconv.Itoa(code))
	if r, ok := ReasonOf(err); ok {
		w.Header().Set(ReasonKey, ReasonName(r))
	}
	http.Error(w, msg, status)
}
