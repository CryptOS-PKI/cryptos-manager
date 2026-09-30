package apperr

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
	"context"
	"errors"
	"strconv"

	connect "connectrpc.com/connect"
)

// MetadataKey carries the numeric code on the error's metadata, so the UI can
// branch on a number instead of matching message text.
//
// Metadata rather than a protobuf detail: it needs no message type, so no api
// release, and connect-web surfaces it on ConnectError.metadata already.
const MetadataKey = "x-cryptos-error-code"

// Interceptor gives every error leaving the web-facing API a code.
//
// One interceptor rather than an edit in each handler: the handlers number in
// the dozens, and the contract we want is a property of the boundary, not of
// each one. A handler opts a failure into a specific code by wrapping it with
// Coded; anything it does not classify still leaves here as CodeUnknown, so the
// UI can always show something and a report can always quote something.
//
// A Connect code already chosen by a handler is preserved -- it is what decides
// the HTTP status, and the web layer branches on Unauthenticated versus
// PermissionDenied for the certificate screens.
func Interceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			resp, err := next(ctx, req)
			if err == nil {
				return resp, nil
			}

			return nil, withCode(ctx, err)
		}
	}
}

func withCode(ctx context.Context, err error) error {
	// Present sanitises: the client gets the rendered message for the code and
	// never the internal cause, which may name a node, a path or a DSN.
	clientMsg, code := registry.PresentContext(ctx, err, CodeUnknown)

	out := connect.NewError(connectCodeOf(err), errors.New(clientMsg))
	out.Meta().Set(MetadataKey, strconv.Itoa(code))

	return out
}

// connectCodeOf keeps the transport-level code a handler chose, defaulting to
// Internal for a plain error. The numeric code says what went wrong; the
// Connect code says how the client should treat it.
func connectCodeOf(err error) connect.Code {
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		return connectErr.Code()
	}

	return connect.CodeInternal
}
