// Package operatorca decides which operator CA the Fleet Manager trusts and
// whether an operator certificate is still good.
//
// The operator CA is always external: an offline OpenSSL CA or an enterprise
// CA, never a CryptOS node. The manager learns only its certificate, the
// trust anchor. It never holds a CA key and never signs an operator
// credential, and nothing in this package generates, loads or stores one.
//
// Resolve picks where the anchors come from (the operatorCAPath file wins
// over registered rows). TrustStore holds the current anchors as numbered
// generations, serves them to the TLS handshake and re-verifies the peer on
// every request. Revocations combines the manager's denylist with each
// anchor's CRL, keyed by anchor, because serials are unique per issuer only,
// and asks the anchor's OCSP responder about each certificate through
// OCSPClient, which can only add a refusal.
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
