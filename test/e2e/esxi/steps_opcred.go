package main

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
	"fmt"
	"math/big"
	"time"

	connect "connectrpc.com/connect"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
)

const operatorCredentialValidity = 7 * 24 * time.Hour // well over the 1610 EXPIRING floor (under 1 day left)

// opCredStep exercises CreateOperatorCredentialRequest, RecordOperatorCredential,
// ListOperatorCredentials, RevokeOperatorCredential and
// CancelOperatorCredentialRequest. The manager never signs an operator
// credential itself (the operator CA is always external); this script signs
// the CSR it is handed back with the same CA it registered at bootstrap,
// the role a real CA operator plays signing out of band.
func (s *scenario) opCredStep() step {
	return step{name: "operator-credentials/request-record-revoke-cancel", run: func(ctx context.Context) (string, error) {
		csrDER, _, err := generateCSR("viewer-e2e@example.org")
		if err != nil {
			return "", err
		}
		requested, err := s.fleet.CreateOperatorCredentialRequest(ctx, connect.NewRequest(&fleetv1.CreateOperatorCredentialRequestRequest{
			Level: "viewer", Email: "viewer-e2e@example.org", FullName: "cryptos-manager e2e viewer", CsrDer: csrDER,
		}))
		if err != nil {
			return "", fmt.Errorf("CreateOperatorCredentialRequest: %w", err)
		}
		requestID := requested.Msg.GetRequestId()

		certDER, err := signCredential(s.ca, s.caKey, csrDER, "viewer", operatorCredentialValidity)
		if err != nil {
			return "", err
		}
		leaf, err := x509.ParseCertificate(certDER)
		if err != nil {
			return "", fmt.Errorf("parsing the signed credential: %w", err)
		}

		if _, err := s.fleet.RecordOperatorCredential(ctx, connect.NewRequest(&fleetv1.RecordOperatorCredentialRequest{
			CertDer: certDER, RequestId: requestID,
		})); err != nil {
			return "", fmt.Errorf("RecordOperatorCredential: %w", err)
		}

		listed, err := s.fleet.ListOperatorCredentials(ctx, connect.NewRequest(&fleetv1.ListOperatorCredentialsRequest{}))
		if err != nil {
			return "", fmt.Errorf("ListOperatorCredentials: %w", err)
		}
		cred := findOperatorCredential(listed.Msg.GetItems(), leaf.SerialNumber)
		if cred == nil {
			return "", fmt.Errorf("ListOperatorCredentials does not carry the credential RecordOperatorCredential just recorded")
		}
		if cred.GetRevoked() {
			return "", fmt.Errorf("the recorded credential is already revoked")
		}

		if _, err := s.fleet.RevokeOperatorCredential(ctx, connect.NewRequest(&fleetv1.RevokeOperatorCredentialRequest{
			SerialHex: cred.GetSerialHex(), ReasonCode: 0, Note: "e2e revoke-path exercise",
		})); err != nil {
			return "", fmt.Errorf("RevokeOperatorCredential: %w", err)
		}
		afterRevoke, err := s.fleet.ListOperatorCredentials(ctx, connect.NewRequest(&fleetv1.ListOperatorCredentialsRequest{}))
		if err != nil {
			return "", fmt.Errorf("ListOperatorCredentials (after revoke): %w", err)
		}
		revokedCred := findOperatorCredential(afterRevoke.Msg.GetItems(), leaf.SerialNumber)
		if revokedCred == nil || !revokedCred.GetRevoked() {
			return "", fmt.Errorf("the credential does not show revoked after RevokeOperatorCredential")
		}

		// The cancel path: a second, unrelated request, cancelled rather than
		// recorded.
		csr2, _, err := generateCSR("cancelled-e2e@example.org")
		if err != nil {
			return "", err
		}
		second, err := s.fleet.CreateOperatorCredentialRequest(ctx, connect.NewRequest(&fleetv1.CreateOperatorCredentialRequestRequest{
			Level: "viewer", Email: "cancelled-e2e@example.org", FullName: "cryptos-manager e2e cancelled", CsrDer: csr2,
		}))
		if err != nil {
			return "", fmt.Errorf("CreateOperatorCredentialRequest (second, for the cancel path): %w", err)
		}
		if _, err := s.fleet.CancelOperatorCredentialRequest(ctx, connect.NewRequest(&fleetv1.CancelOperatorCredentialRequestRequest{
			RequestId: second.Msg.GetRequestId(),
		})); err != nil {
			return "", fmt.Errorf("CancelOperatorCredentialRequest: %w", err)
		}
		requests, err := s.fleet.ListOperatorCredentialRequests(ctx, connect.NewRequest(&fleetv1.ListOperatorCredentialRequestsRequest{}))
		if err != nil {
			return "", fmt.Errorf("ListOperatorCredentialRequests: %w", err)
		}
		cancelled := findOperatorCredentialRequest(requests.Msg.GetItems(), second.Msg.GetRequestId())
		if cancelled == nil || cancelled.GetState() != "cancelled" {
			return "", fmt.Errorf("the second request does not show state cancelled after CancelOperatorCredentialRequest")
		}
		return "requested, recorded, revoked and separately cancelled operator credentials", nil
	}}
}

func findOperatorCredential(items []*fleetv1.OperatorCredential, serial *big.Int) *fleetv1.OperatorCredential {
	for _, c := range items {
		if serialMatches(c.GetSerialHex(), serial) {
			return c
		}
	}
	return nil
}

func findOperatorCredentialRequest(items []*fleetv1.OperatorCredentialRequest, id string) *fleetv1.OperatorCredentialRequest {
	for _, r := range items {
		if r.GetId() == id {
			return r
		}
	}
	return nil
}
