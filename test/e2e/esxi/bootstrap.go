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
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	connect "connectrpc.com/connect"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1/fleetv1connect"
)

// bootstrapSessionHeader is the header RegisterOperatorCA and
// SubmitFirstAdminCertificate take the session secret in, never the body
// (proto/cryptos/fleet/v1/bootstrap.proto).
const bootstrapSessionHeader = "Fleetos-Bootstrap-Session"

// firstAdminValidity is how long the first admin's own certificate lasts: the
// run's own lifetime, nothing more.
const firstAdminValidity = 7 * 24 * time.Hour // well over the 1610 EXPIRING floor (under 1 day left)

// bootstrapResult is what the ceremony hands back: the operator CA this
// script now holds (so it can sign further operator credentials later) and
// an HTTP client presenting the first admin's certificate, ready to build the
// FleetService client from.
type bootstrapResult struct {
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	adminTLS tls.Certificate
	client   *http.Client
}

// runBootstrap stands the manager up from nothing: it waits for the
// bootstrap token the manager just printed, registers this script's own
// throwaway operator CA as the external operator CA, signs and submits the
// first admin certificate, and returns an mTLS client authenticated as that
// admin. baseURL is the manager's own https:// origin; insecureSkipVerify
// is appropriate here because the manager's self-signed bootstrap TLS
// certificate has no CA this script could otherwise check, and the whole
// exchange stays on loopback for the run's own lifetime.
func runBootstrap(ctx context.Context, mp *managerProcess, baseURL, adminEmail string) (*bootstrapResult, error) {
	anonClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	boot := fleetv1connect.NewBootstrapServiceClient(anonClient, baseURL)

	token, err := mp.waitToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("waiting for the bootstrap token: %w", err)
	}
	sessResp, err := boot.StartBootstrapSession(ctx, connect.NewRequest(&fleetv1.StartBootstrapSessionRequest{Token: token}))
	if err != nil {
		return nil, fmt.Errorf("StartBootstrapSession: %w", err)
	}
	session := sessResp.Msg.GetSessionSecret()

	ca, caKey, err := generateCA()
	if err != nil {
		return nil, err
	}
	caDER := ca.Raw
	sum := sha256.Sum256(caDER)
	confirmSHA256 := hex.EncodeToString(sum[:])

	regReq := connect.NewRequest(&fleetv1.BootstrapServiceRegisterOperatorCARequest{
		CaCertDer:        caDER,
		CrlSource:        &fleetv1.BootstrapServiceRegisterOperatorCARequest_None{None: true},
		OcspMode:         fleetv1.OcspMode_OCSP_MODE_OFF,
		Acknowledgements: []fleetv1.OperatorCAAcknowledgement{fleetv1.OperatorCAAcknowledgement_OPERATOR_CA_ACKNOWLEDGEMENT_NO_CRL},
		// Set on the one call: the manager computes the same hash over
		// ca_cert_der, so there is nothing a separate preview round trip would
		// catch that pre-computing it here doesn't.
		ConfirmSha256: confirmSHA256,
	})
	regReq.Header().Set(bootstrapSessionHeader, session)
	regResp, err := boot.RegisterOperatorCA(ctx, regReq)
	if err != nil {
		return nil, fmt.Errorf("RegisterOperatorCA: %w", err)
	}
	if !regResp.Msg.GetConfirmed() {
		return nil, fmt.Errorf("RegisterOperatorCA: operator CA was not confirmed")
	}

	csrDER, adminKey, err := generateCSR(adminEmail)
	if err != nil {
		return nil, err
	}
	adminCertDER, err := signCredential(ca, caKey, csrDER, "admin", firstAdminValidity)
	if err != nil {
		return nil, err
	}
	submitReq := connect.NewRequest(&fleetv1.SubmitFirstAdminCertificateRequest{
		CertDer:  adminCertDER,
		CsrDer:   csrDER,
		FullName: "cryptos-manager e2e",
	})
	submitReq.Header().Set(bootstrapSessionHeader, session)
	if _, err := boot.SubmitFirstAdminCertificate(ctx, submitReq); err != nil {
		return nil, fmt.Errorf("SubmitFirstAdminCertificate: %w", err)
	}

	adminTLS := tls.Certificate{Certificate: [][]byte{adminCertDER}, PrivateKey: adminKey}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{adminTLS},
	}}}
	return &bootstrapResult{ca: ca, caKey: caKey, adminTLS: adminTLS, client: client}, nil
}
