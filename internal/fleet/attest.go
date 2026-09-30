package fleet

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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
)

// attestationContext is the versioned label a node binds every Attest
// signature to. It must match cryptos' AttestationContext byte for byte.
const attestationContext = "CryptOS-PKI attestation v1"

// attestationMessage returns the bytes a node signs for an Attest challenge:
//
//	attestationContext || 0x00 || uint32 big-endian len(nonce) || nonce
//
// The node signs SHA-384 of this rather than of the nonce alone, so a nonce the
// manager chose can never make the node's CA key sign something that parses as
// a certificate, CRL or OCSP body.
func attestationMessage(nonce []byte) []byte {
	msg := make([]byte, 0, len(attestationContext)+1+4+len(nonce))
	msg = append(msg, attestationContext...)
	msg = append(msg, 0x00)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(nonce)))
	return append(msg, nonce...)
}

// attestNonceBytes is the size of the random challenge sent to a node in
// verifyAttestation. It has no relation to the digest size: the node signs
// SHA-384 of the attestation message regardless of how long the nonce is.
const attestNonceBytes = 32

// verifyAttestation drives the enrollment challenge-response: it sends a
// fresh random nonce to conn's node, verifies the node signed
// SHA-384(attestationMessage(nonce)) with its CA identity key (mirroring the
// node's attester, which signs the same digest via crypto.Signer.Sign with
// crypto.SHA384), and returns the identity's SPKI SHA-256 fingerprint (hex)
// for TOFU pinning. A non-nil error means the node's identity must not be
// trusted.
//
// A signature over SHA-384(nonce) alone, the format nodes used before the
// versioned message, is still accepted with a warning, so the manager can be
// upgraded ahead of its nodes. That fallback is for one release only.
func verifyAttestation(ctx context.Context, conn NodeConn) (string, error) {
	nonce := make([]byte, attestNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("attest: nonce: %w", err)
	}

	resp, err := conn.Attest(ctx, nonce)
	if err != nil {
		return "", fmt.Errorf("attest: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(resp.GetIdentityPubDer())
	if err != nil {
		return "", fmt.Errorf("attest: parse identity key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("attest: identity key is not ECDSA")
	}

	sum := sha256.Sum256(resp.GetIdentityPubDer())
	fp := hex.EncodeToString(sum[:])

	digest := sha512.Sum384(attestationMessage(nonce))
	if ecdsa.VerifyASN1(ecPub, digest[:], resp.GetSignature()) {
		log.Printf("attest: verified %q signature from identity %s", attestationContext, fp)
		return fp, nil
	}

	legacy := sha512.Sum384(nonce)
	if ecdsa.VerifyASN1(ecPub, legacy[:], resp.GetSignature()) {
		log.Printf("attest: WARNING identity %s signed the bare nonce, not the %q message; "+
			"accepted for this release only, upgrade the node before the next one", fp, attestationContext)
		return fp, nil
	}

	log.Printf("attest: signature from identity %s verifies under neither the %q message nor the bare nonce", fp, attestationContext)
	return "", errors.New("attest: signature does not verify against the identity key")
}
