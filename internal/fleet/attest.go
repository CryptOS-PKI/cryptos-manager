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
	"encoding/hex"
	"errors"
	"fmt"
)

// attestNonceBytes is the size of the random challenge sent to a node in
// verifyAttestation. It has no relation to the digest size: the node signs
// SHA-384 of the nonce regardless of how long the nonce itself is.
const attestNonceBytes = 32

// verifyAttestation drives the enrollment challenge-response: it sends a
// fresh random nonce to conn's node, verifies the node signed
// SHA-384(nonce) with its CA identity key (mirroring the node's attester,
// which signs the same digest via crypto.Signer.Sign with crypto.SHA384),
// and returns the identity's SPKI SHA-256 fingerprint (hex) for TOFU
// pinning. A non-nil error means the node's identity must not be trusted.
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

	digest := sha512.Sum384(nonce)
	if !ecdsa.VerifyASN1(ecPub, digest[:], resp.GetSignature()) {
		return "", errors.New("attest: signature does not verify against the identity key")
	}

	sum := sha256.Sum256(resp.GetIdentityPubDer())
	return hex.EncodeToString(sum[:]), nil
}
