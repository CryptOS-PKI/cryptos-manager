package fleet

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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
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

// verifySignature checks sig over a SHA-384 digest under pub, using the scheme
// crypto.Signer.Sign(rand, digest, crypto.SHA384) produces for that key type:
// ASN.1 ECDSA for an ECDSA key, RSASSA-PKCS1-v1_5 for an RSA key.
func verifySignature(pub crypto.PublicKey, digest, sig []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, digest, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA384, digest, sig) == nil
	}
	return false
}

// identityKeyType names a supported identity key for logs, or returns "" for
// an unsupported one.
func identityKeyType(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	}
	return ""
}

// verifyAttestation drives the enrollment challenge-response: it sends a
// fresh random nonce to conn's node, verifies the node signed
// SHA-384(attestationMessage(nonce)) with its CA identity key (mirroring the
// node's attester, which signs the same digest via crypto.Signer.Sign with
// crypto.SHA384; ECDSA and RSA identity keys are supported), and returns the identity's SPKI SHA-256 fingerprint (hex)
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
	keyType := identityKeyType(pub)
	if keyType == "" {
		log.Printf("attest: rejecting identity key of unsupported type %T", pub)
		return "", fmt.Errorf("attest: unsupported identity key type %T (want ECDSA or RSA)", pub)
	}

	sum := sha256.Sum256(resp.GetIdentityPubDer())
	fp := hex.EncodeToString(sum[:])
	log.Printf("attest: verifying %s identity %s (%d-byte signature)", keyType, fp, len(resp.GetSignature()))

	digest := sha512.Sum384(attestationMessage(nonce))
	if verifySignature(pub, digest[:], resp.GetSignature()) {
		log.Printf("attest: verified %q signature from %s identity %s", attestationContext, keyType, fp)
		return fp, nil
	}

	legacy := sha512.Sum384(nonce)
	if verifySignature(pub, legacy[:], resp.GetSignature()) {
		log.Printf("attest: WARNING %s identity %s signed the bare nonce, not the %q message; "+
			"accepted for this release only, upgrade the node before the next one", keyType, fp, attestationContext)
		return fp, nil
	}

	log.Printf("attest: signature from %s identity %s verifies under neither the %q message nor the bare nonce", keyType, fp, attestationContext)
	return "", errors.New("attest: signature does not verify against the identity key")
}
