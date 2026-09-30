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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"testing"
)

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func TestVerifyAttestation_OK(t *testing.T) {
	key := mustKey(t)
	conn := &fakeConn{attestKey: key}

	fp, err := verifyAttestation(context.Background(), conn)
	if err != nil {
		t.Fatalf("verifyAttestation: %v", err)
	}

	// fingerprint is the SPKI SHA-256 hex of the same key.
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	sum := sha256.Sum256(der)
	if want := hex.EncodeToString(sum[:]); fp != want {
		t.Fatalf("fingerprint = %s, want %s", fp, want)
	}

	if len(conn.gotNonce) < 16 {
		t.Fatal("expected a non-trivial nonce to be sent")
	}
}

func TestVerifyAttestation_BadSignature(t *testing.T) {
	// A fake that returns a valid identity public key but signs the wrong
	// bytes, so the signature does not verify against the nonce digest.
	conn := &fakeConn{attestKey: mustKey(t), attestBadSig: true}

	if _, err := verifyAttestation(context.Background(), conn); err == nil {
		t.Fatal("verifyAttestation: error = nil, want a signature-verification error")
	}
}

func TestVerifyAttestation_DialError(t *testing.T) {
	conn := &fakeConn{err: errors.New("dial refused")}

	if _, err := verifyAttestation(context.Background(), conn); err == nil {
		t.Fatal("verifyAttestation: error = nil, want the underlying Attest error")
	}
}

func TestVerifyAttestation_NonECDSAKey(t *testing.T) {
	// fakeConn only ever signs with ECDSA keys, so exercise the
	// non-ECDSA-key rejection path directly is out of scope here without a
	// second fake key type; the zero-value AttestResponse (no key, no
	// signature) instead exercises the "unparseable identity key" path.
	conn := &fakeConn{}

	if _, err := verifyAttestation(context.Background(), conn); err == nil {
		t.Fatal("verifyAttestation: error = nil, want a parse error for an empty identity key")
	}
}

// TestAttestationMessage_KnownAnswer is the same vector as the node's
// TestAttestationMessage_KnownAnswer in cryptos, so the bytes the manager
// verifies are pinned to the bytes the node signs.
func TestAttestationMessage_KnownAnswer(t *testing.T) {
	got := attestationMessage([]byte{0xde, 0xad, 0xbe, 0xef})
	want := append([]byte("CryptOS-PKI attestation v1\x00"), 0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef)
	if !bytes.Equal(got, want) {
		t.Fatalf("attestationMessage = %x, want %x", got, want)
	}
}

// captureLog redirects the standard logger for the duration of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return &buf
}

func TestVerifyAttestation_VersionedMessageDoesNotWarn(t *testing.T) {
	logs := captureLog(t)
	conn := &fakeConn{attestKey: mustKey(t)}

	if _, err := verifyAttestation(context.Background(), conn); err != nil {
		t.Fatalf("verifyAttestation: %v", err)
	}
	if strings.Contains(logs.String(), "WARNING") {
		t.Errorf("unexpected warning for a versioned attestation: %q", logs.String())
	}
}

// A node that predates the versioned message signs the bare nonce. It is
// still accepted, so the manager can ship before the node change, but loudly.
func TestVerifyAttestation_LegacyBareNonceAcceptedWithWarning(t *testing.T) {
	logs := captureLog(t)
	key := mustKey(t)
	conn := &fakeConn{attestKey: key, attestLegacy: true}

	fp, err := verifyAttestation(context.Background(), conn)
	if err != nil {
		t.Fatalf("verifyAttestation: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if want := hex.EncodeToString(sum[:]); fp != want {
		t.Fatalf("fingerprint = %s, want %s", fp, want)
	}
	if !strings.Contains(logs.String(), "WARNING") || !strings.Contains(logs.String(), "bare nonce") {
		t.Errorf("want a warning naming the bare-nonce format, got %q", logs.String())
	}
}

func TestVerifyAttestation_LegacyBadSignature(t *testing.T) {
	conn := &fakeConn{attestKey: mustKey(t), attestLegacy: true, attestBadSig: true}

	if _, err := verifyAttestation(context.Background(), conn); err == nil {
		t.Fatal("verifyAttestation: error = nil, want a signature-verification error")
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

func wantFingerprint(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// An RSA CA node signs with RSASSA-PKCS1-v1_5 over SHA-384, because the node's
// attester passes crypto.SHA384 to the generic crypto.Signer.Sign.
func TestVerifyAttestation_RSA_VersionedMessage(t *testing.T) {
	logs := captureLog(t)
	key := mustRSAKey(t)
	conn := &fakeConn{attestSigner: key}

	fp, err := verifyAttestation(context.Background(), conn)
	if err != nil {
		t.Fatalf("verifyAttestation: %v", err)
	}
	if want := wantFingerprint(t, &key.PublicKey); fp != want {
		t.Fatalf("fingerprint = %s, want %s", fp, want)
	}
	if strings.Contains(logs.String(), "WARNING") {
		t.Errorf("unexpected warning for a versioned attestation: %q", logs.String())
	}
}

func TestVerifyAttestation_RSA_LegacyBareNonceAcceptedWithWarning(t *testing.T) {
	logs := captureLog(t)
	key := mustRSAKey(t)
	conn := &fakeConn{attestSigner: key, attestLegacy: true}

	fp, err := verifyAttestation(context.Background(), conn)
	if err != nil {
		t.Fatalf("verifyAttestation: %v", err)
	}
	if want := wantFingerprint(t, &key.PublicKey); fp != want {
		t.Fatalf("fingerprint = %s, want %s", fp, want)
	}
	if !strings.Contains(logs.String(), "WARNING") || !strings.Contains(logs.String(), "bare nonce") {
		t.Errorf("want a warning naming the bare-nonce format, got %q", logs.String())
	}
}

func TestVerifyAttestation_RSA_BadSignature(t *testing.T) {
	conn := &fakeConn{attestSigner: mustRSAKey(t), attestBadSig: true}

	if _, err := verifyAttestation(context.Background(), conn); err == nil {
		t.Fatal("verifyAttestation: error = nil, want a signature-verification error")
	}
}

func TestVerifyAttestation_UnsupportedKeyType(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	conn := &fakeConn{attestSigner: key}

	_, err = verifyAttestation(context.Background(), conn)
	if err == nil {
		t.Fatal("verifyAttestation: error = nil, want an unsupported-key-type error")
	}
	if !strings.Contains(err.Error(), "unsupported identity key type") {
		t.Errorf("error = %q, want it to name the unsupported key type", err)
	}
}
