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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
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
