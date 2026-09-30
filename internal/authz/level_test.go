package authz

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestLevelTokenRoundTrip(t *testing.T) {
	for _, l := range []Level{LevelViewer, LevelOperator, LevelAdmin} {
		got, err := LevelFromToken(l.Token())
		if err != nil || got != l {
			t.Fatalf("round-trip %v: got %v, err %v", l, got, err)
		}
	}
	if _, err := LevelFromToken("bogus"); err == nil {
		t.Error("LevelFromToken(bogus) = nil error, want error")
	}
}

// certWithLevel builds a self-signed cert carrying the access-level extension
// for l, exercising the same extension shape a cryptos profile would stamp.
func certWithLevel(t *testing.T, l Level) *x509.Certificate {
	t.Helper()
	value, err := MarshalLevelValue(l)
	if err != nil {
		t.Fatalf("MarshalLevelValue: %v", err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "op@acme.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: accessLevelOID, Critical: false, Value: value},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestLevelFromCertificate(t *testing.T) {
	for _, l := range []Level{LevelViewer, LevelOperator, LevelAdmin} {
		got, err := LevelFromCertificate(certWithLevel(t, l))
		if err != nil || got != l {
			t.Fatalf("LevelFromCertificate(%v): got %v, err %v", l, got, err)
		}
	}
}

func TestLevelFromCertificate_MissingExtension(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	if _, err := LevelFromCertificate(cert); err == nil {
		t.Error("LevelFromCertificate(no ext) = nil error, want error")
	}
}

func TestMarshalLevelValue_IsDERString(t *testing.T) {
	value, err := MarshalLevelValue(LevelAdmin)
	if err != nil {
		t.Fatalf("MarshalLevelValue: %v", err)
	}
	var s string
	if _, err := asn1.Unmarshal(value, &s); err != nil || s != "admin" {
		t.Fatalf("decoded value = %q, err %v; want admin", s, err)
	}
}
