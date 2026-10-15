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
	"crypto/x509"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/operatorca"
)

// testCredentialValidity mirrors the real constants in bootstrap.go and
// steps_opcred.go: comfortably over operatorca's minLeafValidity (a day), so
// a shorter test fixture can't mask a floor these two need to clear for real.
const testCredentialValidity = 48 * time.Hour

func TestGenerateCAPassesTheManagersOwnAnchorCheck(t *testing.T) {
	ca, _, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	// The real oracle for RegisterOperatorCA: NOT_A_CA, EXPIRING, KEY_TYPE and
	// IS_NODE_CA all come from here, not from a hand-picked subset of them.
	if warnings, err := operatorca.ValidateAnchor(ca, operatorca.AnchorOptions{Now: time.Now()}); err != nil {
		t.Errorf("operatorca.ValidateAnchor rejects the CA generateCA produced: %v", err)
	} else if len(warnings) != 0 {
		t.Errorf("operatorca.ValidateAnchor warnings = %v, want none", warnings)
	}
}

func TestSignCredentialStampsTheLevelTheManagerReads(t *testing.T) {
	ca, caKey, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	csrDER, _, err := generateCSR("admin@example.org")
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}
	certDER, err := signCredential(ca, caKey, csrDER, "admin", testCredentialValidity)
	if err != nil {
		t.Fatalf("signCredential: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != "admin@example.org" {
		t.Errorf("CommonName = %q, want the CSR's", cert.Subject.CommonName)
	}
	level, err := authz.LevelFromCertificate(cert)
	if err != nil {
		t.Fatalf("authz.LevelFromCertificate: %v", err)
	}
	if level != authz.LevelAdmin {
		t.Errorf("level = %v, want LevelAdmin", level)
	}
	if err := cert.CheckSignatureFrom(ca); err != nil {
		t.Errorf("cert does not chain to the operator CA: %v", err)
	}

	// The real oracle: this is exactly what the manager runs a submitted
	// operator certificate through (BASIC_CONSTRAINTS, EKU, KEY_USAGE,
	// KEY_TYPE, EXPIRING and the rest), not a hand-picked subset of it.
	if _, err := operatorca.CheckOperatorCert(cert, ca, operatorca.CertCheck{Now: time.Now(), WantLevel: "admin"}); err != nil {
		t.Errorf("operatorca.CheckOperatorCert rejects a credential signCredential produced: %v", err)
	}
}

func TestSignCredentialRejectsAnUnknownLevel(t *testing.T) {
	ca, caKey, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	csrDER, _, err := generateCSR("viewer@example.org")
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}
	if _, err := signCredential(ca, caKey, csrDER, "superuser", testCredentialValidity); err == nil {
		t.Fatal("signCredential: want an error for an unknown level")
	}
}

func TestParseOIDMatchesTheAccessLevelOID(t *testing.T) {
	oid, err := parseOID(authz.AccessLevelOID)
	if err != nil {
		t.Fatalf("parseOID: %v", err)
	}
	if oid.String() != authz.AccessLevelOID {
		t.Errorf("oid = %v, want %s", oid, authz.AccessLevelOID)
	}
}
