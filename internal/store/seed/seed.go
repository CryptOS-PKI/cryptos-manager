// Package seed provides the manager's built-in catalog fixtures: profiles,
// enrollment adapters, audit history, and enrollment requests. Values are
// ported from the web UI's mock fixtures so the live UI shows familiar data
// until the manager grows a real catalog backend.
package seed

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
	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"github.com/CryptOS-PKI/manager/internal/store"
	"google.golang.org/protobuf/proto"
)

// Catalog returns the manager's seeded profiles, adapters, audit events,
// and enrollment requests.
func Catalog() (profiles []store.Profile, adapters []store.Adapter, audit []store.AuditEvent, enrollments []store.Enrollment) {
	return profilesSeed(), adaptersSeed(), auditSeed(), enrollmentsSeed()
}

// profilesSeed builds the five built-in catalog templates as full
// cryptos.v1.CertificateProfile values and marshals each into a store.Profile.
// The catalog is the same proto shape a node stores in pki.profiles[], so a
// seeded profile applies to a node verbatim.
func profilesSeed() []store.Profile {
	pathLen0 := uint32(0)
	specs := []*cryptosv1.CertificateProfile{
		{
			Name:             "TLS Server (LDAPS)",
			KeyAlg:           "ECDSA-P384",
			ValidityDays:     365,
			BasicConstraints: &cryptosv1.BasicConstraints{IsCa: false},
			KeyUsage:         []string{"digital_signature", "key_encipherment"},
			ExtKeyUsage:      []string{"server_auth"},
		},
		{
			Name:             "TLS Client",
			KeyAlg:           "ECDSA-P384",
			ValidityDays:     365,
			BasicConstraints: &cryptosv1.BasicConstraints{IsCa: false},
			KeyUsage:         []string{"digital_signature"},
			ExtKeyUsage:      []string{"client_auth"},
		},
		{
			Name:             "Domain Controller",
			KeyAlg:           "ECDSA-P384",
			ValidityDays:     365,
			BasicConstraints: &cryptosv1.BasicConstraints{IsCa: false},
			KeyUsage:         []string{"digital_signature", "key_encipherment"},
			ExtKeyUsage:      []string{"server_auth", "client_auth"},
		},
		{
			Name:             "Code Signing",
			KeyAlg:           "RSA-3072",
			ValidityDays:     1095,
			BasicConstraints: &cryptosv1.BasicConstraints{IsCa: false},
			KeyUsage:         []string{"digital_signature"},
			ExtKeyUsage:      []string{"code_signing"},
		},
		{
			Name:             "Subordinate CA",
			KeyAlg:           "ECDSA-P384",
			ValidityDays:     1825,
			BasicConstraints: &cryptosv1.BasicConstraints{IsCa: true, PathLen: &pathLen0},
			KeyUsage:         []string{"cert_sign", "crl_sign"},
		},
	}

	profiles := make([]store.Profile, len(specs))
	for i, spec := range specs {
		raw, err := proto.Marshal(spec)
		if err != nil {
			panic("seed: marshal profile " + spec.GetName() + ": " + err.Error())
		}
		profiles[i] = store.Profile{Name: spec.GetName(), Spec: raw}
	}
	return profiles
}

func adaptersSeed() []store.Adapter {
	return []store.Adapter{
		{
			Kind:       "acme",
			Name:       "ACME (RFC 8555)",
			Endpoint:   "https://pki.acme.example/acme/directory",
			Profile:    "TLS Server (LDAPS)",
			Enabled:    true,
			Challenges: []string{"http-01", "dns-01"},
		},
		{
			Kind:        "ms-autoenroll",
			Name:        "Windows Autoenrollment (XCEP/WSTEP)",
			Endpoint:    "https://pki.acme.example/adpolicyprovider",
			Profile:     "Domain Controller",
			Enabled:     true,
			GPOTemplate: "DomainController",
		},
		{
			Kind:     "scep",
			Name:     "SCEP (RFC 8894)",
			Endpoint: "https://pki.acme.example/scep",
			Profile:  "TLS Client",
			Enabled:  false,
		},
		{
			Kind:     "est",
			Name:     "EST (RFC 7030)",
			Endpoint: "https://pki.acme.example/.well-known/est",
			Profile:  "TLS Client",
			Enabled:  false,
		},
	}
}

func auditSeed() []store.AuditEvent {
	return []store.AuditEvent{
		{
			ID:         "aud-0009",
			At:         "2026-06-30T00:00:00Z",
			Kind:       "revoked",
			Summary:    "Revoked svc-9.acme.example (keyCompromise)",
			TargetKind: "cert",
		},
		{
			ID:         "aud-0008",
			At:         "2026-06-29T00:00:00Z",
			Kind:       "enroll-approved",
			Summary:    "Approved enrollment acme-issuing-03 under ACME Intermediate CA G1",
			TargetKind: "node",
			TargetPath: "/nodes/acme-issuing-03",
		},
		{
			ID:         "aud-0007",
			At:         "2026-06-28T00:00:00Z",
			Kind:       "protocol-toggled",
			Summary:    "Enabled ACME (RFC 8555)",
			TargetKind: "protocol",
			TargetPath: "/protocols/acme",
		},
		{
			ID:         "aud-0006",
			At:         "2026-06-27T00:00:00Z",
			Kind:       "config-applied",
			Summary:    "Config applied to acme-issuing-01",
			TargetKind: "node",
			TargetPath: "/nodes/acme-issuing-01",
		},
		{
			ID:         "aud-0005",
			At:         "2026-06-26T00:00:00Z",
			Kind:       "rekeyed",
			Summary:    "Re-key ceremony completed for acme-root-01",
			TargetKind: "node",
			TargetPath: "/root/acme-root-01",
		},
		{
			ID:         "aud-0004",
			At:         "2026-06-25T00:00:00Z",
			Kind:       "renewed",
			Summary:    "Renewed ldap-a.acme.example",
			TargetKind: "cert",
		},
		{
			ID:         "aud-0003",
			At:         "2026-06-24T00:00:00Z",
			Kind:       "profile-updated",
			Summary:    "Updated profile Code Signing",
			TargetKind: "profile",
			TargetPath: "/profiles/Code Signing",
		},
		{
			ID:         "aud-0002",
			At:         "2026-06-23T00:00:00Z",
			Kind:       "enroll-rejected",
			Summary:    "Rejected enrollment acme-issuing-h03 (failed attestation)",
			TargetKind: "enrollment",
		},
		{
			ID:         "aud-0001",
			At:         "2026-06-22T00:00:00Z",
			Kind:       "profile-created",
			Summary:    "Created profile TLS Server (LDAPS)",
			TargetKind: "profile",
			TargetPath: "/profiles/TLS Server (LDAPS)",
		},
		{
			ID:         "aud-0000",
			At:         "2026-06-21T00:00:00Z",
			Kind:       "issued",
			Summary:    "Issued leaf svc-1.acme.example on acme-issuing-01",
			TargetKind: "cert",
		},
	}
}

func enrollmentsSeed() []store.Enrollment {
	return []store.Enrollment{
		{
			ID:                 "enr-0001",
			ProposedName:       "acme-issuing-04",
			Role:               "issuing",
			ParentCN:           "ACME Intermediate CA G1",
			Address:            "10.20.1.80:8443",
			Status:             "PENDING",
			AttestationSummary: "TPM . sealed",
			AttestationNodeID:  "nid-7f3a",
			CSRKeyType:         "ECDSA P-384",
			CSRSubjectCN:       "ACME Issuing CA G4",
			RequestedAt:        "2026-06-30T00:00:00Z",
		},
		{
			ID:                 "enr-0002",
			ProposedName:       "acme-intermediate-04",
			Role:               "intermediate",
			ParentCN:           "ACME Root CA R2",
			Address:            "10.20.10.80:8443",
			Status:             "PENDING",
			AttestationSummary: "TPM . sealed",
			AttestationNodeID:  "nid-2b9c",
			CSRKeyType:         "ECDSA P-384",
			CSRSubjectCN:       "ACME Intermediate CA R3",
			RequestedAt:        "2026-06-29T00:00:00Z",
		},
		{
			ID:                 "enr-0003",
			ProposedName:       "acme-issuing-h03",
			Role:               "issuing",
			ParentCN:           "ACME Intermediate CA G2",
			Address:            "10.20.2.80:8443",
			Status:             "PENDING",
			AttestationSummary: "UNAVAILABLE . nodeID",
			AttestationNodeID:  "nid-9d11",
			CSRKeyType:         "ECDSA P-256",
			CSRSubjectCN:       "ACME Issuing CA H3",
			RequestedAt:        "2026-06-28T00:00:00Z",
		},
	}
}
