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
	"testing"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

func TestScepApprovalProfilePicksTheFirstHeldProfile(t *testing.T) {
	sc := &nodev1.Scep{
		Enabled: true,
		Profiles: []*nodev1.ScepProfile{
			{Profile: "auto-issue"},
			{Profile: "held", RequireApproval: true},
			{Profile: "held-too", RequireApproval: true},
		},
		AllowedIdentifierSuffixes: []string{".devices.example.org", "example.net"},
	}
	profile, suffix, ok := scepApprovalProfile(sc)
	if !ok || profile != "held" || suffix != "devices.example.org" {
		t.Errorf("scepApprovalProfile = %q, %q, %v; want held, devices.example.org, true", profile, suffix, ok)
	}
}

func TestScepApprovalProfileNeedsApprovalAndASuffix(t *testing.T) {
	for name, sc := range map[string]*nodev1.Scep{
		"no scep block":      nil,
		"no held profile":    {Profiles: []*nodev1.ScepProfile{{Profile: "auto"}}, AllowedIdentifierSuffixes: []string{"example.org"}},
		"no suffix":          {Profiles: []*nodev1.ScepProfile{{Profile: "held", RequireApproval: true}}},
		"no profiles at all": {AllowedIdentifierSuffixes: []string{"example.org"}},
	} {
		if _, _, ok := scepApprovalProfile(sc); ok {
			t.Errorf("%s: scepApprovalProfile ok = true, want false", name)
		}
	}
}

func TestFindScepEnrollmentPrefersTheTransactionID(t *testing.T) {
	items := []*fleetv1.NodeScepEnrollment{
		{Id: "e1", TransactionId: "other", SubjectDn: "CN=dev-a.example.org"},
		{Id: "e2", TransactionId: "tx-b", SubjectDn: "CN=dev-b.example.org"},
	}
	if got := findScepEnrollment(items, "tx-b", "dev-a.example.org"); got != "e2" {
		t.Errorf("findScepEnrollment by transaction = %q, want e2", got)
	}
	if got := findScepEnrollment(items, "tx-unknown", "dev-a.example.org"); got != "e1" {
		t.Errorf("findScepEnrollment by subject = %q, want e1", got)
	}
	if got := findScepEnrollment(items, "tx-unknown", "dev-c.example.org"); got != "" {
		t.Errorf("findScepEnrollment for a device with no enrolment = %q, want empty", got)
	}
}

func TestAdapterNameOfKind(t *testing.T) {
	items := []*fleetv1.EnrollmentAdapter{
		{Kind: "acme", Name: "ACME (RFC 8555)"},
		{Kind: "scep", Name: "SCEP (RFC 8894)"},
	}
	if got := adapterNameOfKind(items, "scep"); got != "SCEP (RFC 8894)" {
		t.Errorf("adapterNameOfKind(scep) = %q", got)
	}
	if got := adapterNameOfKind(items, "est"); got != "" {
		t.Errorf("adapterNameOfKind(est) = %q, want empty", got)
	}
	if got := adapterNameOfKind(nil, "scep"); got != "" {
		t.Errorf("adapterNameOfKind on an empty catalog = %q, want empty", got)
	}
}
