package operatorca

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
	"encoding/hex"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
)

// The extension section a credential request hands the CA operator is the
// op_<level> section of the documented OpenSSL config, with the level DER
// taken from the one encoding the middleware reads.
func TestExtfileSection(t *testing.T) {
	for _, level := range []string{"viewer", "operator", "admin"} {
		got, err := ExtfileSection(level)
		if err != nil {
			t.Fatalf("ExtfileSection(%s): %v", level, err)
		}
		_, der, _ := authz.MarshalLevelExtension(level)
		pairs := strings.Split(strings.ToUpper(hex.EncodeToString(der)), "")
		var octets []string
		for i := 0; i < len(pairs); i += 2 {
			octets = append(octets, pairs[i]+pairs[i+1])
		}
		want := "[ op_" + level + " ]\n" +
			"basicConstraints       = critical, CA:FALSE\n" +
			"keyUsage               = critical, digitalSignature\n" +
			"extendedKeyUsage       = clientAuth\n" +
			"subjectKeyIdentifier   = hash\n" +
			"authorityKeyIdentifier = keyid\n" +
			"1.3.6.1.4.1.59999.1.1  = DER:" + strings.Join(octets, ":") + "\n"
		if got != want {
			t.Errorf("ExtfileSection(%s) =\n%s\nwant\n%s", level, got, want)
		}
	}
	if got, _ := ExtfileSection("admin"); !strings.Contains(got, "DER:13:05:61:64:6D:69:6E") {
		t.Errorf("admin section doesn't carry the documented DER: %s", got)
	}
	if _, err := ExtfileSection("root"); err == nil {
		t.Error("ExtfileSection(root) = nil error, want a refusal")
	}
}

// The signing command names the level's section and file names that are
// safe to paste into a shell whatever the email holds.
func TestSignCommand(t *testing.T) {
	got := SignCommand("operator", "o'brien+ops@example.org")
	want := "openssl ca -config operator-ca.cnf -extensions op_operator -notext " +
		"-in fleetos-operator-o_brien_ops@example.org.csr -out fleetos-operator-o_brien_ops@example.org.crt"
	if got != want {
		t.Fatalf("SignCommand = %q, want %q", got, want)
	}
}
