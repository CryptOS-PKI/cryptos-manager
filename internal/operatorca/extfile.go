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
	"fmt"
	"strings"

	"github.com/CryptOS-PKI/manager/internal/authz"
)

// opCommonLines are the profile lines every op_<level> section carries: the
// operator certificate profile an external OpenSSL CA applies.
const opCommonLines = "basicConstraints       = critical, CA:FALSE\n" +
	"keyUsage               = critical, digitalSignature\n" +
	"extendedKeyUsage       = clientAuth\n" +
	"subjectKeyIdentifier   = hash\n" +
	"authorityKeyIdentifier = keyid\n"

// ExtfileSection returns the OpenSSL config section, op_<level>, that an
// external CA signs an operator credential with. The level extension's DER
// comes from authz.MarshalLevelExtension, the encoding the manager reads.
func ExtfileSection(level string) (string, error) {
	oid, der, err := authz.MarshalLevelExtension(level)
	if err != nil {
		return "", fmt.Errorf("operatorca: extension section: %w", err)
	}
	octets := make([]string, len(der))
	for i, b := range der {
		octets[i] = fmt.Sprintf("%02X", b)
	}
	return fmt.Sprintf("[ op_%s ]\n%s%s  = DER:%s\n", level, opCommonLines, oid, strings.Join(octets, ":")), nil
}

// SignCommand returns the openssl ca command that signs a credential
// request's CSR with the level's section. The file names are built from the
// email with anything a shell could read as syntax replaced by "_".
func SignCommand(level, email string) string {
	base := "fleetos-" + level + "-" + strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == '@':
			return r
		default:
			return '_'
		}
	}, email)
	return fmt.Sprintf("openssl ca -config operator-ca.cnf -extensions op_%s -notext -in %s.csr -out %s.crt", level, base, base)
}
