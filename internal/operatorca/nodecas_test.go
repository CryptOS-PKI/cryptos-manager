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
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// The node CA certificates come from each inventory node's CA chain file.
// A node without one, or with an unreadable one, is skipped with a log line.
func TestNodeCAs_ReadsTheInventoryChains(t *testing.T) {
	root := newCA(t, caOpts{cn: "Example Fleet Root"})
	inter := newCA(t, caOpts{cn: "Example Fleet Intermediate", parent: &root})
	chain := writePEM(t, inter.cert, root.cert)
	logs := &logSink{}

	got := NodeCAs([]store.Node{
		{Name: "pki-inter", CACert: chain},
		{Name: "adopted"},
		{Name: "broken", CACert: filepath.Join(t.TempDir(), "missing.pem")},
	}, os.ReadFile, logs.Logf)
	want := map[string]bool{Fingerprint(inter.cert): true, Fingerprint(root.cert): true}
	if len(got) != 2 || !want[Fingerprint(got[0])] || !want[Fingerprint(got[1])] {
		t.Fatalf("NodeCAs = %v, want the intermediate and the root", subjects(got))
	}
	if logs.count("broken") == 0 {
		t.Fatal("the unreadable chain wasn't logged")
	}
}

func subjects(cs []*x509.Certificate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Subject.String())
	}
	return out
}
