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
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

func fileSource(cas ...testCA) Source {
	src := Source{Kind: KindFile}
	for _, ca := range cas {
		src.File = append(src.File, Anchor{Cert: ca.cert, SHA256: Fingerprint(ca.cert), State: store.OperatorCAActive, FromConfig: true})
	}
	return src
}

// A trusted operator CA that a node's reported chain shows to be that node's
// CA is flagged with an ERROR and a banner, and stays trusted until the next
// start: dropping it mid-run could lock every admin out.
func TestNodeCAWatch_FlagsAnAnchorThatIsANodeCA(t *testing.T) {
	op := newCA(t, caOpts{cn: "Example Operator CA"})
	f := newTrustFixture(t, newFakeTrust(), fileSource(op))
	w := NewNodeCAWatch(f.trust, f.logs.Logf)

	other := newCA(t, caOpts{cn: "Example Workload CA"})
	w.Observe("ca-1", [][]byte{other.leaf(t, leafOpts{}).Raw, other.cert.Raw})
	if len(w.Flags()) != 0 {
		t.Fatalf("an unrelated chain raised a flag: %v", w.Flags())
	}

	leaf := op.leaf(t, leafOpts{})
	w.Observe("ca-1", [][]byte{leaf.Raw, op.cert.Raw})
	w.Observe("ca-1", [][]byte{leaf.Raw, op.cert.Raw})
	flags := w.Flags()
	banner, ok := flags[Fingerprint(op.cert)]
	if !ok || !strings.Contains(banner, "ca-1") {
		t.Fatalf("flags = %v; want a banner for the operator CA naming node ca-1", flags)
	}
	if n := f.logs.count("ERROR"); n != 1 {
		t.Fatalf("%d ERROR lines, want exactly one per anchor", n)
	}
	if got := f.trust.Anchors(); len(got) != 1 {
		t.Fatal("the anchor was dropped mid-run")
	}
}

// A node CA re-issued with the operator CA's key is the same CA.
func TestNodeCAWatch_MatchesBySubjectPublicKey(t *testing.T) {
	op := newCA(t, caOpts{cn: "Example Operator CA"})
	reissued := newCA(t, caOpts{cn: "Example Node CA", key: op.key})
	f := newTrustFixture(t, newFakeTrust(), fileSource(op))
	w := NewNodeCAWatch(f.trust, f.logs.Logf)
	w.Observe("ca-2", [][]byte{reissued.cert.Raw})
	if _, ok := w.Flags()[Fingerprint(op.cert)]; !ok {
		t.Fatal("a node CA with the operator CA's key wasn't flagged")
	}
}

func TestNodeCAWatch_IgnoresJunkAndNil(t *testing.T) {
	var nilWatch *NodeCAWatch
	nilWatch.Observe("ca-1", [][]byte{{1, 2, 3}})
	if nilWatch.Flags() != nil {
		t.Fatal("a nil watch has flags")
	}
	op := newCA(t, caOpts{cn: "Example Operator CA"})
	f := newTrustFixture(t, newFakeTrust(), fileSource(op))
	w := NewNodeCAWatch(f.trust, f.logs.Logf)
	w.Observe("ca-1", [][]byte{{1, 2, 3}, nil})
	if len(w.Flags()) != 0 {
		t.Fatal("an unparseable chain raised a flag")
	}
}
