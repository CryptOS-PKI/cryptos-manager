package memory

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

	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/CryptOS-PKI/manager/internal/store/storetest"
)

func TestStore_NodeIDs(t *testing.T) {
	storetest.NodeIDs(t, func(*testing.T) store.Store { return New(nil) })
}

func TestStore_NewWithCatalogMintsIDsAndHistory(t *testing.T) {
	s := New(testNodes())

	seen := map[string]bool{}
	for _, n := range s.Nodes() {
		if !store.IsNodeID(n.ID) {
			t.Fatalf("seeded node %s has ID %q, want a node ID", n.Name, n.ID)
		}
		if seen[n.ID] {
			t.Fatalf("seeded nodes share ID %s", n.ID)
		}
		seen[n.ID] = true
	}
	if hist := s.NodeNames(); len(hist) != len(testNodes()) {
		t.Fatalf("NodeNames() = %+v, want one span per seeded node", hist)
	}
}
