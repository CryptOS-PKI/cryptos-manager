// Package storetest holds behaviour checks every store.Store implementation
// must pass, so the in-memory and Postgres stores cannot drift apart.
package storetest

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
	"errors"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/google/uuid"
)

// NodeIDs runs the node ID and rename checks against stores built by
// newStore. newStore must return an empty store each time it is called.
func NodeIDs(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Run("AddNodeMintsAUUIDv7", func(t *testing.T) {
		st := newStore(t)
		st.AddNode(store.Node{Name: "a", Endpoint: "a:443", Role: "root"})

		n, ok := st.Node("a")
		if !ok {
			t.Fatal("Node(a) not found after AddNode")
		}
		requireUUIDv7(t, n.ID)
		if got, ok := st.NodeByID(n.ID); !ok || got.Name != "a" || got.Endpoint != "a:443" {
			t.Fatalf("NodeByID(%s) = %+v, %v; want node a", n.ID, got, ok)
		}
	})

	t.Run("AddNodeKeepsAGivenID", func(t *testing.T) {
		st := newStore(t)
		id := store.NewNodeID()
		st.AddNode(store.Node{ID: id, Name: "a", Endpoint: "a:443", Role: "root"})

		if n, _ := st.Node("a"); n.ID != id {
			t.Fatalf("Node(a).ID = %q, want %q", n.ID, id)
		}
	})

	t.Run("ReAddingANameKeepsItsID", func(t *testing.T) {
		st := newStore(t)
		st.AddNode(store.Node{Name: "a", Endpoint: "a:443", Role: "root"})
		first, _ := st.Node("a")

		st.AddNode(store.Node{ID: store.NewNodeID(), Name: "a", Endpoint: "a:8443", Role: "root"})
		second, _ := st.Node("a")
		if second.ID != first.ID {
			t.Fatalf("re-added node ID = %q, want the original %q", second.ID, first.ID)
		}
		if second.Endpoint != "a:8443" {
			t.Fatalf("re-added node endpoint = %q, want the new a:8443", second.Endpoint)
		}
		if len(st.Nodes()) != 1 {
			t.Fatalf("Nodes() = %d nodes, want 1", len(st.Nodes()))
		}
	})

	t.Run("NodeByIDUnknown", func(t *testing.T) {
		st := newStore(t)
		if _, ok := st.NodeByID(store.NewNodeID()); ok {
			t.Fatal("NodeByID(unknown) found a node")
		}
	})

	t.Run("NewNodeStartsItsNameHistory", func(t *testing.T) {
		st := newStore(t)
		st.AddNode(store.Node{Name: "a", Endpoint: "a:443", Role: "root"})
		n, _ := st.Node("a")

		hist := st.NodeNames()
		if len(hist) != 1 {
			t.Fatalf("NodeNames() = %+v, want one span", hist)
		}
		h := hist[0]
		if h.NodeID != n.ID || h.Name != "a" || !h.From.IsZero() || !h.Until.IsZero() {
			t.Fatalf("NodeNames()[0] = %+v, want {%s a open open}", h, n.ID)
		}
	})

	t.Run("RenameKeepsTheIDAndRecordsHistory", func(t *testing.T) {
		st := newStore(t)
		st.AddNode(store.Node{Name: "a", Endpoint: "a:443", Role: "root"})
		n, _ := st.Node("a")
		at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

		got, err := st.RenameNode(n.ID, "b", at)
		if err != nil {
			t.Fatalf("RenameNode: %v", err)
		}
		if got.ID != n.ID || got.Name != "b" || got.Endpoint != "a:443" {
			t.Fatalf("RenameNode returned %+v, want node %s named b", got, n.ID)
		}
		if _, ok := st.Node("a"); ok {
			t.Fatal("Node(a) still found after the rename")
		}
		if cur, ok := st.Node("b"); !ok || cur.ID != n.ID {
			t.Fatalf("Node(b) = %+v, %v; want node %s", cur, ok, n.ID)
		}
		if byID, _ := st.NodeByID(n.ID); byID.Name != "b" {
			t.Fatalf("NodeByID name = %q, want b", byID.Name)
		}
		if old, ok := st.NodeByFormerName("a"); !ok || old.ID != n.ID || old.Name != "b" {
			t.Fatalf("NodeByFormerName(a) = %+v, %v; want node %s now named b", old, ok, n.ID)
		}

		hist := st.NodeNames()
		if len(hist) != 2 {
			t.Fatalf("NodeNames() = %+v, want two spans", hist)
		}
		if hist[0].Name != "a" || !hist[0].From.IsZero() || !hist[0].Until.Equal(at) {
			t.Errorf("first span = %+v, want a from the start until %s", hist[0], at)
		}
		if hist[1].Name != "b" || !hist[1].From.Equal(at) || !hist[1].Until.IsZero() {
			t.Errorf("second span = %+v, want b from %s, open", hist[1], at)
		}
	})

	t.Run("RenameToTheSameNameIsANoOp", func(t *testing.T) {
		st := newStore(t)
		st.AddNode(store.Node{Name: "a", Endpoint: "a:443", Role: "root"})
		n, _ := st.Node("a")

		got, err := st.RenameNode(n.ID, "a", time.Now())
		if err != nil {
			t.Fatalf("RenameNode(same name): %v", err)
		}
		if got.ID != n.ID || got.Name != "a" {
			t.Fatalf("RenameNode(same name) = %+v, want the node unchanged", got)
		}
		if hist := st.NodeNames(); len(hist) != 1 {
			t.Fatalf("NodeNames() = %+v, want the single original span", hist)
		}
	})

	t.Run("RenameUnknownID", func(t *testing.T) {
		st := newStore(t)
		_, err := st.RenameNode(store.NewNodeID(), "b", time.Now())
		if !errors.Is(err, store.ErrNodeNotFound) {
			t.Fatalf("RenameNode(unknown) error = %v, want ErrNodeNotFound", err)
		}
	})

	t.Run("RenameToATakenName", func(t *testing.T) {
		st := newStore(t)
		st.AddNode(store.Node{Name: "a", Endpoint: "a:443", Role: "root"})
		st.AddNode(store.Node{Name: "b", Endpoint: "b:443", Role: "issuing"})
		a, _ := st.Node("a")

		_, err := st.RenameNode(a.ID, "b", time.Now())
		if !errors.Is(err, store.ErrNodeNameTaken) {
			t.Fatalf("RenameNode(taken) error = %v, want ErrNodeNameTaken", err)
		}
		if cur, _ := st.NodeByID(a.ID); cur.Name != "a" {
			t.Fatalf("refused rename changed the name to %q", cur.Name)
		}
		if hist := st.NodeNames(); len(hist) != 2 {
			t.Fatalf("refused rename wrote history: %+v", hist)
		}
	})

	t.Run("AFormerNameCanBeReused", func(t *testing.T) {
		st := newStore(t)
		st.AddNode(store.Node{Name: "a", Endpoint: "a:443", Role: "root"})
		first, _ := st.Node("a")
		if _, err := st.RenameNode(first.ID, "b", time.Now()); err != nil {
			t.Fatalf("RenameNode: %v", err)
		}

		st.AddNode(store.Node{Name: "a", Endpoint: "new:443", Role: "issuing"})
		second, _ := st.Node("a")
		if second.ID == first.ID {
			t.Fatal("a new node taking a former name got the old node's ID")
		}
		if old, ok := st.NodeByFormerName("a"); !ok || old.ID != first.ID {
			t.Fatalf("NodeByFormerName(a) = %+v, %v; want the renamed node %s", old, ok, first.ID)
		}
	})

	t.Run("LatestFormerHolderWins", func(t *testing.T) {
		st := newStore(t)
		st.AddNode(store.Node{Name: "a", Endpoint: "a:443", Role: "root"})
		st.AddNode(store.Node{Name: "x", Endpoint: "x:443", Role: "issuing"})
		one, _ := st.Node("a")
		two, _ := st.Node("x")
		t0 := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

		mustRename(t, st, one.ID, "b", t0)
		mustRename(t, st, two.ID, "a", t0.Add(time.Minute))
		mustRename(t, st, two.ID, "c", t0.Add(2*time.Minute))

		if old, ok := st.NodeByFormerName("a"); !ok || old.ID != two.ID {
			t.Fatalf("NodeByFormerName(a) = %+v, %v; want the latest holder %s", old, ok, two.ID)
		}
	})

	t.Run("NodeByFormerNameUnknown", func(t *testing.T) {
		st := newStore(t)
		st.AddNode(store.Node{Name: "a", Endpoint: "a:443", Role: "root"})
		if _, ok := st.NodeByFormerName("a"); ok {
			t.Fatal("NodeByFormerName found a node for a name that was never given up")
		}
	})

	t.Run("EnrollmentKeepsAdmittedNodeID", func(t *testing.T) {
		st := newStore(t)
		id := store.NewNodeID()
		st.AddEnrollment(store.Enrollment{ID: "enr-1", Kind: "LINK", Status: "PENDING", ProposedName: "a", RequestedAt: "t0"})
		if err := st.UpdateEnrollment("enr-1", func(e *store.Enrollment) {
			e.Status = "APPROVED"
			e.AdmittedNodeName = "a"
			e.AdmittedNodeID = id
		}); err != nil {
			t.Fatalf("UpdateEnrollment: %v", err)
		}
		if got, _ := st.Enrollment("enr-1"); got.AdmittedNodeID != id {
			t.Fatalf("AdmittedNodeID = %q, want %q", got.AdmittedNodeID, id)
		}
	})
}

func mustRename(t *testing.T, st store.Store, id, name string, at time.Time) {
	t.Helper()
	if _, err := st.RenameNode(id, name, at); err != nil {
		t.Fatalf("RenameNode(%s, %s): %v", id, name, err)
	}
}

func requireUUIDv7(t *testing.T, id string) {
	t.Helper()
	u, err := uuid.Parse(id)
	if err != nil {
		t.Fatalf("node ID %q is not a UUID: %v", id, err)
	}
	if u.Version() != 7 {
		t.Fatalf("node ID %q is UUID version %d, want 7", id, u.Version())
	}
	if u.String() != id {
		t.Fatalf("node ID %q is not in canonical lowercase form", id)
	}
}
