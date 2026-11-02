package kv

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
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

var _ store.Store = (*Store)(nil)

// seqRow is a row that keeps insertion order, which a hash doesn't.
type seqRow[T any] struct {
	Seq int64
	Row T
}

func bySeq[T any](rows []seqRow[T]) []seqRow[T] {
	slices.SortFunc(rows, func(a, b seqRow[T]) int { return cmp.Compare(a.Seq, b.Seq) })
	return rows
}

func rowsOf[T any](rows []seqRow[T]) []T {
	out := make([]T, 0, len(rows))
	for _, r := range bySeq(rows) {
		out = append(out, r.Row)
	}
	return out
}

func newestFirst[T any](rows []T, at func(T) time.Time, id func(T) string) []T {
	slices.SortFunc(rows, func(a, b T) int {
		if c := at(b).Compare(at(a)); c != 0 {
			return c
		}
		return cmp.Compare(id(a), id(b))
	})
	return rows
}

// SeedIfEmpty stores the configured nodes the first time the store is used. A
// replica racing another start loses the race on a watched key and then finds
// the store isn't empty.
func (s *Store) SeedIfEmpty(ctx context.Context, nodes []store.Node) error {
	return s.update(ctx, func(x *txn) error {
		for _, h := range allHashes {
			n, err := x.t.HLen(ctx, s.key(h)).Result()
			if err != nil {
				return fmt.Errorf("kv: count %s: %w", h, err)
			}
			if n > 0 {
				log.Printf("kv: store already has %s, not seeding", h)
				return nil
			}
		}
		for _, n := range nodes {
			if n.ID == "" {
				n.ID = store.NewNodeID()
			}
			if err := x.put(keyNodes, n.ID, n); err != nil {
				return err
			}
			if err := x.addNodeName(store.NodeName{NodeID: n.ID, Name: n.Name}); err != nil {
				return err
			}
			log.Printf("kv: seeded node %s with id %s", n.Name, n.ID)
		}
		return nil
	}, allHashes...)
}

func (x *txn) addNodeName(h store.NodeName) error {
	seq, err := x.seq()
	if err != nil {
		return err
	}
	return x.put(keyNodeNames, fmt.Sprint(seq), seqRow[store.NodeName]{Seq: seq, Row: h})
}

// closeNodeName ends the node's current name span at at.
func (x *txn) closeNodeName(id string, at time.Time) error {
	rows, err := readAll[seqRow[store.NodeName]](x.ctx, x.t, x.s, keyNodeNames)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.Row.NodeID == id && r.Row.Until.IsZero() {
			r.Row.Until = at
			if err := x.put(keyNodeNames, fmt.Sprint(r.Seq), r); err != nil {
				return err
			}
		}
	}
	return nil
}

// Nodes returns every node, by name.
func (s *Store) Nodes() []store.Node {
	out := mustValue(readAll[store.Node](bg(), s.rdb, s, keyNodes))("read nodes")
	slices.SortFunc(out, func(a, b store.Node) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

func nodeNamed(nodes []store.Node, name string) (store.Node, bool) {
	for _, n := range nodes {
		if n.Name == name {
			return n, true
		}
	}
	return store.Node{}, false
}

// Node returns the node with the given name.
func (s *Store) Node(name string) (store.Node, bool) { return nodeNamed(s.Nodes(), name) }

// NodeByID returns the node with the given stable ID.
func (s *Store) NodeByID(id string) (store.Node, bool) {
	n, ok, err := readOne[store.Node](bg(), s.rdb, s, keyNodes, id)
	must(err, "read node")
	return n, ok
}

// NodeByFormerName returns the node that most recently gave up name.
func (s *Store) NodeByFormerName(name string) (store.Node, bool) {
	rows := mustValue(readAll[seqRow[store.NodeName]](bg(), s.rdb, s, keyNodeNames))("read node names")
	var latest *seqRow[store.NodeName]
	for i := range rows {
		r := &rows[i]
		if r.Row.Name != name || r.Row.Until.IsZero() {
			continue
		}
		if latest == nil || r.Row.Until.After(latest.Row.Until) ||
			(r.Row.Until.Equal(latest.Row.Until) && r.Seq > latest.Seq) {
			latest = r
		}
	}
	if latest == nil {
		return store.Node{}, false
	}
	return s.NodeByID(latest.Row.NodeID)
}

// NodeNames returns the name history in the order it was recorded.
func (s *Store) NodeNames() []store.NodeName {
	return rowsOf(mustValue(readAll[seqRow[store.NodeName]](bg(), s.rdb, s, keyNodeNames))("read node names"))
}

// AddNode inserts n. A node with the same name keeps its ID and takes n's
// other fields; a new node starts its name history.
func (s *Store) AddNode(n store.Node) {
	ctx := bg()
	err := s.update(ctx, func(x *txn) error {
		nodes, err := readAll[store.Node](ctx, x.t, s, keyNodes)
		if err != nil {
			return err
		}
		row := n
		if existing, ok := nodeNamed(nodes, n.Name); ok {
			row.ID = existing.ID
			log.Printf("kv: node %s (%s) re-registered, keeping its id", row.Name, row.ID)
			return x.put(keyNodes, row.ID, row)
		}
		if row.ID == "" {
			row.ID = store.NewNodeID()
		}
		log.Printf("kv: node %s joined the inventory with id %s", row.Name, row.ID)
		if err := x.put(keyNodes, row.ID, row); err != nil {
			return err
		}
		return x.addNodeName(store.NodeName{NodeID: row.ID, Name: row.Name})
	}, keyNodes, keyNodeNames)
	must(err, "add node")
}

// RemoveNode drops the node and closes its current name span.
func (s *Store) RemoveNode(id string, at time.Time) (store.Node, error) {
	ctx := bg()
	var n store.Node
	err := s.update(ctx, func(x *txn) error {
		var (
			ok  bool
			err error
		)
		if n, ok, err = readOne[store.Node](ctx, x.t, s, keyNodes, id); err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("kv: remove %s: %w", id, store.ErrNodeNotFound)
		}
		x.del(keyNodes, id)
		return x.closeNodeName(id, at)
	}, keyNodes, keyNodeNames)
	if err != nil {
		return store.Node{}, err
	}
	log.Printf("kv: node %s (%s) removed from the inventory", n.Name, id)
	return n, nil
}

// RenameNode changes the node's name and records the change in its history.
func (s *Store) RenameNode(id, newName string, at time.Time) (store.Node, error) {
	ctx := bg()
	var n store.Node
	err := s.update(ctx, func(x *txn) error {
		nodes, err := readAll[store.Node](ctx, x.t, s, keyNodes)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(nodes, func(c store.Node) bool { return c.ID == id })
		if i < 0 {
			return fmt.Errorf("kv: rename %s: %w", id, store.ErrNodeNotFound)
		}
		n = nodes[i]
		if n.Name == newName {
			return nil
		}
		if _, taken := nodeNamed(nodes, newName); taken {
			return fmt.Errorf("kv: rename %s to %q: %w", id, newName, store.ErrNodeNameTaken)
		}
		n.Name = newName
		if err := x.put(keyNodes, id, n); err != nil {
			return err
		}
		if err := x.closeNodeName(id, at); err != nil {
			return err
		}
		return x.addNodeName(store.NodeName{NodeID: id, Name: newName, From: at})
	}, keyNodes, keyNodeNames)
	if err != nil {
		return store.Node{}, err
	}
	return n, nil
}

// Profiles returns every profile, by name.
func (s *Store) Profiles() []store.Profile {
	out := mustValue(readAll[store.Profile](bg(), s.rdb, s, keyProfiles))("read profiles")
	slices.SortFunc(out, func(a, b store.Profile) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// Profile returns the profile with the given name.
func (s *Store) Profile(name string) (store.Profile, bool) {
	p, ok, err := readOne[store.Profile](bg(), s.rdb, s, keyProfiles, name)
	must(err, "read profile")
	return p, ok
}

// CreateProfile adds p, refusing a name already in use.
func (s *Store) CreateProfile(p store.Profile) error {
	ctx := bg()
	return s.update(ctx, func(x *txn) error {
		if _, ok, err := readOne[store.Profile](ctx, x.t, s, keyProfiles, p.Name); err != nil {
			return err
		} else if ok {
			return fmt.Errorf("kv: profile %q already exists", p.Name)
		}
		return x.put(keyProfiles, p.Name, p)
	}, keyProfiles)
}

// changeRow applies change to the row at field of hash name, returning the
// result, or notFound when there is no such row.
func changeRow[T any](s *Store, name, field string, notFound error, change func(*T) error) (T, error) {
	ctx := bg()
	var row T
	err := s.update(ctx, func(x *txn) error {
		var (
			ok  bool
			err error
		)
		if row, ok, err = readOne[T](ctx, x.t, s, name, field); err != nil {
			return err
		}
		if !ok {
			return notFound
		}
		if err := change(&row); err != nil {
			return err
		}
		return x.put(name, field, row)
	}, name)
	return row, err
}

// UpdateProfile replaces the profile named p.Name.
func (s *Store) UpdateProfile(p store.Profile) error {
	_, err := changeRow(s, keyProfiles, p.Name, fmt.Errorf("kv: profile %q not found", p.Name), func(r *store.Profile) error {
		*r = p
		return nil
	})
	return err
}

// DeleteProfile removes the profile with the given name.
func (s *Store) DeleteProfile(name string) error {
	ctx := bg()
	return s.update(ctx, func(x *txn) error {
		if _, ok, err := readOne[store.Profile](ctx, x.t, s, keyProfiles, name); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("kv: profile %q not found", name)
		}
		x.del(keyProfiles, name)
		return nil
	}, keyProfiles)
}

// SetProfileRequestable sets the profile's requestable flag.
func (s *Store) SetProfileRequestable(name string, requestable bool) (store.Profile, error) {
	return changeRow(s, keyProfiles, name, fmt.Errorf("kv: profile %q not found", name), func(r *store.Profile) error {
		r.Requestable = requestable
		return nil
	})
}

// Adapters returns every enrollment adapter, by name.
func (s *Store) Adapters() []store.Adapter {
	out := mustValue(readAll[store.Adapter](bg(), s.rdb, s, keyAdapters))("read adapters")
	slices.SortFunc(out, func(a, b store.Adapter) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// SetAdapterEnabled sets the adapter's enabled state.
func (s *Store) SetAdapterEnabled(name string, enabled bool) (store.Adapter, error) {
	return changeRow(s, keyAdapters, name, fmt.Errorf("kv: adapter %q not found", name), func(r *store.Adapter) error {
		r.Enabled = enabled
		return nil
	})
}

// Enrollments returns every enrollment request, oldest first.
func (s *Store) Enrollments() []store.Enrollment {
	out := mustValue(readAll[store.Enrollment](bg(), s.rdb, s, keyEnrollments))("read enrollments")
	slices.SortFunc(out, func(a, b store.Enrollment) int {
		if c := cmp.Compare(a.RequestedAt, b.RequestedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out
}

// AddEnrollment stores a new enrollment request.
func (s *Store) AddEnrollment(e store.Enrollment) {
	ctx := bg()
	must(s.update(ctx, func(x *txn) error { return x.put(keyEnrollments, e.ID, e) }), "add enrollment")
}

// Enrollment returns the enrollment request with the given ID.
func (s *Store) Enrollment(id string) (store.Enrollment, bool) {
	e, ok, err := readOne[store.Enrollment](bg(), s.rdb, s, keyEnrollments, id)
	must(err, "read enrollment")
	return e, ok
}

// UpdateEnrollment applies mutate to the enrollment with the given ID.
func (s *Store) UpdateEnrollment(id string, mutate func(*store.Enrollment)) error {
	_, err := changeRow(s, keyEnrollments, id, fmt.Errorf("kv: enrollment %q not found", id), func(r *store.Enrollment) error {
		mutate(r)
		return nil
	})
	return err
}

// credentialField keys a credential: serials are unique per issuer only.
func credentialField(issuer, serial string) string { return issuer + "|" + serial }

// OperatorCredentials returns every credential, oldest first.
func (s *Store) OperatorCredentials() []store.OperatorCredential {
	return rowsOf(mustValue(readAll[seqRow[store.OperatorCredential]](bg(), s.rdb, s, keyCredentials))("read operator credentials"))
}

// putNewCredential stores c as a new row.
func (x *txn) putNewCredential(c store.OperatorCredential) error {
	seq, err := x.seq()
	if err != nil {
		return err
	}
	return x.put(keyCredentials, credentialField(c.IssuerSHA256, c.SerialHex), seqRow[store.OperatorCredential]{Seq: seq, Row: c})
}

// AddOperatorCredential records a newly issued credential.
func (s *Store) AddOperatorCredential(c store.OperatorCredential) {
	ctx := bg()
	if c.Kind == "" {
		c.Kind = store.OperatorCredentialRecorded
	}
	must(s.update(ctx, func(x *txn) error { return x.putNewCredential(c) }), "add operator credential")
}

// MarkOperatorCredentialRevoked flags every credential with the serial.
func (s *Store) MarkOperatorCredentialRevoked(serialHex string) error {
	ctx := bg()
	return s.update(ctx, func(x *txn) error {
		rows, err := readAll[seqRow[store.OperatorCredential]](ctx, x.t, s, keyCredentials)
		if err != nil {
			return err
		}
		found := false
		for _, r := range rows {
			if r.Row.SerialHex != serialHex {
				continue
			}
			found = true
			r.Row.Revoked = true
			if err := x.put(keyCredentials, credentialField(r.Row.IssuerSHA256, serialHex), r); err != nil {
				return err
			}
		}
		if !found {
			return fmt.Errorf("kv: operator credential %q not found", serialHex)
		}
		return nil
	}, keyCredentials)
}

// AddMcpKey records a newly minted MCP key.
func (s *Store) AddMcpKey(k store.McpKey) {
	ctx := bg()
	must(s.update(ctx, func(x *txn) error { return x.put(keyMcpKeys, k.ID, k) }), "add mcp key")
}

// McpKeyByHash returns the key whose TokenHash is hash.
func (s *Store) McpKeyByHash(hash string) (store.McpKey, bool) {
	keys := mustValue(readAll[store.McpKey](bg(), s.rdb, s, keyMcpKeys))("read mcp keys")
	for _, k := range keys {
		if k.TokenHash == hash {
			return k, true
		}
	}
	return store.McpKey{}, false
}

// McpKey returns the key with the given ID.
func (s *Store) McpKey(id string) (store.McpKey, bool) {
	k, ok, err := readOne[store.McpKey](bg(), s.rdb, s, keyMcpKeys, id)
	must(err, "read mcp key")
	return k, ok
}

// McpKeys returns every MCP key, newest first.
func (s *Store) McpKeys() []store.McpKey {
	return newestFirst(mustValue(readAll[store.McpKey](bg(), s.rdb, s, keyMcpKeys))("read mcp keys"),
		func(k store.McpKey) time.Time { return k.CreatedAt }, func(k store.McpKey) string { return k.ID })
}

// RevokeMcpKey stamps RevokedAt, keeping the first revocation time.
func (s *Store) RevokeMcpKey(id string, at time.Time) (store.McpKey, error) {
	return changeRow(s, keyMcpKeys, id, fmt.Errorf("kv: mcp key %q not found", id), func(k *store.McpKey) error {
		if k.RevokedAt.IsZero() {
			k.RevokedAt = at
		}
		return nil
	})
}

// TouchMcpKey sets LastUsedAt and reports whether it was the key's first use.
func (s *Store) TouchMcpKey(id string, at time.Time) bool {
	first := false
	_, err := changeRow(s, keyMcpKeys, id, errRefused, func(k *store.McpKey) error {
		first = k.LastUsedAt.IsZero()
		k.LastUsedAt = at
		return nil
	})
	if errors.Is(err, errRefused) {
		return false
	}
	must(err, "touch mcp key")
	return first
}

// AddOAuthRequest records a pending request and drops expired OAuth state.
func (s *Store) AddOAuthRequest(r store.OAuthRequest) {
	ctx := bg()
	now := time.Now()
	err := s.update(ctx, func(x *txn) error {
		reqs, err := readAll[store.OAuthRequest](ctx, x.t, s, keyOAuthReqs)
		if err != nil {
			return err
		}
		for _, old := range reqs {
			if old.ExpiresAt.Before(now) {
				x.del(keyOAuthReqs, old.ID)
			}
		}
		codes, err := readAll[store.OAuthCode](ctx, x.t, s, keyOAuthCodes)
		if err != nil {
			return err
		}
		for _, old := range codes {
			if old.ExpiresAt.Before(now) {
				x.del(keyOAuthCodes, old.CodeHash)
			}
		}
		return x.put(keyOAuthReqs, r.ID, r)
	}, keyOAuthReqs, keyOAuthCodes)
	must(err, "add oauth request")
}

// OAuthRequest returns the pending request with the given ID.
func (s *Store) OAuthRequest(id string) (store.OAuthRequest, bool) {
	r, ok, err := readOne[store.OAuthRequest](bg(), s.rdb, s, keyOAuthReqs, id)
	must(err, "read oauth request")
	return r, ok
}

// takeRow removes and returns a row, so of two callers only one gets it.
func takeRow[T any](s *Store, name, field string) (T, bool) {
	ctx := bg()
	var (
		row T
		ok  bool
	)
	err := s.update(ctx, func(x *txn) error {
		var err error
		if row, ok, err = readOne[T](ctx, x.t, s, name, field); err != nil || !ok {
			return err
		}
		x.del(name, field)
		return nil
	}, name)
	must(err, "take "+name)
	return row, ok
}

// TakeOAuthRequest removes and returns the pending request.
func (s *Store) TakeOAuthRequest(id string) (store.OAuthRequest, bool) {
	return takeRow[store.OAuthRequest](s, keyOAuthReqs, id)
}

// AddOAuthCode records an approved authorization code.
func (s *Store) AddOAuthCode(c store.OAuthCode) {
	ctx := bg()
	must(s.update(ctx, func(x *txn) error { return x.put(keyOAuthCodes, c.CodeHash, c) }), "add oauth code")
}

// TakeOAuthCode removes and returns the code with the given hash.
func (s *Store) TakeOAuthCode(hash string) (store.OAuthCode, bool) {
	return takeRow[store.OAuthCode](s, keyOAuthCodes, hash)
}

// AddApproval records a newly raised approval.
func (s *Store) AddApproval(a store.Approval) {
	ctx := bg()
	must(s.update(ctx, func(x *txn) error { return x.put(keyApprovals, a.ID, a) }), "add approval")
}

// Approval returns the approval with the given ID.
func (s *Store) Approval(id string) (store.Approval, bool) {
	a, ok, err := readOne[store.Approval](bg(), s.rdb, s, keyApprovals, id)
	must(err, "read approval")
	return a, ok
}

// Approvals returns every approval, newest first.
func (s *Store) Approvals() []store.Approval {
	return newestFirst(mustValue(readAll[store.Approval](bg(), s.rdb, s, keyApprovals))("read approvals"),
		func(a store.Approval) time.Time { return a.CreatedAt }, func(a store.Approval) string { return a.ID })
}

// errRefused stops changeRow without writing, for a conditional change whose
// condition didn't hold.
var errRefused = errors.New("kv: condition not met")

// changeApproval applies change to the approval if it allows it.
func (s *Store) changeApproval(id string, change func(*store.Approval) error) (store.Approval, bool) {
	a, err := changeRow(s, keyApprovals, id, errRefused, change)
	if errors.Is(err, errRefused) {
		return store.Approval{}, false
	}
	must(err, "change approval")
	return a, true
}

// DecideApproval records the decision on a pending, unexpired approval.
func (s *Store) DecideApproval(id, status, deciderCN, deciderSerial, deciderLevel string, at time.Time) (store.Approval, bool) {
	return s.changeApproval(id, func(a *store.Approval) error {
		if a.Status != store.ApprovalPending || !at.Before(a.ExpiresAt) {
			return errRefused
		}
		a.Status, a.DecidedByCN, a.DecidedBySerial, a.DecidedByLevel, a.DecidedAt = status, deciderCN, deciderSerial, deciderLevel, at
		return nil
	})
}

// UseApproval marks an approved, unexpired approval used.
func (s *Store) UseApproval(id string, at time.Time) (store.Approval, bool) {
	return s.changeApproval(id, func(a *store.Approval) error {
		if a.Status != store.ApprovalApproved || !at.Before(a.ExpiresAt) {
			return errRefused
		}
		a.Status, a.UsedAt = store.ApprovalUsed, at
		return nil
	})
}

// AddCertificateRequest records a newly filed certificate request.
func (s *Store) AddCertificateRequest(r store.CertificateRequest) {
	ctx := bg()
	must(s.update(ctx, func(x *txn) error { return x.put(keyCertRequests, r.ID, r) }), "add certificate request")
}

// withDerivedExpiry reports a pending request past its expiry as expired,
// without writing that state.
func withDerivedExpiry(r store.CertificateRequest, now time.Time) store.CertificateRequest {
	if r.State == store.CertRequestPending && !now.Before(r.ExpiresAt) {
		r.State = store.CertRequestExpired
	}
	return r
}

// CertificateRequest returns the request with the given ID.
func (s *Store) CertificateRequest(id string, now time.Time) (store.CertificateRequest, bool) {
	r, ok, err := readOne[store.CertificateRequest](bg(), s.rdb, s, keyCertRequests, id)
	must(err, "read certificate request")
	if !ok {
		return store.CertificateRequest{}, false
	}
	return withDerivedExpiry(r, now), true
}

// CertificateRequests returns every certificate request, newest first.
func (s *Store) CertificateRequests(now time.Time) []store.CertificateRequest {
	rows := mustValue(readAll[store.CertificateRequest](bg(), s.rdb, s, keyCertRequests))("read certificate requests")
	for i := range rows {
		rows[i] = withDerivedExpiry(rows[i], now)
	}
	return newestFirst(rows, func(r store.CertificateRequest) time.Time { return r.CreatedAt },
		func(r store.CertificateRequest) string { return r.ID })
}

// UpdateCertificateRequest applies mutate to the request with the given ID.
func (s *Store) UpdateCertificateRequest(id string, mutate func(*store.CertificateRequest)) error {
	_, err := changeRow(s, keyCertRequests, id, fmt.Errorf("kv: certificate request %q not found", id), func(r *store.CertificateRequest) error {
		mutate(r)
		return nil
	})
	return err
}
