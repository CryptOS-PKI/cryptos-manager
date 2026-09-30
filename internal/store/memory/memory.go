// Package memory implements store.Store as an in-process, read-mostly map
// keyed by node name.
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
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
)

// Store is an in-memory, concurrency-safe store.Store backed by a fixed
// snapshot of nodes and catalog data supplied at construction.
type Store struct {
	mu            sync.RWMutex
	nodes         map[string]store.Node
	nodeNames     []store.NodeName
	profiles      []store.Profile
	adapters      []store.Adapter
	audit         []store.AuditEvent
	enrollments   []store.Enrollment
	operatorCreds []store.OperatorCredential
	mcpKeys       map[string]store.McpKey
	oauthRequests map[string]store.OAuthRequest
	oauthCodes    map[string]store.OAuthCode
	approvals     map[string]store.Approval
}

// New builds a Store from the given nodes, keyed by Node.Name, with an
// empty catalog. Use NewWithCatalog to also seed profiles/adapters/audit/
// enrollments.
func New(nodes []store.Node) *Store {
	return NewWithCatalog(nodes, nil, nil, nil, nil)
}

// NewWithCatalog builds a Store from the given nodes, keyed by Node.Name,
// and the given catalog data. A node without an ID gets a fresh one, and every
// node starts its name history.
func NewWithCatalog(nodes []store.Node, profiles []store.Profile, adapters []store.Adapter, audit []store.AuditEvent, enrollments []store.Enrollment) *Store {
	m := make(map[string]store.Node, len(nodes))
	hist := make([]store.NodeName, 0, len(nodes))
	for _, n := range nodes {
		if n.ID == "" {
			n.ID = store.NewNodeID()
		}
		m[n.Name] = n
		hist = append(hist, store.NodeName{NodeID: n.ID, Name: n.Name})
	}

	return &Store{
		nodes:         m,
		nodeNames:     hist,
		profiles:      profiles,
		adapters:      adapters,
		audit:         audit,
		enrollments:   enrollments,
		mcpKeys:       map[string]store.McpKey{},
		oauthRequests: map[string]store.OAuthRequest{},
		oauthCodes:    map[string]store.OAuthCode{},
		approvals:     map[string]store.Approval{},
	}
}

// Nodes returns every node in the store.
func (s *Store) Nodes() []store.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}

	return out
}

// Node returns the node with the given name, and whether it was found.
func (s *Store) Node(name string) (store.Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n, ok := s.nodes[name]

	return n, ok
}

// NodeByID returns the node with the given stable ID, and whether it was
// found.
func (s *Store) NodeByID(id string) (store.Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.nodeByIDLocked(id)
}

func (s *Store) nodeByIDLocked(id string) (store.Node, bool) {
	for _, n := range s.nodes {
		if n.ID == id {
			return n, true
		}
	}

	return store.Node{}, false
}

// NodeByFormerName returns the node that most recently gave up name in a
// rename, and whether there is one.
func (s *Store) NodeByFormerName(name string) (store.Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var latest store.NodeName
	for _, h := range s.nodeNames {
		if h.Name == name && !h.Until.IsZero() && (latest.NodeID == "" || h.Until.After(latest.Until)) {
			latest = h
		}
	}
	if latest.NodeID == "" {
		return store.Node{}, false
	}

	return s.nodeByIDLocked(latest.NodeID)
}

// NodeNames returns every node's name history in the order it was recorded.
func (s *Store) NodeNames() []store.NodeName {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.NodeName, len(s.nodeNames))
	copy(out, s.nodeNames)

	return out
}

// AddNode inserts n into the inventory. A node with the same name keeps its ID
// and takes n's other fields; a new node keeps n.ID or gets a fresh one, and
// starts its name history.
func (s *Store) AddNode(n store.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.nodes[n.Name]; ok {
		n.ID = existing.ID
		s.nodes[n.Name] = n
		log.Printf("memory: node %s (%s) re-registered, keeping its id", n.Name, n.ID)
		return
	}
	if n.ID == "" {
		n.ID = store.NewNodeID()
	}
	s.nodes[n.Name] = n
	s.nodeNames = append(s.nodeNames, store.NodeName{NodeID: n.ID, Name: n.Name})
	log.Printf("memory: node %s joined the inventory with id %s", n.Name, n.ID)
}

// RenameNode changes the name of the node with the given ID and records the
// change in the name history.
func (s *Store) RenameNode(id, newName string, at time.Time) (store.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.nodeByIDLocked(id)
	if !ok {
		return store.Node{}, fmt.Errorf("memory: rename %s: %w", id, store.ErrNodeNotFound)
	}
	if n.Name == newName {
		return n, nil
	}
	if _, taken := s.nodes[newName]; taken {
		return store.Node{}, fmt.Errorf("memory: rename %s to %q: %w", id, newName, store.ErrNodeNameTaken)
	}

	oldName := n.Name
	delete(s.nodes, oldName)
	n.Name = newName
	s.nodes[newName] = n
	for i := range s.nodeNames {
		if s.nodeNames[i].NodeID == id && s.nodeNames[i].Until.IsZero() {
			s.nodeNames[i].Until = at
		}
	}
	s.nodeNames = append(s.nodeNames, store.NodeName{NodeID: id, Name: newName, From: at})
	log.Printf("memory: node %s renamed from %q to %q", id, oldName, newName)

	return n, nil
}

// Profiles returns every certificate issuance profile.
func (s *Store) Profiles() []store.Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.Profile, len(s.profiles))
	copy(out, s.profiles)

	return out
}

// Profile returns the profile with the given name, and whether it was found.
func (s *Store) Profile(name string) (store.Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, p := range s.profiles {
		if p.Name == name {
			return p, true
		}
	}

	return store.Profile{}, false
}

// CreateProfile appends p to the catalog. It returns an error if a profile
// with the same name already exists.
func (s *Store) CreateProfile(p store.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.profiles {
		if existing.Name == p.Name {
			return fmt.Errorf("memory: profile %q already exists", p.Name)
		}
	}
	s.profiles = append(s.profiles, p)

	return nil
}

// UpdateProfile replaces the profile named p.Name. It returns an error if no
// profile has that name.
func (s *Store) UpdateProfile(p store.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.profiles {
		if s.profiles[i].Name == p.Name {
			s.profiles[i] = p
			return nil
		}
	}

	return fmt.Errorf("memory: profile %q not found", p.Name)
}

// DeleteProfile removes the profile with the given name. It returns an error
// if no profile has that name.
func (s *Store) DeleteProfile(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.profiles {
		if s.profiles[i].Name == name {
			s.profiles = append(s.profiles[:i], s.profiles[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("memory: profile %q not found", name)
}

// Adapters returns every enrollment protocol adapter.
func (s *Store) Adapters() []store.Adapter {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.Adapter, len(s.adapters))
	copy(out, s.adapters)

	return out
}

// SetAdapterEnabled sets the enabled state of the adapter with the given name
// and returns the updated adapter. It returns an error if no adapter has that
// name.
func (s *Store) SetAdapterEnabled(name string, enabled bool) (store.Adapter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.adapters {
		if s.adapters[i].Name == name {
			s.adapters[i].Enabled = enabled
			return s.adapters[i], nil
		}
	}

	return store.Adapter{}, fmt.Errorf("memory: adapter %q not found", name)
}

// Audit returns every audit event.
func (s *Store) Audit() []store.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.AuditEvent, len(s.audit))
	copy(out, s.audit)

	return out
}

// AddAuditEvent appends e to the hash-chained audit log: PrevHash is the last
// event's Hash (empty for the first), Hash is computed over the chain, and the
// stored event is returned.
func (s *Store) AddAuditEvent(e store.AuditEvent) store.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	var prev string
	if n := len(s.audit); n > 0 {
		prev = s.audit[n-1].Hash
	}
	e.ChainVersion = store.AuditChainVersion
	e.PrevHash = prev
	e.Hash = store.HashEvent(prev, e)
	s.audit = append(s.audit, e)

	return e
}

// Enrollments returns every enrollment request.
func (s *Store) Enrollments() []store.Enrollment {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.Enrollment, len(s.enrollments))
	copy(out, s.enrollments)

	return out
}

// AddEnrollment appends a new enrollment request.
func (s *Store) AddEnrollment(e store.Enrollment) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.enrollments = append(s.enrollments, e)
}

// Enrollment returns the enrollment request with the given ID, and whether
// it was found.
func (s *Store) Enrollment(id string) (store.Enrollment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, e := range s.enrollments {
		if e.ID == id {
			return e, true
		}
	}

	return store.Enrollment{}, false
}

// UpdateEnrollment applies mutate to the enrollment with the given ID. It
// returns an error if no enrollment has that ID.
func (s *Store) UpdateEnrollment(id string, mutate func(*store.Enrollment)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.enrollments {
		if s.enrollments[i].ID == id {
			mutate(&s.enrollments[i])
			return nil
		}
	}

	return fmt.Errorf("memory: enrollment %q not found", id)
}

// OperatorCredentials returns every issued operator credential in insertion
// order.
func (s *Store) OperatorCredentials() []store.OperatorCredential {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.OperatorCredential, len(s.operatorCreds))
	copy(out, s.operatorCreds)

	return out
}

// AddOperatorCredential records a newly issued operator credential.
func (s *Store) AddOperatorCredential(c store.OperatorCredential) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.operatorCreds = append(s.operatorCreds, c)
}

// MarkOperatorCredentialRevoked flags the credential with the given hex serial
// as revoked. It returns an error if no credential has that serial.
func (s *Store) MarkOperatorCredentialRevoked(serialHex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.operatorCreds {
		if s.operatorCreds[i].SerialHex == serialHex {
			s.operatorCreds[i].Revoked = true
			return nil
		}
	}

	return fmt.Errorf("memory: operator credential %q not found", serialHex)
}

// AddMcpKey records a newly minted MCP key.
func (s *Store) AddMcpKey(k store.McpKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mcpKeys[k.ID] = k
}

// McpKeyByHash returns the key whose TokenHash is hash, and whether it was
// found.
func (s *Store) McpKeyByHash(hash string) (store.McpKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, k := range s.mcpKeys {
		if k.TokenHash == hash {
			return k, true
		}
	}

	return store.McpKey{}, false
}

// McpKey returns the key with the given ID, and whether it was found.
func (s *Store) McpKey(id string) (store.McpKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	k, ok := s.mcpKeys[id]

	return k, ok
}

// McpKeys returns every MCP key, newest first.
func (s *Store) McpKeys() []store.McpKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.McpKey, 0, len(s.mcpKeys))
	for _, k := range s.mcpKeys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})

	return out
}

// RevokeMcpKey stamps RevokedAt on the key with the given ID, keeping the
// first revocation time of an already revoked key.
func (s *Store) RevokeMcpKey(id string, at time.Time) (store.McpKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k, ok := s.mcpKeys[id]
	if !ok {
		return store.McpKey{}, fmt.Errorf("memory: mcp key %q not found", id)
	}
	if k.RevokedAt.IsZero() {
		k.RevokedAt = at
		s.mcpKeys[id] = k
	}

	return k, nil
}

// TouchMcpKey sets LastUsedAt on the key and reports whether it was the
// key's first use.
func (s *Store) TouchMcpKey(id string, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	k, ok := s.mcpKeys[id]
	if !ok {
		return false
	}
	first := k.LastUsedAt.IsZero()
	k.LastUsedAt = at
	s.mcpKeys[id] = k

	return first
}

// AddOAuthRequest records a pending authorization request and drops expired
// OAuth state.
func (s *Store) AddOAuthRequest(r store.OAuthRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, old := range s.oauthRequests {
		if old.ExpiresAt.Before(now) {
			delete(s.oauthRequests, id)
		}
	}
	for h, old := range s.oauthCodes {
		if old.ExpiresAt.Before(now) {
			delete(s.oauthCodes, h)
		}
	}
	s.oauthRequests[r.ID] = r
}

// OAuthRequest returns the pending request with the given ID.
func (s *Store) OAuthRequest(id string) (store.OAuthRequest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.oauthRequests[id]

	return r, ok
}

// TakeOAuthRequest removes and returns the pending request with the given ID.
func (s *Store) TakeOAuthRequest(id string) (store.OAuthRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.oauthRequests[id]
	delete(s.oauthRequests, id)

	return r, ok
}

// AddOAuthCode records an approved authorization code.
func (s *Store) AddOAuthCode(c store.OAuthCode) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.oauthCodes[c.CodeHash] = c
}

// TakeOAuthCode removes and returns the code with the given hash.
func (s *Store) TakeOAuthCode(hash string) (store.OAuthCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.oauthCodes[hash]
	delete(s.oauthCodes, hash)

	return c, ok
}

// AddApproval records a newly raised approval.
func (s *Store) AddApproval(a store.Approval) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.approvals[a.ID] = a
}

// Approval returns the approval with the given ID, and whether it was found.
func (s *Store) Approval(id string) (store.Approval, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, ok := s.approvals[id]

	return a, ok
}

// Approvals returns every approval, newest first.
func (s *Store) Approvals() []store.Approval {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]store.Approval, 0, len(s.approvals))
	for _, a := range s.approvals {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})

	return out
}

// DecideApproval records the decision on a pending, unexpired approval.
func (s *Store) DecideApproval(id, status, deciderCN, deciderSerial, deciderLevel string, at time.Time) (store.Approval, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.approvals[id]
	if !ok || a.Status != store.ApprovalPending || !at.Before(a.ExpiresAt) {
		return store.Approval{}, false
	}
	a.Status = status
	a.DecidedByCN = deciderCN
	a.DecidedBySerial = deciderSerial
	a.DecidedByLevel = deciderLevel
	a.DecidedAt = at
	s.approvals[id] = a

	return a, true
}

// UseApproval marks an approved, unexpired approval used.
func (s *Store) UseApproval(id string, at time.Time) (store.Approval, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.approvals[id]
	if !ok || a.Status != store.ApprovalApproved || !at.Before(a.ExpiresAt) {
		return store.Approval{}, false
	}
	a.Status = store.ApprovalUsed
	a.UsedAt = at
	s.approvals[id] = a

	return a, true
}
