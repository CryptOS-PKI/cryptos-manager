// Package store defines the manager's view of the fleet inventory.
package store

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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Node is one fleet member as seen by the store: its stable ID, its display
// name, its dial address, role, and the file paths for its admin mTLS client
// cert/key and pinned CA.
type Node struct {
	// ID is the node's stable identifier, a UUIDv7 in canonical lowercase
	// form. It is assigned when the node joins the inventory and never
	// changes or gets reused; Name is the editable display label.
	ID        string
	Name      string
	Endpoint  string
	Role      string
	AdminCert string
	AdminKey  string
	CACert    string
}

// NodeName is one span of a node's name history: the node held Name from
// From until Until. A zero From means the name the node joined with; a zero
// Until means the name is current.
type NodeName struct {
	NodeID string
	Name   string
	From   time.Time
	Until  time.Time
}

// ErrNodeNotFound is returned when no node has the requested ID.
var ErrNodeNotFound = errors.New("store: node not found")

// ErrNodeNameTaken is returned when a rename targets a name another node
// already has.
var ErrNodeNameTaken = errors.New("store: node name already in use")

// NewNodeID mints a node ID: a UUIDv7 (RFC 9562) in canonical lowercase form.
func NewNodeID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// NewV7 fails only when the system random source does, which leaves
		// the process unable to do anything safely.
		panic(fmt.Sprintf("store: mint node id: %v", err))
	}
	return id.String()
}

// IsNodeID reports whether s is a node ID in canonical form: a lowercase,
// hyphenated UUID. Anything else, such as a node name, is not.
func IsNodeID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s
}

// Profile is a catalog certificate-issuance template, stored as the marshaled
// cryptos.node.v1.CertificateProfile so it is a lossless superset the node accepts
// verbatim. Name is the catalog identity key; Spec is the marshaled proto.
type Profile struct {
	Name string
	Spec []byte // marshaled cryptos.node.v1.CertificateProfile
	// Requestable allows a signed-in user to request a certificate under
	// this profile via CreateCertificateRequest. Off by default.
	Requestable bool
}

// Adapter is an enrollment protocol adapter's configuration: which protocol
// it speaks, where it listens, and which Profile it issues against. It
// mirrors cryptos.fleet.v1.EnrollmentAdapter.
type Adapter struct {
	Kind        string
	Name        string
	Endpoint    string
	Profile     string
	Enabled     bool
	Challenges  []string
	GPOTemplate string
}

// AuditEvent is one manager-observed audit record. It mirrors
// cryptos.fleet.v1.AuditEvent. PrevHash and Hash back a tamper-evident hash
// chain over the append-ordered log (see HashEvent).
type AuditEvent struct {
	ID         string
	At         string
	Kind       string
	Summary    string
	TargetKind string
	TargetPath string

	// Actor fields: who acted and through which surface. ActorKind is
	// "cert" or "mcp_key"; Via is "web", "mcp" or "api"; Outcome is "ok",
	// "denied", "pending" or "error". ApprovalID and ApproverSerial are
	// reserved for step-up approval.
	ActorKind      string
	ActorCN        string
	ActorSerial    string
	KeyID          string
	Via            string
	Tool           string
	RequestDigest  string
	Outcome        string
	ApprovalID     string
	ApproverSerial string

	// ChainVersion selects the HashEvent formula the row was hashed with.
	// Rows written before actors were recorded carry 0 or 1.
	ChainVersion int

	PrevHash string
	Hash     string
}

// AuditChainVersion is the HashEvent formula every new audit row is hashed
// with. Version 2 added the actor fields to the hash.
const AuditChainVersion = 2

// McpKey is one MCP agent key. Only the SHA-256 of the key is stored; the
// plaintext is shown once at mint. The key is bound to the operator
// certificate serial it was minted under, and that certificate is kept so
// every request can re-validate it. A zero time means the timestamp is unset.
type McpKey struct {
	ID              string
	TokenHash       string
	Label           string
	ClientName      string
	OperatorSerial  string
	OperatorCN      string
	OperatorCertDER []byte
	LevelCeiling    string
	CreatedAt       time.Time
	LastUsedAt      time.Time
	RevokedAt       time.Time
	ExpiresAt       time.Time
}

// OAuthRequest is an authorization request waiting for the operator's
// consent in the browser. It lives until ExpiresAt or until consent is given
// or refused, whichever comes first.
type OAuthRequest struct {
	ID            string
	ClientID      string
	ClientName    string
	RedirectURI   string
	State         string
	CodeChallenge string
	ExpiresAt     time.Time
}

// OAuthCode is an approved, not yet redeemed authorization code. It carries
// the identity captured at consent, so the token endpoint can mint the key
// without seeing the operator certificate itself. Only the code's SHA-256 is
// stored.
type OAuthCode struct {
	CodeHash        string
	ClientID        string
	ClientName      string
	RedirectURI     string
	CodeChallenge   string
	OperatorCN      string
	OperatorSerial  string
	OperatorCertDER []byte
	LevelCeiling    string
	Label           string
	ExpiresAt       time.Time
}

// Stored approval statuses. An approval is also reported as expired once its
// ExpiresAt passes while it is pending or approved; that status is derived on
// read and never stored.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
	ApprovalExpired  = "expired"
	ApprovalUsed     = "used"
)

// Approval kinds. ApprovalKindStepUp (and the empty string, for rows written
// before this field existed) is a step-up request raised by an MCP tool
// call. ApprovalKindCertificateRequest gates a CreateCertificateRequest and
// refuses the requester deciding their own.
const (
	ApprovalKindStepUp             = "step_up"
	ApprovalKindCertificateRequest = "certificate_request"
)

// Approval is a step-up request raised by an MCP tool call, or a person's
// certificate request, that needs a decision before it proceeds. It covers
// exactly one request (the tool and the digest of its arguments, or a
// certificate request ID), made by one key or requester, and is used at most
// once before ExpiresAt. DecidedByLevel is the decider's level at decision
// time, kept so the call can re-check it when the approval is used. A zero
// time means the timestamp is unset.
type Approval struct {
	ID                string
	Tool              string
	Summary           string
	RequestDigest     string
	RequestedByCN     string
	RequestedBySerial string
	KeyID             string
	RequiredLevel     string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	Status            string
	DecidedByCN       string
	DecidedBySerial   string
	DecidedByLevel    string
	DecidedAt         time.Time
	UsedAt            time.Time
	// Kind is ApprovalKindStepUp or ApprovalKindCertificateRequest. Empty is
	// treated as ApprovalKindStepUp.
	Kind string
}

// Enrollment is a node's request to join the fleet under a parent CA,
// pending admin approval. It mirrors cryptos.fleet.v1.EnrollmentRequest.
type Enrollment struct {
	ID                 string
	ProposedName       string
	Role               string
	ParentCN           string
	Address            string
	Status             string
	AttestationSummary string
	AttestationNodeID  string
	CSRKeyType         string
	CSRSubjectCN       string
	RequestedAt        string
	RejectionReason    string
	AdmittedNodeName   string
	AdmittedNodeID     string // stable ID of the admitted node; empty until approved
	Kind               string // LINK|SUBORDINATE
	PinnedKeySHA256    string // TOFU-pinned node identity (SPKI SHA-256 hex)
	AttestationOK      bool
	Profile            string // SUBORDINATE: issuing profile name (store-internal; no proto field)
}

// OperatorCredential is one operator client certificate the manager knows. It
// is the durable record backing the Operators admin surface: the manager never
// holds the operator's private key, only this metadata. It mirrors
// cryptos.fleet.v1.OperatorCredential.
type OperatorCredential struct {
	CommonName string
	SerialHex  string
	Level      string
	NotAfter   string
	Revoked    bool

	// IssuerSHA256 is the fingerprint of the operator CA that signed the
	// credential, empty for a legacy_node row.
	IssuerSHA256 string
	// Kind is how the manager learned of the credential, one of the
	// OperatorCredential* kinds.
	Kind       string
	Email      string
	FullName   string
	LeafSHA256 string
	// RequestID is the credential request the certificate answered, empty
	// when there was none.
	RequestID string
	// FirstSeenAt and LastSeenAt are when the manager first and last saw the
	// credential authenticate; zero when it never has. LastSeenAt is updated
	// at most hourly.
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

// Store is the manager's read access to the fleet inventory and its
// manager-owned catalog data (profiles, adapters, audit, enrollments,
// operator credentials).
type Store interface {
	// Nodes returns every node in the inventory.
	Nodes() []Node
	// Node returns the node with the given name, and whether it was found.
	Node(name string) (Node, bool)
	// NodeByID returns the node with the given stable ID, and whether it was
	// found.
	NodeByID(id string) (Node, bool)
	// NodeByFormerName returns the node that most recently gave up the given
	// name in a rename, and whether there is one. Callers look up the current
	// name with Node first.
	NodeByFormerName(name string) (Node, bool)
	// NodeNames returns every node's name history, oldest span first per
	// node.
	NodeNames() []NodeName
	// AddNode inserts n into the inventory, replacing the fields of any node
	// with the same name while keeping that node's ID. A new node keeps n.ID,
	// or gets a fresh NewNodeID when n.ID is empty, and starts its name
	// history. It is how an adopted node joins the fleet.
	AddNode(n Node)
	// RenameNode changes the name of the node with the given ID to newName
	// and records the change at at in the name history, returning the
	// renamed node. Renaming a node to its current name returns it unchanged
	// and records nothing. It returns ErrNodeNotFound when no node has the
	// ID and ErrNodeNameTaken when another node already has newName.
	RenameNode(id, newName string, at time.Time) (Node, error)
	// RemoveNode drops the node with the given ID from the inventory and
	// returns it as it was. Its name history is kept, with the current span
	// closed at at, so audit entries recorded against the node still read.
	// It returns ErrNodeNotFound when no node has the ID.
	RemoveNode(id string, at time.Time) (Node, error)
	// Profiles returns every certificate issuance profile.
	Profiles() []Profile
	// Profile returns the profile with the given name, and whether it was
	// found.
	Profile(name string) (Profile, bool)
	// CreateProfile adds p to the catalog. It errors if a profile with the
	// same name already exists.
	CreateProfile(p Profile) error
	// UpdateProfile replaces the profile with p.Name. It errors if no
	// profile has that name.
	UpdateProfile(p Profile) error
	// DeleteProfile removes the profile with the given name. It errors if no
	// profile has that name.
	DeleteProfile(name string) error
	// SetProfileRequestable sets whether a signed-in user may request a
	// certificate under the named catalog profile and returns the updated
	// profile. It errors if no profile has that name.
	SetProfileRequestable(name string, requestable bool) (Profile, error)
	// Adapters returns every enrollment protocol adapter.
	Adapters() []Adapter
	// SetAdapterEnabled sets the enabled state of the adapter with the given
	// name and returns the updated adapter. It errors if no adapter has that
	// name.
	SetAdapterEnabled(name string, enabled bool) (Adapter, error)
	// Audit returns every audit event, in append order.
	Audit() []AuditEvent
	// AddAuditEvent appends e to the hash chain: it sets PrevHash to the
	// previous event's Hash (empty for the first), computes Hash, persists
	// the event, and returns the stored copy.
	AddAuditEvent(e AuditEvent) AuditEvent
	// Enrollments returns every enrollment request.
	Enrollments() []Enrollment
	// AddEnrollment appends a new enrollment request.
	AddEnrollment(e Enrollment)
	// UpdateEnrollment applies mutate to the enrollment with the given ID.
	// It returns an error if no enrollment has that ID.
	UpdateEnrollment(id string, mutate func(*Enrollment)) error
	// Enrollment returns the enrollment request with the given ID, and
	// whether it was found.
	Enrollment(id string) (Enrollment, bool)
	// OperatorCredentials returns every issued operator credential, in a
	// stable order.
	OperatorCredentials() []OperatorCredential
	// AddOperatorCredential records a newly issued operator credential.
	AddOperatorCredential(c OperatorCredential)
	// MarkOperatorCredentialRevoked flags the credential with the given hex
	// serial as revoked. It returns an error if no credential has that serial.
	MarkOperatorCredentialRevoked(serialHex string) error
	// AddMcpKey records a newly minted MCP key.
	AddMcpKey(k McpKey)
	// McpKeyByHash returns the key whose TokenHash is hash, revoked or not,
	// and whether it was found.
	McpKeyByHash(hash string) (McpKey, bool)
	// McpKey returns the key with the given ID, and whether it was found.
	McpKey(id string) (McpKey, bool)
	// McpKeys returns every MCP key, newest first.
	McpKeys() []McpKey
	// RevokeMcpKey stamps RevokedAt on the key with the given ID and returns
	// it. Revoking an already revoked key keeps its first RevokedAt. It
	// returns an error if no key has that ID.
	RevokeMcpKey(id string, at time.Time) (McpKey, error)
	// TouchMcpKey sets LastUsedAt on the key with the given ID and reports
	// whether this was the key's first use.
	TouchMcpKey(id string, at time.Time) (firstUse bool)
	// AddOAuthRequest records a pending authorization request, dropping any
	// request or code that has already expired.
	AddOAuthRequest(r OAuthRequest)
	// OAuthRequest returns the pending request with the given ID, and whether
	// it was found. The caller checks ExpiresAt.
	OAuthRequest(id string) (OAuthRequest, bool)
	// TakeOAuthRequest removes and returns the pending request with the
	// given ID, so consent can be given at most once.
	TakeOAuthRequest(id string) (OAuthRequest, bool)
	// AddOAuthCode records an approved authorization code.
	AddOAuthCode(c OAuthCode)
	// TakeOAuthCode removes and returns the code whose CodeHash is hash, so
	// a code can be redeemed at most once.
	TakeOAuthCode(hash string) (OAuthCode, bool)
	// AddApproval records a newly raised approval.
	AddApproval(a Approval)
	// Approval returns the approval with the given ID, and whether it was
	// found.
	Approval(id string) (Approval, bool)
	// Approvals returns every approval, newest first.
	Approvals() []Approval
	// DecideApproval sets status (ApprovalApproved or ApprovalDenied) and the
	// decider on the approval with the given ID, only if it is still pending
	// and at is before its ExpiresAt. It returns the updated approval and
	// true, or false when the approval is missing, already decided or
	// expired. The check and the update are one step, so two deciders
	// cannot both win.
	DecideApproval(id, status, deciderCN, deciderSerial, deciderLevel string, at time.Time) (Approval, bool)
	// UseApproval marks the approval with the given ID used, only if it is
	// approved and at is before its ExpiresAt. It returns the updated
	// approval and true, or false when it is missing, not approved, already
	// used or expired. The check and the update are one step, so an approval
	// runs at most one call.
	UseApproval(id string, at time.Time) (Approval, bool)
	// AddCertificateRequest records a newly filed certificate request.
	AddCertificateRequest(r CertificateRequest)
	// CertificateRequest returns the request with the given ID, reporting a
	// pending request past its ExpiresAt as CertRequestExpired, and whether
	// it was found.
	CertificateRequest(id string, now time.Time) (CertificateRequest, bool)
	// CertificateRequests returns every certificate request, newest first,
	// reporting a pending request past its ExpiresAt as CertRequestExpired.
	CertificateRequests(now time.Time) []CertificateRequest
	// UpdateCertificateRequest applies mutate to the request with the given
	// ID. It errors if no request has that ID.
	UpdateCertificateRequest(id string, mutate func(*CertificateRequest)) error
}

// Certificate request states. A pending request is readable as
// CertRequestExpired once ExpiresAt passes, without anything writing that
// state; approved is reached when its approval is decided and transitions on
// to issued or failed once the issuing node answers.
const (
	CertRequestPending   = "pending"
	CertRequestApproved  = "approved"
	CertRequestIssued    = "issued"
	CertRequestDenied    = "denied"
	CertRequestCancelled = "cancelled"
	CertRequestExpired   = "expired"
	CertRequestFailed    = "failed"
)

// CertificateRequest is a person's request for a certificate under a
// requestable catalog profile (CreateCertificateRequest). ID is a UUID.
// ApprovalID links it to the Approval that gates it. A zero time means the
// timestamp is unset.
type CertificateRequest struct {
	ID              string
	RequesterCN     string
	RequesterSerial string
	Profile         string
	CSRDER          []byte
	Note            string
	State           string
	ApprovalID      string
	CertDER         []byte
	FailureReason   string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	DecidedAt       time.Time
	IssuedAt        time.Time
}

// HashEvent computes the chain hash for an audit event: the SHA-256, in hex, of
// the previous event's hash and the event's immutable fields. Chaining prevHash
// into each hash makes the log tamper-evident: altering any past event breaks
// every hash after it. The identity/derived fields (PrevHash, Hash) are not
// themselves hashed.
//
// The formula is chosen by e.ChainVersion so rows written under an older
// version keep verifying after the hashed field set grows.
func HashEvent(prevHash string, e AuditEvent) string {
	if e.ChainVersion < 2 {
		h := sha256.Sum256([]byte(prevHash + "\n" + e.ID + e.At + e.Kind + e.Summary + e.TargetKind + e.TargetPath))
		return hex.EncodeToString(h[:])
	}

	// Length-prefixed so text moved across a field boundary changes the hash.
	var b strings.Builder
	b.WriteString(prevHash)
	for _, f := range []string{
		strconv.Itoa(e.ChainVersion), e.ID, e.At, e.Kind, e.Summary, e.TargetKind, e.TargetPath,
		e.ActorKind, e.ActorCN, e.ActorSerial, e.KeyID, e.Via, e.Tool, e.RequestDigest, e.Outcome,
		e.ApprovalID, e.ApproverSerial,
	} {
		b.WriteString("\n")
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteString(":")
		b.WriteString(f)
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}
