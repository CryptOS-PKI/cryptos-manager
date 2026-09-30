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
	"context"
	"errors"
	"math/big"
	"time"
)

// Operator CA row states. At most one row is active and at most one is
// retiring; both are trusted. A retired row is kept for the record and
// trusts nothing.
const (
	OperatorCAActive   = "active"
	OperatorCARetiring = "retiring"
	OperatorCARetired  = "retired"
)

// Where a registered operator CA's CRL comes from. A config-file operator CA
// can also read one from a path, which is never stored on a row.
const (
	CRLSourceNone   = "none"
	CRLSourceURL    = "url"
	CRLSourceUpload = "upload"
	CRLSourcePath   = "path"
)

// How the manager finds an operator CA's OCSP responder.
const (
	OCSPModeOff = "off"
	OCSPModeAIA = "aia"
	OCSPModeURL = "url"
)

// Kinds of operator credential record. A legacy_node row was issued by a
// CryptOS node before operator CAs became external; its issuer can't be an
// operator CA any more, so it can't authenticate.
const (
	OperatorCredentialLegacyNode = "legacy_node"
	OperatorCredentialFirstAdmin = "first_admin"
	OperatorCredentialRequested  = "requested"
	OperatorCredentialRecorded   = "recorded"
	OperatorCredentialObserved   = "observed"
)

// ErrDatabaseRequired is returned by operations only the Postgres store
// supports, such as the denylist and registered operator CAs.
var ErrDatabaseRequired = errors.New("store: this needs the Postgres store")

// ErrOperatorCANotFound is returned when no operator CA has the requested
// fingerprint.
var ErrOperatorCANotFound = errors.New("store: operator CA not found")

// OperatorCA is one registered operator CA: the certificate of an external CA
// that signs operator credentials. The manager never holds its key. SHA256
// is the lowercase hex SHA-256 of CertDER. A zero time means unset.
type OperatorCA struct {
	SHA256           string
	CertDER          []byte
	State            string
	CRLSource        string
	CRLURL           string
	OCSPMode         string // empty is stored as OCSPModeAIA
	OCSPURL          string
	Acknowledgements []string
	Warnings         []string
	RegisteredAt     time.Time
	RegisteredBy     string
	RetiredAt        time.Time
	RetiredReason    string
	UpdatedAt        time.Time
}

// OperatorCRL is the last good CRL held for one operator CA, plus the outcome
// of the latest attempt to refresh it. DER is nil when no CRL has been stored
// yet. Number is the cRLNumber, nil when the CRL has none. A stored CRL is
// re-verified against its CA every time it is loaded.
type OperatorCRL struct {
	IssuerSHA256  string
	DER           []byte
	Number        *big.Int
	ThisUpdate    time.Time
	NextUpdate    time.Time
	FetchedAt     time.Time
	Source        string
	LastError     string
	LastAttemptAt time.Time
}

// DenylistEntry is one operator certificate the manager refuses, keyed by
// the operator CA's fingerprint and the normalised hex serial (lowercase, no
// separators, no leading zeros), because serials are unique per issuer only.
type DenylistEntry struct {
	IssuerSHA256    string
	SerialHex       string
	Reason          int
	RevokedAt       time.Time
	RevokedByCN     string
	RevokedBySerial string
	Note            string
}

// TrustVersion is what a replica polls to notice another replica's changes.
// CAs changes whenever an operator CA row is added or changed; Epoch counts
// denylist entries and stored CRLs.
type TrustVersion struct {
	CAs   string
	Epoch int64
}

// DecideCRL is called by PutOperatorCRL with the currently stored CRL, if
// any, and returns whether to store the new one. An error aborts the write
// and is returned as is.
type DecideCRL func(current OperatorCRL, has bool) (bool, error)

// OperatorTrust is the storage behind operator CA trust and revocation. Its
// methods return errors, unlike Store's. The in-memory store supports only
// what a config-file operator CA needs: CRLs kept per process, no registered
// rows and no denylist (ErrDatabaseRequired).
type OperatorTrust interface {
	// OperatorCAs returns every registered operator CA, retired ones
	// included, oldest first.
	OperatorCAs(ctx context.Context) ([]OperatorCA, error)
	// AddOperatorCA stores a new operator CA row.
	AddOperatorCA(ctx context.Context, ca OperatorCA) error
	// SetOperatorCAState moves the row with the given fingerprint to state,
	// recording reason and at when it is retired.
	SetOperatorCAState(ctx context.Context, sha256, state, reason string, at time.Time) error

	// OperatorCRLs returns the stored CRL and last attempt of every operator
	// CA that has either.
	OperatorCRLs(ctx context.Context) ([]OperatorCRL, error)
	// PutOperatorCRL stores c as the CRL for c.IssuerSHA256 if decide
	// accepts it, clearing the last error and bumping the revocation epoch,
	// all in one step so two writers can't both win. It reports whether c
	// was stored.
	PutOperatorCRL(ctx context.Context, c OperatorCRL, decide DecideCRL) (bool, error)
	// RecordOperatorCRLAttempt records a failed refresh without touching the
	// stored CRL.
	RecordOperatorCRLAttempt(ctx context.Context, issuerSHA256, lastError string, at time.Time) error

	// OperatorDenylist returns every denylist entry.
	OperatorDenylist(ctx context.Context) ([]DenylistEntry, error)
	// AddOperatorDenylistEntry adds e and bumps the revocation epoch. An
	// entry that already exists is kept as it was, and it reports false.
	AddOperatorDenylistEntry(ctx context.Context, e DenylistEntry) (bool, error)

	// OperatorTrustVersion returns what the trust poll compares.
	OperatorTrustVersion(ctx context.Context) (TrustVersion, error)

	// TryAdvisoryLock takes the named lock if no one else holds it, across
	// every replica sharing the database. release must be called once the
	// holder is done.
	TryAdvisoryLock(ctx context.Context, name string) (release func(), acquired bool, err error)
}

// ServerCert is the self-signed bootstrap server certificate and its PKCS#8
// key, shared by every replica until real TLS material is configured.
type ServerCert struct {
	CertDER  []byte
	KeyDER   []byte
	NotAfter time.Time
}
