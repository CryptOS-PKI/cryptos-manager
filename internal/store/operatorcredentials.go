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
	"time"
)

// Operator credential request states. A pending request holds its CSR; the
// CSR is dropped once the request is completed, cancelled or expired.
const (
	RequestPending   = "pending"
	RequestCompleted = "completed"
	RequestCancelled = "cancelled"
	RequestExpired   = "expired"
)

// ErrRequestNotFound is returned when no credential request has the ID.
var ErrRequestNotFound = errors.New("store: operator credential request not found")

// ErrRequestNotPending is returned when a credential request is asked to
// change but is no longer pending. The returned request carries its state.
var ErrRequestNotPending = errors.New("store: operator credential request is not pending")

// ErrCredentialRecorded is returned when an operator credential with the same
// issuer and serial is already recorded. A row the manager only observed in
// use doesn't count: recording it upgrades the row.
var ErrCredentialRecorded = errors.New("store: operator credential already recorded")

// OperatorCredentialRequest is a request for an operator credential that the
// external operator CA signs out of band. ID is a UUID. CSRDER is nil once
// the request is no longer pending.
type OperatorCredentialRequest struct {
	ID              string
	Level           string
	Email           string
	FullName        string
	CSRDER          []byte
	State           string
	CreatedByCN     string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	CompletedSerial string
}

// OperatorCredentialStore is the storage behind credential requests,
// recording and observed credentials. Its methods return errors, unlike
// Store's. Every method takes now so a pending request past its ExpiresAt is
// read as expired, with its CSR dropped, before anything else happens. The
// in-memory store supports none of it (ErrDatabaseRequired).
type OperatorCredentialStore interface {
	// AddOperatorCredentialRequest stores a new request.
	AddOperatorCredentialRequest(ctx context.Context, r OperatorCredentialRequest) error
	// OperatorCredentialRequests returns requests newest first, only those in
	// state when it isn't empty.
	OperatorCredentialRequests(ctx context.Context, state string, now time.Time) ([]OperatorCredentialRequest, error)
	// OperatorCredentialRequest returns the request with the ID, or
	// ErrRequestNotFound.
	OperatorCredentialRequest(ctx context.Context, id string, now time.Time) (OperatorCredentialRequest, error)
	// CancelOperatorCredentialRequest cancels a pending request and drops its
	// CSR. A request that isn't pending is returned unchanged with
	// ErrRequestNotPending.
	CancelOperatorCredentialRequest(ctx context.Context, id string, now time.Time) (OperatorCredentialRequest, error)
	// RecordOperatorCredential stores c and, when requestID isn't empty,
	// completes that request with c's serial and drops its CSR, in one step.
	// It returns ErrCredentialRecorded when c's issuer and serial are already
	// recorded (an observed row is upgraded instead), and ErrRequestNotPending
	// or ErrRequestNotFound for the request; either way nothing is written.
	RecordOperatorCredential(ctx context.Context, c OperatorCredential, requestID string, now time.Time) error
	// ObserveOperatorCredential notes that c was seen authenticating at at: a
	// credential the manager doesn't know becomes an observed row, and a
	// known one only has its first and last seen times updated.
	ObserveOperatorCredential(ctx context.Context, c OperatorCredential, at time.Time) error
}
