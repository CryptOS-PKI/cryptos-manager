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
	"bytes"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/google/uuid"
)

// CertificateRequests runs the certificate request checks against stores
// built by newStore, which must return an empty store each time it is
// called.
func CertificateRequests(t *testing.T, newStore func(t *testing.T) store.Store) {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

	req := func(id string, created time.Time) store.CertificateRequest {
		return store.CertificateRequest{
			ID: id, RequesterCN: "alice@example.org", RequesterSerial: "0A:BC",
			Profile: "web-tls", CSRDER: []byte{0x30, 0x01, 0x02}, Note: "for the new box",
			State: store.CertRequestPending, CreatedAt: created, ExpiresAt: created.Add(30 * 24 * time.Hour),
		}
	}

	t.Run("AddAndGet", func(t *testing.T) {
		st := newStore(t)
		in := req(uuid.NewString(), at)
		st.AddCertificateRequest(in)

		got, ok := st.CertificateRequest(in.ID, at)
		if !ok {
			t.Fatalf("CertificateRequest(%s) not found", in.ID)
		}
		if got.ID != in.ID || got.RequesterCN != in.RequesterCN || got.RequesterSerial != in.RequesterSerial ||
			got.Profile != in.Profile || !bytes.Equal(got.CSRDER, in.CSRDER) || got.Note != in.Note ||
			got.State != store.CertRequestPending || got.ApprovalID != "" || got.CertDER != nil || got.FailureReason != "" ||
			!got.CreatedAt.Equal(in.CreatedAt) || !got.ExpiresAt.Equal(in.ExpiresAt) || !got.DecidedAt.IsZero() || !got.IssuedAt.IsZero() {
			t.Fatalf("CertificateRequest = %+v, want %+v", got, in)
		}
	})

	t.Run("UnknownID", func(t *testing.T) {
		st := newStore(t)
		if _, ok := st.CertificateRequest(uuid.NewString(), at); ok {
			t.Fatal("CertificateRequest(unknown) found a row")
		}
		if err := st.UpdateCertificateRequest(uuid.NewString(), func(*store.CertificateRequest) {}); err == nil {
			t.Fatal("UpdateCertificateRequest(unknown) error = nil, want an error")
		}
	})

	t.Run("ListNewestFirst", func(t *testing.T) {
		st := newStore(t)
		older, newer := req(uuid.NewString(), at), req(uuid.NewString(), at.Add(time.Minute))
		st.AddCertificateRequest(older)
		st.AddCertificateRequest(newer)

		all := st.CertificateRequests(at)
		if len(all) != 2 || all[0].ID != newer.ID || all[1].ID != older.ID {
			t.Fatalf("CertificateRequests = %+v, want newest first", all)
		}
	})

	t.Run("PendingPastExpiryReadsExpiredWithoutMutatingTheRow", func(t *testing.T) {
		st := newStore(t)
		r := req(uuid.NewString(), at)
		st.AddCertificateRequest(r)
		later := r.ExpiresAt.Add(time.Second)

		got, ok := st.CertificateRequest(r.ID, later)
		if !ok || got.State != store.CertRequestExpired || got.CSRDER == nil {
			t.Fatalf("CertificateRequest after expiry = %+v, %v; want expired, CSR kept", got, ok)
		}
		// Reading before the expiry still reports it pending: the state was
		// never written.
		if still, ok := st.CertificateRequest(r.ID, at); !ok || still.State != store.CertRequestPending {
			t.Fatalf("CertificateRequest before expiry = %+v, %v; want still pending", still, ok)
		}

		list := st.CertificateRequests(later)
		if len(list) != 1 || list[0].State != store.CertRequestExpired {
			t.Fatalf("CertificateRequests(after expiry) = %+v", list)
		}
	})

	t.Run("UpdateAppliesMutateAndPersists", func(t *testing.T) {
		st := newStore(t)
		r := req(uuid.NewString(), at)
		st.AddCertificateRequest(r)
		approvalID := "apr-" + uuid.NewString()

		if err := st.UpdateCertificateRequest(r.ID, func(cr *store.CertificateRequest) {
			cr.ApprovalID = approvalID
			cr.State = store.CertRequestApproved
			cr.DecidedAt = at.Add(time.Minute)
		}); err != nil {
			t.Fatalf("UpdateCertificateRequest: %v", err)
		}
		approved, _ := st.CertificateRequest(r.ID, at)
		if approved.State != store.CertRequestApproved || approved.ApprovalID != approvalID || !approved.DecidedAt.Equal(at.Add(time.Minute)) {
			t.Fatalf("after approval = %+v", approved)
		}

		if err := st.UpdateCertificateRequest(r.ID, func(cr *store.CertificateRequest) {
			cr.State = store.CertRequestIssued
			cr.CertDER = []byte{0x30, 0x0a}
			cr.IssuedAt = at.Add(2 * time.Minute)
		}); err != nil {
			t.Fatalf("UpdateCertificateRequest (issue): %v", err)
		}
		issued, _ := st.CertificateRequest(r.ID, at)
		if issued.State != store.CertRequestIssued || !bytes.Equal(issued.CertDER, []byte{0x30, 0x0a}) || !issued.IssuedAt.Equal(at.Add(2*time.Minute)) {
			t.Fatalf("after issuance = %+v", issued)
		}
	})

	t.Run("UpdateCanFailTheRequest", func(t *testing.T) {
		st := newStore(t)
		r := req(uuid.NewString(), at)
		st.AddCertificateRequest(r)

		if err := st.UpdateCertificateRequest(r.ID, func(cr *store.CertificateRequest) {
			cr.State = store.CertRequestFailed
			cr.FailureReason = "the issuing node refused the CSR"
		}); err != nil {
			t.Fatalf("UpdateCertificateRequest: %v", err)
		}
		got, _ := st.CertificateRequest(r.ID, at)
		if got.State != store.CertRequestFailed || got.FailureReason != "the issuing node refused the CSR" {
			t.Fatalf("after failure = %+v", got)
		}
	})
}
