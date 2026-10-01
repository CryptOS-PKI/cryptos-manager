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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CryptOS-PKI/manager/internal/store"
	"github.com/google/uuid"
)

// CredentialStore is what the OperatorCredentials suite needs: the request
// and recording methods plus the plain credential list.
type CredentialStore interface {
	store.OperatorCredentialStore
	OperatorCredentials() []store.OperatorCredential
}

// OperatorCredentials runs the credential request, recording and observed
// credential checks against stores built by newStore, which must return an
// empty store each time it is called.
func OperatorCredentials(t *testing.T, newStore func(t *testing.T) CredentialStore) {
	ctx := context.Background()
	at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	request := func(id string, created time.Time) store.OperatorCredentialRequest {
		return store.OperatorCredentialRequest{
			ID: id, Level: "operator", Email: "alice@example.org", FullName: "Alice Example",
			CSRDER: []byte{0x30, 0x01, 0x02}, State: store.RequestPending, CreatedByCN: "admin@example.org",
			CreatedAt: created, ExpiresAt: created.Add(30 * 24 * time.Hour),
		}
	}
	cred := func(issuer, serial string) store.OperatorCredential {
		return store.OperatorCredential{
			IssuerSHA256: issuer, SerialHex: serial, CommonName: "alice@example.org", Level: "operator",
			NotAfter: "2027-09-30T12:00:00Z", Kind: store.OperatorCredentialRecorded,
			Email: "alice@example.org", FullName: "Alice Example", LeafSHA256: "leaf-" + serial,
		}
	}
	mustAdd := func(t *testing.T, st CredentialStore, r store.OperatorCredentialRequest) {
		t.Helper()
		if err := st.AddOperatorCredentialRequest(ctx, r); err != nil {
			t.Fatalf("AddOperatorCredentialRequest: %v", err)
		}
	}
	find := func(st CredentialStore, issuer, serial string) []store.OperatorCredential {
		var out []store.OperatorCredential
		for _, c := range st.OperatorCredentials() {
			if c.IssuerSHA256 == issuer && c.SerialHex == serial {
				out = append(out, c)
			}
		}
		return out
	}

	t.Run("AddAndGetRequest", func(t *testing.T) {
		st := newStore(t)
		in := request(uuid.NewString(), at)
		mustAdd(t, st, in)
		got, err := st.OperatorCredentialRequest(ctx, in.ID, at)
		if err != nil {
			t.Fatalf("OperatorCredentialRequest: %v", err)
		}
		if got.ID != in.ID || got.Level != in.Level || got.Email != in.Email || got.FullName != in.FullName ||
			!bytes.Equal(got.CSRDER, in.CSRDER) || got.State != store.RequestPending || got.CreatedByCN != in.CreatedByCN ||
			!got.CreatedAt.Equal(in.CreatedAt) || !got.ExpiresAt.Equal(in.ExpiresAt) || got.CompletedSerial != "" {
			t.Fatalf("OperatorCredentialRequest = %+v, want %+v", got, in)
		}
	})

	t.Run("UnknownRequest", func(t *testing.T) {
		st := newStore(t)
		for _, id := range []string{uuid.NewString(), "not-a-uuid"} {
			if _, err := st.OperatorCredentialRequest(ctx, id, at); !errors.Is(err, store.ErrRequestNotFound) {
				t.Errorf("OperatorCredentialRequest(%q) error = %v, want ErrRequestNotFound", id, err)
			}
			if _, err := st.CancelOperatorCredentialRequest(ctx, id, at); !errors.Is(err, store.ErrRequestNotFound) {
				t.Errorf("CancelOperatorCredentialRequest(%q) error = %v, want ErrRequestNotFound", id, err)
			}
		}
	})

	t.Run("ListNewestFirstAndByState", func(t *testing.T) {
		st := newStore(t)
		older, newer := request(uuid.NewString(), at), request(uuid.NewString(), at.Add(time.Minute))
		mustAdd(t, st, older)
		mustAdd(t, st, newer)
		if _, err := st.CancelOperatorCredentialRequest(ctx, older.ID, at); err != nil {
			t.Fatal(err)
		}
		all, err := st.OperatorCredentialRequests(ctx, "", at)
		if err != nil || len(all) != 2 || all[0].ID != newer.ID || all[1].ID != older.ID {
			t.Fatalf("OperatorCredentialRequests(all) = %+v, %v; want newest first", all, err)
		}
		pending, err := st.OperatorCredentialRequests(ctx, store.RequestPending, at)
		if err != nil || len(pending) != 1 || pending[0].ID != newer.ID {
			t.Fatalf("OperatorCredentialRequests(pending) = %+v, %v", pending, err)
		}
	})

	t.Run("PendingPastExpiryReadsExpired", func(t *testing.T) {
		st := newStore(t)
		r := request(uuid.NewString(), at)
		mustAdd(t, st, r)
		later := r.ExpiresAt.Add(time.Second)
		got, err := st.OperatorCredentialRequest(ctx, r.ID, later)
		if err != nil || got.State != store.RequestExpired || got.CSRDER != nil {
			t.Fatalf("OperatorCredentialRequest after expiry = %+v, %v; want expired with no CSR", got, err)
		}
		list, err := st.OperatorCredentialRequests(ctx, store.RequestExpired, later)
		if err != nil || len(list) != 1 || list[0].CSRDER != nil {
			t.Fatalf("OperatorCredentialRequests(expired) = %+v, %v", list, err)
		}
		if _, err := st.CancelOperatorCredentialRequest(ctx, r.ID, later); !errors.Is(err, store.ErrRequestNotPending) {
			t.Fatalf("cancel an expired request: error = %v, want ErrRequestNotPending", err)
		}
	})

	t.Run("CancelDropsTheCSR", func(t *testing.T) {
		st := newStore(t)
		r := request(uuid.NewString(), at)
		mustAdd(t, st, r)
		got, err := st.CancelOperatorCredentialRequest(ctx, r.ID, at)
		if err != nil || got.State != store.RequestCancelled || got.CSRDER != nil {
			t.Fatalf("CancelOperatorCredentialRequest = %+v, %v", got, err)
		}
		again, err := st.CancelOperatorCredentialRequest(ctx, r.ID, at)
		if !errors.Is(err, store.ErrRequestNotPending) || again.State != store.RequestCancelled {
			t.Fatalf("second cancel = %+v, %v; want the cancelled request and ErrRequestNotPending", again, err)
		}
	})

	t.Run("RecordCompletesTheRequest", func(t *testing.T) {
		st := newStore(t)
		r := request(uuid.NewString(), at)
		mustAdd(t, st, r)
		c := cred("aa", "1f")
		c.Kind = store.OperatorCredentialRequested
		c.RequestID = r.ID
		if err := st.RecordOperatorCredential(ctx, c, r.ID, at); err != nil {
			t.Fatalf("RecordOperatorCredential: %v", err)
		}
		got, err := st.OperatorCredentialRequest(ctx, r.ID, at)
		if err != nil || got.State != store.RequestCompleted || got.CSRDER != nil || got.CompletedSerial != "1f" {
			t.Fatalf("request after record = %+v, %v; want completed, serial 1f, no CSR", got, err)
		}
		rows := find(st, "aa", "1f")
		if len(rows) != 1 {
			t.Fatalf("credential rows = %+v", rows)
		}
		if row := rows[0]; row.Kind != store.OperatorCredentialRequested || row.RequestID != r.ID || row.Email != c.Email ||
			row.FullName != c.FullName || row.LeafSHA256 != c.LeafSHA256 || row.Level != c.Level || row.NotAfter != c.NotAfter {
			t.Fatalf("credential row = %+v, want %+v", row, c)
		}
	})

	t.Run("RecordRefusesARequestThatIsNotPending", func(t *testing.T) {
		st := newStore(t)
		done := request(uuid.NewString(), at)
		mustAdd(t, st, done)
		if err := st.RecordOperatorCredential(ctx, cred("aa", "01"), done.ID, at); err != nil {
			t.Fatal(err)
		}
		expired := request(uuid.NewString(), at)
		mustAdd(t, st, expired)
		for name, id := range map[string]string{"completed": done.ID, "expired": expired.ID} {
			err := st.RecordOperatorCredential(ctx, cred("aa", "02"), id, expired.ExpiresAt.Add(time.Second))
			if !errors.Is(err, store.ErrRequestNotPending) {
				t.Errorf("%s: error = %v, want ErrRequestNotPending", name, err)
			}
		}
		if err := st.RecordOperatorCredential(ctx, cred("aa", "03"), uuid.NewString(), at); !errors.Is(err, store.ErrRequestNotFound) {
			t.Errorf("unknown request: error = %v, want ErrRequestNotFound", err)
		}
		if rows := append(find(st, "aa", "02"), find(st, "aa", "03")...); len(rows) != 0 {
			t.Fatalf("a refused record wrote %+v", rows)
		}
	})

	t.Run("RecordRefusesADuplicate", func(t *testing.T) {
		st := newStore(t)
		if err := st.RecordOperatorCredential(ctx, cred("aa", "1f"), "", at); err != nil {
			t.Fatal(err)
		}
		r := request(uuid.NewString(), at)
		mustAdd(t, st, r)
		if err := st.RecordOperatorCredential(ctx, cred("aa", "1f"), r.ID, at); !errors.Is(err, store.ErrCredentialRecorded) {
			t.Fatalf("error = %v, want ErrCredentialRecorded", err)
		}
		if got, _ := st.OperatorCredentialRequest(ctx, r.ID, at); got.State != store.RequestPending {
			t.Fatalf("a refused duplicate completed the request: %+v", got)
		}
		if err := st.RecordOperatorCredential(ctx, cred("bb", "1f"), "", at); err != nil {
			t.Fatalf("the same serial under another operator CA: %v", err)
		}
	})

	t.Run("ObserveThenRecord", func(t *testing.T) {
		st := newStore(t)
		seen := cred("aa", "2a")
		seen.Kind, seen.FullName = store.OperatorCredentialObserved, ""
		if err := st.ObserveOperatorCredential(ctx, seen, at); err != nil {
			t.Fatalf("ObserveOperatorCredential: %v", err)
		}
		if err := st.ObserveOperatorCredential(ctx, seen, at.Add(2*time.Hour)); err != nil {
			t.Fatalf("ObserveOperatorCredential again: %v", err)
		}
		rows := find(st, "aa", "2a")
		if len(rows) != 1 || rows[0].Kind != store.OperatorCredentialObserved || !rows[0].FirstSeenAt.Equal(at) ||
			!rows[0].LastSeenAt.Equal(at.Add(2*time.Hour)) {
			t.Fatalf("observed rows = %+v; want one observed row, first seen at, last seen 2h later", rows)
		}

		if err := st.RecordOperatorCredential(ctx, cred("aa", "2a"), "", at.Add(3*time.Hour)); err != nil {
			t.Fatalf("recording an observed credential: %v", err)
		}
		rows = find(st, "aa", "2a")
		if len(rows) != 1 || rows[0].Kind != store.OperatorCredentialRecorded || rows[0].FullName != "Alice Example" ||
			!rows[0].FirstSeenAt.Equal(at) {
			t.Fatalf("rows after recording = %+v; want the observed row upgraded, first seen kept", rows)
		}
		if err := st.RecordOperatorCredential(ctx, cred("aa", "2a"), "", at); !errors.Is(err, store.ErrCredentialRecorded) {
			t.Fatalf("recording it twice: error = %v, want ErrCredentialRecorded", err)
		}

		if err := st.ObserveOperatorCredential(ctx, seen, at.Add(5*time.Hour)); err != nil {
			t.Fatal(err)
		}
		rows = find(st, "aa", "2a")
		if len(rows) != 1 || rows[0].Kind != store.OperatorCredentialRecorded || rows[0].FullName != "Alice Example" ||
			!rows[0].LastSeenAt.Equal(at.Add(5*time.Hour)) {
			t.Fatalf("rows after observing a recorded credential = %+v; want kind and name kept, last seen updated", rows)
		}
	})
}
