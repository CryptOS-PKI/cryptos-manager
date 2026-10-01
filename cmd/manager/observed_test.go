package main

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
	"crypto/x509"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/config"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/memory"
)

// seenStore is the in-memory store that reports observed credentials.
type seenStore struct {
	*memory.Store
	seen chan store.OperatorCredential
}

func (s *seenStore) ObserveOperatorCredential(_ context.Context, c store.OperatorCredential, _ time.Time) error {
	s.seen <- c
	return nil
}

func trustFor(t *testing.T, cfg config.Config, st *seenStore) (*operatorTrust, *x509.Certificate) {
	t.Helper()
	caPath, ca, caKey := writeOperatorCA(t, t.TempDir())
	cfg.OperatorCAPath = caPath
	base, err := buildTLSConfig(context.Background(), cfg, nil, t.Logf)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	trust, err := setupOperatorTrust(context.Background(), cfg, st, st, base, t.Logf)
	if err != nil {
		t.Fatalf("setupOperatorTrust: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	trust.run(ctx, t.Logf)
	leaf, err := x509.ParseCertificate(operatorLeaf(t, ca, caKey).Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return trust, leaf
}

// With Postgres, the serving path records every operator certificate it
// sees authenticate.
func TestSetupOperatorTrust_RecordsObservedCredentialsWithPostgres(t *testing.T) {
	st := &seenStore{Store: memory.New(nil), seen: make(chan store.OperatorCredential, 4)}
	trust, leaf := trustFor(t, config.Config{DatabaseURL: "postgres://db.example.org/manager"}, st)
	if _, err := trust.web.AuthorizePeer(leaf, nil); err != nil {
		t.Fatalf("AuthorizePeer: %v", err)
	}
	select {
	case c := <-st.seen:
		if c.Kind != store.OperatorCredentialObserved || c.IssuerSHA256 == "" {
			t.Fatalf("observed = %+v", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the serving path didn't record the certificate")
	}
}

// Without Postgres there is nowhere to record, so nothing is queued.
func TestSetupOperatorTrust_NoObservedRecordingWithoutPostgres(t *testing.T) {
	st := &seenStore{Store: memory.New(nil), seen: make(chan store.OperatorCredential, 4)}
	trust, leaf := trustFor(t, config.Config{}, st)
	if _, err := trust.web.AuthorizePeer(leaf, nil); err != nil {
		t.Fatalf("AuthorizePeer: %v", err)
	}
	if trust.observed != nil {
		t.Fatal("an observed-credential recorder was built without Postgres")
	}
	select {
	case c := <-st.seen:
		t.Fatalf("recorded %+v without Postgres", c)
	case <-time.After(100 * time.Millisecond):
	}
}
