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
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/storetest"
	upstream "github.com/redis/go-redis/v9"
)

// testURLEnv gates the integration tests, which run against a real Valkey.
// With it unset they skip, so the package stays green without a server; CI
// sets it, and then an unreachable server fails rather than skips.
const testURLEnv = "MANAGER_TEST_KV_URL"

func testURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv(testURLEnv)
	if u == "" {
		t.Skipf("%s not set; skipping Valkey integration test", testURLEnv)
	}
	return u
}

func testNamespace(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "t" + hex.EncodeToString(b)
}

// testStoreIn opens a store on namespace ns; two of them are two replicas.
func testStoreIn(t *testing.T, ns string) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := open(ctx, Options{URL: testURL(t)}, ns)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func testStore(t *testing.T) *Store {
	t.Helper()
	return testStoreIn(t, testNamespace(t))
}

// adminClient talks to the test server directly, for what the store's own
// account must not be able to do.
func adminClient(t *testing.T) *upstream.Client {
	t.Helper()
	o, err := upstream.ParseURL(testURL(t))
	if err != nil {
		t.Fatal(err)
	}
	c := upstream.NewClient(o)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func runSuites(t *testing.T, newStore func(t *testing.T) *Store) {
	t.Run("NodeIDs", func(t *testing.T) {
		storetest.NodeIDs(t, func(t *testing.T) store.Store { return newStore(t) })
	})
	t.Run("CertificateRequests", func(t *testing.T) {
		storetest.CertificateRequests(t, func(t *testing.T) store.Store { return newStore(t) })
	})
	t.Run("OperatorTrust", func(t *testing.T) {
		storetest.OperatorTrust(t, func(t *testing.T) store.OperatorTrust { return newStore(t) })
	})
	t.Run("OperatorCredentials", func(t *testing.T) {
		storetest.OperatorCredentials(t, func(t *testing.T) storetest.CredentialStore { return newStore(t) })
	})
	t.Run("Bootstrap", func(t *testing.T) {
		storetest.Bootstrap(t, func(t *testing.T) storetest.BootstrapStore { return newStore(t) })
	})
}

func TestConformance(t *testing.T) {
	testURL(t)
	runSuites(t, testStore)
}

// TestConformanceUnderTheDocumentedACL runs the same suites on the account
// the docs tell an operator to create, so the recipe can't drift from what
// the store actually calls. The namespace is fixed for the whole run because
// the ACL names its keys. go-redis authenticates with a password only, so
// the restricted account is the server's default user, and admin is a named
// user made first so the rules can be put back.
func TestConformanceUnderTheDocumentedACL(t *testing.T) {
	ctx := context.Background()
	root := adminClient(t)
	const adminUser, adminPass = "kv-test-admin", "kv-test-admin-password"
	if err := root.Do(ctx, "ACL", "SETUSER", adminUser, "on", ">"+adminPass, "~*", "&*", "+@all").Err(); err != nil {
		t.Fatalf("create the admin user: %v", err)
	}
	o, err := upstream.ParseURL(testURL(t))
	if err != nil {
		t.Fatal(err)
	}
	o.Username, o.Password = adminUser, adminPass
	admin := upstream.NewClient(o)
	t.Cleanup(func() { _ = admin.Close() })

	ns := testNamespace(t)
	args := []any{"ACL", "SETUSER", "default", "reset", "on", "nopass"}
	for _, r := range ACLRules(ns) {
		args = append(args, r)
	}
	if err := admin.Do(ctx, args...).Err(); err != nil {
		t.Fatalf("apply the documented ACL: %v", err)
	}
	t.Cleanup(func() {
		if err := admin.Do(context.Background(), "ACL", "SETUSER", "default", "reset", "on", "nopass", "~*", "&*", "+@all").Err(); err != nil {
			t.Errorf("restore the default user: %v", err)
		}
	})

	s := testStoreIn(t, ns)
	if err := s.CheckAuditACL(ctx); err != nil {
		t.Fatalf("CheckAuditACL: %v", err)
	}
	if _, err := s.CheckPersistence(ctx); err != nil {
		t.Fatalf("CheckPersistence: %v", err)
	}

	// Each subtest gets an empty store, like every other run of the suites.
	newStore := func(t *testing.T) *Store {
		t.Helper()
		clean := testStoreIn(t, ns)
		if err := admin.Do(ctx, "EVAL", `for _, k in ipairs(redis.call('KEYS', ARGV[1])) do redis.call('DEL', k) end return 0`, 0, "{"+ns+"}:*").Err(); err != nil {
			t.Fatalf("empty the namespace: %v", err)
		}
		return clean
	}
	runSuites(t, newStore)

	st := newStore(t)
	st.AddAuditEvent(store.AuditEvent{ID: "1", Kind: "k"})
	if got := len(st.Audit()); got != 1 {
		t.Fatalf("audit rows = %d, want 1", got)
	}
	release, ok, err := st.TryAdvisoryLock(ctx, "l")
	if err != nil || !ok {
		t.Fatalf("TryAdvisoryLock = %v, %v", ok, err)
	}
	release()

	for name, do := range map[string]func() error{
		"XDEL":  func() error { return st.rdb.XDel(ctx, st.auditKey(), "0-1").Err() },
		"XTRIM": func() error { return st.rdb.XTrimMaxLen(ctx, st.auditKey(), 0).Err() },
		"DEL":   func() error { return st.rdb.Del(ctx, st.auditKey()).Err() },
		"SET":   func() error { return st.rdb.Set(ctx, st.auditKey(), "x", 0).Err() },
	} {
		if err := do(); !isNoPerm(err) {
			t.Errorf("%s on the audit stream: err = %v, want NOPERM", name, err)
		}
	}
}

func TestPersistenceCheck(t *testing.T) {
	ctx := context.Background()
	admin := adminClient(t)
	s := testStore(t)

	saved, err := admin.ConfigGet(ctx, "*").Result()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.ConfigSet(context.Background(), "appendonly", saved["appendonly"])
		admin.ConfigSet(context.Background(), "save", saved["save"])
	})
	set := func(t *testing.T, appendonly, save string) {
		t.Helper()
		if err := admin.ConfigSet(ctx, "appendonly", appendonly).Err(); err != nil {
			t.Fatal(err)
		}
		if err := admin.ConfigSet(ctx, "save", save).Err(); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("AOF", func(t *testing.T) {
		set(t, "yes", "")
		if got, err := s.CheckPersistence(ctx); err != nil || got != PersistenceAOF {
			t.Fatalf("CheckPersistence = %q, %v", got, err)
		}
	})
	t.Run("SnapshotsOnly", func(t *testing.T) {
		set(t, "no", "3600 1")
		if got, err := s.CheckPersistence(ctx); err != nil || got != PersistenceRDBOnly {
			t.Fatalf("CheckPersistence = %q, %v", got, err)
		}
	})
	t.Run("NoneIsRefused", func(t *testing.T) {
		set(t, "no", "")
		got, err := s.CheckPersistence(ctx)
		if !errors.Is(err, ErrNoPersistence) {
			t.Fatalf("CheckPersistence = %q, %v; want ErrNoPersistence", got, err)
		}
	})
}

func TestParsePersistenceInfo(t *testing.T) {
	for name, tc := range map[string]struct {
		info string
		want Persistence
	}{
		"aof":       {"aof_enabled:1\r\nrdb_saves:0\r\n", PersistenceAOF},
		"snapshots": {"aof_enabled:0\r\nrdb_saves:3\r\n", PersistenceRDBOnly},
		"neither":   {"aof_enabled:0\r\nrdb_saves:0\r\n", PersistenceNone},
		"empty":     {"", PersistenceNone},
	} {
		t.Run(name, func(t *testing.T) {
			if got := parsePersistenceInfo(tc.info); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	for name, tc := range map[string]struct {
		url     string
		addr    string
		pass    string
		db      int
		tls     bool
		wantErr bool
	}{
		"plain":        {url: "redis://valkey:6379", addr: "valkey:6379"},
		"default port": {url: "redis://valkey", addr: "valkey:6379"},
		"tls and db":   {url: "rediss://:s3cret@valkey:6380/2", addr: "valkey:6380", pass: "s3cret", db: 2, tls: true},
		"default user": {url: "redis://default:s3cret@valkey", addr: "valkey:6379", pass: "s3cret"},
		"named user":   {url: "redis://manager:s3cret@valkey", wantErr: true},
		"wrong scheme": {url: "http://valkey", wantErr: true},
		"bad db":       {url: "redis://valkey/x", wantErr: true},
		"no host":      {url: "redis://", wantErr: true},
		"query":        {url: "redis://valkey?db=1", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseURL err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got.addr != tc.addr || got.password != tc.pass || got.db != tc.db || got.tls != tc.tls {
				t.Fatalf("parseURL = %+v", got)
			}
		})
	}
}

func TestParseURLErrorHidesThePassword(t *testing.T) {
	_, err := parseURL("redis://manager:hunter2@valkey")
	if err == nil {
		t.Fatal("want an error")
	}
	if got := err.Error(); containsSecret(got, "hunter2") {
		t.Fatalf("error leaks the password: %s", got)
	}
}

func containsSecret(s, secret string) bool {
	for i := 0; i+len(secret) <= len(s); i++ {
		if s[i:i+len(secret)] == secret {
			return true
		}
	}
	return false
}

func TestAuditChainAcrossReplicas(t *testing.T) {
	ns := testNamespace(t)
	a, b := testStoreIn(t, ns), testStoreIn(t, ns)

	const writers, each = 8, 25
	var wg sync.WaitGroup
	for w := range writers {
		st := a
		if w%2 == 1 {
			st = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				st.AddAuditEvent(store.AuditEvent{ID: fmt.Sprintf("%d-%d", w, i), Kind: "k", Summary: "s"})
			}
		}()
	}
	wg.Wait()

	got := a.Audit()
	if len(got) != writers*each {
		t.Fatalf("audit rows = %d, want %d", len(got), writers*each)
	}
	prev := ""
	for i, e := range got {
		if e.PrevHash != prev {
			t.Fatalf("row %d: PrevHash = %q, want %q", i, e.PrevHash, prev)
		}
		if e.Hash != store.HashEvent(prev, e) {
			t.Fatalf("row %d: hash doesn't verify", i)
		}
		prev = e.Hash
	}
	if err := b.VerifyAudit(context.Background()); err != nil {
		t.Fatalf("VerifyAudit from the other replica: %v", err)
	}
}

func TestAuditChainReportsTampering(t *testing.T) {
	ctx := context.Background()
	admin := adminClient(t)

	fill := func(t *testing.T) (*Store, []upstream.XMessage) {
		t.Helper()
		s := testStore(t)
		for i := range 4 {
			s.AddAuditEvent(store.AuditEvent{ID: fmt.Sprint(i), Kind: "k", Summary: "s"})
		}
		if err := s.VerifyAudit(ctx); err != nil {
			t.Fatalf("clean chain: %v", err)
		}
		msgs, err := admin.XRange(ctx, s.auditKey(), "-", "+").Result()
		if err != nil {
			t.Fatal(err)
		}
		return s, msgs
	}
	expectBroken := func(t *testing.T, s *Store) {
		t.Helper()
		if err := s.VerifyAudit(ctx); !errors.Is(err, ErrAuditChainBroken) {
			t.Fatalf("VerifyAudit = %v, want ErrAuditChainBroken", err)
		}
		// A read returns what is there and reports the break too.
		if got := s.Audit(); got == nil {
			t.Fatal("Audit returned nil")
		}
		if !errors.Is(s.AuditChainError(), ErrAuditChainBroken) {
			t.Fatalf("AuditChainError = %v", s.AuditChainError())
		}
	}

	t.Run("DeletedMiddleEntry", func(t *testing.T) {
		s, msgs := fill(t)
		if err := admin.XDel(ctx, s.auditKey(), msgs[1].ID).Err(); err != nil {
			t.Fatal(err)
		}
		expectBroken(t, s)
	})
	t.Run("DeletedLastEntry", func(t *testing.T) {
		s, msgs := fill(t)
		if err := admin.XDel(ctx, s.auditKey(), msgs[3].ID).Err(); err != nil {
			t.Fatal(err)
		}
		expectBroken(t, s)
	})
	t.Run("EditedEntry", func(t *testing.T) {
		s, msgs := fill(t)
		if err := admin.XDel(ctx, s.auditKey(), msgs[3].ID).Err(); err != nil {
			t.Fatal(err)
		}
		v := msgs[3].Values
		v["event"] = `{"ID":"3","Kind":"forged"}`
		if err := admin.XAdd(ctx, &upstream.XAddArgs{Stream: s.auditKey(), ID: "*", Values: v}).Err(); err != nil {
			t.Fatal(err)
		}
		expectBroken(t, s)
	})
	t.Run("StreamRemoved", func(t *testing.T) {
		s, _ := fill(t)
		if err := admin.Del(ctx, s.auditKey()).Err(); err != nil {
			t.Fatal(err)
		}
		expectBroken(t, s)
	})
}

func TestCheckAuditACLRefusesAnAccountThatCanTrim(t *testing.T) {
	s := testStore(t) // the test server's default user can do anything
	if err := s.CheckAuditACL(context.Background()); !errors.Is(err, ErrAuditACL) {
		t.Fatalf("CheckAuditACL = %v, want ErrAuditACL", err)
	}
}

func TestSeedIfEmpty(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	seed := []store.Node{{Name: "a", Endpoint: "a:443", Role: "root"}}
	if err := s.SeedIfEmpty(ctx, seed); err != nil {
		t.Fatal(err)
	}
	n, ok := s.Node("a")
	if !ok || n.ID == "" {
		t.Fatalf("Node(a) = %+v, %v", n, ok)
	}
	if err := s.SeedIfEmpty(ctx, []store.Node{{Name: "b", Endpoint: "b:443", Role: "root"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Node("b"); ok {
		t.Fatal("a second seed wrote to a store that wasn't empty")
	}
}

func TestReplicasShareState(t *testing.T) {
	ctx := context.Background()
	ns := testNamespace(t)
	a, b := testStoreIn(t, ns), testStoreIn(t, ns)

	a.AddNode(store.Node{Name: "n", Endpoint: "n:443", Role: "issuing"})
	if _, ok := b.Node("n"); !ok {
		t.Fatal("replica b can't see a node replica a added")
	}

	at := time.Now().UTC()
	b.AddApproval(store.Approval{ID: "ap", Status: store.ApprovalPending, ExpiresAt: at.Add(time.Hour)})
	var wins sync.Map
	var wg sync.WaitGroup
	for i, st := range []*Store{a, b, a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := st.DecideApproval("ap", store.ApprovalApproved, "cn", "s", "admin", at); ok {
				wins.Store(i, true)
			}
		}()
	}
	wg.Wait()
	n := 0
	wins.Range(func(any, any) bool { n++; return true })
	if n != 1 {
		t.Fatalf("%d deciders won, want 1", n)
	}

	release, ok, err := a.TryAdvisoryLock(ctx, "l")
	if err != nil || !ok {
		t.Fatalf("a TryAdvisoryLock = %v, %v", ok, err)
	}
	if _, ok, err := b.TryAdvisoryLock(ctx, "l"); err != nil || ok {
		t.Fatalf("b TryAdvisoryLock while a holds it = %v, %v", ok, err)
	}
	release()
	got := make(chan error, 1)
	go func() { got <- b.WithAdvisoryLock(ctx, "l", func(context.Context) error { return nil }) }()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("WithAdvisoryLock: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WithAdvisoryLock didn't get the released lock")
	}

	cert := store.ServerCert{CertDER: []byte("c"), KeyDER: []byte("k"), NotAfter: at}
	if err := a.PutBootstrapServerCert(ctx, cert); err != nil {
		t.Fatal(err)
	}
	c, ok, err := b.BootstrapServerCert(ctx)
	if err != nil || !ok || string(c.CertDER) != "c" {
		t.Fatalf("BootstrapServerCert = %+v, %v, %v", c, ok, err)
	}
	if err := b.DeleteBootstrapServerCert(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := a.BootstrapServerCert(ctx); ok {
		t.Fatal("certificate still there after delete")
	}
}

func TestHealthStatus(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	v, err := s.Version(ctx)
	if err != nil || v == "" {
		t.Fatalf("Version = %q, %v", v, err)
	}
	if p := s.Persistence(ctx); p != PersistenceAOF {
		t.Fatalf("Persistence = %q", p)
	}
}

func TestPingFailsWhileTheServerIsDown(t *testing.T) {
	s := testStore(t)
	s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("Ping on a closed client succeeded")
	}
}

// TestDocsPrintTheACL keeps the recipe in the docs the one the tests run.
func TestDocsPrintTheACL(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/storage.md")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join(ACLRules(defaultNamespace), " ")
	if !strings.Contains(string(doc), want) {
		t.Fatalf("docs/storage.md doesn't print the ACL: %s", want)
	}
}
