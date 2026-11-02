// Package kv implements the manager's stores on a Redis-protocol server:
// Valkey first, plus Redis. Every collection is a hash of JSON rows, and every
// write that reads first runs under WATCH and commits with MULTI/EXEC, retried
// on a conflict, so several replicas sharing the server keep the "in one step"
// promises the store interfaces make. The audit log is a stream; see audit.go.
//
// Connecting is all the manager does: the server, its persistence and its ACL
// are the operator's (docs/storage.md).
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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	redis "github.com/Bugs5382/go-redis"
)

// defaultNamespace is the hash tag every key carries, which keeps them in one
// cluster slot and gives the ACL one prefix to name.
const defaultNamespace = "fleet"

// A conflict means another replica wrote a watched key first, so retrying
// makes progress. The audit chain head is the one contended key, and the
// limit is high enough for many replicas writing it at once.
const (
	maxTxAttempts = 500
	maxTxBackoff  = 20 * time.Millisecond
)

// Options says how to reach the server.
type Options struct {
	// URL is redis://[user][:password@]host[:port][/db], or rediss:// for
	// TLS. A user signs in as that ACL user; without one the server's
	// default user is used.
	URL string
	// CAFile is a PEM bundle to verify the server against, instead of the
	// system roots. Only meaningful with rediss://.
	CAFile string
}

// target is a parsed Options.URL.
type target struct {
	addr     string
	user     string
	password string
	db       int
	tls      bool
	host     string
}

// parseURL reads a server URL. Its errors never carry the URL itself, which
// holds the password.
func parseURL(raw string) (target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return target{}, errors.New("kv: the server URL can't be parsed")
	}
	var t target
	switch u.Scheme {
	case "redis":
	case "rediss":
		t.tls = true
	default:
		return target{}, fmt.Errorf("kv: the server URL must start with redis:// or rediss://, not %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return target{}, errors.New("kv: the server URL has no host")
	}
	if u.RawQuery != "" {
		return target{}, errors.New("kv: the server URL takes no query parameters")
	}
	t.host = u.Hostname()
	port := u.Port()
	if port == "" {
		port = "6379"
	}
	t.addr = net.JoinHostPort(t.host, port)
	if u.User != nil {
		t.user = u.User.Username()
		t.password, _ = u.User.Password()
	}
	if p := strings.TrimPrefix(u.Path, "/"); p != "" {
		if t.db, err = strconv.Atoi(p); err != nil || t.db < 0 {
			return target{}, errors.New("kv: the server URL's path must be a database number")
		}
	}
	return t, nil
}

func tlsConfig(t target, caFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: t.host}
	if caFile == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("kv: read the CA file: %w", err)
	}
	cfg.RootCAs = x509.NewCertPool()
	if !cfg.RootCAs.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("kv: no certificates in %s", caFile)
	}
	return cfg, nil
}

// Store is the Redis-protocol store. It satisfies store.Store,
// store.OperatorTrust, store.OperatorCredentialStore and store.Bootstrap.
type Store struct {
	client *redis.Client
	rdb    redis.UniversalClient
	ns     string

	chainMu  sync.Mutex
	chainErr error

	statusMu sync.Mutex
	status   serverStatus
}

// New connects to the server and pings it. A server that isn't up yet is an
// error redis.Transient recognises, for the caller to wait on.
func New(ctx context.Context, o Options) (*Store, error) {
	return open(ctx, o, defaultNamespace)
}

// clientOptions turns a parsed URL into the client's options.
func clientOptions(t target, caFile string) ([]redis.Option, error) {
	opts := []redis.Option{redis.WithAddr(t.addr), redis.WithDB(t.db)}
	if t.user != "" {
		opts = append(opts, redis.WithUsername(t.user))
	}
	if t.password != "" {
		opts = append(opts, redis.WithPassword(t.password))
	}
	if t.tls {
		cfg, err := tlsConfig(t, caFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, redis.WithTLS(cfg))
	}
	return opts, nil
}

// account names the ACL user for the logs; the password is never logged.
func (t target) account() string {
	if t.user == "" {
		return "default"
	}
	return t.user
}

func open(ctx context.Context, o Options, ns string) (*Store, error) {
	t, err := parseURL(o.URL)
	if err != nil {
		return nil, err
	}
	opts, err := clientOptions(t, o.CAFile)
	if err != nil {
		return nil, err
	}
	log.Printf("kv: connecting to %s as user %q (db %d, tls %v)", t.addr, t.account(), t.db, t.tls)
	c, err := redis.Connect(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("kv: connect to %s as user %q: %w", t.addr, t.account(), err)
	}
	log.Printf("kv: connected to %s as user %q", t.addr, t.account())
	return &Store{client: c, rdb: c.Redis(), ns: ns}, nil
}

// Close closes the connections.
func (s *Store) Close() {
	if err := s.client.Close(); err != nil {
		log.Printf("kv: close: %v", err)
	}
}

// key names a key that holds manager state. The ACL lets the manager do what
// it likes under this prefix and nothing of the kind to the audit stream.
func (s *Store) key(name string) string { return "{" + s.ns + "}:state:" + name }

// Collections and single values.
const (
	keyNodes        = "nodes"
	keyNodeNames    = "node_names"
	keyProfiles     = "profiles"
	keyAdapters     = "adapters"
	keyEnrollments  = "enrollments"
	keyCredentials  = "operator_credentials"
	keyRequests     = "operator_credential_requests"
	keyMcpKeys      = "mcp_keys"
	keyOAuthReqs    = "oauth_requests"
	keyOAuthCodes   = "oauth_codes"
	keyApprovals    = "approvals"
	keyCertRequests = "certificate_requests"
	keyOperatorCAs  = "operator_cas"
	keyOperatorCRLs = "operator_crls"
	keyDenylist     = "operator_denylist"
	keyTokens       = "bootstrap_tokens"
	keySessions     = "bootstrap_sessions"
	keyLatch        = "bootstrap_state"
	keyServerCert   = "bootstrap_server_cert"
	keyAuditHead    = "audit_head"
	keySeq          = "seq"
	keyEpoch        = "revocation_epoch"
	keyCAVersion    = "operator_ca_version"
)

// allHashes lists the collections, for the empty check before seeding.
var allHashes = []string{
	keyNodes, keyNodeNames, keyProfiles, keyAdapters, keyEnrollments, keyCredentials, keyRequests,
	keyMcpKeys, keyOAuthReqs, keyOAuthCodes, keyApprovals, keyCertRequests, keyOperatorCAs,
	keyOperatorCRLs, keyDenylist, keyTokens, keySessions,
}

// ACLRules returns the rules the manager's account needs, in ACL SETUSER
// form, for namespace ns. The second selector is the only grant on the audit
// stream, so the account can append and read it and can't delete, trim,
// overwrite or expire it. docs/storage.md prints these with the default
// namespace, and a test runs the store under them.
func ACLRules(ns string) []string {
	return []string{
		"~{" + ns + "}:state:*",
		"-@all",
		"+ping", "+hello", "+client|setname", "+client|setinfo", "+info", "+config|get", "+select",
		"+hget", "+hset", "+hdel", "+hvals", "+hkeys", "+hlen",
		"+get", "+mget", "+set", "+del", "+incr", "+pexpire",
		"+watch", "+unwatch", "+multi", "+exec", "+discard",
		"+eval", "+evalsha",
		"(~{" + ns + "}:audit +xadd +xrange +xlen)",
	}
}

// update runs fn under WATCH on the named keys and commits the writes it
// queued in one MULTI/EXEC, starting over when another writer got to a watched
// key first. fn may run more than once, and an error from it is returned as
// is with nothing written.
func (s *Store) update(ctx context.Context, fn func(*txn) error, names ...string) error {
	keys := make([]string, len(names))
	for i, n := range names {
		keys[i] = s.key(n)
	}
	for attempt := 1; ; attempt++ {
		err := s.rdb.Watch(ctx, func(t *redis.Tx) error {
			x := &txn{ctx: ctx, s: s, t: t}
			if err := fn(x); err != nil {
				return err
			}
			if len(x.writes) == 0 {
				return nil
			}
			_, err := t.TxPipelined(ctx, func(p redis.Pipeliner) error {
				for _, w := range x.writes {
					w(p)
				}
				return nil
			})
			return err
		}, keys...)
		if !errors.Is(err, redis.TxFailedErr) {
			return err
		}
		if attempt >= maxTxAttempts {
			return fmt.Errorf("kv: gave up after %d conflicting writes on %v: %w", attempt, names, err)
		}
		log.Printf("kv: write on %v lost a race, attempt %d", names, attempt)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(rand.N(maxTxBackoff)):
		}
	}
}

// txn is one attempt of an update: reads go straight to the watched
// connection, and writes queue until the commit, so a read never sees this
// attempt's own writes.
type txn struct {
	ctx    context.Context
	s      *Store
	t      *redis.Tx
	writes []func(redis.Pipeliner)
}

// put queues field = v in hash name.
func (x *txn) put(name, field string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("kv: encode %s/%s: %w", name, field, err)
	}
	key := x.s.key(name)
	x.writes = append(x.writes, func(p redis.Pipeliner) { p.HSet(x.ctx, key, field, b) })
	return nil
}

// del queues removing field from hash name.
func (x *txn) del(name, field string) {
	key := x.s.key(name)
	x.writes = append(x.writes, func(p redis.Pipeliner) { p.HDel(x.ctx, key, field) })
}

// putValue queues the single value at name.
func (x *txn) putValue(name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("kv: encode %s: %w", name, err)
	}
	key := x.s.key(name)
	x.writes = append(x.writes, func(p redis.Pipeliner) { p.Set(x.ctx, key, b, 0) })
	return nil
}

// bump queues adding one to the counter at name.
func (x *txn) bump(name string) {
	key := x.s.key(name)
	x.writes = append(x.writes, func(p redis.Pipeliner) { p.Incr(x.ctx, key) })
}

// seq takes the next value of the store-wide sequence, which orders rows the
// way a serial column does. An attempt that loses a race leaves a gap, which
// orders just the same.
func (x *txn) seq() (int64, error) {
	n, err := x.t.Incr(x.ctx, x.s.key(keySeq)).Result()
	if err != nil {
		return 0, fmt.Errorf("kv: next sequence: %w", err)
	}
	return n, nil
}

// readAll decodes every row of hash name.
func readAll[T any](ctx context.Context, c redis.Cmdable, s *Store, name string) ([]T, error) {
	vals, err := c.HVals(ctx, s.key(name)).Result()
	if err != nil {
		return nil, fmt.Errorf("kv: read %s: %w", name, err)
	}
	out := make([]T, 0, len(vals))
	for _, v := range vals {
		var row T
		if err := json.Unmarshal([]byte(v), &row); err != nil {
			return nil, fmt.Errorf("kv: decode a row of %s: %w", name, err)
		}
		out = append(out, row)
	}
	return out, nil
}

// readOne decodes the row at field of hash name, and says whether there is one.
func readOne[T any](ctx context.Context, c redis.Cmdable, s *Store, name, field string) (T, bool, error) {
	var row T
	v, err := c.HGet(ctx, s.key(name), field).Result()
	if errors.Is(err, redis.Nil) {
		return row, false, nil
	}
	if err != nil {
		return row, false, fmt.Errorf("kv: read %s/%s: %w", name, field, err)
	}
	if err := json.Unmarshal([]byte(v), &row); err != nil {
		return row, false, fmt.Errorf("kv: decode %s/%s: %w", name, field, err)
	}
	return row, true, nil
}

// readValue decodes the single value at name, and says whether there is one.
func readValue[T any](ctx context.Context, c redis.Cmdable, s *Store, name string) (T, bool, error) {
	var v T
	raw, err := c.Get(ctx, s.key(name)).Result()
	if errors.Is(err, redis.Nil) {
		return v, false, nil
	}
	if err != nil {
		return v, false, fmt.Errorf("kv: read %s: %w", name, err)
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return v, false, fmt.Errorf("kv: decode %s: %w", name, err)
	}
	return v, true, nil
}

// bg is the context for store.Store methods, which take none.
func bg() context.Context { return context.Background() }

// must turns a failure into a panic for the store.Store methods that can't
// return one, as the Postgres store does; withRecover answers it with a 500.
func must(err error, what string) {
	if err != nil {
		panic(fmt.Sprintf("kv: %s: %v", what, err))
	}
}

// mustValue is must for a read.
func mustValue[T any](v T, err error) func(string) T {
	return func(what string) T {
		must(err, what)
		return v
	}
}
