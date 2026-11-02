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
	"errors"
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
	"time"

	redis "github.com/Bugs5382/go-redis"
)

// Persistence is how the server keeps data across a restart.
type Persistence string

// What the server's persistence can be.
const (
	PersistenceAOF     Persistence = "aof"
	PersistenceRDBOnly Persistence = "rdb-only"
	PersistenceNone    Persistence = "none"
	// PersistenceUnknown is the health report's value when the server
	// couldn't be asked.
	PersistenceUnknown Persistence = "unknown"
)

// ErrNoPersistence is returned when the server keeps nothing across a
// restart, which would make this memory mode with extra steps.
var ErrNoPersistence = errors.New("kv: the server has no persistence: turn on AOF (appendonly yes), or at least RDB snapshots (docs/storage.md)")

// ErrAuditACL is returned when the manager's account could rewrite the audit
// stream, which would leave the log's append-only promise resting on nothing.
var ErrAuditACL = errors.New("kv: the manager's account can delete from the audit stream: give it the ACL in docs/storage.md")

// statusTTL is how long a health report reuses what the server last said, so
// probes don't add up to a steady load of INFO calls.
const statusTTL = 5 * time.Second

type serverStatus struct {
	at          time.Time
	version     string
	persistence Persistence
}

// parsePersistenceInfo reads INFO persistence, for a server where CONFIG is
// restricted. INFO can't show the snapshot schedule, so a snapshot taken since
// the server started is the evidence that there is one.
func parsePersistenceInfo(info string) Persistence {
	fields := parseInfo(info)
	if fields["aof_enabled"] == "1" {
		return PersistenceAOF
	}
	if n, err := strconv.Atoi(fields["rdb_saves"]); err == nil && n > 0 {
		return PersistenceRDBOnly
	}
	return PersistenceNone
}

func parseInfo(info string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(info, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
			out[k] = v
		}
	}
	return out
}

func (s *Store) readPersistence(ctx context.Context, c redis.Cmdable) (Persistence, error) {
	settings, err := c.ConfigGet(ctx, "appendonly").Result()
	if err == nil {
		save, serr := c.ConfigGet(ctx, "save").Result()
		if serr != nil {
			return "", fmt.Errorf("kv: read the save setting: %w", serr)
		}
		switch {
		case settings["appendonly"] == "yes":
			return PersistenceAOF, nil
		case strings.TrimSpace(save["save"]) != "":
			return PersistenceRDBOnly, nil
		}
		return PersistenceNone, nil
	}
	if redis.Transient(err) || ctx.Err() != nil {
		return "", fmt.Errorf("kv: read the appendonly setting: %w", err)
	}

	log.Printf("kv: CONFIG GET isn't available (%v), reading INFO persistence instead", err)
	info, err := c.Info(ctx, "persistence").Result()
	if err != nil {
		return "", fmt.Errorf("kv: read INFO persistence: %w", err)
	}
	return parsePersistenceInfo(info), nil
}

// CheckPersistence reads the server's persistence at startup. AOF is the
// supported setup, RDB snapshots alone are accepted as a weaker fallback, and
// neither returns ErrNoPersistence.
func (s *Store) CheckPersistence(ctx context.Context) (Persistence, error) {
	p, err := s.readPersistence(ctx, s.rdb)
	if err != nil {
		return "", err
	}
	log.Printf("kv: server persistence: %s", p)
	if p == PersistenceNone {
		return p, ErrNoPersistence
	}
	if p == PersistenceRDBOnly {
		log.Printf("kv: WARNING the server has RDB snapshots only: writes since the last snapshot are lost if it restarts; turn on AOF (docs/storage.md)")
	}
	return p, nil
}

func isNoPerm(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "NOPERM")
}

// CheckAuditACL confirms the account can't XDEL or XTRIM the audit stream, by
// trying both. Neither probe can remove anything if the account can run them:
// no entry has ID 0-1, and nothing is longer than the MAXLEN.
func (s *Store) CheckAuditACL(ctx context.Context) error {
	err := s.rdb.XDel(ctx, s.auditKey(), "0-1").Err()
	if err == nil {
		return ErrAuditACL
	}
	if !isNoPerm(err) {
		return fmt.Errorf("kv: probe XDEL on the audit stream: %w", err)
	}
	err = s.rdb.XTrimMaxLen(ctx, s.auditKey(), math.MaxInt64).Err()
	if err == nil {
		return ErrAuditACL
	}
	if !isNoPerm(err) {
		return fmt.Errorf("kv: probe XTRIM on the audit stream: %w", err)
	}
	log.Printf("kv: the manager's account can't delete from the audit stream")
	return nil
}

// Ping is the readiness check: it gives up within the fail-fast budget while
// the server is down.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.client.FastFail().Redis().Ping(ctx).Err(); err != nil {
		return fmt.Errorf("kv: ping: %w", err)
	}
	return nil
}

// refreshStatus returns the server's version and persistence, reusing a report
// younger than statusTTL.
func (s *Store) refreshStatus(ctx context.Context) (serverStatus, error) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if !s.status.at.IsZero() && time.Since(s.status.at) < statusTTL {
		return s.status, nil
	}
	c := s.client.FastFail().Redis()
	info, err := c.Info(ctx, "server").Result()
	if err != nil {
		return serverStatus{}, fmt.Errorf("kv: read INFO server: %w", err)
	}
	p, err := s.readPersistence(ctx, c)
	if err != nil {
		return serverStatus{}, err
	}
	s.status = serverStatus{at: time.Now(), version: serverVersion(parseInfo(info)), persistence: p}
	return s.status, nil
}

// serverVersion names the server. Valkey also reports a redis_version, for
// compatibility, so its own field comes first.
func serverVersion(fields map[string]string) string {
	if v := fields["valkey_version"]; v != "" {
		return "valkey " + v
	}
	return "redis " + fields["redis_version"]
}

// Version returns the server's name and version.
func (s *Store) Version(ctx context.Context) (string, error) {
	st, err := s.refreshStatus(ctx)
	if err != nil {
		return "", err
	}
	return st.version, nil
}

// Persistence returns the server's persistence for the health report: it can
// change after the startup check, and health is where that shows.
func (s *Store) Persistence(ctx context.Context) Persistence {
	st, err := s.refreshStatus(ctx)
	if err != nil {
		log.Printf("kv: WARNING reading the server's persistence for health: %v", err)
		return PersistenceUnknown
	}
	return st.persistence
}
