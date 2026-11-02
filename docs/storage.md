# 🗄️ Storage: PostgreSQL, KV and memory mode

The manager keeps its own state -- the node inventory, certificate profiles,
enrollments, operator credentials and the hash-chained audit log -- behind one
`store.Store` interface, with three implementations: a PostgreSQL store, a
store on a persistent Redis-protocol server (`storage.mode: kv`), and an
in-memory one (`storage.mode: memory`). The config loader refuses to start
with none configured, naming the ways to fix it, rather than silently
falling back to memory the way earlier builds did.

## ✅ Choosing a mode

- **PostgreSQL (the default).** Set `database_url`. Durable: nodes, profiles,
  enrollments, operator credentials and the audit log all survive a restart.
  Supports first run, MCP, and more than one replica. Use this unless you
  have a specific reason not to.
- **KV (`storage.mode: kv`).** For a site that already runs Valkey or Redis and
  would rather not add PostgreSQL. Everything PostgreSQL does works here: the
  state is durable as long as the server's is, and first run, MCP and several
  replicas are all supported. See [KV mode](#-kv-mode).
- **Memory (`storage.mode: memory`).** For a home lab or a single-box install
  where running a separate Postgres is more operational overhead than it's
  worth. Nothing persists: a restart starts from an empty store, which the
  manager then rebuilds by reconnecting to the configured nodes (their names,
  endpoints and roles come back from `config.yaml`; everything the manager
  only learned at runtime -- operator credentials it issued, enrollment
  requests, its own audit log -- does not). First run and MCP are unavailable
  in this mode (both need a durable store); set `operatorCAPath` to a file instead of
  registering an operator CA interactively.

Setting `database_url` together with a `storage.mode` is refused as a config
error: a deployment has one store.

```yaml
# config.yaml
storage:
  mode: memory
```

## 🗝️ KV mode

Valkey is the first target, and Redis works the same way. Like PostgreSQL, the
server is yours: the manager and the chart only make the connection, and never
run or manage it.

```yaml
# config.yaml
storage:
  mode: kv
  kv:
    url: "rediss://:secret@valkey.example.org:6380/0"
    caFile: /etc/cryptos/fleet/kv-ca/ca.crt  # only for a private CA
```

`url` is `redis://` or `rediss://` (TLS), then an optional `:password@`, the
host, an optional port and an optional database number. A non-empty
`MANAGER_KV_URL` environment variable overrides it, so the password can come
from a secret store. A URL that names a user is refused: the client library
authenticates with a password only, so the manager's account is the server's
`default` user, and your admin account is a named one.

### Set up the server

1. Turn on AOF. In `valkey.conf`:

   ```
   appendonly yes
   ```

2. Give the `default` user the manager's ACL, and make a separate admin. In the
   server's ACL file (`aclfile`), with your own passwords:

   ```
   user admin on >ADMIN_PASSWORD ~* &* +@all
   user default on >MANAGER_PASSWORD ~{fleet}:state:* -@all +ping +hello +client|setname +client|setinfo +info +config|get +select +hget +hset +hdel +hvals +hkeys +hlen +get +mget +set +del +incr +pexpire +watch +unwatch +multi +exec +discard +eval +evalsha (~{fleet}:audit +xadd +xrange +xlen)
   ```

   The second selector, in brackets, is the only grant on the audit stream: the
   account can append to it and read it, and can't `XDEL`, `XTRIM`, `DEL`,
   `SET` or expire it. Selectors need Valkey 7.2 or later, or Redis 7 or later.

3. Put the URL in a Secret. For the chart, set `storage.mode: kv` and
   `storage.kv.existingSecret`; the Secret's `kv-url` key holds the URL. A
   private CA goes in a ConfigMap named by `storage.kv.caConfigMap`, under the
   key `ca.crt`.

### What the manager checks at startup

The manager waits up to 90 seconds for the server, as it does for PostgreSQL,
then:

- **Reads the persistence settings** (`CONFIG GET`, or `INFO persistence` where
  `CONFIG` is restricted). AOF is the supported setup. RDB snapshots alone are
  accepted as a weaker fallback, because writes since the last snapshot are lost
  in a crash; health reports them as degraded. With neither, the manager refuses
  to start: that would be memory mode with extra steps. Where `CONFIG` is
  restricted, RDB can only be seen once the server has taken a snapshot.
- **Tries `XDEL` and `XTRIM` on the audit stream**, in a form that removes
  nothing even if it runs. If either isn't refused, the manager refuses to
  start: the account is the one the audit log has to be safe from.
- **Verifies the audit chain.** A break is logged as an error and shown in
  health, and the manager still starts: it can still run the fleet, and what is
  left of the log is the evidence.

### Several replicas

The store is shared, so `replicaCount` can go above 1, under the same condition
as PostgreSQL: every pod needs the adopted nodes' admin keys, so `nodeCreds`
must be `ReadWriteMany`. Every write that reads first runs under `WATCH` and
commits with `MULTI`/`EXEC`, and starts over if another replica got there first,
so the store keeps the same one-step promises as PostgreSQL's transactions.

### The audit log

Each entry is `XADD`ed to the stream `{fleet}:audit`, with its event, its hash
and the SHA-256 of the entry before it (`prev_hash`), so the entries form a hash
chain. The hash of the newest entry is kept in `{fleet}:state:audit_head`.

All replicas write one chain. A new entry is hashed from the head, and the entry
and the new head commit together, on the condition that the head hasn't moved. A
replica that loses that race rehashes from the new head, so there is one line of
history, in stream order, however many replicas are writing.

The manager verifies the whole chain at startup and on every read of the log. A
changed entry, a removed entry, or a stream that no longer reaches the head is
logged as an error, and health shows `"auditChain": "broken"`. The read still
returns what is there.

The ACL is what stops the manager's own account rewriting the stream, and the
chain is what shows if someone else did. Removing the stream and the head
together needs the admin account and leaves an empty log with no sign of a
break, so guard that account, and back up the AOF.

### Health

`/healthz` reports the server's version, its persistence and the chain:

```json
{"status":"ok","storage":{"mode":"kv","state":"ok","version":"valkey 8.1.11","persistence":"aof","auditChain":"ok"}}
```

Readiness fails with a 503 while the server is unreachable. `persistence` is
`aof`, `rdb-only`, `none` or `unknown`; anything but `aof`, or a broken chain,
reports `degraded` with a 200, because the manager still works.

## 🔒 Why memory mode is single-replica

Two replicas each holding a different, unsynchronized in-memory view would
silently disagree about the fleet. The chart enforces one replica for
`storage.mode: memory` at render time (`replicaCount` over 1 is refused), and
the manager enforces it again at runtime, independent of how it was started:

- **In a Kubernetes cluster,** it claims a `coordination.k8s.io/v1` Lease in
  its own namespace, using the pod's own service account credentials (no
  separate Kubernetes client library). A local file lock cannot see a second
  pod: each pod has its own filesystem (a volume shared read-write-many across
  pods is the exception, and even then, locking over many network filesystems
  that back such a volume is unreliable). A Lease is arbitrated by the API
  server instead, so it works the same way regardless of what backs the
  volume.
- **Outside a cluster** (a bare host, a single Docker Compose node), it takes
  an exclusive, non-blocking `flock` on a file under the same writable
  directory the chart already mounts for node admin credentials
  (`/var/lib/cryptos-manager/node-creds`, or `MANAGER_NODE_CREDS_DIR`). A
  second process on the same host, or sharing the same Compose volume, is
  refused immediately. The kernel releases the lock when the holding process
  exits or crashes, so a restart reclaims it without waiting on anything.

A manager that cannot confirm either way -- for example, a Kubernetes pod
whose service account token isn't mounted -- refuses to start rather than run
unguarded.

The guard is named for the Helm release (`MANAGER_REPLICA_LOCK_NAME`) so two
independent fleet-manager installs in the same namespace don't contend with
each other.

## 🩺 Health and the restart warning

At startup in memory mode, the manager logs a warning naming what is lost on
restart. The `/healthz` body (served anonymously) reports the same thing
machine-readably, for the web console to show as a banner:

```json
{"status": "degraded", "storage": {"mode": "memory", "state": "degraded"}}
```

This is `degraded`, not a failure: readiness still passes, because the store
itself is not unreachable, only non-durable. A PostgreSQL store reports its
reachability and, when it answers, its server version:

```json
{"status": "ok", "storage": {"mode": "postgres", "state": "ok", "version": "18.1"}}
```

and `unavailable` with a 503 while Postgres cannot be reached (readiness fails
on a required dependency's loss; liveness only checks the process).

## 🐘 Setting up PostgreSQL

The manager only connects: create a database and a user yourself, and put the
connection in a secret. It never creates databases, users or roles, and it
never administers PostgreSQL itself; it only runs its own schema migrations
(a small, idempotent migrator, applied on every startup) against the database
it is given.

```sql
CREATE DATABASE manager;
CREATE USER manager WITH PASSWORD 'change-me';
GRANT ALL PRIVILEGES ON DATABASE manager TO manager;
-- PostgreSQL 15+ no longer grants CREATE on the public schema to everyone by
-- default; the migrator needs it to create the manager's tables.
\connect manager
GRANT ALL ON SCHEMA public TO manager;
```

```yaml
# config.yaml
database_url: "postgres://manager:change-me@db:5432/manager"
```

A non-empty `MANAGER_DATABASE_URL` environment variable overrides
`database_url`, so the DSN and its password can come from a Kubernetes Secret
or another secret store instead of the config file; the chart's
`database.existingSecret` does exactly that.

**Supported versions:** PostgreSQL 14 or newer. The schema and migrations use
nothing more recent than `ON CONFLICT` (9.5+); 14 is the oldest upstream
PostgreSQL release still maintained as of this writing. CI and the bundled
`deploy/compose.yaml` both run PostgreSQL 18.

## 🧩 The storage seam

`internal/store.Store` is the only interface the rest of the manager talks
to; `internal/store/postgres`, `internal/store/kv` and `internal/store/memory`
are complete implementations of it, selected once at startup in
`cmd/manager/main.go`. Nothing that holds a `store.Store` knows which it has.
