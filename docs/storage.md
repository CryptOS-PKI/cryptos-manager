# 🗄️ Storage: PostgreSQL and memory mode

The manager keeps its own state -- the node inventory, certificate profiles,
enrollments, operator credentials and the hash-chained audit log -- behind one
`store.Store` interface, with two implementations: a PostgreSQL store and an
in-memory one (`storage.mode: memory`). The config loader refuses to start
with neither configured, naming both ways to fix it, rather than silently
falling back to memory the way earlier builds did.

## ✅ Choosing a mode

- **PostgreSQL (the default).** Set `database_url`. Durable: nodes, profiles,
  enrollments, operator credentials and the audit log all survive a restart.
  Needed for first run, MCP, and more than one replica. Use this unless you
  have a specific reason not to.
- **Memory (`storage.mode: memory`).** For a home lab or a single-box install
  where running a separate Postgres is more operational overhead than it's
  worth. Nothing persists: a restart starts from an empty store, which the
  manager then rebuilds by reconnecting to the configured nodes (their names,
  endpoints and roles come back from `config.yaml`; everything the manager
  only learned at runtime -- operator credentials it issued, enrollment
  requests, its own audit log -- does not). First run and MCP are unavailable
  in this mode (both need Postgres); set `operatorCAPath` to a file instead of
  registering an operator CA interactively.

Setting both `database_url` and `storage.mode: memory` is refused as a config
error: a deployment cannot honestly be both durable and not.

```yaml
# config.yaml
storage:
  mode: memory
```

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
to; `internal/store/postgres` and `internal/store/memory` are both complete
implementations of it, selected once at startup in `cmd/manager/main.go`. A
third mode, a persistent Redis/Valkey-protocol store, is planned (targeted at
a later release) and will be a third implementation of the same interface,
with no change needed anywhere that holds a `store.Store`.
