# cryptos-manager 🛰️

> 🎛️ The Fleet Manager backend for [CryptOS-PKI](https://github.com/CryptOS-PKI). Optional control plane that talks to many CryptOS CA nodes over mTLS gRPC and serves the [`cryptos-web`](https://github.com/CryptOS-PKI/cryptos-web) frontend at the same TLS listener.

> [!WARNING]
> 🚧 **Pre-1.0: any release can change fundamentally.** CryptOS is pre-1.0. Until v1.0.0, any release may change configuration, APIs, on-disk and state formats, trust setup, and upgrade paths, sometimes with no migration path. If you run it in production, you accept that risk. Read [each release's upgrade notes](https://github.com/CryptOS-PKI/cryptos-manager/releases) before you upgrade.

## ✨ What it does

- 🌳 **Cross-node visibility.** Walks every linked node's declared `role`, `parent`, and `pair` to render a multi-Root fleet topology. Each Root is sovereign; the FM never crosses Root trust boundaries on its own.
- 📚 **Inventory.** Tracks issued certificates, revocation status, and audit deltas across the fleet. Persists to Postgres (cross-node inventory only — per-node state stays on each node's embedded etcd).
- 📜 **Declarative pushes.** When linked, an FM operator can push `MachineConfig` updates to nodes; nodes verify signatures and apply on next reboot.
- 🔀 **Enrolment protocol switches.** An admin switches ACME or EST on or off per node (`SetNodeProtocol`). The manager applies the node's config with only that block's `enabled` flag changed, so its settings and write-only secrets stay as the node stores them. A switch takes effect at the node's next reboot, and `ListNodes` and `GetNode` show each protocol's configured and running state with `reboot_required` until the node reports it running. Every switch is audited with who, node, protocol and new state. Rebooting a node from the manager is not available yet.
- 🧩 **MCP for AI agents.** An optional `/mcp` endpoint on the same listener lets an agent read the fleet and issue end-entity certificates, under the same viewer/operator/admin checks as the web UI. See [`docs/mcp.md`](docs/mcp.md).
- 🚫 **Never an issuance authority.** The FM's peer cert lacks `keyCertSign` and `cRLSign`. The FM cannot sign certificates, even if compromised. Each Root retains full control.

## 🔗 Linking model

A node is linked to the FM via **mutual consent**: the operator declares the FM's URL + trust anchor in the node's machine config and reboots; the node calls the FM's `EnrollNode` with a TPM EK attestation; the FM operator approves in the UI; the FM issues the node a 90-day peer cert (EKU `clientAuth` only). Either side can revoke or unlink.

Adopting a fresh node from its maintenance endpoint is safe to retry. The manager mints a bootstrap admin credential per node name and stores it under `MANAGER_NODE_CREDS_DIR` (default `/var/lib/cryptos-manager/node-creds`). A retry reuses it, because a node that got as far as installing trusts only that credential. When the node reports it has already booted its installed system, the retry skips the install, runs the first-boot ceremony only if a Root has not finished it, and registers the node. If the stored credential is gone, the node refuses the handshake and the adoption fails with a hint to reset the node from its console and adopt it again. After the node reboots into its installed system, the adoption pauses until an admin confirms the certificate fingerprint it presents against the `Mgmt SHA-256` line on its console; see [docs/node-trust.md](docs/node-trust.md#-what-adoption-records).

The node always checks the manager's admin credential, and the manager always checks the node's server certificate: against the node's recorded CA chain once the node signs its management certificate with its CA, or against a pinned `server.crt` before that. A node it can't verify is refused. `manager -check-node-trust` connects to each node, verifies it the same way, and exits 1 if any node is refused. See [`docs/node-trust.md`](docs/node-trust.md).

Operators sign in with a client certificate from an **external operator CA**, never a CryptOS node; the manager never signs an operator credential. It re-checks the certificate on every request and refuses revoked ones from its own denylist, the CA's CRL and, where configured, the CA's OCSP responder. See [`docs/operator-ca.md`](docs/operator-ca.md).

Once linked, the node's embedded operator surface becomes read-only and FM owns day-to-day operations. Unlinking is a config change + reboot. A node that has never been linked is managed via [`cryptosctl`](https://github.com/CryptOS-PKI/cryptos-node) only — no web UI in that case (by design — there's no web frontend on the CA image).

## 🧱 Stack

- 🐹 **Go backend**, served behind mTLS TLS 1.3.
- 🐘 **Postgres** for cross-node inventory.
- 📦 **Serves the [`cryptos-web`](https://github.com/CryptOS-PKI/cryptos-web) console bundle** (pinned version, embedded via `embed.FS`) on the same listener as the FM gRPC API.
- ☸️ **Designed to run on Kubernetes** (Deployment + Service + Ingress, Helm chart shipped alongside the container image). Single-node Docker / `docker compose` is supported for small deployments; K8s is the primary target.

## 🚀 Deploying

The manager ships as a **single self-contained image**: the Go binary with the `web` bundle embedded (`go:embed`), serving the SPA and the Connect API on **one** listener. In a real deployment that listener does mTLS client-cert auth (`authBypass: false`), so operators authenticate with a browser-installed client certificate — see [`docs/operator-ca.md`](docs/operator-ca.md) for the external operator CA that signs them and how revocation works. New operator credentials are requested in the manager, signed at the CA and recorded back: see [`docs/operator-credentials.md`](docs/operator-credentials.md).

Bring your own trust material: a **server TLS cert** (`tlsCert`/`tlsKey`, any public or CryptOS-issued cert) and the **operator CA** (`operatorCAPath`, the client-auth trust anchor). No usernames or passwords are stored.

Or start from nothing: with Postgres and no `operatorCAPath`, the manager serves a self-signed certificate and prints a single-use bootstrap token in its log. The token holder registers the operator CA's certificate and checks the first admin certificate it signed; first run then closes for good, unless every admin credential is lost and the offline `-reset-first-run` break-glass reopens it. See [`docs/first-run.md`](docs/first-run.md).

**Docker:**

```sh
docker run -p 443:8443 -p 80:8080 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -v /etc/cryptos/fleet:/etc/cryptos/fleet:ro \
  -v fleet-node-creds:/var/lib/cryptos-manager/node-creds \
  ghcr.io/cryptos-pki/cryptos-manager:vX.Y.Z
# config.yaml (authBypass:false, tlsCert/tlsKey, operatorCAPath, nodes[]) + the
# referenced cert/key/CA files live under the mounted /etc/cryptos/fleet.
```

The image runs as uid 65532 on a read-only root filesystem. The one path it writes is
`/var/lib/cryptos-manager/node-creds`, where adoption keeps the admin key it mints for
each node, so give that path a volume. A named volume picks up the image's directory,
already owned by 65532, the first time it is mounted.

> [!WARNING]
> Without that volume the node keys live in the container and are gone when it is
> recreated. The manager is then locked out of every node it adopted, and each one has
> to be reset from its console and adopted again. Back the volume up with the database.

The image carries its own health check: the manager probes its `/healthz`, which answers
`200 {"status":"ok"}` when it is serving and its Postgres (if configured) answers, and
`503 {"status":"unavailable"}` when the database does not. It is anonymous, like
`/version`, and never includes the database error, which goes to the log instead.
`docker ps` shows the result.

Publish 80 as well as 443. The image listens on 8443 for HTTPS and, when
`httpRedirectListen` is set, on 8080 for a plaintext listener that does nothing but
redirect to HTTPS -- so an operator who types a hostname without a scheme reaches the
login page instead of a refused connection. Both are high ports because the image runs
as uid 65532 and cannot bind a privileged one; the published ports are the conventional
80 and 443.

> [!IMPORTANT]
> The redirect names the **published** HTTPS port, not the one the container binds. If you
> publish HTTPS somewhere other than 443, set `httpsPublicPort` to that port, or the
> redirect will send browsers to a port nothing is listening on.

The web surface itself is reachable without an operator certificate: it serves a landing
page with a Log in action, and every API call still requires a certificate that verifies
against the operator CA. Because both share one listener, a browser may open its
connection for the page before it offers a certificate; an API call that arrives on such a
connection is refused and the connection is closed, so the next attempt makes a fresh TLS
handshake. The refusal is logged (`authz: refused ...`) with the caller's address.

> [!IMPORTANT]
> **Everything under the mount must be readable by uid 65532.** The final image stage is
> `gcr.io/distroless/static-debian12:nonroot`, so the process runs as that uid, and that
> includes `config.yaml` itself. This bites hardest on Debian and Ubuntu, where the server
> key normally lives in `/etc/ssl/private` — that directory is `0710 root:ssl-cert`, so
> bind-mounting a key straight out of it gives the container a path it cannot traverse. The
> `usermod -aG ssl-cert` fix that works for a systemd deployment does not carry over, since
> no host account is involved. Copy the material into the mounted tree instead:

```sh
sudo install -o 65532 -g 65532 -m 0444 fullchain.pem /etc/cryptos/fleet/tls/server-fullchain.pem
sudo install -o 65532 -g 65532 -m 0400 server.key    /etc/cryptos/fleet/tls/server.key
sudo install -o 65532 -g 65532 -m 0400 config.yaml   /etc/cryptos/fleet/config.yaml
```

The failure mode is misleading if you skip this: the manager logs `using postgres store`
and `N node(s) configured` first, then dies on `tls: load server cert: permission
denied`, which reads like a TLS problem rather than a permissions one.

> [!CAUTION]
> **`config.yaml` is a secret, not configuration.** `database_url` carries the Postgres DSN
> inline and the loader does no environment interpolation, so the password is in the file.
> Give it `0400` owned by uid 65532, as above, and keep it out of git — including out of the
> directory you keep a `docker compose` file in.

### Single host with `docker compose`

For a small fleet, the manager plus its own Postgres on one host is a supported topology
rather than an improvisation. [`deploy/compose.yaml`](deploy/compose.yaml) is the worked
example and [`deploy/config.example.yaml`](deploy/config.example.yaml) the config that
goes with it:

```sh
docker compose -f deploy/compose.yaml up -d
```

It publishes 80 and 443, waits for Postgres to be healthy before starting the manager,
and keeps its database in a named volume. Three details in there are load-bearing and
worth knowing before you adapt it:

- **The Postgres volume mounts at `/var/lib/postgresql`, not `/var/lib/postgresql/data`.**
  From Postgres 18 the image stores data in major-version-specific subdirectories, and a
  volume on the old path is rejected outright with
  `there appears to be PostgreSQL data in /var/lib/postgresql/data (unused mount/volume)`.
- **Node credentials get their own volume.** The manager runs read-only, and
  `node-creds` is the one writable path: the admin key minted for each adopted node. It
  is state as much as the database is, so back both up together.
- **Two different things read the mounted files.** `config.yaml`, `tls/` and
  `operator-ca/` are read by the manager, so they must be readable by uid 65532.
  `secrets/postgres.env` is read by the `docker compose` CLI on the host before any
  container starts, so it must be readable by whoever runs compose — do *not* chown that
  one to 65532.
- **`depends_on: service_healthy` orders `up`, not `restart`.** `docker compose restart`
  does not re-evaluate the condition, so the manager can come back before its database.
  It waits for Postgres itself rather than relying on the restart policy, so this is
  survivable either way; the condition and the policy are both kept as belt and braces.

### Building the image yourself

There is no published image before the first release tag, so until then this is the
supported path — and it stays useful afterwards for a patched build.

> [!IMPORTANT]
> **The build context is the workspace root, not this repo.** The `Dockerfile` copies from
> `manager/` and `web/`, so it needs a parent directory holding both checkouts side by side.
> Running `docker build .` from inside this repo fails on the `COPY` paths:

```sh
mkdir -p src && cd src
git clone https://github.com/CryptOS-PKI/cryptos-manager.git manager
git clone https://github.com/CryptOS-PKI/cryptos-web.git web
manager/deploy/build-image.sh            # tags manager:local; IMAGE=... to change
```

Use the script rather than a bare `docker build`. The image copies the checkouts without
their `.git`, so it can only report the build identity it is handed: the script resolves
the manager version (`git describe`), the manager and web commits (suffixed `-dirty` for
uncommitted changes) and the build date, and passes them as the `VERSION`, `COMMIT`,
`WEB_REF` and `BUILD_DATE` build args. They are served at `/version` and set as the
`org.opencontainers.image.{version,revision,created}` labels. A bare `docker build` still
works but reports `dev` / `unknown`. Extra arguments go straight to `docker build`, and
`task image` runs the same script. To run the result with the compose file, set
`MANAGER_IMAGE=manager:local`.

**Helm (OCI):**

```sh
helm install fleet oci://ghcr.io/cryptos-pki/charts/fleet-manager --version X.Y.Z \
  --set tls.certSecret=<server-tls-secret> \
  --set operatorCA.configMap=<operator-ca-configmap> \
  --set database.existingSecret=<postgres-dsn-secret> \
  --set-json 'nodes=[{"name":"pki-root","endpoint":"pki-root.example:443","role":"root","adminCertPath":"...","adminKeyPath":"...","caCertPath":"..."}]'
```

`chart/fleet-manager` is the supported chart. Beyond the TLS Secret and operator CA
ConfigMap it needs a Postgres DSN: `database.existingSecret` names a Secret whose
`database.secretKey` (default `database-url`) holds it, and the chart passes it to the
manager as `MANAGER_DATABASE_URL` so the password never appears in the rendered config. It
refuses to render without one unless `authBypass` is on. The node credentials go on a
PersistentVolumeClaim (`fleet-manager-node-creds`, or `nodeCreds.existingClaim`), which
`helm uninstall` leaves in place.

> [!WARNING]
> That claim holds the admin key for every node the manager adopted. Deleting it locks the
> manager out of those nodes until each one is reset from its console, so back it up with
> the database.

Nodes listed in `nodes` can take their admin credentials from a Secret: set a node's
`adminCredsSecret` to a Secret holding `admin.crt`, `admin.key` and `ca.pem`, and the chart
mounts it read-only at `/etc/cryptos/fleet/node-admin/<name>` and points the node's
`adminCertPath`, `adminKeyPath` and `caCertPath` there. A `server.crt` key in the same Secret
pins the node's server certificate. See `nodes` in
[`values.yaml`](chart/fleet-manager/values.yaml).

The chart runs one pod by default, with a `Recreate` rollout, because the default claim is
`ReadWriteOnce`. More replicas need `nodeCreds.accessModes` to include `ReadWriteMany`, so
every pod sees every node's key; the chart refuses to render otherwise. The pod runs as
uid 65532 with a read-only root filesystem and every capability dropped. Readiness is
`/healthz`, so a pod whose database is down leaves the Service. Startup and liveness only
check that the listener accepts connections, so a database outage does not restart it.

Revocation for the operator CA has its own values: `operatorCRL.urls` (CRL URLs),
`operatorCRL.configMap` with `operatorCRL.files` (CRL files mounted read-only from a
ConfigMap and re-read on every refresh), `operatorRevocationPolicy` and
`operatorOCSP.mode`/`operatorOCSP.url`. The chart checks them as the manager does and
refuses to render a bad value, or any of them with `authBypass`. See
[`docs/operator-ca.md`](docs/operator-ca.md).

The pod template carries a `checksum/config` annotation, so a `helm upgrade` that only
changes the config rolls the pod.

The MCP endpoint is off in the chart too. `mcp.enabled` and `mcp.publicURL` turn it on; the chart refuses to render it with `authBypass`. See [`docs/mcp.md`](docs/mcp.md#with-the-helm-chart).

## 🔌 MCP endpoint

The manager can serve a [Model Context Protocol](https://modelcontextprotocol.io) endpoint at `/mcp` for AI agents. It is off by default.

- 🔑 **Logged in with your operator certificate.** An MCP client such as the `claude` CLI runs a one-time OAuth login; the consent page in the web UI needs your operator certificate, and the client receives a long-lived `fos_mcp_` key bound to that certificate's serial. Clients without OAuth use a key from the Agent keys page.
- 🧮 **Checked live on every call.** The key's certificate is re-validated against the operator CAs trusted now, the denylist, its CA's CRL and OCSP responder (where configured) each time, and its CA must have a fresh CRL, and the key never acts above the certificate's level or its own ceiling.
- 🛑 **Narrow by design.** Agents get read tools and non-CA leaf issuance on intermediate or issuing nodes. CA key material, node provisioning and operator credentials are not exposed.
- ✋ **A person approves the risky calls.** Revocation, profile and adapter changes, and CA or root issuance only raise an approval; they run when the agent calls again after a person approves it in the web UI with their operator certificate. An approval covers one exact request, runs once and lapses after 15 minutes.
- 🧾 **Audited.** Every MCP call, reads included, is in the hash-chained audit log with the operator, key and tool.

```yaml
# config.yaml (also needs authBypass: false and database_url)
mcp:
  enabled: true
  public_url: "https://fleetos.example.org"
```

```sh
claude mcp add --transport http fleetos https://fleetos.example.org/mcp
```

Setup, the tool list and key management are in [`docs/mcp.md`](docs/mcp.md).

## 🗄️ State backend

The manager keeps its state either in memory or in Postgres, chosen by the `database_url` config key:

- **Unset (default).** An in-memory store seeded from the built-in catalog. Nothing persists across a restart. This is the offline-dev and test default.
- **Set to a Postgres DSN.** The manager applies its schema (a small idempotent migrator runs on every startup), seeds the catalog into an empty database on first run, and persists enrollments and the hash-chained audit log. Restarts keep pending enrollments and the audit trail; the seed is a no-op once any table has rows, so live data is never clobbered. That makes `nodes[]` in `config.yaml` bootstrap-only: once the database holds the inventory, a node renamed in the web UI keeps its new name across restarts, and editing the file no longer changes it. Every node has a stable ID, a UUIDv7 assigned when it joins, that never changes; the name is an editable label. An admin removes a node that is gone with `RemoveNode`, which drops it from the inventory without contacting it and keeps its audit history.

```yaml
# config.yaml
database_url: "postgres://manager:secret@db:5432/manager"
```

A non-empty `MANAGER_DATABASE_URL` environment variable overrides `database_url`, so the
DSN and its password can come from a secret store instead of the file. The manager logs
`database_url taken from MANAGER_DATABASE_URL` when it does.

The persistence layer is hand-rolled: raw SQL over [`pgx`](https://github.com/jackc/pgx), a hand-written schema, and a tiny version-tracked migrator — no ORM.

For a bare-host deployment without a container runtime — systemd unit, the
`/etc/ssl/private` trap, an OpenSSL operator CA for a fleet with no spare node, and how to
verify the listener without a browser — see
[`docs/deploying-standalone.md`](docs/deploying-standalone.md).

The Postgres integration tests are gated on the `MANAGER_TEST_DATABASE_URL` env var and **skip** when it is unset, so `task ci` stays green without a database. To run them against a throwaway Postgres:

**Linux / macOS**

```bash
docker run -d --rm -e POSTGRES_PASSWORD=test -p 5433:5432 postgres:18-alpine
MANAGER_TEST_DATABASE_URL=postgres://postgres:test@localhost:5433/postgres \
  go test ./internal/store/... -v
```

**Windows (PowerShell)**

```powershell
docker run -d --rm -e POSTGRES_PASSWORD=test -p 5433:5432 postgres:18-alpine
$env:MANAGER_TEST_DATABASE_URL = "postgres://postgres:test@localhost:5433/postgres"
go test ./internal/store/... -v
```

Pull-request CI (`.github/workflows/ci-go.yaml`) runs the same checks as `task ci` (gofmt, vet, golangci-lint, build, tests) with a Postgres service container and `MANAGER_TEST_DATABASE_URL` set, so these integration tests always run there. It skips draft PRs.

After a stacked pull request is retargeted onto `main`, CI starts on its next push, or when it is toggled to draft and back to ready.

## 📦 Releasing

Nothing tags automatically. On push to `main`, release-drafter categorises the merged conventional-commit PRs into the draft release notes, and [`Bugs5382/changelog-updater-action`](https://github.com/Bugs5382/changelog-updater-action) writes those notes into `CHANGELOG.md` (committed back to `main` as a `[skip ci]` pre-release commit). The maintainer then publishes the GitHub Release by hand, which creates the `vX.Y.Z` tag. That tag triggers `job-release-image.yaml`, which builds and pushes the container image (`ghcr.io/cryptos-pki/manager`) via BuildKit and packages+pushes the Helm chart (`oci://ghcr.io/cryptos-pki/charts/fleet-manager`). The node ISO ships from [`cryptos`](https://github.com/CryptOS-PKI/cryptos). The image and chart assume no particular deploy environment — adopters bring their own registry, trust material, and orchestrator. (The repo's own release/governance tooling — release-drafter, `Bugs5382/changelog-updater-action`, golic — is the maintainer's; adopters don't need it.)

The release image is meant to be rebuildable from its tag. Every base image in the
`Dockerfile` is pinned by digest, the build date is the tagged commit's time rather than
the clock, and the release refuses to build until the `WEB_RELEASE_REF` repository
variable pins the `web` checkout to a tag or commit (falling back to `web`'s `main` would
embed whatever was there that day). A pull request that touches the image runs
`.github/workflows/ci-image.yaml`, which builds it without pushing, runs it read-only with
every capability dropped against a Postgres container, and checks that it turns healthy,
that the node-creds volume is owned by 65532, and that `/healthz` answers 503 once the
database is stopped.

## 🚦 Status

**Alpha.** Read-only fleet integration, mTLS client-cert auth, durable Postgres state (enrollments and the hash-chained audit log, which now records the acting operator), and the MCP endpoint with direct and step-up tools are implemented; the broader inventory write paths are in progress.

## 📡 Fleet API

The FleetService and BootstrapService API this manager serves is defined here, in [`proto/cryptos/fleet/v1`](proto/cryptos/fleet/v1) (package `cryptos.fleet.v1`), with the Go and connect-go stubs under [`gen/go/cryptos/fleet/v1`](gen/go/cryptos/fleet/v1). The fleet protos import the node API from [`cryptos-node`](https://github.com/CryptOS-PKI/cryptos-node) at the version `go.mod` pins: `task proto:deps` copies those protos into `.deps/`, and the generated code imports the node stubs from `github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1`. Change a `.proto` (or bump the cryptos-node pin), run `task generate`, and commit the regenerated tree in the same change; `task ci` fails when `gen/` is stale. Codegen needs [`buf`](https://buf.build) on `PATH`.

## 🧭 Companion repos

- 🧠 [`cryptos-node`](https://github.com/CryptOS-PKI/cryptos-node) — the OS / engine that runs the CAs this FM manages, and the home of the node API (`cryptos.node.v1`) the FM calls.
- 🎨 [`cryptos-web`](https://github.com/CryptOS-PKI/cryptos-web) — the FM's web frontend (its `apps/console` bundle is served by this repo).

## 🙏 Acknowledgements

CryptOS was originally written by [@Bugs5382](https://github.com/Bugs5382).

## 📄 License

[Apache License 2.0](LICENSE). Copyright The CryptOS Authors.
