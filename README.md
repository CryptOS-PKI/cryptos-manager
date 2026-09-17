# 🛰️ manager

The Fleet Manager backend for [CryptOS-PKI](https://github.com/CryptOS-PKI). Optional control plane that talks to many CryptOS CA nodes over mTLS gRPC and serves the [`web`](https://github.com/CryptOS-PKI/web) frontend at the same TLS listener.

## ✨ What it does

- 🌳 **Cross-node visibility.** Walks every linked node's declared `role`, `parent`, and `pair` to render a multi-Root fleet topology. Each Root is sovereign; the FM never crosses Root trust boundaries on its own.
- 📚 **Inventory.** Tracks issued certificates, revocation status, and audit deltas across the fleet. Persists to Postgres (cross-node inventory only — per-node state stays on each node's embedded etcd).
- 📜 **Declarative pushes.** When linked, an FM operator can push `MachineConfig` updates to nodes; nodes verify signatures and apply on next reboot.
- 🚫 **Never an issuance authority.** The FM's peer cert lacks `keyCertSign` and `cRLSign`. The FM cannot sign certificates, even if compromised. Each Root retains full control.

## 🔗 Linking model

A node is linked to the FM via **mutual consent**: the operator declares the FM's URL + trust anchor in the node's machine config and reboots; the node calls the FM's `EnrollNode` with a TPM EK attestation; the FM operator approves in the UI; the FM issues the node a 90-day peer cert (EKU `clientAuth` only). Either side can revoke or unlink.

Once linked, the node's embedded operator surface becomes read-only and FM owns day-to-day operations. Unlinking is a config change + reboot. A node that has never been linked is managed via [`cryptosctl`](https://github.com/CryptOS-PKI/cryptos) only — no web UI in that case (by design — there's no web frontend on the CA image).

## 🧱 Stack

- Go backend, served behind mTLS TLS 1.3.
- Postgres for cross-node inventory.
- Serves the [`web`](https://github.com/CryptOS-PKI/web) bundle (pinned version, embedded via `embed.FS`) on the same listener as the FM gRPC API.
- Designed to run on Kubernetes (Deployment + Service + Ingress, Helm chart shipped alongside the container image). Single-node Docker / `docker compose` is supported for small deployments; K8s is the primary target.

## 🚀 Deploying

The manager ships as a **single self-contained image**: the Go binary with the `web` bundle embedded (`go:embed`), serving the SPA and the Connect API on **one** listener. In a real deployment that listener does mTLS client-cert auth (`authBypass: false`), so operators authenticate with a browser-installed client certificate — see [`docs/operator-pki.md`](docs/operator-pki.md) for minting an operator cert.

Bring your own trust material: a **server TLS cert** (`tlsCert`/`tlsKey`, any public or CryptOS-issued cert) and the **operator CA** (`operatorCAPath`, the client-auth trust anchor). No usernames or passwords are stored.

**Docker:**

```sh
docker run -p 443:8443 -p 80:8080 \
  -v /etc/cryptos/fleet:/etc/cryptos/fleet:ro \
  ghcr.io/cryptos-pki/manager:vX.Y.Z
# config.yaml (authBypass:false, tlsCert/tlsKey, operatorCAPath, nodes[]) + the
# referenced cert/key/CA files live under the mounted /etc/cryptos/fleet.
```

Publish 80 as well as 443. The image listens on 8443 for HTTPS and, when
`httpRedirectListen` is set, on 8080 for a plaintext listener that does nothing but
redirect to HTTPS -- so an operator who types a hostname without a scheme reaches the
login page instead of a refused connection. Both are high ports because the image runs
as uid 65532 and cannot bind a privileged one; the published ports are the conventional
80 and 443.

The redirect names the **published** HTTPS port, not the one the container binds. If you
publish HTTPS somewhere other than 443, set `httpsPublicPort` to that port, or the
redirect will send browsers to a port nothing is listening on.

The web surface itself is reachable without an operator certificate: it serves a landing
page with a Log in action, and every API call still requires a certificate that verifies
against the operator CA.

**Helm (OCI):**

```sh
helm install fleet oci://ghcr.io/cryptos-pki/charts/fleet-manager --version X.Y.Z \
  --set tls.certSecret=<server-tls-secret> \
  --set operatorCA.configMap=<operator-ca-configmap> \
  --set-json 'nodes=[{"name":"pki-root","endpoint":"pki-root.example:443","role":"root","adminCertPath":"...","adminKeyPath":"...","caCertPath":"..."}]'
```

## 🗄️ State backend

The manager keeps its state either in memory or in Postgres, chosen by the `database_url` config key:

- **Unset (default).** An in-memory store seeded from the built-in catalog. Nothing persists across a restart. This is the offline-dev and test default.
- **Set to a Postgres DSN.** The manager applies its schema (a small idempotent migrator runs on every startup), seeds the catalog into an empty database on first run, and persists enrollments and the hash-chained audit log. Restarts keep pending enrollments and the audit trail; the seed is a no-op once any table has rows, so live data is never clobbered.

```yaml
# config.yaml
database_url: "postgres://manager:secret@db:5432/manager"
```

The persistence layer is hand-rolled: raw SQL over [`pgx`](https://github.com/jackc/pgx), a hand-written schema, and a tiny version-tracked migrator — no ORM.

The Postgres integration tests are gated on the `MANAGER_TEST_DATABASE_URL` env var and **skip** when it is unset, so `task ci` stays green without a database. To run them against a throwaway Postgres:

```sh
docker run -d --rm -e POSTGRES_PASSWORD=test -p 5433:5432 postgres:18-alpine
MANAGER_TEST_DATABASE_URL=postgres://postgres:test@localhost:5433/postgres \
  go test ./internal/store/... -v
```

## 📦 Releasing

Nothing tags automatically. On push to `main`, release-drafter categorises the merged conventional-commit PRs into the draft release notes, and [`Bugs5382/changelog-updater-action`](https://github.com/Bugs5382/changelog-updater-action) writes those notes into `CHANGELOG.md` (committed back to `main` as a `[skip ci]` pre-release commit). The maintainer then publishes the GitHub Release by hand, which creates the `vX.Y.Z` tag. That tag triggers `job-release-image.yaml`, which builds and pushes the container image (`ghcr.io/cryptos-pki/manager`) via BuildKit and packages+pushes the Helm chart (`oci://ghcr.io/cryptos-pki/charts/fleet-manager`). The node ISO ships from [`cryptos`](https://github.com/CryptOS-PKI/cryptos). The image and chart assume no particular deploy environment — adopters bring their own registry, trust material, and orchestrator. (The repo's own release/governance tooling — release-drafter, `Bugs5382/changelog-updater-action`, golic — is the maintainer's; adopters don't need it.)

## 🚦 Status

**Alpha.** Read-only fleet integration, mTLS client-cert auth, and durable Postgres state (enrollments and the hash-chained audit log) are implemented; the broader inventory write paths are in progress.

## 🧭 Companion repos

- 📡 [`api`](https://github.com/CryptOS-PKI/api) — shared `.proto` definitions and generated gRPC stubs.
- 🧠 [`cryptos`](https://github.com/CryptOS-PKI/cryptos) — the OS / engine that runs the CAs this FM manages.
- 🎨 [`web`](https://github.com/CryptOS-PKI/web) — the FM's web frontend (served by this repo).

## 📄 License

[Apache License 2.0](LICENSE). Copyright 2026 Shane.
