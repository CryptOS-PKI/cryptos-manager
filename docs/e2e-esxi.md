# 🧪 The ESXi write-path exercise

`test/e2e/esxi` (`task e2e:esxi`) is a scripted, live proof that every write path the Fleet
Manager's public API exposes actually works against a real CryptOS node, not just against a fake
in a unit test. It stands up a throwaway manager of its own, bootstraps it with a throwaway
operator CA, links it to the node(s) a lab gate run (or the cryptos-lab tooling) already installed,
and drives each write path in turn, checking every result on the node itself.

It is the X1 gate for the cryptosctl-parity cutover (`feat(web)` tracking issue): once the web
covers every operation this script proves it still works end to end, the CLI stops being the
fallback.

## ⚙️ What it proves, and what it doesn't yet

Each run exercises, in order: profile create/apply/update/requestable/delete, an enrolment
protocol toggle, issuing and revoking a leaf certificate, a config-push round trip, the node's own
image status (stage/activate/rollback need a signed release image, below), a SCEP challenge
mint/list/revoke, re-keying a subordinate CA, exporting and importing an escrowed CA key, linking
and rejecting a node enrolment, the full operator-credential request/record/revoke/cancel cycle,
and decommissioning a node this run linked itself.

A few of those need a lab resource this run isn't always handed. The step still runs and says so
rather than silently passing:

| Needs | Without it |
| --- | --- |
| A spare node (`spare: true`, not in the manager's own static inventory) | Enrolment, escrow import and decommission report skipped |
| `E2E_REKEY_NODE` / `E2E_REKEY_PROFILE` | Re-key reports skipped: it is destructive to whatever node it targets, so it never runs without an explicit target |
| `E2E_IMAGE_URL` / `E2E_IMAGE_SIGNATURE_PATH` | Only `GetNodeImageStatus` runs; staging a real image needs a signed CryptOS release image and its detached signature, release-pipeline material this script isn't hard-coded to fetch |

> [!NOTE]
> Driving an actual SCEP device enrolment through a minted challenge (`ApproveNodeScepEnrollment`
> / `RejectNodeScepEnrollment`) needs a real RFC 8894 SCEP client talking to the node. This script
> proves challenge minting, listing and revocation; the enrolment-approval half is tracked as a
> follow-up (see the issue this change files alongside it).

## Before you start

- A lab gate run (or the cryptos-lab tooling) has already installed the node(s) you point this at,
  and you hold each one's admin certificate, admin key and (optionally) its CA chain file.
- Docker, for a throwaway Postgres container: the write paths this script proves (operator CAs,
  operator credentials, first run) only wire up with `database_url` set, not the in-memory store.
- `task` and a Go toolchain matching `go.mod`.
- This is lab-only. Never point `E2E_NODES_FILE` at a production node or FleetOS; the appliance's
  own lab/production separation rules apply here the same as everywhere else.

## 1. Write the nodes file

One entry per node, in the shape `internal/config.NodeCfg` already uses for the manager's own
`config.yaml`, plus `spare: true` on at most one of them:

```yaml
nodes:
  - name: pki-root
    endpoint: pki-root.example.org:4443
    role: root
    adminCertPath: /run/e2e-esxi/pki-root/admin.crt
    adminKeyPath: /run/e2e-esxi/pki-root/admin.key
    caCertPath: /run/e2e-esxi/pki-root/ca.pem
  - name: pki-intermediate
    endpoint: pki-intermediate.example.org:4443
    role: intermediate
    adminCertPath: /run/e2e-esxi/pki-intermediate/admin.crt
    adminKeyPath: /run/e2e-esxi/pki-intermediate/admin.key
    caCertPath: /run/e2e-esxi/pki-intermediate/ca.pem
  - name: pki-spare
    endpoint: pki-spare.example.org:4443
    role: issuing
    adminCertPath: /run/e2e-esxi/pki-spare/admin.crt
    adminKeyPath: /run/e2e-esxi/pki-spare/admin.key
    spare: true
```

The spare node is deliberately left out of the manager's own static inventory: this script links
it live, through `CreateEnrollment`/`ApproveEnrollment`, which is itself one of the write paths
under test.

## 2. Start a throwaway Postgres container

```sh
docker run -d --rm --name e2e-esxi-pg -e POSTGRES_PASSWORD=throwaway -p 15432:5432 postgres:18-alpine
```

## 3. Source an env file

| Setting | Required | What |
| --- | --- | --- |
| `E2E_DATABASE_URL` | yes | the throwaway Postgres DSN, for example `postgres://postgres:throwaway@127.0.0.1:15432/postgres?sslmode=disable` |
| `E2E_ADMIN_EMAIL` | yes | the CN this run's throwaway first-admin credential carries |
| `E2E_NODES_FILE` | yes | path to the file from step 1 |
| `E2E_WORKDIR` | yes | a tmpfs directory (for example under `/dev/shm`) for this run's own generated `config.yaml`; nothing durable is ever written here |
| `E2E_MANAGER_BIN` | yes, unless run through `task` | path to a built manager binary; `task e2e:esxi` builds and sets this for you |
| `E2E_STEP_TIMEOUT` | no | per-step timeout, a Go duration (default `2m`) |
| `E2E_REKEY_NODE` / `E2E_REKEY_PROFILE` | no | opts the re-key step in, against the named node under the named parent-signed profile |
| `E2E_IMAGE_URL` / `E2E_IMAGE_SIGNATURE_PATH` / `E2E_IMAGE_SHA256` | no | opts the image stage/activate/rollback steps in |

None of these values, or any node endpoint or address, ever reach this script's own stdout
unredacted: it redacts the same way the release gate does (`cryptos-appliance/test/gate/lib.sh`),
and so does the throwaway manager's own log output, which this script relays through the same
filter.

## 4. Run it

```sh
task e2e:esxi
```

It prints one line per step as it finishes (`ok`, `skip` or `FAIL`, the step name, and a short
result), then exits non-zero if anything genuinely failed (a skip is not a failure). Nothing it
creates outlives the run: the manager process stops, its generated `config.yaml` and the
throwaway operator CA's private key existed only in memory and under `E2E_WORKDIR`.

## ⚠️ Scope

No CI wiring yet: running this from a workflow needs runner-group access to the lab network for
`cryptos-manager`, a separate decision from this script existing. Run it by hand from this box
until that lands.
