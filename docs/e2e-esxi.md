# 🧪 The live write-path exercise

`test/e2e/esxi` (`task e2e:esxi`) is a scripted, live proof that every write path the Fleet
Manager's public API exposes actually works against a real CryptOS node, not just against a fake
in a unit test. It stands up a throwaway manager of its own, bootstraps it with a throwaway
operator CA, links it to the node(s) a lab gate run (or the cryptos-lab tooling) already installed,
and drives each write path in turn, checking every result on the node itself.

It is the X1 gate for the cryptosctl-parity cutover (`feat(web)` tracking issue): once the web
covers every operation this script proves it still works end to end, the CLI stops being the
fallback.

## ⚙️ What it proves, and what it doesn't yet

Each run exercises, in order: profile create/apply/update/requestable/delete, a SCEP challenge
mint/list/revoke, a real RFC 8894 SCEP device enrolment through a minted challenge that is approved
through the manager and a second one that is rejected, an enrolment protocol toggle (EST or
ACME, whichever the node has on, since switching one off drops its stored settings), issuing and
revoking a leaf certificate, a config-push round trip, the node's own image status and, with a
signed image, the whole image lifecycle (stage, activate, roll back, activate again, waiting for
each reboot), re-keying a subordinate CA, exporting an escrowed CA key, linking and rejecting a node
enrolment, importing the escrowed key onto the linked node, the full operator-credential
request/record/revoke/cancel cycle, and decommissioning a node this run linked itself.

The SCEP device is a small client in `test/e2e/esxi/scepdevice.go`: it enrols with a fresh RSA
3072 identity, waits PENDING, and collects its certificate with CertPoll once the enrolment is
approved, or a FAILURE once it is rejected. Both outcomes are checked on the node too: the approved
certificate is in the node's own `ListIssued`, and the rejected enrolment has left its queue.

The image step leaves the node on the image it started on.

A few of those need a resource this run isn't always handed. The step still runs and says so
rather than silently passing:

| Needs | Without it |
| --- | --- |
| A spare node (`spare: true`, not in the manager's own static inventory) | Enrolment, escrow import and decommission report skipped |
| `E2E_REKEY_NODE` / `E2E_REKEY_PROFILE` | Re-key reports skipped: it is destructive to whatever node it targets, so it never runs without an explicit target |
| `E2E_IMAGE_URL` / `E2E_IMAGE_SIGNATURE_PATH` | Only `GetNodeImageStatus` runs; staging needs an image signed by the key the node's running image trusts, and the detached signature over it |
| `E2E_SCEP_URL`, and a `pki.scep.profiles` entry with `require_approval` on the primary node | The device enrolment reports skipped; the challenge mint/list/revoke still runs when the node has any SCEP profile |
| A software-key node for the escrow export (the primary, or the node `E2E_ESCROW_NODE` names) | The export fails: a TPM-held CA key is never exportable |

The nodes don't have to be on ESXi: the script only needs each node's management endpoint and its
admin credential. cryptos-appliance's QEMU full-image suite runs it on CI against its live Root and
Intermediate on every suite run, as one step group of that suite.

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
| `E2E_IMAGE_URL` / `E2E_IMAGE_SIGNATURE_PATH` / `E2E_IMAGE_SHA256` | no | opts the image stage/activate/rollback steps in; the image must differ from the one the primary node is running |
| `E2E_SCEP_URL` | no | the primary node's SCEP listener as this script reaches it, for example `http://pki-intermediate.example.org/scep`; opts the device enrolment in |
| `E2E_ESCROW_NODE` | no | the node the escrow export runs against (default the primary); name a software-key node when the primary holds its CA key in a TPM |
| `E2E_MANAGER_LISTEN` | no | the loopback address the throwaway manager binds (default `127.0.0.1:18443`) |
| `E2E_RESULTS_FILE` | no | where to write the step results as a JSON array (`name`, `status`, `detail`, details redacted) for a harness to report |

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

On CI it runs only inside cryptos-appliance's QEMU full-image suite, which builds the manager
from the pinned commit in `release/pins.yaml`. By hand it runs against any lab nodes you can reach.
Lab only either way: never production nodes or FleetOS.
