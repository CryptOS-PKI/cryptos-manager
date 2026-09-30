# MCP endpoint for AI agents

The manager can serve a [Model Context Protocol](https://modelcontextprotocol.io)
endpoint at `/mcp` on its existing HTTPS listener, so an AI agent can read the fleet
and issue end-entity certificates through the same permission model as the web UI.
It is part of the manager binary; there is no separate service, sidecar or port.

The endpoint is **off by default**. This page covers enabling it, how an agent logs
in, what the agent can and cannot do, and how keys are managed and audited.

## How it fits

```
agent MCP client --HTTPS, no client cert, Authorization: Bearer fos_mcp_...--> manager :443
   /mcp                          -> key check (live operator identity) -> tool policy -> FleetService handlers
   /oauth2/*, /.well-known/*     -> one-time login; the consent step needs the operator certificate
   /cryptos.fleet.v1.FleetService/* -> client-certificate auth, unchanged
```

- **One permission model.** Every tool calls the same FleetService handler the web UI
  calls, in process, as the operator the key belongs to. The viewer, operator and admin
  checks in those handlers apply unchanged. A per-tool policy table is enforced before
  dispatch as a second check.
- **A key is identity only.** An MCP key stands for one operator certificate. What it may
  do is worked out again on every request from that certificate; nothing is cached.
- **Transport.** Stateless Streamable HTTP, built on the official Go MCP SDK
  (`github.com/modelcontextprotocol/go-sdk`).

## Enabling it

```yaml
# config.yaml
authBypass: false
operatorCAPath: "/etc/cryptos/fleet/operator-ca.crt"
operatorCRL:
  - url: "http://pki.example.org/fleetos-operator.crl"
database_url: "postgres://manager:CHANGEME@db:5432/manager"

mcp:
  enabled: true
  public_url: "https://fleetos.example.org"
```

| Key | Default | Meaning |
| --- | --- | --- |
| `mcp.enabled` | `false` | Serve `/mcp` and the login endpoints. |
| `mcp.public_url` | none | The manager's external `https` origin, with no path. It is the OAuth issuer, and `public_url` + `/mcp` is the resource agents connect to. It must be exactly what clients reach, including a non-default port. A trailing `/` is dropped. |

`public_url` is snake_case like `database_url`; the manager refuses unknown keys at
load, so a camelCase spelling fails to start (see
[deploying-standalone.md §4](deploying-standalone.md#4-config-key-casing-is-not-uniform)).

**The manager refuses to start** with `mcp.enabled: true` when any of these hold,
because a key could not be re-validated on each request:

- `authBypass: true` (there is no operator certificate to bind a key to);
- `database_url` is unset (the operator denylist, operator CAs and revocation epoch the
  keys are checked against live in Postgres);
- `public_url` is missing, not `https`, or has a path.

A key also needs its operator certificate's CA to have a **CRL source with a fresh CRL**.
That is checked when the key is created and on every call, not at start, so MCP can be
enabled before the CRL is set up; until then keys are refused with
[1608](error-codes.md) `NO_CRL` or `STALE_CRL`. See [operator-ca.md](operator-ca.md#mcp-needs-a-fresh-crl).

Keys and login state live in Postgres, so every replica shares them and a login can
start on one replica and finish on another.

### With the Helm chart

The in-repo chart (`chart/fleet-manager`) renders the same keys from its values:

| Value | Default | Renders as |
| --- | --- | --- |
| `mcp.enabled` | `false` | `mcp.enabled` |
| `mcp.publicURL` | `""` | `mcp.public_url` |

```sh
helm install fleet oci://ghcr.io/cryptos-pki/charts/fleet-manager --version X.Y.Z \
  --set tls.certSecret=<server-tls-secret> \
  --set operatorCA.configMap=<operator-ca-configmap> \
  --set mcp.enabled=true \
  --set mcp.publicURL=https://fleetos.example.org \
  --set-json 'nodes=[...]'
```

The chart applies the startup checks above at render time, so `helm install` and
`helm template` fail with a message instead of deploying a manager that refuses to
start:

- `mcp.enabled` with `authBypass: true`;
- `mcp.enabled` without `mcp.publicURL`.

With `authBypass: false` the chart already requires `database.existingSecret`. It does
not check the shape of `publicURL` (https, no path); the manager does, at startup. The
chart refuses to render the removed `operatorCANode` value.

## Logging in

An MCP client that supports MCP authorization (the `claude` CLI does) runs the login
by itself the first time it connects:

1. It calls `/mcp`, gets `401` with a `WWW-Authenticate` header pointing at
   `/.well-known/oauth-protected-resource/mcp` (RFC 9728), and discovers the
   authorization server at `/.well-known/oauth-authorization-server` (RFC 8414).
2. It registers itself at `/oauth2/register` (RFC 7591). Only `http` loopback redirect
   URIs are accepted: `127.0.0.1`, `[::1]` or `localhost`, on any port.
3. It opens your browser at `/oauth2/authorize` with PKCE (S256 only).
4. The browser lands on the web UI consent page. It needs your **operator certificate**,
   exactly like the rest of the UI: the certificate your browser presents is the login.
   The page shows the client's name, where the code will be sent, your CN and level, and
   lets you set a label and an optional **level ceiling** (viewer, operator, or up to your
   own level). A viewer-only key for a read-only agent is a good default.
5. On approval the browser hands a one-minute, single-use code to the client's loopback
   listener, and the client exchanges it at `/oauth2/token` for the key. The token
   response has no `expires_in` and no refresh token.

The login request waits 10 minutes for your decision. Denying it sends the client
`error=access_denied`.

**Clients without OAuth support** use the web UI's Agent keys page instead: **Create key**
mints a key with the same binding and shows it once (`CreateMcpKey` in the API).

## Client setup

The examples use `https://fleetos.example.org/mcp`; use your `public_url` + `/mcp`.

**The `claude` CLI** (drives the login itself):

```sh
claude mcp add --transport http fleetos https://fleetos.example.org/mcp
```

Then run `/mcp` in the CLI and choose **Authenticate**; your browser opens the
consent page. If the manager's server certificate comes from a private CA, point the
client at it first, for example `export NODE_EXTRA_CA_CERTS=/path/to/fleet-ca.pem`.

**Any client with a key from the Agent keys page:**

```sh
claude mcp add --transport http fleetos https://fleetos.example.org/mcp \
  --header "Authorization: Bearer $FLEETOS_MCP_KEY"
```

or, in a JSON MCP configuration:

```json
{
  "mcpServers": {
    "fleetos": {
      "type": "http",
      "url": "https://fleetos.example.org/mcp",
      "headers": { "Authorization": "Bearer ${FLEETOS_MCP_KEY}" }
    }
  }
}
```

Keep the key out of shell history and repositories. It starts with `fos_mcp_` so secret
scanners can spot a leaked one; revoke it on the Agent keys page if that happens.

## What an agent can do

These tools are registered. Each runs only when the key's effective level (see below)
meets the minimum. **Step-up** tools never run on the first call: they raise an approval
that a person decides in the web UI (see [Step-up approval](#step-up-approval)).

| Tool | FleetService call | Minimum level | Policy |
| --- | --- | --- | --- |
| `fleet_whoami` | WhoAmI | viewer | direct |
| `fleet_list_nodes` | ListNodes | viewer | direct |
| `fleet_get_node` | GetNode | viewer | direct |
| `fleet_get_node_config` | GetNodeConfig (read-only) | operator | direct |
| `cert_list` | ListCertificates | viewer | direct |
| `cert_get` | GetCertificate | viewer | direct |
| `cert_issue_from_csr` | IssueLeaf | operator | direct, or step-up (see below) |
| `cert_revoke` | RevokeCertificate | operator | step-up |
| `profile_list` | ListProfiles | viewer | direct |
| `profile_create` | CreateProfile | admin | step-up |
| `profile_update` | UpdateProfile | admin | step-up |
| `profile_delete` | DeleteProfile | admin | step-up |
| `profile_apply_to_node` | ApplyProfileToNode | admin | step-up |
| `adapter_list` | ListAdapters | viewer | direct |
| `adapter_set_enabled` | SetAdapterEnabled | admin | step-up |
| `audit_list` | ListAudit | viewer | direct |
| `enrollment_list` | ListEnrollments | viewer | direct |
| `enrollment_reject` | RejectEnrollment | operator | direct |
| `operator_credential_list` | ListOperatorCredentials | operator | direct |
| `approval_status` | none (the key's own approvals) | viewer | direct |

**`cert_get`** takes `node` and `serial_hex` (as `cert_list` shows them) and returns
`certificate_pem`, `chain_pem` (issuer first, up to the root) and `status` (`valid`,
`revoked` or `expired`, with `revoked_at` for a revoked one). A revoked or expired
certificate is still returned. An unknown serial is refused with
[1302](error-codes.md). The manager fetches the certificate from the issuing node with
its `GetIssuedCertificate` call, so the node must run a release that has it. Like every
MCP read, it is audited; the web UI's `GetCertificate` is not.

**`cert_issue_from_csr`** takes `node`, `profile`, `csr_pem` and, on the second call of a
step-up, `approval_id`. The agent generates its key pair locally and sends only the CSR.
An end-entity certificate on an intermediate or issuing node under a non-CA profile is
issued at once. Both the manager's inventory and the node's own configuration must agree
on the node's role, and the profile is read from the node itself. These cases are
step-up instead:

- the root node (by the inventory or by the node's own configuration);
- a profile with `basic_constraints.is_ca: true`;
- a CSR that asks for `cA=TRUE`.

An unknown node or a profile the node does not have is refused outright, before any
approval is raised.

The step-up tools take:

| Tool | Arguments |
| --- | --- |
| `cert_revoke` | `node`, `serial_hex`, `reason_code` (RFC 5280 CRLReason, default 0) |
| `profile_create`, `profile_update` | `profile`: the profile as JSON with proto field names, as `profile_list` shows it; unknown fields are refused |
| `profile_delete` | `name` |
| `profile_apply_to_node` | `profile` (catalog name), `node` |
| `adapter_set_enabled` | `name`, `enabled` |

Each also takes `approval_id`. The arguments are checked before an approval is raised,
so a person is never asked to approve a request that cannot run (an unknown node, a
missing profile, an existing profile name on create, a bad reason code).

## Step-up approval

A step-up call does not execute. It stores an approval and returns:

```json
{
  "status": "pending_approval",
  "approval_id": "apr-...",
  "approve_url": "https://fleetos.example.org/approvals?id=apr-...",
  "summary": "Revoke certificate 0A1B issued by node \"pki-issuing\" (issuing), reason 1 (keyCompromise). This cannot be undone.",
  "expires_at": "2026-09-29T18:15:00Z"
}
```

1. The agent shows the person the `summary` and the `approve_url` (built from
   `mcp.public_url`).
2. The person opens the Approvals page in the web UI with their **operator certificate**,
   reviews the summary and approves or denies. The approver's level must be at least the
   tool's minimum level (the approval's `required_level`). The same person who runs the
   agent may approve in their browser: the agent holds only its key, and the approvals
   calls never accept a key.
3. The agent polls `approval_status` with the `approval_id` until it is `approved`, then
   calls the **same tool with the same arguments plus `approval_id`**.

The second call runs only when all of these hold, and then marks the approval used:

- the approval was raised by this key, for this tool, with the same arguments (the
  SHA-256 of the canonical arguments, `approval_id` left out, must match);
- it is approved, not denied, not already used, and less than **15 minutes** old;
- the key's effective level, worked out live on this call, still meets the tool's
  minimum;
- the approver's level met the tool's minimum.

An approval runs exactly one call. It is marked used before the operation starts, so a
failed operation still uses it; call again without `approval_id` for a new one. The
refusals are [1008](error-codes.md) (no such approval), [1011](error-codes.md) (not
decided yet), [1012](error-codes.md) (different tool, arguments or key),
[1013](error-codes.md) (denied, expired or already used) and [1010](error-codes.md)
(approver level too low).

`approval_status` takes an optional `approval_id`. With one, it returns that approval
if this key raised it; without, every approval this key raised, newest first. The status
is `pending`, `approved`, `denied`, `expired` or `used`.

The Approvals page is backed by two FleetService calls, **operator certificate only**; an
MCP key gets [1007](error-codes.md):

- `ListApprovals`: every approval, newest first, optionally filtered by `status`. Any
  level may list.
- `DecideApproval`: approve (`approve: true`) or deny a pending approval. The decider's
  level must be at least `required_level` ([1010](error-codes.md)); an approval already
  decided or expired gives [1009](error-codes.md).

Approvals live in the store, so with Postgres the agent's request, the person's decision
and the agent's second call can each reach a different replica.

## What an agent cannot do

Not registered as tools at all:

- `ExportCAKey` and `ImportCAKey` (CA key material); `DecommissionNode`; `AdoptNode`,
  `PreviewAdoption` and `ListInstallDisks` (disk wipe and provisioning);
  `ConfirmAdoptionFingerprint` (a person confirms a new node's identity from its console);
  `ApplyNodeConfig` and `SetNodeProtocol` (a node's configuration and its enrolment
  endpoints); `RekeyNode`; `CreateEnrollment` and `ApproveEnrollment` (node admin
  credentials, subordinate signing); `RenameNode`; `RevokeOperatorCredential`, the
  operator credential request RPCs and the operator CA RPCs (operator certificates and
  the CAs that sign them are managed by people); MCP key management itself; and `ListApprovals` and `DecideApproval` (an agent never sees or
  decides approvals). Node-only operations stay in `cryptosctl`.

## Live checks on every call

For every `/mcp` request the manager:

1. hashes the bearer and looks up the key; a revoked key stops at once;
2. re-validates the certificate stored with the key: it must still chain to an operator
   CA trusted now, be inside its validity period, and not be on the denylist or in its
   CA's CRL; the CA must have a CRL within nextUpdate, and this replica's last denylist
   poll must be under 5 minutes old;
3. reads the level from the certificate; the **effective level** is the lower of that level
   and the key's ceiling.

Any failure is the same `401` with the `WWW-Authenticate` header; the reason goes only to
the log, never the key. A client that keeps sending bad keys gets `429` for a while.

What that means in practice:

- **The key is bound to the certificate serial.** Renewing or re-issuing the operator
  certificate ends its keys, and the operator logs in again. A role change is a re-issue,
  so old keys can never carry the old level.
- **Key revocation is immediate.** A denylist entry takes effect on the writing replica
  at once and on the others within about 5 seconds; a CA revocation takes effect when the
  manager next loads the CA's CRL.
- **Removing or retiring the operator CA** ends every key under it.
- The stored certificate is checked against the trusted operator CAs directly, so an
  operator certificate must chain to one of them without help from intermediates the
  browser would otherwise send.

## Managing keys

The web UI's Agent keys page, backed by these FleetService calls (operator certificate
only; an MCP key can never list, create or revoke keys):

- `ListMcpKeys`: your own keys, newest first, revoked ones included. An admin can list
  every operator's keys (`all: true`).
- `RevokeMcpKey`: revoke one of your keys; an admin can revoke any key. Revoking twice is
  harmless.
- `CreateMcpKey`: the manual fallback described above. The ceiling may not exceed your
  level ([1006](error-codes.md)), and it fails with [1004](error-codes.md) while
  `mcp.enabled` is false. Listing and revoking keep working when the endpoint is off.

Listings never include a key or its hash; only the SHA-256 of a key is stored.

## Audit

Every audit row now records who acted, whatever the surface:

| Field | Meaning |
| --- | --- |
| `actor_kind` | `cert` for an operator certificate, `mcp_key` for an MCP key |
| `actor_cn`, `actor_serial` | the operator certificate that acted, or that the key is bound to |
| `key_id` | the key, for MCP actions |
| `via` | `web` or `mcp` |
| `tool` | the MCP tool |
| `request_digest` | SHA-256 of the tool name and its arguments, to match a row to a request without storing it |
| `outcome` | `ok`, `denied`, `pending` or `error` |
| `approval_id` | the step-up approval the row belongs to |
| `approver_serial` | the operator certificate that approved it |

The actor fields are part of the hash chain; rows written before them keep verifying under
the older chain version.

MCP calls are audited **including reads** (`mcp-call` rows), because an agent enumerating
the fleet is itself worth seeing. A successful write, such as an issuance, appears as the
handler's own row (for example `issued`) carrying the key and tool. Key lifecycle events
are `mcp-key-created`, `mcp-key-first-used`, `mcp-key-revoked` and `mcp-key-rejected`
(a known key refused, with the reason). Web reads stay unaudited.

A step-up approval leaves this trail, each row with its `approval_id`:

| Kind | Actor | Notes |
| --- | --- | --- |
| `approval-requested` | the key and its operator | `outcome: pending`, with the tool and request digest |
| `approval-approved` / `approval-denied` | the deciding operator certificate | `approver_serial` set; the summary names the requester and key |
| `approval-decide-refused` | the operator certificate | `outcome: denied`, the decider's level was too low |
| `approval-used` | the key and its operator | `approver_serial` set |
| the operation's own row (for example `revoked`) | the key and its operator | `approval_id` and `approver_serial` set |
| `mcp-call` | the key and its operator | `outcome: denied` when a presented approval was refused |
