# 🪪 Operator CA: trust and revocation

Operators sign in to the Fleet Manager with a client certificate. The CA that
signs those certificates, the **operator CA**, is always **external**: an
offline OpenSSL CA, or an enterprise or offline CA that can issue the operator
profile. It is **never a CryptOS node**. The manager learns only the CA's
certificate (the trust anchor). It never holds the CA's key and never signs an
operator credential.

This page covers where the manager gets the anchor, how it checks revocation,
the config keys, and how to move off `operator_ca_node`.

## 🧭 Where the anchor comes from

The source is chosen only by what is configured:

| Source | When | Trust | Revocation |
| --- | --- | --- | --- |
| Config file | `operatorCAPath` set | The certificates in that PEM file | The denylist (needs Postgres), plus the CRLs from `operatorCRL` |
| Registered | No `operatorCAPath`, Postgres configured, `firstRun` not `disabled` | The active and retiring operator CAs stored in Postgres | The denylist, plus each CA's own CRL source |
| None | No `operatorCAPath`, and no Postgres or `firstRun: disabled` | Nothing | Nothing; every API caller is refused |
| Dev | `authBypass: true` | No certificates at all | n/a |

**The config file wins.** While `operatorCAPath` is set, any operator CA stored
in the database is ignored, and the manager logs so at start. Use the file for
GitOps-pinned deployments.

Every start, and every change to the trusted set, logs each trusted CA's subject
and SHA-256. Compare it with `openssl x509 -in operator-ca.crt -noout -fingerprint -sha256`
on the CA machine.

> [!CAUTION]
> The manager refuses to start when a certificate in `operatorCAPath` is a
> CryptOS node's CA, or has the same public key as one. Point `operatorCAPath`
> at your external operator CA only, not at a node's CA chain.

Trust is re-checked on every request, not only at the TLS handshake. A
certificate whose CA stops being trusted, or which is put on the denylist, is
refused on its next request, even over an open connection.

## 🚫 Revocation

A certificate is refused if any source lists it. Serials are unique per CA only,
so every source is keyed by the CA as well as the serial.

- **The denylist** is the Fleet Manager's own list, in Postgres, always on.
  `RevokeOperatorCredential` writes to it. The replica that writes enforces the
  entry at once and every other replica within about 5 seconds. It needs
  Postgres; without it, revoking returns
  [1603 DATABASE_REQUIRED](error-codes.md).
- **The CRL** is your CA's own revocation list, optional per CA. The manager
  fetches it (or reads the file), verifies it against the CA with the Go standard
  library, and refuses a CRL older than the one it holds. It refreshes every 15
  minutes and at the CRL's nextUpdate, and retries a failure after a minute,
  backing off to 15 minutes.

> [!WARNING]
> The denylist stops a credential at the Fleet Manager only. Other systems that
> trust the same CA don't see it. Revoke at your CA as well and publish a new CRL.

A CRL must be a complete, direct CRL for end-entity certificates, signed by the
operator CA itself, with a nextUpdate. Delta CRLs, indirect CRLs, CRLs limited to
CA certificates or to some reasons, and CRLs with an unknown critical extension
are refused. Entries on hold count as revoked while they are listed.

### When no fresh CRL is available

`operatorRevocationPolicy` decides what the web UI and API do when a CA's CRL is
past its nextUpdate, or a configured CRL has never been fetched:

| | `soft` (default) | `hard` |
| --- | --- | --- |
| Web UI and API | Keep enforcing the last good CRL and the denylist. Log hourly and audit `operator-crl-expired` once. | Refuse certificates under that CA with [1608 STALE_CRL](error-codes.md) until a fresh CRL loads. |
| MCP | Refused ([1608 STALE_CRL](error-codes.md)) | Refused |

> [!WARNING]
> With `hard`, an unreachable CRL URL locks every operator under that CA out of
> the web UI until the CRL publication point is fixed. Use it only with an
> automated, highly available CRL publication point.

A CA with no CRL source is checked against the denylist only; revocations made
at the CA are not seen.

### MCP needs a fresh CRL

MCP keys are long-lived, so they are held to a stricter rule. On every call, and
before a key is created, the bound certificate's CA must have a CRL source with a
CRL within nextUpdate, and this replica's last denylist poll must be under 5
minutes old. Otherwise the call is refused with
[1608](error-codes.md) `NO_CRL`, `STALE_CRL` or `STALE_DENYLIST`.

## ⚙️ Config keys

```yaml
# The external operator CA. Only this CA's certificates in the file.
operatorCAPath: /etc/cryptos/fleet/operator-ca/operator-ca.pem

# Optional: where the CRLs for those CAs come from. Each entry is a url
# (http or https) or a path, never both. Each CRL is matched to the CA
# that signed it, so every CA in the file needs one of these to cover it.
operatorCRL:
  - url: http://pki.example.org/fleetos-operator.crl
  # - path: /etc/cryptos/fleet/operator-crl/fleetos-operator.crl

# Optional: soft (default) or hard.
operatorRevocationPolicy: soft

# Optional: off, aia (default) or url, with url for mode url.
operatorOCSP:
  mode: aia

# Optional: auto (default) or disabled.
firstRun: auto
```

| Key | Default | Rules |
| --- | --- | --- |
| `operatorCAPath` | unset | A PEM file of operator CA certificates. |
| `operatorCRL` | none | Needs `operatorCAPath`. Each entry sets exactly one of `url` (http or https) and `path`. |
| `operatorRevocationPolicy` | `soft` | `soft` or `hard`. |
| `operatorOCSP.mode` | `aia` | `off`, `aia` or `url`. Needs `operatorCAPath`. |
| `operatorOCSP.url` | unset | Required with mode `url`, http or https; refused with any other mode. |
| `firstRun` | `auto` | `auto` or `disabled`. With `disabled` and no `operatorCAPath`, no operator CA is trusted. |

> [!NOTE]
> `operatorOCSP` is validated, but this version doesn't query OCSP responders
> yet. Revocation comes from the denylist and the CRL.

Unknown keys are refused at load, so a misspelt key fails loudly rather than
being ignored.

`mcp.enabled` needs `database_url` and `authBypass: false`. It no longer needs
`operator_ca_node` or `operatorCAPath`.

## 🧾 The self-signed bootstrap certificate

Without `tlsCert` and `tlsKey` the manager serves a self-signed certificate.
With Postgres it is stored there, so restarts and replicas serve the same one,
and it is replaced 7 days before it expires. It is deleted once `tlsCert` is
configured. Every start logs its fingerprint:

```
manager: WARNING serving a SELF-SIGNED bootstrap certificate, SHA-256 AB:CD:...:EF, valid until 2026-12-29; ...
```

> [!CAUTION]
> Compare that fingerprint with the one your browser shows before you trust the
> page.

## 🔁 Migrating from operator_ca_node

`operator_ca_node` named a CryptOS node as the operator CA. A node can't be the
operator CA any more, so the manager refuses to start with that key, and the
chart refuses to render `operatorCANode`, both with a message pointing here.

1. Create an external operator CA (for example the OpenSSL recipe in
   [deploying-standalone.md §3](deploying-standalone.md)) and issue new admin
   certificates from it.
2. Point `operatorCAPath` at it, and add `operatorCRL` if the CA publishes a CRL.
3. Remove `operator_ca_node` (in the chart, `operatorCANode`).
4. Restart and reconnect with a new certificate.
5. Remove the `operator-*` profiles from the node that used to issue operator
   certificates.

> [!WARNING]
> Operator certificates the node issued stop working at step 4: the node's CA
> can't be an operator CA. Install a certificate from the new CA before you
> restart.

Operator credential rows recorded before the change are kept and listed with
the kind `legacy_node`. Issuing an operator credential through the Fleet Manager
is gone; the external CA signs them. See
[operator-credentials.md](operator-credentials.md) for requesting, recording
and denying them.
