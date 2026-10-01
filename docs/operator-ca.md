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
| Config file | `operatorCAPath` set | The certificates in that PEM file | The denylist (needs Postgres), plus the CRLs from `operatorCRL`, plus OCSP per `operatorOCSP` |
| Registered | No `operatorCAPath`, Postgres configured, `firstRun` not `disabled` | The active and retiring operator CAs stored in Postgres | The denylist, plus each CA's own CRL source, plus OCSP per the CA's OCSP mode |
| None | No `operatorCAPath`, and no Postgres or `firstRun: disabled` | Nothing | Nothing; every API caller is refused |
| Dev | `authBypass: true` | No certificates at all | n/a |

Registered CAs come from first run ([first-run.md](first-run.md)): the holder
of the bootstrap token registers the CA's certificate.

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
- **OCSP** is your CA's live answer about one certificate, optional per CA. It
  can only add a refusal: `revoked` refuses with
  [1610 REVOKED_OCSP](error-codes.md), and `unknown` counts as revoked
  ([1610 OCSP_UNKNOWN](error-codes.md), audited `operator-ocsp-unknown`). A
  `good` answer never overrides the denylist or the CRL.

> [!WARNING]
> The denylist stops a credential at the Fleet Manager only. Other systems that
> trust the same CA don't see it. Revoke at your CA as well and publish a new CRL.

A CRL must be a complete, direct CRL for end-entity certificates, signed by the
operator CA itself, with a nextUpdate. Delta CRLs, indirect CRLs, CRLs limited to
CA certificates or to some reasons, and CRLs with an unknown critical extension
are refused. Entries on hold count as revoked while they are listed.

### OCSP

Each operator CA has an OCSP mode (`operatorOCSP.mode` for the config file, the
CA's own setting when registered):

| Mode | Responder |
| --- | --- |
| `aia` (default) | The OCSP URI in the operator certificate's authorityInfoAccess. A certificate without one gets no OCSP check. The URI is read only after the certificate has been verified to chain to the CA, so only the CA can choose it. |
| `url` | The URL you set (`operatorOCSP.url`, or the CA's OCSP URL). The certificate's own URI is ignored. |
| `off` | No OCSP. |

The manager asks with an HTTP POST carrying a 32-byte nonce, and falls back to
GET only when the responder answers POST with 405 and the base64 request is
under 255 bytes. Fetches follow the CRL limits: http or https only, a 10 second
timeout, at most 3 redirects, no proxy from the environment, and a 64 KiB
response cap.

A response is used only if it is a successful basic response for exactly the
requested certificate (hash algorithm, CA name and key hashes, serial), its
thisUpdate is at most 5 minutes ahead and its nextUpdate hasn't passed, and it
is signed by one of:

- the operator CA itself;
- a delegated responder certificate issued **directly** by the operator CA, with
  the `OCSPSigning` extended key usage, valid now, and named by the response's
  responder ID. With `noCheck` it isn't revocation-checked; without it, it must
  not be on the CA's denylist or CRL.

A nonce echoed in the response must match; a response without one is accepted,
because responders for offline CAs often pre-sign. Anything else counts as no
response, and is logged with the responder URL and `OCSP_INVALID` or
`OCSP_UNREACHABLE`, never with the response body.

> [!CAUTION]
> The manager refuses responses from an expired delegated responder
> certificate. Renew it before it expires, or every check falls back to the CRL
> and then to `operatorRevocationPolicy`.

Each replica caches answers in memory for the response's nextUpdate, at most 1
hour, or 5 minutes when the response has no nextUpdate. A certificate in use is
re-checked in the background half way through that time; idle entries just
expire. Concurrent requests for the same certificate share one fetch, and a
failed fetch is remembered for 30 seconds so a dead responder doesn't slow every
request. A denylist entry still refuses a certificate at once, whatever the
cache holds.

When OCSP is configured for a certificate but there is no fresh response, the
manager falls back to the CA's CRL: with a CRL within nextUpdate, the
certificate is allowed unless the CRL lists it. With no fresh CRL either,
`operatorRevocationPolicy` decides (below).

### When no fresh revocation data is available

`operatorRevocationPolicy` decides what the web UI and API do when a CA's CRL is
past its nextUpdate, a configured CRL has never been fetched, or OCSP is
configured for the certificate with no fresh response and no fresh CRL to fall
back on:

| | `soft` (default) | `hard` |
| --- | --- | --- |
| Web UI and API | Keep enforcing the last good CRL and the denylist. Log hourly and audit `operator-crl-expired` once per expiry; for OCSP, show the `OCSP responder unreachable` banner, log hourly and audit `operator-ocsp-unavailable` once per outage. | Refuse certificates under that CA with [1608 STALE_OCSP](error-codes.md) when OCSP was configured for the certificate, otherwise [1608 STALE_CRL](error-codes.md). A certificate with a fresh OCSP `good` is still allowed with a stale CRL. |
| MCP | Refused ([1608 STALE_CRL](error-codes.md)) | Refused |

> [!WARNING]
> With `hard`, an unreachable CRL URL or OCSP responder locks every operator
> under that CA out of the web UI until the CRL publication point or the
> responder is fixed. Use it only with an automated, highly available CRL
> publication point and responder.

A CA with no CRL source and OCSP off (or `aia` and certificates without an OCSP
URI) is checked against the denylist only; revocations made at the CA are not
seen. With OCSP on, the CA's revocations are seen through OCSP only.

### MCP needs a fresh CRL

MCP keys are long-lived, so they are held to a stricter rule. On every call, and
before a key is created, the bound certificate's CA must have a CRL source with a
CRL within nextUpdate, and this replica's last denylist poll must be under 5
minutes old. Otherwise the call is refused with
[1608](error-codes.md) `NO_CRL`, `STALE_CRL` or `STALE_DENYLIST`. A fresh OCSP
`good` doesn't replace the CRL here.

When OCSP is configured for the bound certificate and a fresh response is
available, it must be `good`: `revoked` or `unknown` refuse with
[1610](error-codes.md) `REVOKED_OCSP` or `OCSP_UNKNOWN`. An OCSP failure is
allowed, because the fresh CRL covers it.

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

Unknown keys are refused at load, so a misspelt key fails loudly rather than
being ignored.

With the Helm chart these keys come from values: `operatorCRL.urls` gives the `url`
entries; `operatorCRL.configMap` names a ConfigMap of CRL files, mounted read-only at
`/etc/cryptos/fleet/operator-crl`, and `operatorCRL.files` lists the keys to load as `path`
entries. The manager re-reads those files on every refresh, so an updated ConfigMap
reaches it without a restart (the kubelet takes up to a minute or two to update the
mount). `operatorRevocationPolicy` and `operatorOCSP.mode`/`operatorOCSP.url` pass
through. A config change rolls the pod.

```yaml
operatorCRL:
  urls:
    - http://pki.example.org/fleetos-operator.crl
  configMap: fm-operator-crl
  files:
    - fleetos-operator.crl.pem
operatorRevocationPolicy: soft
operatorOCSP:
  mode: aia
```

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
