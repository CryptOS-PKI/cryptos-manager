# 🚀 First run

A Fleet Manager started with no operator CA can be stood up from nothing. It
prints a single-use **bootstrap token** in its log. Whoever holds the token
registers the external operator CA's certificate and checks the first admin
certificate that CA signed. The manager signs nothing: the session only teaches
it which CA to trust. First run closes for good the first time an admin
certificate signs in.

The user guide, with every step, is on the docs site under **Fleet Manager >
First run**. This page is the reference for how the manager behaves.

## ✅ When first run is open

First run is open only when all of these hold:

- `operatorCAPath` is unset (with it set, first run reports `NOT_APPLICABLE`);
- `authBypass` is false;
- `firstRun` is `auto` (the default), not `disabled`;
- `database_url` is set (without Postgres, first run reports `UNAVAILABLE` with
  `DATABASE_REQUIRED`);
- first run hasn't closed yet.

## 🎟️ The token

At start, and whenever the live token expires, the replica that holds the
`fleetos.bootstrap_token` advisory lock prints a banner:

```
manager: ================= FLEETOS FIRST RUN =================
manager: bootstrap token: fos_boot_7K3Q-M2XD-...-9FJA  (single use, expires 2026-09-30T15:04:05Z)
manager: server certificate SHA-256: AB:CD:...:EF  (check this in the browser first)
manager: open https://<this-host>/ and enter this token to register your operator CA certificate
manager: ======================================================
```

Find it with `grep 'bootstrap token'` on the log (PowerShell:
`Select-String 'bootstrap token'`). That also returns the self-signed
certificate warning, with the fingerprint to check first.

- The token is 256 random bits in Crockford base32, grouped in fours. Case,
  dashes and the letters O, I and L (read as 0, 1 and 1) don't matter when it is
  typed.
- It is printed once and never stored: Postgres holds only its SHA-256.
- It is single use. Starting a session consumes it and prints a new one at
  once, on the replica that served the call. It expires after 60 minutes.
- Only one token is live at a time; issuing a new one retires the old.

> [!CAUTION]
> Anyone who can read the manager's log can start first run. Keep log access
> as tight as access to the manager itself until first run is closed.

## 🔐 The session

`StartBootstrapSession{token}` returns a `fos_bsess_` secret. Send it in the
`Fleetos-Bootstrap-Session` request header, never in a cookie or a URL.

- Postgres holds only its SHA-256.
- It ends after 15 minutes without a call, or 60 minutes after it started.
- There is one live session. Starting a new one ends the old one, whose secret
  then gets 1604.
- It is good only for `RegisterOperatorCA` and `SubmitFirstAdminCertificate`.
  It is not a credential anywhere else in the API, on `/mcp` or for OAuth.

## 🪪 Registering the operator CA

`RegisterOperatorCA` takes the CA certificate (DER or PEM, at most 8 KiB,
exactly one), a CRL source and an OCSP mode:

- **CRL source:** `url` (fetched and checked now), `crl_der` (an initial CRL,
  checked now; later ones by upload) or `none`, which needs the `NO_CRL`
  acknowledgement. A CA with no CRL gets no MCP keys.
- **OCSP mode:** `aia` (default), `url` or `off`. In `url` mode the manager
  probes the responder now, asking about a random serial; no answer is
  `OCSP_UNREACHABLE`, a badly signed one `OCSP_INVALID`. The preview doesn't
  carry `ocsp_probe` details yet: a confirmed registration means the probe
  passed.

The CA must be a CA with `keyCertSign`, have 30 days left, hold a P-384, P-256
or RSA 3072+ key, and not be a CryptOS node's CA (by certificate or public
key). With a CRL source it also needs `cRLSign`. A CA issued by a node's CA is
allowed with a warning.

The first call returns a preview with the fingerprint and `admin_extfile`, the
OpenSSL section for an admin certificate. Call again with `confirm_sha256` set
to that fingerprint (the output of `openssl x509 -fingerprint -sha256` can be
pasted as is) to store and trust it, with no restart. Registering another CA
during first run retires the earlier one at once.

A new session keeps the registration but must confirm it again before it can
submit a certificate: call with `ca_cert_der` empty for the preview, then with
its `confirm_sha256`. With nothing registered, that preview is empty (no
`operator_ca`) and doesn't count as a failure.

## 👤 The first admin certificate

`SubmitFirstAdminCertificate{cert_der, csr_der?, full_name}` checks a
certificate the operator CA signed out of band against the confirmed CA:

- it verifies against the CA alone for client authentication;
- the level extension `1.3.6.1.4.1.59999.1.1` is present, **non-critical** and
  `admin`;
- EKU is exactly clientAuth, key usage has digitalSignature and no
  keyCertSign or cRLSign, and basicConstraints is present with CA:FALSE;
- the subject is exactly `CN=<email>`;
- the key is P-384 or RSA 3072+ (P-256 is refused for operator certificates);
- at least a day is left (over 400 days is a warning);
- it isn't on the denylist or in the CA's CRL, and where OCSP is configured
  for it, the CA's responder doesn't say `revoked` (`REVOKED_OCSP`) or
  `unknown` (`OCSP_UNKNOWN`). With no fresh revocation data,
  `operatorRevocationPolicy: hard` refuses with 1608 (`STALE_OCSP` or
  `STALE_CRL`); `soft` accepts.

With `csr_der`, the CSR must verify, carry the same key and the same email.
Without it, the call is a pre-flight for a certificate made entirely at the CA.
`full_name` is 1 to 128 characters with no control characters.

A later submission with a different certificate puts the earlier first-admin
certificate on the denylist (reason superseded).

## 🔒 Closing

The first API request from an admin certificate that chains to a trusted
operator CA and isn't revoked closes first run, from either operator CA
source. The manager ends every session, deletes every token, records the
certificate as the first admin if no pre-flight did, logs
`manager: first run CLOSED by <cn> (<serial>)` and writes `bootstrap-closed` to
the audit log. Viewer and operator certificates don't close it.

After that `GetBootstrapState` reports `CLOSED`, every session procedure
returns 1601 before it reads a token or session, and no banner is printed
again. Denying or retiring every admin doesn't reopen it; only the break-glass
reset does.

If a manager whose first run is closed ends up trusting no operator CA (for
example `operatorCAPath` was removed), it refuses every caller and logs why.

## 🧯 Break-glass: reopening first run

If every admin credential is lost, `manager -config <config> -reset-first-run`
reopens first run. It is an offline command: shell access to a host that can
reach the database is the authority, and it asks for nothing else.

> [!WARNING]
> Stop every replica first. The command refuses while a replica holds the
> `fleetos.bootstrap_token` lock, or while anything answers `/healthz` on the
> configured `listen` address. The health check only sees the host it runs
> on, so on Kubernetes scale the Deployment to zero before running it.

It then, in one transaction:

1. clears the latch and deletes every bootstrap session and token;
2. marks every registered operator CA `retired` (reason `reset`). The rows are
   kept for the record, and no certificate from any of them signs in after the
   next start;
3. keeps the operator denylist and the stored CRLs. A CA registered again keeps
   its earlier revocations.

It writes a `bootstrap-reset` audit row (actor kind `host`, via `cli`, with the
host name) and prints what it changed and this guidance:

```
The FM never held your operator CA key. If you believe the CA itself is compromised, create a new operator CA before registering again. Otherwise you may register the same CA again.
Revoke at your CA any credential you no longer trust, and publish a new CRL.
```

The next start is a fresh day zero with a new token. MCP keys bound to the old
certificates stop working on their own. With `operatorCAPath` set, the command
warns that first run stays `NOT_APPLICABLE`; with `firstRun: disabled`, that it
stays unavailable. There is no flag to revoke issued credentials: the manager
can't revoke at an external CA, so do that at the CA.

## 🚦 Limits

- **Per client address:** 5 failures, one back each minute. Then 1602.
- **Everyone:** 50 failures within an hour rotate the token and end the live
  session, with a new banner saying why.
- A failure is a bad token or session, or a refused CA, CRL, CSR or
  certificate. Behind a proxy every client shares the proxy's address;
  `X-Forwarded-For` isn't trusted.

## 🛡️ Transport

`BootstrapService` is mounted only on the HTTPS server, outside the
client-certificate middleware, and every procedure refuses a request that
didn't arrive over TLS. It is never on the `authBypass` plaintext listener or
the HTTP redirect listener. Cross-origin writes are refused unless the origin
is in `corsOrigins`. Request bodies are capped at 16 KiB, or 4 MiB plus a
little for `RegisterOperatorCA`, which can carry a CRL.

## 🧾 Audit

Rows written with actor kind `bootstrap_session`: `bootstrap-session-started`,
`operator-ca-registered`, `operator-first-admin-recorded`,
`operator-first-admin-superseded`, `bootstrap-token-rotated`. The latch closing
is written as `bootstrap-closed`, with the admin certificate as the actor, and
the break-glass reset as `bootstrap-reset`.
Neither the token nor the session secret appears in any audit row, error or log
line other than the token's own banner.

## ⚠️ A node's CA as the operator CA, found at runtime

The manager refuses a config-file operator CA that is a CryptOS node's CA at
start. If a node reached later reports a CA chain that holds a trusted
operator CA (the same certificate or key), the manager logs an ERROR and raises
an admin banner flag for that CA. It keeps trusting it until the next start, so
no admin is locked out mid-run. Replace it with an external operator CA.
