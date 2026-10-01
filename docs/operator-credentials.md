# 🎫 Operator credentials after day zero

The Fleet Manager never signs an operator credential. Your external operator CA
(see [operator-ca.md](operator-ca.md)) signs every one of them, out of band. The
manager's part is to prepare the request, check what the CA signed, record it,
and refuse it later if you deny it.

A new operator credential goes through four steps:

| Step | Who | Where |
| --- | --- | --- |
| 1. Request | An admin | The manager: `CreateOperatorCredentialRequest` |
| 2. Sign | The operator CA's operator | The CA machine: `openssl ca` or your CA's template |
| 3. Record | An admin | The manager: `RecordOperatorCredential` |
| 4. Deny, when needed | An admin | The manager (`RevokeOperatorCredential`) **and** the CA |

Requests and recorded credentials live in Postgres. Without `database_url`,
every step answers [1603 DATABASE_REQUIRED](error-codes.md). With no operator
CA configured at all, requesting, listing and recording answer
[1400](error-codes.md).

> [!NOTE]
> The web UI's request, record and deny screens are not in this release yet.
> Until they are, call the FleetService RPCs directly with your admin
> certificate.

## 📝 1. Request a credential

`CreateOperatorCredentialRequest{level, email, full_name, csr_der}` is
admin-only. The CSR comes from one of two places:

- **The admin's machine**, which then has to hand the key to the holder safely.
- **The holder's own machine.** The key never leaves the holder, which is the
  better choice when it is practical:

  ```sh
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out alice.key
  openssl req -new -key alice.key -sha384 -subj "/CN=alice@example.org" -out alice.csr
  openssl req -in alice.csr -outform DER -out alice.csr.der
  ```

> [!CAUTION]
> The CSR's subject must be exactly `CN=<email>`, with nothing else, and the key
> must be P-384 or RSA of 3072 bits or more. The email must match the request's
> `email` (case doesn't matter). Anything else is refused with
> [1606](error-codes.md) `SUBJECT_MISMATCH` or `KEY_TYPE`.

`full_name` is 1 to 128 characters with no control characters, and `level` is
`viewer`, `operator` or `admin`.

The request is stored as `pending` for 30 days and audited as
`operator-credential-requested`. The response carries what the CA operator
needs:

- `csr_pem`, the CSR to hand over;
- `extfile_section`, the OpenSSL section for the level, for example:

  ```ini
  [ op_operator ]
  basicConstraints       = critical, CA:FALSE
  keyUsage               = critical, digitalSignature
  extendedKeyUsage       = clientAuth
  subjectKeyIdentifier   = hash
  authorityKeyIdentifier = keyid
  1.3.6.1.4.1.59999.1.1  = DER:13:08:6F:70:65:72:61:74:6F:72
  ```

- `openssl_command`, the `openssl ca` command that signs it with that section.

`ListOperatorCredentialRequests` (operator level) lists requests newest first,
optionally only one `state`: `pending`, `completed`, `cancelled` or `expired`.
`CancelOperatorCredentialRequest` (admin) cancels a pending request and is
audited as `operator-credential-request-cancelled`. A request's CSR is dropped
once it is completed, cancelled or expired.

## ✍️ 2. Sign it at the operator CA

Sign the CSR with the section for the level. With the OpenSSL operator CA from
[deploying-standalone.md §3](deploying-standalone.md#3-the-operator-ca-is-an-external-ca),
the section is already in `operator-ca.cnf`, and the command is the one the
request returned:

```sh
openssl ca -config operator-ca.cnf -extensions op_operator -notext -in alice.csr -out alice.crt
openssl verify -CAfile operator-ca.crt alice.crt
```

An enterprise CA needs a template that gives the same profile: subject `CN` only,
EKU exactly `clientAuth`, key usage `digitalSignature`, `CA:FALSE`, and the level
extension.

> [!WARNING]
> The level extension `1.3.6.1.4.1.59999.1.1` must be **non-critical**. A
> certificate that marks it critical fails the TLS handshake, so its holder can't
> sign in at all. Recording checks this and refuses it with
> [1610](error-codes.md) `LEVEL_EXT_CRITICAL`.

## 📥 3. Record the signed certificate

`RecordOperatorCredential{cert_der, request_id, full_name}` is admin-only.
`cert_der` is exactly one DER certificate of at most 8 KiB.

- **With `request_id`**, the request must be `pending`, and the certificate's
  level, CN and public key must match it. The credential is recorded with the
  kind `requested`, and the request becomes `completed`.
- **Without it**, a certificate made entirely out of band is imported. Its level
  is read from the extension, and it is recorded with the kind `recorded`.
  `full_name` is optional.

Either way the certificate must pass the operator certificate profile (the
[operator-ca.md](operator-ca.md) rules), not be on the denylist or in the CA's
CRL, and not be recorded already. It is audited as
`operator-credential-recorded`, and the response lists any warnings, such as a
validity over 400 days.

> [!CAUTION]
> During an operator CA rotation, only certificates from the **active** CA can be
> recorded. One signed by the retiring CA is refused with
> [1610](error-codes.md) `NOT_ACTIVE_ANCHOR`. Sign new credentials with the new
> CA.

| Refusal | Why |
| --- | --- |
| 1610 `NOT_CHAINED` | No trusted operator CA signed it, or it doesn't verify for client auth |
| 1610 `NOT_ACTIVE_ANCHOR` | The retiring operator CA signed it |
| 1610 `WRONG_LEVEL`, `SUBJECT_MISMATCH`, `KEY_MISMATCH` | It doesn't match the request |
| 1610 `DUPLICATE` | It is already recorded |
| 1610 `REVOKED` | It is on the denylist or in the CA's CRL |
| 1610 `EKU`, `KEY_USAGE`, `BASIC_CONSTRAINTS`, `KEY_TYPE`, `EXPIRING` | It breaks the profile |
| 1611 `NOT_FOUND`, `EXPIRED`, `NOT_PENDING` | The request can't be used |

Once it is recorded, the holder needs the certificate and key together as a
PKCS#12 file, built where the key is:

```sh
openssl pkcs12 -export -inkey alice.key -in alice.crt -certfile operator-ca.crt \
  -name "FleetOS operator (alice@example.org)" -out alice.p12
```

## 👀 Credentials seen in use

With Postgres, the manager also records every operator certificate it sees
authenticate. The first request from a certificate it hasn't recorded writes one
row with the kind `observed`, holding the serial, issuer, CN, level and expiry.
Each credential's first and last seen times are kept, and the last seen time is
updated at most hourly. An observed certificate recorded later keeps its row and
becomes `recorded` or `requested`.

This is how the Operators page lists everyone who can actually sign in, including
certificates your CA signed that were never recorded, so each of them can be
denied. Recording runs in the background through a bounded queue: it never slows
a request, and when the queue is full a sighting is dropped (and logged) and
tried again on the certificate's next request.

## ⛔ 4. Deny a credential

`RevokeOperatorCredential{serial_hex, issuer_sha256, reason_code, note}` is
admin-only. It puts the serial on the Fleet Manager's denylist under the operator
CA, and the certificate is refused from its next request: at once on the
replica that wrote it, and within about 5 seconds on the others.

- `serial_hex` is the certificate serial in hex; colons, case and leading zeros
  don't matter. A serial the manager never recorded can be denied too.
- `issuer_sha256` is the operator CA's SHA-256 fingerprint. Leave it empty to use
  the recorded credential's CA, or the active CA if the serial isn't recorded.
- `reason_code` is an RFC 5280 CRL reason: 0 to 10, except 7.
- `note` is kept with the denylist entry.

The denial is audited as `operator-revoked`. It never contacts a node.

> [!WARNING]
> Denying a credential in the Fleet Manager does **not** revoke it at your
> operator CA. Other systems that trust the same CA still accept it. Revoke it at
> the CA as well, and publish a new CRL:
>
> ```sh
> openssl ca -config operator-ca.cnf -revoke alice.crt -crl_reason keyCompromise
> openssl ca -config operator-ca.cnf -gencrl -out fleetos-operator.crl.pem
> ```

## 📋 Listing credentials

`ListOperatorCredentials` (operator level) lists every credential the manager
knows, with:

| Field | Meaning |
| --- | --- |
| `kind` | `first_admin`, `requested`, `recorded`, `observed`, or `legacy_node` (issued by a node before external operator CAs; read-only, it can't sign in) |
| `issuer_sha256` | The operator CA that signed it; empty for `legacy_node` |
| `denylisted` | On the Fleet Manager's denylist |
| `crl_revoked` | Listed in the operator CA's CRL |
| `revoked` | Refused by any source |
| `first_seen_at`, `last_seen_at` | When it was first and last seen signing in |

None of these RPCs is offered to MCP agents: operator credentials are managed by
people.

## 🔢 The level extension

An operator certificate carries its access level in the extension
`1.3.6.1.4.1.59999.1.1` (`authz.AccessLevelOID`): the DER of an ASN.1
PrintableString of `viewer`, `operator` or `admin`.

| Level | OpenSSL `DER:` value | `opext` bytes |
| --- | --- | --- |
| `viewer` | `DER:13:06:76:69:65:77:65:72` | `[19, 6, 118, 105, 101, 119, 101, 114]` |
| `operator` | `DER:13:08:6F:70:65:72:61:74:6F:72` | `[19, 8, 111, 112, 101, 114, 97, 116, 111, 114]` |
| `admin` | `DER:13:05:61:64:6D:69:6E` | `[19, 5, 97, 100, 109, 105, 110]` |

`go run ./cmd/opext -level <level>` prints the byte form from the same encoding
the manager reads.

> [!NOTE]
> `1.3.6.1.4.1.59999.1.1` is a placeholder arc. An IANA Private Enterprise
> Number replaces it before GA.
