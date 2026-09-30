# Operator PKI — client-cert auth for the Fleet Manager

> [!WARNING]
> A CryptOS node can no longer be the operator CA. The node-hosted operator
> sub-CA, the `operator-*` profiles on a node and `operator_ca_node` described
> below are refused by the manager. Use an external operator CA: see
> [operator-ca.md](operator-ca.md) and
> [deploying-standalone.md §3](deploying-standalone.md#3-the-operator-ca-is-an-external-ca).
> The level extension and `opext` sections below still apply.

The Fleet Manager's management plane authenticates operators by **mTLS client
certificate**, issued by the fleet's own PKI (the manager dogfoods the system it
manages). There are no usernames or passwords: the certificate your browser
presents during the TLS handshake *is* the login, and no certificate means no
access.

An operator certificate carries the operator's **access level** in a custom
X.509 extension:

- **OID:** `1.3.6.1.4.1.59999.1.1`
  (`authz.AccessLevelOID`). This is a **placeholder** arc.
  **TODO: register an IANA Private Enterprise Number before GA** and replace it
  — the value must stay identical in the cryptos profile config and the manager
  verifier, which share the constant in `internal/authz/level.go`.
- **Value:** the DER of an ASN.1 string of the level token — `viewer`,
  `operator`, or `admin`. The cryptos profile field `extra_extensions[].value`
  is a Go `[]byte`, which yaml.v3 decodes from a **YAML sequence of byte
  integers** (it does not base64-decode a scalar string into `[]byte`). Produce
  the exact sequence to paste into config with the `opext` helper:

  ```console
  $ go run ./cmd/opext -level viewer
  [19, 6, 118, 105, 101, 119, 101, 114]
  $ go run ./cmd/opext -level operator
  [19, 8, 111, 112, 101, 114, 97, 116, 111, 114]
  $ go run ./cmd/opext -level admin
  [19, 5, 97, 100, 109, 105, 110]
  ```

  (A future cryptos enhancement could add a custom `UnmarshalYAML` to
  `X509Extension` so a base64 string works too; until then, the byte sequence is
  the form the parser accepts.)

Levels are cumulative: `viewer` sees the read-only surfaces; `operator` adds
issue/revoke and enrollment approval (when write paths land); `admin` adds
profiles, adapters, and config.

## 1. Operator issuing profiles (cryptos `machine.yaml`)

On the CryptOS node that will host the operator CA, add these profiles under
`pki.profiles` in the node config. The node reads its config from
`/var/lib/cryptos/config/machine.yaml`; on first boot it is staged from
`EFI/cryptos/machine.yaml` on the boot partition, and thereafter it can be
updated via the node's ApplyConfig RPC. Fill each `value:` from `opext` above.

```yaml
pki:
  profiles:
    - name: operator-sub-ca
      key_alg: "ECDSA-P384"
      subject:
        common_name: "ACME Operator CA"
        organization: "ACME"
        country: "US"
      validity_days: 3650
      basic_constraints:
        is_ca: true
        path_len: 0
      key_usage: ["cert_sign", "crl_sign"]
    - name: operator-viewer
      key_alg: "ECDSA-P384"
      subject:
        common_name: "placeholder"   # replaced by the CSR subject at issuance
      validity_days: 365
      basic_constraints:
        is_ca: false
      key_usage: ["digital_signature"]
      ext_key_usage: ["client_auth"]
      extra_extensions:
        - oid: "1.3.6.1.4.1.59999.1.1"
          critical: false
          value: [19, 6, 118, 105, 101, 119, 101, 114]   # opext -level viewer
    - name: operator-operator
      key_alg: "ECDSA-P384"
      subject:
        common_name: "placeholder"
      validity_days: 365
      basic_constraints:
        is_ca: false
      key_usage: ["digital_signature"]
      ext_key_usage: ["client_auth"]
      extra_extensions:
        - oid: "1.3.6.1.4.1.59999.1.1"
          critical: false
          value: [19, 8, 111, 112, 101, 114, 97, 116, 111, 114]   # opext -level operator
    - name: operator-admin
      key_alg: "ECDSA-P384"
      subject:
        common_name: "placeholder"
      validity_days: 365
      basic_constraints:
        is_ca: false
      key_usage: ["digital_signature"]
      ext_key_usage: ["client_auth"]
      extra_extensions:
        - oid: "1.3.6.1.4.1.59999.1.1"
          critical: false
          value: [19, 5, 97, 100, 109, 105, 110]   # opext -level admin
```

The `operator-sub-ca` profile is a CA profile (`is_ca: true`, `path_len: 0`)
so the operator CA can issue leaves but no further sub-CAs. The three
`operator-<level>` profiles are end-entity profiles (`is_ca: false`) with the
`client_auth` extended key usage and the level extension.

## 2. Stand up the operator sub-CA (subordinate ceremony)

Provision a CryptOS node designated as the operator CA. On first boot it stages
its own subordinate-CA CSR and waits for a parent signature. Ferry the CSR to
the fleet root, sign it under `operator-sub-ca`, and return the chain. All three
commands use `cryptosctl`'s global connection flags (`--endpoint`,
`--identity`, `--identity-key`, `--trust`). `--trust` is the node's own
management certificate, a different file for each node, not your CA chain (see
[deploying-standalone.md](deploying-standalone.md#1---trust-is-not-your-fleet-ca-chain)).

`cryptosctl` prints the CSR and the signed chain on standard output, so save
them with a redirect. `-o` picks the output format (`human`, `json` or `yaml`);
it does not name a file.

**Linux / macOS**

```bash
# On the operator-CA node (child): save its subordinate-CA CSR.
cryptosctl --endpoint pki-operca.example.org:443 \
  --identity admin.crt --identity-key admin.key --trust pki-operca.crt \
  ca get-subordinate-csr > operca.csr

# On the fleet root (parent): sign it under the operator-sub-ca profile.
cryptosctl --endpoint pki-root.example.org:443 \
  --identity admin.crt --identity-key admin.key --trust pki-root.crt \
  ca sign-subordinate --csr operca.csr --profile operator-sub-ca > operca-chain.pem

# Back on the operator-CA node (child): adopt the signed chain.
cryptosctl --endpoint pki-operca.example.org:443 \
  --identity admin.crt --identity-key admin.key --trust pki-operca.crt \
  ca submit-subordinate-cert --chain operca-chain.pem
```

**Windows (PowerShell)**

```powershell
# On the operator-CA node (child): save its subordinate-CA CSR.
cryptosctl --endpoint pki-operca.example.org:443 `
  --identity admin.crt --identity-key admin.key --trust pki-operca.crt `
  ca get-subordinate-csr | Out-File -Encoding ascii operca.csr

# On the fleet root (parent): sign it under the operator-sub-ca profile.
cryptosctl --endpoint pki-root.example.org:443 `
  --identity admin.crt --identity-key admin.key --trust pki-root.crt `
  ca sign-subordinate --csr operca.csr --profile operator-sub-ca | Out-File -Encoding ascii operca-chain.pem

# Back on the operator-CA node (child): adopt the signed chain.
cryptosctl --endpoint pki-operca.example.org:443 `
  --identity admin.crt --identity-key admin.key --trust pki-operca.crt `
  ca submit-subordinate-cert --chain operca-chain.pem
```

> [!CAUTION]
> In Windows PowerShell 5.1, `>` writes UTF-16 text, which `cryptosctl` and
> `openssl` can't read back. Use `Out-File -Encoding ascii` as shown.

## 3. Mint the first `admin` operator certificate

Generate an operator key and CSR (standard OpenSSL), then issue an end-entity
leaf under the `operator-admin` profile from the operator CA:

```bash
openssl ecparam -name secp384r1 -genkey -noout -out operator-admin.key
openssl req -new -key operator-admin.key -subj "/CN=you@acme.example" -out operator-admin.csr
```

**Linux / macOS**

```bash
cryptosctl --endpoint pki-operca.example.org:443 \
  --identity admin.crt --identity-key admin.key --trust pki-operca.crt \
  ca issue-leaf --csr operator-admin.csr --profile operator-admin > operator-admin.crt
```

**Windows (PowerShell)**

```powershell
cryptosctl --endpoint pki-operca.example.org:443 `
  --identity admin.crt --identity-key admin.key --trust pki-operca.crt `
  ca issue-leaf --csr operator-admin.csr --profile operator-admin | Out-File -Encoding ascii operator-admin.crt
```

Confirm the level extension is present:

```bash
openssl x509 -in operator-admin.crt -text -noout | grep -A1 "1.3.6.1.4.1.59999.1.1"
```

## 4. Install the certificate in your browser

Bundle the key and certificate into a PKCS#12 file and import it into your
OS/browser keystore. The browser presents it automatically during the manager's
TLS handshake.

```bash
openssl pkcs12 -export -inkey operator-admin.key -in operator-admin.crt \
  -name "CryptOS operator (admin)" -out operator-admin.p12
```

## 5. Point the manager at the operator CA

The manager's `operatorCAPath` config setting is the **operator sub-CA
certificate** (PEM). Any operator certificate issued by that CA is accepted at
the TLS handshake; the level extension then decides the operator's privilege.
See the manager config for `tlsCert` / `tlsKey` (the server certificate) and
`operatorCAPath` (the client-auth trust anchor).
