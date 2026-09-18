# Deploying the Fleet Manager standalone (systemd, no Kubernetes)

The README documents Kubernetes and `docker compose`. This covers a third case
that turns out to be the common one for a small fleet: **a single Linux host,
systemd, local Postgres, no container runtime**. It also records the traps found
doing it for real, several of which are not obvious from the other docs.

Throughout, the placeholder organisation is **ACME** (`acme.example`). Replace
it with your own.

## 0. Before you start: there may be no image to pull

The README's `docker run ghcr.io/cryptos-pki/manager:vX.Y.Z` and
`helm install ... oci://ghcr.io/cryptos-pki/charts/fleet-manager` both require a
**published release**. Releases are cut by hand (see *Releasing*), and the image
and chart are built by the tag. Until the first tag exists, neither path
resolves and you must build from source:

```sh
git clone --depth 1 https://github.com/CryptOS-PKI/manager.git
cd manager
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o cryptos-fleet-manager ./cmd/manager
```

The `web` bundle is embedded via `go:embed`, so this single static binary is the
whole application — no separate frontend build, no Node toolchain on the target
host. Build on a workstation and copy the binary; the target needs nothing but
glibc-free Linux and Postgres.

## 1. `--trust` is NOT your fleet CA chain

**This is the single easiest mistake to make.** A CryptOS node presents an
**ephemeral self-signed server certificate** whose subject is the node's own
address (`CN=10.0.0.20`), *not* a certificate issued by the CA that node
operates. Passing your fleet's CA chain to `cryptosctl --trust` therefore fails:

```console
$ cryptosctl --endpoint 10.0.0.20:443 --trust acme-ca-chain.pem status
cryptosctl: rpc error: code = Unavailable desc = connection error:
  desc = "transport: authentication handshake failed: tls: failed to verify
  certificate: x509: certificate signed by unknown authority"
```

The error reads like a broken chain. It is not — it is the wrong *kind* of
anchor. The node relies on **client**-auth for its security; server identity is
deliberately weak. Capture the node's own presented certificate and use that:

```sh
openssl s_client -connect 10.0.0.20:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform pem > node-10.0.0.20.pem

cryptosctl --endpoint 10.0.0.20:443 \
  --identity admin.crt --identity-key admin.key \
  --trust node-10.0.0.20.pem status
```

Two distinct things are easy to conflate:

| Setting | What it is |
| --- | --- |
| `cryptosctl --trust` | the **node's self-signed server cert** (TLS anchor) |
| manager `nodes[].caCertPath` | the node's **CA identity chain** — root = 1 cert, intermediate = 2 certs `[intermediate, root]` |

They are different files and are not interchangeable.

## 2. There is no `config get` — `apply` can silently drop your profiles

`cryptosctl config` exposes only `apply`:

```console
$ cryptosctl config --help
Available Commands:
  apply       Apply a machine configuration
```

There is **no way to read a node's current `machine.yaml` back off the node**,
and `apply` takes a *complete* configuration. So if you applied a profile at
some point (say a server profile for one host) and later apply a config built
from your original file, that profile is **silently removed** — no warning, and
`ca list-issued` is the only way you'd notice.

Keep the authoritative `machine.yaml` in version control and treat it as the
only source of truth. Never hand-build an `apply` payload from memory.

> Related: profiles are also not readable via any `config`/`ca` verb, because
> the hot-apply normaliser zeroes the `Profiles` field. `ca list-issued` is the
> only evidence a profile took effect.

## 3. The operator CA does not have to be a CryptOS node

[`operator-pki.md`](operator-pki.md) walks through provisioning a **dedicated
CryptOS node** as the operator CA, then a three-command CSR ferry to chain it
under the fleet root. That is the dogfooding path and it is correct, but it
assumes you have a spare node.

For a two-node fleet (one root, one intermediate) there is no third node, and
standing one up means a new machine plus a subordinate ceremony. You usually
don't need it: **`operatorCAPath` is just the client-auth trust anchor.** The
manager accepts any certificate issued by that CA at the handshake and then
reads the level extension to decide privilege. Nothing requires the operator CA
to be CryptOS-issued.

A plain OpenSSL operator CA is sufficient, and it has a real advantage: it needs
**no `config apply` against a production CA node at all**.

```sh
# Operator CA — 10y, may issue leaves but no further sub-CAs.
openssl ecparam -name secp384r1 -genkey -noout -out operator-ca.key
chmod 600 operator-ca.key
openssl req -x509 -new -key operator-ca.key -sha384 -days 3650 \
  -subj "/C=US/O=ACME/CN=ACME Operator CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out operator-ca.crt
```

**Trade-off to understand before choosing this:** every certificate your fleet
CA issues that carries `clientAuth` EKU would *also* satisfy a handshake if you
instead pointed `operatorCAPath` at the fleet intermediate. Use a **separate**
operator CA (as above) rather than reusing the fleet intermediate, so the set of
certs that can open a TLS session to the management plane stays exactly the set
you minted for operators.

### The level extension in OpenSSL form

`operator-pki.md` gives the level extension only as a YAML byte sequence for a
cryptos profile (`value: [19, 5, 97, 100, 109, 105, 110]`). When your operator
CA is OpenSSL, you need the same DER in `-extfile` form. These are identical
bytes — `0x13` is ASN.1 `PrintableString`, `0x05` its length:

```ini
# op-admin.ext
extendedKeyUsage = clientAuth
keyUsage = critical, digitalSignature
basicConstraints = critical, CA:FALSE
1.3.6.1.4.1.59999.1.1 = DER:13:05:61:64:6D:69:6E
```

`basicConstraints` matters: without it `openssl x509 -req -extfile` emits a v3
certificate carrying **no** basic constraints extension at all, which is not what the
cryptos profile path produces for a leaf and not what you want an operator credential to
look like. Pin it to `CA:FALSE` explicitly.

| Level | DER | `opext` bytes |
| --- | --- | --- |
| `viewer` | `DER:13:06:76:69:65:77:65:72` | `[19, 6, 118, 105, 101, 119, 101, 114]` |
| `operator` | `DER:13:08:6F:70:65:72:61:74:6F:72` | `[19, 8, 111, 112, 101, 114, 97, 116, 111, 114]` |
| `admin` | `DER:13:05:61:64:6D:69:6E` | `[19, 5, 97, 100, 109, 105, 110]` |

Mint and verify an operator certificate:

```sh
openssl ecparam -name secp384r1 -genkey -noout -out operator-admin.key
chmod 600 operator-admin.key
openssl req -new -key operator-admin.key -subj "/CN=you@acme.example" -out operator-admin.csr
openssl x509 -req -in operator-admin.csr -CA operator-ca.crt -CAkey operator-ca.key \
  -CAcreateserial -days 365 -sha384 -extfile op-admin.ext -out operator-admin.crt

openssl x509 -in operator-admin.crt -text -noout | grep -A2 '59999.1.1'   # ..admin
openssl verify -CAfile operator-ca.crt operator-admin.crt                 # OK

openssl pkcs12 -export -inkey operator-admin.key -in operator-admin.crt \
  -certfile operator-ca.crt -name "ACME operator (admin)" -out operator-admin.p12
```

Import the `.p12` into your OS/browser keystore; the browser offers it during
the manager's handshake.

## 4. Config key casing is not uniform

Most keys are camelCase, but two are snake_case. A camelCase spelling of either
is not an error — it is silently ignored, which reads as "the feature doesn't
work":

| snake_case (required) | Not `database_url` → `databaseUrl` |
| --- | --- |
| `database_url` | selects the Postgres store |
| `operator_ca_node` | enables operator-cert revocation checking |

Everything else — `listen`, `corsOrigins`, `authBypass`, `tlsCert`, `tlsKey`,
`operatorCAPath`, `httpRedirectListen`, `httpsPublicPort`, `nodes[].adminCertPath`,
`nodes[].adminKeyPath`, `nodes[].caCertPath` — is camelCase.

If `operator_ca_node` is unset the manager starts and logs:

```
manager: no operator_ca_node configured, operator-cert revocation not enforced
```

That is a real gap, not a cosmetic warning: a revoked operator certificate keeps
working until you set it.

## 5. A worked `config.yaml`

```yaml
listen: "0.0.0.0:443"

# Plaintext listener that only redirects to HTTPS, so an operator who types the
# hostname without a scheme reaches the login page instead of a refused
# connection. Omit it to disable the listener entirely.
httpRedirectListen: "0.0.0.0:80"

authBypass: false
tlsCert: "/etc/ssl/certs/fm.acme.example.fullchain.pem"
tlsKey: "/etc/ssl/private/fm.acme.example.key"
operatorCAPath: "/etc/cryptos/fleet/operator-ca.crt"

database_url: "postgres://manager:CHANGEME@127.0.0.1:5432/manager"

nodes:
  - name: pki-root
    endpoint: "10.0.0.20:443"
    role: root
    adminCertPath: "/etc/cryptos/fleet/pki-root/admin.crt"
    adminKeyPath: "/etc/cryptos/fleet/pki-root/admin.key"
    caCertPath: "/etc/cryptos/fleet/pki-root/ca.pem"      # 1 cert
  - name: pki-inter
    endpoint: "10.0.0.21:443"
    role: intermediate
    adminCertPath: "/etc/cryptos/fleet/pki-inter/admin.crt"
    adminKeyPath: "/etc/cryptos/fleet/pki-inter/admin.key"
    caCertPath: "/etc/cryptos/fleet/pki-inter/ca.pem"     # 2 certs [inter, root]
```

Database setup — the manager runs its own idempotent migrator and seeds the
catalog on first start, so an empty database is all you need:

```sh
sudo -u postgres psql -c "CREATE ROLE manager LOGIN PASSWORD 'CHANGEME';"
sudo -u postgres psql -c "CREATE DATABASE manager OWNER manager;"
```

Node `adminCertPath`/`adminKeyPath` are **not** required for the process to
start — the manager parses the node list and dials lazily, logging
`manager: N node(s) configured`. You can bring the UI up first and add node
credentials after.

### ⚠ The manager host holds a CA-admin client key

`adminKeyPath` is the private key of a credential that can drive your CA nodes'
management API. Putting the Fleet Manager on a host means **that host now holds
CA-admin authority**. This is inherent to the design — the FM is the thing that
operates the fleet — but treat the FM host as a tier-0 asset accordingly:
`0600 root`, full-disk encryption, and the same access controls as the CA nodes
themselves. The FM's *own* peer certificate deliberately lacks `keyCertSign`
and `cRLSign`, so the FM cannot sign certificates; the admin client key is a
separate and more powerful thing.

## 6. systemd unit

The manager binds 443, and 80 as well when `httpRedirectListen` is set. Both are
privileged. Grant the one capability rather than running as root -- it covers both
ports:

```ini
[Unit]
Description=CryptOS Fleet Manager
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
ExecStart=/usr/local/bin/cryptos-fleet-manager -config /etc/cryptos/fleet/config.yaml
Restart=on-failure
RestartSec=5s

User=fleetmgr
Group=fleetmgr
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictSUIDSGID=true
ReadOnlyPaths=/etc/cryptos/fleet /etc/ssl/certs /etc/ssl/private

[Install]
WantedBy=multi-user.target
```

The binary takes exactly one flag:

```console
$ cryptos-fleet-manager --help
Usage of /usr/local/bin/cryptos-fleet-manager:
  -config string
        path to the manager's YAML config file (default "config.yaml")
```

### Debian/Ubuntu: `/etc/ssl/private` will deny you

On Debian-family hosts `/etc/ssl/private` is `0710 root:ssl-cert`. A service
user that is not in `ssl-cert` **cannot traverse the directory**, so the key is
unreadable no matter what mode the key file itself has. The failure is:

```
manager: tls: load server cert: open /etc/ssl/private/fm.acme.example.key: permission denied
```

Note the manager gets as far as `using postgres store` and
`N node(s) configured` before this — Postgres and the node list are fine; only
TLS failed. Fix with the conventional group rather than loosening the
directory:

```sh
sudo usermod -aG ssl-cert fleetmgr
sudo chown root:ssl-cert /etc/ssl/private/fm.acme.example.key
sudo chmod 640 /etc/ssl/private/fm.acme.example.key
```

## 7. Verify without a browser

Prove the listener end to end before fighting keystore imports. **Read this section
rather than reusing an older copy of it:** the web surface is now served without a client
certificate on purpose, so "the page loaded without a cert" is no longer evidence of a
misconfiguration. The gate moved to the API.

```sh
FM=https://fm.acme.example
API=$FM/cryptos.fleet.v1.FleetService/WhoAmI

# 1. The web surface, with no client certificate. Expect 200 — by design.
curl -sS --cacert acme-ca-chain.pem $FM/ -o /dev/null -w '%{http_code}\n'

# 2. NEGATIVE CONTROL. The API with no client certificate must be 401.
curl -sS --cacert acme-ca-chain.pem -X POST -H 'Content-Type: application/json' \
  -d '{}' $API -w '\n%{http_code}\n'

# 3. The API with your operator certificate. Expect 200 and your own identity,
#    which also proves the level extension from section 3 parsed.
curl -sS --cacert acme-ca-chain.pem --cert operator-admin.crt --key operator-admin.key \
  -X POST -H 'Content-Type: application/json' -d '{}' $API -w '\n%{http_code}\n'

# 4. NEGATIVE CONTROL. A certificate from any other CA must fail the HANDSHAKE,
#    not merely be refused by the API. Expect a TLS error and no HTTP status.
curl -sS --cacert acme-ca-chain.pem --cert /tmp/unrelated.crt --key /tmp/unrelated.key \
  $FM/ -o /dev/null -w '%{http_code}\n'

# 5. The redirect. Expect 307 and a Location on https, path and query intact.
curl -sS -o /dev/null -D - http://fm.acme.example/fleet | grep -iE 'HTTP/|location'
```

Expected, verified against the built binary:

| # | Expected |
| --- | --- |
| 1 | `200` — the SPA serves anonymously so an operator with no certificate can be *told* that |
| 2 | `401` with body `client certificate required` — **this** is the negative control |
| 3 | `200` and `{"operator":{"cn":"you@acme.example","serial":"...","level":"admin"}}` |
| 4 | a TLS error and `000` for the status — here `alert unknown ca`, though the exact curl message and exit code vary by curl and OpenSSL build. The server logs `tls: failed to verify certificate: x509: certificate signed by unknown authority` |
| 5 | `307 Temporary Redirect`, `Location: https://fm.acme.example/fleet` |

Reading the results:

- **2 returning anything other than 401** — particularly `200` — means the API is not
  gated. That is the check that tells you `authBypass: true` is set somewhere, and that
  your management plane is open to anyone who can reach the port.
- **3 returning 403 `operator certificate missing access level`** means the handshake
  worked and the level extension did not. Re-mint with `op-admin.ext` from section 3,
  including `basicConstraints`, and confirm with
  `openssl x509 -in operator-admin.crt -text -noout | grep -A2 '59999.1.1'`.
- **4 returning a status at all** means the listener is trusting a CA you did not
  intend. Check `operatorCAPath`.
- The certificate is still *requested* during the handshake, so a browser holding one is
  still prompted to choose it. Cancelling that prompt now lands on the login page rather
  than `ERR_BAD_SSL_CLIENT_AUTH_CERT`, which is worth knowing because the old error was
  indistinguishable from having no certificate installed.

### Container: connect to the published port, not the listener

The image listens on **8443** for HTTPS and **8080** for the redirect, because it runs as
uid 65532 and cannot bind a privileged port. Publish them as the conventional pair and
address the published ports in every command above:

```sh
docker run -p 443:8443 -p 80:8080 \
  -v /etc/cryptos/fleet:/etc/cryptos/fleet:ro \
  ghcr.io/cryptos-pki/manager:vX.Y.Z
```

If you publish HTTPS on anything other than 443, set `httpsPublicPort` to the published
port as well. The redirect names the port clients reach, not the one the process bound,
so without it browsers get sent to a port nothing is listening on.

## 8. CRLs and OCSP come from the PKI nodes, not from here

Revocation material must be served over **`http://`, not `https://`**. A CDP or AIA URL
is fetched by a client in the middle of *building* the trust path, so serving it over TLS
that depends on that same chain is a bootstrap loop. RFC 5280 expects plain HTTP.

**The CryptOS nodes already do this, and the Fleet Manager plays no part in it.** Each
node serves `/crl` and `/ocsp` from its own anonymous plaintext listener on
`pki.revocation_http_port`, which defaults to **80** on the node. A relying party checking
a certificate talks to the node that issued it. Point `pki.revocation_base_url` at that
node and the CDP lands in the certificates it issues.

So do **not** run a static file server on port 80 of the manager host. Nothing needs to be
there, and since the redirect listener binds that port, the two would contend for it. If
you have a reason to serve files from the manager host's port 80 instead of the redirect,
leave `httpRedirectListen` unset and the manager will not bind it.

Two things this does not cover:

- **Trust rollout.** Getting the root and intermediate certificates into machine stores is
  an out-of-band job (Puppet, AD GPO, an image build). It is not an HTTP fetch and does
  not need a distribution point.
- **AIA (`caIssuers`).** CryptOS serves no `caIssuers` endpoint on any tier — the nodes
  expose `/crl` and `/ocsp` only. If you need an AIA URL, it needs its own static host,
  and that host should not be the manager's port 80 either.

## Related

- [`operator-pki.md`](operator-pki.md) — the dogfooded operator-CA-on-a-node path.
- ⚠ The level extension arc `1.3.6.1.4.1.59999.1.1` is a **placeholder**; an
  IANA Private Enterprise Number must replace it before GA, and the value has
  to change in lockstep in the cryptos profile config and
  `internal/authz/level.go`.
