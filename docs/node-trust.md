# 🔐 Node trust: how the manager and a node verify each other

The manager talks to each node over mutual TLS, and both sides check the other
on every connection. This page says what each side checks, what to do before
upgrading to a manager that refuses unverified nodes, how to pin a node, and
what changes when the node gets its CA.

## 🤝 What each side checks

| Side | What it checks | When |
| --- | --- | --- |
| The node | The manager's admin client certificate, against the admin trust in the node's config. | Always. A manager without the right admin key is refused. |
| The manager | The node's management server certificate, against the node's recorded CA chain or its pinned certificate. | Always. A node it can't verify is refused. |

The manager accepts the node's certificate when either of these vouches for it:

- **The recorded CA chain.** The certificate chains to the node's CA chain and
  is valid for the host in the node's endpoint (the IP or DNS name the manager
  dials). A node listed in the config file gets its chain from `caCertPath`. An
  adopted node gets it from `ca.crt`, which the manager writes next to the
  node's admin certificate when the node gets its CA.
- **The pin.** The certificate is the one saved as `server.crt` next to the
  node's admin certificate. It is the same file `cryptosctl --trust` takes.

A node with neither is refused, and so is one whose certificate matches
neither. The manager reads both files on every connection, so a new pin or
chain takes effect without a restart.

## ⚠️ Before you upgrade

> [!WARNING]
> Before upgrading to this version, make sure every node is either pinned
> (`server.crt`, or the fingerprint recorded at adoption) or has a recorded CA
> chain. Unpinned nodes are refused after the upgrade: nothing can be read from
> them and every operation on them fails until you pin them.

A recorded CA chain only verifies a node that signs its management certificate
with its CA. A node on a CryptOS release that still makes a self-signed
management certificate every boot needs a pin, even when its `caCertPath` is
set.

### List the nodes that would be refused

With the new release's binary, `-check-node-trust` prints one line per node and
exits 1 if any node would be refused. It reads the config file and opens the
database the way a start does (applying the schema), but it does not serve, so
on a standalone install you can run it before switching over. Run it on the manager host, with the same config file and
`MANAGER_DATABASE_URL` the manager uses:

```sh
./manager -config /etc/cryptos/fleet/config.yaml -check-node-trust
```

```text
node trust: pki-root (192.0.2.10:443): pinned
node trust: pki-issuing (192.0.2.11:443): REFUSED: no CA chain is recorded and no server certificate is pinned; pin it at /var/lib/cryptos-manager/node-creds/pki-issuing/server.crt or with -pin-node
```

Without the new binary, check the files by hand. A node is pinned when a
`server.crt` sits in the folder of its admin certificate:

- **An adopted node:** `$MANAGER_NODE_CREDS_DIR/<node name>/`, by default
  `/var/lib/cryptos-manager/node-creds/<node name>/`. Managers before this
  version never wrote a pin at adoption, so an adopted node is unpinned unless
  you pinned it yourself. On the manager host:

  ```sh
  for d in /var/lib/cryptos-manager/node-creds/*/; do [ -f "$d/server.crt" ] || echo "unpinned: $(basename "$d")"; done
  ```

- **A node listed in the config file:** the folder of its `adminCertPath`. With
  the Helm chart's `adminCredsSecret`, the pin is the Secret's `server.crt` key.
  An empty result means the node is unpinned:

  ```sh
  kubectl -n fleet get secret pki-root-admin -o jsonpath='{.data.server\.crt}'
  ```

On Kubernetes the manager's image has no shell, so the files on the node
credentials claim can't be listed from the pod. After the upgrade, run the
check through the manager binary instead:

```sh
kubectl -n fleet exec deploy/fleet-manager -- /manager -config /etc/cryptos/fleet/config.yaml -check-node-trust
```

After an upgrade the manager also logs one `node trust:` line per node at
startup, with `REFUSED` on each node it will refuse.

### Pin each node

Pin every node the check lists, using [Pin a node](#-pin-a-node). A node listed
in the config file can be pinned before the upgrade: older managers ignore
`server.crt`, so the file waits harmlessly until the new version reads it. An
adopted node on Kubernetes can only be pinned with `-pin-node` once the new
version runs, so it is refused from the upgrade until you pin it; plan that
window.

## 🧭 What adoption records

Adoption records what the manager needs to verify the node afterwards:

1. The fingerprint you confirm in the adopt wizard pins the node's
   maintenance-mode certificate for the install steps.
2. The installed node boots with a new management certificate. Nothing links
   it to the maintenance certificate you confirmed, so adoption pauses on the
   `awaiting-fingerprint-confirmation` phase and shows the fingerprint the
   node presents:

   ```text
   the node is back in running mode and presents certificate sha256 5a0e...c3. Compare it with the Mgmt SHA-256 line on the node's console and confirm it to continue
   ```

   > [!CAUTION]
   > Compare the fingerprint with the `Mgmt SHA-256` line on the node's
   > console before you confirm it. If they differ, something other than your
   > node answered on its address: choose "Does not match" in the wizard and
   > find out what answered before you adopt again.

   Confirming (the adopt wizard, or `ConfirmAdoptionFingerprint` with the
   stream's `adoption_id`) resumes the adoption. Only then does the manager
   save that certificate as the node's `server.crt` and dial the node,
   verified against it. The comparison ignores case, colons and spaces.

   The adoption stops, and nothing is pinned, recorded or registered, when:

   - the confirmed fingerprint differs from the presented one (the call and
     the adoption fail with `InvalidArgument`);
   - nobody confirms within 15 minutes (`DeadlineExceeded`);
   - the wizard cancels or the adoption stream is closed.

   The manager admin credential minted for the adoption stays, so adopting
   the node again resumes from here. Both a confirmation and a refused
   fingerprint are audited (`node-adoption-fingerprint-confirmed`,
   `node-adoption-fingerprint-rejected`) with the operator who sent it.

   > [!WARNING]
   > The waiting adoption lives in the manager replica that runs the adoption
   > stream. With `replicaCount` above 1, a confirmation that reaches another
   > replica returns `NotFound`; send it again so it reaches the replica that
   > holds the stream, or adopt with a single replica.

3. A root's ceremony gives it its CA. The manager reads the CA chain from the
   node and saves it as `ca.crt` next to the admin certificate. An intermediate
   or issuing node gets its CA when its subordinate enrollment is approved, and
   the manager saves the signed chain the same way.

A retried adoption asks you to confirm the certificate the node presents
again, then replaces the node's old `server.crt` with it. A root that has
already run its ceremony presents a CA-signed certificate by then; confirm that
one the same way.

## 🔄 When the node gets its CA

Before its CA exists, a node presents a self-signed management certificate and
makes a new one every boot, so its pin holds only until the next reboot.

Once the node signs its management certificate with its CA, the recorded chain
verifies it, across reboots, and the pin is no longer needed. The switch needs
no action: while the node still presents the pinned self-signed certificate the
pin accepts it, and once it presents the CA-signed one the chain accepts it.
The certificate must name the host in the node's endpoint; if the manager dials
a name the certificate does not list, the chain check fails.

## 📌 Pin a node

The pin is a file named `server.crt` in the same folder as the node's admin
certificate:

- **An adopted node:** `$MANAGER_NODE_CREDS_DIR/<node name>/server.crt`, next to
  the `admin.crt` the manager wrote at adoption. The folder defaults to
  `/var/lib/cryptos-manager/node-creds`.
- **A node listed in the config file:** the folder of its `adminCertPath`, or
  the `server.crt` key of its Helm `adminCredsSecret`.

### With the manager binary

Read the fingerprint on the node's console. It is the `Mgmt SHA-256` line, in
capitals and in groups of four characters. Then give it to `-pin-node`, which
fetches the certificate the node presents and saves it only if the fingerprints
match (case, spaces and colons are ignored). On the manager host:

```sh
./manager -config /etc/cryptos/fleet/config.yaml -pin-node pki-root -expect-sha256 "5A0E 91C4 ..."
```

On Kubernetes:

```sh
kubectl -n fleet exec deploy/fleet-manager -- /manager -config /etc/cryptos/fleet/config.yaml -pin-node pki-root -expect-sha256 "5A0E 91C4 ..."
```

A node whose admin certificate sits in a read-only Secret can't be pinned this
way; add `server.crt` to the Secret instead (below).

### By hand

1. Read the fingerprint on the node's console, as above.

2. Save the certificate the node presents. Run this where the manager can reach
   the node, with the node's address and port.

   **Linux / macOS**

   ```sh
   openssl s_client -connect 192.0.2.20:443 </dev/null 2>/dev/null | openssl x509 -out server.crt
   ```

   **Windows (PowerShell)**

   ```powershell
   $null | openssl s_client -connect 192.0.2.20:443 2>$null | openssl x509 -out server.crt
   ```

3. Check the saved certificate's fingerprint:

   ```sh
   openssl x509 -in server.crt -noout -fingerprint -sha256
   ```

   > [!CAUTION]
   > The fingerprint must match the `Mgmt SHA-256` line on the node's console,
   > ignoring colons, spaces and case. If it doesn't, you reached something
   > other than your node. Don't install the file; find out what answered on
   > that address first.

4. Put `server.crt` in the node's folder (above), readable by the manager, or
   add it to the node's admin Secret by recreating the Secret with the new key
   next to the files it already holds:

   ```sh
   kubectl -n fleet create secret generic pki-root-admin --from-file=admin.crt --from-file=admin.key --from-file=ca.pem --from-file=server.crt --dry-run=client -o yaml | kubectl apply -f -
   ```

   The manager reads the pin on every connection, so the new key takes effect
   once Kubernetes updates the mounted Secret, without a restart.

## ⛔ When the manager refuses a node

Every call to a refused node fails, the manager logs why, and the fleet view
shows the node down with the same text in its health detail (inside the gRPC
connection error). A node with nothing to verify against:

```text
nodeclient: node pki-root refused: its server certificate (sha256 5a0e...c3) cannot be verified: no CA chain is recorded and no server certificate is pinned. Check the fingerprint against the Mgmt SHA-256 line on the node's console, then pin it by saving the certificate as /var/lib/cryptos-manager/node-creds/pki-root/server.crt or with manager -pin-node "pki-root" -expect-sha256 <fingerprint>
```

A node whose certificate matches neither its chain nor its pin, typically a
node that rebooted before its CA ceremony:

```text
nodeclient: node pki-root refused: its server certificate (sha256 5a0e...c3) does not match the pinned server certificate /var/lib/cryptos-manager/node-creds/pki-root/server.crt: x509: certificate signed by unknown authority (...). If the node rebooted before its CA ceremony it has a new certificate: check it against the node's console and re-pin it
```

Pin the node's current certificate again with [Pin a node](#-pin-a-node).

> [!CAUTION]
> Compare the new certificate with the node's console, not with the fingerprint
> in the error. The error shows what answered on the node's address, which is
> exactly what you have not checked yet.

> [!WARNING]
> Before its CA exists, a pinned node is refused after every reboot until you
> re-pin it. Plan a re-pin into any reboot of a node that has no CA yet.

## 🧪 Skipping verification in a lab

A node listed in the config file can set `insecureSkipNodeVerify: true`, and the
Helm chart takes the same key in `nodes[]`:

```yaml
nodes:
  - name: lab-root
    endpoint: "192.0.2.30:443"
    role: root
    adminCertPath: /etc/cryptos/fleet/lab-root/admin.crt
    adminKeyPath: /etc/cryptos/fleet/lab-root/admin.key
    insecureSkipNodeVerify: true
```

> [!CAUTION]
> `insecureSkipNodeVerify` is for lab testing only and must never be used in
> production. The manager does not check which server it reached, so anything
> that answers on the node's address is treated as the node. There is no switch
> that turns verification off for every node.

With it set, the manager logs a warning for the node at startup and on every
connection, and the fleet view shows the node's health detail as
`server certificate not verified: insecureSkipNodeVerify is set (lab testing only)`.
The key is read from the config file at each start and matched by node name,
so a node renamed in the manager is verified again.

## 🪪 Linking a running node

A `LINK` enrollment checks the node another way: at request and at approval,
the node proves it holds its CA identity key, and approval is refused if that
key changed in between. This check does not use `server.crt`.
