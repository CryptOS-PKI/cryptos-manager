# 🔐 Node trust: how the manager and a node verify each other

The manager talks to each node over mutual TLS. This page says what each side
checks, how to pin a node's server certificate so the manager checks it too, and
what to do when the node reboots.

## 🤝 What each side checks

| Side | What it checks | When |
| --- | --- | --- |
| The node | The manager's admin client certificate, against the admin trust in the node's config. | Always. A manager without the right admin key is refused. |
| The manager | The node's management server certificate, against a pinned copy. | Only when the node is pinned (below). |

A node that is not pinned is still dialed, but the manager does not check which
server it reached. It logs this once per node:

```text
nodeclient: node pki-root has no pinned server certificate (/var/lib/cryptos-manager/node-creds/pki-root/server.crt); its server certificate is not verified
```

## 🔄 Why the pin changes on every boot

A CryptOS node makes a new self-signed certificate for its management listener
every time it boots. The certificate is not signed by the node's CA, so the
node's CA chain (`nodes[].caCertPath`) can't be used to check it. It is the same
certificate `cryptosctl --trust` takes.

This means a pin holds until the node's next reboot. After a reboot the manager
refuses the node until you pin the new certificate.

During adoption, the fingerprint you confirm pins the node's maintenance-mode
certificate. That pin covers only the adoption steps up to the install. The
installed node boots with a new certificate, and the manager does not check it
unless you pin it.

## 📌 Pin a node

The pin is a file named `server.crt` in the same folder as the node's admin
certificate:

- **An adopted node:** `$MANAGER_NODE_CREDS_DIR/<node name>/server.crt`, next to
  the `admin.crt` the manager wrote at adoption. The folder defaults to
  `/var/lib/cryptos-manager/node-creds`.
- **A node listed in the config file:** the folder of its `adminCertPath`.

The manager reads the file on every connection, so a new or replaced file takes
effect without a restart.

1. Read the fingerprint on the node's console. It is the `Mgmt SHA-256` line,
   in capitals and in groups of four characters.

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

4. Put `server.crt` in the node's folder (above), readable by the manager.

## 🔁 Re-pin after the node reboots

After a pinned node reboots, every call the manager makes to it fails with an
error like this, and the manager logs the same line:

```text
nodeclient: node pki-root presented a server certificate (sha256 5a0e...c3) that does not match the pinned server certificate
```

Repeat [Pin a node](#-pin-a-node) with the node's new certificate and replace
`server.crt`.

> [!CAUTION]
> Compare the new certificate with the node's console, not with the fingerprint
> in the error. The error shows what answered on the node's address, which is
> exactly what you have not checked yet.

> [!WARNING]
> Until you re-pin, the manager can't reach the node: nothing can be read from
> it and every operation on it fails. Plan a re-pin into
> any reboot of a pinned node.

> [!WARNING]
> Before you adopt a node again under the same name, remove its old
> `server.crt`. The re-installed node presents a new certificate, and a stale
> pin makes the adoption fail while it waits for the node to come back.

To stop verifying a node, delete its `server.crt`.

## 🪪 Linking a running node

A `LINK` enrollment checks the node another way: at request and at approval,
the node proves it holds its CA identity key, and approval is refused if that
key changed in between. This check does not use `server.crt`.
