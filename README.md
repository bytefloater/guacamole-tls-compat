# guacamole-tls-compat

An LD_PRELOAD shim that lets [Apache Guacamole](https://guacamole.apache.org/) (`guacd`) connect to legacy RDP hosts that require TLS 1.2 and SHA-1 signed certificates.

## Problem

Guacamole's RDP support is built on FreeRDP, which uses OpenSSL 3 by default. OpenSSL 3 negotiates TLS 1.3 and rejects SHA-1 signed certificates at its default security level. Many legacy Windows hosts don't support TLS 1.3 and ship with SHA-1 signed RDP certificates — the result is a TLS handshake failure before any connection is established.

## How it works

When guacd connects to an RDP host, the shim checks the destination IP against a config file. If the IP is listed, it applies three TLS adjustments to that connection before the handshake begins. All other connections are untouched.

**The three adjustments:**

| Setting | Why |
|---|---|
| TLS max version → 1.2 | Legacy Schannel rejects TLS 1.3 ClientHello |
| Security level → 0 | Permits SHA-1 signed server certificates |
| sigalgs list includes `RSA+SHA1` | RFC 5246 requires the server cert's algorithm to appear in the client's list |

Settings are applied to the individual `SSL` connection object, not the shared `SSL_CTX`, so they affect only the matched connection.

**Why `SSL_set_bio` is the interception point:**

LD_PRELOAD only intercepts calls made from outside a shared library. FreeRDP calls `SSL_set_bio()` directly from its own code to attach a socket to the SSL object — this is the earliest point where the destination IP is known and the call is visible to LD_PRELOAD. Handshake functions (`SSL_connect`, `SSL_do_handshake`) are called internally within libssl and are invisible to LD_PRELOAD. `SSL_set_fd` is also intercepted as a fallback for older FreeRDP versions.

The shim is injected only into `guacd` via a systemd drop-in. No other process on the host is affected.

## Supported legacy hosts

A **legacy host** is any RDP server whose Schannel requires all of the following from the connecting client:

- TLS max version ≤ 1.2
- SHA-1 signed server certificate accepted
- `RSA+SHA1` present in the `signature_algorithms` extension
- RSA key exchange (no ECDHE)

| Host | Notes |
|---|---|
| Windows Server 2008 / 2008 R2 | Supports TLS 1.0/1.1 only natively |
| Windows Server 2012 / 2012 R2 | Standard configuration; SHA-1 RDP cert; no TLS 1.3 |
| Windows XP + [Legacy Update](https://legacyupdate.net/) | Requires KB4019276 (TLS 1.2 backport) and KB948963 (AES ciphers) |

> **Windows XP:** Cipher overlap with OpenSSL 3 at security level 0 exists (`AES-128-CBC-SHA`, `AES-256-CBC-SHA`, `3DES-EDE-CBC-SHA`). Whether XP's backported TLS 1.2 correctly handles the `signature_algorithms` extension is untested — it may silently ignore it (connection succeeds) or reject it (handshake fails). OpenSSL 3.x ClientHello compatibility with very old Schannel is also a known concern ([openssl/openssl#28284](https://github.com/openssl/openssl/issues/28284)). Live testing is recommended.

## Requirements

- Linux with systemd
- `guacd` managed by systemd
- Build: `gcc`, `make`, `libssl-dev` (Debian/Ubuntu) or `openssl-devel` (RHEL/Rocky)

## Installation

```bash
git clone https://github.com/your-org/guacamole-tls-compat.git
cd guacamole-tls-compat
sudo bash install.sh
```

The installer builds the shim from source, installs it to `/usr/local/lib/`, creates the host config file, writes the systemd drop-in, and restarts `guacd`.

Then add your legacy hosts to the config:

```bash
sudo nano /etc/guacamole/tls-compat-hosts.conf
```

## Host config

`/etc/guacamole/tls-compat-hosts.conf` — one entry per line, either a single IP address or a CIDR range. Lines beginning with `#` are comments.

```
# Single addresses
192.168.10.50
2001:db8::1

# CIDR ranges
10.0.5.0/24
fd00::/8
```

The file is read at guacd startup. Restart guacd to apply changes:

```bash
sudo systemctl restart guacd
```

## Verification

Confirm the shim is loaded:

```bash
grep tls12_cap /proc/$(pgrep guacd)/maps
```

To enable debug logging:

```bash
sudo systemctl set-environment TLSCOMPAT_DEBUG=1
sudo systemctl restart guacd
sudo journalctl -u guacd -f | grep tls12_cap
```

Each connection attempt logs the peer IP, whether it matched the config, and whether the downgrade was applied. Unset when done:

```bash
sudo systemctl unset-environment TLSCOMPAT_DEBUG
sudo systemctl restart guacd
```

## Removal

```bash
sudo bash install.sh uninstall
```

Removes the library and systemd drop-in and restarts `guacd`. The host config file is preserved.

## Building manually

```bash
make             # produces tls12_cap.so
make install     # copies to /usr/local/lib/
make clean
```

Override `PREFIX` to change the install path:

```bash
make install PREFIX=/opt/guacd
```

## Tests

```bash
bash tests/smoke_test.sh
```

Verifies the build produces a valid shared object, `SSL_set_bio@@OPENSSL_3.0.0` and `SSL_set_fd@@OPENSSL_3.0.0` are exported, old blanket interceptors are absent, and the library loads cleanly with and without a config file.

## Security considerations

Capping TLS at 1.2 and setting security level 0 weakens the TLS posture for the listed hosts. This shim is intended as a targeted workaround while legacy systems are still in service — consider also restricting network access to those hosts at the firewall level.
