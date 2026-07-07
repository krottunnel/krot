# krot-server

**Self-hosted ngrok in Rust. Zero-knowledge, thread-per-core, passwordless.**

`krot-server` is the relay side of [krot](https://github.com/krottunnel/krot) — an open-source tunnel service. HTTPS passthrough on the apex domain, automatic Let's Encrypt via ACME, SSH-style key authorization, one binary per container.

The client (`krot-client`, the CLI that publishes tunnels) is not shipped in this image — install it on the developer machine from the [GitHub Releases](https://github.com/krottunnel/krot/releases/latest) or via `cargo install --git https://github.com/krottunnel/krot krot-client`.

---

## Tags

| Tag | Points to |
|---|---|
| `latest` | the latest stable release |
| `X.Y.Z` | pinned patch release (e.g. `0.1.0`) |
| `X.Y` | latest patch in a minor series (e.g. `0.1`) |
| `edge` | manual dispatches from `main`, `linux/amd64` only |

Supported architectures on tagged releases: `linux/amd64`, `linux/arm64`.

---

## Quick start

```bash
docker run -d --name krot \
  -p 7853:7853/udp \
  -p 7853:7853/tcp \
  -p 80:80/tcp \
  -p 443:443/tcp \
  -v krot-data:/var/lib/krot \
  -v krot-config:/etc/krot \
  krottunnel/krot-server:latest \
  --domain krot.example \
  --acme-contact mailto:admin@krot.example \
  --acme-production \
  --tcp-fallback-bind 0.0.0.0:7853

# Grab the one-shot admin token printed on first start:
docker logs krot | grep KROT_ADMIN_TOKEN
```

Prerequisites: a VPS with a public IP, your own domain, wildcard DNS `*.krot.example → <VPS IP>`, ports 80/443/7853 open.

---

## Ports

| Port | Protocol | Purpose |
|---|---|---|
| `7853` | UDP | QUIC endpoint for `krot-client` connections |
| `7853` | TCP | TLS-over-TCP fallback for clients behind UDP-blocking NAT |
| `80` | TCP | ACME HTTP-01 challenges + public HTTP router |
| `443` | TCP | HTTPS router (SNI passthrough), shares ALPN with fallback |
| `9700` | TCP | Admin API (bound to loopback by default — do not expose) |

---

## Volumes

| Volume | Mount | What's inside |
|---|---|---|
| Data | `/var/lib/krot` | Server identity cert, ACME cache, `admin_token.hash` |
| Config | `/etc/krot` | `authorized_keys` (hot-reload), `peers.txt` (hot-reload) |

Both mounts are marked as `VOLUME` in the image and can be backed by named Docker volumes, host bind mounts, or NFS.

---

## Common flags

Full CLI reference: `docker run --rm krottunnel/krot-server:latest --help`.

| Flag | Purpose |
|---|---|
| `--domain <apex>` | Turn on DomainMode. Without it, IpMode (TCP tunnels only). |
| `--acme-contact mailto:...` | Enable ACME (Let's Encrypt staging by default). |
| `--acme-production` | Switch ACME to production issuance. |
| `--tls-cert <path> --tls-key <path>` | Bring your own PEM cert instead of ACME. |
| `--tcp-fallback-bind 0.0.0.0:7853` | Enable TCP fallback listener. |
| `--admin-bind 127.0.0.1:9700` | Admin API bind. Empty disables. |
| `--cores N` | Worker threads. Defaults to `available_parallelism()`. |
| `--issue-admin-token` | Force-issue a new admin token (useful after loss). |

---

## Onboarding a client

```bash
# On the developer machine:
krot init --server krot.example --admin-token R54VHZ9FD0JJ44...
# → enrolled at krot.example:7853

krot http 3000 --name alice
# → https://alice.krot.example
```

The `admin-token` is single-use with a 10-minute TTL. To enroll another client, run:

```bash
docker exec krot krot-server --issue-admin-token
```

---

## Reverse proxy for the admin API

The admin API binds to loopback inside the container by default. To reach it from the host, publish it explicitly and put a TLS-terminating reverse proxy in front:

```bash
docker run ... -p 127.0.0.1:9700:9700/tcp ... krottunnel/krot-server:latest \
  --admin-bind 0.0.0.0:9700 ...
```

Never publish the admin API to `0.0.0.0` on the host without TLS + authentication in front.

---

## Image details

- **Base:** `debian:bookworm-slim` with `ca-certificates` and `tini`.
- **Runtime user:** UID/GID 1000 (non-root).
- **Binary size:** ~7 MB (release + LTO + strip).
- **Full image size:** ~85 MB.
- **Signals:** `SIGTERM` triggers graceful shutdown (5 s deadline for `ServerBye` acks).

---

## Documentation

- **Full README, architecture, CLI reference:** [github.com/krottunnel/krot](https://github.com/krottunnel/krot)
- **Changelog:** [CHANGELOG.md](https://github.com/krottunnel/krot/blob/main/CHANGELOG.md)
- **Security policy:** [SECURITY.md](https://github.com/krottunnel/krot/blob/main/SECURITY.md)
- **Report a vulnerability:** [private advisory form](https://github.com/krottunnel/krot/security/advisories/new)

---

## License

`MIT OR Apache-2.0` — at your choice. See [LICENSE-MIT](https://github.com/krottunnel/krot/blob/main/LICENSE-MIT) and [LICENSE-APACHE](https://github.com/krottunnel/krot/blob/main/LICENSE-APACHE).
