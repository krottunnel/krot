# Changelog

All notable changes to krot will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Workspace crates (`krot-proto`, `krot-transport`, `krot-server`,
`krot-client`) share a single version and are released together.

## [0.1.0] — 2026-07-07

Initial public release of the KROT/1 tunnel service.

### Added
- QUIC transport (`krot-transport`, quinn 0.11, rustls 0.23) with ALPN
  `krot/1` and TLS-over-TCP fallback ALPN `krot-tcp/1`.
- Ed25519 challenge-response authentication with domain separator
  `b"krot-auth-v1\0"`. Fresh 32-byte nonces from `OsRng`.
- postcard framing with LEB128 varint length prefix, capped at 64 KiB.
- HTTP and TCP tunnel primitives. Per-tunnel labels, port allocation
  with reservation, hot-reload watchdog on peer list.
- Per-identity rate limiting via `governor`, partitioned per-core so
  no single mutex is a contention point.
- Hot-reload of `authorized_keys` and `peers.txt` via `notify`;
  malformed edits keep the last-good in-memory state.
- Session resume across handshake reconnects. Server keeps resume
  state 60 s past the last activity.
- TCP mux over TLS fallback — OPEN/DATA/FIN framing, bidirectional
  streams over a single TCP connection. DATA payloads capped at 256 KiB.
- Passive HTTP inspection — 8 KiB header cap, host-based routing to
  registered HTTP tunnels.
- **Styled login-page auth for HTTP tunnels** — `krot http --auth
  user:pass` serves a dark-themed sign-in page with the krot brand
  mark. Successful POST installs an 8-hour rolling session cookie
  (`HttpOnly; SameSite=Lax`). In-memory session store, no
  external dependencies. Credential sources: CLI flag, env var, file.
- API-key auth for HTTP tunnels — `krot http --api-key SECRET`
  accepts both `X-API-Key` and `Authorization: Bearer`. Meant for
  machine callers (curl, CI); credentials compared in constant time.
- ACME (HTTP-01) integration for automatic TLS certificates on the
  HTTPS router. ACME dir `0o700`, credentials `0o600`.
- SNI-based dispatch on the shared 443 listener — QUIC, TLS-over-TCP
  fallback, and HTTPS all cohabit port 443.
- Admin API. Single-use, time-bounded enrollment tokens. Bearer
  tokens hashed (BLAKE3), compared in constant time. Prometheus
  scrape at `/metrics`.
- Observability: 30+ Prometheus counters and gauges, JSON logs via
  `KROT_LOG_FORMAT=json`.
- Client CLI (`krot-client`) — enroll, run, config in
  `~/.krot/config.toml` (`0o600`).
- Server CLI (`krot-server`) with single-core and multi-core
  (`SO_REUSEPORT` thread-per-core) modes. `--resume-grace-secs` flag
  to tune the session-resume grace window (default 30, lower for
  faster local dev cycles).
- Property tests (`proptest`) on framing, mux, auth, peer list,
  authorized-keys parser, and the login/session-cookie flow.
- `cargo-fuzz` scaffolding: five targets across `krot-proto` and
  `krot-server`.
- GitHub Actions CI: stable + MSRV test matrix on Linux and macOS,
  `cargo fmt --check`, `cargo clippy -D warnings`, `cargo audit`,
  60-second fuzz smoke per target.
- Multi-platform release workflow: pre-built binaries for
  `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`,
  `x86_64-apple-darwin`, `aarch64-apple-darwin`,
  `x86_64-pc-windows-msvc`, `i686-pc-windows-msvc`.
- Multi-arch Docker image (`linux/amd64`, `linux/arm64`) via
  `Dockerfile` with OCI labels and GHA build cache.
- MIT OR Apache-2.0 dual license.

### Security
- Bounded allocations everywhere network input is decoded: 64 KiB
  postcard frames, 8 KiB HTTP admin/inspector requests, 256 KiB mux
  DATA payloads, 4 KiB login-form bodies.
- File permissions enforced: `0o600` on `admin_token.hash`, server
  identity, client config, ACME credentials; `0o700` on ACME state
  dir.
- Constant-time comparisons on all secret material (admin token
  BLAKE3, session token BLAKE3, login credentials, API keys).
- Session cookies: `HttpOnly; SameSite=Lax`. Open-redirect
  guard on the `next` parameter (only site-relative paths accepted).
- No secrets emitted in logs.
- Accept loops (TCP fallback, HTTP router, HTTPS router) survive
  transient errors (`EMFILE`, `ECONNABORTED`, `ENOBUFS`) — log +
  100 ms backoff + continue, no permanent listener death.

[0.1.0]: https://github.com/krottunnel/krot/releases/tag/v0.1.0
