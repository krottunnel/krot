# Security policy

`krot` is a self-hosted tunneling service. It handles cryptographic
identities, terminates TLS on an apex domain, and forwards user
traffic between authenticated peers. Bugs in these paths can have
real impact — please report them privately.

## Reporting a vulnerability

**Do not open a public GitHub issue.**

Use GitHub's [private security advisory form](https://github.com/krottunnel/krot/security/advisories/new)
to report privately. Include:

- A clear description of the issue and the affected component
  (`krot-server`, `krot-client`, wire protocol, admin API, etc.).
- Steps to reproduce, ideally a minimal PoC.
- Version / commit hash you tested against.
- Your assessment of severity and impact.

Expect a first reply within **72 hours**. Coordinated disclosure
timeline is **90 days** from the initial report, extendable by mutual
agreement.

## In scope

The following are treated as security bugs and receive priority:

- Authentication bypass against the wire protocol (Ed25519 challenge,
  session resume, admin token, session cookie).
- Cross-tunnel data leakage (traffic for tunnel A reaching client B).
- Server-side memory corruption or unbounded allocation reachable
  from an unauthenticated network peer.
- Denial of service that survives a legitimate rate limit — i.e. an
  attack that a modest attacker can sustain against a well-configured
  server.
- Privilege escalation via the admin API (bypassing bearer-token
  auth, escaping the loopback binding assumption).
- TLS misconfiguration that downgrades the wire-protocol security
  guarantees (weakened ciphers, ALPN confusion, cert validation
  bypass).
- Log injection or secret leakage into logs / metrics.

## Out of scope

The following are **not** considered vulnerabilities:

- **`--auth user:pass` credentials in `ps` output.** The flag is
  documented as dev-only; use `--auth-env` or `--auth-file` for
  non-dev deployments.
- **Attacks that require prior enrollment.** If an attacker already
  has an entry in `authorized_keys`, they are — by design — trusted
  to publish tunnels. Revoke the key via hot-reload.
- **DNS hijacking / domain takeover of the apex.** Out of `krot`'s
  control; users must secure their own DNS.
- **Bruteforcing a well-chosen admin token, session cookie, or API
  key.** 32 bytes of entropy plus rate limiting on the reverse proxy
  is expected to defeat this; if it doesn't, that's a rate-limiter
  bug (which IS in scope).
- **Physical or network-layer access to the VPS.** Same as any
  self-hosted service — if the attacker owns the host, they own the
  service.
- **Loss of the client identity file.** Users are expected to
  protect `~/.krot/identity` (`0o600` by default). Rotation is
  documented in the README under Security.

## Platform caveats

- **Windows.** `krot` sets restrictive Unix modes (`0o600` on
  identity files, `admin_token.hash`, ACME credentials; `0o700` on the
  ACME directory) via `#[cfg(unix)]` blocks. On Windows those blocks
  compile to nothing — files land with default NTFS ACLs. On a
  single-user machine this is fine. If you deploy `krot-server` on a
  multi-user Windows host, restrict the data directory manually via
  `icacls` or NTFS permissions before starting the service.
- **Filesystems without atomic rename.** Runtime state (`identity`,
  `admin_token.hash`, `authorized_keys`) is written via
  write-tmp-then-rename. A filesystem that does not honor POSIX
  atomic-rename semantics (some FUSE mounts, older SMB shares) can
  leave a corrupt file after a mid-write crash. Store the data
  directory on a real local filesystem (ext4, xfs, apfs, ntfs local
  volume).

## Supported versions

Only the latest released version receives security fixes. Fixes for
older versions are considered on a case-by-case basis. Once `krot`
reaches 1.0, the policy will be revised to cover an explicit LTS
window.

## Credit

If you'd like public credit for a valid report, we'll acknowledge you
in the release notes and (if provided) link to your website or
handle. Anonymous reports are equally welcome.
