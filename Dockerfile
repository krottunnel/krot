# syntax=docker/dockerfile:1.7
#
# Production Dockerfile for `krot-server` — targets Docker Hub.
#
# Build (single-arch, host):
#   docker build -t krottunnel/krot-server:dev .
#
# Build multi-arch and push (uses buildx, requires a Docker Hub login):
#   docker buildx build \
#     --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION="$(git describe --tags --always --dirty)" \
#     --build-arg VCS_REF="$(git rev-parse HEAD)" \
#     --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
#     -t krottunnel/krot-server:latest \
#     -t krottunnel/krot-server:0.1.0 \
#     --push .
#
# The `.github/workflows/docker.yml` job does all of the above
# automatically on every `v*.*.*` tag push.

# ---------- builder ----------
FROM --platform=$BUILDPLATFORM rust:1.83-slim-bookworm AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      pkg-config \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Bring in workspace manifests first — kept separate from sources so
# BuildKit reuses the dependency layer whenever only sources change.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

# Cache Cargo registry + target/ across builds. This is the big
# CI-friendly win: cold builds still take a few minutes, warm ones
# take seconds.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin krot-server \
 && cp target/release/krot-server /usr/local/bin/krot-server \
 && strip /usr/local/bin/krot-server


# ---------- runtime ----------
FROM debian:bookworm-slim AS runtime

# Metadata plumbing.
ARG VERSION="0.0.0-dev"
ARG VCS_REF="unknown"
ARG BUILD_DATE="1970-01-01T00:00:00Z"

# OCI image labels — Docker Hub renders these in the image sidebar.
# See https://github.com/opencontainers/image-spec/blob/main/annotations.md
LABEL org.opencontainers.image.title="krot-server" \
      org.opencontainers.image.description="Self-hosted tunnel service (QUIC + TLS fallback), Rust, thread-per-core." \
      org.opencontainers.image.url="https://github.com/krottunnel/krot" \
      org.opencontainers.image.source="https://github.com/krottunnel/krot" \
      org.opencontainers.image.documentation="https://github.com/krottunnel/krot#readme" \
      org.opencontainers.image.vendor="krottunnel" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# `ca-certificates` is required by instant-acme for Let's Encrypt.
# `tini` forwards SIGTERM to krot-server so `docker stop` triggers
# the graceful-shutdown path.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      tini \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime user. UID/GID 1000 for easy host bind-mount
# ownership on typical single-user Linux hosts.
RUN groupadd --system --gid 1000 krot \
 && useradd  --system --uid 1000 --gid 1000 \
             --home-dir /var/lib/krot --shell /usr/sbin/nologin krot

COPY --from=builder /usr/local/bin/krot-server /usr/local/bin/krot-server

# Prepare state + config directories with correct ownership BEFORE
# declaring them as VOLUMEs so first-boot defaults still apply on an
# empty host bind mount.
RUN mkdir -p /var/lib/krot /etc/krot \
 && chown krot:krot /var/lib/krot /etc/krot \
 && touch /etc/krot/authorized_keys \
 && chown krot:krot /etc/krot/authorized_keys \
 && chmod 0600     /etc/krot/authorized_keys

USER krot

# Persistent state (identity cert, ACME account + cert cache,
# admin_token.hash).
VOLUME ["/var/lib/krot"]
# Operator-editable config (authorized_keys, peers.txt).
VOLUME ["/etc/krot"]

# QUIC control endpoint. See PROTOCOL.md §Appendix A.
EXPOSE 7853/udp
# DomainMode: ACME HTTP-01 + plain-HTTP tunnel routing.
EXPOSE 80/tcp
# DomainMode: HTTPS + shared-443 SNI dispatch (§16.1.8).
EXPOSE 443/tcp
# Admin API (default off — bind explicitly with --admin-listen).
EXPOSE 7580/tcp

# No HEALTHCHECK by default: krot-server intentionally does not
# expose an unauthenticated liveness endpoint. If you want one, wire
# it at deploy time using the admin API's authenticated /metrics
# scrape as a proxy for liveness.

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/krot-server"]

# IpMode by default. Override with --domain, --tls-cert, --tls-key or
# --acme-contact at `docker run` time.
CMD [ \
  "--data-dir",        "/var/lib/krot", \
  "--authorized-keys", "/etc/krot/authorized_keys", \
  "--bind",            "0.0.0.0:7853" \
]
