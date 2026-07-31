# syntax=docker/dockerfile:1.6
#
# p2p-hiverelay — P2P relay backbone for the Holepunch/Pear ecosystem.
#
# Multi-arch (linux/amd64, linux/arm64) — designed for Umbrel Home (ARM)
# AND x86 Umbrel/server hosts. Built via `docker buildx build --platform`.
#
# Multi-stage build:
#   Stage 1 (deps):    install production deps for all workspaces
#   Stage 2 (runtime): minimal Debian bookworm-slim runtime, non-root user, tini PID 1
#
# Build:
#   docker build -t p2p-hiverelay:latest .
#
# Multi-arch build (push to registry):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t hiverelay/hiverelay:0.6.0 -t hiverelay/hiverelay:latest --push .
#
# Quick run (data volume + API port published):
#   docker run -d --name hiverelay \
#     -v hiverelay-data:/data \
#     -p 9100:9100 \
#     p2p-hiverelay:latest
#
# Open the TUI (connects to the running container's API):
#   docker exec -it hiverelay hiverelay tui
#
# Environment overrides:
#   HIVERELAY_REGION=NA           (region code)
#   HIVERELAY_MAX_STORAGE=50GB    (accepts human-readable sizes)
#   HIVERELAY_API_KEY=...         (secures management endpoints)
#   HIVERELAY_API_PORT=9100       (API port inside container)
#   HIVERELAY_HOLESAIL=1          (enable Holesail for NAT traversal)
#   LNBITS_URL=http://...         (LNbits payment provider; auto-detected on Umbrel)
#   LNBITS_ADMIN_KEY=...          (LNbits admin key for invoice creation)

# ─── Stage 1: dependencies ────────────────────────────────────────────
# Use Debian bookworm-slim (glibc) instead of Alpine (musl). Two upstream
# Bare ecosystem packages — udx-native, sodium-native — ship prebuilt
# binaries for `linux-x64`/`linux-arm64` (glibc) but NOT for
# `linux-x64-musl`/`linux-arm64-musl`. On Alpine, require-addon detects
# musl via /etc/alpine-release and looks for a musl prebuild that doesn't
# exist → crash at first import. Building from source on Alpine works
# but requires cmake-bare/cmake-napi + python3 + make + g++ in BOTH
# stages (the binary lands in a path require-addon doesn't search by
# default) and roughly doubles the runtime image. Debian bookworm-slim
# is ~50 MB larger than Alpine but loads the glibc prebuilds directly.
#
# Tracked in issue #21. Reconsider when udx-native ships musl prebuilds:
#   https://github.com/holepunchto/udx-native
#
# Node 22 LTS — Bare/Pear runtime targets stay aligned.
FROM node:22-bookworm-slim AS deps
WORKDIR /app

# Install build tools needed for any native deps that DO build from
# source on Linux (sodium-universal's fallback, hypercore-crypto, etc).
# Debian-based — no musl complications.
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 make g++ git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy ALL workspace package.json files (npm needs them all to resolve workspaces)
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY packages/services/package.json packages/services/
COPY packages/client/package.json packages/client/
COPY packages/verifier/package.json packages/verifier/
COPY patches patches/

# Install production deps across all workspaces. --workspaces installs deps
# for every workspace; --include-workspace-root pulls in root devDeps if any
# are needed at runtime (none currently, but explicit is better).
RUN npm ci --omit=dev --workspaces --include-workspace-root --no-audit --no-fund

# ─── Stage 2: runtime ─────────────────────────────────────────────────
FROM node:22-bookworm-slim AS runtime

LABEL org.opencontainers.image.title="p2p-hiverelay"
LABEL org.opencontainers.image.description="Always-on P2P relay infrastructure for the Holepunch/Pear ecosystem"
LABEL org.opencontainers.image.source="https://github.com/bigdestiny2/P2P-Hiverelay"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# tini for proper PID 1 signal handling (graceful shutdown).
# wget for HEALTHCHECK without bringing curl/openssl bloat.
# ca-certificates so HTTPS to public registries / payment providers works.
# libatomic1 is required by the Linux ARM64 rocksdb-native prebuild. Without it
# require-addon reports a misleading ADDON_NOT_FOUND even though the prebuild is
# present, and Umbrel ARM64 nodes fail before the relay can expose /health.
RUN apt-get update && \
    apt-get install -y --no-install-recommends tini wget ca-certificates gosu libatomic1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Bring in already-installed modules from the deps stage. npm 7+ hoists
# most workspace deps to the root `node_modules/`. Per-package
# `node_modules/` only exist when there's a version conflict — historically
# `packages/core/node_modules/` etc. weren't created by `npm ci --workspaces`
# at all, so the per-package COPY commands here used to fail the whole
# build. Copy the root tree once; that's enough for production startup.
COPY --from=deps /app/node_modules ./node_modules

# Copy application source (respects .dockerignore)
COPY . .

# Non-root user for security. Fixed UID/GID so volume permissions stay
# consistent across image rebuilds — operators with existing data
# volumes don't get bitten by an auto-assigned UID drift between builds.
RUN groupadd -r -g 999 hiverelay && \
    useradd -r -u 999 -g hiverelay -d /data -s /usr/sbin/nologin hiverelay && \
    mkdir -p /data /config && \
    chown -R hiverelay:hiverelay /app /data /config

# Make the hiverelay binary globally callable inside the container, so
# `docker exec -it hiverelay hiverelay tui` just works.
RUN ln -s /app/packages/core/cli/index.js /usr/local/bin/p2p-hiverelay && \
    ln -s /app/packages/core/cli/index.js /usr/local/bin/hiverelay && \
    chmod +x /app/packages/core/cli/index.js

# Entrypoint: self-heal /data ownership then drop privileges.
#
# Self-hosting platforms (Umbrel, StartOS) bind-mount a host directory over
# /data whose owner is the host user, NOT the image's build-time uid 999. A
# non-root container then can't create its store -> EACCES on startup. So we
# start as root, fix ownership only when it's wrong (cheap on restarts), and
# drop to the unprivileged `hiverelay` user via gosu before exec'ing node.
# COPY the entrypoint from a committed file rather than generating it inline.
# Some remote builders can lose heredoc-generated files, which leaves the
# image without /usr/local/bin/docker-entrypoint.sh and exits 127 on boot.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# NOTE: no `USER` directive — the entrypoint starts as root to fix the
# bind-mount ownership, then gosu-drops to uid 999. The relay process itself
# runs unprivileged.

VOLUME ["/data", "/config"]

# API port. Gateway (9200) and other transport ports may need their own
# `-p` mappings when you enable them.
EXPOSE 9100

ENV NODE_ENV=production \
    HIVERELAY_STORAGE=/data \
    HIVERELAY_CONFIG_DIR=/config \
    HIVERELAY_LOG_LEVEL=info \
    HIVERELAY_API_PORT=9100 \
    HIVERELAY_API_HOST=0.0.0.0

# Health check hits the local API. wget is a small http client; using it
# instead of node -e fetch() keeps healthcheck startup fast and avoids
# loading the entire app just to check liveness.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --quiet --tries=1 --timeout=4 --spider \
    http://127.0.0.1:${HIVERELAY_API_PORT:-9100}/health || exit 1

# tini as PID 1 → graceful SIGTERM handling so shutdown actually runs.
# Debian installs tini at /usr/bin/tini (vs Alpine's /sbin/tini).
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh", "node", "/app/packages/core/cli/index.js"]

# Default: start a relay node. Override to run other subcommands, e.g.:
#   docker run ... p2p-hiverelay:latest help
CMD ["start"]
