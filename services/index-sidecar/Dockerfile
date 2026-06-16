# Index sidecar image. Debian-slim (glibc) so sodium-native / hypercore-11
# prebuilds load without a musl rebuild — the dependency generation here
# (corestore-7/hc11) is deliberately isolated from the relay image.
FROM node:20-bookworm-slim

WORKDIR /app

# Install deps first for layer caching. The lockfile IS committed (this is a
# dependency-isolation-critical service — pin the corestore-7/hc11 generation
# exactly), so build reproducibly with npm ci.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

COPY . .

ENV INDEX_HOST=0.0.0.0 \
    INDEX_PORT=9300 \
    STORAGE_DIR=/data

EXPOSE 9300
VOLUME ["/data"]

# Drop privileges — the sidecar needs only its store dir + outbound swarm.
USER node

CMD ["node", "index.mjs"]
