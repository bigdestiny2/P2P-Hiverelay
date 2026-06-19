# p2p-hiverelay-index (index sidecar)

A **Tier-2** queryable, signed P2P index for a HiveRelay — a [`schema-sheets`](https://www.npmjs.com/package/schema-sheets)
room that mirrors the relay's catalogue, pins, relay-directory and verifications,
JMESPath-queryable and blind-replicable by clients (e.g. PearBrowser desktop).

It runs **out-of-process** because schema-sheets is built on **corestore-7 /
hypercore-11 / ajv-8**, which collide with the relay's **corestore-6 /
hypercore-10 / ajv-6**. The sidecar keeps that dependency generation fully
isolated in its own `node_modules` and its own corestore. See
[`../../docs/INDEX-LAYER.md`](../../docs/INDEX-LAYER.md) for the full design,
the spike that established this, and the tier model.

## What it does

1. **Projects** the relay's already-public, already-redacted data into a room:
   - polls `GET /catalog.json` → `app-manifest` + `pin-registry` rows
   - polls `GET /.well-known/hiverelay.json` (signed capability doc) → one
     `relay-directory` row (with `capabilitySig` copied verbatim so clients
     re-verify the projection, never trusting the room writer)
   - writes are **debounced to content changes only** — Autobase appends are
     ~18KB/row (measured), so unchanged entries cost nothing.
2. **Serves** the §2 query routes (the relay reverse-proxies these so the
   desktop uses a single `gatewayUrl`):
   - `GET /api/index/room` → `{ indexRoom, discoveryKey, schemas, queries }`
   - `GET /index/pins|relays|manifests|verifications?query=&type=&page=&pageSize=&gte=&lte=`
   - `GET /health`
3. **Announces** the room on the swarm so clients **blind-replicate it
   read-only** (no encryption key — public read-only by design).
4. **Publishes** its room key to the relay (`POST /api/manage/index-room`,
   operator-authed loopback) so the relay advertises `indexRoom` in its
   capability doc + `/catalog.json`.

## System prerequisites

On **bare metal** (running directly with Node, not the Docker image), the host
needs **`libatomic1`**:

```sh
sudo apt-get install -y libatomic1   # Debian/Ubuntu
```

corestore-7's storage engine, `rocksdb-native`, dynamically links
`libatomic.so.1`, which is **not** installed by default on minimal Ubuntu/Debian
(e.g. a fresh Ubuntu 24.04 box). `sodium-native` is unaffected — only
`rocksdb-native` needs it.

The failure is **very misleading**: the sidecar crashes inside `require-addon`
with `Error: Cannot find addon '.' imported from .../rocksdb-native/binding.js`,
listing candidate `.node` paths — *even though* the prebuild
(`prebuilds/linux-x64/rocksdb-native.node`) exists. `require-addon` swallows the
real `dlopen` error. Confirm the actual cause with:

```sh
ldd node_modules/rocksdb-native/prebuilds/linux-x64/rocksdb-native.node
#   libatomic.so.1 => not found        ← the real problem
node -e "process.dlopen({exports:{}}, 'node_modules/rocksdb-native/prebuilds/linux-x64/rocksdb-native.node')"
#   Error: libatomic.so.1: cannot open shared object file: No such file or directory
```

The Docker image (`Dockerfile`) and the fleet host provisioning
(`../../scripts/deploy-vps.sh`) already install `libatomic1`; you only need this
step for an ad-hoc bare-metal run. See
[`../../docs/INDEX-LAYER.md`](../../docs/INDEX-LAYER.md#system-prerequisites) for
the full diagnostic.

## Run

```sh
npm install
RELAY_URL=http://127.0.0.1:8080 RELAY_API_KEY=<relay-management-key> npm start
```

### Environment

| var | default | meaning |
|-----|---------|---------|
| `RELAY_URL` | `http://127.0.0.1:8080` | relay loopback base |
| `RELAY_API_KEY` | – | management key, to publish the room pointer |
| `INDEX_HOST` / `INDEX_PORT` | `127.0.0.1` / `9300` | query server bind |
| `STORAGE_DIR` | `./store` | corestore-7 store dir |
| `INDEX_ROOM_KEY` | – | reopen an existing room (z32); else created + persisted |
| `RELAY_PUBKEY` | discovered | membership name / relay-directory |
| `POLL_INTERVAL_MS` | `15000` | projection cadence |
| `ENABLE_SWARM` | `true` | announce the room for client replication |

## Trust & privacy

The room is an **index, not an authority**. It carries only the relay's own
*public* registries (no user data); `isIndexable()` is a defense-in-depth gate
that drops any private/redacted/unkeyed entry before it can become a row. The
room ships **without an encryption key** so any peer replicates it read-only.
Clients must re-verify: relay rows via `capabilitySig`/`verifyCapabilityDoc`,
anchored claims via the relay's anchor-proof route, manifests via attestations.

## Test

```sh
npm test   # node:test — schemas, mappers, room, projector, server, e2e replication
```
