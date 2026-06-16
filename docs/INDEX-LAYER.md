# Index layer — schema-sheets Tier-2 index (design + decision record)

**Status:** built, tested, not yet deployed. **Scope:** additive; the relay
gains one signed capability field + a read-only reverse-proxy; the index itself
is an out-of-process sidecar. Consumes the design in the PearBrowser handover
(`HIVERELAY-BACKBONE-HANDOVER.md`, kept off-GitHub).

## The tier model

The catalogue/index is layered so every consumer can pick its dependency cost:

| Tier | Surface | Shape | For |
|------|---------|-------|-----|
| 0 | `GET /catalog.json` | flat JSON over HTTP | always present; verifier depends on it |
| 1 | `catalogBeeKey` (v0.18.0) | signed Hyperbee, key-range | Bare-native, dependency-light clients |
| 2 | `indexRoom` (this) | schema-sheets: 4 schemas, JMESPath, multi-writer-capable | rich query, relay-directory, verifications |

Tier-2's `app-manifest` schema and Tier-1's bee both derive from the **same**
`/catalog.json`, so the tiers can't diverge. A relay without a sidecar simply
omits `indexRoom`; clients fall back to Tier-1/Tier-0.

## Why a sidecar (the spike)

schema-sheets is built on **corestore-7 / hypercore-11 / autobase-7 / ajv-8**.
The relay is on **corestore-6 / hypercore-10 / ajv-6**. These are incompatible
generations:

- Installing schema-sheets into the relay tree **crashed** — `ajv-formats@3`
  bound the relay's hoisted `ajv@6` (`Cannot read properties of undefined
  (reading 'code')`).
- The handover's "`new SchemaSheets(node.store.namespace(...))`, run in-process"
  is therefore **not viable** on today's relay — you cannot hand a corestore-6
  store to an autobase-7 library.

A spike in an isolated package confirmed the rest of the design is sound:

| Check | Result |
|-------|--------|
| Instantiate + join + add schema on Node | ✅ |
| 500 rows | 965ms (1.93 ms/row) |
| Storage | 112KB → 9.2MB ≈ **18KB/row** (Autobase write-amp; `updateRow` has no in-place mutate) |
| JMESPath query | ✅ |
| Blind read-only replica (key only, no enc key) | ✅ 500/500 rows |

So the index runs as a **dependency-isolated sidecar process** with its own
corestore-7 store and swarm. It reads the relay's public HTTP and publishes a
room; the relay only advertises the pointer and reverse-proxies the read API.

### Coupling to the hypercore-11 migration

This sidecar is the **bridge** until the relay's own hc11/corestore-7 storage
migration lands. Once the relay is on that generation, the index *could* move
in-process as the handover originally envisioned; until then, isolation is
mandatory. The sidecar's mappers/schemas are written against **public shapes**
(catalog entries, capability doc) so they port to an in-process host unchanged.

## How the desktop consumes it

1. Fetch the relay's signed capability doc → read `indexRoom` (z32). The field
   is **additively signed** (schemaVersion stays 1; the canonical signer covers
   it, so old verifiers still validate).
2. Either **blind-replicate the room** over the swarm (read-only, no enc key)
   and query locally, **or** hit the relay gateway `GET /index/*` (the relay
   reverse-proxies to the sidecar — single `gatewayUrl`).
3. Re-verify: relay rows via `capabilitySig` + `verifyCapabilityDoc`; anchored
   claims via the relay anchor-proof route; manifests via attestations. The room
   is an index, not an authority.

## §2 contract conformance

| Contract item | Status |
|---------------|--------|
| `indexRoom` additive field, schemaVersion 1, sig-covered | ✅ relay |
| `GET /api/index/room` | ✅ sidecar (+ relay proxy) |
| `GET /index/{pins,relays,manifests,verifications}` + `query`/`gte`/`lte`/`type` | ✅ |
| page/pageSize pagination (as `/catalog.json`) | ✅ |
| public read-only room (no enc key) | ✅ |
| `/catalog.json`, `/v1/hyper/*`, `/.well-known/hiverelay.json` unchanged | ✅ |

## Decisions (handover §6)

- **Plugin API surface (§6.2):** registries are reached via `start(ctx).node.*`,
  not the constructor — but moot here since the sidecar reads them over HTTP.
- **Curated, per-relay room (§6.3/§6.4):** the sidecar is the sole writer; the
  membership name is `relay:<pubkey-prefix>`. Per-relay (no shared-room conflict
  policy).
- **Verifications (§6.5):** accept + client-filter in v1.
- **Bare/ESM (§6.6):** non-issue on the relay side — the sidecar runs on Node.
- **Bootstrap relay (§6.1):** operator config (`indexSidecarUrl` + a well-known
  relay), intentionally not recorded in this repo doc.

## Deployment (not yet flipped live)

Two containers on the appliance — the relay (unchanged image) + the sidecar:

```yaml
# docker-compose snippet (illustrative)
services:
  relay:
    # ...existing Blindspark relay...
    environment:
      HIVERELAY_INDEX_SIDECAR_URL: http://index:9300   # relay proxies /index/* here
  index:
    build: ./services/index-sidecar
    environment:
      RELAY_URL: http://relay:8080
      RELAY_API_KEY: ${APP_RELAY_MANAGEMENT_KEY}
      INDEX_PORT: "9300"
      STORAGE_DIR: /data
    volumes:
      - index-data:/data
volumes:
  index-data:
```

Relay config: set `indexSidecarUrl` (or `INDEX_SIDECAR_URL`). The sidecar
publishes its room key to the relay over loopback once ready.

## Write-amplification mitigation

The ~18KB/row Autobase cost is contained by **content-debounce**: the projector
hashes each mapped row and writes only on change (`updateRow`/`addRow` are never
called for unchanged entries). **Open item:** Autobase input logs are
append-only; a long-lived room needs periodic checkpoint/room re-bootstrap to
bound growth.

## Phase-2 / open items

- `pin-registry` `pending`/`rejected` states need the operator-authed feed
  (v1 projects only public catalogue states).
- `verification` rows need invited verifier writers (multi-writer room).
- deterministic room key (today: created once + persisted).
- sidecar metrics + `base.update()` sync indicator.
