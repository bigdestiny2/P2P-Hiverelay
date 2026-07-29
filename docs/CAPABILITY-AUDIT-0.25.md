# HiveRelay v0.25 Capability Audit

**Scope:** what v0.25 actually enables, what is wired but off, what is specified but unwired,
what is built but undeployed — and a concrete fleet enablement plan.

| | |
|---|---|
| Audit date | 2026-07-28 |
| Tree | `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay`, branch `feat/service-http-wiring`, HEAD `935b0e4` |
| Tag at HEAD | `v0.25.0-rc.6` (`git describe --tags` → `v0.25.0-rc.6`) |
| Fleet snapshot | `docs/html/fleet-live.json`, `generatedAt 2026-07-27 10:17 UTC`, 12 relays (`summary.total: 12`) |
| Method | Read-only. No SSH, no fleet mutation. Every claim carries `file:line` or a quoted command. |

> Repair status (2026-07-29, post-RC7 worktree): this document preserves the
> audited RC6 baseline below. The release repair now translates the shipped
> service/Tor environment into Node first-boot defaults, keeps persisted config
> and `services.json` authoritative, persists management API edits to
> `<storage>/services.json`, accepts `storage-proof`, configures packaged
> OutboxLog with a finite partitioned-Hypercore journal, and leaves shard-store
> opt-in. Focused regression tests cover precedence, explicit disable, Tor
> fields, bounded journal bytes, and private notify descriptor loading. These
> fixes require a new prerelease and are not yet deployed. The Node plugin
> lifecycle now also consumes `config.vrfBeacon`, closing the audited
> beacon-config dead end.

### Evidence-quality caveat, stated once and load-bearing throughout

`docs/html/fleet-live.json` records `services_source: "config"` for **10 of 12** relays.
Only `utah-0.5gb` is `"live"`; `bern` is `"error": "ssh/unreachable"` with no field at all.
Per this project's own rule — `docs/LADDER-SHIP-MAP.md:422`, *"`services.json` is runtime authority for
which plugins load | Writing config alone does not enable services (dubai incident)"* — a `config`-sourced
row is **not** runtime proof. `packages/core/core/relay-node/index.js:998-1006` (`_loadServicesOverride`)
*replaces* `config.plugins` wholesale from `<storage>/services.json`.

Therefore: every per-box service statement below means **"configured"**, not **"verified running"**,
except for `utah-0.5gb`. No committed tool produces this file — `git grep -l services_source` over all
refs matches only `docs/html/fleet-live.json` itself. That is finding **D-5**.

`dallas` (12 GB / 300 GB, NA) appears in **no** committed machine-readable inventory:
`fleet/relays.json` has 12 entries and no dallas; `fleet-live.json` has 12 relays and no dallas.
It exists only in the gitignored `fleet/relays.local.json:77-81`. The real fleet is 13 boxes.

---

## 1. What v0.25 actually enables

### 1.1 Summary verdict per rung

| Rung | Moves? | Honest one-line statement |
|---|---|---|
| **G0** | **No — and one regression** | Core storage/custody discipline is genuinely strong, but `config/default.js:205` ships `serviceDefaultPeerRole: 'authenticated-user'`, silently reverting a security fix. Net negative. |
| **G1** | **Yes, in code. No, in deployment** | VRF HTTP, notify push adapters, outboxlog durability, gateway fixes are all real and merged. Zero of them reach a box through packaging; the fleet's service set is hand-written `services.json`. |
| **G2-S** | **No** | Custody advertised from config alone (`capability-doc.js:166`), no runtime gate. No new cohort. |
| **G2-W** | **No** | Wire layer exists only in `hiverelay-blind-vnext-integration/packages/blind-protocol/`. Nothing split-transport in `packages/`. |
| **G3** | **No** | `shard-store` on 4 boxes, pin registry never persisted, no repair path for cells. |
| **G4-T** | **Code yes, claim no** | Substantial new Tor code merged. The packaging default that the badge rests on is inert; the "verified reachable" gate does not verify reachability. |
| **G4-I** | **No** | Untouched. |

### 1.2 What genuinely landed (evidence)

| Capability | Evidence | Reaches a box? |
|---|---|---|
| VRF HTTP surface | `packages/core/core/relay-node/api-vrf.js` (+162, new), `api-vrf-http-adapter.js` (+39, new), `packages/services/builtin/vrf/http-adapter.js` (+213, new); routes mounted `api.js:950-970` | Yes — `vrf` configured on 10 boxes |
| Tor transport hardening | New `packages/core/transports/tor/{auth-keys,enrollment,peer-listener,vport-policy,redaction}.js`; ClientAuthV3 guard credential `transports/tor/index.js:709-717`; roster validation fails closed `auth-keys.js:245-246,259` | Only on hand-configured utah / utah-8gb |
| Notify push adapters | `packages/services/builtin/notify-push/{apns,fcm,webpush,jwt,token-codec}.js`, reachable via `notify-push/index.js:27,54,58` | **No** — no config sets `notify.push` |
| Notify honesty gate | `capability-doc.js:727-729` `notifyEgressLive()` requires `egress.live === true`; gates `:72`, `:242`, `:505` | Yes, on rc.4+ boxes only (2) |
| Outboxlog bounded persistence | `packages/services/builtin/outboxlog/index.js:150-158` throws `OUTBOXLOG_BOUNDED_PERSISTENCE_REQUIRED` | Not yet — see B-1 |
| Public read-plane fixes | `CHANGELOG.md:44-58` — non-HEAD file GET 502; egress budget unenforced on exact app-origin | Ships in rc.5/rc.6 |
| App-origin HTTPS gateway runtime | `packages/core/gateway/{hive-host,exact-app-context,public-app-admission}.js`, wired `gateway-server.js:23,75,115-150,238-246`; `git ls-tree v0.25.0-rc.5 packages/core/gateway/` lists all three; 34/34 unit tests pass | Merged but opt-in-off (no `hiveAppHostSuffix` default) |
| Fleet update path fix | `CHANGELOG.md:9-42` — `patch-package` moved to prod deps; `rollback_to_previous()` gains `--force` | **rc.6 only, and rc.6 is not in any channel** |

### 1.3 Audited RC6 baseline: the two headline claims were inert

Every `HIVERELAY_*` service/Tor variable in the three shipped packagings is read by **zero** lines
on the runtime those packagings launch. Measured directly:

```
$ for v in HIVERELAY_TOR HIVERELAY_ENABLE_SERVICES HIVERELAY_VRF HIVERELAY_NOTIFY \
           HIVERELAY_OUTBOXLOG HIVERELAY_STORAGE_PROOF HIVERELAY_WITNESSLOG \
           HIVERELAY_REPAIRTICKET HIVERELAY_SHARD_STORE; do
    grep -rn "process\.env\.$v\b" packages/ | grep -v node_modules | wc -l
  done
→ 0 0 0 0 0 0 0 0 0
```

- All three packagings run the **Node** CLI: `hiverelay.service:13`
  `ExecStart=/usr/bin/node /opt/hiverelay/cli/index.js start --storage /var/lib/hiverelay`;
  `Dockerfile:156` `ENTRYPOINT [... "node", "/app/packages/core/cli/index.js"]`;
  `umbrel-app/docker-compose.yml` inherits that image.
- Six of the vars are read **only** by the Bare/Pear runtime:
  `bare-relay.js:480,486,496,508,519,530` (`=== '1'`). `BareRelay` is imported only by
  `packages/core/pear-entry.js:30`.
- Three — `HIVERELAY_ENABLE_SERVICES`, `HIVERELAY_VRF`, `HIVERELAY_TOR` (+ six `HIVERELAY_TOR_*`) —
  are read by **no code anywhere in the repo**.
- `docker-entrypoint.sh` is 13 lines of chown + exec; it translates nothing.
- Defaults therefore stand: `config/default.js:207-208` `enableServices: false, plugins: []`;
  `config/default.js:272` `transports.tor: false`.

**Consequence:** a clean `docker compose up -d` / systemd install produces a relay with zero services
and no onion. Every fleet box's service set exists because someone hand-wrote `services.json`.
`services.json` is the runtime authority **by default, not by design**.

Nuance worth recording: the Node-vs-Bare split *is* documented (`docs/SERVICES.md:394-395`,
`PRODUCTION.md:196-210`, `docs/PROTOCOL-SPEC.md:588`, `docs/FLEET-TOR-COHORT.md:22`). The defect is
that the deployment artifacts contradict their own docs — `hiverelay.service:20`
*"Utility services (enabled by default across the fleet)"* and `:32` *"Tor (enabled by default)"*
sit directly above `ExecStart=/usr/bin/node`. And `dashboard-admin-operator/server.cjs:517` writes a
systemd drop-in `Environment=HIVERELAY_OUTBOXLOG=1` then `:210` reports the service enabled from that
same variable — an operator tool built on the false assumption.

### 1.4 Honesty gates: good where they exist, unevenly applied

| Gate | Location | Verdict |
|---|---|---|
| Notify egress liveness | `capability-doc.js:727-729`, rationale `:718-726` | **Exemplary.** Refuses to advertise `notify-v1` when the provider is a memory stub. |
| forwardRelay opt-in | `capability-doc.js:189` gated on `relay.forwardRelay && .enabled`; test `capability-doc.test.js:78-88` | Correct |
| privacyTransports readiness | `capability-doc.js:47` `if (tt.health !== 'ready') return []` | Correct in form; the underlying health signal is weak — see A-3 |
| **Custody** | `capability-doc.js:166` `const custodyEnabled = !relayKernelProfile && moduleEnabled(config.custody)` | **Config-only.** Advertises 4 custody verbs with `_custodyProtocol` possibly null. Contrast `:77`, which gates `seed.publish` on `relay._publishProtocol` three lines below. |
| **The four services v0.25 turns on** | `grep -cinE "vrf\|shard-store\|witnesslog\|repairticket" packages/core/core/capability-doc.js` → **0** | **Absent.** `buildServicesProtocolProfile` (`:501-544`) handles exactly `notify` and `outboxlog`. |

---

## 2. Wired but not enabled

Everything here works; nothing turns it on.

| Capability | How to turn it on | Resource cost | Which boxes can take it |
|---|---|---|---|
| `identity` service | add `"identity"` to `<storage>/services.json` plugins | Zero. `identity-service.js:26-50` — constructor sets `this.node = null`; grep for `setInterval\|Map\|readFile\|writeFile` in that file returns **no matches** | All 13 — but see caveat below |
| `schema` service | same | One Map, 65 KB/schema guard `schema-service.js:55`, no timers, no disk | All 13 |
| `sla` service | same | One Map + one 60 s interval `sla-service.js:16,59` | ≥ 2 GB |
| `storage` service | same | `storage-service.js:30-31` maxDrives 256, maxWriteBytes 10 MiB; exposes Hyperdrive CRUD | ≥ 2 GB |
| `ai` service | same, plus `config.ai.qvac.models` for any real capability | Free at rest (`ai-service.js:695` — models load only from `qvac.models`) + one 60 s cleanup timer. With models, dominant consumer | ≥ 8 GB only |
| **VRF randomness beacon** | **Impossible on the Node fleet today.** `vrf-service.js:106-112` reads `opts.beacon` in the constructor only; `start()` (`:130`) never reads `context.config.vrfBeacon`. PluginLoader passes fixed `constructorOpts` = `{policyGuard, getAppTier, ai}` (`relay-node/index.js:1799-1804`). Sole wiring is `bare-relay.js:460` | One `setInterval` + in-memory ring buffer | None until a 1-line fix (see §3) |
| **forwardRelay** privacy tier | `config.forwardRelay.enabled = true` (or the existing operator-dashboard toggle, `dashboard-admin-operator/server.cjs:518`) | **Unbounded.** `forward-relay.js` ignores `stream.write()` backpressure; bounded only by 64 MB × 5 forwards/peer | **None.** Do not enable — see §6 |
| **Tor transport** | `config.transports.tor = true` in the box's `config.json`, or `--tor`. **Not** `HIVERELAY_TOR=1` | Tor daemon + descriptor uploads | Boxes with host tor ≥ 0.4.9; currently 3 hosts have tor, 2 have transport |
| `notify` real egress | one `notify.push` descriptor + provider credentials per box; requires 0.25 (`v0.24.3` has no `notify` config key at all) | Negligible; constraint is credential custody | ≥ 2 GB |
| `storage-proof` via API | **Blocked.** `api-service-config.js:1-16` `BUILTIN_SERVICE_PLUGINS` has 14 names and omits `storage-proof`, which `plugin-loader.js:43` registers. Verified: `normalizeManageServicePlugins(['storage-proof'])` → `{"ok":false,"error":"unknown service plugin: storage-proof"}` | n/a | Hand-edit `services.json` only |

**Caveat on `identity`, which the raw cost argument understates:** `docs/SERVICE-CONTRACT.md:27,57`
deliberately assigns identity lifecycle to the app side ("zero relay involvement"). And
`identity.peers` discloses connected-peer pubkeys; it is role-gated only when the router is attached
(`relay-node/index.js:1866-1869`) — the fallback path `services/registry.js:139-175` applies no role
check. On Tor / blind-custody hosts that is peer-graph exposure, not "a Map lookup".
Given the `serviceDefaultPeerRole` regression (§7, C-1), **fix the role default first.**

### 2.1 There is no supported way to *enable* a service on a systemd box

| Surface | Finding |
|---|---|
| CLI | `grep` for `args.plugins`/`args.services` in `packages/core/cli/index.js` → nothing. `--help` start options (`:1567-1595`) list only `--tor`, `--tor-socks-port`, `--tor-control-port` |
| TUI | `cli/manage.js:252-258` offers only Disable / Restart / View details / Back. It *does* have an Enable path for **transports** (`:378-406`) — just not services |
| Full dashboard | `dashboard/index.html` has zero occurrences of `plugin`; `grep -rn "manage/services" dashboard/` matches only `blindspark.html`, served only when `uiSimple` (`api-dashboard-routes.js:19`), and `config/default.js:98` is `simple: false` |
| Setup wizard | `cli/setup.js:242-251` *does* write `config.plugins`, but its `ALL_SERVICES` list (`:100-110`) offers **9 of 15** builtins — it omits `outboxlog, witnesslog, repairticket, notify, storage-proof, shard-store`, i.e. exactly the utility set the fleet runs |
| Management API | **Writes the wrong file.** `POST /api/manage/services/config` → `api-service-config.js:151-153` → `api.js:2192-2196` `saveConfig()` → `~/.hiverelay/config.json`. The only writer of `<storage>/services.json` is `RelayNode.setServicesConfig` (`relay-node/index.js:1017`), which has **zero production callers** (grep finds only `test/unit/api-services.test.js:49`, `test/unit/relay-node.test.js:276`) |

**Net:** on a box that already has `services.json` with `enabled: true`, an API/dashboard service edit
appears to work and is **silently discarded at the next restart** by `_loadServicesOverride`.
`docs/HIVERELAY-DETAILED-ARCHITECTURE-DIAGRAM.md:372-373`, which draws
`/api/manage/services/config → storage/services.json atomic write`, is inaccurate.

---

## 3. Spec'd but not wired

| Spec | Where specified | What exists | What is missing | Effort |
|---|---|---|---|---|
| VRF randomness beacon | `docs/SERVICES.md:133` — "Enabled via `vrfBeacon: { enabled, intervalMs, domain, retain }`" | Full beacon impl + 5 HTTP routes (`api-vrf.js:16-19`, mounted `api.js:950-970`) | `start()` never reads `context.config.vrfBeacon`. Routes return **503 `BEACON_DISABLED`** (`vrf-service.js:394-396` → `api-vrf.js:158-159`) on all 10 vrf boxes | **Trivial.** `_buildServiceContext()` already passes `config: this.config` (`relay-node/index.js:4407`) — merge `context.config?.vrfBeacon` before the `:156` gate. Do **not** widen `constructorOpts` |
| Bandwidth receipts | `PROTOCOL-SPEC.md:714,752`; `:937` "Bandwidth served +0.001 pts/MB — From verified bandwidth receipts" | `BandwidthReceipt` class (`protocol/bandwidth-receipt.js:71`), instantiated `relay-node/index.js:1542`, advertised as `bandwidth-receipts` (`capability-doc.js:231`) | **No ingestion path.** `createReceipt`/`collectReceipt`/`aggregateReceipt` have zero production callers. `messages.js:621` `// bandwidthReceiptEncoding removed`. Reputation instead self-scores: `index.js:1549-1556` `recordBandwidth(<own swarm pubkey>, bytesRelayed)` — the inverse of the §13.7 Sybil argument. `verified.count/bytes` in `GET /api/usage` is structurally always 0 | Medium |
| Reputation uptime + geo | `PROTOCOL-SPEC.md:938-939`, §11.5 `:977` | `recordUptime()` (`incentive/reputation/index.js:89`), `applyGeoBonus()` (`:100`) | **Zero callers anywhere**, incl. the three vnext worktrees. `record.region` permanently null. Note `selectRelays` (`:190`) also has zero production callers — this is dead code, not a live degradation. Replica diversity is handled independently by `quorum-selector.js:67` and `auto-heal.js:249-251` | Small |
| Tor negative probe | `docs/TOR-ONION-TRANSPORT.md:102` — "an all-invalid roster runs **fail-open** — hence the negative probe in the health gate" | Consumer plumbing only: `redaction.js:41-42`, `api-overview.js:265,282-284`, `dashboard/index.html:1177,1193-1203` ("neg-probe ok"/"neg-probe fail") | **No producer.** `grep -n negativeProbe packages/core/transports/tor/index.js` → empty; `getInfo()` (`:800-814`) never emits it. `_probeNow()` (`:617-644`) is a *positive* SOCKS self-connect. The dashboard failure branch can never fire. `GIGA-RELEASE-ARCHITECTURE.md:171` already says "NOT implemented … Required before RC" | Medium |
| Shard-store STO-005 accounting | code comment `relay-node/index.js:4408-4411` | `shard-store/index.js:142` reads `context.storageAccounting` | Context built at `:1811`, `StorageAccounting` constructed at `:2437` — ~625 lines later. Runtime-verified: `providerAccountingRegistered: false`. **Impact is telemetry only** — the admission guard uses `measureProvenStorageTreeBytes` (`:3614-3624`), a real tree walk that already counts shard cores; eviction's cap gate uses `max(diskBytes, …)` (`storage-accounting.js:262-268`) | Small |
| Shard pin persistence | `docs/BLIND-SHARD-STORE-SPEC.md:362` — "journal-first (append per pin) + periodic snapshot checkpoint" | `ShardPinRegistry` in-memory (`shard-pin.js:133`) | `grep -rn pinPersistence packages/` → **exactly one line**, `shard-store/index.js:130 persistence: this.opts.pinPersistence \|\| null`, and `opts` is the fixed 3-key `constructorOpts`. Blobs persist (Hyperblobs+Hyperbee) but pins do not → every restart strands shard bytes with **no GC path** | Medium |
| Blind-cell repair | `docs/BLIND-CELLS.md:208` states it honestly as spec-only | client-side `shard-recover.js` | `grep -iE "shard\|cell\|custody" packages/core/core/auto-heal.js` → **no matches** in both trees. AutoHeal is scoped to archive-tier drives (`:67` `ARCHIVE_TIER = 1`, filtered `:459,:490`) | Large |
| Split transport (G2-W) | `02-apps/peerit/docs/SPLIT-TRANSPORT-SPEC-V1-2026-07-26.md` — **outside this repo** | Wire layer in `hiverelay-blind-vnext-integration/packages/blind-protocol/` (`registry.js:48-49` OHTTP roles, `:1344` `BlindOhttpKeyConfigV1`, `schemas.js:1500` FORWARD family) | `BlindTransportDescriptorV1` exists in **no code tree** — only in two prose documents. `LADDER-SHIP-MAP.md:303` already records the spec is *behind* the code | Medium |
| `MSG` opcode table | `PROTOCOL-SPEC.md` §4 | `protocol/messages.js:14-45` | **100 % dead.** Repo-wide `grep -rn "\bMSG\b"` returns only the definition; not re-exported from the package root, so `import { MSG } from 'p2p-hiverelay'` (`docs/DEVELOPER.md:973`) throws. **9** names have no encoding and no handler: `SEED_CANCEL 0x04, SEED_HEARTBEAT 0x05, SEED_STATUS 0x06, RELAY_UPGRADE 0x18, BANDWIDTH_RECEIPT 0x22, RECEIPT_ACK 0x23, PEER_ANNOUNCE 0x30, PEER_QUERY 0x31, PEER_RESPONSE 0x32` | Small (doc) |

**Dimension note:** `docs/BLIND-CELLS.md` and `docs/NAMESPACE.md` verify line-for-line against code, and
`docs/STORAGE-CAP-SAFETY.md` self-flags its own gap accurately. The spec-drift problem is concentrated
in `PROTOCOL-SPEC.md` and a handful of Tor/services sentences.

> Resolution note (2026-07-29): the Tor negative-probe finding above records the audited baseline. The release-repair branch now produces `negativeProbe`, automatically probes an exposed vport, degrades restricted endpoints that accept anonymous access, and refuses to sign-advertise a restricted endpoint without a successful negative proof. Live/fleet evidence is still pending.

---

## 4. Built but not deployed — per-box gap analysis

### 4.1 THE ROLLOUT STATE HAS MOVED SINCE THE UNDERLYING AUDITS RAN — READ THIS FIRST

The dimension audits recorded `origin/main:fleet/channels.json` as `canary: v0.24.3`.
**That is now stale.** Commit `6248942` (*"chore(fleet): promote canary to v0.25.0-rc.5; add `hold` channel (#204)"*)
has landed:

```
$ git show origin/main:fleet/channels.json
  "stable": "v0.24.3",  "canary": "v0.25.0-rc.5",  "hold": "v0.24.3"
```

`fleet/updater.sh:31` points at exactly that file
(`https://raw.githubusercontent.com/bigdestiny2/P2P-Hiverelay/main/fleet/channels.json`), and it resolves
a **tag**, not a branch (`:157-176` → `git fetch --tags` → `git rev-parse refs/tags/$TARGET^{}`), so
`v0.25.0-rc.5` not being an ancestor of main is irrelevant. The tag is fetchable and validly signed
(`git tag -v v0.25.0-rc.5` → good signature, principal `bigdestiny2@users.noreply.github.com`).

**Every canary box with a live timer is now attempting to install rc.5 — the one build that cannot
be installed.** `CHANGELOG.md:9-14`: *"**Use this, not rc.5.** rc.5 cannot be installed by the fleet
updater."* `patch-package` was a devDependency while `postinstall` invoked it; `npm ci --omit=dev`
skips it and `postinstall` exits **127**. The failure lands at `updater.sh:280` `deps_if_changed`,
*before* `systemctl restart` at `:281`, so the relay does not go down — but rc.5's own
`rollback_to_previous()` lacks `git checkout --force`, and `npm ci` has already dirtied
`package-lock.json`, so the rollback also fails. Observed on utah 2026-07-28 (`CHANGELOG.md:38-42`).

`v0.25.0-rc.6` fixes both and is validly signed — and is named in **no channel**.

| | State |
|---|---|
| `origin/main` canary | `v0.25.0-rc.5` — **broken install** |
| Branch `feat/service-http-wiring` channels.json | `v0.25.0-rc.4` — would *revert* the promotion on merge |
| HEAD / newest signed tag | `v0.25.0-rc.6` — the only installable 0.25 build, unreferenced |

**Exposure.** Canary boxes are utah, utah-0.5gb, bern (`fleet/relays.json`). Per
`docs/RELEASE-RUNBOOK-0.25.0-rc.5.md:110` (*"Automation off | utah, utah-8gb, dallas | stale/none | ❌ | inactive"*),
utah's timer is off and bern is down. **The single exposed box is `utah-0.5gb`** — the 0.5 GB,
ABRT-prone box, whose agent is additionally stale (no `verify_tag`, no signers, runbook `:109`).

**Action, before anything else in this report:** set `canary` to `v0.25.0-rc.6` on `origin/main`, and
resolve the `channels.json` conflict this branch will otherwise cause on merge.

### 4.2 Per-box gap table

Free-disk computed from `fleet-live.json` `diskGB × (100 − disk_pct)`.

| Box | RAM | Disk free | Chan | Ver | Svcs | Src | Principal gaps |
|---|---|---|---|---|---|---|---|
| utah | 12 GB | 276 GB | canary | rc.4 | 10 | config | Timer off, so pinned at rc.4 by hand. Tor transport live. Left on an rc.5 checkout by the failed update |
| utah-8gb | 8 GB | 960 GB (n/a) | **stable** | rc.4 | 10 | config | Hand-placed above its channel; **arming its timer downgrades it to v0.24.3** (see §6, R-3). Tor live |
| dallas | 12 GB | 265 GB | — | 0.24.3 | **unknown** | **none** | Absent from every committed inventory. No updater. Largest un-Tor'd NA box |
| bern | 4 GB | 500 GB (n/a) | canary | — | — | error | Provider outage. Documented shard-store candidate (`LADDER-SHIP-MAP.md:137`) that never got it |
| dubai | 4 GB | n/a | stable | 0.24.3 | 10 | config | Tor host, services via services.json. On 0.24.3 → no notify honesty gate |
| sydney | 2 GB | 32.4 GB | stable | 0.24.3 | 9 | config | Track B blind public-test host at :443. No shard-store |
| amsterdam | 2 GB | 34.2 GB | stable | 0.24.3 | 10 | config | **Runs shard-store at 2 GB, contradicting `LADDER-SHIP-MAP.md:138`** ("Small boxes (0.5–2 GB): utilities only, no shard-store") |
| utah-2gb-a | 2 GB | 47.4 GB | stable | 0.24.3 | 9 | config | Room for more; NA-concentrated |
| utah-us | 2 GB | 33.6 GB | stable | 0.24.3 | 9 | config | Same |
| sing-2 | 1 GB | **59.2 GB** | stable | 0.24.3 | 9 | config | **Roomiest APAC box, no shard-store.** Still running full 9-service suite despite the documented ≤1 GB trim |
| sing-1 | 1 GB | 8.5 GB | stable | 0.24.3 | 9 | config | Named in the ABRT row; documented trim not evidenced |
| miami | 0.5 GB | 16 GB | stable | 0.24.3 | 9 | config | Named in the ABRT row; documented trim not evidenced |
| utah-0.5gb | 0.5 GB | 11.4 GB | canary | 0.24.3 | **1 (live)** | **live** | The only runtime-verified row. Runs `["outboxlog"]` — **not** the documented trim of `outboxlog, notify, vrf`. **Only box exposed to the rc.5 install failure** |

### 4.3 Five of fifteen builtins run nowhere

`plugin-loader.js:20-47` registers 15. Union of `services` across all 12 relay records = 10.
Difference = **`storage`, `identity`, `ai`, `sla`, `schema`**.

Sharper than "some services are unused": `docs/SERVICES.md:508` lists the shipped **Service Operator**
profile default set as `identity, storage, schema, vrf`. **No fleet box runs that profile.** The
configuration the docs present as the production services posture has zero instances.
(`ai` and `sla` are labelled experimental at `SERVICES.md:512`, so their absence is consistent with
stated intent — though `zk` and `arbitration` carry the same label and run on 10 boxes via the poker bundle.)

### 4.4 Deployed-but-non-functional

| Service | Boxes | Why it produces nothing |
|---|---|---|
| `notify` | 10 | `config/default.js:227-231` `push: null` → `notify-service.js:76` installs `createMemoryPushProvider`, `live: false` (`:1053-1061`). Wakes are recorded (`:526`) and return `ok: true` (`:536`) having been dropped. **On the 8 boxes at v0.24.3 this is actively mis-advertised**: `git show v0.24.3:.../capability-doc.js:163` pushes `notify-v1` with no egress condition, and `:405-409` advertises `providers: ['runtime','apns','fcm','webpush']`. Only utah and utah-8gb (rc.4) correctly stay silent |
| `vrf` beacon | 10 | Five beacon routes return 503 `BEACON_DISABLED` — unreachable by config on the Node runtime |
| `storage-proof` | 10 | Runs, but the management API rejects its own name; invisible in the Services tab |
| Tor transport | 0 of 12 | `summary.tor_transport: 0` while `tor_host: 3` |

---

## 5. Fleet service diversity plan

This is the headline deliverable. It is **ordered**, and the ordering is load-bearing.

### 5.0 Two hard blockers — nothing below proceeds until both clear

| # | Blocker | Evidence | Gate |
|---|---|---|---|
| **B-0** | `origin/main` canary points at rc.5, which cannot install | §4.1 | Set canary → `v0.25.0-rc.6`; resolve this branch's conflicting `channels.json` |
| **B-1** | Any box that restarts into rc.6 with `outboxlog` and no hypercore journal **fails `start()`** | `outboxlog/index.js:150-158` throws; `relay-node/index.js:699` constructs `storageAdmission` unconditionally; `:1813` rethrows `SERVICE_START_FAILED` unless `config.servicesFailOpen === true` — a key that appears **exactly once in the repo** (that line) and in no doc | Validate the journal config on one box first |

**B-1 detail and honesty caveat.** The gate landed in rc.1 (`git show v0.24.3:.../outboxlog/index.js | grep -c BOUNDED_PERSISTENCE_REQUIRED` → 0; rc.4/rc.5/rc.6 → 1) and is documented at
`docs/STORAGE-CAP-SAFETY.md:264-271` and `docs/SERVICES.md:251,263-266` — but **not** in
`docs/RELEASE-RUNBOOK-0.25.0-rc.5.md` or `CHANGELOG.md` (grep for `OUTBOXLOG_BOUNDED_PERSISTENCE_REQUIRED`
or `maxJournalStorageBytes` over both → no output). The updater *is* health-gated with auto-rollback
(`updater.sh:283-304`), so the expected outcome is a reverted upgrade, not a fleet outage.

**The obvious fix is not yet validated.** Setting
`{"outboxlog":{"journal":"hypercore","maxJournalStorageBytes":…}}` on a fresh store still failed in
testing with `STORAGE_EMPTY: No Hypercore is stored here`, and the repo's own test for exactly that
config (`test/unit/storage-startup-rollback.test.js:218`) is one of the three known failures.
**Do not push that config fleet-wide.** Recover the working configuration from utah / utah-8gb, which
already survived this gate on rc.4, and replicate it.

### 5.1 Sequencing principle

1. Blockers (B-0, B-1) and the security regression (C-1) first.
2. Then large NA boxes — highest headroom, lowest blast radius.
3. Then non-NA (EU/ME/APAC) — this is where the diversity value is.
4. **0.5–1 GB boxes last**, and mostly by *removal*, not addition.
   `docs/FLEET-STABILITY-2026-07-27.md:9` records `status=6/ABRT` "every few hours" on
   miami, utah-0.5gb, sing-1 running the full plugin suite.

### 5.2 The regional concentration problem, stated plainly

| Region | Boxes | Share |
|---|---|---|
| NA | utah, utah-8gb, utah-us, utah-2gb-a, utah-0.5gb, miami, dallas | **7 of 13** |
| APAC | sing-1, sing-2, sydney | 3 |
| EU | amsterdam, bern | 2 |
| ME | dubai | 1 |

Five of seven NA boxes are `utah-*` — one provider, one site. Adding services to NA boxes adds
capability but **zero** diversity. Worse, the fleet is currently unable to *express* this:

- `capability-doc.js:305` `const region = (config.regions && config.regions[0]) \|\| null` — nothing
  sets `config.regions`, so every relay signs `region: null`.
- The doc has **no `operator` field at all** (`grep -n operator capability-doc.js` → comments only;
  the doc object at `:331-350` has `region`, no `operator`).
- `packages/client/index.js:5455` therefore falls back to `doc.pubkey`, and
  `quorum-selector.js:126` `const op = r.operator || r.pubkey` counts **every relay as its own operator**.

With `DEFAULT_MIN_OPERATORS = 3` (`quorum-selector.js:39`), a 5-relay quorum drawn entirely from this
one operator reports **5 distinct operators and passes**. The region dimension *does* warn
(1 region < `minRegions` 3, so `diversityWarning` fires and the client emits `quorum-warning`,
`packages/client/index.js:3818-3820`) — but the operator dimension is **falsely satisfied**, which is
the more dangerous of the two. This directly contradicts `docs/PROTOCOL-SPEC.md:118-119`:
*"Three endpoints or relay keys under one operator are not independent replicas."*

**Step 0 of the diversity plan is therefore not a service at all** — it is making the concentration
*visible*. See §5.3 wave 1.

### 5.3 The plan

`services.json` shape required by `_loadServicesOverride` (`relay-node/index.js:1000-1006`) —
`enabled` must be strictly `true`:

```json
{ "enabled": true, "plugins": ["…"], "updatedAt": 0 }
```

Write it to `/var/lib/hiverelay/services.json` and restart. **Do not use
`POST /api/manage/services/config`** — it writes `~/.hiverelay/config.json`, which
`_loadServicesOverride` then overwrites at the next restart (§2.1).

---

#### Wave 0 — blockers and the security regression (no service changes)

| Step | Action | Evidence |
|---|---|---|
| 0.1 | `origin/main` `channels.json` canary → `v0.25.0-rc.6`; resolve this branch's conflicting copy | §4.1 |
| 0.2 | Fix `packages/core/config/default.js:205` → `serviceDefaultPeerRole: 'anonymous'` | §7 C-1 |
| 0.3 | Add `'storage-proof'` to `api-service-config.js:1-16` `BUILTIN_SERVICE_PLUGINS` | one line |
| 0.4 | Make `POST /api/manage/services/config` call `node.setServicesConfig()` | `relay-node/index.js:1017` is the only writer and has no production caller |
| 0.5 | Recover utah/utah-8gb's working `outboxlog.journal` config; validate on **one** box | B-1 |
| 0.6 | Bind `dashboard-admin-operator` to 127.0.0.1 + shared secret | §6 R-1 — **it is listening on `*:3458` right now** |

#### Wave 1 — make diversity measurable (all 13 boxes, no runtime cost)

Set in each box's `config.json` (not `services.json`):

| Box | `regions` | `operator` |
|---|---|---|
| utah, utah-8gb, utah-us, utah-2gb-a, utah-0.5gb, miami, dallas | `["NA"]` | `"hiverelay-foundation-fleet"` |
| amsterdam, bern | `["EU"]` | same |
| sing-1, sing-2, sydney | `["AS"]` (sydney `["OC"]`) | same |
| dubai | `["AS"]` | same |

Use the canonical enum at `protocol/messages.js:64` (`NA/SA/EU/AF/AS/OC`), matching `fleet/relays.json` —
**not** `APAC`/`ME`. Use **one shared** operator string; the shipped auto-recommendation at
`cli/index.js:1503` proposes a *per-host* id (`'hive-foundation-' + hostname`), which would preserve
the 13-distinct-operators illusion.

**This requires a code change to have any effect on quorum clients:** `capability-doc.js` must emit
an `operator` field (today it emits none), and `capabilityDocToRelayInfo` must prefer it over
`doc.pubkey`. Until then `config.operator` only surfaces via `/catalog.json`
(`api-catalog-read.js:101-102`), which the quorum path does not read.

Expected outcome — and this is the point — `selectQuorum` starts correctly reporting
**1 operator, not 13**, and `insufficient-operator-diversity` begins firing. That is a prerequisite
for ever honestly claiming G3, not an obstacle to it.

#### Wave 2 — large NA boxes (capability, not diversity)

| Box | Add | New set | Rationale |
|---|---|---|---|
| dallas | `identity, schema, sla` + full utility suite | — | First: it is currently unmanaged, so it is the safest test subject. **Also add a `fleet/relays.json` entry with `channel: "hold"`** (see §6 R-6) |
| utah (12 GB) | `identity, schema, sla` | 13 | Canary; already Tor-live |
| utah-8gb (8 GB) | `identity, schema, sla` | 13 | 960 GB disk |

`ai` is deferred to next milestone on all boxes — free at rest, but only meaningful with
`config.ai.qvac.models`, at which point it becomes the box's dominant consumer.

#### Wave 3 — non-NA (the actual diversity win)

| Box | RAM | Add | New set |
|---|---|---|---|
| dubai | 4 GB | `identity, schema, sla` | 13 |
| amsterdam | 2 GB | `identity, schema, sla`; **and remove `shard-store`** — see below | 12 |
| sydney | 2 GB | `identity, schema, sla` | 12 |
| bern | 4 GB | on recovery: `identity, schema, sla` **+ `shard-store`** (500 GB, documented candidate at `LADDER-SHIP-MAP.md:137`) | 13 |

#### Wave 4 — 2 GB NA remainder

`utah-us`, `utah-2gb-a`: add `identity, schema, sla` → 12 services.

#### Wave 5 — the fragile boxes, handled by REMOVAL (last, one at a time, 48 h soak each)

`docs/FLEET-STABILITY-2026-07-27.md:31-33` says the ≤1 GB trim was applied. **No artifact in the repo
corroborates it**: `git log --all -S "Plugin set trimmed"` hits only `40ea4bf`, the commit that adds
the doc; no fleet script touches plugin sets; and `fleet-live.json`, committed in that same commit,
shows miami/sing-1/sing-2 still at 9 services. The one live reading (`utah-0.5gb` = `["outboxlog"]`)
does not match the documented trim either. `dashboard-admin-operator/control-policy.json:20-28`
independently defines the ≤1.1 GB tier as `["outboxlog","notify","vrf"]`.

| Box | RAM | Free | Target `plugins` | Removing |
|---|---|---|---|---|
| sing-2 | 1 GB | 59.2 GB | `["outboxlog","notify","vrf","storage-proof","identity"]` | poker, zk, arbitration, witnesslog, repairticket |
| sing-1 | 1 GB | 8.5 GB | `["outboxlog","notify","vrf","identity"]` | + storage-proof (only 8.5 GB free) |
| miami | 0.5 GB | 16 GB | `["outboxlog","notify","vrf","identity"]` | same |
| utah-0.5gb | 0.5 GB | 11.4 GB | `["outboxlog","notify","vrf"]` | restore notify+vrf to match the documented trim; **no `identity`** |

Rationale for removal over addition:
- `arbitration-service.js:111` `this.disputes = new Map()` — **no size cap, no TTL, no eviction** in
  771 lines (only `.clear()` on stop, `:150`). With the peer-role regression (C-1) it is remotely
  fillable by any swarm peer.
- `witnesslog`/`repairticket` each hold ~256 MiB of value bytes in RAM
  (`DEFAULT_MAX_TOTAL_BYTES`, `outbox-log.js:32`) and perform a **synchronous full-JSON snapshot
  rewrite on every append** (`outbox-log.js:1487-1493,1947-1962`) with no storage-authority admission
  — the exact gap `docs/STORAGE-CAP-SAFETY.md:273-278` names as blocking any mainnet-ready claim.
- `poker` drags in `vrf + arbitration + zk` via `SERVICE_BUNDLES` (`plugin-loader.js:57-59`).
  Listing `vrf` alone does **not** drag in the others — `expandServiceDeps` (`:64-70`) expands bundle
  keys only.

### 5.4 What NOT to enable, and why

| Do not enable | Where | Why |
|---|---|---|
| **`forwardRelay`** anywhere | `config.forwardRelay.enabled` | `forward-relay.js` pushes `targetStream` 'data' straight into protomux and **ignores `stream.write()`'s return value** — no backpressure. Bounded only by 64 MB × 5 forwards/peer. Also reachable one-click via the operator dashboard (`server.cjs:518`), which is currently unauthenticated |
| **`shard-store` on any new box** | — | Pin registry never persisted (`shard-store/index.js:130`, sole occurrence). Blobs persist, pins do not → each restart permanently strands bytes with no GC path. `unpin` is a no-op after restart (`:402-408`, `pins.remove()` → `removed:false`). Fix pin persistence **journal-first** first (`shard-pin.js:278-285` uses a 250 ms debounce on an `unref()`'d timer and only force-flushes in `stop()` — which never runs under the fleet's 2-minute SIGKILL watchdog, `FLEET-STABILITY:21`) |
| **`shard-store` on amsterdam** — remove it | 2 GB box | Directly violates `LADDER-SHIP-MAP.md:138` and `:424` |
| `ai` on < 8 GB | — | `ai-service.js:46-52` maxQueue 100 / maxConcurrent 2; with models it dominates the box |
| `storage` on < 2 GB | — | `storage-service.js:30-31` — 256 drives, 10 MiB writes |
| `arbitration`/`zk`/`poker` on ≤ 1 GB | — | Uncapped dispute map + ABRT history |
| `identity` on Tor / custody hosts, pre-fix | utah, utah-8gb, dubai | `identity.peers` discloses peer pubkeys and is role-unchecked on the registry fallback path (`services/registry.js:139-175`). Safe **after** C-1 |
| **`diskHealthGate: true` anywhere** | `PRODUCTION.md:433` recommends it | Combined with the deployed watchdog it becomes a SIGKILL loop, not a drain — see §6 R-4 |

### 5.5 Expected end state

| Metric | Now | After |
|---|---|---|
| Builtins running somewhere | 10 / 15 | 13 / 15 (`storage`, `ai` remain deferred) |
| Boxes running `identity` | 0 | 9 (excl. the three 0.5–1 GB fragile + utah-0.5gb) |
| Boxes running `shard-store` | 4 (incl. one policy violation) | 4 (amsterdam → bern), **after** pin persistence |
| Distinct operators reported to quorum clients | 13 (false) | 1 (true) |
| Regions expressed in capability docs | 0 (`region: null`) | 4 |
| Non-NA share of the full service suite | 4 / 13 | 6 / 13 |

---

## 6. Improvements, ranked

Score = (impact × likelihood) / effort. Impact/likelihood on 1–5.

### Before promoting stable

| # | Item | I | L | E | Score | Evidence |
|---|---|---|---|---|---|---|
| **R-1** | **`dashboard-admin-operator` is an unauthenticated fleet-root control plane on `0.0.0.0`** | 5 | 5 | S | **25** | `server.cjs:622` `server.listen(PORT, …)` with no host arg (verified: `address()` → `"::"`); `grep -cnE 'apiKey\|Authorization\|token' server.cjs` → **0**; wildcard CORS on preflight (`:298-301`) *and* every response (`:574`). Unauth side effects: `systemctl restart` (`:463`), `git pull && npm install && restart` (`:472`), `/etc/fstab` + `swapon` (`:479-489`), systemd drop-ins + `config.json` rewrite (`:513-551`). Injection: `POST /api/relay` validates only truthiness (`:397`), persists (`:420`), and `probeNode` interpolates unquoted into `exec(\`nc -z -G 3 -w 3 ${ip} 22\`)` (`:107`) and `ssh … root@${ip}` (`:112`) — re-executed every 60 s by `setInterval` (`:632`). **Verified live on this machine:** `lsof -nP -iTCP:3458 -sTCP:LISTEN` → `node 51423 … TCP *:3458 (LISTEN)`. Its own `README.md:106` says "runs locally / do not expose port 3458"; the sibling `scripts/local-fleet-dashboard.mjs:121` correctly binds `127.0.0.1`. **Fix:** bind 127.0.0.1, shared secret, `execFile` with argv array, drop wildcard CORS |
| **R-2** | **Canary channel points at the uninstallable rc.5** | 5 | 5 | T | **25** | §4.1 |
| **R-3** | Arming a timer downgrades a hand-placed box | 4 | 4 | S | **16** | `updater.sh:178` gates only on SHA equality; `:273` checks out whatever the channel names, in either direction. `utah-8gb` is `channel: stable` running rc.4 while stable is pinned at `v0.24.3` — arming its timer converges it *backwards*, recorded as a successful update (health-gates green at 0.24.3). This is by design (`fleet/README.md:89-91` — channel rollback = set the tag back); the defect is the declared-vs-actual drift. **Fix:** pin utah-8gb to `hold` before arming any timer |
| **R-4** | `diskHealthGate` + watchdog = SIGKILL loop, not drain | 4 | 3 | T | **12** | `api-health.js:75-92` returns 503 `{ok:false, reason:'disk-critical'}`; `PRODUCTION.md:433-436` documents it as the drain signal; `fleet/health-watchdog.sh:46` tests `grep -q '"ok"…true'`, which fails on `ok:false` regardless of curl flags → `NEED_FAILS=2` (`:15`) → `systemctl kill -s SIGKILL` + `fuser -k -9` (`:63-71`), timer `OnUnitActiveSec=2min`. A restart frees no disk (`STORAGE-CAP-SAFETY.md:30-34`) → ~4 min loop forever. **Latent**: `diskHealthGate` defaults false (`relay-node/index.js:2423`) and no shipped config sets it — it arms the moment an operator follows the doc. Second copy of the same logic at `dashboard-admin-operator/controller.cjs:236-250`, there **without** the 90 s boot grace. **Fix:** whitelist HTTP 503 + `reason:"disk-critical"` as deliberate drain |
| **R-5** | Cap-raise repin swallows the durability error it explicitly requests | 4 | 2 | T | **8** | `app-lifecycle.js:1170` `try { await node.appRegistry.persistEntry(appKeyHex, { throwOnError: true }) } catch (_) {}` then `:1172` commits the reservation. The seed path 470 lines earlier does the opposite: `:702-711` restores the pre-seed view and rethrows, under a comment (`:713-717`) stating that committing first *"would leave a commitment in the ledger with no durable entry backing it"* — exactly what `:1170-1172` produces. In bee mode `_restoreDurableEntry` (`app-registry.js:2122`) reverts the map, so in-memory does **not** diverge; what diverges is ledger (newCap) vs durable (oldCap), while `_eagerReplicate` still gets `maxStorage: newCap` (`:1206`) and the function returns `{ok:true, changed:true}` |
| **R-6** | `dallas` in no committed inventory | 3 | 3 | T | **9** | `fleet/relays.json` → 12 entries, no dallas; `fleet-live.json` → 12 relays, no dallas; only in gitignored `relays.local.json:77-81`. **Fix carefully:** a plain entry enrolls it in the release gate — `scripts/check-fleet-rollout.mjs:209` and `verify-release-evidence.mjs:713-724` both default a missing channel to `stable`, and `:574` requires the evidence relay-name set to equal the channel-filtered inventory. Add with `channel: "hold"` |
| **R-7** | Rejected `seedCore` leaves the swarm topic joined forever | 3 | 3 | T | **9** | `seeder.js:173` joins `{server:true, client:true}` and `:174` `await swarm.flush()` **before** validation; a throw from `_authoritativeCoreSize` (`:181`, 10 s) or `STORAGE_BOUND_BELOW_ACTUAL` (`:183-189`) lands in the catch at `:261` whose `!entry` branch (`:275-277`) closes the core but never leaves the swarm. Success path proves the asymmetry: `_releaseEntryOwned` does `await this.swarm.leave(entry.topic)` (`:811`). `hyperswarm` re-announces every 10 min (`peer-discovery.js:4`), `_stop()` never sweeps it, and `unseedCore` bails at `if (!entry) return` (`:842`) — restart is the only remedy. Reachable from `POST /seed-core` and remotely, up to `MAX_SEED_DISCOVERY_KEYS = 64` |
| **R-8** | `storageAdmission.failClosed()` invisible to every health surface | 4 | 4 | S | **16** | `storage-admission-authority.js:802-804` — sets `_fatalReason`, no emit/log/metric. `grep -rn "storageAdmission\.\(snapshot\|getSnapshot\)" packages/` → **zero consumers**. `api-health.js:68-101`, `api-operator-telemetry.js:130-142`, `ws-feed.js`, `capability-doc.js` — none reference it. Worse than "silent": `canAcknowledge()` returns false (`:593`) → `hyper-gateway.js:720,769` return null → every gateway drive read 404s with *"still replicating"* — actively misdirecting. `fleet/health-watchdog.sh:46` also cannot see it. Same blind-spot class as `PRODUCTION.md:438-442` (Fly volume incident). **Fix:** surface `fatalReason`/`acceptingMutations` on `/health` and `/api/health-detail` |

### Next milestone

| # | Item | Score | Evidence |
|---|---|---|---|
| N-1 | Shard pin persistence, journal-first | 12 | §3 / §5.4. Blocks all shard-store expansion |
| N-2 | Parse `HIVERELAY_*` in `cli/index.js` (or strike the packaging claims) | 10 | §1.3 |
| N-3 | Gateway HTML rewrite has no size cap | 9 | `hyper-gateway.js:588-618` — `drive.get()` whole file → `.toString('utf-8')` → `Buffer.from()`, with `entry.value.blob.byteLength` already in hand at `:552`. `gatewayMaxTransformBytes`/`gatewayMaxResponseBytes` exist (`relay-node/index.js:146-147`) and are contract-asserted (`gateway-server.js:185-189`) but **never reach the data plane** — `gateway-server.js:270` passes no byte options, so `:466-467` `this._gateway?._maxResponseBytes ?? config.gatewayMaxResponseBytes` self-compares. Verified by instantiation: both fields `undefined`. **Best fix is simpler than the pre-check:** `drive.get(path, { timeout })` *does* cancel — `hyperdrive/index.js:316-320` forwards opts to `blobs.get`, `hyperblobs/lib/streams.js:118` → `core.session({ timeout })` |
| N-4 | `_withTimeout` abandons reads that keep running | 8 | `hyper-gateway.js:325-346` races a `setTimeout` reject with no cancel; wraps `drive.get` at `:589-593`. The tree already solved this: `cancellable-drive-update.js` exists because *"a raw `Promise.race` left the upgrade ref pending"* (`app-lifecycle.js:883`), and `seeder.js:419-438` calls `core.replicator.clearRequests(…)` in both the timeout handler and `finally`. The HTML branch is the only drive-read path with neither res-close teardown nor cancellation (the streaming branch has it at `:685-689`) |
| N-5 | Anchor/repair sweeps have no re-entrancy latch | 8 | `relay-node/index.js:4254`, `:4284` are bare `setInterval`s; `_trackFireAndForget` is `this._scope.tracked(promise)` (`:803-806`), which does not serialize. `repairUnanchored` does **not** take the per-key `_withDriveLease` lock (`app-lifecycle.js:404`) that `seedApp` (`:371`) does. Real amplification: `_runAnchorCheck` calls `clearAnchored` (`index.js:5049`) whenever its 3 s-bounded check returns false, while a concurrent `repairUnanchored` may have just called `setAnchored` (`:1459`). Also leaks a `PeerDiscoverySession` per attempt (`:1397` discards the return). The tree has the pattern: `eviction.js:347`, `storage-accounting.js:190` |
| N-6 | AppRegistry `'error'` event has zero subscribers | 6 | `app-registry.js:2219-2223`; emits at `:365,1984,2028,2123,2157`; `_emitSafely` (`:545-556`) no-ops without listeners. `grep -rn "appRegistry\.on("` → zero. Siblings *are* wired: `index.js:2449` `storageAccounting.on('error')`, `:3356` `eviction.on('error')`. Narrower than it looks — most failures route through `_failRegistryJournal` → `failClosed` (`:1701-1702`) — but the diagnosis is discarded, so an operator sees writes stop with no attribution. Silent classes remain: `APP_REGISTRY_METADATA_BUDGET_EXCEEDED` (`:1871-1877`) |
| N-7 | Dashboard WS has no `bufferedAmount` ceiling or ping | 6 | `ws-feed.js:176-184` `try { ws.send(msg) } catch {}`; `grep -nE "ping\|pong\|bufferedAmount\|isAlive" ws-feed.js` → one hit, `terminate()` inside `stop()`. `api.js:443,567` `createServer()` with no options → no TCP keepalive, no `setTimeout`. Payload measured: 835 B empty, **10.5 KB at today's 13-relay fleet**, 732 KB at `MAX_NETWORK_RELAYS = 1000` (`api-network-state.js:1`). At today's size ~4.7 MB over a ~15 min RTO window; at the cap, ~330 MB. `dht-relay-ws/index.js:500` implements the ceiling and `docs/DEVELOPER.md:1573-1577` sells it as a virtue. (Note `poker/ws-adapter.js:285` also has it, but that class is imported only by tests — the shipping poker feed `ws-feed-poker.js:58` has none) |

---

## 7. Claims to correct

| # | Location | Current text | Replacement |
|---|---|---|---|
| **C-1** | `packages/core/config/default.js:205` — **code, not docs** | `serviceDefaultPeerRole: 'authenticated-user'` | `serviceDefaultPeerRole: 'anonymous'`. **This is a security regression, not a doc error.** Commit `9125f3c` (*"security+docs: default services to anonymous role"*) fixed `relay-node/index.js:180`, `bare-relay.js` and `docs/SERVICES.md:458` — and did **not** touch `config/default.js`, the only one the CLI reads (`cli/index.js:507` → `:526`; merge at `relay-node/index.js:434` puts opts last). Verified: `HOME=$(mktemp -d) node -e "loadConfig({})"` → `"authenticated-user"`. Effect: `protocol.js:525` grants any anonymous swarm peer the `authenticated-user` role; `router/index.js:246` then opens `arbitration.submit` (uncapped Map, `arbitration-service.js:111`) on 10 boxes. No test asserts the value in either file |
| **C-2** | `docs/HIVERELAY-0.25-LAUNCH.html:278` | "Docker Compose, the systemd unit, and the Umbrel appliance now ship with `HIVERELAY_TOR=1` … The path to onion-hidden relays is **on by default**" | "Docker Compose, the systemd unit and the Umbrel appliance **express** a Tor default as `HIVERELAY_TOR=1`. The Node runtime those packagings launch does not read it; Tor is enabled by `config.transports.tor` or `--tor`." |
| **C-3** | `docs/HIVERELAY-0.25-LAUNCH.html:288`; same claim at `docs/COMMUNITY-UPDATE-0.25.0-rc.1.md:27,62-63` and `CHANGELOG.md:131-133` | "A fresh appliance is no longer an empty seeder. Outboxlog, notify, storage-proof, VRF, witnesslog, and repairticket are enabled in the unit / compose path" | "These services are enabled by env var **under the Bare/Pear runtime only**. The unit / compose / Umbrel paths launch the Node CLI, which enables services from `<storage>/services.json` or `config.plugins`." Verified: `HOME=$(mktemp -d)` + all eight vars exported → `loadConfig()` returns `enableServices: false, plugins: []` |
| **C-4** | `docs/LADDER-SHIP-MAP.md:21`, `:59`, `:110` | "Packaging: Tor + utility **defaults** in Docker/systemd/Umbrel" | "Tor + utility defaults are *expressed* in packaging as `HIVERELAY_*` env vars; the Node runtime reads none of them. Runtime enablement is `config.transports.tor` (or `--tor`) and `<storage>/services.json`." Note the existing hedges at `:64`/`:67` misattribute the cause to uneven host Tor — falsified for Docker, which ships its own healthy tor sidecar (`docker-compose.yml:88-105`, `depends_on: service_healthy`) and still never enables it |
| **C-5** | `docs/TOR-ONION-TRANSPORT.md:102` | "an all-invalid roster runs **fail-open** — hence the negative probe in the health gate" | Delete the trailing clause. No negative probe exists. Align with `GIGA-RELEASE-ARCHITECTURE.md:171` ("NOT implemented … Required before RC") and `LADDER-SHIP-MAP.md:230,272,403` (Ship 8). Also: the `authorized_clients/*.auth` fail-open scenario is **not reachable** in this runtime — the transport uses control-port `ADD_ONION` with ClientAuthV3, invalid entries throw (`auth-keys.js:245-246,259`), and an empty roster installs an unreachable guard credential (`tor/index.js:709-717`) |
| **C-6** | `docs/TOR-ONION-TRANSPORT.md:14,118` and `capability-doc.js:39-41` | "only while **verified reachable**" / "reports **verified-ready** health" | "while descriptor-uploaded." `config/default.js:325` `probeVport: null` (and `tor/index.js:190` defaults it null too); `tor/index.js:617-623` promotes `DESCRIPTOR_UPLOADED → READY` when no probe vport is set. No shipped config overrides it — so **no relay ever runs the self-probe**, and there is no network-derived DEGRADED transition (the four other `_setHealth(DEGRADED)` sites, `:378,482,529,572`, are all local control-port failures) |
| **C-7** | `docs/HIVERELAY-0.25-LAUNCH.html:393` | "Split transport (OHTTP + Protomux). **Spec exists; code does not.** Lands after 0.26." | "Wire layer built in the vnext `blind-protocol` package; runtime, `BlindTransportDescriptorV1` and main-tree merge missing." `LADDER-SHIP-MAP.md:285` explicitly flags the current sentence as *"wrong"*; commit `aae40ff` corrected three docs and skipped this one, so the known-wrong sentence shipped inside the signed tag |
| **C-8** | `docs/HTTPS-GATEWAY.md:3,17,148`; `GIGA-RELEASE-ARCHITECTURE.md:179` | "app-origin gateway … lives in the `hr-https-gateway` worktree and is **not merged**" | "The relay-side runtime **is merged** and is in `v0.25.0-rc.5`+ (`git ls-tree v0.25.0-rc.5 packages/core/gateway/` lists all three modules; 34/34 unit tests pass). The **edge and ops** half remains on branch `feat/public-https-hive-gateway`: `deploy/public-hive-gateway/nginx.conf.template`, `fleet/quarantine-public-gateway.sh`, `scripts/lib/public-hive-gateway-*.mjs`, `docs/PUBLIC-HTTPS-HIVE-GATEWAY-SPEC.md`, and the integration tests." The named worktree does not exist on this machine (maxdepth-5 search → nothing) |
| **C-9** | `docs/SERVICES.md:447` | "Services are enabled **automatically** when the relay node starts" | "Services are opt-in: set `enableServices` and select `plugins`, or write `<storage>/services.json`." Contradicted by `config/default.js:207` and `relay-node/index.js:1792`; contradicted by the same document at `:2` and `:501`. `git log -L447` shows the sentence last changed 2026-04-12 (`ae94575`) while `enableServices: false` landed 2026-05-04 (`c2cfa88`) |
| **C-10** | `docs/PROTOCOL-SPEC.md:820,865,869` (§9) | "built on **Autobase** … the Autobase's discovery key is used as the swarm topic … `apply` linearizes the causal DAG" | "Per-relay append-only Hypercore logs; peers exchange log keys over the `hiverelay-registry-meta` protomux channel; a Hyperbee caches derived state." No Autobase dependency exists (`grep -rn '"autobase"' package.json packages/*/package.json` → nothing; `ls node_modules/autobase` → absent). §9.2 is the worse error: the topic is fixed (`registry/index.js:37-38`, hash of `'hiverelay-seeding-registry-v1'`), so an implementer following the spec joins the wrong topic. Conflict resolution is last-write-wins on wall-clock `entry.timestamp` (`:515-577`), weaker than the DAG linearization promised. Same claim repeated at `docs/DEVELOPER.md:108,192,293` (the last lists `autobase` in a dependency table). `config/default.js:179` `registryKey: null, // null = create new autobase` is a **dead knob** — `grep -n registryKey packages/core/core/registry/index.js` → no matches |
| **C-11** | `docs/PROTOCOL-SPEC.md:45` (§1.1) | "**All** HiveRelay protomux channels are registered under one of three protocol names" | "…under one of twelve; see the channel matrix." The relay registers 12 (`grep -rn -B3 -A3 createChannel packages/`). Severity is doc-consistency only — the enumeration already exists at `README.md:357-373` (11) and `docs/HIVERELAY-DETAILED-ARCHITECTURE-DIAGRAM.md:349-361` (9, with direction + file + persistence path); `hiverelay-pair` is covered at `docs/DEVELOPER.md:785`. Point §1.1 at one of those |
| **C-12** | `docs/PROTOCOL-SPEC.md:373` (§5.3) | `SEED_HEARTBEAT` drawn into the lifecycle as "(periodic, confirms active seeding)" | Remove. Never sent. The sharper interop hazard the spec should state instead: wire indices are **positional**, and actual registration order is `seedRequest, seedAccept, unseedRequest, seedDeny` (`seed-request.js:155-174`) — not the table's `REQUEST, ACCEPT, REJECT, CANCEL`. An implementer inferring indices from §4 sends **UNSEED where the spec implies REJECT** |
| **C-13** | `docs/SERVICES.md` §Built-in Services (`:96-407`) | 12 of 15 builtins documented | Add `witnesslog`, `repairticket`, `shard-store` (`grep -ci` → 0 for each). `shard-store` is the G3 custody surface — `LADDER-SHIP-MAP.md:137` makes its enablement the difference between "fleet utility floor" and "partial G3". Also: `SERVICES.md:512` claims to name "newer optional providers" while omitting three of them; `dashboard/blindspark.html:1009-1027` `SERVICE_META` covers only 9, so those three render as *"Optional service plugin exposed by this relay."* |
| **C-14** | `docs/SERVICE-CONTRACT.md:34-38` | enumerated "stable, additive" outboxlog surface | Add the 8 served-but-unlisted routes (`http-adapter.js`: `/api/bridge/status:190`, `/api/identity*:206`, `/api/sync/capabilities:212`, `/api/sync/commit:235`, `/api/sync/events:256`, `/api/sync/list:268`, `/api/sync/status:282`, `/api/swarm/leave:309`). Three — `sync/commit`, `sync/capabilities`, `swarm/leave` — are documented **nowhere** in the repo. Worse, the *enumerated* writes `create`/`append` are 403-rejected under `legacyWrites:false` (`outbox-log.js:188,213`), the production config published at `SERVICES.md:337` — so on a production relay the contract's write surface is dead and the sole working write path is un-enumerated |
| **C-15** | `README.md:37,39` | "Monorepo and package manifests are aligned at `v0.20.2`" | "Monorepo and package manifests are at `v0.25.0-rc.6`; the last release with a captured multi-arch GHCR digest is `v0.20.2`." Drift since `4441a5b` (2026-06-24, when the badge read v0.20.1). `scripts/prepare-release.mjs:226-231` rewrites only the badge; `scripts/audit-workspace-alignment.mjs:6758-6762` only checks the badge. Also stale on `main` (badge v0.24.3, table v0.20.2) |
| **C-16** | `umbrel-app/docker-compose.yml:38` | `ghcr.io/bigdestiny2/p2p-hiverelay:0.25.0-rc.4` | Pin by digest. Lines `:30-38` insist on `name:tag@sha256:` and warn a bare tag *"reintroduces the audited supply-chain gap (HR-DIS-002) and CI will reject it"* — while line 38 is a bare tag, two RCs behind |
| **C-17** | `docs/FLEET-STABILITY-2026-07-27.md:31-33` | "Plugin set trimmed to `outboxlog`, `notify`, `vrf`" (past tense) | "Trim **planned** for ≤1 GB boxes; applied state unverified." No artifact corroborates it (§5.3 wave 5). `docs/RELEASE-RUNBOOK-0.25.0-rc.5.md:206-208` propagates it into release-ops guidance for utah-0.5gb — the one canary box with a live timer — where the single live reading is `["outboxlog"]`, not the documented three |
| **C-18** | `docs/HIVERELAY-DETAILED-ARCHITECTURE-DIAGRAM.md:372-373` | "Operator or API client → `/api/manage/services/config` → `storage/services.json` atomic write" | The endpoint writes `~/.hiverelay/config.json` (`api.js:2192-2196`). The only writer of `services.json` is `setServicesConfig` (`relay-node/index.js:1017`), which has no production caller |
| **C-19** | `docs/HIVERELAY-OPERATOR-DASHBOARD-DESIGN-2026-07-19.html:564` | negative-probe bit *"(shipped)"* | Drop "(shipped)". Contradicted by `:433` of the same file and by C-5 |

---

## 8. Open questions

| # | Question | Why unresolved | Evidence that would settle it |
|---|---|---|---|
| **Q-1** | What is each box's **actual** runtime service set? | 10 of 12 rows are `services_source: "config"`; `services.json` is the runtime authority (`LADDER-SHIP-MAP.md:422`). Read-only audit, no SSH | `GET /api/v1/services` per box — public and unauthenticated (`api-service-read.js:8`, dispatched `api.js:1443` with no `_requireAuth`), and present identically at `v0.24.3`. Commit a prober that sets `services_source: "live"` for all 13 |
| **Q-2** | Was the ≤1 GB trim applied to miami / sing-1 / sing-2? | Absence of evidence, not evidence of absence — a trim via `services.json` leaves `config.plugins` unchanged, so a `config`-sourced probe cannot see it | `cat /var/lib/hiverelay/services.json` or Q-1's probe on those three |
| **Q-3** | Does `outboxlog.journal = "hypercore"` actually work on a real box tree? | The prescribed B-1 fix still failed with `STORAGE_EMPTY` on a fresh store, and `test/unit/storage-startup-rollback.test.js:218` (same config) is a known failure | Read utah / utah-8gb's live `config.json` — they survived the gate on rc.4, so a working configuration exists |
| **Q-4** | How many shard bytes are currently stranded? | Mechanism is certain (§3), volume is not. `putAuth` defaults to `['custody']` (`relay-node/index.js:4415-4417`), requiring a signed custody assignment, so current stored volume is unknown | `du` of the shard hypercore vs `liveHashes()` on the 4 shard-store boxes |
| **Q-5** | What generated `fleet-live.json` / `FLEET-OPS-LIVE.html`? | `git grep -l services_source` over all refs matches only the JSON. Raw values like `"tor_host": "inactive\ninactive"` are the fingerprint of an ad-hoc ssh one-liner. The two files do not even reference each other (`grep -rl "fleet-live" .` → nothing) | Commit the generator |
| **Q-6** | Is `dallas` running services at all? | In no committed machine-readable inventory. `docs/PEERIT-BLIND-CELLS-HANDOVER-2026-07-27.md:62-67` gives version/disk/health but no plugin set | Q-1's probe, after adding a `channel: "hold"` entry to `fleet/relays.json` |
| **Q-7** | Which boxes have live updater timers *right now*? | `docs/RELEASE-RUNBOOK-0.25.0-rc.5.md:110` is a point-in-time record from before the rc.5 canary promotion landed | `systemctl is-active hiverelay-updater.timer` on all 13 — **do this before B-0**, since it determines rc.5's real blast radius |
| **Q-8** | Does `/api/v1/services` reflect `services.json` faithfully? | `docs/CORESTORE7-MIGRATE-RUNBOOK.md:98` records outboxlog missing from that endpoint on utah/utah-8gb while listed in `services.json` — consistent with the B-1 gate firing, but not proven | Correlate the endpoint against `services.json` + journal for `SERVICE_START_FAILED` |
| **Q-9** | Is any client actually reading `region`/`operator` today? | `capability-doc.js` emits `region` (always null) and no `operator` at all. Whether external SDK consumers branch on them is out of tree | Grep the peerit / client consumers in `02-apps/` |

### Dimensions that produced nothing worth reporting

None. All six dimensions produced findings that survived refutation; two (`spec-not-wired`,
`ladder-honesty`) produced findings whose *impact* claims were materially overstated and have been
corrected in place above rather than dropped.

---

## Appendix: contradictions between dimension audits, resolved

| Contradiction | Resolution |
|---|---|
| `origin/main` canary = `v0.24.3` (built-not-deployed) vs. observed `v0.25.0-rc.5` | **Both were true at different times.** Commit `6248942` (PR #204) landed after that audit. The finding's *conclusion* (rc.5 cannot reach a box) survives for a different and worse reason: it is now the declared canary and cannot install. §4.1 |
| "rc.5 fails relay startup on 10 boxes" (service-diversity) vs. "rc.5 never restarts the relay" (built-not-deployed) | The install fails at `updater.sh:280` *before* `systemctl restart` (`:281`), so rc.5 cannot reach the outboxlog gate. **rc.6 is the first build that can.** B-1 is therefore a blocker for the *next* promotion, not a past event |
| shard-store STO-005 "re-opens the disk-full failure" vs. "accounting is honest" | Runtime-verified: the admission guard uses `measureProvenStorageTreeBytes` (a real tree walk) and eviction uses `max(diskBytes, …)`, both of which already count shard cores. **Downgraded to a telemetry gap.** The *pin persistence* defect is the real shard-store blocker |
| "`identity` is a free win" vs. `SERVICE-CONTRACT.md:27` assigning identity to the app side | Both hold. The cost claim is exact (zero state/timers/disk); the *posture* question is real, and `identity.peers` leaks peer pubkeys under the C-1 role regression. Sequenced after C-1 in §5.3 |
| "shard-store missing from sydney/utah-us despite headroom" vs. `LADDER-SHIP-MAP.md:138` forbidding it on 0.5–2 GB | The ship map wins. The correct finding is the inverse: **amsterdam (2 GB) runs it in violation**, and sing-2 (1 GB, 59 GB free) is not a candidate either. The genuine gap is bern (4 GB, 500 GB), a documented candidate that is down |
| "no relay-tree document defines G2-W" vs. `LADDER-SHIP-MAP.md:45,281,286-301` | Refuted as stated. The ladder gate exists and is detailed. What is external and stale is the **normative wire-format text** |
| "no committed inventory mentions dallas" vs. eight tracked docs naming it | Narrowed to: absent from every **machine-readable** inventory (`fleet/relays.json`, `fleet-live.json`, `FLEET-OPS-LIVE.html`); its *service state* is recorded nowhere |
| "the negative-probe fail-open is exploitable" vs. the ClientAuthV3 guard credential | The doc sentence is false (no probe exists), but the exploit is unreachable — invalid rosters throw, empty rosters get a guard credential. **Doc-correction only** (C-5) |
