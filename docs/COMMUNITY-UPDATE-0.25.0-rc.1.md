# Community update pack — HiveRelay **v0.25.0-rc.1** (canary)

**Date:** 2026-07-26  
**Tag:** [`v0.25.0-rc.1`](https://github.com/bigdestiny2/P2P-Hiverelay/releases/tag/v0.25.0-rc.1) (prerelease)  
**Fleet:** canary → `v0.25.0-rc.1` · stable remains `v0.24.3`  
**Not this release:** blind public-test GA, stable fleet-wide Tor onions, npm stable promote

Copy/paste blocks below. Prefer the short form for chat/social; long form for GitHub, blog, Discord announce channel, newsletter.

---

## One-liner

**HiveRelay v0.25.0-rc.1 is on the canary channel:** Tor + utility services default-on in packaging, app-reachable service HTTP (VRF / notify / client helpers), and a clear ladder for what’s next — without claiming fleet-wide blind or live onions yet.

---

## Short form (~150–220 words)

### HiveRelay v0.25.0-rc.1 — canary is open

We’ve cut **HiveRelay v0.25.0-rc.1** and pointed the **canary** fleet channel at it. **Stable stays on v0.24.3** until the RC has been through health-gated soak.

**What’s in this RC**

- **Tor packaging defaults** — Docker, systemd, and Umbrel compose ship with Tor enabled by default (host still needs a real Tor control/SOCKS setup for live onions).
- **Utility services on by default** in packaging — outboxlog, notify, storage-proof, VRF, witnesslog, repairticket (shard-store still opt-in for larger disks).
- **Service HTTP wiring apps can actually call** — VRF under `/api/v1/vrf/*`, notify push provider resolution, client helpers, dashboard notify/VRF panels.
- **Outboxlog durability fixes** and operator-facing honesty gates on notify capabilities.
- **Ship map** — `docs/LADDER-SHIP-MAP.md` documents fleet vs blind public-test vs later merge tracks so claims stay bounded.

**What this is not**

- Not a stable-channel promote.
- Not “every relay has a live onion” — packaging path first; host Tor + evidence still required.
- Not the blind-cell public-test product tag (that’s a **parallel** `1.0.0-rc.1.public-test.1` track on pilot hosts).

**Links**  
Release: https://github.com/bigdestiny2/P2P-Hiverelay/releases/tag/v0.25.0-rc.1  
Repo: https://github.com/bigdestiny2/P2P-Hiverelay  
Ladder map: `docs/LADDER-SHIP-MAP.md` in the tag tree

Operators on canary: expect the updater to pull on the next tick (health-gated, auto-rollback). Feedback welcome.

---

## Long form (~450–650 words)

### HiveRelay v0.25.0-rc.1 — making the utility relay useful (and honest)

Today we published **HiveRelay v0.25.0-rc.1** as a **prerelease** and promoted the fleet **canary** channel to that tag. This is Track A of our ladder: the **fleet utility substrate** — not the full blind-cell product cut, and not a silent flip of every production box.

#### Why an RC, not “stable is 0.25”

Stable remains **v0.24.3**. Canary boxes (health-gated, auto-rollback) take the risk first. That matches how the fleet updater works: channel control in `fleet/channels.json` on `main`, code checkout from a **signed** release tag.

#### What’s new in the RC

**1. Tor as a packaging default (path to G4-T, not a blanket fleet claim)**  
Docker Compose, the systemd unit, and Umbrel packaging now default **Tor on** (`HIVERELAY_TOR=1` / sidecar companion where compose applies), with key-file and control/SOCKS wiring documented. Operators can still set `HIVERELAY_TOR=0`. Live onion endpoints still need Tor ≥ 0.4.9 on the host, cookie control, and operational evidence — packaging alone does not equal “all fleet IPs are hidden.”

**2. Utility services default-on in packaging**  
Outboxlog, notify, storage-proof, VRF, witnesslog, and repairticket are enabled by default in the unit/compose path so a fresh appliance isn’t an empty DHT seeder. **Shard-store** stays opt-in for capacity reasons on small VPS disks.

**3. Service HTTP wiring apps and the dashboard can use**  
- VRF HTTP: beacon info/latest, select, status, info under `/api/v1/vrf/*`  
- Notify: push provider resolution (e.g. webpush descriptor → live provider) with fail-closed bad config  
- Client helpers on `HiveRelayClient` for notify, shard, witness, VRF  
- Dashboard panels for notify (manage status path) and VRF  

**4. Outboxlog durability / operator reliability**  
Journal and app-lifecycle fixes (including registry load vs reseed split) that keep messaging and recovery paths honest under load and restart.

**5. Documentation for dual-track shipping**  
`docs/LADDER-SHIP-MAP.md` is the chronological map:

- **Track A** — fleet channel (`v0.25.x`)  
- **Track B** — blind public-test images (`1.0.0-rc.1.public-test.1`) on pilot FDs (syd / dal)  
- **Track C** — later monorepo merge / opt-in blind profile (`v0.26.x` story)

Marketing line when both are live: **“Fleet v0.25 + Blind public-test on syd1 (+ dal)”** — two components, not one tag.

#### Explicit non-claims (please don’t oversell)

| Don’t say | Why |
|-----------|-----|
| “Stable fleet is 0.25” | Stable is still **0.24.3** |
| “Tor is live on every relay” | Status still shows no onion until host Tor + upgrade evidence |
| “Blind substrate is GA / in 0.25” | Blind public-test is a **parallel** version line and lease |
| “Browser is a full DHT peer” | Still false; use honest stack language |

#### What operators should do

- **Canary operators:** watch the next updater tick; confirm `/health` version `0.25.0-rc.1` and service counts. Keep shard-store off on tiny boxes.  
- **Stable operators:** no action until we promote stable after soak.  
- **Home/Umbrel/StartOS:** image pin for this RC is prerelease-oriented; community store lags stable by design.  
- **App developers:** prefer the new client helpers and VRF/notify HTTP surfaces; treat capability docs as authoritative for what a given relay actually offers.

#### What’s next

1. Canary soak → possible **v0.25.0** stable if health stays green.  
2. Track B Peerit bind against frozen public-test digests (separate from this fleet tag).  
3. Boot-restore / blind packages merge as a later product cut — not redefined into 0.25.

Thanks for running relays, filing rough edges, and holding us to honest badges.

— HiveRelay / Blindspark

**Links**  
- Release: https://github.com/bigdestiny2/P2P-Hiverelay/releases/tag/v0.25.0-rc.1  
- Changelog: https://github.com/bigdestiny2/P2P-Hiverelay/blob/v0.25.0-rc.1/CHANGELOG.md (see monorepo after this update lands)  
- Ladder map: https://github.com/bigdestiny2/P2P-Hiverelay/blob/v0.25.0-rc.1/docs/LADDER-SHIP-MAP.md  
- Tor transport: `docs/TOR-ONION-TRANSPORT.md`

---

## Social / X (short)

**Option A (technical)**  
HiveRelay **v0.25.0-rc.1** is on **canary**: Tor + utility services default-on in packaging, VRF/notify HTTP apps can call, dashboard panels, ship ladder docs. Stable stays **0.24.3**. Not blind GA; not “onions everywhere” yet.  
https://github.com/bigdestiny2/P2P-Hiverelay/releases/tag/v0.25.0-rc.1

**Option B (plain language)**  
New HiveRelay canary release: home/VPS packaging turns on useful services by default and lays the Tor path. We’re rolling canary first so stable doesn’t break. Details + honesty notes in the release.

---

## Discord / community chat (medium)

**HiveRelay v0.25.0-rc.1 (canary)**

Cut + canary channel live. Highlights:

1. Tor **default in packaging** (Docker / systemd / Umbrel)  
2. Utility services **on by default** (outbox, notify, VRF, …; shard-store opt-in)  
3. **HTTP wiring** for VRF + notify + client helpers + dashboard  
4. Ladder doc so fleet vs blind public-test don’t get mashed into one claim  

**Stable = still 0.24.3.** Canary soaks first.  
Release: https://github.com/bigdestiny2/P2P-Hiverelay/releases/tag/v0.25.0-rc.1

If you run a canary box, post `/health` version + any Tor host prep gaps here.

---

## GitHub release body (canonical)

Use the block in § “GitHub release notes source” below when editing the prerelease.

---

## Website / homepage blurb (status strip)

**Status:** Canary **v0.25.0-rc.1** · Stable **v0.24.3** · Prerelease: Tor + utilities packaging defaults, service HTTP wiring · [Release notes](https://github.com/bigdestiny2/P2P-Hiverelay/releases/tag/v0.25.0-rc.1)

---

## Operator email / newsletter subject lines

- `HiveRelay v0.25.0-rc.1 on canary — Tor packaging + service HTTP`  
- `[Canary] HiveRelay 0.25.0-rc.1: utility services default-on (stable unchanged)`

---

## GitHub release notes source

```markdown
## HiveRelay v0.25.0-rc.1 (canary prerelease)

**Channel:** fleet **canary** → this tag · **stable** remains `v0.24.3`  
**Signed tag** · health-gated updater · auto-rollback on mismatch

### Highlights
- **Tor packaging defaults** — Docker Compose, systemd unit, and Umbrel enable Tor by default (`HIVERELAY_TOR=1` / sidecar). Host Tor control/SOCKS still required for live onions.
- **Utility services default-on** in packaging — outboxlog, notify, storage-proof, VRF, witnesslog, repairticket. **Shard-store** remains opt-in (disk).
- **Service HTTP wiring** — VRF `/api/v1/vrf/*`, notify push provider resolution, `HiveRelayClient` helpers, dashboard notify + VRF panels.
- **Outboxlog / lifecycle durability** fixes for journal recovery and registry load vs reseed.
- **Docs:** `docs/LADDER-SHIP-MAP.md` — Track A fleet vs Track B blind public-test vs later merge (claim boundaries).

### Not in this release
- Stable-channel promote
- Fleet-wide live onion evidence
- Blind public-test GA / monorepo blind-daemon product cut (`1.0.0-rc.1.public-test.1` is a parallel pilot track)

### Upgrade notes
- Canary boxes pull on the next `hiverelay-updater` tick.
- Small VPS: leave `HIVERELAY_SHARD_STORE` off; raise heap only when services demand it.
- Tor: install Tor ≥ 0.4.9, cookie control on 9051, see `deploy/tor/torrc` and `docs/TOR-ONION-TRANSPORT.md`.

### Packages (lockstep)
`p2p-hiverelay` · `p2p-hiveservices` · `p2p-hiverelay-client` · `p2p-hiverelay-verifier` → **0.25.0-rc.1**

### Links
- Ladder map: [`docs/LADDER-SHIP-MAP.md`](./docs/LADDER-SHIP-MAP.md)
- Community pack: [`docs/COMMUNITY-UPDATE-0.25.0-rc.1.md`](./docs/COMMUNITY-UPDATE-0.25.0-rc.1.md)
- Changelog: [`CHANGELOG.md`](./CHANGELOG.md)
```
