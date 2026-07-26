# Ladder ship map (chronological)

**Date:** 2026-07-26 · **Status:** living operator/product plan · **Baseline:** monorepo `v0.24.3` (`fleet/channels.json` stable = canary)

> Two parallel tracks, one honesty ladder. **Version tags and claim badges stay separate until a deliberate merge.** Do not call the blind public-test pilot “fleet v0.25.0,” and do not claim rungs the current ship has not evidenced.

**Related:** [GIGA-RELEASE-ARCHITECTURE](./GIGA-RELEASE-ARCHITECTURE.md) · [BLIND-CELLS](./BLIND-CELLS.md) · [TOR-ONION-TRANSPORT](./TOR-ONION-TRANSPORT.md) · [RELEASE](./RELEASE.md) · [fleet/README](../fleet/README.md) · Peerit status HTML (`02-apps/peerit/docs/HIVERELAY-STATUS-JULY19-VS-JULY26.html`) · Split-transport spec (`02-apps/peerit/docs/SPLIT-TRANSPORT-SPEC-V1-2026-07-26.md`)

---

## 1. Tracks

```text
Track A — Fleet channel (systemd/Docker/Umbrel, channels.json)
Track B — Blind public-test (syd-1 → Dallas/Bern, OCI edge+daemon)
Track C — Merge + promote (when B is accepted + boot-restore lands on main)
```

| Track | Version line | Scope | What it ships | Claim boundary |
|-------|--------------|-------|---------------|----------------|
| **A** | `v0.25.x` (from today’s `v0.24.3`) | All raw fleet relays | Tor defaults + utility services + service HTTP wiring | G0+G1 (+ Tor path); partial G3 only if shard-store opt-in |
| **B** | `1.0.0-rc.1.public-test.1` | **syd-1 first**, then at most one 2nd owner-operated failure domain | blind-edge (:443) + blind-daemon (Unix sock) | `LIVE_PUBLIC_TEST_ONLY` — no GA, no stable channel, no wide fleet |
| **C** | `v0.26.x` (or first monorepo tag that **contains** blind packages) | Main + optional fleet profile | boot-restore, blind packages in tree, opt-in blind-cell profile | Productizable G2-S/G3 — still not “every box is blind” |

Honest versioning:

```text
v0.25.0                    = fleet substrate (Tor + utilities + service HTTP)     ← Track A
1.0.0-rc.1.public-test.1   = blind edge/daemon public-test images                 ← Track B (syd → dal)
v0.26.x / later            = first tag where blind-daemon is IN the monorepo
                             + optional fleet enable                               ← Track C
```

Marketing one-liner when both are live: **“Fleet v0.25.0 + Blind public-test on syd1 (+ dal)”** — two components, one sentence, **not one tag**.

---

## 2. Honesty ladder (product)

| Rung | Meaning | How we ship it |
|------|---------|----------------|
| **G0** | Integrity (can't forge bytes/sigs) | Core already |
| **G1** | Payload opacity | Encrypted/outbox/signed envelopes; utility services HTTP |
| **G2-S** | Storage-schema opacity | Blind cells / no app semantics at rest |
| **G2-W** | Wire opacity | Split transport (OHTTP + Protomux) — **spec’d, not built** |
| **G3** | At-rest unlinkability | BlindShard/cells + multi-relay cohort |
| **G4-T** | Route separation | Tor onion path (+ later split-web) |
| **G4-I** | Read-interest privacy | Bucket/PIR later — **not in near map** |
| **G5** | Active-reader resistance | **Impossible for public data** — never claim |

---

## 3. Where we are now

| Item | State |
|------|--------|
| Fleet channel | **v0.24.3** stable = canary |
| Main tip (packaging) | Tor + utility **defaults** in Docker/systemd/Umbrel (`dad9f44` lineage) |
| Service wiring (Track A content) | VRF/notify HTTP, client helpers, dashboard panels, outboxlog durability fixes — land via `feat/service-http-wiring` then tag |
| Dubai pattern | Utility services live via **`services.json`** (runtime authority for plugins), not config alone |
| Track B | Signed public-test manifest; **deploy parked** on DNS / live syd-1 qualify |
| Boot-restore | Worktree only — **not on main** until Track C |
| Blind packages on main | **Absent** (`blind-daemon` / edge only in vNext worktrees) |

**Badge today (honest):** G0 + G1 + **partial G2-S/G3** (shard-store code exists; not fleet-wide) + **partial G4-T** (Tor code + packaging default; host deploy uneven).

### Physical co-location (Sydney pattern; same on Dallas)

```text
sydney host (fleet name; public-test host syd-1)
├── HiveRelay node (fleet channel)     :9100   ← Track A → v0.25.0
│     outboxlog / notify / … / optional shard-store
└── Blind public-test stack (sidecars) :443    ← Track B · 1.0.0-rc.1.public-test.1
      blind-edge (public-CA TLS)
      blind-daemon (private socket, WAL / cells / DESCRIBE|CELL|INBOX|CORE|FORWARD)
```

Qualification order for Track B: **syd-1 full accept → then Dallas (or Bern) only → then Peerit binds as client**. Never “flip stable to blind on all relays” from the public-test lease.

---

## 4. Chronological ship sequence

### Phase 0 — Freeze hygiene (before any tag)

**When:** now  
**Owners:** main (service wiring), boot-restore agent (their worktree)

| Step | Action | Why |
|------|--------|-----|
| 0.1 | Branch dirty main → `feat/service-http-wiring` (leave main clean for their merge) | Avoid clobbering boot-restore |
| 0.2 | Do **not** touch syd-1 Blind compose / roots / :443 | Public-test lease |
| 0.3 | Keep `channels.json` on **v0.24.3** until a health-gated canary | No silent fleet flip |

**Ladder impact:** none (process only).

---

### Ship 1 — `v0.25.0-rc.1` · Fleet canary (Track A only)

**When:** after 0.1 committed + green tests  
**Channel:** `canary` only (utah, utah-0.5gb)  
**Not:** syd Blind stack, not stable, not Dallas Blind

| Contents | Ladder |
|----------|--------|
| Service HTTP: VRF `/api/v1/vrf/*`, notify push resolution, client helpers | Apps can use G1 surfaces |
| Dashboard notify + VRF panels | Operator visibility |
| Packaging: Tor + utilities default-on (Docker/systemd/Umbrel) | Ops path to G4-T + G1 services |
| Outboxlog durability fixes when included in the tag | G1 messaging reliability |
| **No** blind-daemon, **no** stable-wide shard-store | Honesty |

**Host work with canary:**

- Ensure `services.json` / heap sane (dubai pattern)
- Tor host prep where claimed (cookie control, key file)
- Shard-store **off** on tiny boxes

**Gate to promote:** canary green 24–48h, `/health` + `/api/v1/services` expected counts, no OOM thrash.

**Claim after Ship 1:** *“Canary runs Tor-default utility relay with app-reachable service HTTP.”*  
**Not:** blind substrate fleet-wide.

---

### Ship 2 — `v0.25.0` · Fleet stable (Track A)

**When:** Ship 1 green  
**Channel:** bump `stable` (+ keep canary on same or next RC)

| Contents | Ladder |
|----------|--------|
| Same as 0.25.0-rc.1 | G0+G1+partial G2-S tooling + partial G4-T path |
| Roll all raw relays: utah*, dubai, miami, sing-*, sydney **main process :9100**, bern, … | Fleet utility floor |
| Large disks (utah-8gb, bern, dubai if capacity): optional `shard-store` in `services.json` | **Partial G3** (cells via shard HTTP, not full daemon) |
| Small boxes (0.5–2 GB): utilities only, no shard-store | Avoid OOM |

**Sydney/Dallas note:**

- **:9100 HiveRelay** may upgrade to v0.25.0 like everyone else.
- **Blind edge/daemon on :443** stay on **public-test OCI**, not this tag.

**Claim:** *“Fleet is a Tor-capable utility substrate with optional cell custody service.”*  
Still **not** “blind public-test complete” or “WAL boot-restore GA.”

---

### Ship 3 — Blind public-test **live** · `1.0.0-rc.1.public-test.1` (Track B)

**When:** can run **in parallel** with Ship 1–2 (preferred: after DNS)  
**Version line:** **not** `v0.25.x` — images `1.0.0-rc.1.public-test.1`  
**Lease:** LIVE_PUBLIC_TEST_ONLY · two owner-operated failure domains max

#### 3a — User / DNS

| Step | Action |
|------|--------|
| 3a.1 | A record `syd1.p2phiverelay.xyz` → syd-1 public IP (fleet **sydney**) |
| 3a.2 | (Later) Dallas (or Bern) name, e.g. `dal1.p2phiverelay.xyz` |

#### 3b — **syd-1** deploy + qualify

| Step | Action | Ladder / product |
|------|--------|------------------|
| 3b.1 | ACME cert for syd1; open 443; **leave 9100 alone** | Edge TLS |
| 3b.2 | Load digest-pinned edge+daemon OCI; compose `docker-compose.blind-public-test.yml` | Blind runtime |
| 3b.3 | Node ceremony: new Blind root; preserve `/opt/hiverelay` + `~/.hiverelay` | Store genesis |
| 3b.4 | Qualify: DESCRIBE / CELL / INBOX / CORE / FORWARD-one-hop + negatives | G2-S + **G3 path** + partial G4-T if Tor in pilot |
| 3b.5 | Restart / WAL recovery / rollback-sidecar evidence | Durability pilot |
| 3b.6 | **Independent syd-1 acceptance** before any second site | Gate |

#### 3c — **Dallas** (2nd FD; handover said Bern — same slot)

| Step | Action |
|------|--------|
| 3c.1 | Continuity-linked phase-2 manifest (new pin-history entry, same digests) |
| 3c.2 | Baseline capture **before** mutate; full qualify |
| 3c.3 | Two-relay cell write/readback; one-relay-down behavior |
| 3c.4 | Claim: **two owner-operated FDs**, not independent operators |

#### 3d — Peerit public-test bind

| Step | Action |
|------|--------|
| 3d.1 | Clean Peerit commit binds to exact protocol/store/OCI/descriptor hashes |
| 3d.2 | Two-relay catalogue; cell e2e through Peerit only |
| 3d.3 | No seed publish until seed-spec review |

**Ladder after Ship 3 (pilot only):** G0+G1+G2-S+**partial G3** with real multi-relay cells + Edge HTTPS; G4-T only if Tor pilot evidence lands.  
**Explicit non-claims:** no GA, no stable channel, no “all relays are blind.”

---

### Ship 4 — Boot-restore / main merge (Track C entry)

**When:** after Track B acceptance (or when boot-restore agent finishes independently, then re-qualify B)  
**Who:** boot-restore + release worktrees → **main**

| Contents | Ladder |
|----------|--------|
| `packages/blind-daemon`, blind-edge, IPC, boot floors, sealed-manifest recovery | Durability of G2-S/G3 store |
| Rebase **service-http-wiring** onto merged main | Avoid dual `api.js` / `app-lifecycle` / outboxlog forks |
| Resolve conflicts only once | Process |

**Tag options:**

- `v0.26.0-rc.1` if product stays 0.x fleet numbering, **or**
- keep public-test RC line until freeze, then first monorepo tag that **contains** blind packages

**Claim:** *“Blind stack is in main and can be built/released as one product.”*  
Still not fleet-wide enable.

---

### Ship 5 — `v0.26.0-rc.1` · Blind-capable monorepo canary

**When:** Ship 4 green unit/integration + Linux durability smoke

| Contents | Ladder |
|----------|--------|
| Unified tag: fleet utilities + optional blind-daemon profile | G0–G3 **code complete** for GA path |
| Canary: 1–2 large relays run **profile=blind** (or sidecars from same tag digests) | Pilot → canary |
| Syd/dal promote from public-test digests → release digests **or** re-pin | Continuous line |
| Capability-doc honesty: advertise only evidenced routes | Badges |

**Gate:** Linux Phase-0-class durability/throughput (giga holdouts), negative-probe on restricted Tor if claiming private onion, boot-restore after wipe test.

---

### Ship 6 — `v0.26.0` · First **opt-in** blind fleet profile

**When:** Ship 5 canary green

| Contents | Ladder |
|----------|--------|
| Stable channel for **core+utilities** stays default | Don't force blind on 0.5–2 GB boxes |
| Documented operator profile: `blind-cell-relay` on large NA/EU/APAC seeds | G3 cohort |
| Shard-store + blind-daemon policy (one architecture story) | No dual fantasies |
| 3rd **independent** operator only if external evidence exists | Independence claim |

**Claim:** *“Operators can run a verified blind-cell relay profile.”*  
Not: every relay is blind; not G2-W/G4-I/G5.

---

### Ship 7 — App-origin HTTPS gateway evidence + public read plane

**When:** can overlap late Ship 5–6  
**From giga map:** path gateway shipped; **app-origin** still needs owner/fleet evidence

| Contents | Ladder / product |
|----------|------------------|
| Signed-tag digests, two-operator gateway evidence, Docker nginx capture | Public read plane honesty |
| Capability-doc: public vs blind 403 boundaries | G1/G2-S on read path |
| Does **not** replace Blind Edge public-test | Different ingress |

**Claim:** *“Public content has an evidenced HTTPS read plane; private/blind still fail closed.”*

---

### Ship 8 — Tor hardening RC (full G4-T evidence)

**When:** after Ship 2 packaging is live on hosts

| Contents | Ladder |
|----------|--------|
| Persistent onion keys + backup | Production Tor |
| Negative-probe on restricted discovery (giga holdout) | No fail-open roster |
| 100 MB bulk-over-onion measurement | Capacity honesty |
| Optional: onion peer vport + control-plane health ads | G4-T operational |

**Claim:** *“Relay location can be onion-hidden with measured limits.”*  
Never: TA-resistant / mixnet-level anonymity.

---

### Ship 9 — Split transport (G2-W + stronger G4-T)

**When:** after Ship 6–8 stable; **spec exists, code does not**

| Contents | Ladder |
|----------|--------|
| OHTTP ingress + Protomux data plane per split-transport spec | **G2-W** |
| Browser path: ingress sees identity not request; gateway sees request not identity | G4-T under non-collusion |
| Dev-profile → canary → stable | Long fuse |

**Claim:** *“Wire opacity under stated non-collusion assumptions.”*  
Still not G4-I or G5.

---

### Ship 10 — G4-I research/pilot only (optional, late)

Bucket download / PIR-ish patterns for “can't tell which post I read.”  
**Not** required for “whole ladder” product ship; separate research track.

### Ship 11 — Forever non-ship

**G5** for public content — document as unachievable; badge every public explainer.

---

## 5. Time order vs ladder

```text
NOW ──► 0.25.0-rc.1 ──► 0.25.0 ──► (stable fleet utilities+Tor path)
              │
              │   parallel
              ▼
         Blind PT 1.0.0-rc.1.public-test.1
              syd-1 ──► Dallas (2nd FD) ──► Peerit bind
              │
              ▼
         boot-restore → main
              │
              ▼
         0.26.0-rc.1 ──► 0.26.0 (opt-in blind profile)
              │
              ├── gateway app-origin evidence
              ├── Tor negative-probe + bulk measure
              └── (later) split transport G2-W
```

| Time | Ship | Ladder rungs **advanced** |
|------|------|---------------------------|
| Now | hygiene | — |
| Soon | **0.25.0** | Ops floor for G1 services + G4-T path |
| Parallel | **Blind PT syd→dal** | G2-S/G3 **pilot evidence** |
| After PT+merge | **0.26** | G2-S/G3 **productizable** |
| After 0.26 | Gateway evidence + Tor ops | Honest public plane + G4-T ops |
| Later | Split transport | **G2-W** |
| Never | G5 public | — |

---

## 6. Where Sydney + Dallas sit

| Role | Track | Version | Relation to 0.25.0 |
|------|-------|---------|---------------------|
| **sydney :9100** | A | → 0.25.0 with fleet | Ordinary utility relay |
| **syd-1 Blind :443** | B | `1.0.0-rc.1.public-test.1` | **Not** 0.25.0; co-located pilot |
| **Dallas Blind** | B phase-2 | same public-test digests + continuity pin | Still not fleet 0.25; unlocks two-FD durability claim |
| **After accept** | C | feeds **0.26** monorepo/opt-in profile | First time “blind” is a fleet version story |

If Dallas replaces Bern in the handover: same **phase-2 seat**, same lease constraints.

### Track A vs Track B FAQ

| Question | Answer |
|----------|--------|
| Does v0.25.0 **include** blind-daemon / blind-edge on every relay? | **No** — that would be GA/stable and violates the public-test lease |
| Does v0.25.0 **block** or **depend on** syd/dal blind? | **No** — ship Tor + utilities fleet-wide while public-test continues on ≤2 nodes |
| Is syd/dal “using” 0.25.0? | Ordinary relay on those boxes *may* get v0.25.0 via channel; Blind stack is sidecars, public-test versioned |
| When does blind become “part of” a fleet version? | After public-test acceptance → merge boot-restore into main → **v0.26** (or later), not by redefining 0.25 |

---

## 7. Dependency / conflict rules

1. **0.25.0 never requires** Blind OCI or boot-restore on main.
2. **Public-test never mutates** `channels.json` stable/canary.
3. On syd/dal: Blind owns **443**; fleet relay owns **9100**.
4. Merge boot-restore **before** claiming 0.26 “includes blind substrate.”
5. Rebase service-http-wiring **after** that merge (shared files: `api.js`, `app-lifecycle`, outboxlog, client).
6. Shard-store on large fleet boxes ≠ full blind-daemon; badge **partial G3** until daemon profile is the story.
7. On pilot hosts, Track A may update the main relay (`services.json`, Tor, utilities) without touching Blind compose, blind roots, or :443 Edge.

---

## 8. Definition of done (honest marketing)

You can call the **product ladder complete for honest marketing** when:

| Done | Ship |
|------|------|
| G0+G1 fleet-wide | already + 0.25.0 utilities |
| G2-S evidenced at rest (no app schema) | Blind PT + 0.26 |
| G3 multi-relay cells (owner FDs → then independent ops) | PT two-FD → later 3rd operator |
| G4-T onion path with negative-probe + measured limits | Ship 8 |
| G2-W optional product | Ship 9 |
| G4-I optional research | Ship 10 |
| G5 never claimed | docs discipline |

---

## 9. Immediate next three moves (in order)

1. **Branch + tag path for Track A:** `feat/service-http-wiring` → `v0.25.0-rc.1` canary → `v0.25.0` stable.
2. **Unblock Track B:** DNS `syd1.p2phiverelay.xyz` → deploy/qualify syd-1 → Dallas as 2nd FD.
3. **Only then** merge boot-restore + tag **0.26** for “blind-capable product.”

---

## 10. Ops notes that feed the map

| Lesson | Implication |
|--------|-------------|
| **`services.json` is runtime authority** for which plugins load | Writing config alone does not enable services (dubai incident) |
| Plugin names must match registered builtins on that version | Invalid names (e.g. wrong `storage-proof` id on 0.24.3) silently fail load |
| Small boxes OOM under co-tenants + heavy services | utah-2gb: stop non-relay processes; keep shard-store off on 0.5–2 GB |
| Boot-restore and service-HTTP share hot files | Branch wiring off main; merge boot-restore first into main when ready, then rebase |

---

*Update this file when a ship lands or a claim badge changes. Prefer a one-line “shipped / parked / blocked” note under the relevant Ship section rather than rewriting history.*
