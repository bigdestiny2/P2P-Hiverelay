# Peerit blind-cells handover — sydney + dallas public-test

**Date:** 2026-07-27 · **From:** fleet/test-repair session · **To:** Peerit blind-cells agent
**Scope:** Track B blind public-test deployment on sydney (syd-1) → dallas (dal-1)

> You are deploying the **blind-edge :443 + blind-daemon (Unix sock)** public-test stack as the second track of the dual-path ship plan. This is a **parallel version line** (`1.0.0-rc.1.public-test.1`), NOT a fleet channel bump. The raw fleet relay on each box (`:9100`) stays on its own version and must not be touched.

---

## 1. Fleet status (verified live 2026-07-27 14:30 UTC)

### All relays

| Relay | Version | Health | Disk | Channel | Note |
|-------|---------|--------|------|---------|------|
| utah | v0.25.0-rc.4 | ✅ running (2h48m) | 21% | canary | Tor cohort — **live onion advertised** |
| utah-8gb | v0.25.0-rc.4 | ✅ running | 4% | canary | Tor cohort — live onion |
| utah-us | v0.24.3 | ✅ running | 46% | stable | |
| utah-2gb-a | v0.24.3 | ✅ running | 22% | stable | |
| utah-0.5gb | v0.24.3 | ✅ running | 44% | canary | |
| miami | v0.24.3 | ✅ running | 21% | stable | |
| sing-1 | v0.24.3 | ✅ running | 67% | stable | |
| sing-2 | v0.24.3 | ✅ running | 26% | stable | |
| **sydney** | v0.24.3 | ✅ running (1h35m) | 46% | stable | **Track B pilot host (syd-1)** |
| bern | ❌ unreachable | — | — | canary | **Provider outage** — SSH + ping dead; needs console/power recovery |
| amsterdam | v0.24.3 | ✅ running | 44% | stable | |
| dubai | v0.24.3 | ✅ running | 28% | stable | |
| **dallas** | v0.24.3 | ✅ running (4h) | 9% (265GB free) | stable | **Track B 2nd failure domain (dal-1)** |

**Scorecard: 11/12 healthy. bern is a provider-side outage (network/power), not a process issue — file a ticket with the VPS provider for console access.**

### Tor evidence (live, not just packaged)

utah's signed capability doc carries a **real advertised onion**:
```
3ks4cpnp4x3keay2qanvqnqwehvcqlcxysuk5qktcvbkeko44fgrsuid.onion
```
- Restricted discovery: `client-auth-v3` + `pairing-channel` enrollment
- Peer vport: `19737` (Noise/Protomux)
- Exposure: `dual` (clearnet + onion)
- **This is G4-T evidenced** — not a packaging claim.

### Session work that landed (today)

9 commits on `feat/service-http-wiring` restoring features orphaned by convergence refactors. The unit suite went from **broken at load** → **~310/327 files green**. Key restorations relevant to your work:
- **Tor enrollment subsystem restored** (roster-expiry, fail-closed tombstone, `authClientEnrollmentPolicy`) — the doc-claimed enrollment feature was dead; now `tor-enrollment 7/7`.
- **Gateway exact-app-context routing restored** — app-origin Host serving was 400'ing; now `gateway-server 34/34`.
- **Outboxlog fleet-seed gate fixed** — now probes `announceAuthorityOwnedCore` correctly and propagates the storage bound.

---

## 2. Track B host readiness

### Sydney (syd-1, first failure domain) — READY

- **IP:** `104.194.135.205` · **SSH key:** `~/.ssh/cloudzy_hiverelay`
- **Health:** running, v0.24.3, uptime 1h35m, disk 46% ok
- **Fleet relay :9100:** healthy — **do not touch**
- **Disk:** 60GB total (~32GB free) — enough for the blind public-test stack
- **Tor:** not installed (not required for blind-edge; the edge uses public-CA TLS on :443)

### Dallas (dal-1, second failure domain) — READY (Tor pending, not blocking)

- **IP:** `172.86.90.115` · **SSH key:** `~/.ssh/cloudzy_hiverelay`
- **Health:** running, v0.24.3, uptime 4h, disk 9% (265GB free)
- **Fleet relay :9100:** healthy — **do not touch**
- **Disk:** 300GB total (~265GB free) — **plenty for blind cells + cohort storage**
- **Tor:** **not installed** — install only if the pilot claims a Tor path; blind-edge on :443 doesn't need it

### Port allocation (per host)

```
:9100  → HiveRelay fleet relay (Track A) — DO NOT TOUCH
:443   → blind-edge (Track B, public-CA TLS) — YOURS
/var/run/hiverelay-blind/blind-daemon.sock → blind-daemon (Unix socket) — YOURS
```

---

## 3. Prerequisites NOT done yet (blockers)

| Prereq | Status | Action |
|--------|--------|--------|
| **DNS `syd1.p2phiverelay.xyz`** | ❌ not resolving | Create A record → `104.194.135.205` |
| **DNS `dal1.p2phiverelay.xyz`** | ❌ not resolving | Create A record → `172.86.90.115` (do this AFTER syd-1 accepts) |
| **Blind OCI images built/pushed** | ⚠️ in worktree, not published | Build + push `1.0.0-rc.1.public-test.1` digests (see §4) |
| **ACME cert for syd1** | ❌ pending | Issue after DNS lands; blind-edge terminates TLS |
| **`docker-compose.blind-public-test.yml`** | ⚠️ exists as `docker-compose.blind.yml` | Adapt for public-test (see §4) |

**Do NOT start deploy until DNS + cert are live on syd-1.** The edge needs a valid public-CA cert; a self-signed cert violates the public-test lease.

---

## 4. Where the blind artifacts live

The blind-edge + blind-daemon packages are **NOT in the main hiverelay checkout** — they live in worktrees. The most complete set:

```
~/Projects/pear-ecosystem/00-core/v1-integration/
├── packages/
│   ├── blind-daemon/     ← coordinator, cell control snapshots, CLI, WAL
│   └── blind-edge/       ← server, IPC client, readiness checks
├── docker-compose.blind.yml   ← hardened compose (read-only, cap_drop ALL, pids_limit)
└── docs/                   ← v1 release sequence, evidence runs
```

**Other worktrees with blind packages** (for cross-reference, not authoritative):
- `hiverelay-blind-vnext-integration/` — boot-restore integration
- `tor-gateway-convergence-review/` — ⚠️ this is the worktree whose refactors orphaned the main-repo code; do NOT use its main-repo merge
- `hq/` — the vnext/hq lane referenced in the ladder map

**Image references** (from the compose):
```yaml
HIVERELAY_BLIND_DAEMON_IMAGE: hiverelay/blind-daemon:local  # → build + tag 1.0.0-rc.1.public-test.1
HIVERELAY_BLIND_EDGE_IMAGE:   hiverelay/blind-edge:local    # → build + tag 1.0.0-rc.1.public-test.1
```

Build from the `v1-integration` worktree, push to GHCR with digest pinning, then pin the digests in the public-test compose before deploying.

---

## 5. Deployment + qualification sequence

Per `docs/LADDER-SHIP-MAP.md` Ship 3. **Strict order: syd-1 fully accepts BEFORE dallas starts.**

### 3a — DNS + cert

1. `syd1.p2phiverelay.xyz` A record → `104.194.135.205`
2. ACME cert for `syd1.p2phiverelay.xyz` (blind-edge terminates :443)

### 3b — syd-1 deploy + qualify

1. Load digest-pinned edge+daemon OCI (`1.0.0-rc.1.public-test.1`)
2. Compose up: `blind-edge` (:443) + `blind-daemon` (Unix sock) + `blind-volume-init`
3. Node ceremony: **new Blind root** (do not reuse fleet relay identity); preserve `/opt/hiverelay` + `~/.hiverelay`
4. **Qualify against the protocol surface:**
   - `DESCRIBE` — daemon responds with capability profile
   - `CELL` — write + readback a blind cell
   - `INBOX` — cell inbox lifecycle
   - `CORE` — core control snapshot stream
   - `FORWARD` — one-hop forward relay
   - **Negatives:** unauthorized write rejected, wrong-key read rejected, oversized payload rejected
5. Restart + WAL recovery + rollback-sidecar evidence (durability pilot)
6. **Independent syd-1 acceptance gate** — all of the above green before proceeding

### 3c — Dallas (2nd failure domain) — ONLY after 3b accepts

1. Continuity-linked phase-2 manifest (new pin-history entry, same digests)
2. `dal1.p2phiverelay.xyz` A record → `172.86.90.115`
3. Baseline capture BEFORE mutate; full qualify (same as 3b.4)
4. **Two-relay cell write/readback** — write to syd-1, read from dal-1 (and vice versa)
5. **One-relay-down behavior** — kill dal-1 daemon, verify syd-1 still serves; restart, verify recovery
6. Claim: **two owner-operated failure domains** — NOT independent operators

### 3d — Peerit public-test bind — ONLY after 3c accepts

1. Clean Peerit commit binds to exact protocol/store/OCI/descriptor hashes
2. Two-relay catalogue; cell e2e through Peerit only
3. **No seed publish until seed-spec review**

---

## 6. Honest claim boundaries (the lease)

This is `LIVE_PUBLIC_TEST_ONLY`. Do NOT:

- ❌ Call it "GA" or "stable"
- ❌ Bump `fleet/channels.json` stable or canary
- ❌ Enable blind-daemon on any fleet relay (only the sidecar on :443)
- ❌ Claim "independent operators" — both FDs are owner-operated
- ❌ Claim G3 (at-rest unlinkability) until two-relay cohort cell e2e is evidenced
- ❌ Merge blind packages into main (that's Track C, after your acceptance)

**What you CAN claim after syd-1 + dal-1 accept:**
- G0 + G1 + G2-S + **partial G3** (multi-relay cells, owner-operated FDs)
- Edge HTTPS on public-CA TLS
- G4-T only if a Tor path is piloted (optional, not required for blind-edge)

**Marketing line when live:** *"Fleet v0.25.0 + Blind public-test on syd1 (+ dal)"* — two components, one sentence, **not one tag.**

---

## 7. Guardrails

1. **`:9100` is off-limits.** The fleet relay on each box runs its own version and must not be restarted, reconfigured, or upgraded by the blind deploy.
2. **Image digests are load-bearing.** Pin them in the compose; a tag-mutable image violates the public-test lease.
3. **The blind root is new.** Do not reuse the fleet relay's identity key for the blind daemon.
4. **Small boxes are fragile.** sydney has 60GB disk; monitor blind-daemon WAL growth and cap it. dallas has 300GB — the roomier host.
5. **bern is down.** If the plan named bern as the alternate 2nd FD, dallas is the replacement (same slot, same lease constraints).

---

## 8. Contacts / references

- **Ladder map:** `docs/LADDER-SHIP-MAP.md` (canonical ship sequence)
- **Blind cells design:** `docs/BLIND-CELLS.md`
- **Tor transport:** `docs/TOR-ONION-TRANSPORT.md` (enrollment now restored)
- **Giga release architecture:** `docs/GIGA-RELEASE-ARCHITECTURE.md`
- **Blind artifacts:** `~/Projects/pear-ecosystem/00-core/v1-integration/`
- **Fleet status script:** `bash fleet/fleet-status.sh` (from hiverelay checkout)
- **Local fleet inventory (SSH keys):** `fleet/relays.local.json` (gitignored — operator-only)
