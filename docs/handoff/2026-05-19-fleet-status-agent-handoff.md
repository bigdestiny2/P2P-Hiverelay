# Fleet status + agent handoff — 2026-05-19

State of the HiveRelay fleet and everything an incoming agent needs to
pick up cold. Captured during a live status check on 2026-05-19.

## TL;DR

- **Fleet is healthy.** 8 relays up, all seed-probes pass, no wedges.
- **5 in-house relays on v0.8.14 with ~95.7h uptime** (≈4 days) — well
  past the historical ~57.8h wedge window. The cancellation contract
  (v0.8.13) + per-drive corestore session (v0.8.14) hold under load.
- **utah-us canary still on the debug branch** (`fix/drive-close-
  corestore-cascade`, commit `0573166`) with `HIVERELAY_STORE_TRACE=1`
  and the hourly auto-capture watcher armed. Has run 95.7h without
  any wedge auto-captured.
- **Bonus diagnostic from the canary:** the trace captured 15
  `close-call` events + 1 `watchdog` event showing the root corestore
  transitioning `closed=true` at 09:39:20Z on 2026-05-18 — yet the
  relay stayed up. That means either (a) v0.8.14's merge commit
  `1821d56` covers Hyperdrive sites the canary precursor `0573166`
  doesn't, or (b) at least one Hyperdrive site still constructs against
  the raw root store instead of a session. **Follow-up audit needed.**

## Live status snapshot

```
relay         up    peers  anchored  v        uptime
utah          ✓     12     416/417   0.8.14   5741m  (≈95.7h)
utah-us       ✓     12     499/517   0.8.13*  5741m  (≈95.7h, canary)
singapore-1   ✓     12     356/357   0.8.14   5740m
singapore-2   ✓     12     343/345   0.8.14   5740m
bern          ✓     12     117/118   0.8.14   5737m
milkyb-fra    ✓     12     4/4       0.8.13   10105m (external)
milkyb-iad    ✓     12     6/6       0.8.13   10106m (external)
milkyb-syd    ✓     12     3/3       0.8.13   10105m (external)
```

`*` utah-us is on the canary precursor (`fix/drive-close-corestore-
cascade`), which predates the v0.8.14 version bump — same fix, just
older string. Verified per-drive `node.store.session()` is in its code.

Real-seed-probe (the only reliable wedge detector — bad-sig probes
fail at validation before the corestore is touched):

```
utah, utah-us, sing-1, sing-2, bern  →  INVALID_SIGNATURE  (healthy)
```

## What shipped recently (commits on `main`)

```
b6ad60e docs(feedback): corroborate silent-partial-pin on a 2nd drive (Drop)
c172735 ops: relay-janitor — Tier-1 auto-sweep, Tier-2 report-only
83fd3c1 test-scripts: self-expiring synthetic drives
1821d56 release: v0.8.14 — corestore-session fix + Dockerfile verifier COPY
d64c893 Merge fix/drive-close-corestore-cascade — silent corestore-close root cause
0a735a2 docs: resolve debug session silent-corestore-close + update KB
0573166 fix(relay): use corestore session per drive to prevent store-close cascade
9b38d6f docs(handoff): _scanRegistry TOCTOU guard — ready, deliberately not applied
```

## The silent corestore-close story (resolved)

1. **v0.8.10** baseline: relays wedged after ~6h. Symptom:
   `POST /api/v1/seed` returns 503 `corestore is closed` on valid
   signed requests; bare probes still work because validation is
   pre-store.
2. **v0.8.13** (Iain) shipped `LifecycleScope` cancellation contract
   that drains fire-and-forget loops on `stop()`. Improved time-to-
   wedge ~6h → ~57.8h. But continuous-operation vector survived (these
   relays never called `stop()`).
3. **Root cause** (debug session, see `.planning/debug/resolved/silent-
   corestore-close.md`): `_runCustodyExpiryPass` runs every 60s, calls
   `unseedApp` on expired entries, which calls `drive.close()`. Inside
   hyperdrive's `_close`, it called close on its corestore reference —
   which was the RAW `node.store` because every `new Hyperdrive(node.
   store, key)` passed the root store directly. Cascade closed the
   root.
4. **v0.8.14 fix** (`1821d56`): every `new Hyperdrive(node.store.
   session({…}), key)` — each drive gets its own session. Close
   propagates to the session, root store unaffected.
5. **Verified canary**: utah-us 95.7h uptime, 15 trace events show the
   custody-expiry close path still firing, but the relay stays up
   because the cascade is broken at the session boundary.

The captured stack:
```
at _storeRef.close (relay-node/index.js:510:28)        ← instrumentation wrapper on node.store
at Hyperdrive._close (hyperdrive/index.js:191:28)      ← hyperdrive closing its store ref
at async close (ready-resource/index.js:56:54)
at async AppLifecycle.unseedApp (app-lifecycle.js:953:11)
at async RelayNode._runCustodyExpiryPass (relay-node/index.js:2580:9)
```

## Open follow-ups (not blocking)

1. **Hyperdrive-site audit** — the canary captured a watchdog event
   showing root corestore `closing=true closed=true` at
   2026-05-18T09:39:20Z, yet the relay kept serving. This implies
   either v0.8.14's merge commit covers more Hyperdrive sites than
   the canary commit, OR some Hyperdrive site still uses the raw
   `node.store` and the cascade is being absorbed elsewhere. Audit
   targets: `packages/core/core/gateway/server.js`, any
   `services/storage-service`-style code, the registry's localLog
   construction, anything else that calls `new Hyperdrive(...)`.
   Apply `.session()` defensively where missing.

2. **Retire the canary** — move utah-us off `fix/drive-close-corestore-
   cascade` back to `main` (v0.8.14). Disarm the
   `HIVERELAY_STORE_TRACE=1` env (drop the drop-in at
   `/etc/systemd/system/hiverelay.service.d/store-trace.conf`), remove
   the watcher cron (`crontab -r`-style), and `git checkout main &&
   git reset --hard origin/main && systemctl restart hiverelay`. That
   also clears its 48 lingering test-junk entries (the janitor's
   version-gate correctly refused to sweep them on the canary).

3. **fed-junk upstream fix** — the janitor exposed 1061 federated
   "junk" entries that the relay accumulated via catalog-sync, but the
   PearBrowser drive (`8b21b577…`) is BYTE-IDENTICAL to fed-junk in a
   mirroring relay's registry. There is no local field to distinguish
   important mirrored content from accidental accretion. The real fix
   is **upstream**: tighten catalog-sync accept-mode / federation
   follow-policy so relays don't blind-accumulate. Design discussion
   needed.

4. **_scanRegistry TOCTOU guard** — `9b38d6f` parked a candidate
   `_scanAlive` fix (gate on seedingRegistry/seeder presence rather
   than the running flag). Ready, deliberately not applied because
   the root cause turned out to be the cascade, not TOCTOU. Keep in
   reserve.

## Operational facts the next agent will need

### Repo + git

- Local: `/Users/localllm/hiverelay`
- Origin: `https://github.com/bigdestiny2/P2P-Hiverelay`
- `main` HEAD: `b6ad60e` (as of this handoff)
- Push gotcha: `gh auth switch -u bigdestiny2` before `git push` —
  the alt account `iesetorg` lacks push rights and produces a confusing
  `403 denied to iesetorg`.

### Relay SSH access

| Relay        | IP                | SSH command                                                          |
| ------------ | ----------------- | -------------------------------------------------------------------- |
| utah         | 144.172.101.215   | `ssh root@144.172.101.215`                                           |
| utah-us      | 144.172.91.26     | `ssh root@144.172.91.26` (CANARY)                                    |
| singapore-1  | 104.194.153.179   | `ssh root@104.194.153.179`                                           |
| singapore-2  | 104.194.152.121   | `ssh -i ~/.ssh/cloudzy_hiverelay root@104.194.152.121`               |
| bern         | 45.59.123.112     | `ssh -i ~/.ssh/cloudzy_hiverelay root@45.59.123.112`                 |
| milkyb-{fra,iad,syd} | Fly.io   | **no SSH for us** — external operator (Iain), HTTPS only             |

All five in-house: code at `/root/hiverelay`, systemd unit `hiverelay`,
log at `/var/log/hiverelay.log`, API on `:9100` localhost-bound.

### Observatory (Bern)

- `systemctl is-active hiverelay-observatory` on Bern
- HTTP on `:9200`, **closed in firewall** — tunnel:
  `ssh -i ~/.ssh/cloudzy_hiverelay -N -L 9200:127.0.0.1:9200 root@45.59.123.112`
- Open `http://localhost:9200/` — relay cards + SSE log stream
- Endpoints: `/api/state`, `/api/logs/stream` (SSE), `/api/logs/recent?n=200`, `/healthz`
- Iain (`iain@laptop`) has an SSH tunnel key with port-forwarding-only
  restriction; he can be on the dashboard concurrently.

### The wedge-detection probe ladder

| Request                              | Healthy relay              | Wedged relay              |
| ------------------------------------ | -------------------------- | ------------------------- |
| `POST /api/v1/seed {}`               | `appKey required` (400)    | `appKey required` (400)   |
| well-formed 128-hex BAD signature    | `INVALID_SIGNATURE` (4xx)  | `INVALID_SIGNATURE` (4xx) |
| **valid signed seed request**        | 200 OK + anchor            | **`corestore is closed` 503** |

Only the third row distinguishes wedged from healthy. The proven valid-
signed detector is `node scripts/publish-test-drive.js --target <relay>`.

### utah-us canary specifics

- branch: `fix/drive-close-corestore-cascade` @ `0573166`
- `HIVERELAY_STORE_TRACE=1` set via
  `/etc/systemd/system/hiverelay.service.d/store-trace.conf`
- hourly watcher: `/root/store-close-watcher.sh` + cron
  `17 */1 * * *`, log `/root/store-close-watcher.log`,
  capture file `/root/store-close-capture-*.txt` (touches
  `/root/store-close-capture.captured` after one-shot disarm)
- captured? NO (`.captured` does not exist as of 2026-05-19); 15
  close-call traces + 1 watchdog event written to
  `/var/log/hiverelay.log` since the deploy, all survived
- pid 429294 has been alive 95.7h
- to retire: see follow-up #2 above

### Tooling on the local machine

- `scripts/publish-test-drive.js` — synthetic publisher (real ed25519
  keypair + signed seed). `--target utah` or `--roundrobin`.
  Self-expires (storageClass:'temporary', short retainUntil) so it
  doesn't add to junk.
- `scripts/custody-e2e.js` — 6-stage atomic-custody E2E. Same self-
  expiry.
- `scripts/relay-janitor.js` — fleet GC (DRY-RUN default). `--tier1
  --apply` sweeps test-junk safely. fed-junk is REPORT-ONLY by design
  (PearBrowser indistinguishability — see header comment).
- `scripts/deploy-vps.sh` — fleet redeploy via SSH.
- `tools/observatory/` — Node poller + SSE log tail; deployed to Bern.

### Key docs

- `CHANGELOG.md` — release history; v0.8.14 is current.
- `docs/RELEASE-NOTES-0.8.14.md` — corestore-session fix details.
- `docs/repro/2026-05-17-v0.8.13-partial-recurrence.md` — the
  partial-fix discovery that led to v0.8.14.
- `docs/repro/2026-05-15-corestore-closed-repro.md` — original repro.
- `docs/FEEDBACK-PEARBROWSER-PIN-CAP-FAILURE.md` — the publisher-side
  silent-partial-pin case study (now corroborated by the Drop drive).
- `.planning/debug/resolved/silent-corestore-close.md` — full debug
  session record.
- `.planning/debug/CAPTURED-TRACE-2026-05-18.md` — the stack capture
  that localised the root cause.
- `.planning/debug/knowledge-base.md` — accumulated lessons.

### gotchas worth knowing

- `npm install` on the monorepo thrashes — it cycles between dropping
  `brittle`, `socks/build/`, and `ip-address` depending on what was
  installed last. The lockfile currently includes `socks` + `ip-
  address` as root deps (yes, an oddity from the workspace install
  quirks); leave them.
- Node 20+ everywhere. utah-us happens to have node 18; this works for
  `publish-test-drive.js` but if you need the test suite there,
  upgrade first.
- The relay's `/var/log/hiverelay.log` is interleaved with terminal
  `[status]` status-line CR-overwrites — grep with `grep -v
  '\[status\]'` to read JSON pino lines cleanly.
- 4th-party peer `299a0be26e5e…` shows up in every relay's `/peers`
  and is NOT in our fleet; mystery operator federating with us. Same
  for the milkyb fleet which IS Iain's. Both benign.

### Active TODO / decision queue

1. (open) Hyperdrive-site audit — see follow-up #1
2. (open) Retire the canary — see follow-up #2
3. (open) fed-junk upstream design — see follow-up #3
4. (parked) `_scanAlive` TOCTOU candidate — see follow-up #4
5. (resolved) Silent corestore-close — root cause + fix shipped

The fleet is in a good state. Nothing is on fire; the open items are
hardening + design work, not emergencies.
