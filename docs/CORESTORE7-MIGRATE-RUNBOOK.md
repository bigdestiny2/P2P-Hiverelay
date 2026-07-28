# Corestore 7 production migration runbook

**Date:** 2026-07-26  
**Status:** Proven on utah + utah-8gb for `v0.25.0-rc.4`

## Root cause of the 0.25 “hang”

Opening a **Corestore 6** production tree with **Corestore 7** is fine when RocksDB migration is clean. Earlier rc canaries left a **partial / corrupt `storage/db/`** next to legacy `storage/cores/`.

In that mixed state:

| Operation | Result |
|-----------|--------|
| `store.ready()` | Succeeds quickly |
| `store.get({ name }).ready()` (any named core, even fresh) | **Hangs forever** |
| Same tree under CS6 | Named cores ready in tens of ms |

Empty CS7 stores work immediately. Removing the bad `db/` and letting CS7 rebuild from `cores/` restores `core.ready()` (~100ms for `app-registry-v1`).

This is **not** “Corestore cannot open production data” — it is **incomplete CS7 RocksDB state from aborted canaries**.

## Fix on a box (operator)

1. **Stop updater** so canary hold does not immediately pull back to 0.24.3:

   ```bash
   systemctl stop hiverelay-updater.timer
   systemctl disable hiverelay-updater.timer
   ```

2. Stop the relay and free `:9100` (avoid `pkill -f` patterns that match the SSH command line):

   ```bash
   systemctl kill -s SIGKILL hiverelay || true
   fuser -k -9 9100/tcp 2>/dev/null || true
   ```

3. **Quarantine** the bad RocksDB (keep for forensics; do not delete until soak is green):

   ```bash
   STORAGE=/root/.hiverelay/storage
   if [ -d "$STORAGE/cores" ] && [ -d "$STORAGE/db" ]; then
     mv "$STORAGE/db" "$STORAGE/db.corrupt-pre-cs7-$(date +%Y%m%d%H%M%S)"
   fi
   ```

4. Checkout **0.25** and install CS7 deps:

   ```bash
   cd /root/hiverelay
   git fetch --tags origin
   git checkout -f v0.25.0-rc.4
   npm ci   # need corestore@7; omit=dev can skip patch-package if you rely on patches
   ```

5. Ensure full features + Tor config (`services.json` plugins + `config.transports.tor` / `dhtRelayWs`), host Tor daemon running.

6. Start and **wait** — first boot reseeds many apps; health may take **60–120s**:

   ```bash
   systemctl start hiverelay
   # poll /health until version shows 0.25.x
   ```

7. Verify:

   ```bash
   curl -sS http://127.0.0.1:9100/health
   curl -sS http://127.0.0.1:9100/status   # transports.tor.running, dhtRelayWs
   curl -sS http://127.0.0.1:9100/api/v1/services
   ```

## Rollback to 0.24.3

1. Stop relay, `git checkout -f v0.24.3`, reinstall CS6 deps (`npm ci --omit=dev`).
2. Restore a **CS6-era** `db/` only if you had one that worked under 0.24; CS6 primarily uses `cores/`.
3. Re-enable updater only after channel points at the intended tag.

## Do not

- Point CS7 at a tree with a half-written `db/` from failed experiments without quarantine.
- Leave canary channel at `v0.24.3` while manually running 0.25 — the fleet updater will **pull you back** (observed 2026-07-26 on utah).
- Use `pkill -f 'cli/index.js'` over SSH — it can match and kill the remote shell.

## Fleet status (post-fix, 2026-07-26 evening)

| Box | Version | Tor | Notes |
|-----|---------|-----|--------|
| utah | `0.25.0-rc.4` | host + transport on | Updater timer disabled |
| utah-8gb | `0.25.0-rc.4` | host + transport on | Updater timer disabled |
| Other raw VPS | `0.24.3` | mostly off | Utilities rolled where SSH worked |
| bern, utah-0.5gb | — | — | SSH key / reachability broken |

## Code follow-ups (for rc.5)

1. Startup guard: if `cores/` exists and `db/` fails `get({name}).ready()` within N seconds, emit a clear error / optional auto-quarantine of `db/`.
2. Point canary channel at `v0.25.0-rc.4` (or later) once soak is accepted; re-enable updater.
3. Investigate **outboxlog** missing from `/api/v1/services` while listed in `services.json` (other utilities load).
