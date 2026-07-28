# Fleet stability — why nodes were dropping (2026-07-27)

## Failure modes (observed)

| Mode | Symptom | Root cause | Nodes hit |
|------|---------|------------|-----------|
| **Event-loop hang** | `systemctl active`, `:9100` LISTEN, `/health` times out | Process stuck; often memory cgroup reclaim (`wchan=mem_cgroup_handle_ov`) or CS7 bad `storage/db` | utah-8gb, miami, others intermittently |
| **OOM / cgroup kill** | journal `oom-kill`, `MemoryMax` | Working set exceeds cgroup cap; no swap on large boxes | utah-8gb (5.8G peak), sing-1 |
| **ABRT / core-dump** | `status=6/ABRT` every few hours | Heap/native pressure on **0.5–1GB** boxes running full plugin suite | miami, utah-0.5gb, sing-1 |
| **CS7 bloated RocksDB** | RSS multi-GB, hang within minutes of start | Partial/corrupt `storage/db` growing to multi-GB blobs; healthy utah has ~186MB db | utah-8gb (**8.6GB** db quarantined) |
| **SSH offline** | connect timeout | Host/network unreachable | bern |

Systemd alone cannot fix hangs: the main PID stays alive, so `Restart=` never fires.

## Fixes applied

### 1. Local health watchdog (all reachable boxes)

- `fleet/health-watchdog.sh` + `hiverelay-health-watchdog.{service,timer}`
- Install: `ssh root@box 'bash -s' < fleet/install-health-watchdog.sh`
- Every **2 minutes**: if unit is active but `/health` fails **twice** → `SIGKILL` + free `:9100` + `systemctl start`
- 90s grace after process start (boot reseed)

### 2. utah-8gb remigrate + memory

- Quarantined `storage/db` (8.6GB) → `db.bloated-pre-stabilize-*`
- CS7 rebuilds from `cores/`; RSS dropped **~5.5GB → ~110MB**
- Added **4G swap**, disabled thrashing `MemoryHigh` soft-lock (`MemoryHigh=infinity`, keep `MemoryMax=6G`)
- Full feature plugins retained

### 3. Small boxes (≤1GB RAM)

- Plugin set trimmed to `outboxlog`, `notify`, `vrf` (full suite belongs on ≥2GB)
- Restart + existing `MemoryMax` caps + swap kept

### 4. Fleet-wide hardening drop-ins

- `Restart=always`, `TimeoutStopSec=12`, `KillMode=mixed`, `FinalKillSignal=SIGKILL`
- Swap added where missing (utah, dallas, utah-us, utah-2gb-a, …)

## Post-fix snapshot

**12/13 healthy**, bern offline (SSH timeout — infrastructure, not process).

| Box | Version | ~RSS | Watchdog |
|-----|---------|------|----------|
| utah, utah-8gb | 0.25.0-rc.4 | ~110–210MB | enabled |
| rest (reachable) | 0.24.3 | 130–780MB | enabled |

## Ops notes

- Do **not** use `pkill -f hiverelay` over SSH (kills the SSH session). Prefer `systemctl kill -s SIGKILL hiverelay` + `fuser -k 9100/tcp`.
- If a 0.25 box hangs again with multi-GB RSS and large `storage/db`, re-quarantine db per `docs/CORESTORE7-MIGRATE-RUNBOOK.md`.
- 0.5GB boxes will still be fragile under load; prefer seed-only light plugins.
- Bern needs provider-side recovery (power/network/console).
