# Fleet Tor cohort (host daemon)

**Date:** 2026-07-26  
**HiveRelay version on cohort:** `v0.24.3` (canary held after broken `v0.25.0-rc.1` — see PR #200)

## Live nodes

| Box | Role | Tor daemon | `transports.tor` | Onion (from boot log) |
|-----|------|------------|------------------|------------------------|
| **utah** | canary, 350 GB | 0.4.9.11 | `running: true` | `fspwtbvyjbfihelxqpyu2bdpfu26hsxfm4djrgg4mv6zcmnpbvgpz7id.onion` |
| **utah-8gb** | stable seed, 960 GB | 0.4.9.11 | `running: true` | `fagxjurvyggru4eyjcypkf2btxz37q7yinm3m6zvsk2bytexqgiwgpyd.onion` |

## What was installed (each box)

1. Tor Project apt repo + `tor` **0.4.9.11**
2. `/etc/tor/torrc.d/99-hiverelay.conf` — SOCKS 9050, Control 9051, cookie auth, **no** `HiddenServiceDir`
3. `/root/.hiverelay/config.json` — `transports.tor: true` + cookie/key/roster paths under `/root/.hiverelay/storage/tor/`
4. systemd drop-in `hiverelay.service.d/tor.conf` — `After=tor`, cookie ReadWritePaths

## Enablement note

The Node CLI now translates `HIVERELAY_TOR=1` and the bounded `HIVERELAY_TOR_*`
host/port/key/min-version/roster fields into first-boot defaults. Persisted
`config.transports.tor` and `config.tor.*` still win, so the fleet cohort keeps
its explicit config and verifies readiness from the signed capability document.

## Not in cohort

- **bern** — SSH timed out (45.59.123.112:22)
- Smaller VPS / sydney Blind `:443` stack

## Incident note (canary rc.1)

`v0.25.0-rc.1` crash-looped on canary: missing gateway modules in tag + loader duplicate export + corestore open failure. Canary channel held at **v0.24.3** (PR #200) until a fixed RC.

## Claims

These two relays are **onion-capable utility relays** on clearnet + Tor. Do **not** claim fleet-wide Tor or blind public-test.
