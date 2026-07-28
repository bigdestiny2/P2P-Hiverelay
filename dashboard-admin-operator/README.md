# Dashboard Admin Operator

Operator-facing **HiveRelay fleet control plane** — live health, feature matrix, restart / update / doctor, feature toggles, and inventory management.

This is the manage UI used for day-to-day fleet ops (not the public `dashboard/` pages or the static status HTML).

## Quick start

From the monorepo root:

```bash
npm run dashboard:admin-operator
```

Open **http://localhost:3458/**

Faster probes while debugging:

```bash
npm run dashboard:admin-operator:dev
```

## What it does

| Capability | How |
|---|---|
| Live fleet matrix | SSH probe → `/status` + `/health` every 60s (SSE) |
| **Healthy ranges** | Policy by tier (small/medium/large): mem, disk, swap, watchdog |
| **Auto-control** | After each probe: force-restart hung/degraded, doctor disk, ensure swap/watchdog |
| Restart / update / doctor | Per-node manual actions |
| Feature toggles | DHT WS, outboxlog, forward relay, services, eviction, … |
| Stabilize all | Install local health watchdog + swap on every reachable box |
| Add / remove relays | Writes inventory JSON |

### Control APIs

| Endpoint | Purpose |
|---|---|
| `GET /api/control` | Policy + last control cycle |
| `POST /api/control` | `{ "autoControl": true/false }` |
| `POST /api/control/run` | Run evaluation + remediation now |
| `POST /api/control/stabilize-all` | Baseline all reachable nodes |

Policy file: `control-policy.json` (cooldowns, tier limits, auto on/off).

## Inventory

Default fleet directory: `../fleet` (repo `fleet/`).

Resolution order for the relays file:

1. `HIVERELAY_FLEET_INVENTORY` — explicit path  
2. `fleet/relays.local.json` — **preferred** (local SSH key paths; usually gitignored)  
3. `fleet/relays.json` — committed template  

Channels: `fleet/channels.json` (`stable` / `canary` tags).

### Env

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `3458` | HTTP listen port |
| `FLEET_INTERVAL` | `60` | Probe interval (seconds) |
| `HIVERELAY_FLEET_DIR` | `<repo>/fleet` | Fleet directory |
| `HIVERELAY_FLEET_INVENTORY` | *(auto)* | Override relays JSON path |

Example with an explicit inventory:

```bash
HIVERELAY_FLEET_INVENTORY=./fleet/relays.local.json \
  npm run dashboard:admin-operator
```

## Layout

```
dashboard-admin-operator/
  server.cjs          # HTTP + SSE + SSH probe/actions
  public/
    index.html        # shell
    app.js            # UI (table, KPIs, actions)
    styles.css
  README.md
```

## SSH keys

Each inventory entry needs a working `sshKey` for that host, e.g.:

- `utah`, `dubai` → `~/.ssh/id_ed25519`
- other cloudzy boxes → `~/.ssh/cloudzy_hiverelay` (or `~/.ssh/hiverelay_fleet` symlink)

Without the right key the node shows **degraded** / **offline** even if the process is healthy.

## Relation to other dashboards

| Surface | Role |
|---|---|
| **`dashboard-admin-operator/`** | This — manage + control the fleet |
| `dashboard/` | Public product UI (catalog, network, …) |
| `docs/html/FLEET-OPS-LIVE.html` | Static snapshot status page |
| `scripts/local-fleet-dashboard.mjs` | Proxied single-relay `/dashboard` with API key |

## Security note

This server runs **locally** and executes SSH as your user against the fleet. Do not expose port `3458` to the public internet.
