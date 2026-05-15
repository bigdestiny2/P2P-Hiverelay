# HiveRelay Observatory

Fleet-wide topology + state dashboard. Polls each relay's HTTP endpoints
every 10s and renders a per-relay card view at `/`.

## What it shows

For each relay:
- Up/down (from `/health`), running flag, uptime
- Connected peer count + 12-char pubkey list, with known peers labeled
  (`37cf4bfbdf33 utah-us`) and unknowns flagged
- App count + anchored count (from `/catalog.json`)
- Version (from `/.well-known/hiverelay.json`)
- Operator + region tag
- Any endpoint errors

## Endpoints

- `/` — dashboard HTML
- `/api/state` — current snapshot JSON
- `/api/history` — last N polls (compact derived metrics only)
- `/api/config` — fleet config (relays + poll interval)
- `/healthz` — observatory self-health

## Run locally

```sh
cd tools/observatory
npm start
# open http://localhost:9200
```

## Deploy to Bern (or any observatory host)

```sh
# From repo root, rsync the directory to the target
rsync -a --delete \
  tools/observatory/ \
  root@45.59.123.112:/root/hiverelay-observatory/

# On the target:
ssh root@45.59.123.112 '
  cp /root/hiverelay-observatory/systemd/hiverelay-observatory.service \
     /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable hiverelay-observatory
  systemctl restart hiverelay-observatory
  systemctl is-active hiverelay-observatory
  curl -s http://127.0.0.1:9200/healthz
'
```

Open `http://45.59.123.112:9200/` once UFW (or your firewall) allows
inbound 9200, or tunnel: `ssh -L 9200:127.0.0.1:9200 root@45.59.123.112`.

## Roadmap

- **v0.1**: pull poller, per-relay cards, in-memory history
- **v0.2** (current): live log tail (SSH `tail -F` aggregated → SSE) + filter/auto-scroll panel
- **v0.3**: topology graph (force-directed) showing peer connections
- **v0.4**: custody flow visualizer — driven by `scripts/custody-e2e.js`
- **v1.0**: persistent storage (SQLite), alert hooks, historical queries

## Log streaming setup (v0.2)

Each relay gets a dedicated SSH key authorized to do nothing but
`tail -F /var/log/hiverelay.log`. The observatory spawns one SSH per
relay, parses the output (JSON pino lines + plaintext), filters out
`[status]` clutter, and fans out to SSE subscribers at
`/api/logs/stream`. The dashboard's log panel attaches to that stream.

Bootstrap on each relay (already done for the production fleet, listed
for repro):

```sh
# On the observatory host (Bern):
ssh-keygen -t ed25519 -N "" -f /root/.ssh/observatory_tail \
  -C "observatory-log-tail@bern"

# On each relay, append to /root/.ssh/authorized_keys (one line):
command="tail -n 50 -F /var/log/hiverelay.log",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 <PUBKEY> observatory-log-tail@bern
```

The `command="..."` force-prefix is the security boundary: even if the
private key on Bern leaks, the attacker can only read `/var/log/
hiverelay.log` on each relay. No shell, no port forwarding, no other
files.

Set `OBSERVATORY_LOG_TAIL=false` to disable log tailing (useful when
running locally without the SSH key on disk).

## Env vars

| Var                       | Default                       | Notes                                       |
| ------------------------- | ----------------------------- | ------------------------------------------- |
| `OBSERVATORY_PORT`        | `9200`                        | HTTP listen port                            |
| `OBSERVATORY_POLL_MS`     | `10000`                       | Poll interval per relay                    |
| `OBSERVATORY_HISTORY`     | `360`                         | State-poll history ring size (~1h at 10s) |
| `OBSERVATORY_LOG_TAIL`    | `true`                        | Set `false` to disable log streaming        |
| `OBSERVATORY_TAIL_KEY`    | `/root/.ssh/observatory_tail` | SSH key path                                |
| `OBSERVATORY_LOG_RING`    | `2000`                        | Log-line ring buffer size                   |

## Adding/removing relays

Edit the `RELAYS` array in `server.js`. Each entry needs
`{ id, host, region, operator }`. Restart the service after edit.

## Security note

The observatory only hits **public** relay endpoints (`/health`,
`/peers`, `/status`, `/catalog.json`, `/.well-known/hiverelay.json`).
No API keys are needed and none should be configured here. If we later
want to hit `/api/manage/*` for federation state, keys should be threaded
via per-relay env vars, not committed to source.

The observatory's own HTTP surface is unauthenticated. Don't expose it
to the public internet; bind to localhost + SSH-tunnel, or put it behind
a private reverse proxy.
