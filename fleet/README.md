# Fleet management

Tooling for the **raw systemd fleet** — the relay boxes we operate
directly (utah, utah-us, utah-8gb, sing-1, sing-2, bern, dubai). The Umbrel and StartOS
packaged relays auto-update through their own registries and are *not*
managed here.

It exists because hand-SSHing five boxes from one laptop is fragile: a
stale `known_hosts` entry looks identical to "we lost a server" (it cost
us a false bern alarm on 2026-06-16), versions drift silently, and none
of it scales to community-operated home boxes. So the fleet manages
itself.

## Model: pull, not push

Each box runs a small **`hiverelay-updater`** agent on a systemd timer.
There is no orchestrator and no inbound SSH in the steady state — every
box owns its own lifecycle, which also means this works behind NAT and
for boxes we don't control.

```
fleet/channels.json   ──(raw.githubusercontent)──▶  each box's updater
   stable: v0.15.6                                   reads its channel,
   canary: v0.16.3                                   checks out the tag,
                                                      health-gates, and
                                                      rolls back on failure
```

| File | Role |
|---|---|
| `channels.json` | **The control plane.** Target tag per channel. Edit + commit to release. |
| `relays.json` | Inventory: the boxes, their channel, SSH key, tailnet name. |
| `updater.sh` | The agent. Resolve target → checkout → restart → health-gate → rollback. |
| `hiverelay-updater.{service,timer}` | systemd units (every 15 min, 5 min jitter). |
| `install-updater.sh` | Install the agent on a box, set its channel. |
| `tailscale-enroll.sh` | Put a box on the tailnet (break-glass plane). |
| `fleet-status.sh` | One-shot health table from your workstation. |

`updater.sh` is the **automated, fleet-wide** layer. `hiverelay manage`
(the per-node interactive TUI in `packages/core/cli/manage.js`) is the
**manual, single-box** layer. They compose: the timer keeps boxes on
their channel; `manage` is for hands-on tweaks to one node.

## Releasing

1. Cut a release as usual (tag `vX.Y.Z`, CI publishes the image).
2. **Canary:** bump `canary` in `channels.json`, commit. The canary box
   (utah) self-updates within ~15 min, health-gates, rolls back if bad.
3. **Verify:** `bash fleet/fleet-status.sh` — confirm the canary is on
   the new version and green.
4. **Promote:** bump `stable` to the same tag, commit. The stable boxes
   follow on their next tick.

To **hold** a box, point its channel at the version it already runs. To
**roll the whole channel back**, set the tag back — boxes check out the
older tag exactly like a forward update (health-gated the same way).

## Safety properties

- **Health-gated:** after restart the agent polls `/health` for
  `running:true` (120s). No green → automatic rollback to the prior SHA.
- **Dirty-tree guard:** the agent refuses to act if the repo has
  uncommitted changes — it never clobbers a hand-edit.
- **Single-flight:** `flock`; overlapping ticks can't collide.
- **Jittered:** boxes update on randomized offsets — no thundering herd
  on GitHub and no fleet-wide simultaneous restart.
- **Deps only when needed:** `npm ci` runs only if `package-lock.json`
  changed between the old and new tag.
- **No update bloat:** repeated updates can't grow the box. After a
  green update the agent packs loose git objects (`git gc`, plain, only
  when >512M free, never on rollback). `npm` cache is content-addressed
  and self-limiting (~0.5M); `node_modules` is replaced in place, not
  accumulated. The real footprint risk is logs, bounded separately:
  `harden-box.sh` (run by `install-updater.sh`) caps journald at 200M
  (1G keep-free) and logrotates `/var/log/hiverelay.log`. *Tracked
  follow-up:* the 5s status-line `process.stdout.write` in
  `packages/core/cli/index.js` is the log-volume driver — quieting it at
  the source (TTY-gate + 60s structured log) ships with the next version
  bump; until then the cap + rotation are the guarantee.

## Break-glass: Tailscale

SSH stays for hands-on work, but over the tailnet so it never depends on
local `known_hosts` or key distribution again (the bern failure mode):

```bash
sudo bash fleet/tailscale-enroll.sh        # interactive login, or export TS_AUTHKEY
```

Then add the printed tailnet name to the box's `tailnet` field in
`relays.json`. `fleet-status.sh` and any manual SSH prefer the tailnet
name automatically.

## First rollout (one-time)

```bash
# On each box (repo already cloned at ~/hiverelay):
sudo bash fleet/tailscale-enroll.sh
sudo bash fleet/install-updater.sh canary   # utah
sudo bash fleet/install-updater.sh stable   # the other four
hiverelay-updater --dry-run                  # confirm the decision, no changes
```

`channels.json` ships with `stable: v0.15.6` (the fleet's current
version) so installing the agent on a stable box is a **no-op** until you
promote — installation is safe. Set `canary: v0.16.3` lets utah move
first.
