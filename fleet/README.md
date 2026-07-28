# Fleet management

Tooling for the **raw systemd fleet** — the relay boxes we operate
directly (utah, utah-us, utah-2gb-a, utah-0.5gb, utah-8gb, sing-1, sing-2, bern, dubai). The Umbrel and StartOS
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
   stable: v0.20.1                                   reads its channel,
   canary: v0.20.1                                   checks out the tag,
                                                      health-gates, and
                                                      rolls back on failure
```

| File | Role |
|---|---|
| `channels.json` | **The control plane.** Target tag per channel. Edit + commit to release. |
| `relays.json` | Inventory: the boxes, their channel, SSH key, tailnet name. |
| `relays.local.json` | Local inventory with real SSH key paths (gitignored). Preferred by Admin Operator. |
| `../dashboard-admin-operator/` | **Dashboard Admin Operator** — live manage UI (`npm run dashboard:admin-operator`). |
| `health-watchdog.sh` + `hiverelay-health-watchdog.{service,timer}` | Local timer: if `/health` fails twice, SIGKILL+restart (fixes event-loop hangs systemd cannot see). |
| `install-health-watchdog.sh` | Install the timer on a box (`ssh root@box 'bash -s' < fleet/install-health-watchdog.sh`). |
| `updater.sh` | The agent. Resolve target → checkout → restart → health-gate → rollback. |
| `hiverelay-updater.{service,timer}` | systemd units (every 15 min, 5 min jitter). |
| `install-updater.sh` | Install the agent on a box, set its channel. |
| `tailscale-enroll.sh` | Put a box on the tailnet (break-glass plane). |
| `fleet-status.sh` | One-shot health table from your workstation. |
| `scripts/check-fleet-rollout.mjs` | Retry until a channel has checked out the release tag SHA and `/health` is green. |

`updater.sh` is the **automated, fleet-wide** layer. `hiverelay manage`
(the per-node interactive TUI in `packages/core/cli/manage.js`) is the
**manual, single-box** layer. They compose: the timer keeps boxes on
their channel; `manage` is for hands-on tweaks to one node.

## Signed releases (required)

The updater checks out a channel-named tag it resolves over the network and
runs it **as root**. It refuses to check out any tag that is not an annotated
tag signed by a key in a locally provisioned allowed-signers file — a moved or
forged tag (repo, GitHub-account, CDN, or CA MITM) is rejected and the box
stays on its current version. This is fail-closed: a missing allowed-signers
file or an untrusted signer both abort the update.

One-time setup (maintainer + one file per box) is documented in
[`docs/SUPPLY-CHAIN.md`](../docs/SUPPLY-CHAIN.md#1-signed-release-tags-hr-dis-003--required-operator-setup).
In short:

- Maintainer: sign release tags (`git tag -s vX.Y.Z`) with a dedicated SSH (or
  GPG) key, and publish the public half in an `allowed-signers` file.
- Each box: install it at `/etc/hiverelay/allowed-signers` (override with
  `HIVERELAY_ALLOWED_SIGNERS`).

Audit a tag by hand: `hiverelay-updater --verify-only vX.Y.Z` (exit 0 =
trusted). Break-glass override: `HIVERELAY_REQUIRE_SIGNED_TAGS=0` (loud, never
standing).

## Releasing

1. Cut a release as usual (**signed** tag `git tag -s vX.Y.Z`, CI publishes and
   cosign-signs the image). An unsigned tag will be refused by every box.
2. **Canary:** bump `canary` in `channels.json`, commit. The canary box
   (utah) self-updates within ~15 min, health-gates, rolls back if bad.
3. **Verify:** `npm run fleet:check-rollout -- --target vX.Y.Z --channel canary`
   from a workstation with SSH access. This checks the exact release tag SHA,
   not just the package version, and requires `/health` `running:true`.
4. **Promote:** bump `stable` to the same tag, commit. The stable boxes
   follow on their next tick.

For a quick table without waiting for convergence, run:

```bash
bash fleet/fleet-status.sh
```

To **hold** a box, point its channel at the version it already runs. To
**roll the whole channel back**, set the tag back — boxes check out the
older tag exactly like a forward update (health-gated the same way).

## Safety properties

- **Health-gated:** after restart the agent polls `/health` for
  `running:true` and a runtime `version` matching the target tag (120s). No
  green -> automatic rollback to the prior SHA.
- **Signed-tag gate (fail closed):** the agent refuses to check out any tag
  that is not signed by a key in `/etc/hiverelay/allowed-signers`. A moved or
  forged tag is rejected before checkout; the box stays on its current
  version. See "Signed releases" above and `docs/SUPPLY-CHAIN.md`.
- **Dirty-tree guard:** the agent refuses to act if the repo has
  uncommitted changes — it never clobbers a hand-edit.
- **Config treated as data:** `/etc/hiverelay-updater.conf` is parsed for a
  single validated `CHANNEL=` value; the updater does not source it as shell.
- **Single-flight:** `flock`; overlapping ticks can't collide.
- **Jittered:** boxes update on randomized offsets — no thundering herd
  on GitHub and no fleet-wide simultaneous restart.
- **Release proof:** when `FLEET_SSH_PRIVATE_KEY` is configured in CI, the
  release workflow waits after channel promotion until every target-channel
  relay has checked out the release tag commit, reports the release package
  version, and reports healthy. It also writes `fleet-rollout-evidence.json`,
  a public-safe per-relay summary that omits SSH hosts and keys.
- **Deps only when needed:** `npm ci` runs only if `package-lock.json`
  changed between the old and new tag.
- **No update bloat:** repeated updates can't grow the box. After a
  green update the agent packs loose git objects (`git gc`, plain, only
  when >512M free, never on rollback). `npm` cache is content-addressed
  and self-limiting (~0.5M); `node_modules` is replaced in place, not
  accumulated. The real footprint risk is logs, bounded separately:
  `harden-box.sh` (run by `install-updater.sh`) caps journald at 100M
  (1G keep-free) and logrotates `/var/log/hiverelay.log`. The interactive
  5s status bar is TTY-gated in `packages/core/cli/index.js`; service
  runs emit one structured `relay status` log per minute instead.

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

`channels.json` ships with `stable: v0.20.1` and `canary: v0.20.1`, so
installing the agent on a box already at the current release is a
**no-op** until you promote the channel to a newer tag.
