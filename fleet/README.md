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
signed origin/main control commit (changes only fleet/channels.json)
          │ allowed-signer verification + monotonic state/target checks
          ▼
 each box's updater ──▶ signed release tag ──▶ health gate / containment
```

| File | Role |
|---|---|
| `channels.json` | **The control plane.** Target tag per channel; publish only through `fleet:publish-channel`. |
| `relays.json` | Inventory: the boxes, their channel, SSH key, tailnet name. |
| `updater.sh` | The agent. Resolve target → checkout → restart → health-gate → rollback. |
| `updater-launcher.sh` | Stable installed entry point; verifies the checked-out updater belongs to a trusted signed release tag before executing it. |
| `hiverelay-updater.{service,timer}` | systemd units (every 15 min, 5 min jitter). |
| `install-updater.sh` | Install the launcher/units and quarantine helper, bind the node's channel/relay identity/repo path, and preserve the root-only runtime environment. |
| `tailscale-enroll.sh` | Put a box on the tailnet (break-glass plane). |
| `fleet-status.sh` | One-shot health table from your workstation. |
| `scripts/check-fleet-rollout.mjs` | Retry until a channel has checked out the release tag SHA and `/health` is green. |

`updater.sh` is the **automated, fleet-wide** layer. `hiverelay manage`
(the per-node interactive TUI in `packages/core/cli/manage.js`) is the
**manual, single-box** layer. They compose: the timer keeps boxes on
their channel; `manage` is for hands-on tweaks to one node.

## New-root reprovision planning

`plan-reprovision.mjs` is a local, dry-run-only guard for
`hiverelay/fleet-reprovision-plan/v1`. It names exactly one target relay and
fails closed unless the input binds:

- one immutable release artifact, source commit, release sequence, and
  protocol/store/IPC hashes;
- signed, timestamped fleet inventory with operator, host, failure-domain,
  role, storage-generation, admission, clock, retention, capacity, backup, and
  root metadata;
- a zero-unknown retention census, after-drain capacity and replica floors,
  isolated restore proof, and a distinct empty root; and
- a rehearsed D-7 rollback artifact that reads both blind and legacy state
  while the old root remains retained.

The current `relays.json` is discovery metadata, not signed inventory or
observed capacity evidence. Audit that boundary without contacting a relay:

```bash
node fleet/plan-reprovision.mjs \
  --target-relay utah \
  --source-commit "$(git rev-parse HEAD)" \
  --max-inventory-age 900 \
  --out /tmp/hiverelay-reprovision-plan.json \
  --require-ready
```

That command is expected to remain blocked until an immutable RC and the
required operator evidence exist. The planner has no execute, SSH, deploy,
channel, key, root, or fleet mutation mode. Even a blocker-free result only
means ready for independent review and a separate human operation lease; it
does not pass PG-5 or PG-7.

## Signed releases (required)

The updater resolves a channel only from the latest commit on the configured
Git control branch that changed exactly `fleet/channels.json`. That commit must
be signed by a locally allowed signer and contain no other file change. Each
box atomically persists its last accepted control commit and target SHA under
`/var/lib/hiverelay-updater/`; a replayed control head, a newer control commit
pointing to an older/divergent release, or a moved target tag is rejected.

The selected tag must also be annotated and signed by an allowed key before
the updater checks it out and runs it **as root**. A forged tag or mutable raw
HTTP channel response therefore cannot select code. Missing trust, invalid
signatures, and unsafe state all fail closed with the box on its current
version. `HIVERELAY_REQUIRE_SIGNED_TAGS=0` is a loud tag-only break glass; it
does not disable signed control-commit or monotonic-state verification.

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

The root-installed `/usr/local/bin/hiverelay-updater` is a deliberately small
launcher, not a frozen copy of `fleet/updater.sh`. On every tick it requires
the checked-out updater file to match `HEAD` exactly and requires `HEAD` to be
named by an allowed-signer-verified annotated release tag. It then executes
that release's updater. A successful signed checkout therefore supplies the
updater used on the next tick without allowing an unsigned branch or dirty
updater file to become root-executed code.

## Updater runtime environment

The systemd unit requires `/etc/hiverelay/hiverelay-updater.env`. The installer
creates it empty for ordinary relays, sets mode `0600`, and never overwrites
existing contents on reinstall. The file is parsed by systemd as environment
data; neither the launcher nor updater sources it as shell code.

For a relay named in an enabled manifest from the exact trusted target tag,
the gateway gate is mandatory. Origin, connect IP, app key/path, expected
content hash, immutable drive version, TLS fingerprint, active nginx hash, and
admission profile all come from that signed manifest. They are deliberately
not operator environment switches. The node-local environment supplies only
paths and execution details:

```ini
HIVERELAY_PUBLIC_GATEWAY_PROBE_CONFIG=/root/.hiverelay/config.json
HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_CONFIG=/etc/nginx/conf.d/hiverelay-public-apps.conf
HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_BINARY=/usr/sbin/nginx
HIVERELAY_PUBLIC_GATEWAY_PROBE_EVIDENCE=/root/.hiverelay/gateway-evidence/preflight-live.json
HIVERELAY_PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY=0
HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE=/etc/letsencrypt/live/hiverelay-public-apps/fullchain.pem
HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY=/etc/letsencrypt/live/hiverelay-public-apps/privkey.pem
HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT=/etc/letsencrypt
HIVERELAY_PUBLIC_GATEWAY_OPS_SS_BINARY=/usr/sbin/ss
HIVERELAY_PUBLIC_GATEWAY_OPS_EVIDENCE=/root/.hiverelay/gateway-evidence/operator-readiness.json
```

`HIVERELAY_PUBLIC_GATEWAY_PROBE_CA` and a 1–300 second
`HIVERELAY_PUBLIC_GATEWAY_PROBE_TIMEOUT` are optional. The default quarantine
helper is `/usr/local/sbin/hiverelay-quarantine-public-gateway`; its recovery
backup defaults to the active nginx fragment plus `.pre-quarantine`. Override
the command or backup only with reviewed absolute paths. Missing cohort paths
fail closed rather than changing the node into an ordinary relay.

The five `OPS_*` paths are required only when the verified cohort entry names
`deploymentProfile: public-t1-gateway` and carries its canonical operator
contract digest. They cannot opt a relay into or out of the profile. Each tick
runs live DNS, every-address Web-PKI TLS/SPKI, loopback listener, exact finite
config, and signed-contract checks, including empty CNAME/HTTPS/SVCB routing,
no UDP/QUIC listener on port 443, and protocol/metadata/validity binding for
each per-address content probe. A failure poisons both evidence files and
quarantines only the public nginx edge. Legacy/noncohort relays do not run the
ops scripts. Keep certificate/key paths inside the reviewed certificate root
and keep the key and updater environment root-only.

HTTPS/SVCB checks cover both the admitted app and wildcard witness through the
built-in raw UDP resolver with strict query validation and bounded TC-to-TCP
fallback; RCODE, malformed, transport, and timeout failures never become an
empty RRset. The public app/default/quarantine vhosts explicitly disable gzip
and gunzip even when a stock parent enables gzip, strip upstream
`Accept-Encoding`, disable request access logs, and route only critical errors
to stderr. Fresh pinned-image `nginx -T` proof remains an external activation
gate when Docker is unavailable.

Public-T1 activation also waits for two storage invariants: persisted
`storageProvedDriveVersion` must authorize every RelayNode HTTP checkout, and
SeedingRegistry must be bounded or explicitly disabled for this profile while
direct single-app seeding remains. Missing proof/lease is unavailable and must
not open, update, or fetch a drive.

```bash
sudoedit /etc/hiverelay/hiverelay-updater.env
sudo chmod 0600 /etc/hiverelay/hiverelay-updater.env

# Exercise the same environment and entry point as the timer immediately.
sudo systemctl start hiverelay-updater.service
sudo journalctl -u hiverelay-updater.service -n 50 --no-pager
```

Keep `HIVERELAY_API_KEY` only in the relay's existing
`/etc/hiverelay/hiverelay.env`; the updater reads it there for authenticated
health probes. Do not duplicate it in the updater environment.

### Identity bootstrap before an enabled gateway manifest

Do not introduce this updater and the first enabled public-gateway manifest in
one release. Existing nodes initially lack `RELAY_NAME`, and the updater from
the release they are leaving cannot enforce policy that only exists in the
release they are entering.

First publish a trusted signed release whose canonical gateway manifest is
missing or explicitly disabled. Re-run `install-updater.sh <channel>
<exact-relay-name>` on every raw fleet node, confirm its config contains the
correct identity, and exercise the systemd unit. Only a later signed release
may enable a reviewed cohort. This bootstrap release remains an ordinary
API-health rollout; it does not authorize public HTTPS.

The disabled bootstrap must already carry the exact five-file quarantine
authority: `fleet/quarantine-public-gateway.sh`, its verifier, and the three
local verifier libraries. Enabled publication requires those five files plus
`fleet/updater.sh` to be tracked with exact modes and blob-identical in the
target and trusted signed predecessor. The updater freezes the five current-
release files and byte-compares the installed helper before execution.

## Releasing

Cut a signed release as usual; an unsigned tag is refused by every box. Publish
each channel only through `fleet:publish-channel` from a completely clean,
attached `main` that exactly matches `origin/main`. Its default is validation-
only: it does not change the control worktree, refs, or remotes. Review that
output, then repeat the same arguments with explicit
`--publish`; it signs and verifies a commit changing only `channels.json`,
checks the remote again, and performs one atomic compare-and-swap publication
with exact branch/tag leases. It sends only the validated release-tag object
and signed channel commit; unrelated refs and unguarded force updates are off.

For a legacy/non-gateway release:

```bash
export HIVE_RELEASE_TARGET=vX.Y.Z
export HIVE_ALLOWED_SIGNERS="$HOME/.config/hiverelay/allowed-signers"
export HIVE_CANARY_EVIDENCE="$HOME/.hiverelay/fleet-evidence/${HIVE_RELEASE_TARGET}-canary.json"
install -d -m 0700 "$(dirname "$HIVE_CANARY_EVIDENCE")"

# Canary validation, then explicit publication.
npm run fleet:publish-channel -- --channel canary \
  --target "$HIVE_RELEASE_TARGET" --allowed-signers "$HIVE_ALLOWED_SIGNERS"
npm run fleet:publish-channel -- --channel canary \
  --target "$HIVE_RELEASE_TARGET" --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --publish

npm run fleet:check-rollout -- --target "$HIVE_RELEASE_TARGET" \
  --channel canary --evidence "$HIVE_CANARY_EVIDENCE"

# Stable remains a separate explicit decision: validate, then publish.
npm run fleet:publish-channel -- --channel stable \
  --target "$HIVE_RELEASE_TARGET" --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --canary-evidence "$HIVE_CANARY_EVIDENCE"
npm run fleet:publish-channel -- --channel stable \
  --target "$HIVE_RELEASE_TARGET" --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --canary-evidence "$HIVE_CANARY_EVIDENCE" --publish
```

This checks the exact release tag SHA and `/health`, not only the package
version. An enabled public-gateway release automatically adds its signed cohort
and observation gates; use the full publisher, checker, and observer sequence
in `docs/PUBLIC-HIVE-GATEWAY-CANARY-RUNBOOK.md`.

For a quick table without waiting for convergence, run:

```bash
bash fleet/fleet-status.sh
```

To **hold** a box, point its channel at the version it already runs. To
**roll a whole channel back**, use an explicit reviewed recovery procedure;
the automatic updater deliberately rejects an older or divergent target even
when a newer channel commit is signed. A future automated rollback path needs
its own signed authorization schema rather than overloading normal promotion.

## Safety properties

- **Health-gated:** after restart the agent polls `/health` for
  `running:true` and a runtime `version` matching the target tag (120s). No
  green -> automatic rollback to the prior SHA.
- **Signed-tag gate (fail closed):** the agent refuses to check out any tag
  that is not signed by a key in `/etc/hiverelay/allowed-signers`. A moved or
  forged tag is rejected before checkout; the box stays on its current
  version. See "Signed releases" above and `docs/SUPPLY-CHAIN.md`.
- **Signed monotonic channel control:** raw HTTP is not channel authority. The
  agent accepts `fleet/channels.json` only from an allowed-signer-verified,
  single-parent commit changing exactly that file. Root-private atomic state
  rejects control replay and release-target downgrade/divergence.
- **Dirty-tree guard:** the agent refuses to act if the repo has
  uncommitted changes — it never clobbers a hand-edit.
- **Config treated as data:** `/etc/hiverelay-updater.conf` stores validated
  `CHANNEL=`, mandatory `RELAY_NAME=`, and `REPO_DIR=` values. The
  launcher/updater parse the values as data and never source the file as
  shell. `RELAY_NAME` must match the exact `fleet/relays.json` identity.
- **Runtime environment survives reinstall:** gateway probe settings live in
  the required, root-only `/etc/hiverelay/hiverelay-updater.env`; the installer
  preserves its bytes across idempotent reinstalls.
- **Updater code advances safely:** the installed launcher verifies both the
  updater blob and current signed release tag before executing checkout code.
- **Signed gateway membership is not optional:** after target-tag trust is
  established, the updater normalizes the manifest from that exact commit.
  Named cohort nodes must run the live preflight and a second standalone
  verifier bound to every signed node expectation. Missing manifest/disabled
  and noncohort nodes retain the ordinary API health path.
- **Same-release containment:** if a known cohort node fails while already on
  the target, the updater atomically replaces stale evidence with an invalid
  tombstone and swaps only the public-app nginx fragment for a TLS `421`
  reject. It does not stop or restart the separate management API. Recovery is
  documented in the public gateway canary runbook.
- **Failed public-T1 transition containment:** before rolling management code
  back from a failed new target, the updater invalidates both target evidence
  artifacts and quarantines public HTTPS. A healthy prior management service
  does not reopen or claim the prior public edge; that requires refreshed
  prior-release manifest/config/nginx/DNS/TLS/SPKI/socket/content evidence.
- **Frozen retirement authority:** before a public-T1 retirement checkout, the
  updater materializes the quarantine helper, verifier, and complete local
  import closure from the exact current SHA. Target-tree bytes cannot judge
  whether the old edge was contained, and an old installed helper fails exact
  byte identity before execution.
- **Trusted containment executables:** quarantine and nginx must be stable,
  owner-trusted, executable, single-link regular files whose lexical paths
  equal their physical canonical paths under a non-writable ancestor chain.
  Launcher, updater, verifier, and helper reject intermediate ancestor
  symlinks. Rejection diagnostics are emitted without ever running untrusted
  helper bytes.
- **Single-flight:** the production service creates a root-only
  `/run/hiverelay-updater` runtime directory and locks its directory descriptor
  with the trusted `/usr/bin/flock`; overlapping ticks cannot collide and there
  is no unlocked fallback.
- **Jittered:** boxes update on randomized offsets — no thundering herd
  on GitHub and no fleet-wide simultaneous restart.
- **Release proof:** when `FLEET_SSH_PRIVATE_KEY` is configured in CI, the
  release workflow waits after channel promotion until every target-channel
  relay has checked out the release tag commit, reports the release package
  version, and reports healthy. It also writes `fleet-rollout-evidence.json`,
  a public-safe per-relay summary that omits SSH hosts and keys.
- **Deps only when needed:** `npm ci` (never `npm install`) runs only if
  `package-lock.json` changed between tags. The updater then re-hashes every
  tracked file against Git, on both target and rollback paths, before restart.
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
# First check out an allowed-signer-verified release tag. The installed
# launcher intentionally refuses an unsigned branch checkout.
sudo bash fleet/tailscale-enroll.sh
sudo bash fleet/install-updater.sh canary utah   # on utah
sudo bash fleet/install-updater.sh stable sing-1 # on sing-1
sudo systemctl start hiverelay-updater.service # exercise the real unit/env now
```

Repeat on each box with its configured channel and exact name from
`fleet/relays.json`; the second argument is mandatory.

`channels.json` ships with `stable: v0.20.1` and `canary: v0.20.1`, so
installing the agent on a box already at the current release is a
**no-op** until you promote the channel to a newer tag.
