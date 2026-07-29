# Release runbook — v0.25.0-rc.5 (canary, Track A)

**Prepared:** 2026-07-28 · **Branch:** `feat/service-http-wiring` · **Status:** ready for maintainer signing

Everything up to the signed tag is done. The remaining steps need your signing key
and a push, so they are yours.

---

## 0. What is already prepared

| Item | State |
|------|-------|
| Code fixes + restored features | committed (`2fa58c1`) |
| Doc corrections (pilot hostnames, Ship 9 state) | committed (`aae40ff`) |
| Version bump to `0.25.0-rc.5` + CHANGELOG | committed (`59d2362`) |
| Fleet watchdog / admin operator / stability writeup | committed (`40ea4bf`) |
| `hold` channel added to `channels.json` | committed, pinned at `v0.24.3` |
| `canary` promotion in `channels.json` | **NOT applied** — do it after the tag exists |

Unit suite at time of prep: **3510 tests, 3 known failures** (serve-only recovery
mode; two startup-rollback cases blocked on the Corestore-7 storage-sweep
question). Previously the suite aborted at test 727 on a hard `TypeError`.

---

## 1. Blockers you must clear

### 1a. The branch is not on `main`

Every box resolves its target from
`https://raw.githubusercontent.com/bigdestiny2/P2P-Hiverelay/main/fleet/channels.json`.
Nothing ships until this branch lands on `main`.

```bash
git rev-list --count origin/main..HEAD
```

At prep time this was **124 commits**. Open a PR from `feat/service-http-wiring`
rather than fast-forwarding — `rc.3` was previously cut from `main` by mistake
without the feature tree, and that is exactly the failure this gap invites.

### 1b. Do NOT sign by hand — use `scripts/release.sh`

`git tag -s` defaults to **GPG**, but the fleet verifies **SSH** signatures
(`ssh-ed25519` in `allowed-signers`). A hand-cut GPG tag produces a signature
every enforcing box rejects, and `gpg` will simply fail with "No secret key"
because no GPG key exists here.

The repo ships a keyvault-integrated cutter that does the right thing: sign with
SSH from the vault, **self-verify against `fleet/allowed-signers` before pushing**,
push, and create the GitHub prerelease.

```bash
scripts/release.sh status                    # what is configured
scripts/release.sh cut v0.25.0-rc.5          # sign + verify + push + prerelease
```

Two prerequisites, both currently unmet:

**The vault is locked.** `status` reports
`locked: no agent running for ~/.keyvault/secrets.vault`, and consequently cannot
see the key. Current tooling reports this as `unavailable while vault is locked`;
it never treats a locked vault as proof the key is absent. Unlock first:

```bash
keyvault agent --daemonize
# or run the cut under: keyvault exec --scope hiverelay-release -- scripts/release.sh cut v0.25.0-rc.5
```

**The signer principal does not match `allowed-signers`.** `release.sh` derives
`SIGNER_EMAIL` from `git config user.email`, which is
`33146784+bigdestiny2@users.noreply.github.com`, but the principal in
`fleet/allowed-signers` — and in the copy installed on every enforcing box — is
`bigdestiny2@users.noreply.github.com`, with no numeric prefix. Signing with the
default tags under a principal that is not in the file, so `verify_tag` on miami,
sydney, and amsterdam would refuse the checkout. Override it:

```bash
HIVERELAY_RELEASE_SIGNER_EMAIL=bigdestiny2@users.noreply.github.com \
  scripts/release.sh cut v0.25.0-rc.5
```

`release.sh` self-verifies against `fleet/allowed-signers` before it pushes, so a
principal mismatch fails locally rather than shipping a tag the fleet rejects.

Prior tags *are* signed — `git tag -v v0.24.3` errors only because local
verification is unconfigured, not because a signature is missing:

```bash
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$PWD/fleet/allowed-signers" tag -v v0.24.3
```

### 1c. `main`'s canary channel is parked at v0.24.3

`origin/main:fleet/channels.json` currently reads `canary: v0.24.3` — PR #203
(`ops/canary-hold-after-rc4`) deliberately held it after rc.4. utah is on rc.4
only because it was placed there by hand. Promoting means moving canary forward
from `v0.24.3`, not from `v0.25.0-rc.4`.

### 1d. The pull-based automation is not actually provisioned (read this first)

Surveyed 2026-07-28. The fleet is in three states, and the "boxes self-update
within ~15 min" model in `fleet/README.md` does not currently hold:

| State | Boxes | Agent | Signed-tag gate | Timer |
|-------|-------|-------|-----------------|-------|
| **Provisioned** | miami, sydney, amsterdam | 13796 B (current) | ✅ `verify_tag`, signers installed | active |
| **Stale agent** | utah-us, utah-2gb-a, utah-0.5gb, sing-1, sing-2, dubai | 6799 B (2026-06-22) | ❌ no `verify_tag`, no signers | active |
| **Automation off** | utah, utah-8gb, dallas | stale / none | ❌ | inactive |

Three consequences:

1. **The supply-chain gate is not deployed on 9 of 12 boxes.** The six
   stale-agent boxes would check out *any* tag the channel names, signed or not.
   `fleet/README.md` describes this as fail-closed; that is currently true only
   for miami, sydney, and amsterdam.
2. **utah — the designated canary — has its updater timer off**, so a canary
   promotion would not reach it at all. The only canary box that would move is
   **utah-0.5gb**, the 0.5 GB box that was ABRT-looping under the full plugin
   suite.
3. **sydney is one of the three boxes that WILL enforce the gate.** Pinning it to
   `hold` (§3) is still the right move, but note it is already the strictest box
   in the fleet, not the loosest.

**Recommended order: provision before promoting.** Reinstall the current agent and
allowed-signers on the nine boxes that lack them, and re-enable the timers you
intend to be automatic, *then* cut the tag and bump the channel. Otherwise the
promotion is a no-op on the intended canary and an unverified checkout on six
others.

```bash
# per box, from a workstation with SSH:
ssh root@<box> 'bash -s' < fleet/install-updater.sh <canary|stable>
scp fleet/allowed-signers root@<box>:/etc/hiverelay/allowed-signers
```

---

## 2. Cut the release

From the repo root, with the vault unlocked (§1b). `release.sh` signs, self-verifies
against `fleet/allowed-signers`, pushes the tag, and creates the GitHub prerelease:

```bash
cd /Users/localllm/Projects/pear-ecosystem/00-core/hiverelay && HIVERELAY_RELEASE_SIGNER_EMAIL=bigdestiny2@users.noreply.github.com scripts/release.sh cut v0.25.0-rc.5
```

The tag must be **exactly** `v0.25.0-rc.5` — `release.sh status` cross-checks it
against `package.json`, and the updater's health gate compares the running
version against the tag.

`--promote-canary` also bumps `channels.json`. Do **not** use it here: §1d shows
the canary box is not actually self-updating, so promote deliberately (§4) after
provisioning.

---

## 3. Hold sydney and dallas OFF this rollout

**dallas needs nothing.** It has no `/etc/hiverelay-updater.conf` and no updater
installed, so it is excluded by construction and will not move.

**sydney is `CHANNEL=stable`.** Today that is harmless — this release only bumps
`canary`, and sydney is not a canary box. It becomes load-bearing the moment you
promote `stable`. Pin it now so that promotion cannot sweep it in:

```bash
ssh -i ~/.ssh/cloudzy_hiverelay root@104.194.135.205 'printf "CHANNEL=hold\n" > /etc/hiverelay-updater.conf && cat /etc/hiverelay-updater.conf'
```

Confirm the box resolves the held target rather than a moving one:

```bash
ssh -i ~/.ssh/cloudzy_hiverelay root@104.194.135.205 'hiverelay-updater --dry-run'
```

Both hosts run the Track B blind public-test stack on `:443`. Track A never
touches `:443`, the blind compose, or the blind roots — only the fleet relay on
`:9100` — but keeping them off the rollout entirely is the safer reading of the
`LIVE_PUBLIC_TEST_ONLY` lease.

---

## 4. Promote the canary channel

Only after the signed tag is pushed:

```bash
# fleet/channels.json — canary only; stable stays on v0.24.3
#   "canary": "v0.25.0-rc.4"  ->  "canary": "v0.25.0-rc.5"
git commit -am 'chore(fleet): promote canary to v0.25.0-rc.5' && git push
```

Canary boxes are **utah** and **utah-0.5gb** (and bern, currently down). They
self-update within ~15 minutes on a jittered timer, health-gate, and roll back
automatically if `/health` does not report `running:true` at the target version
within 120s.

Verify convergence against the release tag SHA — not just the package version:

```bash
npm run fleet:check-rollout -- --target v0.25.0-rc.5 --channel canary
```

⚠️ **utah-0.5gb has 0.5 GB RAM.** Per `docs/FLEET-STABILITY-2026-07-27.md` it runs
a trimmed plugin set (`outboxlog`, `notify`, `vrf`) and was ABRT-looping under the
full suite. Watch it specifically after the tick.

---

## 5. Fleet state at prep time

12/13 up. bern is a provider-side outage (SSH + ping dead), not a process fault.

| Box | Channel | Version | Note |
|-----|---------|---------|------|
| utah | canary | 0.25.0-rc.4 | canary target; live onion advertised |
| utah-0.5gb | canary | 0.24.3 | 0.5 GB — trimmed plugins, watch closely |
| utah-8gb | stable | 0.25.0-rc.4 | manually placed after CS7 remigrate |
| utah-us, utah-2gb-a, miami, sing-1, sing-2, amsterdam, dubai | stable | 0.24.3 | |
| **sydney** | stable | 0.24.3 | Track B host — pin to `hold` (§3) |
| **dallas** | *(no updater)* | 0.24.3 | Track B host — excluded by construction |
| bern | canary | — | provider outage; needs console/power |

---

## 6. Do NOT promote `stable` from this runbook

`npm run release:check-blockers` reports the full public-release evidence chain as
open: image manifest, digest-pinned image smoke, Umbrel package smoke, official
Umbrel PR, Umbrel runtime review, StartOS registry, and fleet rollout evidence.
Those gate the *public full release*, not a canary tick. Close them before
`stable` moves off `v0.24.3`.
