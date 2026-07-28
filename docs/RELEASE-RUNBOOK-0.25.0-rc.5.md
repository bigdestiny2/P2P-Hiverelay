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

### 1b. No signing key is configured

The updater refuses any tag that is not an annotated tag signed by a key in
`/etc/hiverelay/allowed-signers`. It fails closed: a box that cannot verify the
tag stays on its current version. This repo currently has no signing config:

```bash
git config --get user.signingkey   # empty
git config --get gpg.format        # empty
git config --get tag.gpgsign       # empty
```

Configure it, then tag. **An unsigned tag is refused by every box.**

---

## 2. Cut the release

```bash
git tag -s v0.25.0-rc.5 -m "v0.25.0-rc.5 — restore orphaned lifecycle/gateway features"
```

Verify before pushing — this is the exact check each box performs:

```bash
git tag -v v0.25.0-rc.5
```

Then:

```bash
git push origin v0.25.0-rc.5
```

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
