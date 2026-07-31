# Fleet plan — 2026-07-31

**Status:** current · **Supersedes:** [FLEET-PLAN-2026-07-28](./FLEET-PLAN-2026-07-28.md) · **Baseline:** canary `v0.25.0-rc.9` · stable `v0.24.3` · hold `v0.24.3`

Signed `v0.25.0-rc.9` (`46d2d7a`) is cut, published, and live on the canary cohort. This note records what shipped on 2026-07-31, what the release pipeline taught us, and what remains.

## What shipped

- **Signed `v0.25.0-rc.9`** — SSH-signed tag on `46d2d7a`, self-verified against `fleet/allowed-signers`. GHCR multi-arch image built, cosign keyless-signed, and smoke-passed (amd64 + arm64, first boot and Umbrel restart persistence). All four npm packages at `next=0.25.0-rc.9`; `latest` untouched.
- **Canary promoted to rc.9** (`fleet/channels.json`). utah and dubai-2gb converged healthily via the gated updater. bern (canary) remains unreachable and cannot pull; utah-0.5gb stays held on `v0.24.3`. amsterdam drifted back to its pinned `v0.24.3` — the convergence mechanism working as designed.
- **Lineage reconciliation** — the rc.9 prep lived on the release branch, so the release workflow's `main`-ancestry gate rejected the tag. An `ours`-strategy merge (#220, zero file changes, mirrors #209 for rc.8) records `46d2d7a` as a `main` ancestor without touching the v1 tree.

## Release pipeline repairs (all merged)

The rc.9 pipeline failed through five distinct layers before completing; each is now fixed permanently:

1. **npm publish by path** — `npm publish "packages/core"` parses as GitHub shorthand and dies on git ssh auth. Fixed with `./` prefix on both lines (#223, #224). rc.9's packages were published manually from the exact tag tree.
2. **`UMBREL_STORE_TOKEN` rotated** — the repo secret was expired; the store checkout had been silently failing since 2026-07-07. Rotated from keyvault; `UMBREL_OFFICIAL_PR_TOKEN` and `ECOSYSTEM_CONSUMER_TOKEN` verified valid.
3. **Store sync tolerance** — `prepare-release.mjs`'s `syncCommunityUmbrelStore` was written against an imagined store layout (npm package, landing page, image-lined README) the real store never had. All optional files are now guarded; unusable checkouts skip honestly (#228, #231).
4. **Dead upstream git dependencies** — `Start9Labs/avahi-sys` and `Start9Labs/jsonpath` were deleted upstream, breaking the start-os v0.3.5.1 `--locked` tools build. Git `insteadOf` rewrites to the `fedimint` mirrors (same branches, same pinned commits, verified) on both lines (#232–#235).
5. **Store validation entrypoint** — the store now has a real `package.json` + `scripts/validate.mjs` (28 dependency-free structural checks: manifest fields, compose `tag@sha256` ↔ manifest version agreement, app_proxy wiring, assets). `npm run validate` now validates instead of ENOENT (store PR #2; skip-guard #236/#237 as fallback).

## Main-line security/reliability ports (merged today)

The v0.25 release line carried fixes `main` had silently reverted or never received; all ported and merged:

- **C-1** `serviceDefaultPeerRole: 'anonymous'` in `config/default.js` + regression test (#213)
- **R-8** fail-closed storage authority reported on `/health` before the disk gate (#214)
- **N-6** AppRegistry `'error'` no longer discarded silently (#216)
- **Dockerfile `patches/`** copied before `npm ci` so audited fixes reach release images (#215)
- **Health watchdog** stack + the installer's stale embedded copy (#218, #221)
- **Unit-suite stream flakes** — hyperswarm hands server-side Noise streams to the consumer with no `'error'` handler: dispatcher now attaches at swarm creation (#219), client teardown window guarded (#227), both on main; pass-1 cherry-picked to the release line (#226)
- **Appliance env wiring** — `HIVERELAY_API_HOST`/`API_PORT`/`HOLESAIL` now read as CLI fallbacks (#225)
- **B-1** `servicesFailOpen` documented and defaulted `false` (#222)
- **Phase 2.2** `quorum-selector` counts operators, not relays (#230)

Open contributor PRs: #191 (poker open-join — request-changes posted, needs rebase onto the control-capability model). #124 closed as already-absorbed.

## Remaining

| # | Item | Kind |
|---|------|------|
| 1 | bern unreachable — canary box cannot pull rc.9 | fleet ops |
| 2 | utah-8gb running rc.4 against its pinned `v0.24.3` target; has not converged | fleet ops |
| 3 | sing-1 at 75% disk — verify/set `maxStorageBytes` | fleet ops |
| 4 | miami crash-looping on the peerit/p2pbuilders OutboxLog namespace registration (repair proven read-only; production write needs a fleet lease) | fleet ops |
| 5 | `swarm.destroy`/`relayDiscovery.destroy` `OPERATION_TIMEOUT` uncaught flake class in unit teardown (issue #217) | code |
| 6 | Phase 1.1 canary-of-one throwaway pre-flight host | infra decision |
| 7 | Per-box `config.regions`/`config.operator` rollout (feeds the #230 operator counting) | fleet ops |
| 8 | v0.25.0 stable promotion — gated on canary soak + the Phase 0/1 evidence, all now in place | decision |

## Lessons encoded

- The exact-head signing authorization ritual works: rc.9's tag is byte-identical to the reviewed head, and every pipeline failure since has been infrastructure, not release content.
- Prerelease evidence runs can be re-dispatched from the release branch (`workflow_dispatch` uses the branch's workflow file) — that is how fixes reached an immutable tag's pipeline.
- The store drift (five layers) is the same honesty-ladder failure as CAPABILITY-AUDIT-0.25: fixtures described an imagined layout, reality was never checked. The store now self-validates on every release.
