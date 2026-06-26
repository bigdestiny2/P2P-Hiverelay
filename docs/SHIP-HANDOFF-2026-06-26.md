# HiveRelay Ship Handoff - 2026-06-26

This is the current ship boundary after the Core3/HiveRelay release-distribution,
security, and data-plane hardening work through PR #139.

## Current Source State

- Branch: `main`
- HEAD inspected: `70e0d8b`
- Commit subject: `security: cap gateway rate-limit buckets (#139)`
- Worktree: clean (`main...origin/main`)
- Package version: `p2p-hiverelay-monorepo@0.20.2`
- Architecture graph: `docs/HIVERELAY-ARCHITECTURE-GRAPH.md` and
  `docs/assets/hiverelay-core3-architecture.svg`

## Verified Green

- PR #139 CI finished green:
  audit, lint, unit, integration, and Bare tests passed.
- Post-merge main Test run: `28254705847` passed.
- Post-merge Docker snapshot publish: `28254705840` passed.
- Recent security hardening merged after the release-helper work:
  - PR #137 `c5314da`: hardened quorum ranking signals.
  - PR #138 `a2e159a`: capped service-router rate-limit buckets.
  - PR #139 `70e0d8b`: capped public gateway rate-limit buckets.
- Local verification during the #139 loop passed:
  `npm test`, `npm run test:unit`, `npm run test:bare`, `npm run lint`,
  `npm run audit:workspace`, `npm audit`, focused gateway and
  release-distribution tests, Docker build/run smoke, SVG XML validation, and
  `git diff --check`.
- Release default probes confirmed:
  - Full releases with no explicit channel resolve to `both`.
  - Prereleases with no explicit channel resolve to `none`.

## Current Red

Release distribution preflight run: `28244297762`.

The run is side-effect-free and is failing on malformed GitHub-hosted release
values, not missing repo code:

- `UMBREL_STORE_TOKEN must be a GitHub token without whitespace or control characters`
- `UMBREL_OFFICIAL_PR_TOKEN must be a GitHub token without whitespace or control characters`
- `UMBREL_OFFICIAL_FORK must be a GitHub owner/umbrel-apps fork slug with a normal owner name and must not be getumbrel/umbrel-apps`
- `STARTOS_REGISTRY_URL must be a public https URL without embedded credentials, query strings, fragments, or reserved/local hostnames`

The same preflight did not report malformed `FLEET_SSH_PRIVATE_KEY` or
`STARTOS_DEVELOPER_KEY_PEM`.

## Repair Path

Create a local env file with the corrected full-release values, then run:

```sh
npm run release:apply-github-secrets -- \
  --repo bigdestiny2/P2P-Hiverelay \
  --env-file /private/tmp/hiverelay-release-secrets.env \
  --dry-run

npm run release:apply-github-secrets -- \
  --repo bigdestiny2/P2P-Hiverelay \
  --env-file /private/tmp/hiverelay-release-secrets.env
```

The helper validates the candidate file with the same full-release preflight
before writing to GitHub. Secret values are sent through `gh secret set` stdin
and are not printed.

After applying the fixed values, rerun:

```sh
gh workflow run release-distribution-preflight.yml \
  --repo bigdestiny2/P2P-Hiverelay \
  -f channel=both \
  -f prerelease=false
```

## Live Ship Sequence

Do not cut a full live release until the distribution preflight passes.

1. Rotate the malformed GitHub values using `release:apply-github-secrets`.
2. Rerun the full-release preflight with `channel=both` and `prerelease=false`.
3. Cut a fresh versioned release through `release-surfaces.yml`.
4. Verify public evidence sidecars:
   `release-evidence.json`, `fleet-rollout-evidence.json`,
   `official-umbrel-pr-evidence.json`, `startos-registry-evidence.json`,
   `release-image-manifest-evidence.json`, and package smoke evidence.
5. For review-ready Umbrel handoff, capture real-device setup/add-wallet/service
   management evidence and run `npm run release:verify-review-ready-handoff`.

## Ship Status

Repo-side release code, UI hardening, release default behavior, and architecture
documentation are ready. Live fleet/store promotion is still externally gated
until the malformed GitHub secret/variable values are corrected and a fresh
passing full-release preflight exists.
