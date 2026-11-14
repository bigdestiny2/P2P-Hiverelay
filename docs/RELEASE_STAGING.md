# Staged release contract

Every ordinary tag push, published Release event and release-surfaces dispatch publishes `artifact-v1`. The channel is `none`; a non-none override fails before publication. `prepare-release` also defaults to and requires `none`. Fleet changes use the existing signed channels-only publisher under its separate authority.

Artifact success means exact versioned packages, versioned OCI image, installable packages, smoke proofs and the immutable parent/StartOS child closure are published. It leaves npm `latest`, OCI `latest`, GitHub latest, fleet channels, metadata, consumer defaults, Umbrel stores and StartOS registry pending. npm uses the fixed `next` tag. GA artifact preflight requires the configured StartOS developer signing key because later registry publication must reuse the signed package bytes; RC sideload artifacts retain the optional ephemeral-signing behavior. A reused npm version must match both the SHA-512 integrity and SHA-1 shasum of the exact source tarball before its staging tag is changed. Fresh and reused OCI publication use the version tag only. GitHub creation explicitly passes `--latest=false`; an already published Release with a conflicting latest pointer is refused. Neither phase changes the Release's prerelease flag. RC artifacts remain RC; they cannot be promoted as GA.

The outer release evidence schema remains version 1 to preserve the existing immutable StartOS authority. Its `release.stage` is a separately versioned exact-key contract, shared by the writer, artifact/handoff/closure verifiers and StartOS workflow. It records four ordered package identities, `artifact-v1`, `next`, `githubLatest:false`, the source-verified metadata branch (main or the explicit maintenance branch), the exact deferred surface list and the distinct promotion receipt filename. Successful artifact statuses use `deferred-stable-promotion`, never a successful distribution claim. Historical checkpoints keep their original rules.

## Independent qualification

Stable publication is the explicit tag-dispatched `release-stable-promotion.yml` workflow in protected environment `hiverelay-stable-promotion`. Its entry point is:

```
node scripts/release-stages/promote.mjs --mode promote --bundle-dir <bundle> --allowed-signers <trusted-file>
```

The protected environment must pin `PROMOTION_ALLOWED_SIGNERS`, its exact SHA-256, and `PROMOTION_SIGNER_IDENTITY`. The public trust file and identity are independent of the submitted bundle. Existing release authority may authorize the SSH signature namespace `hiverelay-stable-qualification-v1`; availability and authorization must be established by the conductor. This source change does not install keys, authorize a signer or establish any real qualification.

The bundle contains the unchanged eight artifact files named by `promote.mjs`, plus `release-qualification.json`, its detached `.sig`, and all referenced proof files. References are relative regular files with exact SHA-256, inside the bundle; symlinks and escaped paths fail. JSON and archives have explicit size/inventory bounds. The qualification JSON has exactly:

- `schemaVersion:1`, `kind:"hiverelay-stable-qualification-v1"`, `issuedAt`, `expiresAt`, `producer`, `reviewer`.
- `artifact`: exact version, tag SHA, artifact checkpoint hash, closure hash, image-manifest hash, complete image identity and the four package identities.
- `proofs`: hash-linked `consumers`, `canary`, `fleet`, `inventory`, `inventoryPlan`, `channels`, `rehearsals`, `umbrelRuntimeReview`.
- `distribution`: the reviewed repository plan, official draft PR binding and exact StartOS registry package URL/hash.

The independent reviewer must differ from the producer, sign the exact JSON bytes using the authorized namespace, and set validity to at most 30 minutes. Signing a shape or fixture is not qualification: the reviewer must authenticate actual command outputs, consumer source changes or reviewed no-change receipts, platform/runtime provenance and current release identities. No local unsigned booleans authorize the workflow.

Reference-consumer proof (`hiverelay-reference-consumer-proof-v1`) binds this exact artifact and all of PearBrowser Desktop, PearBrowser and Peerit. Each row includes exact source commit, `changed-source` or `reviewed-no-change`, a hash-bound source receipt, runtime, platform, `execution:"actual-consumer"`, and actual clean-install, seed, gateway, restart, browser-compatibility, migration and rollback checks. Each check retains name, successful exit code, command, completion time and hash-bound raw output.

The signed intended inventory is an explicit complete list of addressed canary/stable relays, using the existing `tailnet`/`publicIp` fields. A hash-bound `inventoryPlan` must account for every relay in the exact tagged `fleet/relays.json`: every name is either intended or has an explicit `hold-not-intended`/`retired` disposition, reason and reviewed receipt. Source and intended addresses must match. The promoter reads the tagged inventory bytes itself. Holds or retired hosts cannot silently disappear from the intended fleet. The fresh fleet proof must cover exactly every intended name, exact source SHA and package/live versions, with all summary and per-host success values. The promoter also invokes the existing SSH rollout verifier against those same inventory/channel bytes before and after publication; proof-file presence cannot replace the live probes. Ambient SSH wrapper overrides are removed. Enabled public-gateway releases additionally require the existing signed manifest, pinned hosts and completed gateway observation-window evidence.

Canary proof (`hiverelay-canary-observation-v1`) binds the same artifact and intended inventory, its own hash-bound historical channel snapshot, start/completion timestamps, a required observation of at least 24 hours, maximum sample gap at most five minutes, and all hash-bound fleet samples covering that window. The window must finish within 30 minutes of promotion. Rehearsal proof (`hiverelay-release-rehearsal-proof-v1`) retains actual restore, device-rebind, rollback, offline-author/fresh-reader and capacity/replica-floor command evidence. The existing real Umbrel runtime-review verifier is mandatory and binds the intended official PR URL.

## Reviewed distribution and promotion

Prepare metadata and consumer defaults with the existing release preparation/synchronization helpers in disposable checkouts. Do not run them in the artifact source checkout. Independently review and sign a complete distribution plan with the qualification:

- Exactly the fixed metadata repository, community store, protected official fork, and every release-managed consumer repository from `audit-ecosystem-consumers.mjs`.
- For each repository: role, repository, fixed branch, exact base commit, expected Git tree SHA, hash-bound index-applicable patch, and the exact changed-file paths and SHA-256 values. An empty patch is represented by a nonempty comment-only patch when the reviewed tree is already current.
- The optional final official PR URL, fixed base/owner/ref, and the original device-review PR URL, exact head SHA and full tree SHA. The original review tree must equal the planned official tree, and a live original PR/commit/content read must prove that exact revision and the artifact image digest. The final fork branch and draft may be newly created; their distinct URL and exact tree equivalence are retained without rewriting the original review evidence.
- The protected HTTPS StartOS registry URL and same-origin download URL, bound to the unchanged artifact package hash.

The promoter clones clean isolated repositories, refuses a moved base, applies only reviewed managed paths, verifies every changed byte and resulting tree before the first push, then uses the existing bounded commit/push publication operations. A fresh official branch uses an absence lease, and an absent final PR is created as a draft from that same reviewed tree. It does not use the old consumer helper's unrestricted `git add -A`. Current matching trees are reused. It reads remote branch heads and official PR state back, publishes the existing StartOS package only when the registry positively reports it absent, then downloads and hashes the registry bytes. A conflicting package or ambiguous readback fails.

Only then does it move npm and OCI `latest` to the already verified versions/digests and set GitHub `make_latest=true`. It never rebuilds the application, runs npm publish, or changes a versioned image during stable promotion. The existing raw OCI index and platform revision verifiers bind the index/children before and after label changes. The artifact closure is authenticated live before and after promotion and all local immutable artifact hashes must remain equal.

Publication is non-atomic. A failure after some pushes or labels may leave a partial public state, and no successful receipt is emitted. Retry the same source and signed plan only while fresh qualification remains valid; every surface is reread. A changed base, conflicting bytes, expired authority or failed subprocess stops the retry. Rollback requires a separately authorized reviewed plan and current proofs; do not edit the artifact checkpoint or casually move immutable tags.

## Final acceptance

`release-stable-promotion-evidence.json` is a distinct versioned receipt containing the artifact/qualification hashes, immutable file inventory, promotion workflow/run attempt, package/index/children identity, hash-bound retained live fleet evidence, distribution results and label readbacks. The workflow retains the receipt and `stable-promotion-fleet-evidence.json` together in an immutable Actions artifact. Public filenames include the exact run and attempt (`release-stable-promotion-RUN-ATTEMPT.json` and `stable-promotion-fleet-RUN-ATTEMPT.json`). Failed or partial attempts therefore remain distinguishable without overwriting sealed evidence. Receipt publication compares and rereads occupied same-attempt bytes; it uploads only missing assets. The artifact closure is unchanged. Download the exact accepted attempt assets into the bundle using the two conventional local filenames before final verification.

```
node scripts/release-stages/promote.mjs --mode verify --bundle-dir <bundle> --allowed-signers <trusted-file>
```

Final verification authenticates the exact successful promotion workflow run, downloads and hashes its immutable Actions artifact, compares the current published receipt, verifies qualification at the recorded operation time, and repeats current closure, package/image/latest, distribution and complete intended-fleet readbacks. Artifact-only receipts cannot clear the full-release blocker. Later promotion replaces the old checkpoint-specific official-PR/registry sidecars with its own authority; real device, distribution, fleet and closure obligations remain mandatory. Existing artifact sidecars are never rewritten with later workflow timestamps.

This source/fixture lane is not artifact publication, real-device acceptance, consumer acceptance, canary acceptance, fleet convergence or full GA acceptance. All actual external actions remain with the conductor's separately authorized gates.
