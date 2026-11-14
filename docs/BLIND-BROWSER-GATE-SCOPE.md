# Blind browser verification scope

The public browser controls retain the RC9 v1 API in the two artifacts in
`packages/blind-client-public-browser/browser-artifacts/`. The private
`blind-client-control-v1.mjs` predecessor and its manifest/evidence remain
byte-frozen. The public successor generator checks their exact hashes and
records the old generators' exact failure modes as negative compatibility
checks. It must reject unrelated failures and any changed predecessor byte.

The missing RC8 commit `1cebfaad` is not an appropriate whole-commit repair:
it replaces the frozen v1 executable bytes. RC9's public successor closure
instead preserves the earlier predecessor hashes.

## Upstream-refresh evidence revision

The November 2026 dependency refresh uses build metadata and observation
schemas V2. This is an evidence-format revision, not a browser API or wire
protocol revision: the two exported v1 executable artifacts remain byte-for-byte
identical to RC9. Current root manifests are inputs to the successor closure;
they are not required to remain the RC9 dependency graph.

The exact RC9 root manifests, public artifact authority, producer scripts,
artifacts, manifests and observations are archived under
`packages/blind-client-public-browser/predecessors/rc9/`. Its pinned
`reference.json` records commit `d96389fad63f522b429ba182a3adc4d632ab150f`,
tree `ee3ea9c9f6f1622df508ab63ffb20db6d2a652e3`, and every original path,
byte length and SHA-256. Verification rejects changed or missing snapshot
bytes. Historical V1 observations cannot qualify V2 manifests. All private
v1/v2/v3 predecessor files and exact negative-check requirements remain frozen.

The successor closure binds both current root manifests, the exact storage 3.4
migration patch and installer, the current browser authority and evidence
producers, and the normalized browser dependency graphs. Its accepted source
base is commit `1e1466d3ed486b4d6fc68abccb9a8375873af626`; it does not assert
that a later commit or whole repository tree has already been accepted.
The final candidate identity still needs the external postcommit sequence.

The V2 host producer pins the available macOS arm64 Node 22.23.4 executable
and matching headers. This records the runtime actually observed; it is not a
claim to use the newest Node release. Chromium is the pinned Chrome for Testing
151.0.7922.34. The separate clean-install proof uses the pinned Linux arm64
container image and its actual Node 22.23.1 runtime. These are local browser
and cross-OS container observations, not independent physical-host or deployed
fleet qualification. They preserve `releaseReady: false` and
`standaloneAuthority: false`.

## Current gates

The `blind-sdk-tests` CI job runs these complementary checks:

1. Private client artifact verification, malformed/substituted artifact rejection,
   the exact predecessor regeneration failure, and current descriptor masks.
2. Public browser contract and behavior tests.
3. `blind-protocol-v1-compatibility-floor.test.js`, which rejects any changed
   frozen protocol, predecessor artifact, manifest or evidence hash.
4. The public successor generator with
   `--check --ci-structural-only --require-release-evidence`: deterministic
   current-source builds, normalized graphs, committed artifact/manifest equality,
   frozen predecessor hashes and exact existing evidence bindings.
5. The public successor Chromium runner with `--ci-functional-only`, executing
   both committed artifacts in a real browser under the required CSP.

CI structural and functional modes remain non-authoritative verification
signals. They do not write release evidence or establish production readiness.
The canonical host-mode Chromium and cross-host runners remain the evidence
producers; their exact runtime, container, environment and source bindings still
apply. An integration that changes an input in the public source closure must
regenerate the affected manifests and rerun those producers. An unchanged
executable alone is insufficient to reuse evidence after a closure change.

## Historical commands

`npm run verify:blind-specs` still performs the protocol/document/IPC consistency
checks and then invokes the old private v1 generator. On RC9 the preceding checks
pass, and that final generator must fail with exactly:

```text
generated browser artifact drift: packages/blind-client/browser-artifacts/blind-client-control-v1.mjs
```

This command is not used by the current CI or release-surfaces workflow. Its
failure must not be reported as a failure to reproduce the active public
browser artifacts, nor should its success be manufactured by replacing frozen
bytes. The historical `verify-blind-vnext-successor-v3.mjs` gate also targets
the preserved private successor lineage; it is not the RC9 public-browser gate.

The old npm commands and frozen generator files remain unchanged because they
are themselves inputs to the accepted successor preservation contract. Use the
current gates above for RC9, while retaining these historical results explicitly
in an audit or handoff. None of these browser checks qualifies daemon storage,
relay deployment, consumer migration or fleet convergence.
