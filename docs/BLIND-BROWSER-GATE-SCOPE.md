# Blind browser verification scope

The RC9 public browser controls are the two artifacts in
`packages/blind-client-public-browser/browser-artifacts/`. The private
`blind-client-control-v1.mjs` predecessor and its manifest/evidence remain
byte-frozen. The public successor generator checks their exact hashes and
records the old generators' exact failure modes as negative compatibility
checks. It must reject unrelated failures and any changed predecessor byte.

The missing RC8 commit `1cebfaad` is not an appropriate whole-commit repair:
it replaces the frozen v1 executable bytes. RC9's public successor closure
instead preserves the earlier predecessor hashes. No artifact regeneration is
needed for the test and CI scope correction documented here.

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
