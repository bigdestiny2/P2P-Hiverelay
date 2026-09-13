# Private intent source and retained artifact lint boundary

The root `npm run lint` command continues to use the existing Standard rules.
First-party private intent sources and tests remain in that check. Bare process
fixtures and browser-evaluated fixtures declare only their actual runtime globals
in file-local comments. These comments do not create or change runtime values.

Six exact files are excluded to preserve previously accepted, byte-pinned runtime
and compiler artifacts:

| Source artifact | Corresponding pinned Pear consumer copy |
| --- | --- |
| `packages/blind-intent-store-bare/runtime.js` | `packages/blind-intent-pear-consumer/vendor/blind-intent-store-bare/runtime.js` |
| `packages/blind-intent-store-bare/native/flags-darwin-arm64.cjs` | `packages/blind-intent-pear-consumer/vendor/blind-intent-store-bare/native/flags-darwin-arm64.cjs` |
| `packages/blind-intent-store-bare/native/flags-linux-x64.cjs` | `packages/blind-intent-pear-consumer/vendor/blind-intent-store-bare/native/flags-linux-x64.cjs` |

`packages/blind-intent-pear-consumer/vendor/source-manifest.json` records the
source and copied file hashes. Both copies of each artifact retain those hashes.
The native target tests also require the accepted compiler artifact bytes and
reject incompatible runtime targets or attempts to overwrite different retained
artifacts. The runtime adapter is pinned by that consumer manifest; its Bare
global declarations cannot be inserted without changing the accepted bytes.

These are exact-file exclusions, not directory patterns. New source, tests,
runtime successors or vendor additions do not inherit an exclusion. Updating an
accepted artifact requires a separately versioned and independently qualified
successor; do not run a formatter over these files or regenerate their accepted
manifests merely to satisfy lint.

The first-party browser backend changes only its lint declaration for native
IndexedDB globals. Two browser test expressions retain their intent: the wrong-origin check
returns its failure marker only if construction unexpectedly succeeds,
and `Object('valid')` supplies the same boxed-string invalid input as
`new String('valid')`. The remaining first-party corrections change formatting
or declare globals. Runtime tests remain necessary for component qualification.

This lint reconciliation changes no dependency, package version, protocol,
default production selector or accepted checkpoint source binding. Passing this
gate does not qualify publication, immutable images, full 0.27 or fleet rollout.
