# Private intent integration runtime

This test-only package locks standalone Bare and bare-runtime 1.31.0 independently
of the current root Bare cohort. It is not a workspace or a product dependency.
The private intent backend and Pear consumer retain their own unchanged locks,
native target bindings and packaged Pear runtime.

From a fresh source checkout, run `npm ci`, then
`npm run test:integration:prepare`, then `npm run test:integration` (or `npm test`).
Preparation installs all three own locks with lifecycle scripts disabled. The
runner preflights the actual standalone runtime and executes both private suites
through their existing package test commands, separately from ordinary root
Brittle tests. `--list` remains the complete test inventory and does not install
or stage anything. Private fixtures are staged only by their existing harnesses.

Only macOS arm64 and Linux x64 are qualified for these private tests. Unsupported
hosts fail explicitly; no tests are skipped. The separately locked Pear worker
still observes embedded Bare 1.29.4. Neither this setup nor a local test pass
qualifies new native targets, full I02, application/device integration, physical
power-loss durability, browser artifacts, migration authority or fleet rollout.

The frozen public WIRE and client-composition vector runners also use this
standalone Bare 1.31.0 install. Run `npm run test:blind-wire:cross-runtime` and
`npm run test:blind-client-composition:cross-runtime` after preparation. They
compare Node, this private Bare runtime, and a browser-targeted bundle; the
browser bundle executes in Node, not in a real browser. An explicit native
executable can be selected with `HIVERELAY_PRIVATE_BARE_EXECUTABLE` (absolute
path); the actual process must report exactly v1.31.0 and its own executable
identity. Missing installs and mismatches fail without a fallback or skip.
The root public Bare 1.37.1 remains separately qualified: routing the frozen
sodium-v4 wire graph through it on macOS arm64 currently exits with a native
segmentation fault, reproduced on both pre-refresh and refreshed public graphs.
