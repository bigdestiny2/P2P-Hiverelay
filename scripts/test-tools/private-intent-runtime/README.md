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
