# Hiverelay TODO Triage - 2026-06-24

Source root: `/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay`

This Level 2 loop checked the highest-value TODO/FIXME surface in maintained Hiverelay source. The result is intentionally a classification artifact rather than a code patch: the current worktree is already very large and dirty, and the marker scan found no active first-party TODO/FIXME implementation cluster worth forcing into this loop.

## Marker Scan

Command shape:

```sh
rg -n -i "todo|fixme|xxx|hack" \
  packages scripts test docs dashboard fleet startos \
  -g '!node_modules/**' \
  -g '!package-lock.json' \
  -g '!docs/handoff/**' \
  -g '!*.min.*'
```

Actionable maintained-source findings:

- None.

Remaining hits were non-actionable:

- `test/unit/private-mode.test.js` contains historical comments documenting a removed `process.exit` test workaround. The comments are useful guardrails and should stay.
- `test/unit/error-prefixes.test.js` deliberately tries to assign a string containing `hacked` to a frozen error-prefix map to prove runtime mutation fails.
- `scripts/test-resilience.js` uses `HIVERELAY_API_KEY=xxx` in usage examples. This is placeholder documentation for an operator-supplied secret, not a code TODO.
- `docs/handoff/2026-05-23-v0.8.20-merge-plan.md` contains an old PR-plan mention of a TODO comment. It is historical handoff material and was excluded from maintained-source scoring.

## Focused Validation

The marker-related regression slice passed:

```sh
./node_modules/.bin/brittle --timeout 120000 \
  test/unit/private-mode.test.js \
  test/unit/error-prefixes.test.js
```

Result:

- 40/40 tests passed.
- 308/308 assertions passed.

This validates that the historical test-workaround comments are attached to passing regression coverage and that the error-prefix mutation test behaves as intended.

## Classification

The Hiverelay TODO/FIXME backlog is currently not the compounding drag. The higher-value Hiverelay work is in already documented release/evidence tracks:

- release evidence sidecars;
- Umbrel runtime review evidence;
- StartOS registry evidence;
- live fleet rollout evidence;
- security-doc cleanup for shipped vs future guarantees;
- release-surface synchronization.

Future loops should not open a broad TODO cleanup in Hiverelay unless new maintained-source markers appear. Prefer the release-evidence cleanup loop named in `docs/TEST-COMMAND-MATRIX-2026-06-23.md` and `docs/CURRENT_STATUS_AUDIT_2026-06-23.md`.

## Residual Risk

The repository has many pre-existing modified and untracked files. This triage does not claim ownership of that dirty worktree and does not prove the broad release surface. It only proves that the current TODO/FIXME marker surface is not hiding a high-value maintained-source implementation cluster.
