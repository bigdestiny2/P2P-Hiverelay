# Storage cap safety

HiveRelay treats the configured storage cap and physical disk headroom as two
different limits:

- An operator cap from `--max-storage`, `HIVERELAY_MAX_STORAGE`, persisted
  `maxStorageBytes`, setup, or the management API is explicit. Its byte value is
  never increased or reinterpreted because it happens to equal the built-in
  50 GiB default.
- An unset cap is resolved at startup to no more than the legacy 50 GiB. The
  resolver measures the exact storage directory and uses:

  `min(50 GiB, already-held bytes + max(0, available bytes - reserve))`

- The physical reserve is 10% of the storage filesystem, with a 2 GiB floor
  and a 20 GiB ceiling. Admission checks the current available bytes again at
  runtime, so unrelated disk use cannot consume that reserve unnoticed.

The storage path must already exist before a custom-path startup. HiveRelay
never measures the nearest existing ancestor of a missing path: `/data` may be
an intended mount, and measuring `/` in its place would prove the wrong
filesystem. The built-in `~/.hiverelay/storage` directory is owned and created
by HiveRelay. Operators that require a pinned mount identity may configure
`storageFilesystem.realpath` and/or `storageFilesystem.device`; a mismatch
pauses new adoption.

## Already over cap

Crossing the logical cap or physical reserve pauses new drive and bare-core
adoption. It does not stop the node, delete data, or silently enable eviction.
Existing pins can reopen after restart so they remain serveable and visible to
management. Health/config endpoints and manual unseed/purge recovery remain
available. Automatic eviction runs only when the operator has separately
enabled its existing eviction policy.

Lowering `maxStorageBytes` through the management API applies the new adoption
gate immediately and reports whether the node is over cap. Recovery remains an
operator decision: raise the explicit cap, free unrelated filesystem space,
manually unseed eligible content, or explicitly enable the reviewed eviction
policy.

## Persistence and precedence

Persisted cap presence is the source of truth; numeric equality is not used as
provenance. An explicit 50 GiB value is written to `config.json` and reloads as
explicit. A disk-derived unset value is not written as if the operator chose
it, so it is safely recomputed from the same storage filesystem on restart.

CLI flags override persisted configuration. `HIVERELAY_MAX_STORAGE` is used
until an explicit `maxStorageBytes` has been persisted; unrelated persisted
settings do not erase the environment designation.
