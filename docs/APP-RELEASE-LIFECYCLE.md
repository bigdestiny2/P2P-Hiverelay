# Bounded app release storage

HiveRelay app publishing now uses three linked controls:

1. The live Hyperdrive tree is mirrored exactly. Byte-identical files are not
   rewritten, changed files use Hyperblobs block deduplication, and removed
   build paths are deleted.
2. Every release carries a domain-separated Ed25519 statement in
   `manifest.json` at `hiverelay.release`. The statement binds the publisher,
   app id, version, release sequence, drive key, content-tree hash, per-drive
   storage budget, and rollback drive keys.
3. Before a publish would exceed its per-drive budget, the publisher creates a
   new uniquely-namespaced Hyperdrive. It signs the old-key to new-key
   transition and writes the same statement to the old drive at
   `/.hiverelay/rotation.json`.

Relays verify the signed statement against the pinned manifest, recompute its
content-tree hash from that exact pinned Hyperdrive version, and bind it to the
publisher from the seed request and the seed storage bound. A relay only
accepts a key rotation when it names the currently served predecessor. Release
authority is durably persisted before reclamation can begin and survives relay
restart. Reclamation is scoped to the exact app id and publisher, retains the
signed rollback key set, and sends only older drives from that release chain
through the existing unseed, tombstone, and purge path. Archive, custody, and
unexpired paid-lease entries remain non-purgable.

## Publisher usage

```sh
node scripts/publish-app.js ./dist \
  --id my-app \
  --name "My App" \
  --version 2.4.0 \
  --storage-budget 1GiB \
  --rollback-window 3
```

`--name` or `--id` is required because a signed chain needs a stable app
identity. The defaults are a 1 GiB budget per drive and three retained
releases. The rollback window accepts 1 through 32 releases.

Publisher state is stored under the selected `--storage` directory:

- `release-state.json` contains the mode-0600 Ed25519 seed, monotonic sequence,
  generation, active drive key, and bounded release history.
- `app-drives.json` contains the active app-id to drive-key lookup.

Back up the publisher storage. The signing seed is the authority for the
release chain, while the Corestore contains the writable Hyperdrive keys.

When no relay URLs are supplied and `--no-stay` is set, the script performs an
offline publish without binding a DHT socket. With an operator API key it uses
`/seed`; without one it sends the existing replay-hardened publisher-signed
request to `/api/v1/seed`.

## Storage semantics

The publisher reserves 64 KiB inside each budget for the signed predecessor
pointer and uses a conservative metadata estimate before writing. A single
release that cannot fit in a fresh drive plus that reserve is rejected with the
estimated required size.

The rollback window is measured in signed releases. Multiple releases can live
in the same drive, so the retained drive-key list is deduplicated. On relays,
signed release sequence is authoritative for supersession; legacy unsigned
entries continue to use semantic version ordering until that publisher adopts
a signed chain. Once adopted, an older unsigned manifest cannot regain release
authority by claiming a larger semantic version.

Blind releases still receive publisher-side delta syncing, budgeting, and a
signed encrypted rotation pointer. Relays preserve their existing blind-drive
non-inspection contract, so automatic manifest-based rollback reclamation is
limited to non-blind releases.
