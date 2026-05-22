# Blind-path audit — 2026-05-19

Scope: every code path that touches an entry with `blind === true` must
honor the publisher's privacy contract. Public/non-blind drives stay
untouched — those are publisher-attested discoverable content (manifest,
catalog, gateway). Goal is to close any leak where a relay operator
(threat model: root on the relay box) could read blind-drive metadata
or content through the relay's own machinery.

## Verdict summary

| # | Path                                                  | Verdict          | Fix scope                |
| - | ----------------------------------------------------- | ---------------- | ------------------------ |
| 1 | `_indexAppManifest` (app-lifecycle.js)                | **LEAK**         | 1-line early-return      |
| 2 | HyperGateway HTTP                                     | OK               | (already guarded)        |
| 3 | `/catalog.json` HTTP + `_shouldRedactEntry`           | **LEAK (cond.)** | 2-line predicate update  |
| 4 | `catalogForBroadcast` (P2P gossip)                    | OK               | (always redactPrivate)   |
| 5 | Log/event emissions (`app-replaced`, `app-version-rejected`) | LEAK     | cascade-fixed by Path 1  |
| 6 | `/api/manage/*` endpoints calling `catalog()`         | LEAK             | cascade-fixed by Path 3  |
| 7 | Federation catalog-sync                               | OK               | (blind flag propagated)  |
| 8 | On-disk replication blocks                            | LIMITATION       | doc-only (PUBLISHING.md) |
| 9 | `app-replaced` / `app-version-rejected` (logging)     | LEAK             | cascade-fixed by Path 1  |

**Net code change: 2 surgical edits** (Path 1 + Path 3). All other
"LEAK" entries cascade-fix automatically when those two land. The
remaining items are either already-airtight (2, 4, 7) or out of scope
for relay code (8).

---

## Path 1 — `_indexAppManifest` (LEAK)

**File:** `packages/core/core/relay-node/app-lifecycle.js:692`

**Today:** Unconditionally opens `/manifest.json` on every anchored drive,
parses it, and persists `appId`, `name`, `description`, `author`,
`categories`, `version`, `privacyTier` into `app-registry.json`. No
`blind` check anywhere.

**Why this is a leak for blind drives:** A blind publisher's manifest
may or may not be encrypted (a real blind publisher would ship an
encrypted manifest or no manifest at all, but the relay can't enforce
that). Today the relay opens it regardless — and the parsed metadata
ends up in `app-registry.json` on disk in plaintext. Operator with
root sees blind drive's name/author/description.

Also triggers Paths 5 and 9 — the `app-replaced` / `app-version-rejected`
events are emitted from inside this method with `appId` and `version`
in the payload, which flow into logs and the ws-feed.

**Fix:**

```js
async _indexAppManifest (appKeyHex, drive) {
  const node = this.node
  // Blind drives: publisher's privacy contract says "do not inspect."
  // We don't open /manifest.json, don't persist any manifest-derived
  // fields, and don't fire app-replaced / app-version-rejected events
  // (which would leak appId+version into logs). The registry entry
  // keeps its commitment-level fields (appKey, blindContentId,
  // ciphertextRoot, durability, revocable) which are signed
  // publisher commitments, not inspected content.
  const existing = node.appRegistry.get(appKeyHex)
  if (existing && existing.blind === true) return

  try {
    // ... rest unchanged
```

**Cascade effect:** Closes Paths 5 and 9 entirely (the events that emit
manifest-derived data never fire for blind entries).

---

## Path 2 — HyperGateway HTTP (OK)

**File:** `packages/core/gateway/hyper-gateway.js:289`

```js
if (appEntry && appEntry.blind) {
  res.writeHead(403)
  res.end(JSON.stringify({
    error: 'Private app — encrypted content, P2P access only',
    blind: true,
    hint: 'Use PearBrowser or Hyperswarm to access this app with the encryption key'
  }))
  return
}
```

The gateway checks `appEntry.blind` **before opening the drive** and
returns 403. The HTTP path is closed for blind content.

No change needed.

---

## Path 3 — `/catalog.json` HTTP + `_shouldRedactEntry` (LEAK conditional)

**File:** `packages/core/core/app-registry.js:269`

**Today:**

```js
_shouldRedactEntry (entry, opts = {}) {
  if (opts.redactPrivate !== true) return false   // caller has to opt in
  const privacyTier = String(entry.privacyTier || 'public').toLowerCase()
  return entry.blind === true ||
    privacyTier !== 'public' ||
    entry.metadataVisibility === 'redacted'
}
```

`/catalog.json` (api.js:393) passes `redactPrivate: this.node.config?.
custody?.redactedCatalog !== false`. So:
- Default config (`redactedCatalog` unset): redaction ON → blind safe ✓
- Operator sets `redactedCatalog: false`: redaction OFF → blind entries
  return full metadata over public HTTP ✗

Also, every `appRegistry.catalog()` call site that *forgets* to pass
`{ redactPrivate: true }` skips redaction. There's at least one such
call (api.js:792).

**Why this is a leak:** The `blind` flag is the publisher's commitment,
not an operator preference. An operator can't override it for content
they didn't author. Currently they can, via `redactedCatalog: false`.

**Fix:** Make blind unconditional, independent of caller opts:

```js
_shouldRedactEntry (entry, opts = {}) {
  // The blind flag is the publisher's privacy commitment — the relay
  // honors it unconditionally, regardless of caller opts or operator
  // config. opts.redactPrivate only controls whether non-blind
  // privacy-tier entries also get redacted.
  if (entry.blind === true) return true
  if (opts.redactPrivate !== true) return false
  const privacyTier = String(entry.privacyTier || 'public').toLowerCase()
  return privacyTier !== 'public' || entry.metadataVisibility === 'redacted'
}
```

**Cascade effect:** Closes Path 6 entirely (every `catalog()` call,
including the no-opts ones in `/api/manage/*`, now always redacts
blind entries).

---

## Path 4 — `catalogForBroadcast` (OK)

**File:** `packages/core/core/app-registry.js:387`

```js
const redacted = this._shouldRedactEntry(entry, { redactPrivate: true })
```

Hardcoded `redactPrivate: true`. With Path 3's fix applied, blind
entries are doubly-guaranteed redacted.

No change needed.

---

## Path 5 — Log/event emissions in `_indexAppManifest` (cascade-fixed)

**File:** `packages/core/core/relay-node/app-lifecycle.js:750, 759`

Events `app-replaced { appId, oldVersion, newVersion, ... }` and
`app-version-rejected { appId, rejectedVersion, ... }` flow through
ws-feed and observatory logs. They emit manifest-derived data.

Path 1's early-return makes these unreachable for blind entries (they
fire inside `_indexAppManifest` after the manifest is parsed).

Verified: other log emissions (`seeding`, `anchored`, `reseeded`,
`unseeded`) only carry `appKey` (public identifier), `discoveryKey`
(public identifier), drive `version` (hypercore version number, not
manifest version), and `source`. All opaque/operational. No fix needed.

---

## Path 6 — `/api/manage/*` endpoints calling `catalog()` (cascade-fixed)

**File:** `packages/core/core/relay-node/api.js:792`

`this.node.appRegistry.catalog()` (no opts) → redactPrivate undefined →
no redaction → blind entries' full metadata returned to authenticated
operators. Path 3's unconditional blind-redaction fixes this — blind
stays redacted even when no opts passed.

No additional fix needed. Worth a once-over to confirm every callsite
in api.js is intentionally either:
- already passing `redactPrivate: true` (or trusting Path 3 to redact blind regardless), OR
- a deliberate non-redacting path (which should no longer exist for blind entries after Path 3)

---

## Path 7 — Federation catalog-sync (OK)

**File:** `packages/core/core/federation.js:375-401`

```js
const synthRequest = {
  ...
  blind: app.blind === true,
  ...
}
...
await this.node.seedApp(appKey, {
  ...
  blind: synthRequest.blind,
  ...
})
```

The `blind` flag is propagated through the entire federation accept
path. A blind entry mirrored from a peer stays blind locally.

No change needed.

---

## Path 8 — On-disk replication blocks (architectural limitation)

**File:** `/root/.hiverelay/storage/cores/`

For any drive, the hypercore replication layer writes whatever blocks
the publisher pushes. If the publisher pushed plaintext under
`blind: true`, the operator with root can read those plaintext bytes
off disk.

**Why this isn't a code-level fix:** The relay can't cryptographically
verify pushed blocks are ciphertext — that's a chicken-and-egg with
the relay-doesn't-have-the-key requirement that defines blindness.

**What the relay does today:** Config defaults `requireEncryptedPayload:
true` + `allowTransparent: false` (`relay-node/index.js:81-82`). The
seed-request carries `ciphertextRoot` — a publisher-attested commitment
to "the block tree is ciphertext rooted at X." Honor system.

**Recommended doc change** (PUBLISHING.md, not in this PR's scope):
loud paragraph stating "blind:true is a publisher contract — YOU must
encrypt your blocks before pushing. The relay accepts your
ciphertextRoot commitment but cannot prove blocks aren't plaintext.
If you push plaintext under blind:true, operators with disk access
can read your content."

---

## Path 9 — `app-replaced` / `app-version-rejected` (cascade-fixed)

Same fix as Path 5: Path 1's early-return guarantees these events
never fire for blind entries.

---

## Tests to add

```js
// test/unit/blind-path-airtight.test.js (new file)

test('_indexAppManifest skips blind entries entirely', ...)
test('_shouldRedactEntry returns true for blind regardless of opts.redactPrivate', ...)
test('catalog() with no opts still redacts blind entries', ...)
test('catalog() with { redactPrivate: false } still redacts blind entries', ...)
test('catalogForBroadcast redacts blind entries (regression guard)', ...)
test('app-replaced is not emitted for blind entries (Path 5 cascade)', ...)
test('app-version-rejected is not emitted for blind entries (Path 9 cascade)', ...)
```

7 tests, all small. They fuzz the boundary by setting `blind: true` on
a registry entry and asserting each surface returns no identifying
data.

## Risk

Low. Two surgical edits (each <10 lines) + tests. No protocol changes,
no behavior change for non-blind drives. Public/non-blind discovery
(manifest indexing, catalog, gateway, federation) keeps working exactly
as today. The change is purely "add the guards that should have been
there from day one."

## What this ships in

v0.8.15 alongside the Hyperdrive-session audit fixes (`hyper-gateway.js`,
`storage-service.js`, `gateway/server.js` — already applied locally on
main, not yet released). Same release vehicle, same fleet rollout,
canary retired as a side effect.
