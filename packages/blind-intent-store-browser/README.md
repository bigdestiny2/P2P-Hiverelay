# Private bounded browser intent backend — I03.1

`@hiverelay/blind-intent-store-browser@0.0.0-i03.1` adds an IndexedDB backend
for the existing authenticated `EncryptedIntentStore`. It is private source
qualification, not a published browser API or worker artifact. Existing public
client exports and v1/v2/v3 artifacts remain byte-exact.

The caller supplies the exact stable secure origin, a bounded database name,
explicit `create` or `reopen`, and record/byte/ciphertext capacities. Database
names must be primitive strings; missing, null or coercible non-string names
are rejected before any IndexedDB access. Create
refuses an existing database; reopen refuses a missing database, including after
eviction. Neither path substitutes an empty store for missing acknowledged work.
Reopen also requires the exact persisted policy and format. Ciphertext and
revisions are retained; the key stays outside IndexedDB in caller custody.

```js
const backend = new BrowserIntentBackend({
  name: 'my-app.intents', origin: location.origin, mode: 'reopen',
  maxRecords: 256, maxTotalBytes: 16 * 1024 * 1024
})
await backend.ready()
// Existing EncryptedIntentStore({ backend, sealer }) owns intent authentication.
await backend.close()
```

Read/write transactions cover both records and the capacity authority. Exact
u64 CAS resolves only on transaction completion, not request success. A write
requires the browser's strict durability hint and atomically advances count,
ciphertext bytes and inventory generation. A revision conflict changes nothing.
Count/byte exhaustion leaves existing unresolved records intact; shrinking or
equal-sized updates remain possible at capacity. There is no automatic deletion
or TTL, including for terminal records. The bound covers retained ciphertext and
record count; browser indexes, storage-engine overhead and physical device caches
need separate operational measurement.

Eight operations are admitted per backend before copying ciphertext. The copy
is made into an owned Uint8Array before yielding, without invoking subclass
slice methods, preventing caller mutation from changing admitted
bytes. Transaction deadlines abort/fence unknown work. Unknown aborts fence the
session and abort its queued transactions. Close drains admitted transactions;
page/process loss can leave a committed revision whose caller never received an
acknowledgment. Reopen and reconcile that same logical intent before sending.

Enumeration retains at most four cursor tokens, returns up to 256 keys and
examines at most limit + 1 keys in a transaction. A token is bound to the exact
inventory generation: another page's successful CAS invalidates continuation
with `INTENT_SCAN_CHANGED`. Restart the scan; do not treat that failure as an
empty inventory. Same-origin code and the browser administrator are trusted.
Other contexts sharing the same origin can access its database; paths and app
labels are not origin isolation.

The real-browser tests run the unchanged accepted intent codec and AES-GCM
sealer, SENT-to-PENDING_UNKNOWN recovery, two-page CAS, conflicts, capacity,
input copying/admission, wrong-key refusal, generation-bound enumeration,
page loss after commit before caller acknowledgment, and explicit database
deletion followed by fail-closed reopen. The latter tests the missing-store
boundary, not actual storage-pressure eviction or physical power loss.

Observed here on macOS arm64: Chromium 151.0.7922.34, installed Brave Chromium
151.0.7922.173, Firefox 153.0 and Playwright WebKit 26.5 using Playwright 1.62.1.
Playwright WebKit is not Safari/iOS qualification. This is one host; independent
hosts, Windows/Linux/mobile rows, actual quota exhaustion/eviction, public
worker coexistence, key custody, authenticated backup freshness and origin
deployment/recovery remain open. No browser family is inferred from another.

Run `npm ci --ignore-scripts --workspaces=false`, install the Firefox 1538 test
runtime under `.browser-cache`, and `npm test`. The test currently names this
Mac's installed Brave and native Firefox arm64 executable. It fails when a
required row is unavailable rather than skipping it. Source, dependency lock,
test bundle and observed runtime identities belong in the lane evidence.

Semantics follow the primary [Indexed Database API 3.0 specification](https://w3c.github.io/IndexedDB/),
particularly transactions and transaction completion. A strict durability hint
does not prove physical power-loss durability on this machine.
