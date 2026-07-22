# Publishing on HiveRelay

A short guide for publishers — what to know before you ask a relay to
pin your Hyperdrive. Most of this is one specific gotcha
(`maxStorage`), one diagnostic pattern (`verify-pin`), and the trade-offs
behind a few publisher commitments.

If you only read one section, read **[The `maxStorage` trap](#the-maxstorage-trap)**.

---

## The `maxStorage` trap

**Symptom**: a fresh client can resolve an older app drive but hangs while
retrieving it. Your CI relay-health check passes and the relay catalog says the
drive is seeded, yet the client sees something indistinguishable from "no peers
found."

**Cause**: your seed request declared a `maxStorage` cap smaller than
the drive's actual `byteLength`. The relay accepted the request,
replicated metadata fully, then stalled mid-blob when it hit the cap.
Roughly 30% of the blob blocks are missing, and end users hang
waiting for those blocks to arrive from a peer that doesn't have them.

**Why it's silent (pre-v0.8.11)**: the relay had no way to know its cap
was too small until after metadata arrived, and no mechanism to tell
the publisher when that happened. The publisher's `seeded` callback
fired on the initial accept ACK, before the size mismatch was
discoverable.

**Fix (v0.8.11+)**: the relay now size-checks every drive after the
first metadata sync. If `drive.byteLength + drive.blobs.byteLength >
maxStorage`, the relay emits a `seed-aborted` event, unseeds the drive
locally, and tells the publisher exactly what cap to use. The client
SDK also size-defaults `maxStorage` from a locally-cached drive when
you don't pass an explicit cap, and warns at seed time if your
explicit cap is already too small.

### How to size `maxStorage` correctly

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'

const client = new HiveRelayClient('./storage')
await client.start()

// publish the drive locally (or read its size from local drive metadata)
const drive = await client.publish('./my-app')

// Compute size = metadata + blob bytes, with headroom for future releases.
const metaBytes = drive.db.core.byteLength       // ~1 MB typical
const blobBytes = drive.blobs.core.byteLength    // most of your drive
const headroomMultiplier = 4                     // covers ~3-4 future releases
const maxStorage = (metaBytes + blobBytes) * headroomMultiplier

await client.seed(drive.key, {
  replicas: 5,
  ttlDays: 365,
  maxStorage
})
```

### `verify-pin` — a fresh-corestore round-trip after every pin

The most reliable way to know your pin worked is to round-trip a real
blob from a fresh corestore that has never seen the drive before.
That's what an end user does on first launch.

Minimal `verify-pin.js`:

```js
import Corestore from 'corestore'
import Hyperswarm from 'hyperswarm'
import Hyperdrive from 'hyperdrive'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const driveKey = process.argv[2]
if (!driveKey) { console.error('Usage: verify-pin.js <driveKey-hex>'); process.exit(2) }

const storeDir = mkdtempSync(join(tmpdir(), 'verify-pin-'))
const store = new Corestore(storeDir)
const swarm = new Hyperswarm()
swarm.on('connection', (conn) => store.replicate(conn))

const drive = new Hyperdrive(store, Buffer.from(driveKey, 'hex'))
await drive.ready()
swarm.join(drive.discoveryKey, { server: false, client: true })

await Promise.race([
  drive.update({ wait: true }),
  new Promise((_, reject) => setTimeout(() => reject(new Error('metadata timeout')), 20_000))
])

const files = await new Promise((resolve, reject) => {
  const out = []
  const stream = drive.list('/')
  stream.on('data', e => out.push(e.key))
  stream.on('end', () => resolve(out))
  stream.on('error', reject)
})
if (files.length === 0) { console.error('drive has no files'); process.exit(2) }

const blob = await Promise.race([
  drive.get(files[0]),
  new Promise((_, reject) => setTimeout(() => reject(new Error('blob fetch timed out')), 20_000))
])
if (!blob) { console.error('blob is empty'); process.exit(2) }

console.log('✓ Drive is fully reachable —', files[0], '(' + blob.byteLength + ' bytes)')
await swarm.destroy()
await store.close()
process.exit(0)
```

Run after every release that updates the drive:

```bash
node verify-pin.js <your-drive-key>
# exit 0  → the sampled drive content is retrievable
# exit 2  → relays returned metadata but stalled on blobs (or no peers)
```

Bake it into the release gate — `build → signed artifact/release record →
hive-pin → verify-pin`. A future release cannot ship as “succeeded but
unreachable” when `verify-pin` is a required gate.

### What `maxStorage` is NOT

- **Not the relay's total storage cap.** That's per-relay configuration
  (`node.config.maxStorageBytes`) and applies across all seeded apps.
- **Not a quota that grows automatically as your drive grows.** Each
  seed request declares its own cap and the relay enforces it for the
  life of the seed.
- **Not retroactive.** If you seeded with a 256 MB cap and your drive
  grows to 365 MB, you need to re-seed with a higher cap — the relay
  won't auto-expand.
- **Not relevant to read-only consumers.** Only the publisher's seed
  request carries `maxStorage`. Consumers downloading via
  `drive.get(path)` aren't capped by it.

---

## Publisher commitments

These three fields on `client.seed(driveKey, opts)` are signed by the
publisher and enforced by the relay through the drive's lifetime.
Used carefully they make your drive's behavior predictable; used
carelessly they lock you out of your own content.

### `revocable: false` — non-revocable seeding

Publishes a commitment that this drive will not be unseeded by the
publisher. After this, only the relay operator can take the content
down; no signed unseed request from you will be honored against this
entry.

Useful for: archive-tier content where you want to commit to permanence;
audit trails; legal-record-style content.

Risk: you cannot ever take it back. Don't use this unless you're sure.

### `unseedFreezeMs` — cooldown before publisher unseed

If you set `unseedFreezeMs: 86_400_000` (24h), any signed unseed
request you send within 24h of the original seed will be rejected by
the relay. It's a "commit then think" buffer — useful if your release
pipeline ever issues a release-then-immediately-recall pattern.

### `durability: 1` — archive tier

Opts the drive into AutoHeal: relays running v0.8+ maintain a
diversity-enforced replica fleet across regions and operators. If
you set this, the seed is automatically non-revocable.

---

## Pin script template

A complete pin script that uses all the safety features:

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'

const client = new HiveRelayClient('./pin-storage')
await client.start()

const drive = await client.publish('./my-app', { appId: 'my-app' })
const meta = drive.db.core.byteLength
const blob = drive.blobs.core.byteLength
const driveSize = meta + blob

console.log('Drive size:', (driveSize / 1024 / 1024).toFixed(1), 'MB')

// 4× headroom — covers several future releases at current growth.
const maxStorage = Math.max(256 * 1024 * 1024, driveSize * 4)

// Listen for relay-side aborts BEFORE issuing the seed.
client.on('seed-aborted', (info) => {
  console.error('Relay aborted:', info.reason)
  if (info.recommendedCap) {
    console.error('Try maxStorage =', info.recommendedCap, 'or higher')
  }
  process.exit(2)
})

// Also catch SDK-side cap warnings (the relay accepted the seed but the
// SDK sees the cap is already too small for the current drive).
client.on('seed-cap-warning', (info) => {
  console.warn('SDK cap warning:', info.hint)
})

await client.seed(drive.key, {
  replicas: 5,
  ttlDays: 365,
  maxStorage
})

console.log('✓ Seed request sent. Run verify-pin.js to confirm reachability.')
```

---

## Failure-mode reference

| Symptom | Cause | Fix |
|---|---|---|
| Fresh drive retrieval hangs forever | `maxStorage` < drive size | Re-seed with `maxStorage` ≥ `driveSize × 1.25` |
| Drive metadata resolves but content fetch hangs | Same as above (partial pin) | Same |
| `seeded` event fires but `verify-pin` times out | Relay is on v0.8.10 or older (no size check) | Upgrade relay to v0.8.11+, re-seed |
| `seed-aborted` event with `reason: maxStorage-too-small` | Working as intended — v0.8.11+ relay caught it | Use `info.recommendedCap` |
| Random `503 Retry-After` from the relay | Transient core lifecycle (v0.8.7+) | Retry per the `Retry-After` header |

---

## Reporting publisher-side bugs

If your pin succeeded but end users still see hangs, please include:

1. Output of `verify-pin.js <driveKey>` from a fresh machine
2. The `maxStorage` value you passed to `client.seed()`
3. The drive's actual size from local drive metadata or
   `drive.db.core.byteLength + drive.blobs.core.byteLength`
4. The relay's commit hash (curl `<relay-url>/.well-known/hiverelay.json`)

A reproduction repo helps — see `pearbrowser-desktop` for an example
of a project that hit and fixed this exact bug.

---

## Related

- [Atomic Blind Custody whitepaper](./ATOMIC-BLIND-CUSTODY.md) — protocol
  spec for encrypted handoff
- [What's in the Relay](./WHATS-IN-THE-RELAY.md) — guided tour of every
  v0.8.0+ component
- [Release notes](./) — see `RELEASE-NOTES-0.8.*.md` for each version's
  changes
