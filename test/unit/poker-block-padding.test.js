/**
 * poker-block-padding tests.
 *
 * The relay is card-blind — it never reads entry.payload — but the *size* of
 * each Hypercore block still leaks the action type (a fold, a raise, and a
 * card-reveal produce very different JSON lengths). HypercorePersistence pads
 * each block up to a fixed size bucket with trailing ASCII whitespace before
 * append, which equalizes the common actions while staying:
 *
 *   - signature-transparent (pad is OUTSIDE the signed JSON object)
 *   - reader-transparent     (JSON.parse ignores trailing whitespace)
 *   - backward-compatible     (legacy un-padded blocks parse unchanged)
 *
 * These tests lock in the pure padding maths, the option normalization, the
 * JSON round-trip (whitespace tolerance), and the end-to-end behaviour through
 * _mirror against a capturing mock core — no Corestore / PokerApp needed.
 */

import test from 'brittle'
import {
  DEFAULT_PAD_BUCKETS,
  HypercorePersistence,
  _padBlockForTest as padBlock,
  _resolvePadBucketsForTest as resolveBuckets
} from 'p2p-hiveservices/builtin/poker/persistence-hypercore.js'

// A signed-log-shaped entry with a payload of the requested approximate size.
function entryWithPayload (payload, seq = 0) {
  return {
    tableKey: 'a'.repeat(64),
    writer: 'b'.repeat(64),
    seq,
    ts: 1_700_000_000_000,
    payload,
    signature: 'c'.repeat(128)
  }
}

// Build a persistence instance with a mock core that records appended blobs.
// pokerApp/store only need to be truthy for the constructor.
function harness (padding) {
  const blocks = []
  const core = { append: async (blob) => { blocks.push(blob) } }
  const opts = { pokerApp: {}, store: {} }
  if (padding !== undefined) opts.padding = padding
  const p = new HypercorePersistence(opts)
  return { p, core, blocks }
}

// ─── pure _padBlock maths ───────────────────────────────────────────────────

test('padBlock: pads up to the smallest bucket >= length', (t) => {
  const out = padBlock('abc', [10])
  t.is(Buffer.byteLength(out, 'utf8'), 10, 'padded to bucket size')
  t.is(out.slice(0, 3), 'abc', 'original content preserved at the front')
  t.ok(/^abc {7}$/.test(out), 'remainder is trailing spaces')
})

test('padBlock: exact bucket boundary is left unchanged', (t) => {
  t.is(padBlock('abc', [3]), 'abc', 'no padding when already on a boundary')
})

test('padBlock: picks the first bucket that fits, not a larger one', (t) => {
  const out = padBlock('x'.repeat(1500), [1024, 4096, 16384])
  t.is(Buffer.byteLength(out, 'utf8'), 4096, 'rounds up to 4096, not 16384')
})

test('padBlock: over-top-bucket rounds up to a multiple of the top bucket', (t) => {
  const out = padBlock('y'.repeat(5), [3])
  t.is(Buffer.byteLength(out, 'utf8'), 6, 'ceil(5/3)*3 = 6')
})

test('padBlock: disabled (null buckets) returns the input untouched', (t) => {
  t.is(padBlock('hello', null), 'hello', 'null disables padding')
  t.is(padBlock('hello', []), 'hello', 'empty ladder disables padding')
})

test('padBlock: byte-accurate for multibyte UTF-8 content', (t) => {
  // 'é' is 2 bytes in UTF-8 — padding must count bytes, not chars.
  const out = padBlock('é', [4])
  t.is(Buffer.byteLength(out, 'utf8'), 4, 'pads to 4 bytes accounting for multibyte')
})

// ─── _resolvePadBuckets normalization ───────────────────────────────────────

test('resolveBuckets: default ladder when omitted or true', (t) => {
  t.alike(resolveBuckets(undefined), DEFAULT_PAD_BUCKETS.slice(), 'undefined → defaults')
  t.alike(resolveBuckets(true), DEFAULT_PAD_BUCKETS.slice(), 'true → defaults')
})

test('resolveBuckets: false disables padding', (t) => {
  t.is(resolveBuckets(false), null, 'false → null')
})

test('resolveBuckets: custom array is sorted ascending', (t) => {
  t.alike(resolveBuckets([512, 128, 1024]), [128, 512, 1024], 'sorted ascending')
})

test('resolveBuckets: garbage entries fall back to defaults', (t) => {
  t.alike(resolveBuckets([0, -5, 'x', 2.5]), DEFAULT_PAD_BUCKETS.slice(), 'no valid → defaults')
  t.alike(resolveBuckets([]), DEFAULT_PAD_BUCKETS.slice(), 'empty → defaults')
})

// ─── JSON round-trip (the load-bearing safety property) ─────────────────────

test('round-trip: JSON.parse recovers the exact entry from a padded block', (t) => {
  const entry = entryWithPayload({ action: 'raise', amount: 200 })
  const padded = padBlock(JSON.stringify(entry), DEFAULT_PAD_BUCKETS)
  t.not(Buffer.byteLength(padded, 'utf8'), Buffer.byteLength(JSON.stringify(entry), 'utf8'), 'block was actually padded')
  t.alike(JSON.parse(padded), entry, 'JSON.parse ignores trailing whitespace → identical entry')
})

// ─── _mirror end-to-end against a mock core ─────────────────────────────────

test('_mirror: fold and raise produce equal-size blocks (size-blind)', async (t) => {
  const { p, core, blocks } = harness() // default padding on
  await p._mirror('a'.repeat(64), core, entryWithPayload({ action: 'fold' }, 0))
  await p._mirror('a'.repeat(64), core, entryWithPayload({ action: 'raise', amount: 12345 }, 1))

  t.is(blocks.length, 2, 'two blocks appended')
  t.is(blocks[0].byteLength, 1024, 'fold block padded to first bucket')
  t.is(blocks[1].byteLength, 1024, 'raise block padded to the same bucket')
  t.is(blocks[0].byteLength, blocks[1].byteLength, 'fold and raise are size-indistinguishable')
})

test('_mirror: a large reveal lands in a higher bucket but still round-trips', async (t) => {
  const { p, core, blocks } = harness()
  const big = entryWithPayload({ shares: 'd'.repeat(5000) }, 0)
  await p._mirror('a'.repeat(64), core, big)

  t.is(blocks[0].byteLength, 16384, 'large payload padded to the 16 KiB bucket')
  t.alike(JSON.parse(blocks[0].toString('utf8')), big, 'large block still parses back to the entry')
})

test('_mirror: padding:false preserves legacy raw-JSON blocks', async (t) => {
  const { p, core, blocks } = harness(false)
  const entry = entryWithPayload({ action: 'check' }, 0)
  await p._mirror('a'.repeat(64), core, entry)

  const raw = JSON.stringify(entry)
  t.is(blocks[0].byteLength, Buffer.byteLength(raw, 'utf8'), 'no padding applied when disabled')
  t.is(blocks[0].toString('utf8'), raw, 'block is exactly the raw JSON')
})

test('_mirror: custom bucket ladder is honoured', async (t) => {
  const { p, core, blocks } = harness([256, 512])
  await p._mirror('a'.repeat(64), core, entryWithPayload({ action: 'call' }, 0))
  t.is(blocks[0].byteLength, 512, 'padded to the smallest custom bucket that fits (>256 bytes of envelope)')
})
