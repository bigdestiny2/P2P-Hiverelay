/**
 * SignedLog — per-table append-only log of player-signed entries.
 *
 * This is the cryptographic substrate the poker app sits on. The relay does
 * NOT interpret entry payloads — it only enforces that each appended entry:
 *
 *   1. Names a writer pubkey that's in the table's allowlist.
 *   2. Has a per-writer monotonic `seq` (no gaps, no rewinds).
 *   3. Was signed by that writer's secret key over a canonical serialization
 *      of the rest of the entry.
 *   4. Carries a `ts` within a bounded skew of the relay's clock.
 *   5. Fits within MAX_ENTRY_BYTES (DoS bound).
 *   6. Names the correct `tableKey` (no cross-table replay).
 *
 * Everything else (action types, card indices, shuffle proofs, decryption
 * shares) is opaque payload. The relay is card-blind by construction — it
 * never inspects or validates `payload`. That's the whole point: the relay
 * provides ordering + availability, players enforce game rules off the log.
 *
 * ─── Entry shape ────────────────────────────────────────────────────────────
 *
 *   {
 *     tableKey: <hex 64>,        // pubkey of the table (binds the entry)
 *     writer:   <hex 64>,        // pubkey of the player who signed
 *     seq:      <int >= 0>,      // per-writer monotonic counter
 *     ts:       <ms epoch>,      // signer's wall-clock at sign time
 *     payload:  <any JSON>,      // opaque to the relay
 *     signature:<hex 128>        // ed25519 over canonical(entry minus sig)
 *   }
 *
 * The canonical signing payload is built from a fixed-order concatenation
 * of the non-signature fields (see `_canonicalEntry`). We do not rely on
 * JSON key ordering — payload sub-objects are passed through `sortKeys`
 * recursively so the same logical entry always produces the same bytes.
 *
 * ─── Subscriptions ──────────────────────────────────────────────────────────
 *
 * `subscribe(fn)` returns an unsubscribe. The callback is invoked
 * synchronously after every successful append, with the appended entry.
 * This is the hook the HTTP/WS adapter uses to push live events. Errors in
 * subscribers are swallowed (logged via the optional `log` option) so one
 * bad subscriber can't break the log.
 *
 * ─── Persistence ────────────────────────────────────────────────────────────
 *
 * In-memory only. Production persistence (autobase, hyperbee, or a hand-
 * scoped hypercore per table) is wired by the consumer — this module is
 * deliberately storage-agnostic. The `_replay()` hook lets a caller rehydrate
 * a log from a serialized snapshot if they're holding their own store.
 */

import sodium from 'sodium-universal'
import b4a from 'b4a'

// Wall-clock skew tolerance for entry timestamps. We accept entries up to
// this many milliseconds in the future (so a slightly-fast signer doesn't
// get rejected) and up to this much in the past (so a brief network hiccup
// doesn't kill an otherwise-fine entry). Tighter than seeding-manifest's
// 5min — poker actions are interactive and any 60s clock skew is a problem
// for the game anyway.
export const TS_SKEW_MS = 60 * 1000

// Per-entry byte budget. Big enough to comfortably carry shuffle proofs,
// decryption shares, and signed-envelope receipts; small enough to make
// trying to grief the log with megabytes obviously broken.
export const MAX_ENTRY_BYTES = 64 * 1024

// A table can grow over time but extremely long sessions should rotate to
// a fresh log to keep memory bounded. This is a soft cap — `append` refuses
// new entries past it. Operators can override per-table via the constructor.
export const DEFAULT_MAX_ENTRIES = 100_000

// ed25519 sig length in bytes.
const SIG_BYTES = 64

/**
 * Reasons returned by `append` when an entry is rejected. Stable strings —
 * they show up in arbitration evidence and operator dashboards. Don't
 * rename without coordinating with consumers.
 */
export const REJECT = Object.freeze({
  BAD_SHAPE: 'bad-shape',
  WRONG_TABLE: 'wrong-table',
  UNKNOWN_WRITER: 'unknown-writer',
  BAD_SEQ: 'bad-seq',
  BAD_TS: 'bad-ts',
  BAD_SIG: 'bad-sig',
  OVERSIZED: 'oversized',
  LOG_FULL: 'log-full'
})

export class SignedLog {
  /**
   * @param {object} opts
   * @param {string} opts.tableKey      Hex pubkey identifying the table.
   * @param {string[]} opts.writers     Allowed writer pubkeys (hex).
   * @param {number} [opts.maxEntries]  Override DEFAULT_MAX_ENTRIES.
   * @param {number} [opts.tsSkewMs]    Override TS_SKEW_MS.
   * @param {(label, info) => void} [opts.log]  Optional logger for warnings.
   */
  constructor (opts) {
    if (!opts || !isHexKey(opts.tableKey)) {
      throw new Error('SignedLog: bad tableKey')
    }
    if (!Array.isArray(opts.writers) || opts.writers.length === 0) {
      throw new Error('SignedLog: writers must be a non-empty array')
    }
    const writers = new Set()
    for (const w of opts.writers) {
      if (!isHexKey(w)) throw new Error('SignedLog: bad writer pubkey: ' + w)
      writers.add(w.toLowerCase())
    }

    this.tableKey = opts.tableKey.toLowerCase()
    this.writers = writers
    this.maxEntries = opts.maxEntries || DEFAULT_MAX_ENTRIES
    this.tsSkewMs = opts.tsSkewMs || TS_SKEW_MS
    this._log = opts.log || (() => {})

    /** @type {object[]} Append-only entries; index is the global log index. */
    this.entries = []
    /** @type {Map<string, number>} writer pubkey → last accepted seq. */
    this._lastSeq = new Map()
    /** @type {Set<Function>} subscribers — see subscribe(). */
    this._subscribers = new Set()
    /** @type {number} Wall-clock at construction; used in state(). */
    this.createdAt = Date.now()
    /** @type {?number} Wall-clock of the last accepted entry. */
    this.lastTs = null
  }

  /**
   * Try to append a signed entry. Returns `{ ok: true, index, ts }` on
   * success, or `{ ok: false, reason }` with a code from REJECT. Never
   * throws — bad entries are first-class data here, not exceptions.
   *
   * @param {object} entry
   * @param {object} [opts]
   * @param {number} [opts.now]  Inject a clock for deterministic tests.
   */
  append (entry, opts = {}) {
    const now = opts.now || Date.now()

    // 1. Shape.
    if (!entry || typeof entry !== 'object') return reject(REJECT.BAD_SHAPE, 'not-object')
    if (typeof entry.tableKey !== 'string') return reject(REJECT.BAD_SHAPE, 'tableKey')
    if (typeof entry.writer !== 'string') return reject(REJECT.BAD_SHAPE, 'writer')
    if (!Number.isInteger(entry.seq) || entry.seq < 0) return reject(REJECT.BAD_SHAPE, 'seq')
    if (typeof entry.ts !== 'number' || !Number.isFinite(entry.ts)) return reject(REJECT.BAD_SHAPE, 'ts')
    if (typeof entry.signature !== 'string') return reject(REJECT.BAD_SHAPE, 'signature')
    // `payload` may be any JSON-serializable value, including null/undefined.

    // 2. Table binding.
    if (entry.tableKey.toLowerCase() !== this.tableKey) return reject(REJECT.WRONG_TABLE, entry.tableKey)

    // 3. Writer allowlist.
    const writer = entry.writer.toLowerCase()
    if (!this.writers.has(writer)) return reject(REJECT.UNKNOWN_WRITER, writer)

    // 4. Per-writer monotonic seq. We enforce strict +1 (no gaps): clients
    //    can re-send the same entry idempotently by accepting BAD_SEQ as a
    //    duplicate, but the relay never reorders or fills gaps. This makes
    //    every writer's sub-log deterministic without any consensus step.
    const expected = (this._lastSeq.get(writer) ?? -1) + 1
    if (entry.seq !== expected) return reject(REJECT.BAD_SEQ, { expected, got: entry.seq })

    // 5. Timestamp skew. Both directions — too far in the past suggests
    //    a stale replay, too far in the future suggests a clock-fudging
    //    attempt to extend a timeout deadline.
    if (entry.ts > now + this.tsSkewMs) return reject(REJECT.BAD_TS, 'future')
    if (entry.ts < now - this.tsSkewMs) return reject(REJECT.BAD_TS, 'past')

    // 6. Byte budget. Serialize once and reuse for sig verification.
    const canonical = _canonicalEntry(entry)
    if (canonical.byteLength > MAX_ENTRY_BYTES) return reject(REJECT.OVERSIZED, canonical.byteLength)

    // 7. Signature. ed25519 detached. Sodium throws on bad-length keys, so
    //    we already enforced hex64 via isHexKey at construction.
    let sig
    try {
      sig = b4a.from(entry.signature, 'hex')
    } catch {
      return reject(REJECT.BAD_SIG, 'hex-decode')
    }
    if (sig.byteLength !== SIG_BYTES) return reject(REJECT.BAD_SIG, 'length')
    const pub = b4a.from(writer, 'hex')
    const ok = sodium.crypto_sign_verify_detached(sig, canonical, pub)
    if (!ok) return reject(REJECT.BAD_SIG, 'verify')

    // 8. Log bound.
    if (this.entries.length >= this.maxEntries) return reject(REJECT.LOG_FULL, this.maxEntries)

    // Accept. Freeze a defensive shallow copy so subscribers can't mutate
    // the canonical record.
    const frozen = Object.freeze({ ...entry, writer })
    const index = this.entries.length
    this.entries.push(frozen)
    this._lastSeq.set(writer, entry.seq)
    this.lastTs = entry.ts

    // Emit. Subscriber errors are swallowed — we will not let a buggy
    // listener block the log.
    for (const fn of this._subscribers) {
      try { fn(frozen, index) } catch (err) { this._log('subscriber-error', { error: err && err.message }) }
    }

    return { ok: true, index, ts: entry.ts }
  }

  /**
   * Build the signed-payload bytes for an entry that hasn't been signed yet.
   * Callers sign this with their ed25519 secret key and attach the hex
   * signature as `entry.signature` before calling `append`. Exposed so
   * client SDKs can use the exact same canonicalization the relay does.
   */
  static canonicalBytes (entryWithoutSignature) {
    return _canonicalEntry(entryWithoutSignature)
  }

  /**
   * Read entries from `fromIdx` inclusive. Returns at most `limit` (default
   * unbounded). Pure read — does not advance any cursor; safe to call from
   * many readers in parallel.
   */
  slice (fromIdx = 0, limit = Infinity) {
    const start = Math.max(0, fromIdx | 0)
    const end = Math.min(this.entries.length, start + (Number.isFinite(limit) ? limit : this.entries.length))
    return {
      from: start,
      to: end,
      entries: this.entries.slice(start, end)
    }
  }

  /**
   * Compact public state. Designed for `/api/poker/<table>/state` — clients
   * use it to learn current writer cursors without pulling the whole log.
   */
  state () {
    const writers = {}
    for (const w of this.writers) writers[w] = this._lastSeq.get(w) ?? -1
    return {
      tableKey: this.tableKey,
      createdAt: this.createdAt,
      lastTs: this.lastTs,
      lastIndex: this.entries.length - 1,
      length: this.entries.length,
      writers
    }
  }

  /**
   * Register a callback invoked synchronously after every successful append.
   * Returns an unsubscribe function.
   *
   * @param {(entry: object, index: number) => void} fn
   * @returns {() => void}
   */
  subscribe (fn) {
    if (typeof fn !== 'function') throw new Error('SignedLog.subscribe: not a function')
    this._subscribers.add(fn)
    return () => { this._subscribers.delete(fn) }
  }

  /**
   * Re-apply an array of already-validated entries — used to rehydrate a
   * log from an external store at startup. Skips validation; only the
   * persistence layer should call this, and only with entries it itself
   * validated on the way in.
   */
  _replay (entries) {
    for (const e of entries) {
      this.entries.push(Object.freeze({ ...e, writer: e.writer.toLowerCase() }))
      this._lastSeq.set(e.writer.toLowerCase(), e.seq)
      this.lastTs = e.ts
    }
  }
}

// ─── Module-local helpers ────────────────────────────────────────────────────

function reject (reason, detail) {
  return { ok: false, reason, detail: detail === undefined ? null : detail }
}

function isHexKey (s) {
  return typeof s === 'string' && /^[0-9a-f]{64}$/i.test(s)
}

/**
 * Build the bytes signed by `entry.signature`. Order is fixed:
 *   tableKey\n writer\n seq\n ts\n payload_json
 * where payload_json is `payload` recursively key-sorted and stringified.
 *
 * Why not JSON.stringify(entry)? Because key order in JS engines is
 * deterministic in practice but not guaranteed by the spec, and we need
 * sign+verify to agree byte-for-byte across runtimes (Bare, Node, browsers).
 */
function _canonicalEntry (entry) {
  const parts = [
    String(entry.tableKey).toLowerCase(),
    String(entry.writer).toLowerCase(),
    String(entry.seq),
    String(entry.ts),
    JSON.stringify(_sortDeep(entry.payload === undefined ? null : entry.payload))
  ]
  return b4a.from(parts.join('\n'), 'utf8')
}

function _sortDeep (v) {
  if (v === null || typeof v !== 'object') return v
  if (Array.isArray(v)) return v.map(_sortDeep)
  const out = {}
  for (const k of Object.keys(v).sort()) out[k] = _sortDeep(v[k])
  return out
}

export { _canonicalEntry as canonicalEntryForTest }
