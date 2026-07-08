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
  LOG_FULL: 'log-full',
  // ─── Open-join control-entry rejections (public tables) ──────────────────
  SEAT_TAKEN: 'seat-taken',       // claim-seat for an already-occupied seat
  TABLE_FULL: 'table-full',       // claim-seat when writers.size === maxSeats
  SEAT_INVALID: 'seat-invalid',   // seat index outside [0, maxSeats)
  NOT_GENESIS: 'not-genesis',     // revoke-seat by someone other than the host
  RATE_LIMITED: 'rate-limited'    // too many claim-seat attempts from one key
})

/**
 * Control-entry kinds. These ride in the entry ENVELOPE (`entry.kind`), NOT in
 * `entry.payload`, so the relay can act on them while keeping `payload` fully
 * opaque — card-blindness is preserved (a seat index and a "kind" tag are not
 * card values). An entry with no `kind` is an ordinary game action, gated on
 * the writer allowlist exactly as before.
 *
 *   claim-seat  { kind, seat }    self-signed by a NOT-yet-writer; if the seat
 *                                 is free and the table is under maxSeats the
 *                                 author is admitted as a writer (open-join).
 *   revoke-seat { kind, target }  genesis(host)-signed; removes `target` from
 *                                 the writer set and frees their seat (kick).
 */
export const KIND = Object.freeze({
  CLAIM_SEAT: 'claim-seat',
  REVOKE_SEAT: 'revoke-seat'
})

// Open-join claim-seat rate limit (per author pubkey). A token bucket that
// refills one token per CLAIM_REFILL_MS up to CLAIM_BURST. Consumed only AFTER
// signature verification, so a spoofed writer field can't drain a victim's
// bucket. Storage-flood is already closed by rejecting losing claims before
// they're stored; this bounds claim-retry churn on top of that.
export const CLAIM_BURST = 5
export const CLAIM_REFILL_MS = 10 * 1000

export class SignedLog {
  /**
   * @param {object} opts
   * @param {string} opts.tableKey      Hex pubkey identifying the table.
   * @param {string[]} opts.writers     Genesis writer pubkeys (hex). For an
   *                                    open (public) table this is just the
   *                                    creator; strangers join via claim-seat.
   * @param {number} [opts.maxSeats]    Hard cap on the writer set. Defaults to
   *                                    writers.length — so a fixed invite table
   *                                    is "already full" and open-join is a
   *                                    no-op on it. Pass a larger number to
   *                                    open N-writers.length seats to claimers.
   * @param {string} [opts.genesis]     The admission authority — the only key
   *                                    allowed to sign a revoke-seat (kick).
   *                                    Defaults to writers[0].
   * @param {number} [opts.claimBurst]      Override CLAIM_BURST.
   * @param {number} [opts.claimRefillMs]   Override CLAIM_REFILL_MS.
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
    const seatOrder = []
    for (const w of opts.writers) {
      if (!isHexKey(w)) throw new Error('SignedLog: bad writer pubkey: ' + w)
      const lw = w.toLowerCase()
      if (!writers.has(lw)) seatOrder.push(lw)
      writers.add(lw)
    }

    const maxSeats = opts.maxSeats == null ? writers.size : opts.maxSeats
    if (!Number.isInteger(maxSeats) || maxSeats < writers.size) {
      throw new Error('SignedLog: maxSeats must be an integer >= genesis writer count')
    }
    const genesis = (opts.genesis == null ? seatOrder[0] : String(opts.genesis).toLowerCase())
    if (!isHexKey(genesis) || !writers.has(genesis)) {
      throw new Error('SignedLog: genesis must be one of the genesis writers')
    }

    this.tableKey = opts.tableKey.toLowerCase()
    this.writers = writers
    this.maxSeats = maxSeats
    this.genesis = genesis
    this.maxEntries = opts.maxEntries || DEFAULT_MAX_ENTRIES
    this.tsSkewMs = opts.tsSkewMs || TS_SKEW_MS
    this.claimBurst = opts.claimBurst || CLAIM_BURST
    this.claimRefillMs = opts.claimRefillMs || CLAIM_REFILL_MS
    this._log = opts.log || (() => {})

    /** @type {object[]} Append-only entries; index is the global log index. */
    this.entries = []
    /** @type {Map<string, number>} writer pubkey → last accepted seq. */
    this._lastSeq = new Map()
    /** @type {Map<number, string>} seat index → occupant writer pubkey. */
    this._seats = new Map()
    /** @type {Map<string, number>} occupant writer pubkey → seat index. */
    this._seatOf = new Map()
    /** @type {Map<string, {tokens:number, ts:number}>} claim-seat rate buckets. */
    this._claimBuckets = new Map()
    /** @type {Set<Function>} subscribers — see subscribe(). */
    this._subscribers = new Set()
    /** @type {number} Wall-clock at construction; used in state(). */
    this.createdAt = Date.now()
    /** @type {?number} Wall-clock of the last accepted entry. */
    this.lastTs = null

    // Seat the genesis writers deterministically at seats 0..n-1 in the order
    // they were supplied. Strangers then claim any remaining free seat.
    for (let i = 0; i < seatOrder.length; i++) {
      this._seats.set(i, seatOrder[i])
      this._seatOf.set(seatOrder[i], i)
    }
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

    // 1b. Control-entry shape (open-join). `kind` rides in the ENVELOPE, never
    //     in payload, so the relay stays card-blind while still able to act on
    //     seat admission. An entry with no `kind` is an ordinary game action.
    const kind = entry.kind == null ? null : entry.kind
    if (kind !== null) {
      if (typeof kind !== 'string') return reject(REJECT.BAD_SHAPE, 'kind')
      if (kind === KIND.CLAIM_SEAT) {
        if (!Number.isInteger(entry.seat) || entry.seat < 0) return reject(REJECT.BAD_SHAPE, 'seat')
      } else if (kind === KIND.REVOKE_SEAT) {
        if (typeof entry.target !== 'string' || !isHexKey(entry.target)) return reject(REJECT.BAD_SHAPE, 'target')
      } else {
        return reject(REJECT.BAD_SHAPE, 'unknown-kind')
      }
    }

    // 2. Table binding.
    if (entry.tableKey.toLowerCase() !== this.tableKey) return reject(REJECT.WRONG_TABLE, entry.tableKey)

    const writer = entry.writer.toLowerCase()

    // 3. Writer gate. `claim-seat` is the ONLY kind a not-yet-writer may
    //    append — every other kind (game actions, revoke-seat) still requires
    //    existing membership. This scoped relaxation is the delicate heart of
    //    open-join: keep it exactly this narrow or an unauthenticated peer
    //    could forge game state.
    if (kind === KIND.CLAIM_SEAT) {
      if (this.writers.has(writer)) return reject(REJECT.SEAT_TAKEN, 'already-seated')
      if (entry.seat >= this.maxSeats) return reject(REJECT.SEAT_INVALID, entry.seat)
    } else {
      if (!this.writers.has(writer)) return reject(REJECT.UNKNOWN_WRITER, writer)
      // Only the genesis (host) may kick.
      if (kind === KIND.REVOKE_SEAT && writer !== this.genesis) return reject(REJECT.NOT_GENESIS, writer)
    }

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

    // 6. Byte budget. Serialize once and reuse for sig verification. The
    //    canonical bytes bind kind/seat/target when present (see _canonicalEntry).
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
    const okSig = sodium.crypto_sign_verify_detached(sig, canonical, pub)
    if (!okSig) return reject(REJECT.BAD_SIG, 'verify')

    // 8. Admission, AFTER the signature so a forged `writer` field can neither
    //    probe live seat state nor drain a victim's rate bucket. A losing
    //    claim is rejected here and NEVER stored — that is what keeps the open
    //    self-claim path from being a log-storage flood: only winners persist.
    if (kind === KIND.CLAIM_SEAT) {
      if (!this._takeClaimToken(writer, now)) return reject(REJECT.RATE_LIMITED, writer)
      if (this._seats.has(entry.seat)) return reject(REJECT.SEAT_TAKEN, entry.seat)
      if (this.writers.size >= this.maxSeats) return reject(REJECT.TABLE_FULL, this.maxSeats)
    } else if (kind === KIND.REVOKE_SEAT) {
      const target = entry.target.toLowerCase()
      if (target === this.genesis) return reject(REJECT.NOT_GENESIS, 'cannot-revoke-genesis')
      if (!this.writers.has(target)) return reject(REJECT.BAD_SHAPE, 'target-not-writer')
    }

    // 9. Log bound.
    if (this.entries.length >= this.maxEntries) return reject(REJECT.LOG_FULL, this.maxEntries)

    // Accept. Freeze a defensive shallow copy so subscribers can't mutate
    // the canonical record, then apply any control effect (writer-set / seat
    // mutation) so the append gate and state() see it immediately.
    const frozen = Object.freeze({ ...entry, writer })
    const index = this.entries.length
    this.entries.push(frozen)
    this._lastSeq.set(writer, entry.seq)
    this.lastTs = entry.ts
    if (kind !== null) this._applyControl(frozen)

    // Emit. Subscriber errors are swallowed — we will not let a buggy
    // listener block the log.
    for (const fn of this._subscribers) {
      try { fn(frozen, index) } catch (err) { this._log('subscriber-error', { error: err && err.message }) }
    }

    return { ok: true, index, ts: entry.ts }
  }

  /**
   * Apply a control entry's effect on the derived writer-set / seat-map.
   * Called on the live path (after an accepted append) and on rehydrate
   * (_replay). Idempotent-safe for replay because the persisted log only ever
   * contains winning claims (losers were rejected at the gate, never stored).
   */
  _applyControl (entry) {
    const writer = entry.writer.toLowerCase()
    if (entry.kind === KIND.CLAIM_SEAT) {
      this.writers.add(writer)
      this._seats.set(entry.seat, writer)
      this._seatOf.set(writer, entry.seat)
    } else if (entry.kind === KIND.REVOKE_SEAT) {
      const target = String(entry.target).toLowerCase()
      this.writers.delete(target)
      const seat = this._seatOf.get(target)
      if (seat !== undefined) {
        this._seats.delete(seat)
        this._seatOf.delete(target)
      }
    }
  }

  /**
   * Per-author token bucket for claim-seat attempts. Refills one token every
   * claimRefillMs up to claimBurst. Returns true if a token was available (and
   * consumes it), false if rate-limited. Consumed only after signature checks.
   */
  _takeClaimToken (writer, now) {
    let b = this._claimBuckets.get(writer)
    if (!b) { b = { tokens: this.claimBurst, ts: now }; this._claimBuckets.set(writer, b) }
    const refill = Math.floor((now - b.ts) / this.claimRefillMs)
    if (refill > 0) {
      b.tokens = Math.min(this.claimBurst, b.tokens + refill)
      b.ts = now
    }
    if (b.tokens <= 0) return false
    b.tokens -= 1
    return true
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
    const seats = {}
    for (const [seat, w] of this._seats) seats[seat] = w
    return {
      tableKey: this.tableKey,
      createdAt: this.createdAt,
      lastTs: this.lastTs,
      lastIndex: this.entries.length - 1,
      length: this.entries.length,
      writers,
      // Open-join projection: current seat map, cap, and admission authority.
      // `open` is true when the table has room for claimers beyond its genesis.
      seats,
      maxSeats: this.maxSeats,
      genesis: this.genesis,
      open: this.maxSeats > this._seatOf.size
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
      const frozen = Object.freeze({ ...e, writer: e.writer.toLowerCase() })
      this.entries.push(frozen)
      this._lastSeq.set(e.writer.toLowerCase(), e.seq)
      this.lastTs = e.ts
      // Reconstruct the writer-set / seat-map from control entries so a
      // restarted relay derives the exact roster that was live before restart.
      if (e.kind != null) this._applyControl(frozen)
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
  // Control fields ride in the envelope and MUST be signature-bound so they
  // can't be stripped or forged. They're appended ONLY when present, so an
  // ordinary action entry (no kind) canonicalizes to the exact same 5-part
  // bytes as before — every pre-existing signature still verifies, zero
  // migration. Stripping `kind` from a signed claim-seat yields the 5-part
  // form, whose bytes differ from what was signed → BAD_SIG.
  const kind = entry.kind
  if (kind !== undefined && kind !== null && kind !== '') {
    parts.push('kind:' + String(kind))
    if (String(kind) === 'claim-seat') parts.push('seat:' + String(entry.seat))
    else if (String(kind) === 'revoke-seat') parts.push('target:' + String(entry.target).toLowerCase())
  }
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
