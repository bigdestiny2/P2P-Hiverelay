/**
 * PokerApp — relay-side substrate for turn-based, card-blind, signed-log
 * applications (poker is the first consumer; liar's dice, mafia, sealed-bid
 * markets fit the same shape).
 *
 * The relay's job here is intentionally narrow:
 *
 *   - Hold a per-table append-only SignedLog (see ./signed-log.js).
 *   - Enforce signature + per-writer ordering + clock skew + byte budget.
 *   - Serve `/state`, `/log?from=`, accept `/move`, emit subscriber events.
 *   - Pin the resulting log via the existing seeder + custody pipeline.
 *
 * The relay is **card-blind**: payloads are opaque. Hole cards, decryption
 * shares, shuffle proofs, action bytes — all of it is `entry.payload`, which
 * the relay never reads. Cryptographic hand evaluation happens in the
 * players' Pear apps, off the log.
 *
 * ─── Lifecycle ──────────────────────────────────────────────────────────────
 *
 *   const app = new PokerApp({ maxTables, defaultLifetimeMs })
 *   await app.start({ node: relayNode })       // ServiceProvider hook
 *   const table = app.createTable({ tableKey, writers })
 *   const r = app.submitEntry(tableKey, signedEntry)
 *   //   → { ok: true, index, ts } | { ok: false, reason, detail }
 *   const view = app.getLog(tableKey, fromIdx)
 *   const st = app.getState(tableKey)
 *   const off = app.subscribe(tableKey, entry => {...})
 *   await app.stop()
 *
 * The ServiceProvider methods (`manifest`, `start`, `stop`) match the
 * existing plugin-loader contract so PokerApp can be configured into a
 * relay via the same `plugins:` list operators already use.
 *
 * ─── Storage / persistence ──────────────────────────────────────────────────
 *
 * In-memory only. Production persistence is a separate concern wired by the
 * operator — they can:
 *
 *   a) Snapshot the log periodically and re-hydrate via `SignedLog._replay`.
 *   b) Mirror entries into a hypercore + replicate via the existing seeder.
 *   c) Mirror entries into an autobase (the architecture-doc preferred
 *      shape) so each player writes to their own core.
 *
 * The default `PokerApp` shipped here keeps tables in memory because the
 * substrate is the same regardless of persistence — making memory the
 * default keeps the MVP path simple and lets the operator pick the right
 * persistence for their workload without fighting the framework.
 *
 * ─── Why a "signed log" rather than "game state"? ───────────────────────────
 *
 * Server-authoritative game state (the hiveworm pattern) is wrong for poker:
 * the relay would have to see card values, which breaks the security model.
 * A signed log keeps the relay card-blind by construction. Any number of
 * other turn-based games with hidden-info structure (liar's dice, blind
 * auctions, secret-roles party games) fit the same shape, so the substrate
 * is named `PokerApp` for the consumer but is fundamentally generic.
 *
 * Renaming follow-up: when a second consumer lands, lift this to
 * `SignedLogApp` and have `PokerApp` extend it with poker-specific niceties
 * (default writer counts, schema hooks, dispute-evidence builders).
 */

import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import { SignedLog, REJECT } from './signed-log.js'
import { hashControlOptions, verifySignedLogControl } from './control-capability.js'

const DEFAULT_MAX_TABLES = 1024
const DEFAULT_TABLE_LIFETIME_MS = 24 * 60 * 60 * 1000 // 24h, see seeding-manifest 'session'
const DEFAULT_TABLE_REAPER_INTERVAL_MS = 5 * 60 * 1000 // every 5 min

export class PokerApp extends ServiceProvider {
  /**
   * @param {object} [opts]
   * @param {number} [opts.maxTables]            Soft cap on concurrent tables.
   * @param {number} [opts.defaultLifetimeMs]    Idle TTL for a table.
   * @param {number} [opts.reaperIntervalMs]     How often to evict idle tables.
   * @param {number} [opts.maxEntriesPerTable]   Forwarded to SignedLog.
   * @param {(label, info) => void} [opts.log]   Optional structured logger.
   */
  constructor (opts = {}) {
    super()
    this.maxTables = opts.maxTables || DEFAULT_MAX_TABLES
    this.defaultLifetimeMs = opts.defaultLifetimeMs || DEFAULT_TABLE_LIFETIME_MS
    this.reaperIntervalMs = opts.reaperIntervalMs || DEFAULT_TABLE_REAPER_INTERVAL_MS
    this.maxEntriesPerTable = opts.maxEntriesPerTable || undefined
    this._log = opts.log || (() => {})

    /** @type {Map<string, {log: SignedLog, options: object, idleAt: ?number}>} */
    this._tables = new Map()
    this._closedTables = new Map()
    /** @type {?ReturnType<typeof setInterval>} */
    this._reaper = null
    /** @type {?object} Relay node (set by start) for pubsub/seeder hooks. */
    this.node = null
  }

  // ─── ServiceProvider interface ────────────────────────────────────────────

  manifest () {
    return {
      name: 'poker',
      version: '0.2.0',
      description: 'Card-blind signed-log substrate for turn-based games',
      capabilities: [
        'createTable', 'submitEntry', 'getLog', 'getState', 'listTables',
        'createAuthorized', 'grantWriter', 'revokeWriter', 'closeAuthorized'
      ]
    }
  }

  /**
   * Wire up to the relay node. `context.node` is the RelayNode instance —
   * gives us pubsub for emitting table events the WS gateway can fan out.
   */
  async start (context = {}) {
    this.node = context.node || null
    this._reaper = setInterval(() => this._reap(), this.reaperIntervalMs)
    // unref so the reaper doesn't keep the process alive in tests.
    if (this._reaper.unref) this._reaper.unref()
  }

  async stop () {
    if (this._reaper) {
      clearInterval(this._reaper)
      this._reaper = null
    }
    this._tables.clear()
    this._closedTables.clear()
    this.node = null
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  /**
   * Register a new table. The caller (out-of-band) is responsible for
   * deciding the table's keypair and broadcasting the table key to invited
   * players via whatever pairing channel the app uses.
   *
   * @param {object} args
   * @param {string} args.tableKey      Hex pubkey identifying the table.
   * @param {string[]} args.writers     Allowed writer pubkeys (hex), N seats.
   * @param {object} [args.options]     App-level options (blinds, etc.) —
   *                                    OPAQUE to the relay; held verbatim.
   * @returns {object} Public table descriptor.
   */
  createTable (args) {
    if (!args || typeof args !== 'object') throw new Error('createTable: bad args')
    const requestedKey = String(args.tableKey).toLowerCase()
    if (this._closedTables.has(requestedKey)) {
      throw new Error('createTable: table closed')
    }
    if (this._tables.has(requestedKey)) {
      throw new Error('createTable: table already exists')
    }
    if (this._tables.size >= this.maxTables) {
      throw new Error('createTable: max tables reached')
    }
    const log = new SignedLog({
      tableKey: args.tableKey,
      writers: args.writers,
      maxEntries: this.maxEntriesPerTable,
      log: this._log
    })
    const record = {
      log,
      options: args.options ? deepFreeze(JSON.parse(JSON.stringify(args.options))) : {},
      idleAt: Date.now() + this.defaultLifetimeMs,
      authority: args.authority ? String(args.authority).toLowerCase() : null,
      controlRevision: Number.isSafeInteger(args.controlRevision) ? args.controlRevision : null
    }
    // Subscribe internally so any successful append resets the idle timer
    // and (optionally) publishes onto the node's pubsub for WS fan-out.
    log.subscribe((entry, index) => {
      record.idleAt = Date.now() + this.defaultLifetimeMs
      this._emit(log.tableKey, entry, index)
    })
    this._tables.set(log.tableKey, record)
    return this._publicDescriptor(log.tableKey, record)
  }

  createAuthorized (args) {
    if (!args || typeof args !== 'object') return { ok: false, reason: 'bad-control' }
    const checked = verifySignedLogControl(args.control, {
      action: 'create', tableKey: args.tableKey, revision: 0
    })
    if (!checked.ok) return checked
    const control = checked.control
    const writers = normalizeWriters(args.writers)
    if (!writers || JSON.stringify(writers) !== JSON.stringify(control.writers)) {
      return { ok: false, reason: 'control-writers-mismatch' }
    }
    if (hashControlOptions(args.options || {}) !== control.optionsHash) {
      return { ok: false, reason: 'control-options-mismatch' }
    }
    if (this._closedTables.has(control.tableKey)) return { ok: false, reason: 'table-closed' }
    // A legacy unsigned create could otherwise squat a public table key before
    // its owner arrives. Possession of the table secret proves authority, so an
    // authenticated create may replace only an unauthorised legacy placeholder.
    const existing = this._get(control.tableKey)
    if (existing && existing.authority) return { ok: false, reason: 'table-exists' }
    if (existing) this._tables.delete(control.tableKey)
    try {
      const table = this.createTable({
        tableKey: control.tableKey,
        writers,
        options: args.options,
        authority: control.authority,
        controlRevision: control.revision
      })
      return { ok: true, table }
    } catch (err) {
      return { ok: false, reason: createFailureReason(err) }
    }
  }

  grantWriter (args) {
    return this._applyWriterControl(args, 'grant')
  }

  revokeWriter (args) {
    return this._applyWriterControl(args, 'revoke')
  }

  closeAuthorized (args) {
    if (!args || typeof args !== 'object') return { ok: false, reason: 'bad-control' }
    const record = this._get(args.tableKey)
    if (!record) {
      const closed = this._closedTables.get(String(args.tableKey || '').toLowerCase())
      return closed ? { ok: true, already: true, closure: closed } : { ok: false, reason: 'no-such-table' }
    }
    if (!record.authority) return { ok: false, reason: 'control-unsupported' }
    const checked = verifySignedLogControl(args.control, {
      action: 'close',
      tableKey: record.log.tableKey,
      authority: record.authority,
      revision: record.controlRevision + 1
    })
    if (!checked.ok) return checked
    const closure = Object.freeze({
      tableKey: record.log.tableKey,
      authority: record.authority,
      revision: checked.control.revision,
      closedAt: Date.now(),
      control: checked.control
    })
    this._tables.delete(record.log.tableKey)
    this._closedTables.set(record.log.tableKey, closure)
    this._emitControl(record.log.tableKey, { type: 'closed', closure })
    return { ok: true, closure }
  }

  /**
   * Try to append a signed entry to a table's log.
   * Returns the SignedLog.append result verbatim.
   *
   * Dual-convention: the P2P service RPC dispatches every capability as
   * `method(params, context)` — a single params object — whereas the HTTP
   * adapter (and direct callers) pass positional args. When the first arg is
   * a params object we read the fields from it; otherwise we treat it as the
   * positional tableKey. This keeps poker reachable over BOTH transports.
   */
  submitEntry (tableKey, signedEntry) {
    if (tableKey && typeof tableKey === 'object') {
      signedEntry = tableKey.entry ?? tableKey.signedEntry ?? signedEntry
      tableKey = tableKey.tableKey
    }
    const record = this._get(tableKey)
    if (!record) {
      const key = typeof tableKey === 'string' ? tableKey.toLowerCase() : ''
      return { ok: false, reason: this._closedTables.has(key) ? 'table-closed' : 'no-such-table' }
    }
    return record.log.append(signedEntry)
  }

  /**
   * Read entries from `fromIdx`. Returns `{ from, to, entries }`.
   * Dual-convention (see submitEntry): accepts `{ tableKey, from, limit }`
   * from the service RPC as well as positional `(tableKey, from, limit)`.
   */
  getLog (tableKey, fromIdx = 0, limit = Infinity) {
    if (tableKey && typeof tableKey === 'object') {
      const p = tableKey
      tableKey = p.tableKey
      fromIdx = p.from ?? p.fromIdx ?? 0
      limit = p.limit ?? Infinity
    }
    const record = this._get(tableKey)
    if (!record) return null
    return record.log.slice(fromIdx, limit)
  }

  // Dual-convention (see submitEntry): accepts `{ tableKey }` or positional.
  getState (tableKey) {
    if (tableKey && typeof tableKey === 'object') tableKey = tableKey.tableKey
    const record = this._get(tableKey)
    if (!record) {
      const closure = this._closedTables.get(String(tableKey || '').toLowerCase())
      return closure ? { tableKey: closure.tableKey, closed: true, closure } : null
    }
    return {
      ...record.log.state(),
      options: record.options,
      idleAt: record.idleAt,
      authority: record.authority,
      controlRevision: record.controlRevision,
      closed: false
    }
  }

  /**
   * Subscribe to new entries for a single table. Returns an unsubscribe.
   */
  subscribe (tableKey, fn) {
    const record = this._get(tableKey)
    if (!record) throw new Error('subscribe: no such table')
    return record.log.subscribe(fn)
  }

  /**
   * Public list of tables — used by `/api/poker/tables`. We only return
   * the table key, writer count, and last-activity timestamp. App options
   * may leak game configuration so they're behind the per-table state read.
   */
  listTables () {
    const out = []
    for (const [key, record] of this._tables) {
      const st = record.log.state()
      out.push({
        tableKey: key,
        writers: st.writers ? Object.keys(st.writers).length : 0,
        lastTs: st.lastTs,
        length: st.length,
        idleAt: record.idleAt
      })
    }
    return out
  }

  /**
   * Manually drop a table — used by the operator UI or by app glue when a
   * hand finishes and the players want their ephemeral session cleared
   * sooner than the reaper would.
   */
  closeTable (tableKey) {
    return this._tables.delete(String(tableKey).toLowerCase())
  }

  _applyWriterControl (args, action) {
    if (!args || typeof args !== 'object') return { ok: false, reason: 'bad-control' }
    const record = this._get(args.tableKey)
    if (!record) return { ok: false, reason: 'no-such-table' }
    if (!record.authority) return { ok: false, reason: 'control-unsupported' }
    const checked = verifySignedLogControl(args.control, {
      action,
      tableKey: record.log.tableKey,
      authority: record.authority,
      revision: record.controlRevision + 1
    })
    if (!checked.ok) return checked
    const result = action === 'grant'
      ? record.log.addWriter(checked.control.writer)
      : record.log.removeWriter(checked.control.writer)
    if (!result.ok) return result
    record.controlRevision = checked.control.revision
    record.idleAt = Date.now() + this.defaultLifetimeMs
    this._emitControl(record.log.tableKey, { type: action, control: checked.control })
    return { ok: true, changed: result.changed, table: this._publicDescriptor(record.log.tableKey, record) }
  }

  /**
   * Rehydrate a table's log from an array of already-validated entries.
   * Used by persistence adapters at startup to replay a stored stream
   * into the in-memory SignedLog.
   *
   * SAFETY: the entries are NOT re-validated. The caller is responsible for
   * having validated them on the way INTO the store originally (this is the
   * standard pattern — validate at ingest, trust at hydrate). Only call
   * this from your own persistence layer, never from user input.
   *
   * @param {string} tableKey
   * @param {object[]} entries Entries in the same shape SignedLog.append
   *   accepts (already signed). Order matters — per-writer seq order must
   *   be preserved.
   * @returns {number} Number of entries replayed.
   */
  replayEntries (tableKey, entries) {
    const record = this._get(tableKey)
    if (!record) throw new Error('replayEntries: no such table')
    if (!Array.isArray(entries)) throw new Error('replayEntries: entries must be an array')
    record.log._replay(entries)
    return entries.length
  }

  // ─── Internal ─────────────────────────────────────────────────────────────

  _get (tableKey) {
    if (typeof tableKey !== 'string') return null
    return this._tables.get(tableKey.toLowerCase()) || null
  }

  /**
   * Public descriptor returned from createTable — same shape as listTables
   * entries plus the (opaque) options.
   */
  _publicDescriptor (tableKey, record) {
    const st = record.log.state()
    return {
      tableKey,
      writers: Array.from(record.log.writers),
      options: record.options,
      lastTs: st.lastTs,
      length: st.length,
      idleAt: record.idleAt,
      authority: record.authority,
      controlRevision: record.controlRevision
    }
  }

  /**
   * Fan a successful append out via the relay's pubsub if one exists.
   * Best-effort — failure to publish does not affect log state.
   *
   * Topic is PER-TABLE (`poker/<tableKey>`) so a subscriber receives only the
   * table it asked for via `client.subscribeService('poker', tableKey, …)` —
   * never a cross-table firehose. No new exposure: the same entries are already
   * readable from the open `GET /api/poker/<table>/log`, and card-blindness
   * holds because the payload stays whatever the players signed (the relay
   * neither reads nor adds to it). Only live appends are published — `_replay`
   * (hydration) does not notify subscribers, so restarts don't re-emit history.
   */
  _emit (tableKey, entry, index) {
    if (!this.node || !this.node.router || !this.node.router.pubsub) return
    try {
      this.node.router.pubsub.publish('poker/' + tableKey, { tableKey, index, entry })
    } catch (err) {
      this._log('emit-error', { error: err && err.message })
    }
  }

  _emitControl (tableKey, event) {
    if (!this.node || !this.node.router || !this.node.router.pubsub) return
    try {
      this.node.router.pubsub.publish('poker/control/' + tableKey, { tableKey, ...event })
    } catch (err) {
      this._log('control-emit-error', { error: err && err.message })
    }
  }

  /**
   * Periodic eviction of idle tables. A table whose idleAt has passed is
   * dropped from memory; the audit log can still be re-fetched from the
   * underlying seeder if the operator wired persistence (out of scope here).
   *
   * Idempotent — safe to call repeatedly. Doesn't throw on lookup misses.
   */
  _reap () {
    const now = Date.now()
    for (const [key, record] of this._tables) {
      if (record.idleAt && record.idleAt < now) {
        this._tables.delete(key)
        this._log('reaped', { tableKey: key })
      }
    }
    for (const [key, closure] of this._closedTables) {
      if (closure.control.expiresAt < now) this._closedTables.delete(key)
    }
  }
}

function normalizeWriters (writers) {
  if (!Array.isArray(writers) || writers.length === 0) return null
  const normalized = new Set()
  for (const writer of writers) {
    if (typeof writer !== 'string' || !/^[0-9a-f]{64}$/i.test(writer)) return null
    normalized.add(writer.toLowerCase())
  }
  return [...normalized].sort()
}

function createFailureReason (err) {
  const message = err && err.message ? err.message : ''
  if (message.includes('already exists')) return 'table-exists'
  if (message.includes('max tables')) return 'max-tables'
  return 'create-failed'
}

// Helper: deep-freeze a JSON-safe object so opaque app options can't be
// mutated through references handed back from getState.
function deepFreeze (o) {
  if (o === null || typeof o !== 'object') return o
  Object.freeze(o)
  for (const k of Object.keys(o)) deepFreeze(o[k])
  return o
}

export { REJECT }
export { SignedLog } from './signed-log.js'
export {
  CONTROL_CLOCK_SKEW_MS,
  MAX_CONTROL_VALIDITY_MS,
  SIGNED_LOG_CONTROL_ACTIONS,
  SIGNED_LOG_CONTROL_DOMAIN,
  SIGNED_LOG_CONTROL_VERSION,
  canonicalSignedLogControl,
  hashControlOptions,
  verifySignedLogControl
} from './control-capability.js'

// Verifiable hand-seed helpers. The relay stays card-blind; these let clients
// derive and check an unbiasable per-hand randomness anchor from the VRF
// service and fold it into their own mental-poker shuffle. See ./hand-seed.js.
export {
  handSeedAlpha,
  verifyHandSeed,
  handDeckOrder,
  combineBetas,
  HAND_SEED_DOMAIN,
  DECK_DOMAIN,
  DEFAULT_DECK_SIZE
} from './hand-seed.js'
