/**
 * Hypercore-backed persistence for PokerApp.
 *
 * Wraps a PokerApp so that every successfully-appended SignedLog entry is
 * also appended to a per-table Hypercore. On startup, the adapter rehydrates
 * each table's in-memory SignedLog from its Hypercore's blocks.
 *
 * ─── Why a hypercore (and not raw files)? ──────────────────────────────────
 *
 * Three things drop out for free once entries live in a Hypercore:
 *
 *   1. The relay's existing seeder / federation / custody-pipeline picks up
 *      the core via its key. No extra plumbing.
 *   2. The cancellation-contract (reliability v2) guarantees apply — a
 *      relay claiming to pin a table's history can't lie about it.
 *   3. Cross-relay replication is the same code path used for every other
 *      seeded core, including the partial-pin auto-heal work.
 *
 * ─── Storage layout ────────────────────────────────────────────────────────
 *
 * One hypercore per table, accessed via the corestore namespace:
 *
 *   store.get({ name: 'poker/<tableKey>' })
 *
 * Each block is a single signed entry, JSON-encoded as utf-8. We don't use
 * any binary framing on top — the SignedLog format already covers
 * everything the relay needs and JSON keeps debugging trivial.
 *
 * ─── Table provisioning ────────────────────────────────────────────────────
 *
 *   await persistence.createPersistentTable({ tableKey, writers, options })
 *
 * If a backing hypercore exists, its blocks are replayed into a fresh
 * SignedLog via PokerApp.replayEntries (which calls SignedLog._replay —
 * the trust-at-hydrate path). New entries then go through the normal
 * cryptographic check before being appended both to the in-memory log
 * and to the core. We never bypass validation on the live path — only
 * on the rehydrate-from-store path, and the store IS our own append
 * sink, so the entries it returns are entries we ourselves accepted.
 *
 * ─── What this is NOT ──────────────────────────────────────────────────────
 *
 * Not autobase. Not multi-writer in the corestore sense — one core per
 * table, the relay is the only one appending. The "multi-writer" property
 * of a poker table comes from multiple ed25519-signed entries within that
 * single linear core. (Autobase would be the right tool for a model where
 * every player has their own writer core and the table is a merge — that's
 * a bigger refactor for a follow-up.)
 *
 * ─── Failure modes ─────────────────────────────────────────────────────────
 *
 * If the core append fails after the in-memory append succeeded, the log is
 * ahead of disk. We emit a `mirror-error` event and continue — the in-memory
 * log is the source of truth for live play; missing-from-disk entries would
 * be re-published by clients on reconnect via re-submission (signed-log
 * idempotency: same writer + same seq = BAD_SEQ on the in-memory log so the
 * client knows it's already accepted, but the core append can be retried by
 * the operator's reconciliation pass — out of scope here).
 */

import { EventEmitter } from 'events'

const CORE_NAME_PREFIX = 'poker/'
const APPEND_TIMEOUT_MS = 5000

export class HypercorePersistence extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.pokerApp                A started PokerApp.
   * @param {object} opts.store                   A Corestore.
   * @param {(label, info) => void} [opts.log]    Optional logger.
   */
  constructor (opts) {
    super()
    if (!opts || !opts.pokerApp) throw new Error('HypercorePersistence: pokerApp required')
    if (!opts.store) throw new Error('HypercorePersistence: store required')
    this.pokerApp = opts.pokerApp
    this.store = opts.store
    this._log = opts.log || (() => {})
    /** @type {Map<string, { core: object, unsub: () => void }>} */
    this._mirrors = new Map()
    this._stopped = false
  }

  /**
   * Returns the core for a given table key, opening it if needed.
   * Idempotent — same key returns the same core.
   *
   * @param {string} tableKey hex
   * @returns {Promise<object>} Hypercore instance (ready()-ed)
   */
  async _coreFor (tableKey) {
    const key = String(tableKey).toLowerCase()
    const existing = this._mirrors.get(key)
    if (existing) return existing.core
    const core = this.store.get({ name: CORE_NAME_PREFIX + key })
    await core.ready()
    return core
  }

  /**
   * Open a core for `tableKey`, replay its blocks into a freshly-created
   * PokerApp table, then wire forward mirroring so new appends are saved.
   *
   * Returns the PokerApp table descriptor.
   *
   * Throws if the table already exists in the PokerApp — call closeTable
   * first (or let the reaper handle it) before re-provisioning.
   *
   * @param {object} args
   * @param {string} args.tableKey
   * @param {string[]} args.writers
   * @param {object} [args.options]
   */
  async createPersistentTable (args) {
    if (this._stopped) throw new Error('HypercorePersistence: stopped')
    const key = String(args.tableKey).toLowerCase()
    const core = await this._coreFor(key)

    // Create the in-memory table first so we have somewhere to replay into.
    const desc = this.pokerApp.createTable({
      tableKey: key,
      writers: args.writers,
      options: args.options
    })

    // Replay existing blocks. We deliberately read all at once — tables are
    // bounded in size by maxEntriesPerTable and this only runs at startup.
    const length = core.length
    if (length > 0) {
      const entries = []
      for (let i = 0; i < length; i++) {
        const block = await core.get(i)
        try {
          entries.push(JSON.parse(block.toString('utf8')))
        } catch (err) {
          // Corrupt block — give up rather than partially rehydrate, which
          // would leave per-writer cursors in a half-state.
          this.pokerApp.closeTable(key)
          throw new Error('HypercorePersistence: corrupt block ' + i + ': ' + err.message)
        }
      }
      this.pokerApp.replayEntries(key, entries)
      this.emit('hydrated', { tableKey: key, count: entries.length })
    }

    // Wire forward mirroring. Every successful in-memory append is queued
    // for core.append — failures are surfaced via 'mirror-error' but do
    // NOT roll back the in-memory append (the log is source of truth for
    // live play).
    const unsub = this.pokerApp.subscribe(key, (entry /*, index */) => {
      this._mirror(key, core, entry).catch((err) => {
        this.emit('mirror-error', { tableKey: key, error: err && err.message })
        this._log('mirror-error', { tableKey: key, error: err && err.message })
      })
    })

    this._mirrors.set(key, { core, unsub })
    return desc
  }

  /**
   * Stop mirroring for a single table. Does NOT close the core (it stays
   * available to the seeder for read), does NOT delete blocks, does NOT
   * close the PokerApp table (caller's responsibility).
   */
  detach (tableKey) {
    const key = String(tableKey).toLowerCase()
    const entry = this._mirrors.get(key)
    if (!entry) return false
    try { entry.unsub && entry.unsub() } catch {}
    this._mirrors.delete(key)
    return true
  }

  /**
   * Detach every table and mark the adapter stopped. Does NOT close the
   * underlying corestore (operator owns its lifecycle).
   */
  async stop () {
    this._stopped = true
    for (const [key, { unsub }] of this._mirrors) {
      try { unsub && unsub() } catch {}
      void key // referenced via key in the iteration above
    }
    this._mirrors.clear()
  }

  /**
   * Public list of currently-mirrored tables — useful for ops dashboards.
   */
  listMirrors () {
    const out = []
    for (const [tableKey, { core }] of this._mirrors) {
      out.push({
        tableKey,
        coreKey: core.key ? core.key.toString('hex') : null,
        length: core.length
      })
    }
    return out
  }

  // ─── Internal ─────────────────────────────────────────────────────────────

  /**
   * Append `entry` to the table's core. Wrapped in a timeout so a stalled
   * Hypercore doesn't pile up unbounded promises behind it.
   */
  async _mirror (tableKey, core, entry) {
    if (this._stopped) return
    const blob = Buffer.from(JSON.stringify(entry), 'utf8')
    let timer
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('append-timeout')), APPEND_TIMEOUT_MS)
    })
    try {
      await Promise.race([core.append(blob), timeout])
    } finally {
      clearTimeout(timer)
    }
  }
}

export { CORE_NAME_PREFIX }
