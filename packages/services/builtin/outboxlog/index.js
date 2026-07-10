import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import {
  DEFAULT_OUTBOXLOG_NAMESPACE,
  DEFAULT_OUTBOXLOG_SERVICE_VERSION,
  OUTBOXLOG_BLIND_SEAL_DEFAULT_ALG,
  OUTBOXLOG_BLIND_SEAL_VERSION,
  OUTBOXLOG_MAX_REPLAY_COMMIT_BYTES,
  canonicalOutboxRecord,
  createOutboxBlindSealedBody,
  createJsonFileOutboxPersistence,
  createJsonlOutboxJournal,
  createMemoryOutboxJournal,
  createMemoryOutboxPersistence,
  createOutboxNamespaceRegistry,
  createOutboxLog,
  createOutboxSignatureVerifier,
  isOutboxBlindRecord,
  isOutboxBlindSealedBody,
  verifyOutboxRecordSignature
} from './outbox-log.js'
import {
  createHypercoreOutboxJournal,
  createPartitionedHypercoreOutboxJournal
} from './hypercore-journal.js'
import { createOutboxSwarmHub } from './swarm-hub.js'
export {
  OUTBOXLOG_BLIND_SEAL_AAD_DOMAIN,
  OUTBOXLOG_BLIND_SEAL_AAD_VERSION,
  OUTBOXLOG_BLIND_SEAL_KEY_BYTES,
  OUTBOXLOG_BLIND_SEAL_NONCE_BYTES,
  OUTBOXLOG_BLIND_SEAL_TAG_BYTES,
  OUTBOXLOG_BLIND_KEY_ENVELOPE_ALG,
  OUTBOXLOG_BLIND_KEY_ENVELOPE_SEAL_BYTES,
  OUTBOXLOG_BLIND_KEY_ENVELOPE_VERSION,
  OUTBOXLOG_BLIND_RECIPIENT_DIRECTORY_DOMAIN,
  OUTBOXLOG_BLIND_RECIPIENT_DIRECTORY_VERSION,
  OUTBOXLOG_BLIND_RECIPIENT_PUBLIC_KEY_BYTES,
  OUTBOXLOG_BLIND_RECIPIENT_SECRET_KEY_BYTES,
  createOutboxBlindSealKey,
  createOutboxBlindSealAAD,
  createOutboxBlindRecipientKeyPair,
  createOutboxBlindRecipientDirectoryEntry,
  decodeOutboxBlindRecipientPublicKey,
  decodeOutboxBlindRecipientSecretKey,
  decodeOutboxBlindSealKey,
  encodeOutboxBlindRecipientPublicKey,
  encodeOutboxBlindRecipientSecretKey,
  encodeOutboxBlindSealKey,
  openOutboxBlindPayload,
  openOutboxBlindSealKeyEnvelope,
  verifyOutboxBlindRecipientDirectoryEntry,
  verifyOutboxBlindRecipientDirectoryRecord,
  verifyOutboxBlindRecipientDirectoryRotation,
  wrapOutboxBlindSealKey,
  sealOutboxBlindPayload
} from './blind-seal.js'

// Default re-affirm interval: re-hand the outbox cores to the fleet seeder
// every 10 minutes so a core created between ticks becomes fleet-durable, and
// re-affirmation survives seeder restarts. seedCore() is idempotent, so a
// re-affirm of an already-seeded core is cheap.
export const OUTBOXLOG_SEED_REAFFIRM_DEFAULT_MS = 600000
// Ghost-outbox sweep cadence: reclaim empty (never-appended) group slots older
// than the TTL, hourly by default, plus once at start(). Default ON — a swept
// group holds zero content and the client recreates its outbox on demand.
export const OUTBOXLOG_SWEEP_DEFAULT_TTL_MS = 24 * 60 * 60 * 1000
export const OUTBOXLOG_SWEEP_DEFAULT_INTERVAL_MS = 60 * 60 * 1000

function normalizeReaffirmMs (value, fallback) {
  const n = Number(value)
  if (Number.isFinite(n) && n >= 0) return Math.floor(n)
  return fallback
}

export class OutboxLogApp extends ServiceProvider {
  constructor (opts = {}) {
    super()
    this.engine = opts.engine || createOutboxLog(opts)
    this.sync = this.engine.sync
    this.swarm = opts.swarm || this.engine.swarm || createOutboxSwarmHub(opts)
    this.persistencePath = typeof opts.persistencePath === 'string' ? opts.persistencePath : null
    this.storagePath = typeof opts.storagePath === 'string' ? opts.storagePath : null
    this.journalPath = typeof opts.journalPath === 'string' ? opts.journalPath : null
    this.atomicOnlyRequested = opts.legacyWrites === false
    this.persistenceDisabled = opts.persistence === false
    this.journal = opts.journal || null
    this.node = null
    // Periodic re-affirm interval (ms) for handing the hypercore-outboxes
    // journal cores to the fleet seeder. 0 disables the periodic re-affirm
    // (the one-shot initial seed still runs). Default 10 minutes.
    this.seedReaffirmMs = normalizeReaffirmMs(opts.seedReaffirmMs, OUTBOXLOG_SEED_REAFFIRM_DEFAULT_MS)
    this._seedTimer = null
    // Ghost-outbox sweep (see outbox-log.js sweepGhosts). opts.sweep === false
    // disables; ttl/interval overridable here and via config.outboxlog.sweep.
    this.sweepEnabled = opts.sweep !== false
    this.sweepTtlMs = normalizeReaffirmMs(opts.sweepTtlMs, OUTBOXLOG_SWEEP_DEFAULT_TTL_MS)
    this.sweepIntervalMs = normalizeReaffirmMs(opts.sweepIntervalMs, OUTBOXLOG_SWEEP_DEFAULT_INTERVAL_MS)
    this._sweepTimer = null
    this._stopRequested = false
    this._stopped = false
    this._swarmDestroyed = false
  }

  manifest () {
    return {
      name: 'outboxlog',
      version: '0.1.0',
      description: 'Single-writer signed outbox log with Peerit relay wire compatibility',
      capabilities: ['outboxlog.sync', 'outboxlog.commit', 'outboxlog.directory', 'outboxlog.events', 'outboxlog.namespaces']
    }
  }

  async start (context = {}) {
    this.node = context.node || null
    const config = context && context.config && typeof context.config === 'object' ? context.config : {}
    const outboxlog = config.outboxlog && typeof config.outboxlog === 'object' ? config.outboxlog : {}
    if (outboxlog.legacyWrites !== undefined && this.engine.configureLegacyWrites) {
      this.engine.configureLegacyWrites(outboxlog.legacyWrites)
    }
    if (outboxlog.seedReaffirmMs !== undefined) {
      this.seedReaffirmMs = normalizeReaffirmMs(outboxlog.seedReaffirmMs, this.seedReaffirmMs)
    }
    if (this.engine.configureNamespaces && (outboxlog.namespaces || typeof outboxlog.namespace === 'string')) {
      this.engine.configureNamespaces({
        namespace: typeof outboxlog.namespace === 'string' ? outboxlog.namespace : DEFAULT_OUTBOXLOG_NAMESPACE,
        namespaces: outboxlog.namespaces || null
      })
    }
    const usePartitionedHypercoreJournal = outboxlog.journal === 'hypercore-outboxes' ||
        outboxlog.persistence === 'hypercore-outboxes' ||
        outboxlog.perOutboxHypercore === true
    const useHypercoreJournal = usePartitionedHypercoreJournal ||
        outboxlog.journal === 'hypercore' ||
        outboxlog.persistence === 'hypercore' ||
        outboxlog.hypercore === true
    const configuredJournalPath = this.journalPath || (typeof outboxlog.journalPath === 'string' ? outboxlog.journalPath : null)
    if (!this.persistenceDisabled && this.engine.configurePersistence) {
      let journal = null
      if (usePartitionedHypercoreJournal) {
        journal = await createPartitionedHypercoreOutboxJournal({
          store: context.store || (context.node && context.node.store) || null,
          indexName: typeof outboxlog.indexName === 'string'
            ? outboxlog.indexName
            : (typeof outboxlog.journalName === 'string' ? outboxlog.journalName : undefined),
          coreNamePrefix: typeof outboxlog.outboxCorePrefix === 'string' ? outboxlog.outboxCorePrefix : undefined
        })
      } else if (useHypercoreJournal) {
        journal = await createHypercoreOutboxJournal({
          store: context.store || (context.node && context.node.store) || null,
          name: typeof outboxlog.journalName === 'string' ? outboxlog.journalName : undefined
        })
      }
      const configured = this.engine.configurePersistence({
        persistencePath: useHypercoreJournal ? null : this.persistencePath || (typeof outboxlog.persistencePath === 'string' ? outboxlog.persistencePath : null),
        journal,
        journalPath: useHypercoreJournal ? null : configuredJournalPath,
        storagePath: useHypercoreJournal ? null : this.storagePath || (typeof config.storage === 'string' ? config.storage : null)
      })
      if (journal && configured !== false) this.journal = journal
    }
    const capabilities = this.sync && typeof this.sync.capabilities === 'function' ? this.sync.capabilities() : null
    const atomicOnly = this.atomicOnlyRequested || outboxlog.legacyWrites === false || (
      capabilities && capabilities.legacyWrites &&
      capabilities.legacyWrites.create === false && capabilities.legacyWrites.append === false
    )
    if (atomicOnly) {
      if (this.persistenceDisabled || useHypercoreJournal || !configuredJournalPath) {
        throw new Error('OutboxLog: atomic-only mode requires a durable JSONL journalPath')
      }
      if (typeof this.engine.assertAtomicWriteReady === 'function') {
        this.engine.assertAtomicWriteReady({ requireFsyncedPath: true })
      } else if (!capabilities || capabilities.ready !== true || !capabilities.atomicCommit || capabilities.atomicCommit.durable !== true || capabilities.atomicCommit.ready !== true) {
        throw new Error('OutboxLog: atomic-only mode failed durable journal readiness')
      }
    }
    await this._startFleetSeeding()
    this._startGhostSweep(outboxlog)
  }

  // Startup + periodic ghost sweep. Runs AFTER persistence is configured (the
  // journal/snapshot state is loaded by then), so the very first tick reclaims
  // the churn-era backlog without waiting an interval. Config shape:
  //   outboxlog.sweep: false | { enabled, ttlMs, intervalMs }
  _startGhostSweep (outboxlogConfig = {}) {
    const cfg = outboxlogConfig && outboxlogConfig.sweep
    if (cfg === false) this.sweepEnabled = false
    else if (cfg && typeof cfg === 'object') {
      if (cfg.enabled === false) this.sweepEnabled = false
      this.sweepTtlMs = normalizeReaffirmMs(cfg.ttlMs, this.sweepTtlMs)
      this.sweepIntervalMs = normalizeReaffirmMs(cfg.intervalMs, this.sweepIntervalMs)
    }
    if (!this.sweepEnabled || typeof this.engine.sweepGhosts !== 'function') return
    this._safeSweep()
    if (this.sweepIntervalMs > 0 && !this._sweepTimer) {
      this._sweepTimer = setInterval(() => { this._safeSweep() }, this.sweepIntervalMs)
      if (this._sweepTimer && typeof this._sweepTimer.unref === 'function') this._sweepTimer.unref()
    }
  }

  // Sweep, catching + logging any error so a transient persistence failure
  // never crashes start() or the periodic loop.
  _safeSweep () {
    try {
      const res = this.engine.sweepGhosts({ ttlMs: this.sweepTtlMs })
      if (res && res.swept > 0) {
        this._logSeedInfo('[outboxlog] ghost sweep: reclaimed ' + res.swept + ' empty group slot(s), pruned ' + res.descriptorsPruned + ' stale descriptor(s), ' + res.remaining + ' group(s) remain')
      }
      return res
    } catch (err) {
      this._logSeedWarn('[outboxlog] ghost sweep failed (will retry next interval): ' + (err && err.message ? err.message : err))
      return null
    }
  }

  // Hand the hypercore-outboxes journal cores to the fleet seeder so the log is
  // fleet-durable (not just single-relay-durable). No-op unless the journal is
  // in hypercore-outboxes mode. Never throws — the relay must still start.
  async _startFleetSeeding () {
    if (!this.journal || typeof this.journal.seedCores !== 'function') return
    const seeder = this.node && this.node.seeder
    if (!seeder || typeof seeder.seedCore !== 'function') {
      this._logSeedWarn('[outboxlog] hypercore journal configured but node.seeder unavailable — outbox cores will NOT be fleet-durable; enable relay seeding')
      return
    }
    // Initial one-shot seed (awaited so the log is fleet-durable by the time
    // start() resolves; failure is caught inside _safeSeed and is non-fatal).
    await this._safeSeed()
    // Periodic re-affirm so cores created between ticks become fleet-durable and
    // pins survive seeder restarts. seedCore() is idempotent (cheap re-affirm).
    if (this.seedReaffirmMs > 0 && !this._seedTimer) {
      this._seedTimer = setInterval(() => { this._safeSeed() }, this.seedReaffirmMs)
      // Long-running relay: the timer must not hold the process open.
      if (this._seedTimer && typeof this._seedTimer.unref === 'function') this._seedTimer.unref()
    }
  }

  // Seed all persistence cores, catching + logging any error so a transient
  // seed failure never crashes start() or the re-affirm loop.
  async _safeSeed () {
    try {
      const seeded = await this.seedPersistenceCores()
      this._logSeedInfo('[outboxlog] seeded ' + (Array.isArray(seeded) ? seeded.length : 0) + ' persistence core(s) to fleet seeder')
      return seeded
    } catch (err) {
      this._logSeedWarn('[outboxlog] failed to seed persistence cores to fleet seeder: ' + (err && err.message ? err.message : err))
      return []
    }
  }

  // Overridable log sinks (tests capture these; default to console).
  _logSeedWarn (msg) {
    if (typeof console !== 'undefined' && typeof console.warn === 'function') console.warn(msg)
  }

  _logSeedInfo (msg) {
    if (typeof console !== 'undefined' && typeof console.debug === 'function') console.debug(msg)
  }

  async stop () {
    if (this._stopped) return
    if (this._seedTimer) {
      clearInterval(this._seedTimer)
      this._seedTimer = null
    }
    if (this._sweepTimer) {
      clearInterval(this._sweepTimer)
      this._sweepTimer = null
    }
    const shouldFlush = !this._stopRequested
    this._stopRequested = true
    let failure = null
    let closeSucceeded = false
    try {
      if (shouldFlush && this.engine.flush) await this.engine.flush()
    } catch (err) {
      failure = err
    } finally {
      try {
        // Release exclusive JSONL ownership even when a fenced/failed flush
        // reports an error; a failed release remains retryable on stop().
        if (this.engine.close) await this.engine.close()
        closeSucceeded = true
      } catch (err) {
        if (!failure) failure = err
      } finally {
        // Teardown must still complete if ownership release reports an error.
        if (!this._swarmDestroyed && this.swarm && typeof this.swarm.destroy === 'function') {
          this.swarm.destroy()
          this._swarmDestroyed = true
        }
        this.node = null
      }
    }
    if (closeSucceeded) this._stopped = true
    if (failure) throw failure
  }

  create (appId, opts = {}) {
    if (appId && typeof appId === 'object') {
      opts = { namespace: appId.namespace }
      appId = appId.appId
    }
    return this.sync.create(appId, opts)
  }

  join (appId, inviteKey) {
    if (appId && typeof appId === 'object') {
      inviteKey = appId.inviteKey
      appId = appId.appId
    }
    return this.sync.join(appId, inviteKey)
  }

  append (appId, op) {
    if (appId && typeof appId === 'object') {
      op = appId.op
      appId = appId.appId
    }
    return this.sync.append(appId, op)
  }

  commit (appId, commit) {
    if (appId && typeof appId === 'object') {
      commit = appId.commit
      appId = appId.appId
    }
    return this.sync.commit(appId, commit)
  }

  capabilities () {
    return this.sync.capabilities()
  }

  get (appId, key) {
    if (appId && typeof appId === 'object') {
      key = appId.key
      appId = appId.appId
    }
    return this.sync.get(appId, key)
  }

  list (appId, prefix, opts = {}) {
    if (appId && typeof appId === 'object') {
      opts = appId.opts || {}
      prefix = appId.prefix
      appId = appId.appId
    }
    return this.sync.list(appId, prefix, opts)
  }

  range (appId, opts = {}) {
    if (appId && typeof appId === 'object') {
      opts = appId.opts || appId
      appId = appId.appId
    }
    return this.sync.range(appId, opts)
  }

  count (appId, prefix) {
    if (appId && typeof appId === 'object') {
      prefix = appId.prefix
      appId = appId.appId
    }
    return this.sync.count(appId, prefix)
  }

  status (appId) {
    if (appId && typeof appId === 'object') appId = appId.appId
    return this.sync.status(appId)
  }

  heads (appIds) {
    if (appIds && typeof appIds === 'object' && !Array.isArray(appIds)) appIds = appIds.appIds
    return this.sync.heads(appIds)
  }

  directory (opts = {}) {
    return this.sync.directory(opts)
  }

  events (appId, opts = {}) {
    if (appId && typeof appId === 'object') {
      opts = appId.opts || appId
      appId = appId.appId
    }
    return this.sync.events(appId, opts)
  }

  subscribe (appId, opts, fn) {
    return this.engine.subscribe(appId, opts, fn)
  }

  journalInfo () {
    return this.journal && typeof this.journal.info === 'function' ? this.journal.info() : null
  }

  namespaces () {
    return this.engine.namespaces ? this.engine.namespaces() : []
  }

  // Operator takedown surface (DO-NOT-SERVE by opaque record id). Suppresses a
  // record from serve-time reads without reading/deleting its content. The
  // record still exists in storage; restore() reverses it.
  takedown (appId, key) {
    if (appId && typeof appId === 'object') {
      key = appId.key
      appId = appId.appId
    }
    return this.sync.takedown(appId, key)
  }

  restore (appId, key) {
    if (appId && typeof appId === 'object') {
      key = appId.key
      appId = appId.appId
    }
    return this.sync.restore(appId, key)
  }

  takedowns () {
    return this.sync.takedowns ? this.sync.takedowns() : { takedowns: [], count: 0 }
  }

  async seedPersistenceCores (seeder = this.node && this.node.seeder) {
    if (!this.journal || typeof this.journal.seedCores !== 'function') return []
    return this.journal.seedCores(seeder)
  }
}

export {
  DEFAULT_OUTBOXLOG_NAMESPACE,
  DEFAULT_OUTBOXLOG_SERVICE_VERSION,
  OUTBOXLOG_BLIND_SEAL_DEFAULT_ALG,
  OUTBOXLOG_BLIND_SEAL_VERSION,
  OUTBOXLOG_MAX_REPLAY_COMMIT_BYTES,
  canonicalOutboxRecord,
  createOutboxBlindSealedBody,
  createJsonFileOutboxPersistence,
  createJsonlOutboxJournal,
  createMemoryOutboxJournal,
  createMemoryOutboxPersistence,
  createOutboxNamespaceRegistry,
  createOutboxLog,
  createOutboxSignatureVerifier,
  isOutboxBlindRecord,
  isOutboxBlindSealedBody,
  verifyOutboxRecordSignature
}

export {
  OUTBOXLOG_OUTBOX_CORE_PREFIX,
  OUTBOXLOG_PARTITIONED_INDEX_VERSION,
  OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME,
  coreNameForOutbox,
  createHypercoreOutboxJournal,
  createPartitionedHypercoreOutboxJournal
} from './hypercore-journal.js'
export { createOutboxSwarmHub }
