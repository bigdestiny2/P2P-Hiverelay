/**
 * Corestore-backed operation journal for OutboxLog.
 *
 * The OutboxLog engine stays synchronous for Peerit wire compatibility, so
 * this adapter is opened asynchronously before engine construction. Once ready,
 * it exposes the small sync journal surface the engine expects while mirroring
 * accepted journal entries into one named Hypercore.
 */

import { EventEmitter } from 'node:events'
import { positiveStorageBound } from 'p2p-hiverelay/config/storage-cap.js'

export const OUTBOXLOG_HYPERCORE_JOURNAL_NAME = 'outboxlog/operations'
export const OUTBOXLOG_HYPERCORE_APPEND_TIMEOUT_MS = 5000
export const OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME = 'outboxlog/outboxes/index'
export const OUTBOXLOG_OUTBOX_CORE_PREFIX = 'outboxlog/outboxes/'
export const OUTBOXLOG_PARTITIONED_INDEX_VERSION = 1
export const OUTBOXLOG_STORAGE_OPERATION_OVERHEAD_BYTES = 1024 * 1024
const OUTBOXLOG_STORAGE_LEDGER_KEY = 'outboxlog/storage-consumed-v1'

class JournalStorageController {
  constructor ({ authority, maxStorageBytes, key }) {
    this.authority = authority || null
    this.maxStorageBytes = positiveStorageBound(maxStorageBytes)
    this.key = key
    this.consumedBytes = 0
    this.actualBytes = 0
    this.cores = new Set()
    this.ledgerCore = null
    this.ownershipHandoff = null
    this.settlements = new Set()
  }

  get enabled () {
    return !!this.authority && this.maxStorageBytes !== null
  }

  initialize (actualBytes = 0) {
    if (!this.enabled) throw new Error('OutboxLog journal storage admission unavailable')
    const actual = Number(actualBytes)
    if (!Number.isSafeInteger(actual) || actual < 0 || actual > this.maxStorageBytes) {
      throw new Error('OutboxLog recovered storage exceeds aggregate bound')
    }
    const current = this.authority.get(this.key)
    if (current) {
      if (current.state !== 'committed' || current.boundBytes !== this.maxStorageBytes) {
        throw new Error('OutboxLog journal storage commitment mismatch')
      }
      if (!this.authority.reconcileActual(this.key, actual)) {
        throw new Error('OutboxLog recovered storage reconciliation failed')
      }
    } else {
      const reservation = this.authority.reserve(this.key, this.maxStorageBytes, {
        kind: 'outboxlog',
        measuredActualBytes: actual
      })
      if (!reservation.allowed) {
        const err = new Error('OutboxLog storage admission blocked: ' + (reservation.reason || 'unknown'))
        err.code = 'STORAGE_ADMISSION_BLOCKED'
        err.storageAdmission = reservation
        throw err
      }
      if (!this.authority.commit(reservation, { actualBytes: actual })) {
        this.authority.failClosed('outboxlog-aggregate-commitment-failed')
        const err = new Error('OutboxLog aggregate storage commitment failed')
        err.code = 'STORAGE_RESERVATION_COMMIT_FAILED'
        throw err
      }
    }
    this.actualBytes = Math.max(this.actualBytes, actual)
    this.consumedBytes = Math.max(this.consumedBytes, actual)
    this.ownershipHandoff = this.authority.issueOwnedHandoff(this.key)
    if (!this.ownershipHandoff) throw new Error('OutboxLog owned-core handoff unavailable')
  }

  reserve (encodedBytes, opts = {}) {
    if (!this.enabled) throw new Error('OutboxLog journal storage admission unavailable')
    const admission = this.authority.mutationAdmission()
    if (!admission.allowed) throw new Error('OutboxLog journal storage mutation blocked: ' + admission.reason)
    const encoded = Number(encodedBytes)
    if (!Number.isSafeInteger(encoded) || encoded < 0) throw new Error('OutboxLog journal append size invalid')
    const cost = encoded + OUTBOXLOG_STORAGE_OPERATION_OVERHEAD_BYTES
    const next = this.consumedBytes + cost
    if (!Number.isSafeInteger(next) || next > this.maxStorageBytes) throw new Error('OutboxLog journal maxStorageBytes exceeded')
    this.consumedBytes = next
    return { encoded, cost, dispatched: false, creation: opts.creation === true }
  }

  run (operation) {
    return this.authority.runMutation(operation)
  }

  registerCore (core) {
    if (core) this.cores.add(core)
  }

  async bindLedgerCore (core) {
    this.ledgerCore = core
    this.registerCore(core)
    if (typeof core.getUserData === 'function') {
      const raw = await core.getUserData(OUTBOXLOG_STORAGE_LEDGER_KEY)
      if (raw) {
        const value = Number(Buffer.from(raw).toString('utf8'))
        if (!Number.isSafeInteger(value) || value < 0 || value > this.maxStorageBytes) {
          throw new Error('OutboxLog storage ledger is corrupt')
        }
        this.consumedBytes = Math.max(this.consumedBytes, value)
      }
    }
  }

  assertWritable () {
    const admission = this.authority.mutationAdmission()
    if (!admission.allowed || !this.authority.validateOwnedHandoff(this.ownershipHandoff, this.key)) {
      throw new Error('OutboxLog journal storage mutation blocked: ' + (admission.reason || 'owned handoff invalid'))
    }
  }

  async persistDebt (opts = {}) {
    if (!opts.reconciliation) this.assertWritable()
    if (!this.ledgerCore || typeof this.ledgerCore.setUserData !== 'function') {
      throw new Error('OutboxLog durable storage ledger unavailable')
    }
    await this.ledgerCore.setUserData(OUTBOXLOG_STORAGE_LEDGER_KEY, Buffer.from(String(this.consumedBytes)))
  }

  markDispatched (operation) {
    this.assertWritable()
    operation.dispatched = true
  }

  trackSettlement (appendPromise) {
    const settlement = Promise.resolve(appendPromise).then(async value => {
      await this.reconcile()
      return value
    })
    this.settlements.add(settlement)
    settlement.then(
      () => this.settlements.delete(settlement),
      () => this.settlements.delete(settlement)
    )
    this.authority.trackMutation(settlement)
    return settlement
  }

  async drainSettlements (timeoutMs) {
    if (this.settlements.size === 0) return
    let timer = null
    try {
      await Promise.race([
        Promise.allSettled([...this.settlements]),
        new Promise((_resolve, reject) => {
          timer = setTimeout(() => {
            const err = new Error('OutboxLog append settlement timeout')
            err.code = 'OUTBOXLOG_APPEND_SETTLEMENT_TIMEOUT'
            reject(err)
          }, timeoutMs)
        })
      ])
    } catch (err) {
      this.authority.failClosed('outboxlog-append-settlement-timeout')
      throw err
    } finally {
      if (timer) clearTimeout(timer)
    }
  }

  async reconcile () {
    const actual = await this.measureExact()
    if (actual > this.maxStorageBytes || !this.authority.reconcileActual(this.key, actual)) {
      this.authority.failClosed('outboxlog-physical-bound-exceeded')
      throw new Error('OutboxLog journal physical storage bound exceeded')
    }
    this.actualBytes = Math.max(this.actualBytes, actual)
    this.consumedBytes = Math.max(this.consumedBytes, this.actualBytes)
    return actual
  }

  async measureExact () {
    let actual = 0
    for (const core of this.cores) {
      if (!core || typeof core.info !== 'function') throw new Error('OutboxLog exact core storage info unavailable')
      const info = await core.info({ storage: true })
      if (!info) throw new Error('OutboxLog exact core storage info unavailable')
      if (info.storage) {
        for (const value of Object.values(info.storage)) {
          const bytes = Number(value)
          if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error('OutboxLog exact core storage info invalid')
          actual += bytes
          if (!Number.isSafeInteger(actual)) throw new Error('OutboxLog exact core storage exceeds safe integer range')
        }
        continue
      }

      // Corestore 7 multiplexes cores into one shared database, so Hypercore
      // cannot attribute allocated files per core and reports storage:null.
      // Use the signed logical byteLength for this core in that layout. This
      // never releases capacity: the journal's monotonic durable ledger keeps
      // the conservative per-operation debt, the full aggregate commitment
      // remains charged, and StorageAdmissionAuthority independently measures
      // and enforces the complete Corestore tree's allocated bytes.
      const before = Number(core.byteLength ?? info.byteLength)
      const lengthBefore = Number(core.length ?? info.length)
      const after = Number(core.byteLength ?? info.byteLength)
      const lengthAfter = Number(core.length ?? info.length)
      if (!Number.isSafeInteger(before) || before < 0 || before !== after ||
          !Number.isSafeInteger(lengthBefore) || lengthBefore < 0 || lengthBefore !== lengthAfter) {
        throw new Error('OutboxLog exact core storage info invalid')
      }
      actual += after
      if (!Number.isSafeInteger(actual)) throw new Error('OutboxLog exact core storage exceeds safe integer range')
    }
    return actual
  }

  async complete () {
    await this.persistDebt({ reconciliation: true })
    const before = this.consumedBytes
    await this.reconcile()
    if (this.consumedBytes !== before) {
      await this.persistDebt({ reconciliation: true })
      await this.reconcile()
    }
  }

  abort (operation) {
    // Consumption is monotonic. Once an operation is admitted, its debt is
    // never returned because a timeout/rejection cannot prove the underlying
    // append did not become durable after Promise.race settled.
    if (operation.dispatched) this.authority.failClosed('outboxlog-append-outcome-ambiguous')
  }

  async create (open) {
    const operation = this.reserve(0, { creation: true })
    try {
      if (this.ledgerCore) await this.persistDebt()
      this.assertWritable()
      const core = await open()
      this.markDispatched(operation)
      this.registerCore(core)
      return core
    } catch (err) {
      this.abort(operation)
      throw err
    }
  }

  close () {
    if (!this.ownershipHandoff) return false
    const released = this.authority.releaseOwnedHandoff(this.ownershipHandoff)
    this.ownershipHandoff = null
    return released
  }
}

export async function createHypercoreOutboxJournal ({
  store = null,
  core = null,
  name = OUTBOXLOG_HYPERCORE_JOURNAL_NAME,
  appendTimeoutMs = OUTBOXLOG_HYPERCORE_APPEND_TIMEOUT_MS,
  log = () => {},
  storageAdmission = null,
  maxJournalStorageBytes = null,
  storageKey = null
} = {}) {
  const storageController = new JournalStorageController({
    authority: storageAdmission,
    maxStorageBytes: maxJournalStorageBytes,
    key: storageKey || `outboxlog:${name}`
  })
  if (!storageController.enabled) throw new Error('OutboxLogHypercoreJournal: storage admission required')
  let openedSuccessfully = false
  try {
    if (!core && store && typeof store.get === 'function') {
      core = await tryOpenExistingCore(store, { name })
    }
    if (core) {
      if (typeof core.ready === 'function') await core.ready()
      storageController.registerCore(core)
      await storageController.bindLedgerCore(core)
      storageController.initialize(await storageController.measureExact())
    } else {
      storageController.initialize()
    }
    if (!core) {
      if (!store || typeof store.get !== 'function') throw new Error('OutboxLogHypercoreJournal: store required')
      core = await storageController.create(async () => {
        const opened = store.get({ name })
        if (typeof opened.ready === 'function') await opened.ready()
        return opened
      })
    }
    if (!core || typeof core.append !== 'function' || typeof core.get !== 'function') {
      throw new Error('OutboxLogHypercoreJournal: core must expose append() and get()')
    }
    if (!storageController.ledgerCore) {
      if (typeof core.ready === 'function') await core.ready()
      storageController.registerCore(core)
      await storageController.bindLedgerCore(core)
    }
    await storageController.persistDebt()

    const entries = []
    const length = Number.isSafeInteger(core.length) && core.length > 0 ? core.length : 0
    for (let i = 0; i < length; i++) {
      const block = await core.get(i)
      entries.push(parseBlock(block, i))
    }
    await storageController.complete()

    openedSuccessfully = true
    return new HypercoreOutboxJournal({
      core,
      name,
      entries,
      appendTimeoutMs,
      log,
      storageController
    })
  } finally {
    if (!openedSuccessfully) storageController.close()
  }
}

export async function createPartitionedHypercoreOutboxJournal ({
  store = null,
  indexCore = null,
  indexName = OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME,
  coreNamePrefix = OUTBOXLOG_OUTBOX_CORE_PREFIX,
  appendTimeoutMs = OUTBOXLOG_HYPERCORE_APPEND_TIMEOUT_MS,
  log = () => {},
  storageAdmission = null,
  maxJournalStorageBytes = null,
  storageKey = null
} = {}) {
  if (!store || typeof store.get !== 'function') throw new Error('OutboxLogPartitionedHypercoreJournal: store required')
  const storageController = new JournalStorageController({
    authority: storageAdmission,
    maxStorageBytes: maxJournalStorageBytes,
    key: storageKey || `outboxlog:${indexName}`
  })
  if (!storageController.enabled) throw new Error('OutboxLogPartitionedHypercoreJournal: storage admission required')
  let openedSuccessfully = false
  try {
    if (!indexCore) indexCore = await tryOpenExistingCore(store, { name: indexName })
    const recovering = !!indexCore
    if (!recovering) storageController.initialize()
    if (!indexCore) {
      indexCore = await storageController.create(async () => {
        const core = store.get({ name: indexName })
        assertJournalCore(core, 'index core')
        await readyCore(core)
        return core
      })
    }
    assertJournalCore(indexCore, 'index core')
    await readyCore(indexCore)
    storageController.registerCore(indexCore)
    await storageController.bindLedgerCore(indexCore)

    const outboxes = new Map()
    const indexLength = Number.isSafeInteger(indexCore.length) && indexCore.length > 0 ? indexCore.length : 0
    for (let i = 0; i < indexLength; i++) {
      const meta = parseIndexBlock(await indexCore.get(i), i)
      const existing = outboxes.get(meta.appId)
      if (existing) {
        if (existing.name !== meta.coreName) {
          throw new Error('OutboxLogPartitionedHypercoreJournal: conflicting index block ' + i + ' for ' + meta.appId)
        }
        continue
      }
      const core = recovering
        ? await tryOpenExistingCore(store, { name: meta.coreName })
        : store.get({ name: meta.coreName })
      if (!core) throw new Error('OutboxLogPartitionedHypercoreJournal: indexed outbox core missing for ' + meta.appId)
      assertJournalCore(core, 'outbox core ' + meta.appId)
      await readyCore(core)
      storageController.registerCore(core)
      assertJournalCore(core, 'outbox core ' + meta.appId)
      outboxes.set(meta.appId, {
        appId: meta.appId,
        inviteKey: meta.inviteKey,
        firstSeq: meta.firstSeq,
        name: meta.coreName,
        core,
        indexed: true
      })
    }

    const entries = []
    for (const [appId, outbox] of outboxes) {
      await readyCore(outbox.core)
      const length = Number.isSafeInteger(outbox.core.length) && outbox.core.length > 0 ? outbox.core.length : 0
      for (let i = 0; i < length; i++) {
        entries.push(parseOutboxBlock(await outbox.core.get(i), appId, i))
      }
    }
    entries.sort((a, b) => a.seq - b.seq)
    if (recovering) storageController.initialize(await storageController.measureExact())
    await storageController.persistDebt()
    await storageController.complete()

    openedSuccessfully = true
    return new PartitionedHypercoreOutboxJournal({
      store,
      indexCore,
      indexName,
      coreNamePrefix,
      outboxes,
      entries,
      appendTimeoutMs,
      log,
      storageController
    })
  } finally {
    if (!openedSuccessfully) storageController.close()
  }
}

export class HypercoreOutboxJournal extends EventEmitter {
  constructor ({ core, name, entries = [], appendTimeoutMs = OUTBOXLOG_HYPERCORE_APPEND_TIMEOUT_MS, log = () => {}, storageController = null }) {
    super()
    this.core = core
    this.name = name
    this.appendTimeoutMs = appendTimeoutMs
    this._entries = clone(entries)
    this._pending = Promise.resolve()
    this._errors = []
    this._log = log
    this.storageController = storageController
  }

  loadSync () {
    return clone(this._entries)
  }

  appendSync (entry) {
    const saved = clone(entry)
    const storageOperation = this.storageController.reserve(encodedJsonBytes(saved))
    this._entries.push(saved)
    const previous = this._pending
    const job = this.storageController.run(() => previous.then(
      async () => {
        await this.storageController.persistDebt()
        await appendWithTimeout(this.core, saved, this.appendTimeoutMs, this.storageController, storageOperation)
        await this.storageController.complete(storageOperation)
      },
      async () => {
        await this.storageController.persistDebt()
        await appendWithTimeout(this.core, saved, this.appendTimeoutMs, this.storageController, storageOperation)
        await this.storageController.complete(storageOperation)
      }
    ))
    this._pending = job.catch((err) => {
      try { this.storageController.abort(storageOperation) } catch (storageErr) { err = storageErr }
      const message = err && err.message ? err.message : String(err)
      this._errors.push(message)
      this.emit('append-error', { name: this.name, error: message })
      this._log('outboxlog-hypercore-journal-append-error', { name: this.name, error: message })
    })
  }

  async flush ({ throwOnError = true } = {}) {
    await this._pending
    if (throwOnError && this._errors.length > 0) {
      throw new Error('OutboxLogHypercoreJournal: append failed: ' + this._errors[this._errors.length - 1])
    }
  }

  async close () {
    if (this._closed) return
    this._closed = true
    await this.flush({ throwOnError: false })
    await this.storageController.drainSettlements(this.appendTimeoutMs)
    this.storageController.close()
  }

  info () {
    return {
      name: this.name,
      coreKey: coreKeyHex(this.core),
      length: Number.isSafeInteger(this.core.length) ? this.core.length : this._entries.length,
      buffered: this._entries.length,
      errors: this._errors.length
    }
  }
}

export class PartitionedHypercoreOutboxJournal extends EventEmitter {
  constructor ({
    store,
    indexCore,
    indexName = OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME,
    coreNamePrefix = OUTBOXLOG_OUTBOX_CORE_PREFIX,
    outboxes = new Map(),
    entries = [],
    appendTimeoutMs = OUTBOXLOG_HYPERCORE_APPEND_TIMEOUT_MS,
    log = () => {},
    storageController = null
  }) {
    super()
    this.store = store
    this.indexCore = indexCore
    this.indexName = indexName
    this.coreNamePrefix = coreNamePrefix
    this.appendTimeoutMs = appendTimeoutMs
    this._outboxes = new Map(outboxes)
    this._entries = clone(entries)
    this._pending = Promise.resolve()
    this._errors = []
    this._log = log
    this.storageController = storageController
    this._announcementSeeder = null
    this._announcedCoreKeys = new Set()
  }

  loadSync () {
    return clone(this._entries)
  }

  appendSync (entry) {
    const saved = clone(entry)
    const outbox = this._ensureOutbox(saved)
    const indexEntry = outbox.indexed ? null : indexMetadataFor(outbox, saved)
    const encodedBytes = encodedJsonBytes(saved) + (indexEntry ? encodedJsonBytes(indexEntry) : 0)
    const storageOperation = this.storageController.reserve(encodedBytes)
    this._entries.push(saved)
    const previous = this._pending
    const job = this.storageController.run(() => previous.then(
      () => this._appendPartitioned(saved, outbox, storageOperation),
      () => this._appendPartitioned(saved, outbox, storageOperation)
    ))
    this._pending = job.catch((err) => {
      try { this.storageController.abort(storageOperation) } catch (storageErr) { err = storageErr }
      this._recordError(outbox.name, err)
    })
  }

  async flush ({ throwOnError = true } = {}) {
    await this._pending
    if (throwOnError && this._errors.length > 0) {
      throw new Error('OutboxLogPartitionedHypercoreJournal: append failed: ' + this._errors[this._errors.length - 1])
    }
  }

  async close () {
    if (this._closed) return
    this._closed = true
    await this.flush({ throwOnError: false })
    await this.storageController.drainSettlements(this.appendTimeoutMs)
    await this.withdrawSeedCores()
    this.storageController.close()
  }

  info () {
    const outboxes = sortedOutboxes(this._outboxes).map((outbox) => ({
      appId: outbox.appId,
      name: outbox.name,
      coreKey: coreKeyHex(outbox.core),
      length: Number.isSafeInteger(outbox.core.length) ? outbox.core.length : 0,
      firstSeq: outbox.firstSeq,
      indexed: outbox.indexed === true
    }))
    return {
      mode: 'hypercore-outboxes',
      index: {
        name: this.indexName,
        coreKey: coreKeyHex(this.indexCore),
        length: Number.isSafeInteger(this.indexCore.length) ? this.indexCore.length : 0
      },
      outboxes,
      buffered: this._entries.length,
      errors: this._errors.length
    }
  }

  async seedCores (seeder, opts = {}) {
    if (!seeder || typeof seeder.announceAuthorityOwnedCore !== 'function' ||
        typeof seeder.withdrawAuthorityOwnedCore !== 'function') {
      throw new Error('OutboxLogPartitionedHypercoreJournal: revocable authority-owned core announcer required')
    }
    await this.flush()
    if (this._announcementSeeder && this._announcementSeeder !== seeder) {
      await this.withdrawSeedCores()
    }

    const seeded = []
    await this._seedCore(seeder, {
      role: 'index',
      name: this.indexName,
      core: this.indexCore
    }, seeded)
    for (const outbox of sortedOutboxes(this._outboxes)) {
      await this._seedCore(seeder, {
        role: 'outbox',
        appId: outbox.appId,
        name: outbox.name,
        core: outbox.core
      }, seeded)
    }
    return seeded
  }

  async withdrawSeedCores () {
    const seeder = this._announcementSeeder
    if (!seeder || this._announcedCoreKeys.size === 0) {
      this._announcementSeeder = null
      return false
    }
    let firstError = null
    for (const coreKey of [...this._announcedCoreKeys]) {
      try {
        await seeder.withdrawAuthorityOwnedCore(coreKey, this.storageController.ownershipHandoff)
        this._announcedCoreKeys.delete(coreKey)
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    if (firstError) throw firstError
    this._announcementSeeder = null
    return true
  }

  _ensureOutbox (entry) {
    let outbox = this._outboxes.get(entry.appId)
    if (outbox) {
      if (!outbox.inviteKey && entry.inviteKey) outbox.inviteKey = entry.inviteKey
      if (!Number.isSafeInteger(outbox.firstSeq) || entry.seq < outbox.firstSeq) outbox.firstSeq = entry.seq
      return outbox
    }
    const name = coreNameForOutbox(entry.appId, this.coreNamePrefix)
    outbox = {
      appId: entry.appId,
      inviteKey: entry.inviteKey,
      firstSeq: entry.seq,
      name,
      core: null,
      indexed: false
    }
    this._outboxes.set(entry.appId, outbox)
    return outbox
  }

  async _appendPartitioned (entry, outbox, storageOperation) {
    await this.storageController.persistDebt()
    await readyCore(this.indexCore)
    if (!outbox.core) {
      outbox.core = this.store.get({ name: outbox.name })
      assertJournalCore(outbox.core, 'outbox core ' + entry.appId)
    }
    await readyCore(outbox.core)
    this.storageController.registerCore(outbox.core)
    if (!outbox.indexed) {
      await appendWithTimeout(this.indexCore, indexMetadataFor(outbox, entry), this.appendTimeoutMs, this.storageController, storageOperation)
      outbox.indexed = true
    }
    await appendWithTimeout(outbox.core, entry, this.appendTimeoutMs, this.storageController, storageOperation)
    await this.storageController.complete(storageOperation)
  }

  async _seedCore (seeder, descriptor, seeded) {
    await readyCore(descriptor.core)
    const coreKey = coreKeyHex(descriptor.core)
    if (!coreKey) throw new Error('OutboxLogPartitionedHypercoreJournal: missing core key for ' + descriptor.name)
    await seeder.announceAuthorityOwnedCore(
      descriptor.core,
      this.storageController.ownershipHandoff,
      { role: descriptor.role, appId: descriptor.appId, name: descriptor.name }
    )
    this._announcementSeeder = seeder
    this._announcedCoreKeys.add(coreKey)
    seeded.push({
      role: descriptor.role,
      appId: descriptor.appId,
      name: descriptor.name,
      coreKey,
      maxStorageBytes: this.storageController.maxStorageBytes,
      length: Number.isSafeInteger(descriptor.core.length) ? descriptor.core.length : 0
    })
  }

  _recordError (name, err) {
    const message = err && err.message ? err.message : String(err)
    this._errors.push(message)
    this.emit('append-error', { name, error: message })
    this._log('outboxlog-partitioned-hypercore-journal-append-error', { name, error: message })
  }
}

export function coreNameForOutbox (appId, coreNamePrefix = OUTBOXLOG_OUTBOX_CORE_PREFIX) {
  if (typeof appId !== 'string' || !appId) throw new Error('OutboxLogPartitionedHypercoreJournal: appId required')
  return String(coreNamePrefix) + appId.toLowerCase()
}

async function appendWithTimeout (core, entry, timeoutMs, storageController, operation) {
  const blob = Buffer.from(JSON.stringify(entry), 'utf8')
  storageController.markDispatched(operation)
  let appendPromise
  try {
    appendPromise = Promise.resolve(core.append(blob))
  } catch (err) {
    appendPromise = Promise.reject(err)
  }
  storageController.trackSettlement(appendPromise)
  let timer
  const timeout = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error('append-timeout')), timeoutMs)
  })
  try {
    await Promise.race([appendPromise, timeout])
  } finally {
    clearTimeout(timer)
  }
}

function parseBlock (block, index) {
  return parseJsonBlock(block, index, 'OutboxLogHypercoreJournal: corrupt block ')
}

function parseIndexBlock (block, index) {
  const meta = parseJsonBlock(block, index, 'OutboxLogPartitionedHypercoreJournal: corrupt index block ')
  if (
    !meta ||
    meta.version !== OUTBOXLOG_PARTITIONED_INDEX_VERSION ||
    meta.kind !== 'outbox' ||
    typeof meta.appId !== 'string' ||
    !meta.appId ||
    typeof meta.inviteKey !== 'string' ||
    meta.inviteKey.length !== 64 ||
    !Number.isSafeInteger(meta.firstSeq) ||
    meta.firstSeq < 1 ||
    typeof meta.coreName !== 'string' ||
    !meta.coreName
  ) {
    throw new Error('OutboxLogPartitionedHypercoreJournal: bad index block ' + index)
  }
  return {
    version: meta.version,
    kind: meta.kind,
    appId: meta.appId,
    inviteKey: meta.inviteKey,
    firstSeq: meta.firstSeq,
    coreName: meta.coreName
  }
}

function parseOutboxBlock (block, appId, index) {
  const entry = parseJsonBlock(block, index, 'OutboxLogPartitionedHypercoreJournal: corrupt outbox block ')
  if (!entry || entry.appId !== appId) {
    throw new Error('OutboxLogPartitionedHypercoreJournal: bad outbox block ' + index + ' for ' + appId)
  }
  return entry
}

function parseJsonBlock (block, index, prefix) {
  try {
    return JSON.parse(Buffer.from(block).toString('utf8'))
  } catch (err) {
    throw new Error(prefix + index + ': ' + err.message)
  }
}

function indexMetadataFor (outbox, entry) {
  return {
    version: OUTBOXLOG_PARTITIONED_INDEX_VERSION,
    kind: 'outbox',
    appId: outbox.appId,
    inviteKey: entry.inviteKey,
    firstSeq: entry.seq,
    coreName: outbox.name
  }
}

function encodedJsonBytes (value) {
  return Buffer.byteLength(JSON.stringify(value), 'utf8')
}

function sortedOutboxes (outboxes) {
  return [...outboxes.values()].sort((a, b) => (a.appId < b.appId ? -1 : a.appId > b.appId ? 1 : 0))
}

function assertJournalCore (core, label) {
  if (!core || typeof core.append !== 'function' || typeof core.get !== 'function') {
    throw new Error('OutboxLogPartitionedHypercoreJournal: ' + label + ' must expose append() and get()')
  }
}

async function readyCore (core) {
  if (core && typeof core.ready === 'function') await core.ready()
}

async function tryOpenExistingCore (store, opts) {
  // Corestore's `get({ createIfMissing: false })` still allocates a Hypercore
  // session before its async existence check settles. When the core is absent,
  // ready() and close() both reject with STORAGE_EMPTY and that rejected
  // session can make the root Corestore's later close reject as well. Consult
  // Corestore's durable alias/index first so a normal first boot creates no
  // doomed session.
  if (opts?.name && store?.storage && typeof store.storage.getAlias === 'function') {
    if (typeof store.ready === 'function') await store.ready()
    const discoveryKey = await store.storage.getAlias({ name: opts.name, namespace: store.ns })
    if (!discoveryKey) return null
  } else if (opts?.discoveryKey && store?.storage && typeof store.storage.hasCore === 'function') {
    if (typeof store.ready === 'function') await store.ready()
    if (!await store.storage.hasCore(opts.discoveryKey)) return null
  }
  const core = store.get({ ...opts, createIfMissing: false })
  try {
    await readyCore(core)
    return core
  } catch (err) {
    if (!err || err.code !== 'STORAGE_EMPTY') throw err
    try { if (typeof core.close === 'function') await core.close() } catch (_) {}
    return null
  }
}

function coreKeyHex (core) {
  if (!core || !core.key) return null
  if (Buffer.isBuffer(core.key)) return core.key.toString('hex')
  if (typeof core.key.toString === 'function') return core.key.toString('hex')
  return null
}

function clone (value) {
  return JSON.parse(JSON.stringify(value))
}
