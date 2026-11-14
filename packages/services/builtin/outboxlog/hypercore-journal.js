/**
 * Corestore-backed operation journal for OutboxLog.
 *
 * The OutboxLog engine stays synchronous for Peerit wire compatibility, so
 * this adapter is opened asynchronously before engine construction. Once ready,
 * it exposes the small sync journal surface the engine expects while mirroring
 * accepted journal entries into one named Hypercore.
 */

import { EventEmitter } from 'node:events'
import Hypercore from 'hypercore'
import { createHash } from 'node:crypto'
import { constants as fsConstants, openSync, fstatSync, readSync, closeSync } from 'node:fs'
import { isAbsolute } from 'node:path'
import { positiveStorageBound } from 'p2p-hiverelay/config/storage-cap.js'
import { sharedCoreInfo, sharedOperationFlights } from 'p2p-hiverelay/core/shared-flight-registry.js'
import { normalizeJournalEntry } from './outbox-log.js'

export const OUTBOXLOG_HYPERCORE_JOURNAL_NAME = 'outboxlog/operations'
export const OUTBOXLOG_HYPERCORE_APPEND_TIMEOUT_MS = 5000
export const OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME = 'outboxlog/outboxes/index'
export const OUTBOXLOG_OUTBOX_CORE_PREFIX = 'outboxlog/outboxes/'
export const OUTBOXLOG_PARTITIONED_INDEX_VERSION = 1
export const OUTBOXLOG_STORAGE_OPERATION_OVERHEAD_BYTES = 1024 * 1024
const OUTBOXLOG_STORAGE_LEDGER_KEY = 'outboxlog/storage-consumed-v1'
export const OUTBOXLOG_STORAGE_COMMITMENT_KEY = 'outboxlog/storage-commitment-v1'
const MAX_COMMITMENT_RECORD_BYTES = 16 * 1024

class JournalStorageController {
  constructor ({ authority, maxStorageBytes, key, identity }) {
    this.authority = authority || null
    this.maxStorageBytes = positiveStorageBound(maxStorageBytes)
    this.key = key
    this.identity = identity
    this.durableCommitment = null
    this.recoveryIdentityVerified = false
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
    this.validateRecoveredBytes(actual)
    const recover = this.durableCommitment && this.recoveryIdentityVerified
    const current = this.authority.get(this.key)
    if (current) {
      if (current.state !== 'committed' || current.boundBytes !== this.maxStorageBytes) {
        throw new Error('OutboxLog journal storage commitment mismatch')
      }
      if (!this.authority.reconcileActual(this.key, actual)) {
        throw new Error('OutboxLog recovered storage reconciliation failed')
      }
    } else {
      const reservation = recover
        ? this.authority.recoverOutboxJournal(this.key, this.maxStorageBytes, actual)
        : this.authority.reserve(this.key, this.maxStorageBytes, {
          kind: 'outboxlog',
          measuredActualBytes: actual
        })
      if (!reservation.allowed) {
        const err = new Error('OutboxLog storage admission blocked: ' + (reservation.reason || 'unknown'))
        err.code = 'STORAGE_ADMISSION_BLOCKED'
        err.storageAdmission = reservation
        throw err
      }
      if (!recover && !this.authority.commit(reservation, { actualBytes: actual })) {
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

  validateRecoveredBytes (actual) {
    if (!Number.isSafeInteger(actual) || actual < 0 || actual > this.maxStorageBytes) {
      throw new Error('OutboxLog recovered storage exceeds aggregate bound')
    }
    if (this.durableCommitment && actual > this.consumedBytes) {
      throw new Error('OutboxLog recovered storage exceeds durable debt')
    }
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
        if (!Number.isSafeInteger(value) || value < 0 || value > this.maxStorageBytes ||
            Buffer.from(raw).toString('utf8') !== String(value)) {
          throw new Error('OutboxLog storage ledger is corrupt')
        }
        this.consumedBytes = Math.max(this.consumedBytes, value)
      }
      const commitment = await core.getUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY)
      if (commitment) {
        const bytes = Buffer.from(commitment)
        if (bytes.byteLength > MAX_COMMITMENT_RECORD_BYTES) throw new Error('OutboxLog storage commitment is corrupt')
        let record
        try { record = JSON.parse(bytes.toString('utf8')) } catch (_) {
          throw new Error('OutboxLog storage commitment is corrupt')
        }
        const expected = this.commitmentRecord(record?.consumedBytes)
        if (!Number.isSafeInteger(record?.consumedBytes) || record.consumedBytes < 0 ||
            record.consumedBytes > this.maxStorageBytes ||
            bytes.toString('utf8') !== JSON.stringify(expected) || !raw ||
            record.consumedBytes !== this.consumedBytes) {
          throw new Error('OutboxLog storage commitment mismatch or incomplete ledger')
        }
        this.durableCommitment = record
      }
    }
  }

  commitmentRecord (consumedBytes = this.consumedBytes) {
    return {
      version: 1,
      kind: 'outboxlog-aggregate',
      authorityKey: this.key,
      mode: this.identity.mode,
      name: this.identity.name,
      coreNamePrefix: this.identity.coreNamePrefix,
      coreKey: coreKeyHex(this.ledgerCore),
      boundBytes: this.maxStorageBytes,
      consumedBytes
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
    const record = this.commitmentRecord()
    const encoded = Buffer.from(JSON.stringify(record))
    if (encoded.byteLength > MAX_COMMITMENT_RECORD_BYTES) throw new Error('OutboxLog storage commitment is too large')
    try {
      // Keep the old ledger conservative for older readers. A crash between
      // these writes leaves a detectable mismatch, never reusable capacity.
      await this.ledgerCore.setUserData(OUTBOXLOG_STORAGE_LEDGER_KEY, Buffer.from(String(this.consumedBytes)))
      await this.ledgerCore.setUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY, encoded)
      this.durableCommitment = record
    } catch (err) {
      this.authority.failClosed('outboxlog-storage-ledger-persistence-failed')
      throw err
    }
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
      actual += await this.measureCore(core)
      if (!Number.isSafeInteger(actual)) throw new Error('OutboxLog exact core storage exceeds safe integer range')
    }
    return actual
  }

  async measureCore (core) {
    if (!core || typeof core.info !== 'function') throw new Error('OutboxLog exact core storage info unavailable')
    const contentBytes = deriveCoreStorageBytes(core)
    const info = await sharedCoreInfo(core, {
      owner: this,
      timeoutMs: OUTBOXLOG_HYPERCORE_APPEND_TIMEOUT_MS
    })
    if (!info) throw new Error('OutboxLog exact core storage info unavailable')
    // RocksDB reports storage:null. Its logical content size is not an OS
    // allocation quota; whole-tree admission independently charges allocation.
    if (!info.storage) return contentBytes
    let actual = 0
    for (const value of Object.values(info.storage)) {
      const bytes = Number(value)
      if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error('OutboxLog exact core storage info invalid')
      actual += bytes
      if (!Number.isSafeInteger(actual)) throw new Error('OutboxLog exact core storage exceeds safe integer range')
    }
    return Math.max(actual, contentBytes)
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
    sharedOperationFlights.invalidateOwner(this, { retire: true })
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
  assertJournalIdentity(name, storageKey, null)
  const storageController = new JournalStorageController({
    authority: storageAdmission,
    maxStorageBytes: maxJournalStorageBytes,
    key: storageKey || `outboxlog:${name}`,
    identity: { mode: 'hypercore', name, coreNamePrefix: null }
  })
  if (!storageController.enabled) throw new Error('OutboxLogHypercoreJournal: storage admission required')
  let openedSuccessfully = false
  try {
    if (!core && store && typeof store.get === 'function') {
      core = await tryOpenExistingCore(store, { name })
    }
    if (core) {
      if (typeof core.ready === 'function') await core.ready()
      storageController.recoveryIdentityVerified = await assertOwnedCore(core, store, name)
      storageController.registerCore(core)
      await storageController.bindLedgerCore(core)
    }
    // Validate every recovered block before installing ownership or writing a
    // commitment. A corrupt pre-existing core must not acquire recovery rights.
    const entries = []
    if (core) storageController.validateRecoveredBytes(await storageController.measureExact())
    const length = core && Number.isSafeInteger(core.length) && core.length > 0 ? core.length : 0
    for (let i = 0; i < length; i++) entries.push(parseBlock(await localJournalBlock(core, i), i))
    validateJournalEntries(entries)
    storageController.initialize(core ? await storageController.measureExact() : 0)
    if (!core) {
      if (!store || typeof store.get !== 'function') throw new Error('OutboxLogHypercoreJournal: store required')
      core = await storageController.create(async () => {
        const opened = store.get({ name })
        if (typeof opened.ready === 'function') await opened.ready()
        await assertOwnedCore(opened, store, name)
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

/** Stable binding of the complete recovered authority inventory, including debt. */
export function outboxRecoveryInventoryDigest (authority) {
  const records = authority.snapshot().records
    .sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0)
    .map(record => Object.fromEntries(Object.keys(record).sort().map(key => [key, record[key]])))
  return createHash('sha256').update(JSON.stringify(records)).digest('hex')
}

/**
 * Explicit offline operator migration only. Normal startup never calls this.
 * The caller verifies backup/held-writer/source/config/empty legacy snapshot
 * proofs, selects the immutable plan, then durably records an external intent.
 * Here we independently bind those selected files and the current complete
 * authority/root/owner before installing debt and allocating any journal.
 */
export async function bootstrapEmptyLegacyOutboxJournal ({
  store,
  storageAdmission,
  name = OUTBOXLOG_HYPERCORE_JOURNAL_NAME,
  maxJournalStorageBytes,
  authorizationPath,
  authorizationSha256
}) {
  assertJournalIdentity(name, null, null)
  const bound = positiveStorageBound(maxJournalStorageBytes)
  const authorization = readPinnedOperatorJson(authorizationPath, authorizationSha256)
  if (!store || typeof store.createKeyPair !== 'function' || !storageAdmission || bound === null ||
      authorization.schema !== 'HiveRelayOfflineEmptyOutboxAuthorizationV1' ||
      authorization.action !== 'initialize-exact-empty-single-outbox-journal' ||
      !/^[0-9a-f]{40}$/.test(authorization.sourceCommit) ||
      typeof authorization.sourceRoot !== 'string' || !isAbsolute(authorization.sourceRoot)) {
    throw new Error('OutboxLog offline bootstrap authorization invalid')
  }
  readPinnedOperatorJson(authorization.selectedPlan?.path, authorization.selectedPlan?.sha256)
  const intent = readPinnedOperatorJson(authorization.irreversibleIntent?.path, authorization.irreversibleIntent?.sha256)
  if (intent.selectedPlanSha256 !== authorization.selectedPlan.sha256) {
    throw new Error('OutboxLog offline bootstrap intent mismatch')
  }
  const keyPair = await store.createKeyPair(name)
  const manifest = { version: store.manifestVersion || 1, signers: [{ publicKey: keyPair.publicKey }] }
  const coreKey = Hypercore.key(manifest).toString('hex')
  const expectedJournal = { mode: 'hypercore', name, coreKey, boundBytes: bound }
  if (!authorization.journal || Object.keys(authorization.journal).length !== 4 ||
      Object.keys(expectedJournal).some(key => authorization.journal[key] !== expectedJournal[key])) {
    throw new Error('OutboxLog offline bootstrap journal mismatch')
  }
  const authorityKey = `outboxlog:${name}`
  if (storageAdmission.get(authorityKey)) throw new Error('OutboxLog offline bootstrap commitment already exists')
  const existing = await tryOpenExistingCore(store, { name })
  if (existing) {
    await assertOwnedCore(existing, store, name)
    if (existing.length !== 0 || existing.byteLength !== 0 ||
        await existing.getUserData(OUTBOXLOG_STORAGE_LEDGER_KEY) ||
        await existing.getUserData(OUTBOXLOG_STORAGE_COMMITMENT_KEY)) {
      throw new Error('OutboxLog offline bootstrap journal is not pristine empty state')
    }
  }
  const sample = storageAdmission.filesystemSample({ refresh: true })
  const snapshot = storageAdmission.snapshot()
  const inventoryBefore = outboxRecoveryInventoryDigest(storageAdmission)
  if (sample.ok !== true || !snapshot.recoveryReady || snapshot.activeMutations !== 0 ||
      snapshot.activePhysicalMutations !== 0 || !snapshot.acceptingMutations || snapshot.fatalReason ||
      !authorization.rootIdentity ||
      ['storagePath', 'realpath', 'device', 'inode'].some(key =>
        typeof authorization.rootIdentity[key] !== 'string' || authorization.rootIdentity[key] !== String(sample[key])) ||
      authorization.operatorCapBytes !== storageAdmission.config.maxStorageBytes ||
      authorization.authorityRecordsSha256 !== inventoryBefore) {
    throw new Error('OutboxLog offline bootstrap current authority or storage identity mismatch')
  }
  // This is the separately selected migration grant, not an empty-core shortcut
  // in the runtime loader. Install its entire finite promise before allocation.
  const granted = storageAdmission.recoverOutboxJournal(authorityKey, bound, 0)
  if (!granted.allowed) {
    const error = new Error('OutboxLog offline bootstrap storage admission blocked: ' + granted.reason)
    error.code = 'STORAGE_ADMISSION_BLOCKED'
    error.storageAdmission = granted
    throw error
  }
  const journal = await createHypercoreOutboxJournal({ store, core: existing, name, storageAdmission, maxJournalStorageBytes: bound })
  return {
    journal,
    receipt: {
      schema: 'HiveRelayOfflineEmptyOutboxBootstrapReceiptV1',
      authorizationSha256,
      selectedPlanSha256: authorization.selectedPlan.sha256,
      irreversibleIntentSha256: authorization.irreversibleIntent.sha256,
      coreKey,
      boundBytes: bound,
      consumedBytes: journal.storageController.consumedBytes,
      authorityRecordsBeforeSha256: inventoryBefore,
      authorityRecordsAfterSha256: outboxRecoveryInventoryDigest(storageAdmission)
    }
  }
}

function readPinnedOperatorJson (filename, expectedHash) {
  if (typeof filename !== 'string' || !isAbsolute(filename) || typeof expectedHash !== 'string' || !/^[0-9a-f]{64}$/.test(expectedHash)) {
    throw new Error('OutboxLog offline bootstrap file pin invalid')
  }
  const fd = openSync(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK)
  try {
    const stat = fstatSync(fd, { bigint: true })
    if (!stat.isFile() || stat.nlink !== 1n || stat.size <= 0n || stat.size > 4n * 1024n * 1024n || (stat.mode & 0o022n) !== 0n) {
      throw new Error('OutboxLog offline bootstrap file invalid')
    }
    const bytes = Buffer.alloc(Number(stat.size))
    let offset = 0
    while (offset < bytes.byteLength) {
      const count = readSync(fd, bytes, offset, bytes.byteLength - offset, null)
      if (count === 0) break
      offset += count
    }
    const extra = readSync(fd, Buffer.alloc(1), 0, 1, null)
    const after = fstatSync(fd, { bigint: true })
    if (offset !== bytes.byteLength || extra !== 0 ||
        ['dev', 'ino', 'size', 'mode', 'nlink', 'uid', 'gid', 'mtimeNs', 'ctimeNs'].some(key => stat[key] !== after[key]) ||
        createHash('sha256').update(bytes).digest('hex') !== expectedHash) {
      throw new Error('OutboxLog offline bootstrap file pin mismatch')
    }
    return JSON.parse(bytes.toString('utf8'))
  } finally {
    closeSync(fd)
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
  assertJournalIdentity(indexName, storageKey, coreNamePrefix)
  const storageController = new JournalStorageController({
    authority: storageAdmission,
    maxStorageBytes: maxJournalStorageBytes,
    key: storageKey || `outboxlog:${indexName}`,
    identity: { mode: 'hypercore-outboxes', name: indexName, coreNamePrefix }
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
        await assertOwnedCore(core, store, indexName)
        return core
      })
    }
    assertJournalCore(indexCore, 'index core')
    await readyCore(indexCore)
    storageController.recoveryIdentityVerified = await assertOwnedCore(indexCore, store, indexName)
    storageController.registerCore(indexCore)
    await storageController.bindLedgerCore(indexCore)

    const outboxes = new Map()
    let recoveredBytes = recovering ? await storageController.measureExact() : 0
    if (recovering) storageController.validateRecoveredBytes(recoveredBytes)
    const indexLength = Number.isSafeInteger(indexCore.length) && indexCore.length > 0 ? indexCore.length : 0
    for (let i = 0; i < indexLength; i++) {
      const meta = parseIndexBlock(await localJournalBlock(indexCore, i), i)
      if (meta.coreName !== coreNameForOutbox(meta.appId, coreNamePrefix)) {
        throw new Error('OutboxLogPartitionedHypercoreJournal: indexed outbox name mismatch')
      }
      const existing = outboxes.get(meta.appId)
      if (existing) {
        if (existing.name !== meta.coreName || existing.inviteKey !== meta.inviteKey || existing.firstSeq !== meta.firstSeq) {
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
      await assertOwnedCore(core, store, meta.coreName)
      await readyCore(core)
      storageController.registerCore(core)
      if (recovering) {
        recoveredBytes += await storageController.measureCore(core)
        storageController.validateRecoveredBytes(recoveredBytes)
      }
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
      if (length === 0) throw new Error('OutboxLogPartitionedHypercoreJournal: indexed outbox has no entries')
      for (let i = 0; i < length; i++) {
        const entry = parseOutboxBlock(await localJournalBlock(outbox.core, i), appId, i)
        if (i === 0 && entry.seq !== outbox.firstSeq) {
          throw new Error('OutboxLogPartitionedHypercoreJournal: indexed first sequence mismatch')
        }
        entries.push(entry)
      }
    }
    entries.sort((a, b) => a.seq - b.seq)
    validateJournalEntries(entries)
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
    await assertOwnedCore(outbox.core, this.store, outbox.name)
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

function validateJournalEntries (entries) {
  for (let i = 0; i < entries.length; i++) {
    if (!normalizeJournalEntry(entries[i], i + 1)) {
      throw new Error('OutboxLog journal corrupt operation or sequence at ' + (i + 1))
    }
  }
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

async function localJournalBlock (core, index) {
  const block = await core.get(index, { wait: false })
  if (!block) throw new Error('OutboxLog journal local block missing')
  return block
}

function assertJournalIdentity (name, storageKey, coreNamePrefix) {
  const valid = value => typeof value === 'string' && value.length > 0 &&
    Buffer.byteLength(value) <= 1024 && !value.includes('\0')
  if (!valid(name) || (coreNamePrefix !== null && !valid(coreNamePrefix)) ||
      (storageKey !== null && (!valid(storageKey) || !storageKey.startsWith('outboxlog:') || storageKey.length <= 10))) {
    throw new Error('OutboxLog journal identity invalid')
  }
}

async function assertOwnedCore (core, store, name) {
  const key = coreKeyHex(core)
  if (core?.writable !== true || !key || !/^[0-9a-f]{64}$/.test(key)) {
    throw new Error('OutboxLog journal requires a local writable owner')
  }
  if (store && typeof store.createKeyPair === 'function') {
    const keyPair = await store.createKeyPair(name)
    const manifest = { version: store.manifestVersion || 1, signers: [{ publicKey: keyPair.publicKey }] }
    if (key !== Hypercore.key(manifest).toString('hex')) {
      throw new Error('OutboxLog journal named owner mismatch')
    }
    return true
  }
  // An injected writable core may be freshly admitted, but it cannot claim
  // durable recovery without the selected store's namespace/name proof.
  return false
}

async function tryOpenExistingCore (store, opts) {
  // Corestore 7 session semantics: a store.get({ createIfMissing: false })
  // that misses storage fails the core's opening with STORAGE_EMPTY, and
  // hypercore can never finish closing such a session (close() rethrows the
  // open error before unregistering it), so the failed core stays tracked by
  // the store and every later store.close() rejects on its rejected opening.
  // Probe existence by discovery key instead: get({ discoveryKey }) checks
  // storage before any tracked core is created, so a miss rejects without
  // poisoning Corestore teardown.
  if (opts && opts.name && typeof store.createKeyPair === 'function') {
    // Mirrors corestore's named-core auth: a namespace-derived key pair under
    // the default single-signer manifest determines the core's discovery key.
    const keyPair = await store.createKeyPair(opts.name)
    const manifest = { version: store.manifestVersion || 1, signers: [{ publicKey: keyPair.publicKey }] }
    const discoveryKey = Hypercore.discoveryKey(Hypercore.key(manifest))
    const probe = store.get({ discoveryKey })
    try {
      await readyCore(probe)
      return probe
    } catch (err) {
      try { await probe.close() } catch (_) {}
      if (!err || err.code !== 'STORAGE_EMPTY') throw err
      return null
    }
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

// Deterministic on-disk content size for backends (corestore 7 / RocksDB)
// that cannot report per-core physical file usage: exact block payload bytes
// plus the merkle tree (40 bytes per node, ~2 nodes per block) and the
// bitfield (1 bit per block).
function deriveCoreStorageBytes (core) {
  const { length, byteLength } = core
  const bytes = byteLength + (2 * length * 40) + Math.ceil(length / 8)
  if (!Number.isSafeInteger(length) || length < 0 || !Number.isSafeInteger(byteLength) ||
      byteLength < 0 || !Number.isSafeInteger(bytes)) throw new Error('OutboxLog core storage metrics invalid')
  return bytes
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
