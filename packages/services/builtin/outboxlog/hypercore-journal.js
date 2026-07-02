/**
 * Corestore-backed operation journal for OutboxLog.
 *
 * The OutboxLog engine stays synchronous for Peerit wire compatibility, so
 * this adapter is opened asynchronously before engine construction. Once ready,
 * it exposes the small sync journal surface the engine expects while mirroring
 * accepted journal entries into one named Hypercore.
 */

import { EventEmitter } from 'node:events'

export const OUTBOXLOG_HYPERCORE_JOURNAL_NAME = 'outboxlog/operations'
export const OUTBOXLOG_HYPERCORE_APPEND_TIMEOUT_MS = 5000
export const OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME = 'outboxlog/outboxes/index'
export const OUTBOXLOG_OUTBOX_CORE_PREFIX = 'outboxlog/outboxes/'
export const OUTBOXLOG_PARTITIONED_INDEX_VERSION = 1

export async function createHypercoreOutboxJournal ({
  store = null,
  core = null,
  name = OUTBOXLOG_HYPERCORE_JOURNAL_NAME,
  appendTimeoutMs = OUTBOXLOG_HYPERCORE_APPEND_TIMEOUT_MS,
  log = () => {}
} = {}) {
  if (!core) {
    if (!store || typeof store.get !== 'function') throw new Error('OutboxLogHypercoreJournal: store required')
    core = store.get({ name })
  }
  if (!core || typeof core.append !== 'function' || typeof core.get !== 'function') {
    throw new Error('OutboxLogHypercoreJournal: core must expose append() and get()')
  }
  if (typeof core.ready === 'function') await core.ready()

  const entries = []
  const length = Number.isSafeInteger(core.length) && core.length > 0 ? core.length : 0
  for (let i = 0; i < length; i++) {
    const block = await core.get(i)
    entries.push(parseBlock(block, i))
  }

  return new HypercoreOutboxJournal({
    core,
    name,
    entries,
    appendTimeoutMs,
    log
  })
}

export async function createPartitionedHypercoreOutboxJournal ({
  store = null,
  indexCore = null,
  indexName = OUTBOXLOG_PARTITIONED_JOURNAL_INDEX_NAME,
  coreNamePrefix = OUTBOXLOG_OUTBOX_CORE_PREFIX,
  appendTimeoutMs = OUTBOXLOG_HYPERCORE_APPEND_TIMEOUT_MS,
  log = () => {}
} = {}) {
  if (!store || typeof store.get !== 'function') throw new Error('OutboxLogPartitionedHypercoreJournal: store required')
  if (!indexCore) indexCore = store.get({ name: indexName })
  assertJournalCore(indexCore, 'index core')
  await readyCore(indexCore)

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
    const core = store.get({ name: meta.coreName })
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

  return new PartitionedHypercoreOutboxJournal({
    store,
    indexCore,
    indexName,
    coreNamePrefix,
    outboxes,
    entries,
    appendTimeoutMs,
    log
  })
}

export class HypercoreOutboxJournal extends EventEmitter {
  constructor ({ core, name, entries = [], appendTimeoutMs = OUTBOXLOG_HYPERCORE_APPEND_TIMEOUT_MS, log = () => {} }) {
    super()
    this.core = core
    this.name = name
    this.appendTimeoutMs = appendTimeoutMs
    this._entries = clone(entries)
    this._pending = Promise.resolve()
    this._errors = []
    this._log = log
  }

  loadSync () {
    return clone(this._entries)
  }

  appendSync (entry) {
    const saved = clone(entry)
    this._entries.push(saved)
    const job = this._pending.then(
      () => appendWithTimeout(this.core, saved, this.appendTimeoutMs),
      () => appendWithTimeout(this.core, saved, this.appendTimeoutMs)
    )
    this._pending = job.catch((err) => {
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
    log = () => {}
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
  }

  loadSync () {
    return clone(this._entries)
  }

  appendSync (entry) {
    const saved = clone(entry)
    this._entries.push(saved)
    const outbox = this._ensureOutbox(saved)
    const job = this._pending.then(
      () => this._appendPartitioned(saved, outbox),
      () => this._appendPartitioned(saved, outbox)
    )
    this._pending = job.catch((err) => this._recordError(outbox.name, err))
  }

  async flush ({ throwOnError = true } = {}) {
    await this._pending
    if (throwOnError && this._errors.length > 0) {
      throw new Error('OutboxLogPartitionedHypercoreJournal: append failed: ' + this._errors[this._errors.length - 1])
    }
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

  async seedCores (seeder) {
    if (!seeder || typeof seeder.seedCore !== 'function') {
      throw new Error('OutboxLogPartitionedHypercoreJournal: seeder with seedCore() required')
    }
    await this.flush()

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

  _ensureOutbox (entry) {
    let outbox = this._outboxes.get(entry.appId)
    if (outbox) {
      if (!outbox.inviteKey && entry.inviteKey) outbox.inviteKey = entry.inviteKey
      if (!Number.isSafeInteger(outbox.firstSeq) || entry.seq < outbox.firstSeq) outbox.firstSeq = entry.seq
      return outbox
    }
    const name = coreNameForOutbox(entry.appId, this.coreNamePrefix)
    const core = this.store.get({ name })
    assertJournalCore(core, 'outbox core ' + entry.appId)
    outbox = {
      appId: entry.appId,
      inviteKey: entry.inviteKey,
      firstSeq: entry.seq,
      name,
      core,
      indexed: false
    }
    this._outboxes.set(entry.appId, outbox)
    return outbox
  }

  async _appendPartitioned (entry, outbox) {
    await readyCore(this.indexCore)
    await readyCore(outbox.core)
    if (!outbox.indexed) {
      await appendWithTimeout(this.indexCore, indexMetadataFor(outbox, entry), this.appendTimeoutMs)
      outbox.indexed = true
    }
    await appendWithTimeout(outbox.core, entry, this.appendTimeoutMs)
  }

  async _seedCore (seeder, descriptor, seeded) {
    await readyCore(descriptor.core)
    const coreKey = coreKeyHex(descriptor.core)
    if (!coreKey) throw new Error('OutboxLogPartitionedHypercoreJournal: missing core key for ' + descriptor.name)
    await seeder.seedCore(coreKey)
    seeded.push({
      role: descriptor.role,
      appId: descriptor.appId,
      name: descriptor.name,
      coreKey,
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

async function appendWithTimeout (core, entry, timeoutMs) {
  const blob = Buffer.from(JSON.stringify(entry), 'utf8')
  let timer
  const timeout = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error('append-timeout')), timeoutMs)
  })
  try {
    await Promise.race([core.append(blob), timeout])
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

function coreKeyHex (core) {
  if (!core || !core.key) return null
  if (Buffer.isBuffer(core.key)) return core.key.toString('hex')
  if (typeof core.key.toString === 'function') return core.key.toString('hex')
  return null
}

function clone (value) {
  return JSON.parse(JSON.stringify(value))
}
