import { join } from 'node:path'
import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import {
  createJsonFileOutboxPersistence,
  createOutboxLog
} from '../outboxlog/index.js'
import {
  WITNESSLOG_NAMESPACE,
  assertWitnessRecord,
  normalizeWitnessOutboxRecord,
  redactWitnessRecord,
  stripOutboxFields,
  targetMatchesWitnessRecord,
  verifyWitnessOutboxRecord,
  witnessRecordMarker
} from './record.js'

export class WitnessLogApp extends ServiceProvider {
  constructor (opts = {}) {
    super()
    this.engine = opts.engine || createOutboxLog({
      namespace: WITNESSLOG_NAMESPACE,
      namespaces: {
        [WITNESSLOG_NAMESPACE]: {
          blind: false,
          caps: opts.caps || {
            maxOutboxes: opts.maxOutboxes || 50000,
            maxEntriesPerOutbox: opts.maxEntriesPerOutbox || 10000,
            maxValueBytes: opts.maxValueBytes || 4096
          }
        }
      },
      verifyAppend: (input) => verifyWitnessOutboxRecord(input, this.verifyOpts),
      persistence: opts.persistence === undefined ? null : opts.persistence,
      log: opts.log
    })
    this.sync = this.engine.sync
    this.verifyOpts = opts.verify || {}
    this.persistencePath = typeof opts.persistencePath === 'string' ? opts.persistencePath : null
    this.storagePath = typeof opts.storagePath === 'string' ? opts.storagePath : null
    this.persistenceDisabled = opts.persistence === false
    this.node = null
  }

  manifest () {
    return {
      name: 'witnesslog',
      version: '0.1.0',
      description: 'Signed third-party availability observations for HiveRelay targets',
      capabilities: ['witnesslog.append', 'witnesslog.range', 'witnesslog.events']
    }
  }

  async start (context = {}) {
    this.node = context.node || null
    const config = context && context.config && typeof context.config === 'object' ? context.config : {}
    const witnesslog = config.witnesslog && typeof config.witnesslog === 'object' ? config.witnesslog : {}
    if (!this.persistenceDisabled && this.engine.configurePersistence) {
      const storagePath = this.storagePath ||
        (typeof witnesslog.storagePath === 'string' ? witnesslog.storagePath : null) ||
        (typeof config.storage === 'string' ? config.storage : null)
      const persistencePath = this.persistencePath ||
        (typeof witnesslog.persistencePath === 'string' ? witnesslog.persistencePath : null) ||
        (storagePath ? join(storagePath, 'witnesslog-state.json') : null)
      if (persistencePath) {
        this.engine.configurePersistence({
          persistence: createJsonFileOutboxPersistence(persistencePath)
        })
      }
    }
  }

  async stop () {
    if (this.engine.flush) await this.engine.flush()
    this.node = null
  }

  append (record) {
    const signed = assertWitnessRecord(record, this.verifyOpts)
    const data = normalizeWitnessOutboxRecord(signed)
    const appId = signed.observer.publicKey
    return {
      ...this.sync.append(appId, { type: 'availability', data }),
      id: signed.id
    }
  }

  list (opts = {}) {
    const limit = clampLimit(opts.limit)
    const since = normalizeSince(opts.since)
    const target = opts.target || opts.key || opts.keyHash || null
    const rows = []
    const snapshot = this.engine.snapshot()
    for (const group of snapshot.groups || []) {
      const groupState = Array.isArray(group) ? group[1] : null
      if (!groupState || !Array.isArray(groupState.rows)) continue
      for (const row of groupState.rows) {
        if (!Array.isArray(row) || row.length !== 2) continue
        const value = row[1]
        if (!value || value._ns !== WITNESSLOG_NAMESPACE) continue
        let record
        try {
          record = stripOutboxFields(value)
          assertWitnessRecord(record, this.verifyOpts)
        } catch {
          continue
        }
        if (since && Date.parse(record.observedAt) <= since) continue
        if (!targetMatchesWitnessRecord(record, target)) continue
        rows.push(record)
      }
    }
    rows.sort(compareWitnessRecords)
    const page = rows.slice(0, limit)
    return {
      records: opts.redact === false ? page : page.map(redactWitnessRecord),
      count: page.length,
      total: rows.length,
      nextSince: page.length ? page[page.length - 1].observedAt : (opts.since || null),
      hasMore: rows.length > page.length
    }
  }

  markers (opts = {}) {
    const page = this.list({ ...opts, redact: false })
    return {
      markers: page.records.map(witnessRecordMarker),
      count: page.count,
      total: page.total,
      nextSince: page.nextSince,
      hasMore: page.hasMore
    }
  }

  subscribe (opts, fn) {
    if (typeof opts === 'function') {
      fn = opts
      opts = {}
    }
    if (typeof fn !== 'function') throw new Error('WitnessLog.subscribe: not a function')
    const target = opts && (opts.target || opts.key || opts.keyHash)
    return this.engine.subscribe('*', { replay: false }, event => {
      if (!event || !event.value || event.value._ns !== WITNESSLOG_NAMESPACE) return
      let record
      try {
        record = stripOutboxFields(event.value)
        assertWitnessRecord(record, this.verifyOpts)
      } catch {
        return
      }
      if (!targetMatchesWitnessRecord(record, target)) return
      fn({
        ...witnessRecordMarker(record),
        seq: event.seq,
        topic: 'witness/' + (record.target.keyHash || record.target.key || 'unknown')
      })
    })
  }
}

export {
  WITNESSLOG_DEFAULT_MAX_AGE_MS,
  WITNESSLOG_DEFAULT_MAX_CLOCK_SKEW_MS,
  WITNESSLOG_DEFAULT_MAX_TTL_MS,
  WITNESSLOG_NAMESPACE,
  WITNESSLOG_RECORD_TYPE_AVAILABILITY,
  WITNESSLOG_RECORD_VERSION,
  WITNESSLOG_SIGNATURE_DOMAIN,
  assertWitnessRecord,
  canonicalWitnessRecord,
  createWitnessRecord,
  normalizeWitnessOutboxRecord,
  normalizeWitnessRecord,
  redactWitnessRecord,
  signWitnessRecord,
  stripOutboxFields,
  targetMatchesWitnessRecord,
  verifyWitnessOutboxRecord,
  verifyWitnessRecord,
  witnessRecordBytes,
  witnessRecordMarker
} from './record.js'

function compareWitnessRecords (a, b) {
  return Date.parse(a.observedAt) - Date.parse(b.observedAt) || a.id.localeCompare(b.id)
}

function clampLimit (value) {
  const number = Number(value)
  if (!Number.isSafeInteger(number) || number < 1) return 100
  return Math.min(number, 1000)
}

function normalizeSince (value) {
  if (value == null || value === '') return null
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? ms : null
}
