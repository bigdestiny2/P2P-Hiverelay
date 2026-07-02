import { join } from 'node:path'
import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import {
  createJsonFileOutboxPersistence,
  createOutboxLog
} from '../outboxlog/index.js'
import {
  REPAIRTICKET_NAMESPACE,
  REPAIRTICKET_RECORD_TYPE_CLAIM,
  REPAIRTICKET_RECORD_TYPE_CLOSE,
  REPAIRTICKET_RECORD_TYPE_RECEIPT,
  REPAIRTICKET_RECORD_TYPE_TICKET,
  assertRepairRecord,
  normalizeRepairOutboxRecord,
  redactRepairRecord,
  repairRecordMarker,
  repairRecordOpType,
  repairRecordTicketId,
  stripRepairOutboxFields,
  targetMatchesRepairRecord,
  verifyRepairOutboxRecord
} from './record.js'

export class RepairTicketApp extends ServiceProvider {
  constructor (opts = {}) {
    super()
    this.engine = opts.engine || createOutboxLog({
      namespace: REPAIRTICKET_NAMESPACE,
      namespaces: {
        [REPAIRTICKET_NAMESPACE]: {
          blind: false,
          caps: opts.caps || {
            maxOutboxes: opts.maxOutboxes || 50000,
            maxEntriesPerOutbox: opts.maxEntriesPerOutbox || 20000,
            maxValueBytes: opts.maxValueBytes || 8192
          }
        }
      },
      verifyAppend: (input) => verifyRepairOutboxRecord(input, this.verifyOpts),
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
      name: 'repairticket',
      version: '0.1.0',
      description: 'Signed repair requests, claims, receipts, and closures for HiveRelay availability recovery',
      capabilities: ['repairticket.append', 'repairticket.range', 'repairticket.tickets', 'repairticket.events']
    }
  }

  async start (context = {}) {
    this.node = context.node || null
    const config = context && context.config && typeof context.config === 'object' ? context.config : {}
    const repairticket = config.repairticket && typeof config.repairticket === 'object' ? config.repairticket : {}
    if (!this.persistenceDisabled && this.engine.configurePersistence) {
      const storagePath = this.storagePath ||
        (typeof repairticket.storagePath === 'string' ? repairticket.storagePath : null) ||
        (typeof config.storage === 'string' ? config.storage : null)
      const persistencePath = this.persistencePath ||
        (typeof repairticket.persistencePath === 'string' ? repairticket.persistencePath : null) ||
        (storagePath ? join(storagePath, 'repairticket-state.json') : null)
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
    const signed = assertRepairRecord(record, this.verifyOpts)
    const data = normalizeRepairOutboxRecord(signed)
    const appId = signed.signer.publicKey
    return {
      ...this.sync.append(appId, { type: repairRecordOpType(signed), data }),
      id: signed.id,
      ticketId: repairRecordTicketId(signed)
    }
  }

  list (opts = {}) {
    const collected = collectRecords(this.engine, this.verifyOpts)
    const records = filterRecords(collected, opts)
    const limit = clampLimit(opts.limit)
    const page = records.slice(0, limit)
    return {
      records: opts.redact === false ? page : page.map(redactRepairRecord),
      count: page.length,
      total: records.length,
      nextSince: page.length ? page[page.length - 1].createdAt : (opts.since || null),
      hasMore: records.length > page.length
    }
  }

  tickets (opts = {}) {
    const collected = collectRecords(this.engine, this.verifyOpts)
    const records = filterRecords(collected, { ...opts, type: null, status: null })
    const summaries = repairTicketSummaries(records, collected.byId, opts.now || this.verifyOpts.now)
      .filter(summary => !opts.status || summary.status === opts.status)
    const limit = clampLimit(opts.limit)
    const page = summaries.slice(0, limit)
    return {
      tickets: page,
      count: page.length,
      total: summaries.length,
      nextSince: page.length ? page[page.length - 1].createdAt : (opts.since || null),
      hasMore: summaries.length > page.length
    }
  }

  markers (opts = {}) {
    const collected = collectRecords(this.engine, this.verifyOpts)
    const records = filterRecords(collected, opts)
    const limit = clampLimit(opts.limit)
    const page = records.slice(0, limit)
    return {
      markers: page.map(record => repairRecordMarker(record, collected.byId.get(record.ticketId))),
      count: page.length,
      total: records.length,
      nextSince: page.length ? page[page.length - 1].createdAt : (opts.since || null),
      hasMore: records.length > page.length
    }
  }

  subscribe (opts, fn) {
    if (typeof opts === 'function') {
      fn = opts
      opts = {}
    }
    if (typeof fn !== 'function') throw new Error('RepairTicket.subscribe: not a function')
    const target = opts && (opts.target || opts.key || opts.keyHash)
    // Build the ticket index ONCE, then keep it warm from the event stream.
    // Previously every append re-snapshotted + re-verified the ENTIRE store per
    // open subscriber (O(store) crypto per event) — a quadratic DoS.
    const byId = collectRecords(this.engine, this.verifyOpts).byId
    return this.engine.subscribe('*', { replay: false }, event => {
      if (!event || !event.value || event.value._ns !== REPAIRTICKET_NAMESPACE) return
      let record
      let ticket = null
      try {
        record = stripRepairOutboxFields(event.value)
        assertRepairRecord(record, this.verifyOpts)
        if (record.type === REPAIRTICKET_RECORD_TYPE_TICKET) byId.set(record.id, record)
        if (record.ticketId) ticket = byId.get(record.ticketId) || null
      } catch {
        return
      }
      if (!targetMatchesRepairRecord(record, target, ticket)) return
      fn({
        ...repairRecordMarker(record, ticket),
        seq: event.seq,
        topic: 'repair/' + repairRecordTicketId(record)
      })
    })
  }
}

export {
  REPAIRTICKET_DEFAULT_MAX_AGE_MS,
  REPAIRTICKET_DEFAULT_MAX_CLOCK_SKEW_MS,
  REPAIRTICKET_DEFAULT_MAX_TTL_MS,
  REPAIRTICKET_NAMESPACE,
  REPAIRTICKET_RECORD_TYPE_CLAIM,
  REPAIRTICKET_RECORD_TYPE_CLOSE,
  REPAIRTICKET_RECORD_TYPE_RECEIPT,
  REPAIRTICKET_RECORD_TYPE_TICKET,
  REPAIRTICKET_RECORD_VERSION,
  REPAIRTICKET_SIGNATURE_DOMAIN,
  assertRepairRecord,
  canonicalRepairRecord,
  createRepairRecord,
  normalizeRepairOutboxRecord,
  normalizeRepairRecord,
  redactRepairRecord,
  repairRecordBytes,
  repairRecordMarker,
  repairRecordOpType,
  repairRecordTicketId,
  signRepairRecord,
  stripRepairOutboxFields,
  targetMatchesRepairRecord,
  verifyRepairOutboxRecord,
  verifyRepairRecord
} from './record.js'

function collectRecords (engine, verifyOpts) {
  const records = []
  const byId = new Map()
  const snapshot = engine.snapshot()
  for (const group of snapshot.groups || []) {
    const groupState = Array.isArray(group) ? group[1] : null
    if (!groupState || !Array.isArray(groupState.rows)) continue
    for (const row of groupState.rows) {
      if (!Array.isArray(row) || row.length !== 2) continue
      const value = row[1]
      if (!value || value._ns !== REPAIRTICKET_NAMESPACE) continue
      try {
        const record = stripRepairOutboxFields(value)
        assertRepairRecord(record, verifyOpts)
        records.push(record)
        byId.set(record.id, record)
      } catch {}
    }
  }
  records.sort(compareRepairRecords)
  return { records, byId }
}

function filterRecords ({ records, byId }, opts = {}) {
  const since = normalizeSince(opts.since)
  const target = opts.target || opts.key || opts.keyHash || null
  const ticketId = opts.ticketId || null
  const type = opts.type || null
  return records.filter(record => {
    if (since && Date.parse(record.createdAt) <= since) return false
    if (ticketId && repairRecordTicketId(record) !== ticketId) return false
    if (type && record.type !== type && repairRecordOpType(record) !== type) return false
    if (!targetMatchesRepairRecord(record, target, byId.get(record.ticketId))) return false
    return true
  })
}

function repairTicketSummaries (records, byId, now = null) {
  const nowMs = normalizeNow(now)
  const tickets = records.filter(record => record.type === REPAIRTICKET_RECORD_TYPE_TICKET)
  return tickets.map(ticket => {
    const related = records.filter(record => repairRecordTicketId(record) === ticket.id)
    const signerOf = (record) => record && record.signer && String(record.signer.publicKey).toLowerCase()
    const creator = signerOf(ticket)
    const claims = related.filter(record => record.type === REPAIRTICKET_RECORD_TYPE_CLAIM)
    const receipts = related.filter(record => record.type === REPAIRTICKET_RECORD_TYPE_RECEIPT)
    const closes = related.filter(record => record.type === REPAIRTICKET_RECORD_TYPE_CLOSE)
    // AUTHORITY: derive status only from records whose signer is entitled to set
    // it. A close counts only from the ticket CREATOR (only the filer ends the
    // ticket); a "repaired" receipt counts only from a relay that actually
    // CLAIMED the ticket. Otherwise any keypair could copy a public ticketId and
    // forge a closure/receipt, making the fleet stop healing a dead core.
    const claimers = new Set(claims.map(signerOf))
    const authoritativeCloses = closes.filter(record => signerOf(record) === creator)
    const latestClose = authoritativeCloses[authoritativeCloses.length - 1] || null
    const goodReceipt = receipts.find(record => record.result && record.result.ok && claimers.has(signerOf(record)))
    const status = latestClose
      ? latestClose.outcome
      : (goodReceipt ? 'repaired' : (claims.length ? 'claimed' : (Date.parse(ticket.expiresAt) < nowMs ? 'expired' : 'open')))
    return {
      id: ticket.id,
      status,
      createdAt: ticket.createdAt,
      expiresAt: ticket.expiresAt,
      signer: ticket.signer.publicKey,
      target: redactRepairRecord(ticket).target,
      repair: { ...ticket.repair },
      counts: {
        claims: claims.length,
        receipts: receipts.length,
        closes: closes.length
      },
      latest: related.length ? repairRecordMarker(related[related.length - 1], byId.get(related[related.length - 1].ticketId)) : null
    }
  }).sort(compareTicketSummaries)
}

function normalizeNow (value) {
  if (value == null) return Date.now()
  if (value instanceof Date) return value.getTime()
  if (typeof value === 'number') return value
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) ? parsed : Date.now()
}

function compareRepairRecords (a, b) {
  return Date.parse(a.createdAt) - Date.parse(b.createdAt) || a.id.localeCompare(b.id)
}

function compareTicketSummaries (a, b) {
  return Date.parse(a.createdAt) - Date.parse(b.createdAt) || a.id.localeCompare(b.id)
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
