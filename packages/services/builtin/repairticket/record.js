import { createHash } from 'node:crypto'
import sodium from 'sodium-universal'
import b4a from 'b4a'

export const REPAIRTICKET_NAMESPACE = 'repair'
export const REPAIRTICKET_RECORD_VERSION = 1
export const REPAIRTICKET_RECORD_TYPE_TICKET = 'hiverelay.repair.ticket'
export const REPAIRTICKET_RECORD_TYPE_CLAIM = 'hiverelay.repair.claim'
export const REPAIRTICKET_RECORD_TYPE_RECEIPT = 'hiverelay.repair.receipt'
export const REPAIRTICKET_RECORD_TYPE_CLOSE = 'hiverelay.repair.close'
export const REPAIRTICKET_SIGNATURE_DOMAIN = 'hiverelay.repairticket.v1'
export const REPAIRTICKET_DEFAULT_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000
export const REPAIRTICKET_DEFAULT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000
export const REPAIRTICKET_DEFAULT_MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000

const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_64 = /^[0-9a-f]{128}$/i
const PUBKEY_BYTES = 32
const SIG_BYTES = 64
const URL_MAX = 2048
const SHORT = 256
const MAX_EVIDENCE = 32
const RECORD_TYPES = new Set([
  REPAIRTICKET_RECORD_TYPE_TICKET,
  REPAIRTICKET_RECORD_TYPE_CLAIM,
  REPAIRTICKET_RECORD_TYPE_RECEIPT,
  REPAIRTICKET_RECORD_TYPE_CLOSE
])

export function createRepairRecord (input = {}) {
  const core = normalizeRepairCore(input, { allowMissingId: true })
  const withId = {
    id: core.id || repairRecordId(core),
    ...without(core, ['id'])
  }
  return normalizeRepairCore(withId)
}

export function signRepairRecord (input, secretKey) {
  const record = createRepairRecord(input)
  const key = decodeHexOrBuffer(secretKey, 64, 'secret key')
  const signature = b4a.alloc(SIG_BYTES)
  sodium.crypto_sign_detached(signature, repairRecordBytes(record), key)
  return {
    ...record,
    signature: b4a.toString(signature, 'hex')
  }
}

export function verifyRepairRecord (input, opts = {}) {
  let record
  try {
    record = normalizeRepairRecord(input)
    assertRepairTimestamps(record, opts)
  } catch {
    return false
  }

  const signature = b4a.from(record.signature, 'hex')
  const publicKey = b4a.from(record.signer.publicKey, 'hex')
  if (signature.byteLength !== SIG_BYTES || publicKey.byteLength !== PUBKEY_BYTES) return false
  return sodium.crypto_sign_verify_detached(signature, repairRecordBytes(record), publicKey)
}

export function assertRepairRecord (input, opts = {}) {
  const record = normalizeRepairRecord(input)
  assertRepairTimestamps(record, opts)
  if (!verifyRepairRecord(record, opts)) throw new Error('RepairTicket: bad signature')
  return record
}

export function canonicalRepairRecord (input) {
  const record = input && input.signature
    ? unsignedRepairRecord(normalizeRepairRecord(input))
    : createRepairRecord(input)
  return stable(record)
}

export function repairRecordBytes (input) {
  const record = input && input.signature ? unsignedRepairRecord(normalizeRepairRecord(input)) : createRepairRecord(input)
  return b4a.from(REPAIRTICKET_SIGNATURE_DOMAIN + '|' + stable(record), 'utf8')
}

// blake2b-256 of the raw hypercore key -> the public target id. Lets a
// repair record identify a target without ever exposing the raw key.
export function hashTargetKey (keyHex) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from(String(keyHex).toLowerCase(), 'hex'))
  return b4a.toString(out, 'hex')
}

export function redactRepairRecord (input) {
  const record = normalizeRepairRecord(input)
  const out = clone(record)
  // Read-path redaction must ALWAYS strip the raw key — deriving keyHash when a
  // key-only record was submitted, so no public read ever leaks the raw key.
  if (out.target && out.target.key) {
    if (!out.target.keyHash) out.target.keyHash = hashTargetKey(out.target.key)
    delete out.target.key
  }
  return out
}

export function repairRecordMarker (input, ticket = null) {
  const record = normalizeRepairRecord(input)
  const ticketRecord = ticket ? normalizeRepairRecord(ticket) : null
  const target = record.target || (ticketRecord && ticketRecord.target) || null
  return {
    id: record.id,
    type: record.type,
    ticketId: repairRecordTicketId(record),
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    signer: record.signer.publicKey,
    // Never expose the raw key on the public marker/SSE surface.
    target: target ? (target.keyHash || (target.key ? hashTargetKey(target.key) : null)) : null,
    targetKind: target ? target.kind : null,
    reason: record.repair ? record.repair.reason : null,
    action: record.action || null,
    outcome: record.outcome || null,
    ok: record.result ? record.result.ok : null
  }
}

export function targetMatchesRepairRecord (record, target, ticket = null) {
  if (!target) return true
  const normalized = normalizeTargetQuery(target)
  if (!normalized) return false
  const repair = normalizeRepairRecord(record)
  const ticketRecord = ticket ? normalizeRepairRecord(ticket) : null
  const repairTarget = repair.target || (ticketRecord && ticketRecord.target) || null
  if (!repairTarget) return false
  return repairTarget.key === normalized || repairTarget.keyHash === normalized
}

export function normalizeRepairRecord (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('RepairTicket: record must be an object')
  if (input.signature == null) throw new Error('RepairTicket: missing signature')
  const signature = normalizeHex(input.signature, 128, 'signature')
  return {
    ...normalizeRepairCore(input),
    signature
  }
}

export function normalizeRepairOutboxRecord (input) {
  const record = normalizeRepairRecord(input)
  return {
    ...record,
    _ns: REPAIRTICKET_NAMESPACE
  }
}

export function verifyRepairOutboxRecord ({ appId, data }, opts = {}) {
  if (!data || typeof data !== 'object') return false
  if (data._ns !== REPAIRTICKET_NAMESPACE) return false
  const record = stripRepairOutboxFields(data)
  if (!verifyRepairRecord(record, opts)) return false
  return typeof appId === 'string' && appId.toLowerCase() === record.signer.publicKey.toLowerCase()
}

export function stripRepairOutboxFields (data) {
  const copy = { ...data }
  delete copy._ns
  return copy
}

export function repairRecordTicketId (record) {
  const normalized = normalizeRepairRecord(record)
  return normalized.type === REPAIRTICKET_RECORD_TYPE_TICKET ? normalized.id : normalized.ticketId
}

export function repairRecordOpType (record) {
  const type = typeof record === 'string' ? record : normalizeRepairRecord(record).type
  if (type === REPAIRTICKET_RECORD_TYPE_TICKET) return 'ticket'
  if (type === REPAIRTICKET_RECORD_TYPE_CLAIM) return 'claim'
  if (type === REPAIRTICKET_RECORD_TYPE_RECEIPT) return 'receipt'
  if (type === REPAIRTICKET_RECORD_TYPE_CLOSE) return 'close'
  throw new Error('RepairTicket: unsupported record type')
}

function normalizeRepairCore (input, opts = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('RepairTicket: record must be an object')
  const version = input.version == null ? REPAIRTICKET_RECORD_VERSION : input.version
  const type = input.type || REPAIRTICKET_RECORD_TYPE_TICKET
  if (version !== REPAIRTICKET_RECORD_VERSION) throw new Error('RepairTicket: unsupported record version')
  if (!RECORD_TYPES.has(type)) throw new Error('RepairTicket: unsupported record type')

  const createdAt = normalizeIsoTime(input.createdAt, 'createdAt')
  const expiresAt = normalizeIsoTime(input.expiresAt, 'expiresAt')
  if (Date.parse(expiresAt) <= Date.parse(createdAt)) throw new Error('RepairTicket: expiresAt must be after createdAt')

  const out = {
    version,
    type,
    createdAt,
    expiresAt,
    signer: normalizeSigner(input.signer)
  }

  if (type === REPAIRTICKET_RECORD_TYPE_TICKET) {
    out.target = normalizeTarget(input.target)
    out.repair = normalizeRepairRequest(input.repair)
  } else {
    out.ticketId = normalizeHex(input.ticketId, 64, 'ticketId')
    if (type === REPAIRTICKET_RECORD_TYPE_CLAIM) {
      out.relay = normalizeRelay(input.relay)
      out.action = normalizeAction(input.action)
      if (input.note != null) out.note = normalizeShortString(input.note, 'note', SHORT)
    } else if (type === REPAIRTICKET_RECORD_TYPE_RECEIPT) {
      out.relay = normalizeRelay(input.relay)
      out.proof = normalizeProof(input.proof)
      out.result = normalizeResult(input.result)
    } else {
      out.outcome = normalizeOutcome(input.outcome)
      out.evidence = normalizeEvidence(input.evidence)
      if (input.note != null) out.note = normalizeShortString(input.note, 'note', SHORT)
    }
  }

  if (input.id != null) out.id = normalizeHex(input.id, 64, 'id')
  else if (!opts.allowMissingId) throw new Error('RepairTicket: missing id')
  return out
}

function normalizeSigner (signer) {
  if (!signer || typeof signer !== 'object' || Array.isArray(signer)) throw new Error('RepairTicket: signer required')
  return {
    publicKey: normalizeHex(signer.publicKey, 64, 'signer.publicKey'),
    role: signer.role == null ? null : normalizeShortString(signer.role, 'signer.role', 64),
    appId: signer.appId == null ? null : normalizeShortString(signer.appId, 'signer.appId', SHORT)
  }
}

function normalizeTarget (target) {
  if (!target || typeof target !== 'object' || Array.isArray(target)) throw new Error('RepairTicket: target required')
  const key = target.key == null ? null : normalizeHex(target.key, 64, 'target.key')
  const keyHash = target.keyHash == null ? null : normalizeHex(target.keyHash, 64, 'target.keyHash')
  if (!key && !keyHash) throw new Error('RepairTicket: target key or keyHash required')
  return {
    kind: normalizeShortString(target.kind || 'hypercore', 'target.kind', 64),
    key,
    keyHash
  }
}

function normalizeRepairRequest (repair) {
  if (!repair || typeof repair !== 'object' || Array.isArray(repair)) throw new Error('RepairTicket: repair required')
  return {
    reason: normalizeShortString(repair.reason, 'repair.reason', 128),
    priority: repair.priority == null ? 50 : normalizeInteger(repair.priority, 'repair.priority', 0, 100),
    desiredReplicas: repair.desiredReplicas == null ? 3 : normalizeInteger(repair.desiredReplicas, 'repair.desiredReplicas', 1, 1000),
    observedReplicas: repair.observedReplicas == null ? null : normalizeInteger(repair.observedReplicas, 'repair.observedReplicas', 0, 1000),
    evidence: normalizeEvidence(repair.evidence),
    note: repair.note == null ? null : normalizeShortString(repair.note, 'repair.note', SHORT)
  }
}

function normalizeRelay (relay) {
  if (!relay || typeof relay !== 'object' || Array.isArray(relay)) throw new Error('RepairTicket: relay required')
  return {
    url: normalizeHttpUrl(relay.url),
    operatorKey: relay.operatorKey == null ? null : normalizeHex(relay.operatorKey, 64, 'relay.operatorKey')
  }
}

function normalizeProof (proof) {
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) throw new Error('RepairTicket: proof required')
  return {
    kind: normalizeShortString(proof.kind || 'witnesslog', 'proof.kind', 64),
    witnessId: proof.witnessId == null ? null : normalizeHex(proof.witnessId, 64, 'proof.witnessId'),
    observedAt: proof.observedAt == null ? null : normalizeIsoTime(proof.observedAt, 'proof.observedAt'),
    headSeq: proof.headSeq == null ? null : normalizeInteger(proof.headSeq, 'proof.headSeq', 0),
    digest: proof.digest == null ? null : normalizeShortString(proof.digest, 'proof.digest', SHORT)
  }
}

function normalizeResult (result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('RepairTicket: result required')
  return {
    ok: result.ok === true,
    latencyMs: result.latencyMs == null ? null : normalizeNumber(result.latencyMs, 'result.latencyMs', 0),
    bytes: result.bytes == null ? null : normalizeInteger(result.bytes, 'result.bytes', 0),
    errorCode: result.errorCode == null ? null : normalizeShortString(result.errorCode, 'result.errorCode', 128)
  }
}

function normalizeEvidence (evidence) {
  if (evidence == null) return []
  if (!Array.isArray(evidence) || evidence.length > MAX_EVIDENCE) throw new Error('RepairTicket: invalid evidence')
  return evidence.map((id, index) => normalizeHex(id, 64, 'evidence.' + index))
}

function normalizeAction (action) {
  return normalizeShortString(action || 'seed', 'action', 64)
}

function normalizeOutcome (outcome) {
  return normalizeShortString(outcome || 'repaired', 'outcome', 64)
}

function assertRepairTimestamps (record, opts = {}) {
  const now = opts.now == null
    ? Date.now()
    : (opts.now instanceof Date ? opts.now.getTime() : (typeof opts.now === 'number' ? opts.now : Date.parse(opts.now)))
  if (!Number.isFinite(now)) throw new Error('RepairTicket: invalid now')
  const created = Date.parse(record.createdAt)
  const expires = Date.parse(record.expiresAt)
  const maxSkew = positiveMs(opts.maxClockSkewMs, REPAIRTICKET_DEFAULT_MAX_CLOCK_SKEW_MS)
  const maxAge = positiveMs(opts.maxAgeMs, REPAIRTICKET_DEFAULT_MAX_AGE_MS)
  const maxTtl = positiveMs(opts.maxTtlMs, REPAIRTICKET_DEFAULT_MAX_TTL_MS)
  if (created > now + maxSkew) throw new Error('RepairTicket: record is from the future')
  if (created < now - maxAge) throw new Error('RepairTicket: record is stale')
  if (expires < now - maxSkew) throw new Error('RepairTicket: record is expired')
  if (expires - created > maxTtl) throw new Error('RepairTicket: record TTL too long')
}

function repairRecordId (record) {
  return createHash('sha256')
    .update(REPAIRTICKET_SIGNATURE_DOMAIN + '.id|' + stable(record))
    .digest('hex')
}

function unsignedRepairRecord (record) {
  return without(record, ['signature'])
}

function without (obj, keys) {
  const blocked = new Set(keys)
  const out = {}
  for (const key of Object.keys(obj)) {
    if (!blocked.has(key)) out[key] = obj[key]
  }
  return out
}

function clone (value) {
  return value == null ? value : JSON.parse(JSON.stringify(value))
}

function stable (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
}

function normalizeHex (value, length, label) {
  if (typeof value !== 'string') throw new Error('RepairTicket: invalid ' + label)
  const normalized = value.trim().toLowerCase()
  if (length === 64 && !HEX_32.test(normalized)) throw new Error('RepairTicket: invalid ' + label)
  if (length === 128 && !HEX_64.test(normalized)) throw new Error('RepairTicket: invalid ' + label)
  return normalized
}

function normalizeTargetQuery (value) {
  if (typeof value !== 'string') return null
  const normalized = value.trim().toLowerCase()
  return HEX_32.test(normalized) ? normalized : null
}

function normalizeIsoTime (value, label) {
  if (typeof value !== 'string' || !value) throw new Error('RepairTicket: invalid ' + label)
  const ms = Date.parse(value)
  if (!Number.isFinite(ms)) throw new Error('RepairTicket: invalid ' + label)
  return new Date(ms).toISOString()
}

function normalizeHttpUrl (value) {
  if (typeof value !== 'string' || !value || value.length > URL_MAX) throw new Error('RepairTicket: invalid relay.url')
  let url
  try {
    url = new URL(value)
  } catch {
    throw new Error('RepairTicket: invalid relay.url')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('RepairTicket: invalid relay.url')
  url.hash = ''
  return url.toString()
}

function normalizeShortString (value, label, max) {
  if (typeof value !== 'string' || !value || value.length > max) throw new Error('RepairTicket: invalid ' + label)
  return value
}

function normalizeInteger (value, label, min, max = Number.MAX_SAFE_INTEGER) {
  const number = Number(value)
  if (!Number.isSafeInteger(number) || number < min || number > max) throw new Error('RepairTicket: invalid ' + label)
  return number
}

function normalizeNumber (value, label, min) {
  const number = Number(value)
  if (!Number.isFinite(number) || number < min) throw new Error('RepairTicket: invalid ' + label)
  return number
}

function positiveMs (value, fallback) {
  const number = Number(value)
  return Number.isFinite(number) && number > 0 ? number : fallback
}

function decodeHexOrBuffer (value, bytes, label) {
  if (typeof value === 'string') {
    const hex = value.trim().toLowerCase()
    if (!/^[0-9a-f]+$/i.test(hex) || hex.length !== bytes * 2) throw new Error('RepairTicket: invalid ' + label)
    return b4a.from(hex, 'hex')
  }
  if (value && typeof value.byteLength === 'number' && value.byteLength === bytes) return value
  throw new Error('RepairTicket: invalid ' + label)
}
