import { createHash } from 'node:crypto'
import sodium from 'sodium-universal'
import b4a from 'b4a'

export const WITNESSLOG_NAMESPACE = 'witness'
export const WITNESSLOG_RECORD_VERSION = 1
export const WITNESSLOG_RECORD_TYPE_AVAILABILITY = 'hiverelay.witness.availability'
export const WITNESSLOG_SIGNATURE_DOMAIN = 'hiverelay.witnesslog.v1'
export const WITNESSLOG_DEFAULT_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000
export const WITNESSLOG_DEFAULT_MAX_AGE_MS = 24 * 60 * 60 * 1000
export const WITNESSLOG_DEFAULT_MAX_TTL_MS = 60 * 60 * 1000

const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_64 = /^[0-9a-f]{128}$/i
const PUBKEY_BYTES = 32
const SIG_BYTES = 64
const URL_MAX = 2048
const SHORT = 256

export function createWitnessRecord (input = {}) {
  const core = normalizeWitnessCore(input, { allowMissingId: true })
  const withId = {
    id: core.id || witnessRecordId(core),
    ...without(core, ['id'])
  }
  return normalizeWitnessCore(withId)
}

export function signWitnessRecord (input, secretKey) {
  const record = createWitnessRecord(input)
  const key = decodeHexOrBuffer(secretKey, 64, 'secret key')
  const signature = b4a.alloc(SIG_BYTES)
  sodium.crypto_sign_detached(signature, witnessRecordBytes(record), key)
  return {
    ...record,
    signature: b4a.toString(signature, 'hex')
  }
}

export function verifyWitnessRecord (input, opts = {}) {
  let record
  try {
    record = normalizeWitnessRecord(input)
    assertWitnessTimestamps(record, opts)
  } catch {
    return false
  }

  const signature = b4a.from(record.signature, 'hex')
  const publicKey = b4a.from(record.observer.publicKey, 'hex')
  if (signature.byteLength !== SIG_BYTES || publicKey.byteLength !== PUBKEY_BYTES) return false
  return sodium.crypto_sign_verify_detached(signature, witnessRecordBytes(record), publicKey)
}

export function assertWitnessRecord (input, opts = {}) {
  const record = normalizeWitnessRecord(input)
  assertWitnessTimestamps(record, opts)
  if (!verifyWitnessRecord(record, opts)) throw new Error('WitnessLog: bad signature')
  return record
}

export function canonicalWitnessRecord (input) {
  const record = input && input.signature
    ? unsignedWitnessRecord(normalizeWitnessRecord(input))
    : createWitnessRecord(input)
  return stable(record)
}

export function witnessRecordBytes (input) {
  const record = input && input.signature ? unsignedWitnessRecord(normalizeWitnessRecord(input)) : createWitnessRecord(input)
  return b4a.from(WITNESSLOG_SIGNATURE_DOMAIN + '|' + stable(record), 'utf8')
}

// blake2b-256 of the raw hypercore key -> the public target id, so a witness
// can attest availability without ever exposing the raw key.
export function hashTargetKey (keyHex) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from(String(keyHex).toLowerCase(), 'hex'))
  return b4a.toString(out, 'hex')
}

export function redactWitnessRecord (input) {
  const record = normalizeWitnessRecord(input)
  const target = { ...record.target }
  // Read-path redaction ALWAYS strips the raw key — deriving keyHash for a
  // key-only record so no public read leaks the raw hypercore key.
  if (target.key) {
    if (!target.keyHash) target.keyHash = hashTargetKey(target.key)
    delete target.key
  }
  return {
    id: record.id,
    version: record.version,
    type: record.type,
    observedAt: record.observedAt,
    expiresAt: record.expiresAt,
    observer: { ...record.observer },
    relay: { ...record.relay },
    target,
    probe: { ...record.probe },
    result: { ...record.result },
    signature: record.signature
  }
}

export function witnessRecordMarker (input) {
  const record = normalizeWitnessRecord(input)
  return {
    id: record.id,
    observedAt: record.observedAt,
    expiresAt: record.expiresAt,
    observer: record.observer.publicKey,
    relay: record.relay.url,
    // Never expose the raw key on the public marker/SSE surface.
    target: record.target.keyHash || (record.target.key ? hashTargetKey(record.target.key) : null),
    targetKind: record.target.kind,
    ok: record.result.ok,
    latencyMs: record.result.latencyMs,
    httpStatus: record.result.httpStatus == null ? null : record.result.httpStatus,
    errorCode: record.result.errorCode == null ? null : record.result.errorCode
  }
}

export function targetMatchesWitnessRecord (record, target) {
  if (!target) return true
  const normalized = normalizeTargetQuery(target)
  if (!normalized) return false
  const witness = normalizeWitnessRecord(record).target
  return witness.key === normalized || witness.keyHash === normalized
}

export function normalizeWitnessRecord (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('WitnessLog: record must be an object')
  if (input.signature == null) throw new Error('WitnessLog: missing signature')
  const signature = normalizeHex(input.signature, 128, 'signature')
  return {
    ...normalizeWitnessCore(input),
    signature
  }
}

export function normalizeWitnessOutboxRecord (input) {
  const record = normalizeWitnessRecord(input)
  return {
    ...record,
    _ns: WITNESSLOG_NAMESPACE
  }
}

export function verifyWitnessOutboxRecord ({ appId, data }, opts = {}) {
  if (!data || typeof data !== 'object') return false
  if (data._ns !== WITNESSLOG_NAMESPACE) return false
  const record = stripOutboxFields(data)
  if (!verifyWitnessRecord(record, opts)) return false
  return typeof appId === 'string' && appId.toLowerCase() === record.observer.publicKey.toLowerCase()
}

export function stripOutboxFields (data) {
  const clone = { ...data }
  delete clone._ns
  return clone
}

function normalizeWitnessCore (input, opts = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('WitnessLog: record must be an object')
  const version = input.version == null ? WITNESSLOG_RECORD_VERSION : input.version
  const type = input.type || WITNESSLOG_RECORD_TYPE_AVAILABILITY
  if (version !== WITNESSLOG_RECORD_VERSION) throw new Error('WitnessLog: unsupported record version')
  if (type !== WITNESSLOG_RECORD_TYPE_AVAILABILITY) throw new Error('WitnessLog: unsupported record type')

  const observedAt = normalizeIsoTime(input.observedAt, 'observedAt')
  const expiresAt = normalizeIsoTime(input.expiresAt, 'expiresAt')
  if (Date.parse(expiresAt) <= Date.parse(observedAt)) throw new Error('WitnessLog: expiresAt must be after observedAt')

  const out = {
    version,
    type,
    observedAt,
    expiresAt,
    observer: normalizeObserver(input.observer),
    relay: normalizeRelay(input.relay),
    target: normalizeTarget(input.target),
    probe: normalizeProbe(input.probe),
    result: normalizeResult(input.result)
  }
  if (input.id != null) out.id = normalizeId(input.id)
  else if (!opts.allowMissingId) throw new Error('WitnessLog: missing id')
  return out
}

function normalizeObserver (observer) {
  if (!observer || typeof observer !== 'object' || Array.isArray(observer)) throw new Error('WitnessLog: observer required')
  return {
    publicKey: normalizeHex(observer.publicKey, 64, 'observer.publicKey'),
    appId: observer.appId == null ? null : normalizeShortString(observer.appId, 'observer.appId', SHORT)
  }
}

function normalizeRelay (relay) {
  if (!relay || typeof relay !== 'object' || Array.isArray(relay)) throw new Error('WitnessLog: relay required')
  return {
    url: normalizeHttpUrl(relay.url),
    operatorKey: relay.operatorKey == null ? null : normalizeHex(relay.operatorKey, 64, 'relay.operatorKey')
  }
}

function normalizeTarget (target) {
  if (!target || typeof target !== 'object' || Array.isArray(target)) throw new Error('WitnessLog: target required')
  const key = target.key == null ? null : normalizeHex(target.key, 64, 'target.key')
  const keyHash = target.keyHash == null ? null : normalizeHex(target.keyHash, 64, 'target.keyHash')
  if (!key && !keyHash) throw new Error('WitnessLog: target key or keyHash required')
  return {
    kind: normalizeShortString(target.kind || 'hypercore', 'target.kind', 64),
    key,
    keyHash
  }
}

function normalizeProbe (probe) {
  if (!probe || typeof probe !== 'object' || Array.isArray(probe)) throw new Error('WitnessLog: probe required')
  return {
    nonce: normalizeShortString(probe.nonce, 'probe.nonce', 256),
    method: normalizeShortString(probe.method || 'gateway-head', 'probe.method', 64),
    range: probe.range == null ? null : normalizeRange(probe.range)
  }
}

function normalizeResult (result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('WitnessLog: result required')
  return {
    ok: result.ok === true,
    httpStatus: result.httpStatus == null ? null : normalizeInteger(result.httpStatus, 'result.httpStatus', 100, 599),
    latencyMs: normalizeNumber(result.latencyMs, 'result.latencyMs', 0),
    bytes: result.bytes == null ? null : normalizeInteger(result.bytes, 'result.bytes', 0),
    headSeq: result.headSeq == null ? null : normalizeInteger(result.headSeq, 'result.headSeq', 0),
    digest: result.digest == null ? null : normalizeShortString(result.digest, 'result.digest', 256),
    errorCode: result.errorCode == null ? null : normalizeShortString(result.errorCode, 'result.errorCode', 128)
  }
}

function normalizeRange (range) {
  if (!range || typeof range !== 'object' || Array.isArray(range)) throw new Error('WitnessLog: probe.range must be an object')
  return {
    start: range.start == null ? null : normalizeInteger(range.start, 'probe.range.start', 0),
    end: range.end == null ? null : normalizeInteger(range.end, 'probe.range.end', 0)
  }
}

function assertWitnessTimestamps (record, opts = {}) {
  const now = opts.now == null
    ? Date.now()
    : (opts.now instanceof Date ? opts.now.getTime() : (typeof opts.now === 'number' ? opts.now : Date.parse(opts.now)))
  if (!Number.isFinite(now)) throw new Error('WitnessLog: invalid now')
  const observed = Date.parse(record.observedAt)
  const expires = Date.parse(record.expiresAt)
  const maxSkew = positiveMs(opts.maxClockSkewMs, WITNESSLOG_DEFAULT_MAX_CLOCK_SKEW_MS)
  const maxAge = positiveMs(opts.maxAgeMs, WITNESSLOG_DEFAULT_MAX_AGE_MS)
  const maxTtl = positiveMs(opts.maxTtlMs, WITNESSLOG_DEFAULT_MAX_TTL_MS)
  if (observed > now + maxSkew) throw new Error('WitnessLog: observation is from the future')
  if (observed < now - maxAge) throw new Error('WitnessLog: observation is stale')
  if (expires < now - maxSkew) throw new Error('WitnessLog: observation is expired')
  if (expires - observed > maxTtl) throw new Error('WitnessLog: observation TTL too long')
}

function witnessRecordId (record) {
  return createHash('sha256')
    .update(WITNESSLOG_SIGNATURE_DOMAIN + '.id|' + stable(record))
    .digest('hex')
}

function unsignedWitnessRecord (record) {
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

function stable (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
}

function normalizeHex (value, length, label) {
  if (typeof value !== 'string') throw new Error('WitnessLog: invalid ' + label)
  const normalized = value.trim().toLowerCase()
  if (length === 64 && !HEX_32.test(normalized)) throw new Error('WitnessLog: invalid ' + label)
  if (length === 128 && !HEX_64.test(normalized)) throw new Error('WitnessLog: invalid ' + label)
  return normalized
}

function normalizeId (value) {
  return normalizeHex(value, 64, 'id')
}

function normalizeTargetQuery (value) {
  if (typeof value !== 'string') return null
  const normalized = value.trim().toLowerCase()
  return HEX_32.test(normalized) ? normalized : null
}

function normalizeIsoTime (value, label) {
  if (typeof value !== 'string' || !value) throw new Error('WitnessLog: invalid ' + label)
  const ms = Date.parse(value)
  if (!Number.isFinite(ms)) throw new Error('WitnessLog: invalid ' + label)
  return new Date(ms).toISOString()
}

function normalizeHttpUrl (value) {
  if (typeof value !== 'string' || !value || value.length > URL_MAX) throw new Error('WitnessLog: invalid relay.url')
  let url
  try {
    url = new URL(value)
  } catch {
    throw new Error('WitnessLog: invalid relay.url')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('WitnessLog: invalid relay.url')
  url.hash = ''
  return url.toString()
}

function normalizeShortString (value, label, max) {
  if (typeof value !== 'string' || !value || value.length > max) throw new Error('WitnessLog: invalid ' + label)
  return value
}

function normalizeInteger (value, label, min, max = Number.MAX_SAFE_INTEGER) {
  const number = Number(value)
  if (!Number.isSafeInteger(number) || number < min || number > max) throw new Error('WitnessLog: invalid ' + label)
  return number
}

function normalizeNumber (value, label, min) {
  const number = Number(value)
  if (!Number.isFinite(number) || number < min) throw new Error('WitnessLog: invalid ' + label)
  return number
}

function positiveMs (value, fallback) {
  const number = Number(value)
  return Number.isFinite(number) && number > 0 ? number : fallback
}

function decodeHexOrBuffer (value, bytes, label) {
  if (typeof value === 'string') {
    const hex = value.trim().toLowerCase()
    if (!/^[0-9a-f]+$/i.test(hex) || hex.length !== bytes * 2) throw new Error('WitnessLog: invalid ' + label)
    return b4a.from(hex, 'hex')
  }
  if (value && typeof value.byteLength === 'number' && value.byteLength === bytes) return value
  throw new Error('WitnessLog: invalid ' + label)
}
