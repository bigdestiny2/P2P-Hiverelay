import b4a from 'b4a'
import { blake2b256 } from '@hiverelay/blind-protocol/hashes'
import {
  FORWARD_HTTPS_OUTSTANDING_STATE_V3,
  applyForwardHttpsResultV3,
  assertForwardHttpsPersistedSessionRecordV3,
  markForwardHttpsAwaitingDefinitiveTargetV3,
  prepareForwardHttpsOriginPersistenceV3
} from './browser-forward-state-v3.js'

const MAGIC = b4a.from('HRBCBV03', 'ascii')
const MANIFEST_BYTES = 214

function fail (message, code = 'BAD_BROWSER_ARTIFACT_V3') {
  const error = new Error(message)
  error.code = code
  throw error
}

function bytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  value = b4a.from(value)
  if (value.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  if (nonzero) {
    let any = false
    for (const byte of value) any ||= byte !== 0
    if (!any) fail(`${field} must be nonzero`)
  }
  return value
}

function writeU32 (output, value, offset, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) fail(`${field} is outside u32`)
  output[offset] = value >>> 24
  output[offset + 1] = value >>> 16
  output[offset + 2] = value >>> 8
  output[offset + 3] = value
}

function readU32 (input, offset) {
  return input[offset] * 0x1000000 + input[offset + 1] * 0x10000 + input[offset + 2] * 0x100 + input[offset + 3]
}

function length64 (length) {
  const output = b4a.alloc(8)
  let value = BigInt(length)
  for (let i = 7; i >= 0; i--) {
    output[i] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function domainLengthHash (domain, value) {
  value = b4a.from(value)
  return blake2b256(b4a.concat([b4a.from(domain, 'ascii'), length64(value.byteLength), value]))
}

export const hashBlindClientBrowserArtifactV3 = value => domainLengthHash('hiverelay.blind.client-browser-artifact-hash.v3', value)
export const hashBlindClientBrowserArtifactManifestV3 = value => domainLengthHash('hiverelay.blind.client-browser-manifest-hash.v3', value)
export const hashBlindClientBrowserSourceClosureV3 = value => domainLengthHash('hiverelay.blind.client-browser-source-closure-hash.v3', value)

export function encodeBlindClientBrowserArtifactManifestV3 (value) {
  if (!value || value.version !== 3) fail('browser artifact v3 manifest version is invalid')
  const output = b4a.alloc(MANIFEST_BYTES)
  b4a.copy(MAGIC, output, 0)
  output[8] = 0
  output[9] = 3
  let offset = 10
  for (const field of [
    'baseBrowserV2ArtifactHash',
    'baseBrowserV2ManifestHash',
    'wireV3AbiHash',
    'clientCompositionV3FormatHash',
    'artifactHash',
    'sourceClosureHash'
  ]) {
    b4a.copy(bytes(value[field], 32, field, true), output, offset)
    offset += 32
  }
  writeU32(output, value.exactRequestBytes, offset, 'exactRequestBytes'); offset += 4
  writeU32(output, value.exactResultBytes, offset, 'exactResultBytes'); offset += 4
  writeU32(output, value.forwardReadinessOperationBits, offset, 'forwardReadinessOperationBits'); offset += 4
  if (value.exactRequestBytes !== 65_536 || value.exactResultBytes !== 65_536 || value.forwardReadinessOperationBits !== 0) {
    fail('browser artifact v3 fixed sizes or readiness are invalid')
  }
  if (offset !== MANIFEST_BYTES) fail('browser artifact v3 manifest encoder length mismatch')
  return output
}

export function decodeBlindClientBrowserArtifactManifestV3 (input) {
  input = b4a.from(input)
  if (input.byteLength !== MANIFEST_BYTES || !b4a.equals(input.subarray(0, 8), MAGIC) || input[8] !== 0 || input[9] !== 3) {
    fail('browser artifact v3 manifest fixed header is invalid')
  }
  let offset = 10
  const value = { version: 3 }
  for (const field of [
    'baseBrowserV2ArtifactHash',
    'baseBrowserV2ManifestHash',
    'wireV3AbiHash',
    'clientCompositionV3FormatHash',
    'artifactHash',
    'sourceClosureHash'
  ]) {
    value[field] = b4a.from(input.subarray(offset, offset + 32))
    offset += 32
  }
  value.exactRequestBytes = readU32(input, offset); offset += 4
  value.exactResultBytes = readU32(input, offset); offset += 4
  value.forwardReadinessOperationBits = readU32(input, offset); offset += 4
  if (!b4a.equals(encodeBlindClientBrowserArtifactManifestV3(value), input)) fail('browser artifact v3 manifest is not canonical')
  return Object.freeze(value)
}

export function verifyBlindClientBrowserArtifactV3 (artifactBytes, manifestBytes, sourceClosureBytes, expected = {}) {
  const manifest = decodeBlindClientBrowserArtifactManifestV3(manifestBytes)
  if (!b4a.equals(hashBlindClientBrowserArtifactV3(artifactBytes), manifest.artifactHash)) fail('browser artifact v3 hash mismatch')
  if (!b4a.equals(hashBlindClientBrowserSourceClosureV3(sourceClosureBytes), manifest.sourceClosureHash)) fail('browser artifact v3 source closure hash mismatch')
  for (const field of [
    'wireV3AbiHash', 'clientCompositionV3FormatHash', 'baseBrowserV2ArtifactHash', 'baseBrowserV2ManifestHash'
  ]) {
    if (expected[field] != null && !b4a.equals(bytes(expected[field], 32, `expected ${field}`, true), manifest[field])) {
      fail(`browser artifact v3 ${field} mismatch`)
    }
  }
  return manifest
}

export class BlindClientBrowserCrashModelV3 {
  #record

  constructor () {
    this.#record = null
    this.fetchCount = 0
  }

  get outstanding () {
    if (!this.#record || this.#record.outstandingState === FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE) return null
    return Object.freeze({
      requestBytes: b4a.from(this.#record.outstandingOriginRequest),
      originRequestCommitment: b4a.from(this.#record.outstandingOriginRequestCommitment)
    })
  }

  get nextSequence () {
    return this.#record == null ? 0n : BigInt(this.#record.nextSequence)
  }

  get previousTargetResultHash () {
    return this.#record == null ? b4a.alloc(32) : b4a.from(this.#record.previousTargetResultHash)
  }

  get lastDefinitiveTargetResult () {
    return this.#record == null || this.#record.lastDefinitiveTargetResult.byteLength === 0
      ? null
      : b4a.from(this.#record.lastDefinitiveTargetResult)
  }

  get terminal () {
    return this.#record != null && this.#record.terminal === 1
  }

  get targetFin () {
    return this.#record != null && this.#record.targetFin
  }

  inspectRecord () {
    return this.#record == null ? null : assertForwardHttpsPersistedSessionRecordV3(this.#record)
  }

  persistBeforeFetch (value) {
    const prepared = prepareForwardHttpsOriginPersistenceV3(this.#record, value)
    this.#record = prepared.record
    if (prepared.disposition === 'CONFLICT_TERMINAL') {
      fail('browser changed an already-persisted outstanding request', 'TERMINAL_BROWSER_FORWARD_SESSION')
    }
    return b4a.from(this.#record.outstandingOriginRequest)
  }

  beginFetch () {
    if (!this.#record) fail('network I/O is forbidden before exact request persistence')
    this.#record = markForwardHttpsAwaitingDefinitiveTargetV3(this.#record)
    this.fetchCount++
    return b4a.from(this.#record.outstandingOriginRequest)
  }

  restartExactRetry () {
    if (!this.#record) fail('no persisted request exists for restart retry')
    this.#record = markForwardHttpsAwaitingDefinitiveTargetV3(this.#record)
    return b4a.from(this.#record.outstandingOriginRequest)
  }

  receiveResult (resultBytes) {
    if (!this.#record) fail('result has no persisted request')
    const applied = applyForwardHttpsResultV3(this.#record, resultBytes)
    this.#record = applied.record
    return applied.outcome
  }
}
