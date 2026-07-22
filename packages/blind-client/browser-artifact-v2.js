import b4a from 'b4a'
import { blake2b256 } from '@hiverelay/blind-protocol/hashes'

const MAGIC = b4a.from('HRBCBV02', 'ascii')
const MANIFEST_BYTES = 214

function fail (message) {
  const error = new Error(message)
  error.code = 'BAD_BROWSER_ARTIFACT_V2'
  throw error
}

function bytes32 (value, field) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  value = b4a.from(value)
  if (value.byteLength !== 32) fail(`${field} must be exactly 32 bytes`)
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

export const hashBlindClientBrowserArtifactV2 = value => domainLengthHash('hiverelay.blind.client-browser-artifact-hash.v2', value)
export const hashBlindClientBrowserArtifactManifestV2 = value => domainLengthHash('hiverelay.blind.client-browser-manifest-hash.v2', value)
export const hashBlindClientBrowserSourceClosureV2 = value => domainLengthHash('hiverelay.blind.client-browser-source-closure-hash.v2', value)

export function encodeBlindClientBrowserArtifactManifestV2 (value) {
  if (!value || value.version !== 2) fail('browser artifact v2 manifest version is invalid')
  const output = b4a.alloc(MANIFEST_BYTES)
  b4a.copy(MAGIC, output, 0)
  output[8] = 0
  output[9] = 2
  let offset = 10
  for (const field of [
    'baseBrowserV1ArtifactHash',
    'baseBrowserV1ManifestHash',
    'wireV2AbiHash',
    'clientCompositionV2FormatHash',
    'artifactHash',
    'sourceClosureHash'
  ]) {
    b4a.copy(bytes32(value[field], field), output, offset)
    offset += 32
  }
  writeU32(output, value.exactRequestBytes, offset, 'exactRequestBytes'); offset += 4
  writeU32(output, value.exactResultBytes, offset, 'exactResultBytes'); offset += 4
  writeU32(output, value.forwardReadinessOperationBits, offset, 'forwardReadinessOperationBits'); offset += 4
  if (value.exactRequestBytes !== 65_536 || value.exactResultBytes !== 65_536 || value.forwardReadinessOperationBits !== 0) {
    fail('browser artifact v2 fixed sizes or readiness are invalid')
  }
  if (offset !== MANIFEST_BYTES) fail('browser artifact v2 manifest encoder length mismatch')
  return output
}

export function decodeBlindClientBrowserArtifactManifestV2 (input) {
  input = b4a.from(input)
  if (input.byteLength !== MANIFEST_BYTES || !b4a.equals(input.subarray(0, 8), MAGIC) || input[8] !== 0 || input[9] !== 2) {
    fail('browser artifact v2 manifest fixed header is invalid')
  }
  let offset = 10
  const value = { version: 2 }
  for (const field of [
    'baseBrowserV1ArtifactHash',
    'baseBrowserV1ManifestHash',
    'wireV2AbiHash',
    'clientCompositionV2FormatHash',
    'artifactHash',
    'sourceClosureHash'
  ]) {
    value[field] = b4a.from(input.subarray(offset, offset + 32))
    offset += 32
  }
  value.exactRequestBytes = readU32(input, offset); offset += 4
  value.exactResultBytes = readU32(input, offset); offset += 4
  value.forwardReadinessOperationBits = readU32(input, offset); offset += 4
  if (!b4a.equals(encodeBlindClientBrowserArtifactManifestV2(value), input)) fail('browser artifact v2 manifest is not canonical')
  return Object.freeze(value)
}

export function verifyBlindClientBrowserArtifactV2 (artifactBytes, manifestBytes, expected = {}) {
  const manifest = decodeBlindClientBrowserArtifactManifestV2(manifestBytes)
  if (!b4a.equals(hashBlindClientBrowserArtifactV2(artifactBytes), manifest.artifactHash)) fail('browser artifact v2 hash mismatch')
  for (const field of ['wireV2AbiHash', 'clientCompositionV2FormatHash', 'baseBrowserV1ArtifactHash', 'baseBrowserV1ManifestHash']) {
    if (expected[field] != null && !b4a.equals(bytes32(expected[field], `expected ${field}`), manifest[field])) {
      fail(`browser artifact v2 ${field} mismatch`)
    }
  }
  return manifest
}
