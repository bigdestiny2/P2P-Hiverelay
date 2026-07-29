import b4a from 'b4a'
import sodium from './crypto.js'

const MAGIC = b4a.from('HIVERELAY-BLIND-CLIENT-BROWSER-V1', 'ascii')
const ARTIFACT_HASH_DOMAIN = b4a.from('hiverelay.blind.client-browser-artifact-hash.v1', 'ascii')
const MANIFEST_HASH_DOMAIN = b4a.from('hiverelay.blind.client-browser-artifact-manifest-hash.v1', 'ascii')
const CLOSURE_HASH_DOMAIN = b4a.from('hiverelay.blind.client-browser-source-closure-hash.v1', 'ascii')
const MAX_TEXT_BYTES = 1024
const MAX_ARTIFACT_BYTES = 320 * 1024
const MAX_ARTIFACT_GZIP_BYTES = 90 * 1024

export const BLIND_CLIENT_BROWSER_ARTIFACT_STATUS = Object.freeze({
  artifactPath: 'browser-artifacts/blind-client-control-v1.mjs',
  manifestPath: 'browser-artifacts/blind-client-control-v1.manifest.cenc',
  chromiumEvidencePath: 'browser-artifacts/blind-client-control-v1.chromium-evidence.json',
  crossHostEvidencePath: 'browser-artifacts/blind-client-control-v1.cross-host-evidence.json',
  tupleBound: true,
  sourceClosureBound: true,
  deterministicGeneratorReady: true,
  sameHostByteEqualityProven: true,
  crossHostByteEqualityProven: false,
  realBrowserImportProven: false,
  packageSubpathsExported: true,
  maxArtifactBytes: MAX_ARTIFACT_BYTES,
  maxArtifactGzipBytes: MAX_ARTIFACT_GZIP_BYTES,
  finalTupleBound: true,
  clientCompositionTupleBound: true,
  releaseReady: false,
  releaseBlockers: Object.freeze([
    'REAL_CHROMIUM_HASH_BOUND_EVIDENCE_NOT_VERIFIED',
    'CROSS_HOST_HASH_BOUND_EVIDENCE_NOT_VERIFIED'
  ])
})

const CHROMIUM_EVIDENCE_CHECKS = Object.freeze([
  'STANDALONE_ESM_IMPORT',
  'REQUIRED_CONTROL_EXPORTS',
  'CLOSED_EXTERNAL_PROFILE_DECODER',
  'WEBCRYPTO_AES_256_GCM_ROUNDTRIP',
  'SIGNED_CAPABILITY_CELL_COMPOSITION',
  'PLAINTEXT_SENTINEL_ABSENT_FROM_REQUEST'
])
const CROSS_HOST_EVIDENCE_CHECKS = Object.freeze([
  'CLEAN_LINUX_DEPENDENCY_INSTALL',
  'FROZEN_GENERATOR_CHECK',
  'ARTIFACT_BYTE_EQUALITY',
  'MANIFEST_BYTE_EQUALITY'
])

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function bytes (value, field) {
  if (b4a.isBuffer(value)) return value
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  if (value instanceof ArrayBuffer) return b4a.from(value)
  fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} must be bytes`)
}

function fixed (value, length, field) {
  value = bytes(value, field)
  if (value.byteLength !== length) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} must be exactly ${length} bytes`)
  }
  return b4a.from(value)
}

function exactObject (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} must be an object`)
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} has an unexpected prototype`)
  }
  const keys = Reflect.ownKeys(value)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string') ||
      fields.some(name => !Object.prototype.hasOwnProperty.call(value, name))) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} fields are missing or unexpected`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (fields.some(name => !descriptors[name].enumerable ||
      !Object.prototype.hasOwnProperty.call(descriptors[name], 'value'))) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} fields must be enumerable data properties`)
  }
  return descriptors
}

function u16 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} is outside u16`)
  }
  return b4a.from([(value >>> 8) & 0xff, value & 0xff])
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} must be an unsigned safe integer or bigint`)
    }
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} is outside u64`)
  }
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function textBytes (value, field) {
  if (typeof value !== 'string' || value.length === 0 || value !== value.normalize('NFC')) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} must be non-empty NFC text`)
  }
  const output = b4a.from(value, 'utf8')
  if (output.byteLength > MAX_TEXT_BYTES || b4a.toString(output, 'utf8') !== value) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} is not bounded canonical UTF-8`)
  }
  return output
}

function hash (domain, value) {
  value = bytes(value, 'hash input')
  const output = b4a.alloc(32)
  sodium.crypto_generichash(output, b4a.concat([domain, u64(value.byteLength, 'hash length'), value]))
  return output
}

export function hashBlindClientBrowserArtifact (value) {
  return hash(ARTIFACT_HASH_DOMAIN, value)
}

export function hashBlindClientBrowserSourceClosure (value) {
  return hash(CLOSURE_HASH_DOMAIN, value)
}

function exactManifestInput (value) {
  const fields = [
    'version', 'draft', 'specHash', 'abiHash', 'vectorSetHash',
    'clientCompositionFormatHash', 'clientCompositionVectorSetHash',
    'toolchain', 'buildProfile', 'sourceClosureHash', 'artifactPath',
    'artifactLength', 'artifactHash'
  ]
  exactObject(value, fields, 'browser artifact manifest')
  if (value.version !== 1 || value.draft !== false) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'browser artifact authority requires final version 1')
  }
  let artifactLength
  if (typeof value.artifactLength === 'bigint') artifactLength = value.artifactLength
  else if (Number.isSafeInteger(value.artifactLength)) artifactLength = BigInt(value.artifactLength)
  else fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'browser artifact length is not an exact integer')
  if (artifactLength < 1n || artifactLength > BigInt(MAX_ARTIFACT_BYTES)) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'browser artifact length exceeds its fixed budget')
  }
  const artifactPath = b4a.toString(textBytes(value.artifactPath, 'artifactPath'), 'utf8')
  if (artifactPath !== BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.artifactPath) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'browser artifact path is not the frozen v1 package path')
  }
  return {
    version: 1,
    draft: false,
    specHash: fixed(value.specHash, 32, 'specHash'),
    abiHash: fixed(value.abiHash, 32, 'abiHash'),
    vectorSetHash: fixed(value.vectorSetHash, 32, 'vectorSetHash'),
    clientCompositionFormatHash: fixed(
      value.clientCompositionFormatHash, 32, 'clientCompositionFormatHash'),
    clientCompositionVectorSetHash: fixed(
      value.clientCompositionVectorSetHash, 32, 'clientCompositionVectorSetHash'),
    toolchain: b4a.toString(textBytes(value.toolchain, 'toolchain'), 'utf8'),
    buildProfile: b4a.toString(textBytes(value.buildProfile, 'buildProfile'), 'utf8'),
    sourceClosureHash: fixed(value.sourceClosureHash, 32, 'sourceClosureHash'),
    artifactPath,
    artifactLength,
    artifactHash: fixed(value.artifactHash, 32, 'artifactHash')
  }
}

export function encodeBlindClientBrowserArtifactManifestV1 (input) {
  const value = exactManifestInput(input)
  const toolchain = textBytes(value.toolchain, 'toolchain')
  const buildProfile = textBytes(value.buildProfile, 'buildProfile')
  const artifactPath = textBytes(value.artifactPath, 'artifactPath')
  return b4a.concat([
    MAGIC,
    b4a.from([1, 0]),
    value.specHash,
    value.abiHash,
    value.vectorSetHash,
    value.clientCompositionFormatHash,
    value.clientCompositionVectorSetHash,
    u16(toolchain.byteLength, 'toolchain length'), toolchain,
    u16(buildProfile.byteLength, 'buildProfile length'), buildProfile,
    value.sourceClosureHash,
    u16(artifactPath.byteLength, 'artifactPath length'), artifactPath,
    u64(value.artifactLength, 'artifactLength'),
    value.artifactHash
  ])
}

class Reader {
  constructor (value) {
    this.value = bytes(value, 'browser artifact manifest')
    this.offset = 0
  }

  take (length, field) {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.value.byteLength) {
      fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `truncated ${field}`)
    }
    const output = this.value.subarray(this.offset, this.offset + length)
    this.offset += length
    return output
  }

  byte (field) { return this.take(1, field)[0] }

  text (field) {
    const lengthBytes = this.take(2, `${field} length`)
    const length = (lengthBytes[0] << 8) | lengthBytes[1]
    const raw = this.take(length, field)
    const value = b4a.toString(raw, 'utf8')
    if (!b4a.equals(textBytes(value, field), raw)) {
      fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} is not canonical UTF-8`)
    }
    return value
  }

  uint64 (field) {
    let output = 0n
    for (const byte of this.take(8, field)) output = (output << 8n) | BigInt(byte)
    return output
  }

  end () {
    if (this.offset !== this.value.byteLength) {
      fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'browser artifact manifest has trailing bytes')
    }
  }
}

export function decodeBlindClientBrowserArtifactManifestV1 (input) {
  const reader = new Reader(input)
  if (!b4a.equals(reader.take(MAGIC.byteLength, 'magic'), MAGIC)) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'browser artifact manifest magic is invalid')
  }
  const value = {
    version: reader.byte('version'),
    draft: reader.byte('draft') === 1,
    specHash: b4a.from(reader.take(32, 'specHash')),
    abiHash: b4a.from(reader.take(32, 'abiHash')),
    vectorSetHash: b4a.from(reader.take(32, 'vectorSetHash')),
    clientCompositionFormatHash: b4a.from(reader.take(32, 'clientCompositionFormatHash')),
    clientCompositionVectorSetHash: b4a.from(reader.take(32, 'clientCompositionVectorSetHash')),
    toolchain: reader.text('toolchain'),
    buildProfile: reader.text('buildProfile'),
    sourceClosureHash: b4a.from(reader.take(32, 'sourceClosureHash')),
    artifactPath: reader.text('artifactPath'),
    artifactLength: reader.uint64('artifactLength'),
    artifactHash: b4a.from(reader.take(32, 'artifactHash'))
  }
  reader.end()
  const exact = exactManifestInput(value)
  const canonical = encodeBlindClientBrowserArtifactManifestV1(exact)
  if (!b4a.equals(canonical, bytes(input, 'browser artifact manifest'))) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'browser artifact manifest is noncanonical')
  }
  return Object.freeze(exact)
}

export function hashBlindClientBrowserArtifactManifest (value) {
  return hash(MANIFEST_HASH_DOMAIN, value)
}

export function verifyBlindClientBrowserArtifactV1 (input = {}) {
  exactObject(input, [
    'manifestBytes', 'artifactBytes', 'expectedManifestHash', 'expectedTuple'
  ], 'browser artifact verification input')
  const manifestBytes = b4a.from(bytes(input.manifestBytes, 'browser artifact manifest'))
  const expectedManifestHash = fixed(
    input.expectedManifestHash, 32, 'expected browser artifact manifest hash')
  if (!b4a.equals(hashBlindClientBrowserArtifactManifest(manifestBytes), expectedManifestHash)) {
    fail('BLIND_CLIENT_BROWSER_MANIFEST_DRIFT',
      'browser artifact manifest does not match its authenticated expected hash')
  }
  const manifest = decodeBlindClientBrowserArtifactManifestV1(manifestBytes)
  const artifactBytes = b4a.from(bytes(input.artifactBytes, 'browser artifact bytes'))
  if (BigInt(artifactBytes.byteLength) !== manifest.artifactLength ||
      !b4a.equals(hashBlindClientBrowserArtifact(artifactBytes), manifest.artifactHash)) {
    fail('BLIND_CLIENT_BROWSER_ARTIFACT_DRIFT', 'browser artifact bytes do not match the manifest')
  }
  const expectedTuple = input.expectedTuple
  exactObject(expectedTuple, [
    'specHash', 'abiHash', 'vectorSetHash',
    'clientCompositionFormatHash', 'clientCompositionVectorSetHash'
  ], 'expected browser artifact tuple')
  const expectedSpecHash = fixed(expectedTuple.specHash, 32, 'expected specHash')
  const expectedAbiHash = fixed(expectedTuple.abiHash, 32, 'expected abiHash')
  const expectedVectorSetHash = fixed(expectedTuple.vectorSetHash, 32, 'expected vectorSetHash')
  const expectedClientCompositionFormatHash = fixed(
    expectedTuple.clientCompositionFormatHash, 32, 'expected clientCompositionFormatHash')
  const expectedClientCompositionVectorSetHash = fixed(
    expectedTuple.clientCompositionVectorSetHash, 32, 'expected clientCompositionVectorSetHash')
  if (!b4a.equals(expectedSpecHash, manifest.specHash) ||
      !b4a.equals(expectedAbiHash, manifest.abiHash) ||
      !b4a.equals(expectedVectorSetHash, manifest.vectorSetHash) ||
      !b4a.equals(expectedClientCompositionFormatHash, manifest.clientCompositionFormatHash) ||
      !b4a.equals(expectedClientCompositionVectorSetHash, manifest.clientCompositionVectorSetHash)) {
    fail('BLIND_CLIENT_BROWSER_TUPLE_MISMATCH', 'browser artifact does not match the exact expected HiveRelay tuple')
  }
  const manifestSnapshot = Object.freeze({
    ...manifest,
    specHash: b4a.from(manifest.specHash),
    abiHash: b4a.from(manifest.abiHash),
    vectorSetHash: b4a.from(manifest.vectorSetHash),
    clientCompositionFormatHash: b4a.from(manifest.clientCompositionFormatHash),
    clientCompositionVectorSetHash: b4a.from(manifest.clientCompositionVectorSetHash),
    sourceClosureHash: b4a.from(manifest.sourceClosureHash),
    artifactHash: b4a.from(manifest.artifactHash)
  })
  return Object.freeze({
    get manifest () {
      return Object.freeze({
        ...manifestSnapshot,
        specHash: b4a.from(manifestSnapshot.specHash),
        abiHash: b4a.from(manifestSnapshot.abiHash),
        vectorSetHash: b4a.from(manifestSnapshot.vectorSetHash),
        clientCompositionFormatHash: b4a.from(manifestSnapshot.clientCompositionFormatHash),
        clientCompositionVectorSetHash: b4a.from(manifestSnapshot.clientCompositionVectorSetHash),
        sourceClosureHash: b4a.from(manifestSnapshot.sourceClosureHash),
        artifactHash: b4a.from(manifestSnapshot.artifactHash)
      })
    },
    get artifactBytes () { return b4a.from(artifactBytes) }
  })
}

function canonicalEvidenceJson (value, field) {
  value = bytes(value, field)
  if (value.byteLength < 1 || value.byteLength > 16 * 1024) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} is outside its byte limit`)
  }
  const source = b4a.toString(value, 'utf8')
  if (!b4a.equals(b4a.from(source, 'utf8'), value)) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} is not canonical UTF-8`)
  }
  let parsed
  try {
    parsed = JSON.parse(source)
  } catch {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} is not JSON`)
  }
  if (JSON.stringify(parsed, null, 2) + '\n' !== source) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} is not canonical JSON`)
  }
  return parsed
}

function evidenceText (value, field, maximum = 256) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum ||
      /[^\x20-\x7e]/.test(value)) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} is not bounded printable ASCII`)
  }
  return value
}

function exactChecks (actual, expected, field) {
  if (!Array.isArray(actual) || actual.length !== expected.length ||
      actual.some((value, index) => value !== expected[index])) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} is not the exact checked set`)
  }
}

function commonEvidence (value, fields, expected, field) {
  exactObject(value, fields, field)
  if (value.version !== 1 || value.passed !== true ||
      value.artifactPath !== BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.artifactPath ||
      value.artifactLength !== expected.artifactLength ||
      value.artifactHash !== expected.artifactHash ||
      value.manifestHash !== expected.manifestHash ||
      value.sourceClosureHash !== expected.sourceClosureHash) {
    fail('BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE_MISMATCH',
      `${field} does not bind the exact checked browser artifact`)
  }
}

export function verifyBlindClientBrowserArtifactReleaseEvidenceV1 (input = {}) {
  exactObject(input, [
    'manifestBytes', 'artifactBytes', 'expectedManifestHash', 'expectedTuple',
    'chromiumEvidenceBytes', 'crossHostEvidenceBytes'
  ], 'browser artifact release evidence verification input')
  const verified = verifyBlindClientBrowserArtifactV1({
    manifestBytes: input.manifestBytes,
    artifactBytes: input.artifactBytes,
    expectedManifestHash: input.expectedManifestHash,
    expectedTuple: input.expectedTuple
  })
  const manifest = verified.manifest
  const expected = Object.freeze({
    artifactLength: Number(manifest.artifactLength),
    artifactHash: b4a.toString(manifest.artifactHash, 'hex'),
    manifestHash: b4a.toString(fixed(input.expectedManifestHash, 32, 'expected manifest hash'), 'hex'),
    sourceClosureHash: b4a.toString(manifest.sourceClosureHash, 'hex')
  })
  const chromium = canonicalEvidenceJson(input.chromiumEvidenceBytes, 'Chromium evidence')
  const chromiumFields = [
    'schema', 'version', 'evidenceClass', 'artifactPath', 'artifactLength',
    'artifactHash', 'manifestHash', 'sourceClosureHash', 'chromium', 'checks', 'passed'
  ]
  commonEvidence(chromium, chromiumFields, expected, 'Chromium evidence')
  if (chromium.schema !== 'HiveRelayBlindClientBrowserArtifactChromiumEvidenceV1' ||
      chromium.evidenceClass !== 'real-chromium') {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', 'Chromium evidence has the wrong authority class')
  }
  evidenceText(chromium.chromium, 'Chromium version')
  exactChecks(chromium.checks, CHROMIUM_EVIDENCE_CHECKS, 'Chromium evidence checks')

  const crossHost = canonicalEvidenceJson(input.crossHostEvidenceBytes, 'cross-host evidence')
  const crossHostFields = [
    'schema', 'version', 'evidenceClass', 'artifactPath', 'artifactLength',
    'artifactHash', 'manifestHash', 'sourceClosureHash', 'platform', 'architecture',
    'containerImageId', 'node', 'toolchain', 'checks', 'passed'
  ]
  commonEvidence(crossHost, crossHostFields, expected, 'cross-host evidence')
  if (crossHost.schema !== 'HiveRelayBlindClientBrowserArtifactCrossHostEvidenceV1' ||
      crossHost.evidenceClass !== 'clean-linux-container' || crossHost.platform !== 'linux' ||
      crossHost.toolchain !== manifest.toolchain || !/^sha256:[0-9a-f]{64}$/.test(crossHost.containerImageId)) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', 'cross-host evidence has the wrong authority class')
  }
  evidenceText(crossHost.architecture, 'cross-host architecture', 32)
  evidenceText(crossHost.node, 'cross-host Node version', 64)
  exactChecks(crossHost.checks, CROSS_HOST_EVIDENCE_CHECKS, 'cross-host evidence checks')

  return Object.freeze({
    ...BLIND_CLIENT_BROWSER_ARTIFACT_STATUS,
    crossHostByteEqualityProven: true,
    realBrowserImportProven: true,
    releaseReady: true,
    releaseBlockers: Object.freeze([]),
    artifactHash: expected.artifactHash,
    manifestHash: expected.manifestHash,
    chromium: Object.freeze({ version: chromium.chromium }),
    crossHost: Object.freeze({
      platform: crossHost.platform,
      architecture: crossHost.architecture,
      containerImageId: crossHost.containerImageId,
      node: crossHost.node
    })
  })
}
