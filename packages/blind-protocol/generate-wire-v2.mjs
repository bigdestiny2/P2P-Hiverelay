import fs from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { createHash } from 'node:crypto'
import b4a from 'b4a'
import { encodeCanonical } from './codec.js'
import { createWireAbiV2Value, encodeWireAbiV2 } from './abi-registry-v2.js'
import { encodeVectorManifest, hashAbi, hashSpec, hashVectorSet } from './hashes.js'
import {
  FORWARD_HTTPS_DOMAIN_V2,
  FORWARD_HTTPS_LIMITS_V1,
  FORWARD_HTTPS_RESULT_OUTCOME_V1,
  FORWARD_HTTPS_TRANSPORT_VARIANTS_V2,
  FORWARD_HTTPS_TURN_KIND_V1,
  RELEASE_PROFILE_V2,
  WIRE_V2_PROTOCOL,
  WIRE_V2_SCHEMA_DECLARATIONS,
  blindForwardHttpsTurnRequestV1,
  blindForwardHttpsTurnResultV1,
  forwardHttpsSessionIdV1,
  forwardHttpsTurnRequestCommitmentV1
} from './wire-v2.js'

const check = process.argv.includes('--check')
const root = path.dirname(new URL(import.meta.url).pathname)
const repoRoot = path.resolve(root, '../..')
const vectorRoot = path.join(root, 'vectors-v2/wire')
const legacyVectorRoot = path.join(root, 'vectors/v2')
const fixed = (length, value) => b4a.alloc(length, value)
const hex = value => b4a.toString(value, 'hex')
const json = value => b4a.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8')

const v1CompatibilityFloor = Object.freeze({
  'hiverelay-blind-abi-v1.cenc': '8fcc75ed7f32af8f118a521fe230d77ec1e4b2b209296adda2e73e87b74ff5b6',
  'hiverelay-blind-abi-v1.draft.cenc': '8fcc75ed7f32af8f118a521fe230d77ec1e4b2b209296adda2e73e87b74ff5b6',
  'vector-manifest-v1.cenc': 'e23137dc90f52a1c9c3c8ac1e6ecb98eb32b653260fe1049f078ff8cebabc522',
  'vectors/draft/vector-manifest-v1.draft.cenc': 'e23137dc90f52a1c9c3c8ac1e6ecb98eb32b653260fe1049f078ff8cebabc522',
  'hiverelay-blind-wire-authority-v1.json': 'd6b757334bbec7b85d949085ce4b896a5fe960bc4c86c7f9001f81be78d0cefc',
  'schema-catalog-runtime-authority.js': '6c0c7a8be1f77709cd60edad083606fa3e3889f2f50396592bfe290db6404fcc',
  'wire-runtime-authority.js': '3c861d390f8f6b60a390334e3320cd22cdce6071dfe3a5f42231460e73f52cea',
  'hiverelay-blind-release-closure-v1.json': '9f82a7dbe4aee8cc4dd2c7e22864314a7489280b8ceb3fbf2dd68e71d095a663'
})

async function sha256 (file) {
  return createHash('sha256').update(await fs.readFile(file)).digest('hex')
}

async function assertV1Floor () {
  for (const [name, expected] of Object.entries(v1CompatibilityFloor)) {
    const actual = await sha256(path.join(root, name))
    if (actual !== expected) throw new Error(`frozen WIRE v1 artifact changed: ${name} ${actual}`)
  }
}

async function writeOrCheck (file, bytes) {
  if (!b4a.isBuffer(bytes)) bytes = b4a.from(bytes)
  if (check) {
    let current
    try {
      current = await fs.readFile(file)
    } catch {
      throw new Error(`missing generated WIRE v2 artifact: ${path.relative(repoRoot, file)}`)
    }
    if (!b4a.equals(current, bytes)) throw new Error(`stale generated WIRE v2 artifact: ${path.relative(repoRoot, file)}`)
    return
  }
  await fs.mkdir(path.dirname(file), { recursive: true })
  await fs.writeFile(file, bytes)
}

function capability () {
  return {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    sourceRelayPublicKey: fixed(32, 1),
    sourceDescriptorSequence: 11n,
    sourceDescriptorHash: fixed(32, 2),
    targetRelayPublicKey: fixed(32, 3),
    targetDescriptorSequence: 22n,
    targetDescriptorHash: fixed(32, 4),
    targetCatalogEntryId: fixed(32, 5),
    routeId: fixed(16, 6),
    routePrefixRelayPublicKey: fixed(32, 1),
    maxRelayCount: 2,
    remainingTransitions: 1,
    circuitClass: 1,
    maxCircuitBytes: 16n * 1024n * 1024n,
    initialWindowBytes: 65_536,
    idleMillis: 30_000,
    lifetimeMillis: 600_000,
    issuedAtEpoch: 1_800_000_000,
    expiresAtEpoch: 1_800_000_600,
    circuitNonce: fixed(32, 7),
    tlsExporterBindingHash: fixed(32, 8),
    signature: fixed(64, 9)
  }
}

function dataRequest () {
  const parentCapability = capability()
  return {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    turnKind: FORWARD_HTTPS_TURN_KIND_V1.DATA,
    flags: 0,
    sessionId: forwardHttpsSessionIdV1(parentCapability),
    sequence: 0n,
    requestNonce: fixed(32, 10),
    parentCapability,
    inner: { version: 1, circuitNonce: parentCapability.circuitNonce, offset: 0n, bytes: fixed(64, 11) }
  }
}

function result (requestBytes, outcome) {
  return {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    turnKind: FORWARD_HTTPS_TURN_KIND_V1.DATA,
    outcome,
    sessionId: forwardHttpsSessionIdV1(capability()),
    sequence: 0n,
    requestCommitment: forwardHttpsTurnRequestCommitmentV1(requestBytes),
    relayPublicKey: fixed(32, 3),
    descriptorSequence: 22n,
    descriptorHash: fixed(32, 4),
    signature: fixed(64, 12),
    inner: outcome === FORWARD_HTTPS_RESULT_OUTCOME_V1.ERROR
      ? { version: 1, code: 1, retryable: 0, retryAfterEpoch: null }
      : { version: 1, circuitNonce: fixed(32, 7), offset: 0n, bytes: fixed(32, 13) }
  }
}

function runtimeAuthoritySource (authority) {
  const profiles = JSON.stringify(authority.releaseProfiles, null, 2)
  const variants = JSON.stringify(authority.transportVariants, null, 2)
  const domains = JSON.stringify(authority.additionalDomains, null, 2)
  return '/* eslint-disable */\n// Generated by generate-wire-v2.mjs. Do not edit.\n' +
    'export * from \'./wire-runtime-authority.js\'\n' +
    `export const WIRE_V2_PROTOCOL = Object.freeze(${JSON.stringify(authority.protocol)})\n` +
    `export const WIRE_V2_BASE_ABI_HASH = '${authority.baseAbiHash}'\n` +
    `export const WIRE_V2_ABI_HASH = '${authority.abiHash}'\n` +
    `export const WIRE_V2_RELEASE_PROFILES = Object.freeze(${profiles})\n` +
    `export const WIRE_V2_TRANSPORT_VARIANTS = Object.freeze(${variants})\n` +
    `export const WIRE_V2_ADDITIONAL_DOMAINS = Object.freeze(${domains})\n` +
    'export const WIRE_V2_FORWARD_READINESS_OPERATION_BITS = 0\n'
}

function schemaAuthoritySource (authority) {
  return '/* eslint-disable */\n// Generated by generate-wire-v2.mjs. Do not edit.\n' +
    'export * from \'./schema-catalog-runtime-authority.js\'\n' +
    'export const WIRE_V2_BASE_SCHEMA_COUNT = 73\n' +
    `export const WIRE_V2_ADDITIONAL_SCHEMAS = Object.freeze(${JSON.stringify(authority.additionalSchemas, null, 2)})\n`
}

await assertV1Floor()
if (!check) await fs.rm(legacyVectorRoot, { recursive: true, force: true })

const v1AbiBytes = await fs.readFile(path.join(root, 'hiverelay-blind-abi-v1.cenc'))
const baseAbiHash = hashAbi(v1AbiBytes)
const abiBytes = encodeWireAbiV2(createWireAbiV2Value(baseAbiHash))
const specBytes = await fs.readFile(path.join(repoRoot, 'docs/protocol/HIVERELAY-BLIND-WIRE-V2.md'))
const requestBytes = encodeCanonical(blindForwardHttpsTurnRequestV1, dataRequest())
const successBytes = encodeCanonical(blindForwardHttpsTurnResultV1, result(requestBytes, FORWARD_HTTPS_RESULT_OUTCOME_V1.SUCCESS))
const errorBytes = encodeCanonical(blindForwardHttpsTurnResultV1, result(requestBytes, FORWARD_HTTPS_RESULT_OUTCOME_V1.ERROR))
const changedReplay = b4a.from(requestBytes)
changedReplay[changedReplay.byteLength - 1] ^= 1

const releaseProfiles = Object.entries(RELEASE_PROFILE_V2).map(([canonicalName, value]) => ({
  profileId: value.id,
  canonicalName,
  operationBits: value.operationBits,
  isDefault: value.isDefault
}))
const domains = [
  { ...FORWARD_HTTPS_DOMAIN_V2.REQUEST, purpose: 'REQUEST_COMMITMENT' },
  { ...FORWARD_HTTPS_DOMAIN_V2.RESULT, purpose: 'RESULT_SIGNATURE' },
  { ...FORWARD_HTTPS_DOMAIN_V2.PARENT_CAPABILITY, purpose: 'AUXILIARY_SIGNATURE' }
]

const vectorFiles = [
  { path: 'registry/wire-abi-v2.cenc', bytes: abiBytes },
  { path: 'registry/release-profiles-v2.json', bytes: json(releaseProfiles) },
  { path: 'registry/transport-variants-v2.json', bytes: json(FORWARD_HTTPS_TRANSPORT_VARIANTS_V2) },
  { path: 'registry/domains-v2.json', bytes: json(domains) },
  { path: 'registry/v1-compatibility-floor.json', bytes: json(v1CompatibilityFloor) },
  { path: 'positive/data-request-v1.bin', bytes: requestBytes },
  { path: 'positive/data-result-success-v1.bin', bytes: successBytes },
  { path: 'positive/data-result-error-v1.bin', bytes: errorBytes },
  { path: 'negative/data-request-truncated.bin', bytes: requestBytes.subarray(0, requestBytes.byteLength - 1) },
  { path: 'negative/data-request-changed-replay.bin', bytes: changedReplay },
  {
    path: 'negative/expectations.json',
    bytes: json({
      'data-request-truncated.bin': 'reject-exact-size',
      'data-request-changed-replay.bin': 'reject-terminal-changed-same-sequence'
    })
  }
]
const manifestBytes = encodeVectorManifest(vectorFiles)
const authority = {
  magic: 'hiverelay-blind-wire-authority-v2',
  formatVersion: 2,
  protocol: WIRE_V2_PROTOCOL,
  baseSchemaCount: 73,
  baseAbiHash: hex(baseAbiHash),
  abiHash: hex(hashAbi(abiBytes)),
  specHash: hex(hashSpec(specBytes)),
  vectorSetHash: hex(hashVectorSet(manifestBytes)),
  additionalSchemas: WIRE_V2_SCHEMA_DECLARATIONS,
  releaseProfiles,
  transportVariants: FORWARD_HTTPS_TRANSPORT_VARIANTS_V2,
  additionalDomains: domains,
  exactRequestBytes: FORWARD_HTTPS_LIMITS_V1.EXACT_REQUEST_BYTES,
  exactResultBytes: FORWARD_HTTPS_LIMITS_V1.EXACT_RESULT_BYTES,
  forwardDescriptorOperationBits: 0,
  forwardAdvertisedOperationBits: 0,
  forwardReadinessOperationBits: 0,
  compatibilityFloor: v1CompatibilityFloor
}
const runtimeVectors = {
  requestSha256: createHash('sha256').update(requestBytes).digest('hex'),
  successResultSha256: createHash('sha256').update(successBytes).digest('hex'),
  errorResultSha256: createHash('sha256').update(errorBytes).digest('hex'),
  abiHash: authority.abiHash,
  vectorSetHash: authority.vectorSetHash
}

const outputs = [
  [path.join(root, 'hiverelay-blind-abi-v2.cenc'), abiBytes],
  [path.join(root, 'vector-manifest-v2.cenc'), manifestBytes],
  [path.join(root, 'hiverelay-blind-wire-authority-v2.json'), json(authority)],
  [path.join(root, 'wire-runtime-authority-v2.js'), b4a.from(runtimeAuthoritySource(authority))],
  [path.join(root, 'schema-catalog-runtime-authority-v2.js'), b4a.from(schemaAuthoritySource(authority))],
  [path.join(root, 'wire-runtime-vectors-v2.js'), b4a.from(`/* eslint-disable */\n// Generated by generate-wire-v2.mjs. Do not edit.\nexport const WIRE_RUNTIME_VECTORS_V2 = Object.freeze(${JSON.stringify(runtimeVectors, null, 2)})\n`)]
]
for (const vector of vectorFiles) outputs.push([path.join(vectorRoot, vector.path), vector.bytes])
for (const [file, bytes] of outputs) await writeOrCheck(file, bytes)

if (check) {
  const expected = new Set(vectorFiles.map(vector => vector.path))
  async function walk (directory, prefix = '') {
    const found = []
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name
      if (entry.isDirectory()) found.push(...await walk(path.join(directory, entry.name), relative))
      else found.push(relative)
    }
    return found
  }
  for (const found of await walk(vectorRoot)) {
    if (!expected.has(found)) throw new Error(`unexpected WIRE v2 vector: ${found}`)
  }
}

console.log(check ? 'WIRE v2 authority verified' : 'WIRE v2 authority generated')
