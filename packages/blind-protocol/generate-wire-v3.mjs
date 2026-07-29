import fs from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { createHash } from 'node:crypto'
import b4a from 'b4a'
import sodium from './crypto.js'
import { createWireAbiV3Value, encodeWireAbiV3 } from './abi-registry-v3.js'
import { decodeCanonical, encodeCanonical } from './codec.js'
import { encodeVectorManifest, hashAbi, hashSpec, hashVectorSet } from './hashes.js'
import { blindForwardOpenResultV1, blindForwardOpenV1 } from './schemas.js'
import {
  FORWARD_HTTPS_DOMAIN_V3,
  FORWARD_HTTPS_REQUEST_ROLE_V1,
  FORWARD_HTTPS_RESULT_ROLE_V1,
  FORWARD_HTTPS_SUCCESSOR_TRANSPORT_VARIANTS_V3,
  FORWARD_HTTPS_TLS_EXPORTER_LABEL_V1,
  FORWARD_HTTPS_V3_LIMITS,
  FORWARD_HTTPS_V3_RESULT_MATRIX,
  WIRE_V3_HASH_DOMAIN_PURPOSE,
  WIRE_V3_HASH_RECIPES,
  WIRE_V3_PROTOCOL,
  WIRE_V3_SCHEMA_DECLARATIONS,
  blindForwardHttpsOriginForwardTurnRequestV1,
  blindForwardHttpsOriginForwardTurnResultV1,
  createForwardHttpsForwardedRequestV1,
  forwardHttpsForwardedRequestCommitmentV1,
  forwardHttpsOriginRequestCommitmentV1,
  forwardHttpsResultSignaturePayloadV1,
  forwardHttpsStableSessionIdV1,
  forwardHttpsTargetResultChainHashV1,
  forwardHttpsTlsExporterBindingHashV1,
  forwardHttpsTlsExporterContextV1
} from './wire-v3.js'
import { forwardHttpsParentCapabilitySignaturePayloadV1, RELEASE_PROFILE_V2 } from './wire-v2.js'

const check = process.argv.includes('--check')
const root = path.dirname(new URL(import.meta.url).pathname)
const repoRoot = path.resolve(root, '../..')
const vectorRoot = path.join(root, 'vectors-v3/wire')
const fixed = (length, value) => b4a.alloc(length, value)
const hex = value => b4a.toString(value, 'hex')
const json = value => b4a.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8')

const compatibilityFloor = Object.freeze({
  'hiverelay-blind-abi-v1.cenc': '8fcc75ed7f32af8f118a521fe230d77ec1e4b2b209296adda2e73e87b74ff5b6',
  'hiverelay-blind-abi-v2.cenc': 'ff86d47c480a39156e2ab0268e3da786dbac3ff8528f98f758671ed1bf2a297c',
  'vector-manifest-v1.cenc': 'e23137dc90f52a1c9c3c8ac1e6ecb98eb32b653260fe1049f078ff8cebabc522',
  'vector-manifest-v2.cenc': '803717545ff5f51f396bf06646dda7ca4b12596c61bffc640a244360d287aa7f',
  'hiverelay-blind-wire-authority-v1.json': 'd6b757334bbec7b85d949085ce4b896a5fe960bc4c86c7f9001f81be78d0cefc',
  'hiverelay-blind-wire-authority-v2.json': '165316d7d551afabfe6943981d80cc8ba9cbe0b2db06336a3b95eaeb17783e86',
  'wire-v2.js': '678b417f8ca3adacb50442f46c2e8ae0500334f81d039e3552c1d8b89acd19d4',
  'abi-registry-v2.js': '8aabef205df158f49a08c5bd7a2c7bb6318355c16b3cb1b6dea38eddd361a126',
  'registry.js': '782075a117d9946b53fae90a90cd7cf957ba469cce522151dcc8f8b570b8f61f'
})

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

async function assertCompatibilityFloor () {
  for (const [relative, expected] of Object.entries(compatibilityFloor)) {
    const actual = sha256(await fs.readFile(path.join(root, relative)))
    if (actual !== expected) throw new Error(`frozen WIRE artifact changed: ${relative} ${actual}`)
  }
}

async function writeOrCheck (file, bytes) {
  if (!b4a.isBuffer(bytes)) bytes = b4a.from(bytes)
  if (check) {
    let current
    try {
      current = await fs.readFile(file)
    } catch {
      throw new Error(`missing generated WIRE v3 artifact: ${path.relative(repoRoot, file)}`)
    }
    if (!b4a.equals(current, bytes)) throw new Error(`stale generated WIRE v3 artifact: ${path.relative(repoRoot, file)}`)
    return
  }
  await fs.mkdir(path.dirname(file), { recursive: true })
  await fs.writeFile(file, bytes)
}

function keypair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, fixed(32, seedByte))
  return { publicKey, secretKey }
}

const source = keypair(41)
const target = keypair(42)
const clientSessionNonce = fixed(32, 43)

function originCapability (open) {
  return {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    sourceRelayPublicKey: source.publicKey,
    sourceDescriptorSequence: 11n,
    sourceDescriptorHash: fixed(32, 44),
    targetRelayPublicKey: target.publicKey,
    targetDescriptorSequence: open.nextDescriptorSequence,
    targetDescriptorHash: open.nextDescriptorHash,
    targetCatalogEntryId: fixed(32, 45),
    routeId: open.routeId,
    routePrefixRelayPublicKey: source.publicKey,
    maxRelayCount: 2,
    remainingTransitions: 1,
    circuitClass: 1,
    maxCircuitBytes: 16n * 1024n * 1024n,
    initialWindowBytes: 65_536,
    idleMillis: 30_000,
    lifetimeMillis: 600_000,
    issuedAtEpoch: 1_800_000_000,
    expiresAtEpoch: 1_800_000_600,
    circuitNonce: open.circuitNonce,
    tlsExporterBindingHash: b4a.alloc(32),
    signature: b4a.alloc(64)
  }
}

function originRequest (requestKind, inner, sequence, previousTargetResultHash, capability) {
  return {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    requestRole: FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE,
    requestKind,
    flags: 0,
    stableSessionId: forwardHttpsStableSessionIdV1(capability, clientSessionNonce),
    sequence,
    clientSessionNonce,
    requestNonce: fixed(32, 50 + requestKind),
    previousTargetResultHash,
    parentCapability: capability,
    turnTlsExporterBindingHash: b4a.alloc(32),
    originRequestCommitment: b4a.alloc(32),
    sourceTransformSignature: b4a.alloc(64),
    inner
  }
}

function finalizeCapability (origin, binding) {
  const capability = {
    ...origin,
    tlsExporterBindingHash: binding,
    signature: b4a.alloc(64)
  }
  sodium.crypto_sign_detached(capability.signature, forwardHttpsParentCapabilitySignaturePayloadV1(capability), source.secretKey)
  return capability
}

function transform (originBytes, capability, secretByte) {
  const origin = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, originBytes, { copyBytes: true })
  const context = forwardHttpsTlsExporterContextV1(origin.stableSessionId, origin.sequence, forwardHttpsOriginRequestCommitmentV1(originBytes))
  const binding = forwardHttpsTlsExporterBindingHashV1(fixed(32, secretByte), context)
  return createForwardHttpsForwardedRequestV1(originBytes, finalizeCapability(capability, binding), binding, source.secretKey)
}

function signedResult (forwardedBytes, resultRole, responseKind, inner) {
  const forwarded = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, forwardedBytes, { copyBytes: true })
  const sourceRole = resultRole !== FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT
  const signer = sourceRole ? source : target
  const capability = forwarded.parentCapability
  const value = {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    resultRole,
    requestKind: forwarded.requestKind,
    responseKind,
    flags: 0,
    stableSessionId: forwarded.stableSessionId,
    sequence: forwarded.sequence,
    previousTargetResultHash: forwarded.previousTargetResultHash,
    originRequestCommitment: forwarded.originRequestCommitment,
    forwardedRequestCommitment: forwardHttpsForwardedRequestCommitmentV1(forwardedBytes),
    finalizedParentCapability: capability,
    turnTlsExporterBindingHash: forwarded.turnTlsExporterBindingHash,
    sourceTransformSignature: forwarded.sourceTransformSignature,
    signerPublicKey: signer.publicKey,
    signerDescriptorSequence: sourceRole ? capability.sourceDescriptorSequence : capability.targetDescriptorSequence,
    signerDescriptorHash: sourceRole ? capability.sourceDescriptorHash : capability.targetDescriptorHash,
    resultSignature: b4a.alloc(64),
    inner
  }
  const unsigned = encodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, value)
  sodium.crypto_sign_detached(value.resultSignature, forwardHttpsResultSignaturePayloadV1(unsigned), signer.secretKey)
  return encodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, value)
}

function mutate (bytes, offset) {
  const output = b4a.from(bytes)
  output[offset] ^= 1
  return output
}

function runtimeAuthoritySource (authority) {
  return '/* eslint-disable */\n// Generated by generate-wire-v3.mjs. Do not edit.\n' +
    'export * from \'./wire-runtime-authority-v2.js\'\n' +
    `export const WIRE_V3_PROTOCOL = Object.freeze(${JSON.stringify(authority.protocol)})\n` +
    `export const WIRE_V3_BASE_ABI_HASH = '${authority.baseWireV2AbiHash}'\n` +
    `export const WIRE_V3_ABI_HASH = '${authority.abiHash}'\n` +
    `export const WIRE_V3_COMPATIBILITY_ONLY_SCHEMA_IDS = Object.freeze(${JSON.stringify(authority.compatibilityOnlySchemaIds)})\n` +
    `export const WIRE_V3_SUCCESSOR_TRANSPORT_VARIANTS = Object.freeze(${JSON.stringify(authority.successorTransportVariants, null, 2)})\n` +
    `export const WIRE_V3_ADDITIONAL_DOMAINS = Object.freeze(${JSON.stringify(authority.additionalDomains, null, 2)})\n` +
    `export const WIRE_V3_HASH_RECIPES = Object.freeze(${JSON.stringify(authority.hashRecipes, null, 2)})\n` +
    'export const WIRE_V3_FORWARD_DESCRIPTOR_OPERATION_BITS = 0\n' +
    'export const WIRE_V3_FORWARD_ADVERTISED_OPERATION_BITS = 0\n' +
    'export const WIRE_V3_FORWARD_READINESS_OPERATION_BITS = 0\n'
}

await assertCompatibilityFloor()

const v2AbiBytes = await fs.readFile(path.join(root, 'hiverelay-blind-abi-v2.cenc'))
const baseWireV2AbiHash = hashAbi(v2AbiBytes)
if (hex(baseWireV2AbiHash) !== 'cc1abb0e24bd4c75e0cb99b824e114cf50ad91270362f39d8594a826e29d5053') {
  throw new Error('frozen WIRE v2 ABI hash mismatch')
}
const abiBytes = encodeWireAbiV3(createWireAbiV3Value(baseWireV2AbiHash))
const specBytes = await fs.readFile(path.join(repoRoot, 'docs/protocol/HIVERELAY-BLIND-WIRE-V3.md'))
const open = decodeCanonical(blindForwardOpenV1, await fs.readFile(path.join(root, 'vectors/forward/open.bin')), { copyBytes: true })
const openResult = decodeCanonical(blindForwardOpenResultV1, await fs.readFile(path.join(root, 'vectors/forward/open-result.bin')), { copyBytes: true })
const capability = originCapability(open)

const openOrigin = encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, originRequest(1, open, 0n, b4a.alloc(32), capability))
const openForwarded = transform(openOrigin, capability, 60)
const openTargetResult = signedResult(openForwarded, 1, 1, openResult)
const previousHash = forwardHttpsTargetResultChainHashV1(openTargetResult)

const dataInner = { version: 1, circuitNonce: capability.circuitNonce, offset: 0n, bytes: fixed(64_000, 61) }
const dataOrigin = encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, originRequest(2, dataInner, 1n, previousHash, capability))
const dataForwarded = transform(dataOrigin, capability, 62)
const dataResults = new Map([
  ['ack', signedResult(dataForwarded, 1, 2, null)],
  ['data', signedResult(dataForwarded, 1, 4, { ...dataInner, bytes: fixed(32, 63) })],
  ['window', signedResult(dataForwarded, 1, 5, { version: 1, circuitNonce: capability.circuitNonce, consumedThrough: 64_000n, creditIncrement: 4096 })],
  ['close', signedResult(dataForwarded, 1, 6, { version: 1, circuitNonce: capability.circuitNonce, closeKind: 1, finalSendOffset: 64_000n, reasonCode: 0 })],
  ['error', signedResult(dataForwarded, 1, 7, { version: 1, code: 1, retryable: 0, retryAfterEpoch: null })],
  ['source-error', signedResult(dataForwarded, 2, 7, { version: 1, code: 1, retryable: 0, retryAfterEpoch: null })],
  ['source-ambiguous', signedResult(dataForwarded, 3, 8, null)]
])
const pollOrigin = encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, originRequest(5, null, 1n, previousHash, capability))
const pollForwarded = transform(pollOrigin, capability, 64)

const windowInner = { version: 1, circuitNonce: capability.circuitNonce, consumedThrough: 64_000n, creditIncrement: 4096 }
const windowOrigin = encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, originRequest(3, windowInner, 1n, previousHash, capability))
const windowForwarded = transform(windowOrigin, capability, 65)
const closeInner = { version: 1, circuitNonce: capability.circuitNonce, closeKind: 1, finalSendOffset: 64_000n, reasonCode: 0 }
const closeOrigin = encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, originRequest(4, closeInner, 1n, previousHash, capability))
const closeForwarded = transform(closeOrigin, capability, 66)

const requestFixtures = new Map([
  ['open', { kind: 1, origin: openOrigin, forwarded: openForwarded }],
  ['data', { kind: 2, origin: dataOrigin, forwarded: dataForwarded }],
  ['window', { kind: 3, origin: windowOrigin, forwarded: windowForwarded }],
  ['close', { kind: 4, origin: closeOrigin, forwarded: closeForwarded }],
  ['poll', { kind: 5, origin: pollOrigin, forwarded: pollForwarded }]
])
const responseNames = new Map([
  [1, 'open-accept'], [2, 'ack'], [3, 'noop'], [4, 'data'], [5, 'window'], [6, 'close'], [7, 'error']
])
const responseInner = new Map([
  [1, openResult],
  [2, null],
  [3, null],
  [4, { ...dataInner, bytes: fixed(32, 63) }],
  [5, windowInner],
  [6, closeInner],
  [7, { version: 1, code: 1, retryable: 0, retryAfterEpoch: null }]
])
const completeRoleAndMatrixVectors = []
for (const [requestName, fixture] of requestFixtures) {
  completeRoleAndMatrixVectors.push(
    { path: `positive/${requestName}-origin-role.bin`, bytes: fixture.origin },
    { path: `positive/${requestName}-forwarded-role.bin`, bytes: fixture.forwarded }
  )
  for (const responseKind of FORWARD_HTTPS_V3_RESULT_MATRIX[fixture.kind]) {
    completeRoleAndMatrixVectors.push({
      path: `positive/${requestName}-target-${responseNames.get(responseKind)}.bin`,
      bytes: signedResult(fixture.forwarded, 1, responseKind, responseInner.get(responseKind))
    })
  }
  completeRoleAndMatrixVectors.push(
    {
      path: `positive/${requestName}-source-pre-forward-error.bin`,
      bytes: signedResult(fixture.forwarded, 2, 7, responseInner.get(7))
    },
    {
      path: `positive/${requestName}-source-post-forward-ambiguous.bin`,
      bytes: signedResult(fixture.forwarded, 3, 8, null)
    }
  )
}

const profiles = Object.entries(RELEASE_PROFILE_V2).map(([canonicalName, profile]) => ({
  profileId: profile.id,
  canonicalName,
  operationBits: profile.operationBits,
  isDefault: profile.isDefault
}))
const domains = Object.values(FORWARD_HTTPS_DOMAIN_V3).map(value => ({ ...value }))
const matrix = Object.fromEntries(Object.entries(FORWARD_HTTPS_V3_RESULT_MATRIX).map(([kind, responses]) => [kind, responses]))
const vectorFiles = [
  { path: 'registry/wire-abi-v3.cenc', bytes: abiBytes },
  { path: 'registry/compatibility-floor.json', bytes: json(compatibilityFloor) },
  { path: 'registry/release-profiles-v3.json', bytes: json(profiles) },
  { path: 'registry/successor-transport-variants-v3.json', bytes: json(FORWARD_HTTPS_SUCCESSOR_TRANSPORT_VARIANTS_V3) },
  { path: 'registry/domains-v3.json', bytes: json(domains) },
  { path: 'registry/hash-recipes-v3.json', bytes: json(WIRE_V3_HASH_RECIPES) },
  { path: 'registry/result-matrix-v3.json', bytes: json(matrix) },
  { path: 'positive/open-origin.bin', bytes: openOrigin },
  { path: 'positive/open-forwarded.bin', bytes: openForwarded },
  { path: 'positive/open-target-result.bin', bytes: openTargetResult },
  { path: 'positive/data-origin-max.bin', bytes: dataOrigin },
  { path: 'positive/data-forwarded-max.bin', bytes: dataForwarded },
  { path: 'positive/poll-origin.bin', bytes: pollOrigin },
  { path: 'positive/poll-forwarded.bin', bytes: pollForwarded },
  { path: 'positive/window-origin.bin', bytes: windowOrigin },
  { path: 'positive/window-forwarded.bin', bytes: windowForwarded },
  { path: 'positive/close-origin.bin', bytes: closeOrigin },
  { path: 'positive/close-forwarded.bin', bytes: closeForwarded },
  { path: 'positive/data-target-source-error.bin', bytes: dataResults.get('source-error') },
  { path: 'positive/data-target-source-ambiguous.bin', bytes: dataResults.get('source-ambiguous') },
  ...completeRoleAndMatrixVectors,
  { path: 'negative/origin-bad-magic.bin', bytes: mutate(openOrigin, 0) },
  { path: 'negative/origin-nonzero-padding.bin', bytes: mutate(openOrigin, 65_535) },
  { path: 'negative/forwarded-bad-transform-signature.bin', bytes: mutate(dataForwarded, 600) },
  { path: 'negative/result-bad-signature.bin', bytes: mutate(dataResults.get('ack'), 705) },
  { path: 'negative/result-role-confusion.bin', bytes: mutate(dataResults.get('source-ambiguous'), 7) },
  {
    path: 'negative/expectations.json',
    bytes: json({
      'origin-bad-magic.bin': 'reject-magic',
      'origin-nonzero-padding.bin': 'reject-zero-padding',
      'forwarded-bad-transform-signature.bin': 'reject-source-transform-signature',
      'result-bad-signature.bin': 'reject-role-domain-signature',
      'result-role-confusion.bin': 'reject-role-conditioned-result-matrix',
      'wire-v2-schema-74-or-75': 'compatibility-only-unselectable'
    })
  }
]
const manifestBytes = encodeVectorManifest(vectorFiles)
const authority = {
  magic: 'hiverelay-blind-wire-authority-v3',
  formatVersion: 3,
  protocol: WIRE_V3_PROTOCOL,
  baseSchemaCount: 75,
  compatibilityOnlySchemaIds: [74, 75],
  baseWireV2AbiHash: hex(baseWireV2AbiHash),
  abiHash: hex(hashAbi(abiBytes)),
  specHash: hex(hashSpec(specBytes)),
  vectorSetHash: hex(hashVectorSet(manifestBytes)),
  additionalSchemas: WIRE_V3_SCHEMA_DECLARATIONS,
  releaseProfiles: profiles,
  successorTransportVariants: FORWARD_HTTPS_SUCCESSOR_TRANSPORT_VARIANTS_V3,
  additionalDomains: domains,
  hashDomainPurpose: WIRE_V3_HASH_DOMAIN_PURPOSE,
  hashRecipes: WIRE_V3_HASH_RECIPES,
  tlsExporterLabel: FORWARD_HTTPS_TLS_EXPORTER_LABEL_V1,
  exactRequestBytes: FORWARD_HTTPS_V3_LIMITS.EXACT_REQUEST_BYTES,
  exactResultBytes: FORWARD_HTTPS_V3_LIMITS.EXACT_RESULT_BYTES,
  maxDataBytes: FORWARD_HTTPS_V3_LIMITS.MAX_DATA_BYTES,
  forwardDescriptorOperationBits: 0,
  forwardAdvertisedOperationBits: 0,
  forwardReadinessOperationBits: 0,
  runtimeReady: false,
  authorizesRelease: false,
  compatibilityFloor
}
const outputs = [
  [path.join(root, 'hiverelay-blind-abi-v3.cenc'), abiBytes],
  [path.join(root, 'vector-manifest-v3.cenc'), manifestBytes],
  [path.join(root, 'hiverelay-blind-wire-authority-v3.json'), json(authority)],
  [path.join(root, 'wire-runtime-authority-v3.js'), b4a.from(runtimeAuthoritySource(authority))]
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
  for (const found of await walk(vectorRoot)) if (!expected.has(found)) throw new Error(`unexpected WIRE v3 vector: ${found}`)
}

console.log(check ? 'WIRE v3 authority verified' : 'WIRE v3 authority generated')
