import fs from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { createHash } from 'node:crypto'
import b4a from 'b4a'
import { decodeCanonical } from '@hiverelay/blind-protocol/codec'
import { encodeVectorManifest } from '@hiverelay/blind-protocol/hashes'
import {
  blindForwardHttpsOriginForwardTurnRequestV1,
  blindForwardHttpsOriginForwardTurnResultV1,
  forwardHttpsForwardedRequestCommitmentV1,
  forwardHttpsOriginRequestCommitmentV1
} from '@hiverelay/blind-protocol'
import { hashImportedWireAbi } from './private-hashes.js'
import {
  LOCAL_FORWARD_HTTPS_DIRECTION_V4,
  PRIVATE_IPC_V4_ADDITIONAL_SCHEMAS,
  PRIVATE_IPC_V4_LIMITS,
  createLocalForwardHttpsOriginAuthorityV4,
  createLocalForwardHttpsTargetIngressV4,
  createPrivateIpcV4RegistryValue,
  encodeLocalForwardHttpsOriginAuthorityV4,
  encodeLocalForwardHttpsSourceOriginTranscriptV4,
  encodeLocalForwardHttpsTargetIngressV4,
  encodeLocalForwardHttpsTurnV4,
  encodePrivateIpcV4Registry,
  forwardHttpsTargetTlsExporterBindingHashV4,
  forwardHttpsTargetTlsExporterContextV4,
  hashPrivateIpcV4Registry,
  hashPrivateIpcV4VectorManifest,
  localForwardHttpsSourceReplayTupleV4,
  localForwardHttpsTargetReplayTupleV4
} from './private-ipc-v4-contract.js'

const check = process.argv.includes('--check')
const packageRoot = path.dirname(new URL(import.meta.url).pathname)
const repoRoot = path.resolve(packageRoot, '../..')
const protocolRoot = path.resolve(packageRoot, '../blind-protocol')
const vectorRoot = path.join(packageRoot, 'vectors-v4')
const hex = value => b4a.toString(value, 'hex')
const fixed = (length, value) => b4a.alloc(length, value)
const json = value => b4a.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8')

const compatibilityFloor = Object.freeze({
  'hiverelay-blind-private-ipc-v1.cenc': '116c78ad151543ff9973d4cb92089ddfbc2e3f861b1f502b9aa0c85a5a52e4f6',
  'hiverelay-blind-private-ipc-v1.draft.cenc': '116c78ad151543ff9973d4cb92089ddfbc2e3f861b1f502b9aa0c85a5a52e4f6',
  'vector-manifest-v1.cenc': 'd9949afeeb9fc06db9864d388a6917ca99bbec244395932a707cd8ab9736e29e',
  'hiverelay-blind-private-ipc-authority-v1.json': 'cba3f4be2f616a66730a90ce92ce78a963cf5389d18e41b9cdfe4ae1eeb5a59d',
  'hiverelay-blind-private-ipc-v2.cenc': '3475a93f8d6da4d5c516ec0017f4eb8337a2397f89dbb0000ea004f225461344',
  'vector-manifest-v2.cenc': '0abb90824d9e5388d538ae6a49cee67437056987601717bb9bdb003218deccff',
  'hiverelay-blind-private-ipc-authority-v2.json': '9e2abeed720afcea9165775bca0dff165901a1eab97251a7677d66e6292143a7',
  'hiverelay-blind-private-ipc-v3.cenc': 'c3e109c36d4252399a1dab655cbc94291963fedfff9826630c82c7c33492b639',
  'vector-manifest-v3.cenc': '13ab3659deb5442189f52fb326dfb6b72e4050c0ce2de1fca39de94a20c7489f',
  'hiverelay-blind-private-ipc-authority-v3.json': '253d0c015c12cc67ab2b599992c2b23ea2256ebd5a669d0799f8c21181b3abf3',
  'private-ipc-v3-contract.js': 'f0baeb69c787d461f052468a31c490274b39854a97927583047691c58285f730',
  'private-ipc-v3-status.js': 'f8fbd4c28c955755ca2a42f5c5bd714bd9ecc3b87fbb685d1410553ec1d1369c'
})

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

async function assertCompatibilityFloor () {
  for (const [relative, expected] of Object.entries(compatibilityFloor)) {
    const actual = sha256(await fs.readFile(path.join(packageRoot, relative)))
    if (actual !== expected) throw new Error(`frozen private IPC v1/v2/v3 artifact changed: ${relative} ${actual}`)
  }
}

async function writeOrCheck (file, bytes) {
  if (!b4a.isBuffer(bytes)) bytes = b4a.from(bytes)
  if (check) {
    let current
    try {
      current = await fs.readFile(file)
    } catch {
      throw new Error(`missing generated private IPC v4 artifact: ${path.relative(repoRoot, file)}`)
    }
    if (!b4a.equals(current, bytes)) throw new Error(`stale generated private IPC v4 artifact: ${path.relative(repoRoot, file)}`)
    return
  }
  await fs.mkdir(path.dirname(file), { recursive: true })
  await fs.writeFile(file, bytes)
}

function mutate (input, offset) {
  const output = b4a.from(input)
  output[offset] ^= 1
  return output
}

function statusSource (authority) {
  const status = {
    profile: 'private-ipc-authority-v4',
    authorityArtifactPath: 'packages/blind-ipc/hiverelay-blind-private-ipc-v4.cenc',
    vectorManifestPath: 'packages/blind-ipc/vector-manifest-v4.cenc',
    authorityMetadataPath: 'packages/blind-ipc/hiverelay-blind-private-ipc-authority-v4.json',
    importedWireV3AbiHash: authority.importedWireV3AbiHash,
    basePrivateIpcV3FormatHash: authority.basePrivateIpcV3FormatHash,
    privateIpcFormatHash: authority.privateIpcFormatHash,
    privateIpcVectorSetHash: authority.privateIpcVectorSetHash,
    schemaCount: authority.schemaCount,
    additionalSchemaIds: [16, 17, 18],
    contractReady: true,
    forwardDescriptorOperationBits: 0,
    forwardAdvertisedOperationBits: 0,
    forwardReadinessOperationBits: 0,
    runtimeReady: false,
    releaseReady: false,
    authorizesRelease: false
  }
  return '/* eslint-disable */\n// Generated by generate-private-ipc-v4.mjs. Do not edit.\n' +
    `export const PRIVATE_IPC_V4_STATUS = Object.freeze(${JSON.stringify(status, null, 2)})\n` +
    'export function assertPrivateIpcV4Status (actual) {\n' +
    '  if (!actual || actual.importedWireV3AbiHash !== PRIVATE_IPC_V4_STATUS.importedWireV3AbiHash ||\n' +
    '      actual.basePrivateIpcV3FormatHash !== PRIVATE_IPC_V4_STATUS.basePrivateIpcV3FormatHash ||\n' +
    '      actual.privateIpcFormatHash !== PRIVATE_IPC_V4_STATUS.privateIpcFormatHash ||\n' +
    '      actual.privateIpcVectorSetHash !== PRIVATE_IPC_V4_STATUS.privateIpcVectorSetHash ||\n' +
    '      actual.schemaCount !== 18 || actual.forwardReadinessOperationBits !== 0 ||\n' +
    '      actual.runtimeReleaseReady !== false || actual.authorizesRelease !== false) {\n' +
    '    const error = new Error(\'private IPC v4 authority status mismatch\')\n' +
    '    error.code = \'PRIVATE_IPC_V4_STATUS_MISMATCH\'\n' +
    '    throw error\n' +
    '  }\n' +
    '  return true\n' +
    '}\n'
}

await assertCompatibilityFloor()

const wireAbiBytes = await fs.readFile(path.join(protocolRoot, 'hiverelay-blind-abi-v3.cenc'))
const wireV3AbiHash = hashImportedWireAbi(wireAbiBytes)
const wireAuthority = JSON.parse(await fs.readFile(path.join(protocolRoot, 'hiverelay-blind-wire-authority-v3.json'), 'utf8'))
if (hex(wireV3AbiHash) !== wireAuthority.abiHash) throw new Error('WIRE v3 ABI hash does not match generated authority')
const ipcV3Authority = JSON.parse(await fs.readFile(path.join(packageRoot, 'hiverelay-blind-private-ipc-authority-v3.json'), 'utf8'))
if (ipcV3Authority.privateIpcFormatHash !== 'efb4fd8eae1a2338722deced991fdc907b465d7580acfe2bde8ad692dc1c8200') {
  throw new Error('frozen private IPC v3 format hash mismatch')
}
const basePrivateIpcV3FormatHash = b4a.from(ipcV3Authority.privateIpcFormatHash, 'hex')
const registryBytes = encodePrivateIpcV4Registry(createPrivateIpcV4RegistryValue(wireV3AbiHash, basePrivateIpcV3FormatHash))

const openOriginBytes = await fs.readFile(path.join(protocolRoot, 'vectors-v3/wire/positive/open-origin.bin'))
const openForwardedBytes = await fs.readFile(path.join(protocolRoot, 'vectors-v3/wire/positive/open-forwarded.bin'))
const targetResultBytes = await fs.readFile(path.join(protocolRoot, 'vectors-v3/wire/positive/open-target-result.bin'))
const sourceErrorBytes = await fs.readFile(path.join(protocolRoot, 'vectors-v3/wire/positive/data-target-source-error.bin'))
const sourceAmbiguousBytes = await fs.readFile(path.join(protocolRoot, 'vectors-v3/wire/positive/data-target-source-ambiguous.bin'))
const origin = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, openOriginBytes, { copyBytes: true })
const forwarded = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, openForwardedBytes, { copyBytes: true })

const originAuthority = createLocalForwardHttpsOriginAuthorityV4({
  version: 4,
  authorityKind: 1,
  transportId: 1,
  endpointId: 1,
  flags: 0,
  wireV3AbiHash,
  signedLaunchTopologyHash: fixed(32, 71),
  edgeProcessNonce: fixed(32, 72),
  localChannelNonce: fixed(32, 73),
  tlsExporterBindingHash: fixed(32, 74),
  originRequestCommitment: forwardHttpsOriginRequestCommitmentV1(openOriginBytes),
  stableSessionId: origin.stableSessionId,
  sequence: origin.sequence,
  acceptedMonotonicMillis: 1_000_000n,
  absoluteDeadlineMonotonicMillis: 1_015_000n
})
const originAuthorityBytes = encodeLocalForwardHttpsOriginAuthorityV4(originAuthority)
const originTurn = {
  version: 4,
  direction: LOCAL_FORWARD_HTTPS_DIRECTION_V4.ORIGIN_REQUEST,
  wireRole: 0,
  flags: 0,
  wireV3AbiHash,
  localExchangeId: originAuthority.localExchangeId,
  originRequestCommitment: originAuthority.originRequestCommitment,
  stableSessionId: origin.stableSessionId,
  sequence: origin.sequence,
  body: openOriginBytes
}
const originTurnBytes = encodeLocalForwardHttpsTurnV4(originTurn)
const sourceTranscriptBytes = encodeLocalForwardHttpsSourceOriginTranscriptV4(originAuthority, originTurn)

const targetContext = forwardHttpsTargetTlsExporterContextV4(
  forwarded.stableSessionId,
  forwarded.sequence,
  forwardHttpsForwardedRequestCommitmentV1(openForwardedBytes)
)
const targetBinding = forwardHttpsTargetTlsExporterBindingHashV4(fixed(32, 75), targetContext)
const targetIngress = createLocalForwardHttpsTargetIngressV4({
  endpointId: 2,
  wireV3AbiHash,
  signedLaunchTopologyHash: fixed(32, 71),
  edgeProcessNonce: fixed(32, 76),
  localChannelNonce: fixed(32, 77),
  targetTlsExporterBindingHash: targetBinding,
  acceptedMonotonicMillis: 2_000_000n,
  absoluteDeadlineMonotonicMillis: 2_015_000n,
  body: openForwardedBytes
})
const targetIngressBytes = encodeLocalForwardHttpsTargetIngressV4(targetIngress)

function resultTurn (body, localExchangeId) {
  const result = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, body, { copyBytes: true })
  return encodeLocalForwardHttpsTurnV4({
    version: 4,
    direction: LOCAL_FORWARD_HTTPS_DIRECTION_V4.RESULT,
    wireRole: result.resultRole,
    flags: 0,
    wireV3AbiHash,
    localExchangeId,
    originRequestCommitment: result.originRequestCommitment,
    stableSessionId: result.stableSessionId,
    sequence: result.sequence,
    body
  })
}

const targetResultTurnBytes = resultTurn(targetResultBytes, targetIngress.targetLocalExchangeId)
const sourceErrorTurnBytes = resultTurn(sourceErrorBytes, originAuthority.localExchangeId)
const sourceAmbiguousTurnBytes = resultTurn(sourceAmbiguousBytes, originAuthority.localExchangeId)
const replacementTargetContext = forwardHttpsTargetTlsExporterContextV4(
  forwarded.stableSessionId,
  forwarded.sequence,
  targetIngress.forwardedRequestCommitment
)
const replacementTargetIngress = createLocalForwardHttpsTargetIngressV4({
  ...targetIngress,
  localChannelNonce: fixed(32, 78),
  targetTlsExporterBindingHash: forwardHttpsTargetTlsExporterBindingHashV4(fixed(32, 79), replacementTargetContext),
  acceptedMonotonicMillis: 2_001_000n,
  absoluteDeadlineMonotonicMillis: 2_016_000n,
  targetLocalExchangeId: undefined
})
const replacementOriginAuthority = createLocalForwardHttpsOriginAuthorityV4({
  ...originAuthority,
  localChannelNonce: fixed(32, 80),
  tlsExporterBindingHash: fixed(32, 81),
  acceptedMonotonicMillis: 1_001_000n,
  absoluteDeadlineMonotonicMillis: 1_016_000n,
  localExchangeId: undefined
})

const vectorFiles = [
  { path: 'registry/private-ipc-v4.cenc', bytes: registryBytes },
  { path: 'registry/additional-schemas.json', bytes: json(PRIVATE_IPC_V4_ADDITIONAL_SCHEMAS) },
  { path: 'registry/compatibility-floor.json', bytes: json(compatibilityFloor) },
  { path: 'positive/source-origin-authority-v4.bin', bytes: originAuthorityBytes },
  { path: 'positive/source-origin-turn-v4.bin', bytes: originTurnBytes },
  { path: 'positive/source-origin-transcript-v4.bin', bytes: sourceTranscriptBytes },
  { path: 'positive/source-result-target-v4.bin', bytes: resultTurn(targetResultBytes, originAuthority.localExchangeId) },
  { path: 'positive/source-result-error-v4.bin', bytes: sourceErrorTurnBytes },
  { path: 'positive/source-result-ambiguous-v4.bin', bytes: sourceAmbiguousTurnBytes },
  { path: 'positive/target-ingress-v4.bin', bytes: targetIngressBytes },
  { path: 'positive/target-result-turn-v4.bin', bytes: targetResultTurnBytes },
  { path: 'positive/target-tls-context-v4.bin', bytes: targetContext },
  { path: 'positive/target-tls-binding-v4.bin', bytes: targetBinding },
  { path: 'positive/source-replay-tuple-v4.bin', bytes: localForwardHttpsSourceReplayTupleV4(originAuthority) },
  { path: 'positive/target-replay-tuple-v4.bin', bytes: localForwardHttpsTargetReplayTupleV4(targetIngress) },
  { path: 'positive/replacement-source-authority-v4.bin', bytes: encodeLocalForwardHttpsOriginAuthorityV4(replacementOriginAuthority) },
  { path: 'positive/replacement-target-ingress-v4.bin', bytes: encodeLocalForwardHttpsTargetIngressV4(replacementTargetIngress) },
  { path: 'negative/source-origin-bad-magic.bin', bytes: mutate(sourceTranscriptBytes, 0) },
  { path: 'negative/source-origin-extra-record.bin', bytes: b4a.concat([sourceTranscriptBytes, fixed(1, 1)]) },
  { path: 'negative/source-origin-role-forwarded.bin', bytes: mutate(sourceTranscriptBytes, 292 + 6) },
  { path: 'negative/source-origin-exchange-mismatch.bin', bytes: mutate(sourceTranscriptBytes, 292 + 40) },
  { path: 'negative/target-ingress-origin-role.bin', bytes: b4a.concat([targetIngressBytes.subarray(0, 292), openOriginBytes]) },
  { path: 'negative/target-ingress-bad-binding.bin', bytes: mutate(targetIngressBytes, 140) },
  { path: 'negative/target-ingress-bad-exchange.bin', bytes: mutate(targetIngressBytes, 260) },
  { path: 'negative/target-result-source-role.bin', bytes: mutate(targetResultTurnBytes, 6) },
  {
    path: 'negative/expectations.json',
    bytes: json({
      'source-origin-bad-magic.bin': 'reject-ID16-magic',
      'source-origin-extra-record.bin': 'reject-exact-transcript-length',
      'source-origin-role-forwarded.bin': 'reject-source-socket-role-confusion',
      'source-origin-exchange-mismatch.bin': 'reject-ID16-ID17-binding',
      'target-ingress-origin-role.bin': 'reject-target-role-origin-template',
      'target-ingress-bad-binding.bin': 'reject-target-exchange-recomputation',
      'target-ingress-bad-exchange.bin': 'reject-target-exchange-recomputation',
      'target-result-source-role.bin': 'reject-target-result-role-confusion',
      'missing-eof': 'reject-before-claim-sign-spend-dial-or-response',
      'ID16-on-target-socket': 'reject-record-family',
      'ID18-on-source-socket': 'reject-record-family',
      'outer-envelope-or-native-stream-fallback': 'unrepresentable',
      'raw-exporter-source-address-credentials': 'unrepresentable',
      'socket-or-journal-alias': 'reject'
    })
  }
]
const manifestBytes = encodeVectorManifest(vectorFiles)
const authority = {
  authorityVersion: 4,
  formatVersion: 4,
  authorizesRelease: false,
  contractReady: true,
  runtimeReleaseReady: false,
  importedWireV3AbiHash: hex(wireV3AbiHash),
  basePrivateIpcV3FormatHash: hex(basePrivateIpcV3FormatHash),
  privateIpcFormatHash: hex(hashPrivateIpcV4Registry(registryBytes)),
  privateIpcRegistrySha256: sha256(registryBytes),
  privateIpcVectorSetHash: hex(hashPrivateIpcV4VectorManifest(manifestBytes)),
  privateIpcVectorManifestSha256: sha256(manifestBytes),
  baseSchemaCount: 15,
  additionalSchemas: PRIVATE_IPC_V4_ADDITIONAL_SCHEMAS,
  schemaCount: 18,
  vectorCount: vectorFiles.length,
  exactByteLimits: {
    sourceOriginRequest: PRIVATE_IPC_V4_LIMITS.SOURCE_ORIGIN_TRANSCRIPT_BYTES,
    targetIngressRequest: PRIVATE_IPC_V4_LIMITS.TARGET_INGRESS_BYTES,
    result: PRIVATE_IPC_V4_LIMITS.RESULT_TRANSCRIPT_BYTES,
    targetLocalRequestPlusResult: PRIVATE_IPC_V4_LIMITS.TARGET_LOCAL_REQUEST_PLUS_RESULT_BYTES
  },
  replayPayloadBytes: PRIVATE_IPC_V4_LIMITS.REPLAY_PAYLOAD_BYTES,
  replayCapacity: PRIVATE_IPC_V4_LIMITS.REPLAY_CAPACITY,
  maxDeadlineMillis: PRIVATE_IPC_V4_LIMITS.MAX_DEADLINE_MILLIS,
  forwardDescriptorOperationBits: 0,
  forwardAdvertisedOperationBits: 0,
  forwardReadinessOperationBits: 0,
  compatibilityFloor,
  modelOnly: true,
  releaseBlockers: [
    'filesystem journals, fsync, dedicated socket enforcement and tamper recovery remain runtime/storage work',
    'native peercred enforcement, real TLS exporter extraction and crash injection remain runtime work',
    'FORWARD descriptor, advertised and readiness bits remain zero pending independent acceptance'
  ]
}

const outputs = [
  [path.join(packageRoot, 'hiverelay-blind-private-ipc-v4.cenc'), registryBytes],
  [path.join(packageRoot, 'vector-manifest-v4.cenc'), manifestBytes],
  [path.join(packageRoot, 'hiverelay-blind-private-ipc-authority-v4.json'), json(authority)],
  [path.join(packageRoot, 'private-ipc-v4-status.js'), b4a.from(statusSource(authority))]
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
  for (const found of await walk(vectorRoot)) if (!expected.has(found)) throw new Error(`unexpected private IPC v4 vector: ${found}`)
}

console.log(check ? 'private IPC v4 authority verified' : 'private IPC v4 authority generated')
