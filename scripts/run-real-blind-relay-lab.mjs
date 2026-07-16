#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import fs from 'node:fs/promises'
import https from 'node:https'
import net from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ENDPOINT_ROLE,
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  PRIVACY_PROFILE,
  PROTOCOL,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  admissionParametersV1,
  blake2b256,
  blindErrorV1,
  blindReceiptV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  decodeOuterEnvelope,
  durabilityContinuityBindingV1,
  durabilityContinuityHash,
  durabilityProfileHash,
  durabilityProfileV1,
  encodeCanonical,
  encodeDispatchFrame,
  encodeOuterEnvelope,
  hashStoreFormat,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import {
  createCellReplica,
  createGetCellRequest
} from '@hiverelay/blind-client'
import {
  BlindDirectHttpClient,
  BlindRelayQualifier,
  DescriptorTrustStore,
  openVerifiedCellGetResult,
  verifiedEndpointContext,
  verifyDescriptorBytes,
  verifyOperationResult
} from '@hiverelay/blind-client/control'
import { createNodeCryptoRuntime } from '@hiverelay/blind-client/runtime/node'
import { BlindEdge } from '@hiverelay/blind-edge'
import {
  PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS,
  assembleProductionBlindDaemon
} from '../packages/blind-daemon/production-runtime.js'
import {
  REAL_BLIND_RELAY_FAMILY_SCOPE,
  REAL_BLIND_RELAY_CANONICALIZATION,
  REAL_BLIND_RELAY_LAB_SCHEMA,
  REAL_BLIND_RELAY_LOCAL_PERFORMANCE_THRESHOLDS,
  REAL_BLIND_RELAY_MANDATORY_REPLAY_QUARANTINE_MILLIS,
  realBlindRelayExpectedBlockers,
  sealRealBlindRelayReport,
  verifyRealBlindRelayReport
} from './verify-real-blind-relay-report.mjs'

const EPOCH_MILLIS = 6 * 60 * 60 * 1000
const CELL_PROTOCOL_PROFILE_HASH_BYTE = 0x27
const STORE_FORMAT_AUTHORITY = new URL(
  '../packages/blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc',
  import.meta.url
)
const DESCRIPTOR_VECTOR = new URL(
  '../packages/blind-protocol/vectors/draft/describe/service-descriptor.bin',
  import.meta.url
)
const ADMISSION_VECTOR = new URL(
  '../packages/blind-protocol/vectors/draft/describe/admission-parameters.bin',
  import.meta.url
)

const DEFAULTS = Object.freeze({
  relayCount: 3,
  recordsPerRelay: 24,
  concurrency: 8,
  contentBytes: 256
})
const execFileAsync = promisify(execFile)
const PRIVATE_IPC_V2_STARTUP_QUARANTINE = 'PRIVATE_IPC_V2_REPLAY_JOURNAL_STARTUP_QUARANTINE'
const V2_WRITE_READINESS_TIMEOUT_MS = 20_000
const V2_WRITE_READINESS_POLL_MS = 50
const SOURCE_CLIENT_API = Object.freeze({
  BlindRelayQualifier,
  DescriptorTrustStore,
  verifiedEndpointContext,
  verifyDescriptorBytes
})

function fail (message) {
  const error = new Error(message)
  error.code = 'BLIND_REAL_RELAY_LAB_INVALID'
  throw error
}

function boundedInteger (value, fallback, minimum, maximum, field) {
  if (value == null) return fallback
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${field} must be an integer within ${minimum}..${maximum}`)
  }
  return value
}

function normalizeIdentityScope (value, required = false) {
  if (value == null) {
    if (required) fail('identityScope is required for a scoped real relay lab')
    return null
  }
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(value)) {
    fail('identityScope must match ^[a-z0-9][a-z0-9-]{0,63}$')
  }
  return value
}

function scopedDeterministicLabel (identityScope, label) {
  return identityScope == null
    ? label
    : `hiverelay-blind-real-lab-v1:${identityScope}:${label}`
}

function elapsedMillis (started, ended = process.hrtime.bigint()) {
  return Number(ended - started) / 1e6
}

function percentile (values, quantile) {
  if (values.length === 0) return null
  const sorted = [...values].sort((left, right) => left - right)
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * quantile) - 1))
  return Number(sorted[index].toFixed(3))
}

function latencySummary (values) {
  const total = values.reduce((sum, value) => sum + value, 0)
  return Object.freeze({
    count: values.length,
    meanMs: values.length === 0 ? null : Number((total / values.length).toFixed(3)),
    p50Ms: percentile(values, 0.50),
    p95Ms: percentile(values, 0.95),
    p99Ms: percentile(values, 0.99),
    maxMs: values.length === 0 ? null : Number(Math.max(...values).toFixed(3))
  })
}

function deterministicBytes (label, length) {
  const chunks = []
  let total = 0
  let counter = 0
  while (total < length) {
    const chunk = createHash('sha256').update(`${label}:${counter++}`, 'utf8').digest()
    chunks.push(chunk)
    total += chunk.byteLength
  }
  return b4a.from(Buffer.concat(chunks, total).subarray(0, length))
}

function deterministicRuntime (label) {
  const node = createNodeCryptoRuntime()
  let counter = 0
  return Object.freeze({
    randomBytes (length) {
      return deterministicBytes(`${label}:random:${counter++}`, length)
    },
    aes256GcmEncrypt: node.aes256GcmEncrypt,
    aes256GcmDecrypt: node.aes256GcmDecrypt
  })
}

function signCanonical (codec, value, domainId, secretKey) {
  value.signature = b4a.alloc(sodium.crypto_sign_BYTES)
  const placeholder = encodeCanonical(codec, value)
  const unsigned = placeholder.subarray(0, placeholder.byteLength - sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(value.signature, resultSignaturePayload(domainId, unsigned), secretKey)
  return encodeCanonical(codec, value)
}

function bindDurability (descriptor) {
  descriptor.durabilityProfileHash = durabilityProfileHash(
    encodeCanonical(durabilityProfileV1, descriptor.durability)
  )
  descriptor.durabilityContinuityHash = durabilityContinuityHash(
    encodeCanonical(durabilityContinuityBindingV1, {
      version: 1,
      profileId: descriptor.durability.profileId,
      externalJournalId: descriptor.durability.externalJournalId,
      externalWitnessPublicKey: descriptor.durability.externalWitnessPublicKey,
      externalJournalReplicationClass: descriptor.durability.externalJournalReplicationClass,
      externalJournalFailureGroupId: descriptor.durability.externalJournalFailureGroupId,
      restoreEvidenceFeedId: descriptor.durability.restoreEvidenceFeedId
    })
  )
}

async function privateFile (file, bytes) {
  await fs.writeFile(file, bytes, { mode: 0o600 })
  await fs.chmod(file, 0o600)
}

async function ephemeralLoopbackTls (root) {
  const keyFile = path.join(root, 'loopback-tls-key.pem')
  const certFile = path.join(root, 'loopback-tls-cert.pem')
  await execFileAsync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-subj', '/CN=127.0.0.1', '-days', '1',
    '-keyout', keyFile, '-out', certFile
  ], { timeout: 15_000, maxBuffer: 1024 * 1024 })
  await fs.chmod(keyFile, 0o600)
  return Object.freeze({
    key: await fs.readFile(keyFile),
    cert: await fs.readFile(certFile)
  })
}

function localTlsFetch (url, init = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (error, value) => {
      if (settled) return
      settled = true
      if (init.signal) init.signal.removeEventListener('abort', onAbort)
      if (error) reject(error)
      else resolve(value)
    }
    const headers = {}
    for (const [name, value] of init.headers || []) headers[name] = value
    const request = https.request(url, {
      method: init.method || 'GET',
      headers,
      rejectUnauthorized: false,
      agent: false
    }, response => {
      const chunks = []
      let total = 0
      response.on('data', chunk => {
        total += chunk.byteLength
        if (total > 8 * 1024 * 1024) {
          request.destroy(new Error('local TLS response exceeded the harness bound'))
          return
        }
        chunks.push(b4a.from(chunk))
      })
      response.once('error', finish)
      response.once('end', () => {
        const responseHeaders = new Headers()
        for (const [name, value] of Object.entries(response.headers)) {
          if (Array.isArray(value)) {
            for (const item of value) responseHeaders.append(name, item)
          } else if (value != null) responseHeaders.set(name, String(value))
        }
        finish(null, new Response(b4a.concat(chunks, total), {
          status: response.statusCode,
          statusText: response.statusMessage,
          headers: responseHeaders
        }))
      })
    })
    const onAbort = () => request.destroy(init.signal.reason || new Error('local TLS request aborted'))
    request.once('error', finish)
    if (init.signal) {
      if (init.signal.aborted) return onAbort()
      init.signal.addEventListener('abort', onAbort, { once: true })
    }
    request.end(init.body == null ? undefined : b4a.from(init.body))
  })
}

async function unusedLoopbackPort () {
  const server = net.createServer()
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.once('listening', resolve)
    server.listen(0, '127.0.0.1')
  })
  const address = server.address()
  await new Promise(resolve => server.close(resolve))
  if (!address || typeof address === 'string') fail('could not allocate a loopback port')
  return address.port
}

async function directoryUsage (root) {
  let files = 0
  let bytes = 0
  async function walk (directory) {
    const entries = await fs.readdir(directory, { withFileTypes: true })
    for (const entry of entries) {
      const child = path.join(directory, entry.name)
      if (entry.isDirectory()) await walk(child)
      else if (entry.isFile()) {
        const stat = await fs.stat(child)
        files++
        bytes += stat.size
      }
    }
  }
  await walk(root)
  return Object.freeze({ files, bytes })
}

async function mapConcurrent (values, concurrency, operation) {
  const output = new Array(values.length)
  let cursor = 0
  async function worker () {
    for (;;) {
      const index = cursor++
      if (index >= values.length) return
      output[index] = await operation(values[index], index)
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, worker))
  return output
}

function supportPins (descriptor) {
  return Object.freeze({
    supportedProtocolProfiles: descriptor.protocols.map(value => Object.freeze({
      protocolId: value.protocolId,
      major: value.major,
      minimumMinor: value.minor,
      profileHash: b4a.from(value.profileHash)
    })),
    supportedTransportProfiles: descriptor.endpoints.map(value => Object.freeze({
      transportId: value.transportId,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
      transportProfileHash: b4a.from(value.transportProfileHash)
    }))
  })
}

async function createRelayFixture (root, relayIndex, port, authorityBytes, tls, identityScope = null) {
  const directory = path.join(root, `relay-${relayIndex}`)
  const storeRoot = path.join(directory, 'store')
  const privateIpcReplayRoot = path.join(directory, 'private-ipc-replay')
  const ipcRoot = path.join(directory, 'ipc')
  await fs.mkdir(storeRoot, { recursive: true, mode: 0o700 })
  await fs.mkdir(privateIpcReplayRoot, { recursive: true, mode: 0o700 })
  await fs.mkdir(ipcRoot, { recursive: true, mode: 0o700 })
  await fs.chmod(directory, 0o700)
  await fs.chmod(storeRoot, 0o700)
  await fs.chmod(privateIpcReplayRoot, 0o700)
  await fs.chmod(ipcRoot, 0o700)

  const relayPublicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const relaySecretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(
    relayPublicKey,
    relaySecretKey,
    deterministicBytes(
      scopedDeterministicLabel(identityScope, `real-relay-${relayIndex}:signing-seed`),
      sodium.crypto_sign_SEEDBYTES
    )
  )
  const currentEpoch = Math.floor(Date.now() / EPOCH_MILLIS)

  const admission = decodeCanonical(admissionParametersV1, await fs.readFile(ADMISSION_VECTOR), {
    copyBytes: true
  })
  admission.relayPublicKey = b4a.from(relayPublicKey)
  admission.roleBits = ENDPOINT_ROLE.STORAGE
  admission.validFromEpoch = currentEpoch
  admission.expiresEpoch = currentEpoch + 4
  admission.nonce = deterministicBytes(
    scopedDeterministicLabel(identityScope, `real-relay-${relayIndex}:admission-nonce`),
    32
  )
  const cellCostIndex = admission.resourceCosts.findIndex(row =>
    row.familyId === FAMILY.CELL && row.operationId === OPERATION.CELL.PUT &&
    row.resourceClass === 1 && row.leaseClass === 1)
  if (cellCostIndex === -1) fail('real relay admission fixture has no baseline CELL.PUT cost row')
  const cellCost = admission.resourceCosts[cellCostIndex]
  admission.resourceCosts.splice(cellCostIndex + 1, 0, Object.freeze({
    ...cellCost,
    leaseClass: 4,
    costUnits: cellCost.costUnits * 4n
  }))
  const admissionBytes = signCanonical(
    admissionParametersV1,
    admission,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS,
    relaySecretKey
  )
  const parameterHash = admissionParametersHash(admissionBytes)

  const descriptor = decodeCanonical(blindServiceDescriptorV1, await fs.readFile(DESCRIPTOR_VECTOR), {
    copyBytes: true
  })
  descriptor.relayPublicKey = b4a.from(relayPublicKey)
  descriptor.storeId = deterministicBytes(
    scopedDeterministicLabel(identityScope, `real-relay-${relayIndex}:store`),
    32
  )
  descriptor.descriptorNonce = deterministicBytes(
    scopedDeterministicLabel(identityScope, `real-relay-${relayIndex}:descriptor-nonce:0`),
    32
  )
  descriptor.descriptorSequence = 0n
  descriptor.previousDescriptorHash = null
  descriptor.issuedEpoch = currentEpoch - 1
  descriptor.expiresEpoch = currentEpoch + 3
  descriptor.enabledOperationBits = PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS
  descriptor.capacityBand = 0
  descriptor.endpoints = [descriptor.endpoints[0]]
  descriptor.endpoints[0].endpointId = 1
  descriptor.endpoints[0].transportId = TRANSPORT_ID.HTTPS_DIRECT
  descriptor.endpoints[0].roleBits = ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY |
    ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER
  descriptor.endpoints[0].privacyProfileBits = PRIVACY_PROFILE.DIRECT
  descriptor.endpoints[0].canonicalUrl = b4a.from(
    `https://127.0.0.1:${port}/api/blind/v1/describe`,
    'utf8'
  )
  descriptor.endpoints[0].envelopeClassBits = 0x007e
  if (!descriptor.protocols.some(profile => profile.protocolId === FAMILY.CELL)) {
    descriptor.protocols.push({
      protocolId: FAMILY.CELL,
      major: 1,
      minor: 0,
      featureBits: 0n,
      profileHash: b4a.alloc(32, CELL_PROTOCOL_PROFILE_HASH_BYTE)
    })
  }
  descriptor.admissionProfiles = [descriptor.admissionProfiles[0]]
  descriptor.admissionProfiles[0].profileId = admission.profileId
  descriptor.admissionProfiles[0].schemeId = admission.schemeId
  descriptor.admissionProfiles[0].conformanceClass = admission.conformanceClass
  descriptor.admissionProfiles[0].roleBits = admission.roleBits
  descriptor.admissionProfiles[0].parameterHash = b4a.from(parameterHash)
  descriptor.durability.storeFormatMajor = 1
  descriptor.durability.storeFormatMinor = 1
  descriptor.durability.storeFormatHash = hashStoreFormat(authorityBytes)
  descriptor.build.storeFormatHash = b4a.from(descriptor.durability.storeFormatHash)
  bindDurability(descriptor)
  const genesisDescriptorBytes = signCanonical(
    blindServiceDescriptorV1,
    descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
    relaySecretKey
  )
  const genesisDescriptorHash = serviceDescriptorHash(genesisDescriptorBytes)
  descriptor.descriptorNonce = deterministicBytes(
    scopedDeterministicLabel(identityScope, `real-relay-${relayIndex}:descriptor-nonce:1`),
    32
  )
  descriptor.descriptorSequence = 1n
  descriptor.previousDescriptorHash = b4a.from(genesisDescriptorHash)
  descriptor.issuedEpoch = currentEpoch
  descriptor.expiresEpoch = currentEpoch + 4
  const descriptorBytes = signCanonical(
    blindServiceDescriptorV1,
    descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
    relaySecretKey
  )
  const descriptorHash = serviceDescriptorHash(descriptorBytes)

  const genesisDescriptorFile = path.join(directory, 'descriptor-genesis.bin')
  const descriptorFile = path.join(directory, 'descriptor.bin')
  const admissionFile = path.join(directory, 'admission.bin')
  const secretKeyFile = path.join(directory, 'relay-secret.bin')
  const partitionKeyFile = path.join(directory, 'partition-key.bin')
  const ownerFenceFile = path.join(directory, 'owner-fence-hash.bin')
  await Promise.all([
    privateFile(genesisDescriptorFile, genesisDescriptorBytes),
    privateFile(descriptorFile, descriptorBytes),
    privateFile(admissionFile, admissionBytes),
    privateFile(secretKeyFile, relaySecretKey),
    privateFile(partitionKeyFile, deterministicBytes(
      scopedDeterministicLabel(identityScope, `real-relay-${relayIndex}:partition`),
      32
    )),
    privateFile(ownerFenceFile, deterministicBytes(
      scopedDeterministicLabel(identityScope, `real-relay-${relayIndex}:fence`),
      32
    ))
  ])
  relaySecretKey.fill(0)

  const uid = process.getuid()
  const gid = process.getgid()
  const launchTopologyHash = deterministicBytes(
    scopedDeterministicLabel(identityScope, `real-relay-${relayIndex}:topology`),
    32
  )
  return Object.freeze({
    relayIndex,
    identityScope,
    directory,
    storeRoot,
    privateIpcReplayRoot,
    port,
    currentEpoch,
    relayPublicKey: b4a.from(relayPublicKey),
    descriptor,
    descriptorHash: b4a.from(descriptorHash),
    genesisDescriptorBytes: b4a.from(genesisDescriptorBytes),
    genesisDescriptorHash: b4a.from(genesisDescriptorHash),
    parameterHash: b4a.from(parameterHash),
    launchTopologyHash,
    streamTransportProfileHash: b4a.from(descriptor.endpoints[0].transportProfileHash),
    tls,
    bootstrap: Object.freeze({
      unarySocketPath: path.join(ipcRoot, 'unary.sock'),
      streamSocketPath: path.join(ipcRoot, 'stream.sock'),
      expectedPeerUid: uid,
      expectedPeerGid: gid,
      socketGroupGid: gid,
      launchTopologyHash,
      endpointIds: Object.freeze([1])
    }),
    runtimeConfig: Object.freeze({
      descriptorFiles: Object.freeze([genesisDescriptorFile, descriptorFile]),
      admissionParameterFiles: Object.freeze([admissionFile]),
      relaySecretKeyFile: secretKeyFile,
      storeRoot,
      privateIpcReplayRoot,
      partitionKeyFile,
      ownerFenceTokenHashFile: ownerFenceFile,
      mapGeneration: 1n,
      expectedDescriptorSequence: descriptor.descriptorSequence,
      expectedDescriptorHash: b4a.from(descriptorHash),
      endpointSupportBindings: Object.freeze([Object.freeze({
        endpointId: 1,
        transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
      })]),
      resourceBudget: Object.freeze({
        maxItems: 4096,
        maxBytes: 256 * 1024 * 1024,
        reservePercent: 5
      }),
      server: Object.freeze({
        maxConnections: 4096,
        maxBufferedBytes: 256 * 1024 * 1024,
        closeTimeoutMs: 5000
      })
    })
  })
}

function admissionAdapter () {
  const preflights = new WeakSet()
  const prepared = input => Object.freeze({
    spendTag: blake2b256(input.admission.token),
    requestCommitment: b4a.from(input.requestCommitment),
    costClass: Object.freeze({ ...input.costClass }),
    walCommitRecord: b4a.from(input.admission.token),
    profileId: input.admission.profileId,
    schemeId: input.admission.schemeId,
    parameterHash: b4a.from(input.admission.parameterHash)
  })
  return Object.freeze({
    async prepare (input) {
      return prepared(input)
    },
    async preparePreflight () {
      const authority = Object.freeze({})
      preflights.add(authority)
      return authority
    },
    async confirmAfterEof (input) {
      if (!preflights.has(input.adapterPreflight)) {
        throw new Error('unknown synthetic admission preflight')
      }
      preflights.delete(input.adapterPreflight)
      return prepared(input)
    }
  })
}

async function startRelay (fixture, options = {}) {
  const errors = []
  const diagnostics = []
  const runtime = await assembleProductionBlindDaemon({
    bootstrap: fixture.bootstrap,
    runtimeConfig: fixture.runtimeConfig,
    enableCellRuntime: true,
    resolveAdmissionAdapter: async () => admissionAdapter(),
    releaseGate: async () => {},
    onError: error => errors.push(error)
  })
  for (const [field, methods] of [
    ['operationExecutor', ['execute', 'stageAtomicPut', 'commitAtomicPut', 'cancelAtomicPut']],
    ['capabilityVerifier', ['verify']],
    ['relationVerifier', ['verify']],
    ['cheapStateVerifier', ['inspect']],
    ['terminalStateVerifier', ['check']],
    ['capacityGuard', ['check']],
    ['transactionCoordinator', ['lookup', 'run', 'replay']],
    ['resultVerifier', ['verify']]
  ]) {
    const original = runtime.coordinator[field]
    if (!original) continue
    runtime.coordinator[field] = Object.freeze(Object.fromEntries(methods.map(method => [method, async (...args) => {
      try {
        const value = await original[method](...args)
        if (field === 'resultVerifier' && value !== true) {
          diagnostics.push(Object.freeze({ field, method, code: 'FALSE_RESULT', message: 'returned false' }))
        }
        return value
      } catch (error) {
        diagnostics.push(Object.freeze({
          field,
          method,
          code: error && error.code ? String(error.code) : null,
          message: error && error.message ? String(error.message) : String(error)
        }))
        throw error
      }
    }])))
  }
  for (const method of ['preparePreflight', 'confirmAfterEof']) {
    const original = runtime.admission[method]
    if (typeof original !== 'function') continue
    runtime.admission[method] = async (...args) => {
      try {
        return await original.apply(runtime.admission, args)
      } catch (error) {
        diagnostics.push(Object.freeze({
          field: 'admission',
          method,
          code: error && error.code ? String(error.code) : null,
          message: error && error.message ? String(error.message) : String(error)
        }))
        throw error
      }
    }
  }
  await runtime.start()
  const edge = new BlindEdge({
    host: '127.0.0.1',
    port: fixture.port,
    endpointId: 1,
    tls: relayTls(fixture),
    releaseGate: async () => {},
    readinessTopology: {
      unarySocketPath: fixture.bootstrap.unarySocketPath,
      streamSocketPath: fixture.bootstrap.streamSocketPath,
      launchTopologyHash: fixture.launchTopologyHash,
      streamTransportProfileHash: fixture.streamTransportProfileHash,
      daemonUid: process.getuid(),
      daemonGid: process.getgid(),
      socketGroupGid: process.getgid(),
      socketMode: 0o660
    },
    allowInsecureLoopback: options.allowInsecureLoopback === true,
    testHooks: options.testHooks,
    onError: error => errors.push(error)
  })
  try {
    await edge.start()
  } catch (error) {
    await runtime.close().catch(() => {})
    throw error
  }
  return { fixture, runtime, edge, errors, diagnostics }
}

function relayTls (fixture) {
  return { key: b4a.from(fixture.tls.key), cert: b4a.from(fixture.tls.cert) }
}

async function stopRelay (relay) {
  let failure = null
  try {
    await relay.edge.close()
  } catch (error) {
    failure = error
  }
  try {
    await relay.runtime.close()
  } catch (error) {
    failure = failure || error
  }
  if (failure) throw failure
}

function qualificationApi (api) {
  if (!api || typeof api !== 'object' ||
      typeof api.DescriptorTrustStore !== 'function' ||
      typeof api.BlindRelayQualifier !== 'function' ||
      typeof api.verifyDescriptorBytes !== 'function' ||
      typeof api.verifiedEndpointContext !== 'function') {
    fail('real relay qualification requires one complete blind client authority')
  }
  return api
}

async function qualifyWithApi (relay, clientRuntime, familyId, operationId, phase, api) {
  api = qualificationApi(api)
  const trustStore = new api.DescriptorTrustStore()
  const verifiedGenesis = api.verifyDescriptorBytes(relay.fixture.genesisDescriptorBytes, {
    nowEpoch: relay.fixture.currentEpoch,
    ...supportPins(relay.fixture.descriptor)
  })
  await trustStore.accept(verifiedGenesis, {
    pinnedDescriptorHash: relay.fixture.genesisDescriptorHash,
    continuityRootRelayPublicKey: relay.fixture.relayPublicKey
  })
  const qualifier = new api.BlindRelayQualifier({
    runtime: clientRuntime,
    nowEpoch: () => relay.fixture.currentEpoch,
    fetch: localTlsFetch,
    trustStore,
    ...supportPins(relay.fixture.descriptor)
  })
  const started = process.hrtime.bigint()
  try {
    const qualified = await qualifier.qualifyCandidate({
      canonicalUrl: relay.fixture.descriptor.endpoints[0].canonicalUrl,
      expectedDescriptorHash: relay.fixture.descriptorHash,
      continuityRootRelayPublicKey: relay.fixture.relayPublicKey
    }, {
      familyId,
      operationId,
      endpointId: 1,
      requiredRoleBits: familyId === FAMILY.CELL
        ? ENDPOINT_ROLE.STORAGE
        : ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY,
      privacyProfileBit: PRIVACY_PROFILE.DIRECT,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
    })
    return Object.freeze({
      relayIndex: relay.fixture.relayIndex,
      phase,
      qualified: true,
      endpoint: qualified.endpoint,
      latencyMs: elapsedMillis(started),
      code: null,
      message: null
    })
  } catch (error) {
    return Object.freeze({
      relayIndex: relay.fixture.relayIndex,
      phase,
      qualified: false,
      endpoint: null,
      latencyMs: elapsedMillis(started),
      code: error && error.code ? String(error.code) : null,
      message: error && error.message ? String(error.message) : String(error)
    })
  }
}

async function qualify (relay, clientRuntime, familyId, operationId, phase) {
  return qualifyWithApi(relay, clientRuntime, familyId, operationId, phase, SOURCE_CLIENT_API)
}

function admissionFor (fixture, recordIndex) {
  return Object.freeze({
    profileId: 7,
    schemeId: 9,
    parameterHash: b4a.from(fixture.parameterHash),
    token: deterministicBytes(scopedDeterministicLabel(
      fixture.identityScope,
      `relay-${fixture.relayIndex}:record-${recordIndex}:admission`
    ), 32)
  })
}

function logicalContent (recordIndex, contentBytes) {
  const prefix = b4a.from(`blind-real-relay-record-v1:${recordIndex}:`, 'utf8')
  if (prefix.byteLength >= contentBytes) return b4a.from(prefix.subarray(0, contentBytes))
  return b4a.concat([
    prefix,
    deterministicBytes(`logical-content:${recordIndex}`, contentBytes - prefix.byteLength)
  ])
}

async function putViaAuthenticatedStagedPath (relay, created, recordIndex) {
  const requestId = deterministicBytes(scopedDeterministicLabel(
    relay.fixture.identityScope,
    `relay-${relay.fixture.relayIndex}:record-${recordIndex}:put-request`
  ), 16)
  const dispatch = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    requestId,
    body: created.requestBytes
  })
  const outer = encodeOuterEnvelope({ innerDispatch: dispatch, outerClass: 3 })
  const url = new URL(b4a.toString(relay.fixture.descriptor.endpoints[0].canonicalUrl, 'utf8'))
  url.pathname = '/api/blind/v1/cell'
  const started = process.hrtime.bigint()
  let resultBytes
  try {
    const response = await localTlsFetch(url.href, {
      method: 'POST',
      headers: [
        ['content-type', PROTOCOL.mediaType],
        ['content-length', String(outer.byteLength)]
      ],
      body: outer
    })
    if (response.status !== 200 || response.headers.get('content-type') !== PROTOCOL.mediaType ||
        Number(response.headers.get('content-length')) !== outer.byteLength) {
      fail('public HTTPS staged CELL.PUT returned a non-protocol HTTP response')
    }
    resultBytes = b4a.from(await response.arrayBuffer())
  } catch (error) {
    const diagnostic = relay.diagnostics[relay.diagnostics.length - 1]
    if (diagnostic) {
      error.message += `; ${diagnostic.field}.${diagnostic.method}: ${diagnostic.code || 'ERROR'} ${diagnostic.message}`
    } else if (relay.errors[0]) {
      error.message += `; daemon error: ${relay.errors[0].code || 'ERROR'} ${relay.errors[0].message}`
    }
    throw error
  }
  if (resultBytes.byteLength !== outer.byteLength) {
    fail('public HTTPS staged CELL.PUT changed its selected outer class')
  }
  let resultOuter
  try {
    resultOuter = decodeOuterEnvelope(resultBytes, { copyInner: true, copyBody: true })
  } catch {
    fail('public HTTPS staged CELL.PUT returned an invalid outer envelope')
  }
  if (resultOuter.outerClass !== 3) fail('public HTTPS staged CELL.PUT returned a mismatched outer class')
  const frame = resultOuter.frame
  if (frame.frameKind === FRAME_KIND.ERROR) {
    const value = decodeCanonical(blindErrorV1, frame.body)
    const name = Object.keys(ERROR_CODE).find(key => ERROR_CODE[key] === value.code) || value.code
    const diagnostic = relay.diagnostics[relay.diagnostics.length - 1]
    const daemonError = relay.errors[relay.errors.length - 1]
    fail(`staged CELL.PUT returned ${name}${diagnostic ? ` after ${diagnostic.field}.${diagnostic.method}: ${diagnostic.code || 'ERROR'} ${diagnostic.message}` : daemonError ? `; daemon error: ${daemonError.code || 'ERROR'} ${daemonError.message}` : ''}`)
  }
  if (frame.frameKind !== FRAME_KIND.RESPONSE || frame.familyId !== FAMILY.CELL ||
      frame.operationId !== OPERATION.CELL.PUT || !b4a.equals(frame.requestId, requestId)) {
    fail('staged CELL.PUT returned a mismatched or non-success dispatch')
  }
  const receipt = decodeCanonical(blindReceiptV1, frame.body, { copyBytes: true })
  const canonicalReceipt = encodeCanonical(blindReceiptV1, receipt)
  const unsignedReceipt = canonicalReceipt.subarray(0, canonicalReceipt.byteLength - sodium.crypto_sign_BYTES)
  const signatureVerified = sodium.crypto_sign_verify_detached(
    receipt.signature,
    resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, unsignedReceipt),
    relay.fixture.relayPublicKey
  )
  if (!signatureVerified || !b4a.equals(receipt.requestCommitment, created.requestCommitment) ||
      !b4a.equals(receipt.requestNonce, created.request.clientNonce) ||
      !b4a.equals(receipt.cellBlobHash, created.request.declaredBlobHash) || receipt.stateRevision !== 0n) {
    fail('staged CELL.PUT receipt failed signature or request correlation')
  }
  return Object.freeze({
    latencyMs: elapsedMillis(started),
    receiptEpoch: receipt.receiptEpoch,
    leaseEpoch: receipt.leaseEpoch,
    stateRevision: receipt.stateRevision
  })
}

function v2WriteReadiness (relay) {
  const status = relay.runtime.status()
  return Object.freeze({
    relayIndex: relay.fixture.relayIndex,
    v2WritePathReady: status.v2WritePathReady === true,
    v2WritePathAssembled: status.v2WritePathAssembled === true,
    admissionCaptureComplete: status.admissionCapture?.complete === true,
    replayJournalReady: status.privateIpcReplayJournal?.ready === true,
    replayJournalReason: status.privateIpcReplayJournal?.reason || null,
    replayJournalStartupQuarantineMillis:
      status.privateIpcReplayJournal?.startupWriteQuarantineMillis ?? null
  })
}

async function waitForV2WriteReadiness (relays, phase) {
  const initial = relays.map(v2WriteReadiness)
  if (!initial.every(status => status.v2WritePathReady === false &&
    status.replayJournalReady === false &&
    status.replayJournalReason === PRIVATE_IPC_V2_STARTUP_QUARANTINE &&
    status.replayJournalStartupQuarantineMillis ===
      REAL_BLIND_RELAY_MANDATORY_REPLAY_QUARANTINE_MILLIS)) {
    fail(`${phase} must begin in the mandatory V2 replay-journal startup quarantine`)
  }
  const started = process.hrtime.bigint()
  const deadline = Date.now() + V2_WRITE_READINESS_TIMEOUT_MS
  for (;;) {
    const current = relays.map(v2WriteReadiness)
    if (current.every(status => status.v2WritePathReady && status.replayJournalReady &&
      status.replayJournalReason === null &&
      status.replayJournalStartupQuarantineMillis ===
        REAL_BLIND_RELAY_MANDATORY_REPLAY_QUARANTINE_MILLIS)) {
      return Object.freeze({
        phase,
        startupQuarantineObserved: true,
        startupQuarantineMillis: REAL_BLIND_RELAY_MANDATORY_REPLAY_QUARANTINE_MILLIS,
        readyBeforeWrites: true,
        waitMs: Number(elapsedMillis(started).toFixed(3))
      })
    }
    if (current.some(status => status.replayJournalReason !== PRIVATE_IPC_V2_STARTUP_QUARANTINE &&
      status.replayJournalReason !== null)) {
      fail(`${phase} V2 replay-journal readiness became unavailable: ${JSON.stringify(current)}`)
    }
    if (Date.now() >= deadline) {
      fail(`${phase} V2 replay-journal startup quarantine did not produce a write-ready path: ${JSON.stringify(current)}`)
    }
    await new Promise(resolve => setTimeout(resolve, V2_WRITE_READINESS_POLL_MS))
  }
}

async function getViaPublicEdge (relay, clientRuntime, endpoint, record, phase) {
  const request = await createGetCellRequest({
    runtime: clientRuntime,
    readCap: record.created.readCap,
    clientNonce: deterministicBytes(scopedDeterministicLabel(
      relay.fixture.identityScope,
      `relay-${relay.fixture.relayIndex}:record-${record.recordIndex}:get:${phase}`
    ), 32)
  })
  const started = process.hrtime.bigint()
  const direct = new BlindDirectHttpClient({ runtime: clientRuntime, fetch: localTlsFetch })
  const result = await direct.request({
    endpoint,
    ...request.wire,
    body: request.requestBytes
  })
  if (!result.ok) fail('public CELL.GET returned a canonical relay error')
  const verifiedResult = verifyOperationResult({
    endpoint,
    request: request.request,
    requestCommitment: request.requestCommitment,
    resultBytes: result.body
  })
  const content = await openVerifiedCellGetResult({
    verifiedResult,
    runtime: clientRuntime,
    readCap: record.created.readCap
  })
  if (!b4a.equals(content, record.content)) fail('public CELL.GET returned content that failed integrity')
  return elapsedMillis(started)
}

function exactStoreCounts (relays, expected) {
  return relays.map(relay => {
    const status = relay.runtime.status()
    return Object.freeze({
      relayIndex: relay.fixture.relayIndex,
      expectedCellRecords: expected,
      actualCellRecords: status.storage.accounting.cellRecords,
      storedBytes: status.storage.accounting.storedBytes,
      exact: status.storage.accounting.cellRecords === expected
    })
  })
}

function uniqueHexCount (values) {
  return new Set(values.map(value => b4a.toString(value, 'hex'))).size
}

function independentlyAllocatedCopyCount (records, relayCount, recordsPerRelay) {
  let independentlyAllocated = 0
  for (let recordIndex = 0; recordIndex < recordsPerRelay; recordIndex++) {
    const storageSlots = new Set()
    const encryptedBlobHashes = new Set()
    for (let relayIndex = 0; relayIndex < relayCount; relayIndex++) {
      const record = records[relayIndex * recordsPerRelay + recordIndex]
      storageSlots.add(b4a.toString(record.created.request.storageSlot, 'hex'))
      encryptedBlobHashes.add(b4a.toString(record.created.request.declaredBlobHash, 'hex'))
    }
    if (storageSlots.size === relayCount && encryptedBlobHashes.size === relayCount) independentlyAllocated++
  }
  return independentlyAllocated
}

function localGates (input) {
  const correctnessChecks = Object.freeze({
    exactStoreCounts: input.allCountsExact,
    stableDiskBytesAcrossRestart: input.diskStable,
    noRuntimeErrors: input.noRuntimeErrors,
    allStagedWritesCompleted: input.metrics.stagedCellPut.count === input.attemptedOperations,
    allPublicReadsCompleted: input.metrics.publicCellGet.count === input.attemptedOperations &&
      input.contentChecksBeforeRestart === input.attemptedOperations,
    allRecoveredReadsCompleted: input.metrics.recoveredPublicCellGet.count === input.attemptedOperations &&
      input.contentChecksAfterRestart === input.attemptedOperations,
    restartV2WriteRecoveryObserved: input.recovery.restartV2WriteStartupQuarantineObserved === true &&
      input.recovery.restartV2WriteStartupQuarantineMillis ===
        REAL_BLIND_RELAY_MANDATORY_REPLAY_QUARANTINE_MILLIS &&
      input.recovery.restartMandatoryQuarantineAndLaunchWallMs >=
        REAL_BLIND_RELAY_MANDATORY_REPLAY_QUARANTINE_MILLIS &&
      input.recovery.restartV2WritePathReadyBeforeWrites === true &&
      input.recovery.restartV2PublicHttpsExactPutAttempts === input.relayCount &&
      input.recovery.restartV2RetainedReadChecks === input.relayCount,
    ordinaryClientQualificationSucceeded: input.ordinaryClientQualificationSucceeded,
    independentRelayIdentitiesObserved: input.uniqueRelaySigningKeys === input.relayCount,
    independentStoreIdsObserved: input.uniqueStoreIds === input.relayCount,
    independentCopiesObserved: input.allCopiesIndependentlyAllocatedAndEncrypted
  })
  const thresholds = REAL_BLIND_RELAY_LOCAL_PERFORMANCE_THRESHOLDS
  const performanceChecks = Object.freeze({
    sufficientOperationSample: input.metrics.stagedCellPut.count >= thresholds.minimumOperationsPerPath &&
      input.metrics.publicCellGet.count >= thresholds.minimumOperationsPerPath &&
      input.metrics.recoveredPublicCellGet.count >= thresholds.minimumOperationsPerPath,
    stagedPutThroughput: input.metrics.stagedCellPut.operationsPerSecond >= thresholds.stagedPutMinimumOperationsPerSecond,
    stagedPutP99: input.metrics.stagedCellPut.p99Ms <= thresholds.stagedPutMaximumP99Millis,
    publicGetThroughput: input.metrics.publicCellGet.operationsPerSecond >= thresholds.publicGetMinimumOperationsPerSecond,
    publicGetP99: input.metrics.publicCellGet.p99Ms <= thresholds.publicGetMaximumP99Millis,
    recoveredGetThroughput: input.metrics.recoveredPublicCellGet.operationsPerSecond >= thresholds.recoveredGetMinimumOperationsPerSecond,
    recoveredGetP99: input.metrics.recoveredPublicCellGet.p99Ms <= thresholds.recoveredGetMaximumP99Millis,
    restartPostQuarantineRecoveryWall: input.recovery.restartPostQuarantineRecoveryWallMs <=
      thresholds.restartPostQuarantineRecoveryMaximumWallMillis
  })
  return Object.freeze({
    correctness: Object.freeze({
      ready: Object.values(correctnessChecks).every(Boolean),
      claimClass: 'LOCAL_CORRECTNESS_ONLY',
      checks: correctnessChecks
    }),
    performance: Object.freeze({
      ready: Object.values(performanceChecks).every(Boolean),
      claimClass: 'LOCAL_LOOPBACK_SMOKE_NOT_CAPACITY_OR_SLO',
      capacityClaim: false,
      serviceLevelObjectiveClaim: false,
      thresholds,
      checks: performanceChecks
    })
  })
}

function buildReport (input) {
  const localGateReady = input.gates.correctness.ready && input.gates.performance.ready
  const report = {
    schema: REAL_BLIND_RELAY_LAB_SCHEMA,
    generatedAt: new Date().toISOString(),
    evidenceClass: 'MEASURED_LOCAL_REAL_HTTP_IPC_FILESYSTEM',
    evidenceBinding: {
      algorithm: 'sha256',
      canonicalization: REAL_BLIND_RELAY_CANONICALIZATION,
      checksumOnly: true,
      signed: false,
      authenticityProven: false
    },
    releaseReady: false,
    localGateReady,
    correctnessGateReady: input.gates.correctness.ready,
    performanceGateReady: input.gates.performance.ready,
    gates: input.gates,
    scope: {
      realImplementationsOnly: false,
      realHttpIpcWalFilesystemDataPlane: true,
      modelDataPlane: false,
      syntheticAdmissionAdapter: true,
      economicSettlementMeasured: false,
      relayInstances: input.relayCount,
      independentStoreRoots: input.relayCount,
      independentRelaySigningKeys: input.integrity.uniqueRelaySigningKeys,
      independentlyEncryptedCellCopies: input.integrity.allCopiesIndependentlyAllocatedAndEncrypted,
      networkReplicaProtocolMeasured: false,
      processIsolation: false,
      hostIsolation: false,
      transport: 'ephemeral self-signed loopback TLS plus authenticated Unix IPC',
      testFetchCertificateValidation: false,
      productionReleaseGateBypassed: true,
      sameUidTestTopology: true
    },
    load: {
      logicalRecords: input.recordsPerRelay,
      independentCellCopiesPerLogicalRecord: input.relayCount,
      replicaProtocolMeasured: false,
      attemptedCellWrites: input.relayCount * input.recordsPerRelay,
      contentBytesPerRecord: input.contentBytes,
      concurrency: input.concurrency
    },
    families: REAL_BLIND_RELAY_FAMILY_SCOPE,
    metrics: input.metrics,
    integrity: input.integrity,
    recovery: input.recovery,
    resources: input.resources,
    runtimeErrors: input.runtimeErrors,
    runtimeExclusions: input.runtimeExclusions,
    blockers: input.blockers
  }
  return sealRealBlindRelayReport(report)
}

function immutableNativeRecord (values, byteFields = {}) {
  const record = { ...values }
  for (const [field, value] of Object.entries(byteFields)) {
    const snapshot = b4a.from(value)
    Object.defineProperty(record, field, {
      enumerable: true,
      get () { return b4a.from(snapshot) }
    })
  }
  return Object.freeze(record)
}

function browserQualificationConfigFor (fixture) {
  const pins = supportPins(fixture.descriptor)
  const requirement = (familyId, operationId, requiredRoleBits) => Object.freeze({
    familyId,
    operationId,
    endpointId: 1,
    requiredRoleBits,
    privacyProfileBit: PRIVACY_PROFILE.DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  const advertisedAdmission = fixture.descriptor.admissionProfiles[0]

  return Object.freeze({
    schema: 'HiveRelayRealBlindBrowserQualificationConfigV1',
    localTestOnly: true,
    currentEpoch: fixture.currentEpoch,
    candidate: immutableNativeRecord({}, {
      canonicalUrl: fixture.descriptor.endpoints[0].canonicalUrl,
      expectedDescriptorHash: fixture.descriptorHash,
      continuityRootRelayPublicKey: fixture.relayPublicKey,
      storeId: fixture.descriptor.storeId
    }),
    // The live descriptor is sequence 1. A separate client authority must
    // accept this signed sequence-0 descriptor before it can authenticate the
    // continuation fetched from candidate.canonicalUrl. These bytes are public
    // trust material; the relay signing key never leaves createRelayFixture.
    genesis: immutableNativeRecord({}, {
      descriptorBytes: fixture.genesisDescriptorBytes,
      descriptorHash: fixture.genesisDescriptorHash
    }),
    supportedProtocolProfiles: Object.freeze(pins.supportedProtocolProfiles.map(pin =>
      immutableNativeRecord({
        protocolId: pin.protocolId,
        major: pin.major,
        minimumMinor: pin.minimumMinor
      }, { profileHash: pin.profileHash })
    )),
    supportedTransportProfiles: Object.freeze(pins.supportedTransportProfiles.map(pin =>
      immutableNativeRecord({
        transportId: pin.transportId,
        transportSupportBit: pin.transportSupportBit
      }, { transportProfileHash: pin.transportProfileHash })
    )),
    cellPutRequirement: requirement(
      FAMILY.CELL,
      OPERATION.CELL.PUT,
      ENDPOINT_ROLE.STORAGE
    ),
    cellGetRequirement: requirement(
      FAMILY.CELL,
      OPERATION.CELL.GET,
      ENDPOINT_ROLE.STORAGE
    ),
    admissionParametersRequirement: requirement(
      FAMILY.DESCRIBE,
      OPERATION.DESCRIBE.ADMISSION_PARAMETERS,
      ENDPOINT_ROLE.QUOTA_REDEEMER
    ),
    advertisedAdmissionProfile: immutableNativeRecord({
      profileId: advertisedAdmission.profileId,
      schemeId: advertisedAdmission.schemeId,
      conformanceClass: advertisedAdmission.conformanceClass,
      roleBits: advertisedAdmission.roleBits,
      ...(advertisedAdmission.parameterUrl == null ? { parameterUrl: null } : {})
    }, {
      parameterHash: advertisedAdmission.parameterHash,
      ...(advertisedAdmission.parameterUrl == null
        ? {}
        : { parameterUrl: advertisedAdmission.parameterUrl })
    })
  })
}

// Narrow cross-repository fixture for consumers such as Peerit.  The caller
// supplies the exact client authority it ships, so opaque VerifiedEndpoint
// brands are minted and consumed by one module instance rather than being
// substituted with this checkout's source client.  This is intentionally a
// local test surface: it uses synthetic admission and never asserts a
// production operator, deployment, or economic-settlement claim.
export async function createRealBlindRelayTestFixture (options = {}) {
  if (typeof process.getuid !== 'function' || typeof process.getgid !== 'function') {
    fail('real relay fixture requires POSIX Unix sockets and peer credentials')
  }
  const keep = options.keep === true
  const root = options.root == null
    ? await fs.mkdtemp(path.join(await fs.realpath('/tmp'), 'brfixture-'))
    : await fs.realpath(options.root)
  const authorityBytes = await fs.readFile(STORE_FORMAT_AUTHORITY)
  const tls = await ephemeralLoopbackTls(root)
  const fixture = await createRelayFixture(
    root,
    boundedInteger(options.relayIndex, 0, 0, 255, 'relayIndex'),
    await unusedLoopbackPort(),
    authorityBytes,
    tls
  )
  let relay = null
  let closed = false
  let dropNextPutResponse = false
  let droppedPutResponses = 0
  let admissionCounter = 0
  const relayRuns = []

  const testHooks = Object.freeze({
    beforeResponseFirstByte ({ family, response, result }) {
      if (!dropNextPutResponse || family !== FAMILY.CELL) return
      const outer = decodeOuterEnvelope(result, { copyInner: true, copyBody: true })
      if (outer.frame.frameKind !== FRAME_KIND.RESPONSE ||
          outer.frame.familyId !== FAMILY.CELL ||
          outer.frame.operationId !== OPERATION.CELL.PUT) return
      dropNextPutResponse = false
      droppedPutResponses++
      // The daemon has already returned the committed result.  Closing the
      // public socket here models response loss at the only useful boundary:
      // after durable mutation, before the client receives one response byte.
      response.destroy()
    }
  })

  const launch = async phase => {
    relay = await startRelay(fixture, {
      allowInsecureLoopback: true,
      testHooks
    })
    relayRuns.push(relay)
    await waitForV2WriteReadiness([relay], phase)
  }

  try {
    await launch('joint fixture start')
  } catch (error) {
    if (relay) await stopRelay(relay).catch(() => {})
    if (!keep) await fs.rm(root, { recursive: true, force: true })
    throw error
  }

  const api = Object.freeze({
    root,
    currentEpoch: fixture.currentEpoch,
    get relayPublicKey () { return b4a.from(fixture.relayPublicKey) },
    fetch: localTlsFetch,
    browserQualificationConfig () {
      if (closed || !relay) fail('real relay fixture is not running')
      return browserQualificationConfigFor(fixture)
    },
    async admissionProvider () {
      if (closed) fail('real relay fixture is closed')
      return Object.freeze({
        profileId: fixture.descriptor.admissionProfiles[0].profileId,
        schemeId: fixture.descriptor.admissionProfiles[0].schemeId,
        parameterHash: b4a.from(fixture.parameterHash),
        token: deterministicBytes(`joint-fixture:${fixture.relayIndex}:admission:${admissionCounter++}`, 32)
      })
    },
    async qualifyCellPair (clientApi, clientRuntime) {
      if (closed || !relay) fail('real relay fixture is not running')
      const put = await qualifyWithApi(
        relay,
        clientRuntime,
        FAMILY.CELL,
        OPERATION.CELL.PUT,
        'joint-put',
        clientApi
      )
      const get = await qualifyWithApi(
        relay,
        clientRuntime,
        FAMILY.CELL,
        OPERATION.CELL.GET,
        'joint-get',
        clientApi
      )
      if (!put.qualified || !get.qualified) {
        fail(`joint fixture qualification failed: PUT=${put.code || 'UNKNOWN'} GET=${get.code || 'UNKNOWN'}`)
      }
      return Object.freeze({
        putEndpoint: put.endpoint,
        getEndpoint: get.endpoint,
        putContext: clientApi.verifiedEndpointContext(put.endpoint),
        getContext: clientApi.verifiedEndpointContext(get.endpoint)
      })
    },
    dropNextCellPutResponse () {
      if (closed || !relay) fail('real relay fixture is not running')
      if (dropNextPutResponse) fail('a CELL.PUT response drop is already armed')
      dropNextPutResponse = true
    },
    droppedCellPutResponses () {
      return droppedPutResponses
    },
    status () {
      if (closed || !relay) fail('real relay fixture is not running')
      return relay.runtime.status()
    },
    errors () {
      return relayRuns.flatMap(run => run.errors).map(error => Object.freeze({
        code: error && error.code ? String(error.code) : null,
        message: error && error.message ? String(error.message) : String(error)
      }))
    },
    async restart () {
      if (closed || !relay) fail('real relay fixture is not running')
      if (dropNextPutResponse) fail('armed CELL.PUT response drop was not exercised before restart')
      const current = relay
      relay = null
      await stopRelay(current)
      await launch('joint fixture restart')
    },
    async close () {
      if (closed) return
      closed = true
      const current = relay
      relay = null
      if (current) await stopRelay(current).catch(() => {})
      if (!keep) await fs.rm(root, { recursive: true, force: true })
    }
  })
  return api
}

export async function runRealBlindRelayLab (options = {}) {
  return runRealBlindRelayLabInternal(options)
}

export async function runScopedRealBlindRelayLab (options = {}) {
  const identityScope = normalizeIdentityScope(options.identityScope, true)
  let identities = null
  const report = await runRealBlindRelayLabInternal(
    { ...options, identityScope },
    value => { identities = value }
  )
  if (identities == null) fail('scoped real relay lab did not expose its actual relay identities')
  return Object.freeze({ report, identities })
}

async function runRealBlindRelayLabInternal (options = {}, observeIdentities = null) {
  if (typeof process.getuid !== 'function' || typeof process.getgid !== 'function') {
    fail('real relay lab requires POSIX Unix sockets and peer credentials')
  }
  const identityScope = normalizeIdentityScope(options.identityScope)
  const relayCount = boundedInteger(options.relayCount, DEFAULTS.relayCount, 2, 8, 'relayCount')
  const recordsPerRelay = boundedInteger(
    options.recordsPerRelay,
    DEFAULTS.recordsPerRelay,
    1,
    250_000,
    'recordsPerRelay'
  )
  const concurrency = boundedInteger(options.concurrency, DEFAULTS.concurrency, 1, 128, 'concurrency')
  const contentBytes = boundedInteger(options.contentBytes, DEFAULTS.contentBytes, 32, 4000, 'contentBytes')
  const keep = options.keep === true
  const root = options.root == null
    ? await fs.mkdtemp(path.join(await fs.realpath('/tmp'), 'brlab-'))
    : await fs.realpath(options.root)
  const rssBefore = process.memoryUsage().rss
  const authorityBytes = await fs.readFile(STORE_FORMAT_AUTHORITY)
  const tls = await ephemeralLoopbackTls(root)
  const ports = []
  const fixtures = []
  let relays = []
  const relayRuns = []
  let report
  try {
    for (let index = 0; index < relayCount; index++) {
      ports.push(await unusedLoopbackPort())
      fixtures.push(await createRelayFixture(
        root,
        index,
        ports[index],
        authorityBytes,
        tls,
        identityScope
      ))
    }
    if (observeIdentities) {
      observeIdentities(Object.freeze({
        identityScope,
        relays: Object.freeze(fixtures.map(fixture => Object.freeze({
          relayIndex: fixture.relayIndex,
          relayPublicKey: b4a.toString(fixture.relayPublicKey, 'hex'),
          storeId: b4a.toString(fixture.descriptor.storeId, 'hex')
        })))
      }))
    }
    relays = await Promise.all(fixtures.map(startRelay))
    relayRuns.push(...relays)
    const initialV2WriteReadiness = await waitForV2WriteReadiness(relays, 'initial relay start')

    const clientRuntimes = fixtures.map(fixture => deterministicRuntime(scopedDeterministicLabel(
      identityScope,
      `client-${fixture.relayIndex}`
    )))
    const qualificationLatencies = []
    const qualificationResults = []
    const initialGetEndpoints = []
    for (let index = 0; index < relays.length; index++) {
      const put = await qualify(
        relays[index], clientRuntimes[index], FAMILY.CELL, OPERATION.CELL.PUT, 'initial-put')
      const get = await qualify(
        relays[index], clientRuntimes[index], FAMILY.CELL, OPERATION.CELL.GET, 'initial-get')
      if (!put.qualified || !get.qualified) fail('ordinary CELL client qualification did not succeed')
      qualificationLatencies.push(put.latencyMs, get.latencyMs)
      qualificationResults.push(put, get)
      initialGetEndpoints.push(get.endpoint)
    }

    const work = []
    for (let relayIndex = 0; relayIndex < relayCount; relayIndex++) {
      for (let recordIndex = 0; recordIndex < recordsPerRelay; recordIndex++) {
        work.push(Object.freeze({ relayIndex, recordIndex }))
      }
    }
    const writePhaseStarted = process.hrtime.bigint()
    const records = await mapConcurrent(work, concurrency, async item => {
      const relay = relays[item.relayIndex]
      const content = logicalContent(item.recordIndex, contentBytes)
      const created = await createCellReplica({
        runtime: clientRuntimes[item.relayIndex],
        relayPublicKey: relay.fixture.relayPublicKey,
        allocationEpoch: relay.fixture.currentEpoch,
        sizeClass: 1,
        leaseClass: 1,
        structuredContent: content,
        clientNonce: deterministicBytes(scopedDeterministicLabel(
          identityScope,
          `relay-${item.relayIndex}:record-${item.recordIndex}:create`
        ), 32),
        admission: admissionFor(relay.fixture, item.recordIndex)
      })
      const write = await putViaAuthenticatedStagedPath(
        relay,
        created,
        item.recordIndex
      )
      return Object.freeze({ ...item, content, created, write })
    })
    const writePhaseMs = elapsedMillis(writePhaseStarted)
    const writeLatencies = records.map(record => record.write.latencyMs)
    const beforeRestartCounts = exactStoreCounts(relays, recordsPerRelay)
    const rssAfterWrite = process.memoryUsage().rss

    const readPhaseStarted = process.hrtime.bigint()
    const readLatencies = await mapConcurrent(records, concurrency, record => getViaPublicEdge(
      relays[record.relayIndex],
      clientRuntimes[record.relayIndex],
      initialGetEndpoints[record.relayIndex],
      record,
      'before-restart'
    ))
    const readPhaseMs = elapsedMillis(readPhaseStarted)
    const diskBeforeRestart = await Promise.all(fixtures.map(fixture => directoryUsage(fixture.storeRoot)))

    const stopStarted = process.hrtime.bigint()
    await Promise.all(relays.map(stopRelay))
    const stopMs = elapsedMillis(stopStarted)
    relays = []
    const restartRecoveryStarted = process.hrtime.bigint()
    relays = await Promise.all(fixtures.map(startRelay))
    relayRuns.push(...relays)
    // A restart must not merely enter the replay-journal quarantine. It must
    // leave it, accept a real exporter-bound public V2 attempt, and then serve
    // the retained content without changing the exact per-relay store count.
    const restartV2WriteReadiness = await waitForV2WriteReadiness(relays, 'relay restart')
    // The mandatory replay quarantine is correctness evidence, not work the
    // local performance budget can make faster.  Budget only the qualification,
    // exact retry, and retained readback work that begins after readiness.
    const restartPostQuarantineRecoveryStarted = process.hrtime.bigint()
    const recoveredGetEndpoints = []
    for (let index = 0; index < relays.length; index++) {
      const get = await qualify(
        relays[index], clientRuntimes[index], FAMILY.CELL, OPERATION.CELL.GET, 'recovered-get')
      if (!get.qualified) fail('ordinary recovered CELL.GET client qualification did not succeed')
      qualificationLatencies.push(get.latencyMs)
      qualificationResults.push(get)
      recoveredGetEndpoints.push(get.endpoint)
    }
    const restartProbeRecords = records.filter(record => record.recordIndex === 0)
    if (restartProbeRecords.length !== relayCount) {
      fail('restart V2 probe requires one exact retained CELL.PUT per relay')
    }
    await mapConcurrent(restartProbeRecords, concurrency, record => putViaAuthenticatedStagedPath(
      relays[record.relayIndex], record.created, record.recordIndex
    ))
    const restartV2RetainedReadLatencies = await mapConcurrent(
      restartProbeRecords,
      concurrency,
      record => getViaPublicEdge(
        relays[record.relayIndex],
        clientRuntimes[record.relayIndex],
        recoveredGetEndpoints[record.relayIndex],
        record,
        'after-restart-v2-exact-put'
      )
    )
    const afterRestartCounts = exactStoreCounts(relays, recordsPerRelay)
    const recoveryReadStarted = process.hrtime.bigint()
    const recoveryReadLatencies = await mapConcurrent(records, concurrency, record => getViaPublicEdge(
      relays[record.relayIndex],
      clientRuntimes[record.relayIndex],
      recoveredGetEndpoints[record.relayIndex],
      record,
      'after-restart'
    ))
    const recoveryReadMs = elapsedMillis(recoveryReadStarted)
    const restartRecoveryFinished = process.hrtime.bigint()
    const restartAndRecoveryMs = elapsedMillis(restartRecoveryStarted, restartRecoveryFinished)
    const restartMandatoryQuarantineAndLaunchMs = elapsedMillis(
      restartRecoveryStarted,
      restartPostQuarantineRecoveryStarted
    )
    const restartPostQuarantineRecoveryMs = elapsedMillis(
      restartPostQuarantineRecoveryStarted,
      restartRecoveryFinished
    )
    const diskAfterRestart = await Promise.all(fixtures.map(fixture => directoryUsage(fixture.storeRoot)))
    const rssAfterRestart = process.memoryUsage().rss

    const allCountsExact = [...beforeRestartCounts, ...afterRestartCounts].every(value => value.exact)
    const diskStable = diskAfterRestart.every((value, index) => value.bytes === diskBeforeRestart[index].bytes)
    const runtimeErrors = relayRuns.flatMap(relay => relay.errors).map(error => Object.freeze({
      code: error && error.code ? String(error.code) : null,
      message: error && error.message ? String(error.message) : String(error)
    }))
    const noRuntimeErrors = runtimeErrors.length === 0
    const ordinaryClientQualificationSucceeded = qualificationResults.every(result =>
      result.qualified === true && result.code === null && result.message === null)
    const writeOpsPerSecond = work.length / (writePhaseMs / 1000)
    const readOpsPerSecond = work.length / (readPhaseMs / 1000)
    const recoveryReadOpsPerSecond = work.length / (recoveryReadMs / 1000)
    const metrics = Object.freeze({
      qualification: latencySummary(qualificationLatencies),
      stagedCellPut: Object.freeze({
        ...latencySummary(writeLatencies),
        wallMs: Number(writePhaseMs.toFixed(3)),
        operationsPerSecond: Number(writeOpsPerSecond.toFixed(3))
      }),
      publicCellGet: Object.freeze({
        ...latencySummary(readLatencies),
        wallMs: Number(readPhaseMs.toFixed(3)),
        operationsPerSecond: Number(readOpsPerSecond.toFixed(3))
      }),
      recoveredPublicCellGet: Object.freeze({
        ...latencySummary(recoveryReadLatencies),
        wallMs: Number(recoveryReadMs.toFixed(3)),
        operationsPerSecond: Number(recoveryReadOpsPerSecond.toFixed(3))
      })
    })
    const independentlyAllocatedLogicalRecords = independentlyAllocatedCopyCount(
      records,
      relayCount,
      recordsPerRelay
    )
    const allCopiesIndependentlyAllocatedAndEncrypted = independentlyAllocatedLogicalRecords === recordsPerRelay
    const uniqueRelaySigningKeys = uniqueHexCount(fixtures.map(fixture => fixture.relayPublicKey))
    const uniqueStoreIds = uniqueHexCount(fixtures.map(fixture => fixture.descriptor.storeId))
    const recovery = Object.freeze({
      relaysStopped: relayCount,
      relaysRestarted: relayCount,
      cleanStopWallMs: Number(stopMs.toFixed(3)),
      restartAndRecoveryWallMs: Number(restartAndRecoveryMs.toFixed(3)),
      restartMandatoryQuarantineAndLaunchWallMs:
        Number(restartMandatoryQuarantineAndLaunchMs.toFixed(3)),
      restartPostQuarantineRecoveryWallMs: Number(restartPostQuarantineRecoveryMs.toFixed(3)),
      retainedStateReadChecks: recoveryReadLatencies.length,
      diskBytesStableAcrossRestart: diskStable,
      initialV2WriteStartupQuarantineObserved: initialV2WriteReadiness.startupQuarantineObserved,
      initialV2WritePathReadyBeforeWrites: initialV2WriteReadiness.readyBeforeWrites,
      initialV2WriteReadinessWaitMs: initialV2WriteReadiness.waitMs,
      restartV2WriteStartupQuarantineObserved: restartV2WriteReadiness.startupQuarantineObserved,
      restartV2WriteStartupQuarantineMillis: restartV2WriteReadiness.startupQuarantineMillis,
      restartV2WritePathReadyBeforeWrites: restartV2WriteReadiness.readyBeforeWrites,
      restartV2WriteReadinessWaitMs: restartV2WriteReadiness.waitMs,
      restartV2PublicHttpsExactPutAttempts: restartProbeRecords.length,
      restartV2RetainedReadChecks: restartV2RetainedReadLatencies.length
    })
    const gates = localGates({
      allCountsExact,
      diskStable,
      noRuntimeErrors,
      ordinaryClientQualificationSucceeded,
      allCopiesIndependentlyAllocatedAndEncrypted,
      uniqueRelaySigningKeys,
      uniqueStoreIds,
      relayCount,
      attemptedOperations: work.length,
      contentChecksBeforeRestart: readLatencies.length,
      contentChecksAfterRestart: recoveryReadLatencies.length,
      metrics,
      recovery
    })
    const runtimeExclusions = [...new Set(relays.flatMap(relay => relay.runtime.status().exclusions || []))].sort()
    const blockers = realBlindRelayExpectedBlockers({
      correctnessReady: gates.correctness.ready,
      performanceReady: gates.performance.ready
    })

    report = buildReport({
      relayCount,
      recordsPerRelay,
      concurrency,
      contentBytes,
      gates,
      metrics,
      integrity: Object.freeze({
        contentChecksBeforeRestart: readLatencies.length,
        contentChecksAfterRestart: recoveryReadLatencies.length,
        exactStoreCountsBeforeRestart: beforeRestartCounts,
        exactStoreCountsAfterRestart: afterRestartCounts,
        allCountsExact,
        uniqueRelaySigningKeys,
        uniqueStoreIds,
        deterministicLogicalCorpus: true,
        independentlyAllocatedLogicalRecords,
        allCopiesIndependentlyAllocatedAndEncrypted,
        replicaProtocolMeasured: false,
        ordinaryClientQualificationSucceeded,
        qualificationAttempts: qualificationResults.map(result => Object.freeze({
          relayIndex: result.relayIndex,
          phase: result.phase,
          qualified: result.qualified,
          code: result.code,
          message: result.message
        }))
      }),
      recovery,
      resources: Object.freeze({
        processRssBytesBefore: rssBefore,
        processRssBytesAfterWrite: rssAfterWrite,
        processRssBytesAfterRestart: rssAfterRestart,
        processRssDeltaBytes: rssAfterRestart - rssBefore,
        perRelayRssUnavailableReason: 'RELAYS_SHARE_ONE_NODE_PROCESS',
        storesBeforeRestart: diskBeforeRestart.map((usage, relayIndex) => Object.freeze({ relayIndex, ...usage })),
        storesAfterRestart: diskAfterRestart.map((usage, relayIndex) => Object.freeze({ relayIndex, ...usage })),
        aggregateStoredPayloadBytes: beforeRestartCounts.reduce((sum, row) => sum + row.storedBytes, 0)
      }),
      runtimeErrors,
      runtimeExclusions,
      blockers
    })
    verifyRealBlindRelayReport(report)
    return report
  } finally {
    await Promise.all(relays.map(relay => stopRelay(relay).catch(() => {})))
    if (!keep) await fs.rm(root, { recursive: true, force: true })
  }
}

function parseCli (argv) {
  const options = {}
  for (let index = 0; index < argv.length; index++) {
    const value = argv[index]
    if (value === '--relays') options.relayCount = Number(argv[++index])
    else if (value === '--records') options.recordsPerRelay = Number(argv[++index])
    else if (value === '--concurrency') options.concurrency = Number(argv[++index])
    else if (value === '--content-bytes') options.contentBytes = Number(argv[++index])
    else if (value === '--output') options.output = argv[++index]
    else if (value === '--pretty') options.pretty = true
    else if (value === '--assert-local') options.assertLocal = true
    else if (value === '--assert-correctness') options.assertCorrectness = true
    else if (value === '--assert-performance') options.assertPerformance = true
    else if (value === '--keep') options.keep = true
    else fail(`unknown argument ${value}`)
  }
  return options
}

async function main () {
  const cli = parseCli(process.argv.slice(2))
  const report = await runRealBlindRelayLab(cli)
  const json = JSON.stringify(report, null, cli.pretty ? 2 : 0) + '\n'
  if (cli.output) await fs.writeFile(cli.output, json)
  else process.stdout.write(json)
  if (cli.assertLocal && !report.localGateReady) process.exitCode = 1
  if (cli.assertCorrectness && !report.correctnessGateReady) process.exitCode = 1
  if (cli.assertPerformance && !report.performanceGateReady) process.exitCode = 1
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] || '')) {
  main().catch(error => {
    process.stderr.write(`[blind-real-relay-lab] ${error.code || 'ERROR'}: ${error.message}\n`)
    process.exitCode = 1
  })
}
