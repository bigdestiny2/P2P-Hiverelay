// Shared integration fixture for the vNext direct-HTTPS runtime tests.
// Builds one full relay: descriptor chain (genesis + one successor), signed
// admission parameters, the accepted production unary assembly, the accepted
// forward storage authority, and the vNext public edge over real peercred IPC.
// TLS key material is generated with the platform openssl binary when present
// (real exporter sockets); plaintext loopback is used only through the
// explicit allowInsecureLoopback test seam. Environment boundaries that this
// macOS host cannot provide (Linux SO_PEERCRED, Chromium/IndexedDB, Bare) are
// recorded in the lane evidence, never faked.

import { execFile } from 'node:child_process'
import fs from 'node:fs/promises'
import http from 'node:http'
import https from 'node:https'
import path from 'node:path'
import { promisify } from 'node:util'
import { pathToFileURL } from 'node:url'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ENDPOINT_ROLE,
  FAMILY,
  INBOX_FRAME_CLASS,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  admissionParametersV1,
  blindServiceDescriptorV1,
  blake2b256,
  decodeCanonical,
  encodeCanonical,
  hashStoreFormat,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import {
  PRODUCTION_DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS,
  loadProductionRuntimeConfig
} from '../../blind-daemon/production-runtime.js'
import { loadDaemonBootstrapConfig } from '../../blind-daemon/bootstrap-config.js'
import { daemonOperationProfile, deriveAdmissionCost } from '../../blind-daemon/operation-catalog.js'
import { assembleForwardHttpsRelayVnext } from '../../blind-daemon/forward-https-runtime-vnext.js'
import { PRIVATE_IPC_V4_STATUS } from '@hiverelay/blind-ipc'
import { ForwardHttpsEdgeVnext } from '../forward-https-vnext.js'
import {
  bindDurability,
  descriptorValue,
  parameterValue
} from '../../blind-daemon/test/coordinator-fixtures.js'
import { createBlindBoundaryScratch } from '../../../test/blind-boundary-scratch.js'

const execFileAsync = promisify(execFile)
const SIX_HOURS_MILLIS = 6 * 60 * 60 * 1000
export const RELAY_PUBLIC_ROLE_BITS = ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY |
  ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER

export const FIXTURE_TEST_SHAPE = Object.freeze({
  cellSizeClass: 1,
  inboxFrameClassBits: 1,
  inboxRetentionClass: 2,
  inboxCreateLeaseClass: 2,
  inboxRenewLeaseClass: 4,
  inboxAppendFrameClass: 1,
  inboxPageLimit: 1,
  inboxWatchMaxWaitMillis: 1000,
  coreMirrorLeaseClass: 1,
  coreMirrorLength: 4n
})

export function signCanonicalFixture (codec, value, domainId, secretKey) {
  value.signature = b4a.alloc(sodium.crypto_sign_BYTES)
  const placeholder = encodeCanonical(codec, value)
  const unsigned = placeholder.subarray(0, placeholder.byteLength - sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(value.signature, resultSignaturePayload(domainId, unsigned), secretKey)
  return encodeCanonical(codec, value)
}

async function privateFile (file, bytes) {
  await fs.writeFile(file, bytes, { mode: 0o600 })
  await fs.chmod(file, 0o600)
}

function inboxResourceCostRows () {
  const shape = FIXTURE_TEST_SHAPE
  const largestFrameBytes = INBOX_FRAME_CLASS[shape.inboxFrameClassBits]
  const predictedReadBytes = 4096 + shape.inboxPageLimit * (41 + largestFrameBytes)
  const storedShape = Object.freeze({
    inboxRetentionClass: shape.inboxRetentionClass,
    inboxFrameClassBits: shape.inboxFrameClassBits
  })
  const costs = [
    deriveAdmissionCost(daemonOperationProfile(FAMILY.INBOX, OPERATION.INBOX.CREATE), {
      retentionClass: shape.inboxRetentionClass,
      frameClassBits: shape.inboxFrameClassBits,
      leaseClass: shape.inboxCreateLeaseClass
    }),
    deriveAdmissionCost(daemonOperationProfile(FAMILY.INBOX, OPERATION.INBOX.RENEW), {
      leaseClass: shape.inboxRenewLeaseClass
    }, storedShape),
    deriveAdmissionCost(daemonOperationProfile(FAMILY.INBOX, OPERATION.INBOX.APPEND), {
      frameClass: shape.inboxAppendFrameClass
    }, storedShape),
    deriveAdmissionCost(daemonOperationProfile(FAMILY.INBOX, OPERATION.INBOX.READ), {}, {
      canonicalResultBytes: predictedReadBytes
    }),
    deriveAdmissionCost(daemonOperationProfile(FAMILY.INBOX, OPERATION.INBOX.WATCH), {
      maxWaitMillis: shape.inboxWatchMaxWaitMillis
    }, { canonicalResultBytes: predictedReadBytes })
  ]
  return costs.map((cost, index) => Object.freeze({
    familyId: FAMILY.INBOX,
    operationId: index === 0
      ? OPERATION.INBOX.CREATE
      : index === 1
        ? OPERATION.INBOX.RENEW
        : index === 2
          ? OPERATION.INBOX.APPEND
          : index === 3
            ? OPERATION.INBOX.READ
            : OPERATION.INBOX.WATCH,
    resourceClass: cost.resourceClass,
    leaseClass: cost.leaseClass,
    costUnits: 10n
  }))
}

export function splitAdmissionAdapterFixture () {
  const preflights = new WeakSet()
  const prepared = input => ({
    spendTag: blake2b256(input.admission.token),
    requestCommitment: input.requestCommitment,
    costClass: input.costClass,
    walCommitRecord: input.admission.token,
    profileId: input.admission.profileId,
    schemeId: input.admission.schemeId,
    parameterHash: input.admission.parameterHash
  })
  return Object.freeze({
    async prepare (input) { return prepared(input) },
    async preparePreflight () {
      const authority = Object.freeze({})
      preflights.add(authority)
      return authority
    },
    async confirmAfterEof (input) {
      if (!preflights.has(input.adapterPreflight)) throw new Error('unknown admission preflight')
      preflights.delete(input.adapterPreflight)
      return prepared(input)
    }
  })
}

// One signed relay identity: a two-descriptor chain (genesis 0, successor 1)
// plus the signed admission parameters for the full 17-operation baseline.
export async function createRelayIdentityFixture (options = {}) {
  const relayPublicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const relaySecretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(relayPublicKey, relaySecretKey)
  const currentEpoch = Math.floor(Date.now() / SIX_HOURS_MILLIS)

  const parameters = parameterValue(relayPublicKey, {
    roleBits: RELAY_PUBLIC_ROLE_BITS,
    validFromEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4
  })
  parameters.resourceCosts = [...parameters.resourceCosts, ...inboxResourceCostRows()]
    .sort((left, right) => {
      for (const field of ['familyId', 'operationId', 'resourceClass', 'leaseClass']) {
        if (left[field] !== right[field]) return left[field] - right[field]
      }
      return 0
    })
  const canonicalParameters = signCanonicalFixture(admissionParametersV1, parameters,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, relaySecretKey)
  const parameterHash = admissionParametersHash(canonicalParameters)

  const descriptor = descriptorValue({
    relayPublicKey: b4a.from(relayPublicKey),
    storeId: options.storeId || b4a.alloc(32, 0x62),
    enabledOperationBits: PRODUCTION_DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS,
    issuedEpoch: currentEpoch - 1,
    expiresEpoch: currentEpoch + 3,
    capacityBand: 0
  })
  descriptor.endpoints = [descriptor.endpoints[0]]
  descriptor.endpoints[0].endpointId = 1
  descriptor.endpoints[0].transportId = 1
  descriptor.endpoints[0].roleBits = RELAY_PUBLIC_ROLE_BITS
  descriptor.protocols = [1, 2, 3, 4].map(protocolId => ({ ...descriptor.protocols[0], protocolId }))
  if (options.port != null) {
    descriptor.endpoints[0].canonicalUrl = b4a.from(`https://127.0.0.1:${options.port}/api/blind/v1/describe`, 'utf8')
  }
  descriptor.admissionProfiles = [descriptor.admissionProfiles[0]]
  descriptor.admissionProfiles[0].profileId = parameters.profileId
  descriptor.admissionProfiles[0].schemeId = parameters.schemeId
  descriptor.admissionProfiles[0].conformanceClass = parameters.conformanceClass
  descriptor.admissionProfiles[0].roleBits = parameters.roleBits
  descriptor.admissionProfiles[0].parameterHash = b4a.from(parameterHash)
  const authorityBytes = await fs.readFile(new URL(
    '../../blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc',
    import.meta.url
  ))
  descriptor.durability.storeFormatMajor = 1
  descriptor.durability.storeFormatMinor = 2
  descriptor.durability.storeFormatHash = hashStoreFormat(authorityBytes)
  descriptor.build.storeFormatHash = b4a.from(descriptor.durability.storeFormatHash)
  bindDurability(descriptor)
  const genesisBytes = signCanonicalFixture(blindServiceDescriptorV1, descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)

  const successor = decodeCanonical(blindServiceDescriptorV1, genesisBytes, { copyBytes: true })
  successor.descriptorSequence = 1n
  successor.previousDescriptorHash = serviceDescriptorHash(genesisBytes)
  successor.issuedEpoch = currentEpoch
  successor.expiresEpoch = currentEpoch + 4
  successor.descriptorNonce = b4a.alloc(32, 0x64)
  const successorBytes = signCanonicalFixture(blindServiceDescriptorV1, successor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)

  return Object.freeze({
    relayPublicKey,
    relaySecretKey,
    currentEpoch,
    canonicalParameters,
    parameterHash,
    genesisBytes,
    successorBytes,
    genesisHash: serviceDescriptorHash(genesisBytes),
    successorHash: serviceDescriptorHash(successorBytes),
    descriptor: successor
  })
}

// Materialize one relay's launch environment under a contained scratch root.
// Unix socket paths live under the short POSIX /tmp root: the portable
// <=100-byte socket path bound cannot be met inside this run's deep checkout
// (a pre-existing environment limitation of every boundary test here, noted
// in the lane evidence). The tmp root is real (no symlink ancestors) and is
// removed by removeFixtureScratch.
export async function createRelayEnvironmentFixture (identity, options = {}) {
  const directory = options.directory || await createBlindBoundaryScratch(options.prefix || 'fhv-')
  await fs.chmod(directory, 0o700)
  const socketDirectory = await fs.mkdtemp(path.join(await fs.realpath('/tmp'), 'fhv-'))
  await fs.chmod(socketDirectory, 0o700)
  const roots = {}
  for (const name of ['store', 'inbox-store', 'core-store', 'private-ipc-replay', 'forward-storage']) {
    roots[name] = path.join(directory, name)
    await fs.mkdir(roots[name], { mode: 0o700, recursive: true })
  }
  const descriptorFile = path.join(directory, 'descriptor.bin')
  const successorDescriptorFile = path.join(directory, 'descriptor-successor.bin')
  const parametersFile = path.join(directory, 'admission.bin')
  const secretKeyFile = path.join(directory, 'relay-secret.bin')
  const storeManifestKeyFile = path.join(directory, 'store-manifest-key.bin')
  const ownerFenceFile = path.join(directory, 'owner-fence-hash.bin')
  const inboxCursorKeyFile = path.join(directory, 'inbox-cursor-key.bin')
  const forwardManifestKeyFile = path.join(directory, 'forward-manifest-key.bin')
  const forwardAtRestKeyFile = path.join(directory, 'forward-atrest-key.bin')
  await Promise.all([
    privateFile(descriptorFile, identity.genesisBytes),
    privateFile(successorDescriptorFile, identity.successorBytes),
    privateFile(parametersFile, identity.canonicalParameters),
    privateFile(secretKeyFile, identity.relaySecretKey),
    privateFile(storeManifestKeyFile, b4a.alloc(32, 0x71)),
    privateFile(ownerFenceFile, b4a.alloc(32, 0x72)),
    privateFile(inboxCursorKeyFile, b4a.alloc(32, 0x73)),
    privateFile(forwardManifestKeyFile, b4a.alloc(32, 0x74)),
    privateFile(forwardAtRestKeyFile, b4a.alloc(32, 0x75))
  ])
  const uid = process.getuid()
  const gid = process.getgid()
  const edgeUid = uid === 0xffffffff ? uid - 1 : uid + 1
  const launchTopologyHash = options.launchTopologyHash || b4a.from('81'.repeat(32), 'hex')
  const environment = {
    ...process.env,
    HIVERELAY_BLIND_UNARY_SOCKET: path.join(socketDirectory, 'unary.sock'),
    HIVERELAY_BLIND_STREAM_SOCKET: path.join(socketDirectory, 'stream.sock'),
    HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: b4a.toString(launchTopologyHash, 'hex'),
    HIVERELAY_BLIND_ENDPOINT_IDS: '1',
    HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS: `1:${TRANSPORT_SUPPORT.DIRECT_HTTP}`,
    HIVERELAY_BLIND_EDGE_UID: String(edgeUid),
    HIVERELAY_BLIND_DAEMON_UID: String(uid),
    HIVERELAY_BLIND_DAEMON_GID: String(gid),
    HIVERELAY_BLIND_SHARED_GID: String(gid),
    HIVERELAY_BLIND_DESCRIPTOR_FILES: `${descriptorFile},${successorDescriptorFile}`,
    HIVERELAY_BLIND_ADMISSION_PARAMETER_FILES: parametersFile,
    HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE: secretKeyFile,
    HIVERELAY_BLIND_STORE_ROOT: roots.store,
    HIVERELAY_BLIND_PRIVATE_IPC_REPLAY_ROOT: roots['private-ipc-replay'],
    HIVERELAY_BLIND_INBOX_STORE_ROOT: roots['inbox-store'],
    HIVERELAY_BLIND_INBOX_CURSOR_KEY_FILE: inboxCursorKeyFile,
    HIVERELAY_BLIND_CORE_STORE_ROOT: roots['core-store'],
    HIVERELAY_BLIND_STORE_MANIFEST_KEY_FILE: storeManifestKeyFile,
    HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE: ownerFenceFile,
    HIVERELAY_BLIND_MAP_GENERATION: '1',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE: '1',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: b4a.toString(identity.successorHash, 'hex')
  }
  return Object.freeze({
    directory,
    socketDirectory,
    environment,
    roots,
    launchTopologyHash,
    descriptorFile,
    successorDescriptorFile,
    parametersFile,
    secretKeyFile,
    forwardManifestKeyFile,
    forwardAtRestKeyFile
  })
}

export async function readSecretFile (file, length) {
  const bytes = b4a.from(await fs.readFile(file))
  if (bytes.byteLength !== length) throw new Error(`${file} must be exactly ${length} bytes`)
  return bytes
}

export const PINNED_WIRE_V3_ABI_HASH = b4a.from(PRIVATE_IPC_V4_STATUS.importedWireV3AbiHash, 'hex')
export const PINNED_PRIVATE_IPC_V4_FORMAT_HASH = b4a.from(PRIVATE_IPC_V4_STATUS.privateIpcFormatHash, 'hex')
export const PINNED_LAUNCH_TOPOLOGY_HASH = b4a.from('81'.repeat(32), 'hex')

// Assemble the full vNext relay (unary + forward runtimes) on the accepted base.
export async function assembleRelayFixture (identity, layout, forward = {}) {
  const bootstrap = loadDaemonBootstrapConfig(layout.environment)
  const localPeerBootstrap = Object.freeze({ ...bootstrap, expectedPeerUid: process.getuid() })
  const runtimeConfig = loadProductionRuntimeConfig(layout.environment, bootstrap.endpointIds)
  const manifestKey = await readSecretFile(layout.forwardManifestKeyFile, 32)
  const atRestKey = await readSecretFile(layout.forwardAtRestKeyFile, 32)
  const relaySecretKey = await readSecretFile(layout.secretKeyFile, 64)
  const relay = await assembleForwardHttpsRelayVnext({
    bootstrap: localPeerBootstrap,
    runtimeConfig,
    resolveAdmissionAdapter: async () => splitAdmissionAdapterFixture(),
    releaseGate: async () => {},
    testOnlyPrivateIpcReplayJournalOptions: forward.replayJournalOptions,
    onError: forward.onError,
    forward: {
      relaySecretKey,
      relayPublicKey: identity.relayPublicKey,
      wireV3AbiHash: forward.wireV3AbiHash || PINNED_WIRE_V3_ABI_HASH,
      privateIpcV4Hash: forward.privateIpcV4Hash || PINNED_PRIVATE_IPC_V4_FORMAT_HASH,
      signedLaunchTopologyHash: layout.launchTopologyHash,
      endpointId: 1,
      expectedPeerUid: process.getuid(),
      expectedPeerGid: process.getgid(),
      socketGroupGid: process.getgid(),
      monotonicMillis: forward.monotonicMillis,
      nowEpoch: forward.nowEpoch,
      storage: {
        root: layout.roots['forward-storage'],
        manifestKey,
        atRestKey,
        sourceStoreId: forward.sourceStoreId || b4a.alloc(32, 0x76),
        targetStoreId: forward.targetStoreId || b4a.alloc(32, 0x77),
        mapGeneration: 1n,
        ownerFenceTokenHash: await readSecretFile(layout.environment.HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE, 32),
        sourceDurabilityContinuityHash: forward.sourceDurabilityContinuityHash || b4a.alloc(32, 0x78),
        targetDurabilityContinuityHash: forward.targetDurabilityContinuityHash || b4a.alloc(32, 0x79)
      },
      source: forward.source || null,
      target: forward.target || null
    }
  })
  manifestKey.fill(0)
  atRestKey.fill(0)
  return relay
}

// Generate one real self-signed loopback TLS identity with the platform
// openssl binary. Returns null when openssl is unavailable (recorded, never
// simulated): the FORWARD exporter tests skip in that case.
export async function createLoopbackTlsFixture (directory) {
  const keyFile = path.join(directory, 'edge-tls-key.pem')
  const certFile = path.join(directory, 'edge-tls-cert.pem')
  try {
    await execFileAsync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
      '-subj', '/CN=127.0.0.1', '-days', '1',
      '-keyout', keyFile, '-out', certFile
    ], { stdio: ['ignore', 'ignore', 'pipe'] })
  } catch {
    return null
  }
  const [key, cert] = await Promise.all([
    fs.readFile(keyFile),
    fs.readFile(certFile)
  ])
  await fs.chmod(keyFile, 0o600)
  return Object.freeze({ key, cert, keyFile, certFile })
}

export async function createEdgeFixture (options = {}) {
  const edge = new ForwardHttpsEdgeVnext({
    host: '127.0.0.1',
    port: options.port == null ? 0 : options.port,
    endpointId: 1,
    role: options.role,
    tls: options.tls || null,
    allowInsecureLoopback: options.tls == null,
    unarySocketPath: options.unarySocketPath,
    forwardSocketPath: options.forwardSocketPath,
    launchTopologyHash: options.launchTopologyHash,
    wireV3AbiHash: options.wireV3AbiHash,
    edgeProcessNonce: options.edgeProcessNonce,
    expectedDaemonUid: process.getuid(),
    expectedDaemonGid: process.getgid(),
    monotonicMillis: options.monotonicMillis,
    onError: options.onError,
    onUnaryExchange: options.onUnaryExchange,
    onForwardExchange: options.onForwardExchange,
    socketFactory: options.socketFactory
  })
  await edge.start()
  return edge
}

export function edgeBaseUrl (edge) {
  const address = edge.address()
  const protocol = edge.tls ? 'https' : 'http'
  return `${protocol}://127.0.0.1:${address.port}`
}

// A fetch-shaped helper over node:https with explicit TLS trust control.
// Tests disable PKI verification on loopback because authority in this
// substrate comes from signed descriptors, not certificate chains (recorded
// in the lane evidence; never a semantic fallback). Implements the exact
// subset of the fetch API used by BlindDirectHttpClient and the probes.
export function edgeFetchFixture (options = {}) {
  const rejectUnauthorized = options.rejectUnauthorized === true
  return async function edgeFetch (url, init = {}) {
    const target = typeof url === 'string' ? new URL(url) : url
    const headers = {}
    const headerPairs = Array.isArray(init.headers) ? init.headers : Object.entries(init.headers || {})
    for (const [name, value] of headerPairs) headers[name.toLowerCase()] = value
    const body = init.body == null ? null : b4a.from(init.body)
    if (body && headers['content-length'] == null && headers['transfer-encoding'] == null) {
      headers['content-length'] = String(body.byteLength)
    }
    const transport = target.protocol === 'https:' ? https : http
    const response = await new Promise((resolve, reject) => {
      const request = transport.request({
        method: init.method || 'GET',
        hostname: target.hostname,
        port: target.port || (target.protocol === 'https:' ? 443 : 80),
        path: target.pathname + target.search,
        agent: false,
        rejectUnauthorized,
        headers,
        timeout: 15_000
      }, resolve)
      request.on('timeout', () => {
        request.destroy()
        reject(new Error('edge fetch deadline elapsed'))
      })
      request.on('error', reject)
      if (init.signal) {
        if (init.signal.aborted) {
          request.destroy()
          reject(init.signal.reason || new Error('edge fetch aborted'))
          return
        }
        init.signal.addEventListener('abort', () => {
          request.destroy()
          reject(init.signal.reason || new Error('edge fetch aborted'))
        }, { once: true })
      }
      request.end(body)
    })
    const chunks = []
    for await (const chunk of response) chunks.push(b4a.from(chunk))
    const responseBody = b4a.concat(chunks)
    const headerMap = new Map()
    for (const [name, value] of Object.entries(response.headers)) {
      headerMap.set(name.toLowerCase(), Array.isArray(value) ? value.join(', ') : String(value))
    }
    return {
      status: response.statusCode,
      headers: {
        get: name => (headerMap.has(String(name).toLowerCase()) ? headerMap.get(String(name).toLowerCase()) : null)
      },
      body: {
        getReader () {
          let delivered = false
          return {
            async read () {
              if (delivered) return { done: true, value: undefined }
              delivered = true
              return { done: false, value: responseBody }
            },
            async cancel () {},
            releaseLock () {}
          }
        }
      },
      async arrayBuffer () {
        return responseBody.buffer.slice(responseBody.byteOffset, responseBody.byteOffset + responseBody.byteLength)
      }
    }
  }
}

export function fixtureAdmission (parameterHash, byte) {
  return {
    profileId: 7,
    schemeId: 9,
    parameterHash: b4a.from(parameterHash),
    token: b4a.alloc(32, byte)
  }
}

export async function removeFixtureScratch (layout) {
  const { removeBlindBoundaryScratch } = await import('../../../test/blind-boundary-scratch.js')
  const directory = typeof layout === 'string' ? layout : layout.directory
  await removeBlindBoundaryScratch(directory)
  const socketDirectory = typeof layout === 'string' ? null : layout.socketDirectory
  if (socketDirectory) await fs.rm(socketDirectory, { recursive: true, force: true })
}

// ---------------------------------------------------------------------------
// FORWARD one-hop: target-relay child-process runner. Executed directly
// (node forward-https-vnext-integration-fixture.mjs --target-child), it boots
// the complete target relay (unary assembly, forward target runtime on the
// accepted storage, target edge with real TLS) as a separate OS process and
// prints one JSON readiness line on stdout. The parent test drives the source
// relay against it and terminates it with SIGTERM. This is the real
// multiprocess boundary: the target daemon verifies the target edge's
// peercred (getpeereid on macOS here; SO_PEERCRED on syd-1) across processes.
// ---------------------------------------------------------------------------

async function targetChildMain () {
  const net = await import('node:net')
  const port = await new Promise(resolve => {
    const server = net.createServer()
    server.listen(0, '127.0.0.1', () => {
      const assigned = server.address().port
      server.close(() => resolve(assigned))
    })
  })
  const identity = await createRelayIdentityFixture({ port })
  const layout = await createRelayEnvironmentFixture(identity)
  const tls = await createLoopbackTlsFixture(layout.directory)
  const { ForwardHttpsEdgeVnext, FORWARD_HTTPS_EDGE_ROLE_VNEXT } = await import('../forward-https-vnext.js')
  const replayOffset = { value: -15_000n }
  const relay = await assembleRelayFixture(identity, layout, {
    onError: error => console.error(`[target-child] daemon error: ${error.code || 'ERROR'} ${error.message}`),
    replayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset.value
    },
    target: {
      socketPath: layout.environment.HIVERELAY_BLIND_UNARY_SOCKET.replace('unary.sock', 'target-ingress.sock'),
      resolveCatalogEntry: async catalogEntryId => {
        const snapshot = relay.unary.descriptorState.requireCurrent()
        return Object.freeze({
          catalogEntryId,
          relayPublicKey: b4a.from(identity.relayPublicKey),
          descriptorSequence: snapshot.descriptorSequence,
          descriptorHash: b4a.from(snapshot.hash)
        })
      }
    }
  })
  replayOffset.value = 0n
  await relay.start()
  const edge = new ForwardHttpsEdgeVnext({
    host: '127.0.0.1',
    port,
    endpointId: 1,
    role: FORWARD_HTTPS_EDGE_ROLE_VNEXT.TARGET,
    tls,
    unarySocketPath: layout.environment.HIVERELAY_BLIND_UNARY_SOCKET,
    forwardSocketPath: relay.targetIpc.socketPath,
    launchTopologyHash: layout.launchTopologyHash,
    wireV3AbiHash: PINNED_WIRE_V3_ABI_HASH,
    expectedDaemonUid: process.getuid(),
    expectedDaemonGid: process.getgid(),
    onError: error => console.error(`[target-child] edge error: ${error.code || 'ERROR'} ${error.message}`)
  })
  await edge.start()
  const snapshot = relay.unary.descriptorState.requireCurrent()
  process.stdout.write(`${JSON.stringify({
    ready: true,
    port,
    relayPublicKey: b4a.toString(identity.relayPublicKey, 'hex'),
    descriptorSequence: snapshot.descriptorSequence.toString(),
    descriptorHash: b4a.toString(snapshot.hash, 'hex'),
    genesisHash: b4a.toString(identity.genesisHash, 'hex'),
    parameterHash: b4a.toString(identity.parameterHash, 'hex')
  })}\n`)
  const shutdown = async () => {
    await edge.close().catch(() => {})
    await relay.close().catch(() => {})
    await removeFixtureScratch(layout)
    process.exit(0)
  }
  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

const invokedAsScript = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href
if (invokedAsScript && process.argv.includes('--target-child')) {
  targetChildMain().catch(error => {
    console.error(`[target-child] fatal: ${error.code || 'ERROR'} ${error.message}`)
    process.exit(1)
  })
}
