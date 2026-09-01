import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ENDPOINT_ROLE,
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  HEALTH_INTEGRITY_STATE,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  allocationCommitment,
  admissionParametersHash,
  admissionParametersV1,
  blake2b256,
  blindErrorV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  decodeDispatchFrame,
  decodeOuterEnvelope,
  encodeCanonical,
  encodeDispatchFrame,
  encodeOuterEnvelope,
  getCellV1,
  hashStoreFormat,
  putCellV1,
  resultSignaturePayload,
  serviceDescriptorHash,
  cellStorageSlot
} from '@hiverelay/blind-protocol'
import {
  LOCAL_STAGED_DIRECTION_V2,
  LOCAL_STAGED_FLAG_V2,
  LOCAL_STAGED_FRAME_KIND_V2,
  OUTER_CLASS,
  decodeLocalStagedCellPutFramesV2,
  decodeLocalTransportBindingV2,
  deriveLocalStagedOpenBindingHashV2,
  encodeLocalStagedCellPutFrameV2,
  encodeLocalStagedCellPutOpenV2,
  encodeLocalTransportBindingV2,
  verifyStagedCellPutPublicOuterEnvelopeV2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import { loadDaemonBootstrapConfig } from '../bootstrap-config.js'
import { runBlindDaemonCli } from '../cli.js'
import { PRODUCTION_ADMISSION_ADAPTER_SCRIPT_CONTRACT } from '../production-entrypoint.js'
import {
  PRODUCTION_RUNTIME_EXCLUSIONS,
  PRODUCTION_RUNTIME_OPERATION_BITS,
  PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS,
  assertProductionRuntimeCompleteness,
  assembleProductionBlindDaemon,
  loadProductionRuntimeConfig,
  productionStorageOperationalIntegrity
} from '../production-runtime.js'
import { BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS } from '../storage-engine.js'
import {
  bindDurability,
  descriptorValue,
  parameterValue
} from './coordinator-fixtures.js'
import {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'

const SIX_HOURS_MILLIS = 6 * 60 * 60 * 1000
const ADMISSION_SCRIPT_SCHEMA = PRODUCTION_ADMISSION_ADAPTER_SCRIPT_CONTRACT.schema

test('production completeness gate cannot be satisfied by publishing only ABI authorities', t => {
  let error = null
  try {
    assertProductionRuntimeCompleteness()
  } catch (failure) {
    error = failure
  }
  t.is(error?.code, 'BLIND_RUNTIME_INCOMPLETE')
  t.ok(error.message.includes(PRODUCTION_RUNTIME_EXCLUSIONS[0]))

  error = null
  try {
    assertProductionRuntimeCompleteness({ runtimeExclusions: [] })
  } catch (failure) {
    error = failure
  }
  t.is(error?.code, 'BLIND_STORAGE_INCOMPLETE')
  t.ok(error.message.includes(BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS[0]))

  assertProductionRuntimeCompleteness({ runtimeExclusions: [], storageBlockers: [] })
  t.pass('only an explicitly empty runtime and storage blocker set is complete')
})

test('production storage health separates operational integrity from promotion blockers', t => {
  const verified = productionStorageOperationalIntegrity({
    state: 'READY',
    storeFormat: { bound: true },
    blockers: ['ONLINE_REBALANCE_UNIMPLEMENTED', 'PROFILE2_EXTERNAL_JOURNAL_WITNESS_UNASSEMBLED']
  })
  t.alike(verified, {
    fullStoreVerified: true,
    integrityState: HEALTH_INTEGRITY_STATE.VERIFIED
  })

  const unbound = productionStorageOperationalIntegrity({
    state: 'READY',
    storeFormat: { bound: false },
    blockers: []
  })
  t.alike(unbound, {
    fullStoreVerified: false,
    integrityState: HEALTH_INTEGRITY_STATE.DEGRADED
  })

  const readOnly = productionStorageOperationalIntegrity({
    state: 'READ_ONLY',
    storeFormat: { bound: true },
    blockers: []
  })
  t.alike(readOnly, {
    fullStoreVerified: false,
    integrityState: HEALTH_INTEGRITY_STATE.FAILED
  })
})

function signCanonical (codec, value, domainId, secretKey) {
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

async function runtimeFixture (options = {}) {
  const directory = await createBlindBoundaryScratch('brt-')
  await fs.chmod(directory, 0o700)
  const storeRoot = path.join(directory, 'store')
  const privateIpcReplayRoot = path.join(directory, 'private-ipc-replay')
  await fs.mkdir(storeRoot, { mode: 0o700 })
  await fs.mkdir(privateIpcReplayRoot, { mode: 0o700 })

  const relayPublicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const relaySecretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(relayPublicKey, relaySecretKey)
  const currentEpoch = Math.floor(Date.now() / SIX_HOURS_MILLIS)

  const endpointRoleBits = options.cellRuntime
    ? ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY | ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER
    : ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY
  const parameters = parameterValue(relayPublicKey, {
    roleBits: endpointRoleBits,
    validFromEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4
  })
  if (options.excludeCellPutAdmission === true) {
    parameters.resourceCosts = parameters.resourceCosts.filter(row =>
      row.familyId !== FAMILY.CELL || row.operationId !== OPERATION.CELL.PUT)
  }
  const canonicalParameters = signCanonical(admissionParametersV1, parameters,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, relaySecretKey)

  const descriptor = descriptorValue({
    relayPublicKey: b4a.from(relayPublicKey),
    storeId: b4a.alloc(32, 0x62),
    enabledOperationBits: options.cellRuntime
      ? PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS
      : PRODUCTION_RUNTIME_OPERATION_BITS,
    issuedEpoch: options.descriptorSequence == null ? currentEpoch : currentEpoch - 1,
    expiresEpoch: options.descriptorSequence == null ? currentEpoch + 4 : currentEpoch + 3,
    capacityBand: 0
  })
  descriptor.endpoints = [descriptor.endpoints[0]]
  descriptor.endpoints[0].endpointId = 1
  descriptor.endpoints[0].transportId = 1
  descriptor.endpoints[0].roleBits = endpointRoleBits
  descriptor.admissionProfiles = [descriptor.admissionProfiles[0]]
  descriptor.admissionProfiles[0].profileId = parameters.profileId
  descriptor.admissionProfiles[0].schemeId = parameters.schemeId
  descriptor.admissionProfiles[0].conformanceClass = parameters.conformanceClass
  descriptor.admissionProfiles[0].roleBits = parameters.roleBits
  descriptor.admissionProfiles[0].parameterHash = admissionParametersHash(canonicalParameters)
  const authorityBytes = await fs.readFile(new URL(
    '../../blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc',
    import.meta.url
  ))
  descriptor.durability.storeFormatMajor = 1
  descriptor.durability.storeFormatMinor = 2
  descriptor.durability.storeFormatHash = options.storeFormatHash == null
    ? hashStoreFormat(authorityBytes)
    : b4a.from(options.storeFormatHash)
  descriptor.build.storeFormatHash = options.buildStoreFormatHash == null
    ? b4a.from(descriptor.durability.storeFormatHash)
    : b4a.from(options.buildStoreFormatHash)
  bindDurability(descriptor)
  const canonicalGenesisDescriptor = signCanonical(blindServiceDescriptorV1, descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)
  let activeDescriptor = descriptor
  let canonicalDescriptor = canonicalGenesisDescriptor
  const descriptorChain = [canonicalGenesisDescriptor]
  if (options.descriptorSequence != null) {
    if (options.descriptorSequence !== 1) throw new Error('runtime fixture only supports one exact successor')
    activeDescriptor = decodeCanonical(blindServiceDescriptorV1, canonicalGenesisDescriptor, { copyBytes: true })
    activeDescriptor.descriptorSequence = 1n
    activeDescriptor.previousDescriptorHash = serviceDescriptorHash(canonicalGenesisDescriptor)
    activeDescriptor.issuedEpoch = currentEpoch
    activeDescriptor.expiresEpoch = currentEpoch + 4
    activeDescriptor.descriptorNonce = b4a.alloc(32, 0x64)
    canonicalDescriptor = signCanonical(blindServiceDescriptorV1, activeDescriptor,
      RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)
    descriptorChain.push(canonicalDescriptor)
  }

  const descriptorFile = path.join(directory, 'descriptor.bin')
  const successorDescriptorFile = path.join(directory, 'descriptor-successor.bin')
  const parametersFile = path.join(directory, 'admission.bin')
  const secretKeyFile = path.join(directory, 'relay-secret.bin')
  const storeManifestKeyFile = path.join(directory, 'store-manifest-key.bin')
  const ownerFenceFile = path.join(directory, 'owner-fence-hash.bin')
  await Promise.all([
    ...descriptorChain.map((bytes, index) => privateFile(
      index === 0 ? descriptorFile : successorDescriptorFile, bytes)),
    privateFile(parametersFile, canonicalParameters),
    privateFile(secretKeyFile, relaySecretKey),
    privateFile(storeManifestKeyFile, b4a.alloc(32, 0x71)),
    privateFile(ownerFenceFile, b4a.alloc(32, 0x72))
  ])
  relaySecretKey.fill(0)

  const uid = process.getuid()
  const gid = process.getgid()
  const edgeUid = uid === 0xffffffff ? uid - 1 : uid + 1
  const environment = {
    ...process.env,
    HIVERELAY_BLIND_RUNTIME_PROFILE: options.cellRuntime ? 'CELL_V1' : 'DESCRIBE_ONLY_V1',
    HIVERELAY_BLIND_UNARY_SOCKET: path.join(directory, 'ipc', 'unary.sock'),
    HIVERELAY_BLIND_STREAM_SOCKET: path.join(directory, 'ipc', 'stream.sock'),
    HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: '81'.repeat(32),
    HIVERELAY_BLIND_ENDPOINT_IDS: '1',
    HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS: `1:${TRANSPORT_SUPPORT.DIRECT_HTTP}`,
    HIVERELAY_BLIND_EDGE_UID: String(edgeUid),
    HIVERELAY_BLIND_DAEMON_UID: String(uid),
    HIVERELAY_BLIND_DAEMON_GID: String(gid),
    HIVERELAY_BLIND_SHARED_GID: String(gid),
    HIVERELAY_BLIND_DESCRIPTOR_FILES: descriptorChain.length === 1
      ? descriptorFile
      : `${descriptorFile},${successorDescriptorFile}`,
    HIVERELAY_BLIND_ADMISSION_PARAMETER_FILES: parametersFile,
    HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE: secretKeyFile,
    HIVERELAY_BLIND_STORE_ROOT: storeRoot,
    HIVERELAY_BLIND_PRIVATE_IPC_REPLAY_ROOT: privateIpcReplayRoot,
    HIVERELAY_BLIND_STORE_MANIFEST_KEY_FILE: storeManifestKeyFile,
    HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE: ownerFenceFile,
    HIVERELAY_BLIND_MAP_GENERATION: '1',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE: String(activeDescriptor.descriptorSequence),
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: b4a.toString(serviceDescriptorHash(canonicalDescriptor), 'hex')
  }
  return { directory, environment, privateIpcReplayRoot }
}

function productionAdmissionScript () {
  return `
({
  schema: '${ADMISSION_SCRIPT_SCHEMA}',
  createAdmissionAdapterResolver (context) {
    if (context.runtimeProfile !== 'CELL_V1' ||
        context.launchTopologyHash.$hiverelayType !== 'bytes' ||
        context.launchTopologyHash.hex !== '${'81'.repeat(32)}' ||
        context.endpointIds.length !== 1 || context.endpointIds[0] !== 1) {
      throw new Error('entrypoint launch binding mismatch')
    }
    const adapter = Object.freeze({
      prepare () { throw new Error('not exercised during startup') },
      preparePreflight () { throw new Error('not exercised during startup') },
      confirmAfterEof () { throw new Error('not exercised during startup') }
    })
    return () => adapter
  }
})
`
}

async function configureProductionAdmissionScript (fixture, name, source, digest = null) {
  const file = path.join(fixture.directory, name)
  const bytes = Buffer.from(source)
  await privateFile(file, bytes)
  fixture.environment.HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE = file
  fixture.environment.HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256 = digest ||
    createHash('sha256').update(bytes).digest('hex')
  return file
}

async function assertPrivateSocketsAbsent (t, fixture) {
  for (const name of ['unary.sock', 'stream.sock']) {
    let error = null
    try {
      await fs.lstat(path.join(fixture.directory, 'ipc', name))
    } catch (failure) {
      error = failure
    }
    t.is(error?.code, 'ENOENT', `${name} must not exist after rejected startup`)
  }
}

function childOutput (child) {
  let stdout = ''
  let stderr = ''
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  child.stdout.on('data', chunk => { stdout += chunk })
  child.stderr.on('data', chunk => { stderr += chunk })
  return {
    stdout: () => stdout,
    stderr: () => stderr
  }
}

function waitForText (child, output, match, timeoutMillis = 10000) {
  if (output().includes(match)) return Promise.resolve()
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error(`child did not emit ${match}`)), timeoutMillis)
    const inspect = () => {
      if (output().includes(match)) finish()
    }
    const exited = (code, signal) => finish(new Error(`child exited before ready (${code}, ${signal})`))
    const finish = error => {
      clearTimeout(timer)
      child.stdout.off('data', inspect)
      child.off('exit', exited)
      if (error) reject(error)
      else resolve()
    }
    child.stdout.on('data', inspect)
    child.once('exit', exited)
  })
}

function preparedAdmissionResult (input) {
  return {
    spendTag: blake2b256(input.admission.token),
    requestCommitment: input.requestCommitment,
    costClass: input.costClass,
    walCommitRecord: input.admission.token,
    profileId: input.admission.profileId,
    schemeId: input.admission.schemeId,
    parameterHash: input.admission.parameterHash
  }
}

function splitAdmissionAdapter () {
  const preflights = new WeakSet()
  return Object.freeze({
    async prepare (input) { return preparedAdmissionResult(input) },
    async preparePreflight () {
      const authority = Object.freeze({})
      preflights.add(authority)
      return authority
    },
    async confirmAfterEof (input) {
      if (!preflights.has(input.adapterPreflight)) throw new Error('unknown admission preflight')
      preflights.delete(input.adapterPreflight)
      return preparedAdmissionResult(input)
    }
  })
}

async function rejectsCode (t, promise, code) {
  let rejected = null
  try {
    await promise
  } catch (error) {
    rejected = error
  }
  t.is(rejected?.code, code)
  return rejected
}

async function assembleProductionCellFixture (fixture, options = {}) {
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const localPeerBootstrap = Object.freeze({ ...bootstrap, expectedPeerUid: process.getuid() })
  const runtimeConfig = options.runtimeConfig ||
    loadProductionRuntimeConfig(fixture.environment, bootstrap.endpointIds)
  return assembleProductionBlindDaemon({
    bootstrap: options.bootstrap || localPeerBootstrap,
    runtimeConfig,
    enableCellRuntime: true,
    resolveAdmissionAdapter: async () => splitAdmissionAdapter(),
    testOnlyPrivateIpcReplayJournalOptions: options.replayOptions,
    onError: options.onError,
    releaseGate: async () => {}
  })
}

async function assertCellReadRuntimeLive (t, runtime, fill) {
  const now = process.hrtime.bigint() / 1_000_000n
  const result = await runtime.coordinator.dispatch({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestId: b4a.alloc(16, fill),
    body: encodeCanonical(getCellV1, {
      version: 1,
      storageSlot: b4a.alloc(32, fill + 1),
      clientNonce: b4a.alloc(32, fill + 2),
      admission: null
    })
  }, {
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    outerClass: null,
    acceptedMonotonicMillis: now,
    absoluteDeadlineMonotonicMillis: now + 5000n
  })
  const frame = decodeDispatchFrame(result.dispatch, { copyBody: true })
  const error = decodeCanonical(blindErrorV1, frame.body)
  t.is(frame.frameKind, FRAME_KIND.ERROR)
  t.is(error.code, ERROR_CODE.NOT_FOUND)
}

async function assertV2WriteMasked (t, runtime, fill) {
  const readiness = await runtime.readiness.serverSnapshot({
    edgeInstanceNonce: b4a.alloc(32, fill),
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  t.is(readiness.readyOperationBits & 0x08, 0)
  t.is(runtime.daemon.v2WriteDisabledReason, 'DURABLE_REPLAY_AUTHORITY_MISSING')
}

async function exchangeProductionV2Put (runtime, bootstrap, outer) {
  const acceptedMonotonicMillis = process.hrtime.bigint() / 1_000_000n
  const endpoint = runtime.descriptorState.requireCurrent().descriptor.endpoints[0]
  const edgeProcessNonce = b4a.alloc(32, 0xd1)
  const localChannelNonce = b4a.alloc(32, 0xd2)
  const publicSessionBindingHash = b4a.alloc(32, 0xd3)
  const openFields = Object.freeze({
    endpointId: endpoint.endpointId,
    outerClass: 3,
    acceptedMonotonicMillis,
    openDeadlineMonotonicMillis: acceptedMonotonicMillis + 15_000n,
    requestEnvelopeBytes: OUTER_CLASS[3]
  })
  const openBindingHash = deriveLocalStagedOpenBindingHashV2({
    open: openFields,
    launchTopologyHash: bootstrap.launchTopologyHash,
    authorityKind: 1,
    edgeProcessNonce,
    localChannelNonce,
    transportProfileHash: endpoint.transportProfileHash,
    publicSessionBindingHash
  })
  const context = decodeLocalTransportBindingV2(encodeLocalTransportBindingV2({
    authorityKind: 1,
    edgeProcessNonce,
    localChannelNonce,
    transportProfileHash: endpoint.transportProfileHash,
    publicSessionBindingHash,
    openBindingHash
  }))
  const open = encodeLocalStagedCellPutOpenV2({ ...openFields, context })
  const frames = []
  for (let offset = 0, sequence = 0n; offset < outer.byteLength; sequence++) {
    const end = Math.min(outer.byteLength, offset + 65_515)
    frames.push(encodeLocalStagedCellPutFrameV2({
      direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
      frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
      sequence,
      flags: end === outer.byteLength ? LOCAL_STAGED_FLAG_V2.FIN : 0,
      bytes: outer.subarray(offset, end)
    }))
    offset = end
  }
  const socket = net.createConnection({ path: bootstrap.streamSocketPath })
  await once(socket, 'connect')
  const chunks = []
  let socketError = null
  socket.on('data', chunk => chunks.push(b4a.from(chunk)))
  socket.on('error', error => { socketError = error })
  const completed = new Promise(resolve => socket.once('close', resolve))
  socket.end(b4a.concat([open, ...frames]))
  await completed
  return { wire: b4a.concat(chunks), open, socketError }
}

test('production assembler derives signed readiness and exposes only its real surface', async t => {
  const fixture = await runtimeFixture()
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  const environment = { ...fixture.environment }
  delete environment.HIVERELAY_BLIND_PRIVATE_IPC_REPLAY_ROOT
  const bootstrap = loadDaemonBootstrapConfig(environment)
  const runtimeConfig = loadProductionRuntimeConfig(environment, bootstrap.endpointIds)
  t.is(runtimeConfig.privateIpcReplayRoot, null)
  const runtime = await assembleProductionBlindDaemon({
    bootstrap,
    runtimeConfig,
    releaseGate: async () => {}
  })
  t.teardown(() => runtime.close())

  const readiness = await runtime.readiness.serverSnapshot({
    edgeInstanceNonce: b4a.alloc(32, 0x91),
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  t.is(readiness.selfVerified, true)
  t.is(readiness.readyRoleBits, ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY)
  t.is(readiness.readyOperationBits, PRODUCTION_RUNTIME_OPERATION_BITS)
  t.is(runtime.status().enabledOperationBits, 0x7)
  t.is(runtime.daemon.dispatchStagedPut, null)
  t.is(runtime.status().storage.storeFormat.bound, true)
  t.is(runtime.status().storage.storeFormat.publicationFinal, false)
  t.ok(runtime.status().storage.blockers.length > 0)
  t.ok(runtime.status().exclusions.includes('CELL_PUBLIC_EXECUTION_UNASSEMBLED'))
  await runtime.close()
})

test('production startup permits only blind-only 1.2 stores, rebuilds a missing head, and rejects record loss', async t => {
  const fixture = await runtimeFixture()
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  const environment = { ...fixture.environment }
  delete environment.HIVERELAY_BLIND_PRIVATE_IPC_REPLAY_ROOT
  const bootstrap = loadDaemonBootstrapConfig(environment)
  const first = await assembleProductionBlindDaemon({
    bootstrap,
    runtimeConfig: loadProductionRuntimeConfig(environment, bootstrap.endpointIds),
    releaseGate: async () => {}
  })
  await first.close()

  t.exception(() => loadProductionRuntimeConfig({
    ...environment,
    HIVERELAY_BLIND_STORE_READER_MODE: 'legacy-only'
  }, bootstrap.endpointIds), /STORE_READER_MODE is invalid/)
  t.exception(() => loadProductionRuntimeConfig({
    ...environment,
    HIVERELAY_BLIND_STORE_READER_MODE: 'blind-plus-legacy-dual-read'
  }, bootstrap.endpointIds), /STORE_READER_MODE is invalid/)

  await fs.unlink(path.join(environment.HIVERELAY_BLIND_STORE_ROOT, 'control',
    'blind-store-generation-head-v2.json'))
  const recovered = await assembleProductionBlindDaemon({
    bootstrap,
    runtimeConfig: loadProductionRuntimeConfig(environment, bootstrap.endpointIds),
    releaseGate: async () => {}
  })
  await recovered.close()
  t.ok((await fs.stat(path.join(environment.HIVERELAY_BLIND_STORE_ROOT, 'control',
    'blind-store-generation-head-v2.json'))).isFile(), 'a valid contiguous record chain rebuilds its missing head')

  await fs.unlink(path.join(environment.HIVERELAY_BLIND_STORE_ROOT, 'control',
    'blind-store-generation-record-0000000000000000-v2.json'))
  await t.exception.all(() => assembleProductionBlindDaemon({
    bootstrap,
    runtimeConfig: loadProductionRuntimeConfig(environment, bootstrap.endpointIds),
    releaseGate: async () => {}
  }), /record filenames must be contiguous/)
})

test('legacy-only admission adapter cannot advertise or dispatch production V2 CELL.PUT', async t => {
  const fixture = await runtimeFixture({ cellRuntime: true })
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const runtimeConfig = loadProductionRuntimeConfig(fixture.environment, bootstrap.endpointIds)
  const runtime = await assembleProductionBlindDaemon({
    bootstrap,
    runtimeConfig,
    enableCellRuntime: true,
    resolveAdmissionAdapter: async () => ({
      async prepare (input) {
        return {
          spendTag: blake2b256(input.admission.token),
          requestCommitment: input.requestCommitment,
          costClass: input.costClass,
          walCommitRecord: input.admission.token,
          profileId: input.admission.profileId,
          schemeId: input.admission.schemeId,
          parameterHash: input.admission.parameterHash
        }
      }
    }),
    releaseGate: async () => {}
  })
  t.teardown(() => runtime.close())

  const readiness = await runtime.readiness.serverSnapshot({
    edgeInstanceNonce: b4a.alloc(32, 0x92),
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  t.is(readiness.readyRoleBits,
    ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY | ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER)
  const withoutPut = PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS ^ 0x08
  t.is(readiness.readyOperationBits, withoutPut)
  t.is(runtime.status().enabledOperationBits, withoutPut)
  t.is(runtime.daemon.dispatchStagedPut, null)
  t.is(runtime.daemon.streamTransportProfileHashForEndpoint, null)
  t.ok(runtime.status().exclusions.includes('CELL_PUBLIC_EXECUTION_UNASSEMBLED'))
  t.absent(runtime.status().exclusions.includes('CHARGED_CELL_READ_CHECKPOINT_STATE_UNASSEMBLED'))
  t.is(runtime.status().cell.productionReady, false)
  t.is(runtime.status().v2WritePathReady, false)
  t.alike(runtime.status().admissionCapture, { complete: false, required: 1, captured: 0 })
  t.is('partitionKey' in runtime.storage.transactionStore, false,
    'the assembled store retains no partition secret')
  t.ok(runtime.storage.transactionStore.ownerFenceTokenHash.some(byte => byte !== 0),
    'assembler wipe did not alias the store-owned writer fence hash')
  t.ok(runtime.storage.transactionStore.durabilityContinuityHash.some(byte => byte !== 0),
    'assembler state did not alias the store-owned durability continuity hash')
  t.ok(runtime.storage.relayPublicKey.some(byte => byte !== 0) &&
    runtime.storage.storeId.some(byte => byte !== 0) &&
    runtime.storage.durabilityContinuityHash.some(byte => byte !== 0) &&
    runtime.storage.durabilityProfileHash.some(byte => byte !== 0),
  'Cell storage identity authorities remain live through the runtime lifetime')

  const now = process.hrtime.bigint() / 1_000_000n
  const result = await runtime.coordinator.dispatch({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestId: b4a.alloc(16, 0x93),
    body: encodeCanonical(getCellV1, {
      version: 1,
      storageSlot: b4a.alloc(32, 0x94),
      clientNonce: b4a.alloc(32, 0x95),
      admission: null
    })
  }, {
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    outerClass: null,
    acceptedMonotonicMillis: now,
    absoluteDeadlineMonotonicMillis: now + 5000n
  })
  const errorFrame = decodeDispatchFrame(result.dispatch, { copyBody: true })
  const error = decodeCanonical(blindErrorV1, errorFrame.body)
  t.is(errorFrame.frameKind, FRAME_KIND.ERROR)
  t.is(error.code, ERROR_CODE.NOT_FOUND)
  await runtime.close()
  t.is('partitionKey' in runtime.storage.transactionStore, false,
    'closing the store does not reveal or retain a partition secret')
  t.alike(runtime.storage.transactionStore.ownerFenceTokenHash, b4a.alloc(32),
    'store-owned writer fence hash is destroyed on close')
  t.alike(runtime.storage.transactionStore.durabilityContinuityHash, b4a.alloc(32),
    'store-owned durability continuity hash is destroyed on close')
  t.alike(runtime.storage.relayPublicKey, b4a.alloc(32),
    'Cell relay identity is destroyed on close')
  t.alike(runtime.storage.storeId, b4a.alloc(32),
    'Cell store identity is destroyed on close')
  t.alike(runtime.storage.durabilityContinuityHash, b4a.alloc(32),
    'Cell durability continuity identity is destroyed on close')
  t.alike(runtime.storage.durabilityProfileHash, b4a.alloc(32),
    'Cell durability profile identity is destroyed on close')
})

test('captured split adapter and production-owned replay journal execute one real production V2 CELL.PUT', async t => {
  const fixture = await runtimeFixture({ cellRuntime: true, descriptorSequence: 1 })
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const localPeerBootstrap = Object.freeze({ ...bootstrap, expectedPeerUid: process.getuid() })
  const runtimeConfig = loadProductionRuntimeConfig(fixture.environment, bootstrap.endpointIds)
  const adapter = splitAdmissionAdapter()
  const daemonErrors = []
  let resolveCalls = 0
  let replayOffset = -15_000n
  const runtime = await assembleProductionBlindDaemon({
    bootstrap: localPeerBootstrap,
    runtimeConfig,
    enableCellRuntime: true,
    resolveAdmissionAdapter: async () => { resolveCalls++; return adapter },
    testOnlyPrivateIpcReplayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset
    },
    onError: error => daemonErrors.push(error),
    releaseGate: async () => {}
  })
  t.teardown(() => runtime.close())
  t.is(runtime.status().v2WritePathReady, false)
  t.is(runtime.status().privateIpcReplayJournal.reason,
    'PRIVATE_IPC_V2_REPLAY_JOURNAL_STARTUP_QUARANTINE')
  replayOffset = 0n
  t.is(runtime.status().v2WritePathReady, true)
  t.is(resolveCalls, 1)
  t.alike(runtime.status().admissionCapture, { complete: true, required: 1, captured: 1 })
  t.is(runtime.status().enabledOperationBits, PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS)
  t.is(typeof runtime.daemon.dispatchStagedPut, 'function')
  t.is(typeof runtime.daemon.streamTransportProfileHashForEndpoint, 'function')
  t.ok(b4a.equals(runtime.daemon.stagedPutRelayPublicKey,
    runtime.descriptorState.requireCurrent().descriptor.relayPublicKey))

  const keys = [0, 1, 2].map(() => {
    const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
    sodium.crypto_sign_keypair(publicKey, secretKey)
    return { publicKey, secretKey }
  })
  const descriptor = runtime.descriptorState.requireCurrent().descriptor
  const allocationEpoch = runtime.storage.status().epochFloor
  const cellBlob = b4a.alloc(4096, 0xe1)
  const declaredBlobHash = blake2b256(cellBlob)
  const storageSlot = cellStorageSlot({ allocationEpoch, createPublicKey: keys[0].publicKey })
  const allocation = allocationCommitment({
    relayPublicKey: descriptor.relayPublicKey,
    storageSlot,
    allocationEpoch,
    sizeClass: 1,
    leaseClass: 1,
    declaredCellBlobHash: declaredBlobHash,
    createPublicKey: keys[0].publicKey,
    renewPublicKey: keys[1].publicKey,
    dropPublicKey: keys[2].publicKey
  })
  const createSignature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(createSignature, allocation, keys[0].secretKey)
  const profile = descriptor.admissionProfiles[0]
  const requestId = b4a.alloc(16, 0xe2)
  const dispatch = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    requestId,
    body: encodeCanonical(putCellV1, {
      version: 1,
      storageSlot,
      allocationEpoch,
      sizeClass: 1,
      leaseClass: 1,
      clientNonce: b4a.alloc(32, 0xe3),
      createPublicKey: keys[0].publicKey,
      renewPublicKey: keys[1].publicKey,
      dropPublicKey: keys[2].publicKey,
      declaredBlobHash,
      createSignature,
      admission: {
        profileId: profile.profileId,
        schemeId: profile.schemeId,
        parameterHash: profile.parameterHash,
        token: b4a.alloc(32, 0xe4)
      },
      cellBlob
    })
  })
  const outer = encodeOuterEnvelope({ outerClass: 3, innerDispatch: dispatch }, {
    randomFill: padding => padding.fill(0xe5)
  })
  await runtime.start()
  const exchange = await exchangeProductionV2Put(runtime, localPeerBootstrap, outer)
  for (const error of daemonErrors) t.comment(`${error.code || 'ERROR'}: ${error.message}`)
  if (exchange.socketError) t.comment(`${exchange.socketError.code}: ${exchange.socketError.message}`)
  const local = decodeLocalStagedCellPutFramesV2(exchange.wire)
  t.is(local.remainder.byteLength, 0)
  t.ok(local.frames.length > 0)
  const resultOuter = b4a.concat(local.frames.map(frame => frame.bytes))
  const verified = verifyStagedCellPutPublicOuterEnvelopeV2(resultOuter,
    exchange.open, LOCAL_STAGED_DIRECTION_V2.RESULT, requestId)
  const response = decodeOuterEnvelope(resultOuter, { copyInner: true })
  t.is(verified.outerClass, 3)
  t.is(response.frame.frameKind, FRAME_KIND.RESPONSE)
  t.alike((await runtime.storage.readCell(storageSlot)).cellBlob, cellBlob)
  t.is(runtime.storage.status().accounting.atomicStagingLeases, 0)
  t.is(resolveCalls, 1, 'the live PUT uses the assembly-captured adapter without dynamic re-resolution')
  t.ok((await fs.readdir(path.join(fixture.environment.HIVERELAY_BLIND_STORE_ROOT, 'control')))
    .some(name => name.includes('0000000000000001')), 'first acknowledged PUT appends the D7 floor record')
  await runtime.close()
})

test('production replay journal restart quarantines writes, preserves tuples, and releases its writer lock on close', async t => {
  const fixture = await runtimeFixture({ cellRuntime: true, descriptorSequence: 1 })
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  let now = 10_000n
  const replayOptions = { monotonicMillis: () => now }
  let runtime = await assembleProductionCellFixture(fixture, { replayOptions })
  t.teardown(async () => runtime && runtime.close())

  t.is(runtime.status().v2WritePathReady, false)
  now += 15_000n
  t.is(runtime.status().v2WritePathReady, true)
  const replayTupleHash = b4a.alloc(32, 0xa6)
  await runtime.testOnlyDurableReplayAuthority.reserve({
    replayTupleHash,
    expiresMonotonicMillis: now + 15_000n
  })
  await runtime.close()

  runtime = await assembleProductionCellFixture(fixture, { replayOptions })
  let status = runtime.status()
  t.is(status.v2WritePathReady, false)
  t.is(status.privateIpcReplayJournal.occupied, 1)
  t.is(status.privateIpcReplayJournal.reason,
    'PRIVATE_IPC_V2_REPLAY_JOURNAL_STARTUP_QUARANTINE')
  const readiness = await runtime.readiness.serverSnapshot({
    edgeInstanceNonce: b4a.alloc(32, 0xa7),
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  t.is(readiness.readyOperationBits & 0x08, 0,
    'startup quarantine suppresses CELL.PUT from the production readiness proof')
  await rejectsCode(t, runtime.testOnlyDurableReplayAuthority.reserve({
    replayTupleHash,
    expiresMonotonicMillis: now + 15_000n
  }), 'PRIVATE_IPC_V2_REPLAY_JOURNAL_STARTUP_QUARANTINE')
  await rejectsCode(t, runtime.testOnlyDurableReplayAuthority.reserve({
    replayTupleHash: b4a.alloc(32, 0xa8),
    expiresMonotonicMillis: now + 15_000n
  }), 'PRIVATE_IPC_V2_REPLAY_JOURNAL_STARTUP_QUARANTINE')

  now += 14_999n
  t.is(runtime.status().v2WritePathReady, false)
  now++
  status = runtime.status()
  t.is(status.v2WritePathReady, true)
  t.is(status.privateIpcReplayJournal.occupied, 0)
  await runtime.testOnlyDurableReplayAuthority.reserve({
    replayTupleHash,
    expiresMonotonicMillis: now + 15_000n
  })
  await runtime.close()

  runtime = await assembleProductionCellFixture(fixture, { replayOptions })
  t.is(runtime.status().privateIpcReplayJournal.state, 'OPEN',
    'a clean close releases the exclusive replay writer lock and permits restart')
  await runtime.close()
  runtime = null
})

test('missing production replay root permits CELL reads but refuses V2 writes', async t => {
  const fixture = await runtimeFixture({ cellRuntime: true, descriptorSequence: 1 })
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  const environment = { ...fixture.environment }
  delete environment.HIVERELAY_BLIND_PRIVATE_IPC_REPLAY_ROOT
  const bootstrap = loadDaemonBootstrapConfig(environment)
  const runtimeConfig = loadProductionRuntimeConfig(environment, bootstrap.endpointIds)
  const errors = []
  const runtime = await assembleProductionCellFixture(fixture, {
    runtimeConfig,
    onError: error => errors.push(error)
  })
  t.teardown(() => runtime.close())

  t.is(errors[0]?.code, 'PRIVATE_IPC_V2_REPLAY_JOURNAL_ROOT_UNCONFIGURED')
  t.is(runtime.status().privateIpcReplayJournal.reason,
    'PRIVATE_IPC_V2_REPLAY_JOURNAL_ROOT_UNCONFIGURED')
  t.is(runtime.status().privateIpcReplayJournal.recovery,
    'OPERATOR_REPLAY_JOURNAL_REPAIR_OR_MIGRATION_AND_RESTART_REQUIRED')
  t.is(runtime.status().v2WritePathAssembled, true)
  t.is(runtime.status().v2WritePathReady, false)
  await assertCellReadRuntimeLive(t, runtime, 0xac)
  await assertV2WriteMasked(t, runtime, 0xad)
})

test('production replay journal lock and topology faults degrade only V2 writes while reads remain live', async t => {
  const fixture = await runtimeFixture({ cellRuntime: true, descriptorSequence: 1 })
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  const now = 40_000n
  const replayOptions = { monotonicMillis: () => now }
  let runtime = await assembleProductionCellFixture(fixture, { replayOptions })
  t.teardown(async () => runtime && runtime.close())

  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const runtimeConfig = loadProductionRuntimeConfig(fixture.environment, bootstrap.endpointIds)
  const competingStoreRoot = path.join(fixture.directory, 'competing-store')
  await fs.mkdir(competingStoreRoot, { mode: 0o700 })
  const competingErrors = []
  let degraded = await assembleProductionCellFixture(fixture, {
    runtimeConfig: Object.freeze({ ...runtimeConfig, storeRoot: competingStoreRoot }),
    replayOptions,
    onError: error => competingErrors.push(error)
  })
  t.is(competingErrors[0]?.code, 'PRIVATE_IPC_V2_REPLAY_JOURNAL_LOCKED')
  t.is(degraded.status().privateIpcReplayJournal.reason,
    'PRIVATE_IPC_V2_REPLAY_JOURNAL_LOCKED')
  t.is(degraded.status().v2WritePathAssembled, true)
  t.is(degraded.status().v2WritePathReady, false)
  await assertCellReadRuntimeLive(t, degraded, 0xac)
  await assertV2WriteMasked(t, degraded, 0xad)
  await degraded.close()
  t.is(runtime.status().privateIpcReplayJournal.state, 'OPEN')
  await runtime.close()

  const driftedBootstrap = Object.freeze({
    ...bootstrap,
    expectedPeerUid: process.getuid(),
    launchTopologyHash: b4a.alloc(32, 0xa9)
  })
  const driftErrors = []
  degraded = await assembleProductionCellFixture(fixture, {
    bootstrap: driftedBootstrap,
    replayOptions,
    onError: error => driftErrors.push(error)
  })
  t.is(driftErrors[0]?.code, 'PRIVATE_IPC_V2_REPLAY_JOURNAL_IDENTITY_MISMATCH')
  t.is(degraded.status().privateIpcReplayJournal.reason,
    'PRIVATE_IPC_V2_REPLAY_JOURNAL_IDENTITY_MISMATCH')
  t.is(degraded.status().privateIpcReplayJournal.recovery,
    'OPERATOR_REPLAY_JOURNAL_REPAIR_OR_MIGRATION_AND_RESTART_REQUIRED')
  t.is(degraded.status().v2WritePathReady, false)
  await assertCellReadRuntimeLive(t, degraded, 0xaf)
  await assertV2WriteMasked(t, degraded, 0xb0)
  await degraded.close()
  runtime = null
})

test('production replay journal poison masks only V2 writes', async t => {
  const fixture = await runtimeFixture({ cellRuntime: true, descriptorSequence: 1 })
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  let now = 70_000n
  let injected = false
  const runtime = await assembleProductionCellFixture(fixture, {
    replayOptions: {
      monotonicMillis: () => now,
      faultInjector: async point => {
        if (injected || point !== 'reserve:after-sync') return
        injected = true
        const error = new Error('injected production replay durability uncertainty')
        error.code = 'INJECTED_PRODUCTION_REPLAY_POISON'
        throw error
      }
    }
  })
  now += 15_000n
  await rejectsCode(t, runtime.testOnlyDurableReplayAuthority.reserve({
    replayTupleHash: b4a.alloc(32, 0xaa),
    expiresMonotonicMillis: now + 100n
  }), 'INJECTED_PRODUCTION_REPLAY_POISON')
  const poisoned = runtime.status()
  t.is(poisoned.privateIpcReplayJournal.state, 'POISONED')
  t.is(poisoned.v2WritePathReady, false)
  const poisonedReadiness = await runtime.readiness.serverSnapshot({
    edgeInstanceNonce: b4a.alloc(32, 0xab),
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  t.is(poisonedReadiness.readyOperationBits & 0x08, 0)
  await assertCellReadRuntimeLive(t, runtime, 0xb2)
  await runtime.close()
})

test('production launch floor and explicit one-hot transport authority fail closed', async t => {
  const fixture = await runtimeFixture()
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  t.exception(() => loadProductionRuntimeConfig({
    ...fixture.environment,
    HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS: '1:3'
  }, bootstrap.endpointIds))

  const environment = {
    ...fixture.environment,
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: 'ff'.repeat(32)
  }
  let rejected
  try {
    await assembleProductionBlindDaemon({
      bootstrap,
      runtimeConfig: loadProductionRuntimeConfig(environment, bootstrap.endpointIds),
      releaseGate: async () => {}
    })
  } catch (error) {
    rejected = error
  }
  t.is(rejected.code, 'BLIND_RUNTIME_DESCRIPTOR_FLOOR_MISMATCH')
})

test('production assembly rejects split build/durability pins and stale signed store authorities', async t => {
  const split = await runtimeFixture({ buildStoreFormatHash: b4a.alloc(32, 0xa1) })
  t.teardown(async () => removeBlindBoundaryScratch(split.directory))
  const splitBootstrap = loadDaemonBootstrapConfig(split.environment)
  await t.exception(assembleProductionBlindDaemon({
    bootstrap: splitBootstrap,
    runtimeConfig: loadProductionRuntimeConfig(split.environment, splitBootstrap.endpointIds),
    releaseGate: async () => {}
  }), /build and durability profiles name different store-format authorities/)

  const stale = await runtimeFixture({ storeFormatHash: b4a.alloc(32, 0xa2) })
  t.teardown(async () => removeBlindBoundaryScratch(stale.directory))
  const staleBootstrap = loadDaemonBootstrapConfig(stale.environment)
  let rejected
  try {
    await assembleProductionBlindDaemon({
      bootstrap: staleBootstrap,
      runtimeConfig: loadProductionRuntimeConfig(stale.environment, staleBootstrap.endpointIds),
      releaseGate: async () => {}
    })
  } catch (error) {
    rejected = error
  }
  t.is(rejected?.code, 'BLIND_STORE_FORMAT_AUTHORITY_INVALID')
  t.ok(rejected?.message.includes('expected storeFormatHash'))
})

test('packaged CLI assembly starts through its real child-process path and shuts down cleanly', async t => {
  const fixture = await runtimeFixture()
  let child = null
  t.teardown(async () => {
    if (child && child.exitCode == null && child.signalCode == null) child.kill('SIGKILL')
    await removeBlindBoundaryScratch(fixture.directory)
  })
  const cliUrl = pathToFileURL(path.resolve('packages/blind-daemon/cli.js')).href
  const source = `import { runBlindDaemonCli } from ${JSON.stringify(cliUrl)}; ` +
    'await runBlindDaemonCli({ releaseGate: async () => {} })'
  child = spawn(process.execPath, ['--input-type=module', '--eval', source], {
    cwd: path.resolve('.'),
    env: fixture.environment,
    stdio: ['ignore', 'pipe', 'pipe']
  })
  const output = childOutput(child)
  await waitForText(child, output.stdout, 'private IPC ready')
  t.absent(output.stderr().includes('BLIND_DISPATCHER_MISSING'))
  t.absent(output.stderr().includes('BLIND_READINESS_SNAPSHOT_MISSING'))
  t.ok(output.stdout().includes('public operations=DESCRIBE only'))
  for (const name of ['unary.sock', 'stream.sock']) {
    const stat = await fs.lstat(path.join(fixture.directory, 'ipc', name))
    t.is(stat.isSocket(), true)
    t.is(stat.mode & 0o777, 0o660)
  }
  const exited = once(child, 'exit')
  child.kill('SIGTERM')
  const [code, signal] = await exited
  t.is(code, 0)
  t.is(signal, null)
})

test('packaged CLI can explicitly assemble the captured CELL runtime without weakening its default', async t => {
  const fixture = await runtimeFixture({ cellRuntime: true, descriptorSequence: 1 })
  let runtime = null
  t.teardown(async () => {
    if (runtime) await runtime.close().catch(() => {})
    await removeBlindBoundaryScratch(fixture.directory)
  })
  await configureProductionAdmissionScript(fixture, 'admission-adapter.js', productionAdmissionScript())
  let replayOffset = -15_000n
  runtime = await runBlindDaemonCli({
    environment: fixture.environment,
    releaseGate: async () => {},
    testOnlyPrivateIpcReplayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset
    },
    installSignalHandlers: false
  })
  t.is(runtime.status().started, true)
  t.is(runtime.status().v2WritePathAssembled, true)
  t.is(runtime.status().v2WritePathReady, false)
  t.alike(runtime.status().admissionCapture, { complete: true, required: 1, captured: 1 })
  replayOffset = 0n
  t.is(runtime.status().v2WritePathReady, true)
  await runtime.close()
  runtime = null
})

test('explicit CELL CLI rejects every adapter startup failure before creating sockets', async t => {
  const fixture = await runtimeFixture({ cellRuntime: true, descriptorSequence: 1 })
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  const failures = [
    {
      name: 'missing',
      expected: 'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
      configure: async () => {
        fixture.environment.HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE =
          path.join(fixture.directory, 'missing-adapter.js')
        fixture.environment.HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256 = '00'.repeat(32)
      }
    },
    {
      name: 'digest',
      expected: 'BLIND_ADMISSION_ADAPTER_DIGEST_MISMATCH',
      configure: () => configureProductionAdmissionScript(fixture, 'digest-adapter.js',
        productionAdmissionScript(), '00'.repeat(32))
    },
    {
      name: 'export',
      expected: 'BLIND_ADMISSION_ADAPTER_EXPORT_INVALID',
      configure: () => configureProductionAdmissionScript(fixture, 'export-adapter.js',
        '({ schema: \'wrong\', createAdmissionAdapterResolver () { return () => null } })')
    },
    {
      name: 'initialize',
      expected: 'BLIND_ADMISSION_ADAPTER_INITIALIZATION_FAILED',
      configure: () => configureProductionAdmissionScript(fixture, 'initialize-adapter.js', `
({
  schema: '${ADMISSION_SCRIPT_SCHEMA}',
  createAdmissionAdapterResolver () { throw new Error('initialization refused') }
})
`)
    },
    {
      name: 'required-profile',
      expected: 'BLIND_ADMISSION_ADAPTER_RESOLUTION_FAILED',
      configure: () => configureProductionAdmissionScript(fixture, 'null-adapter.js', `
({
  schema: '${ADMISSION_SCRIPT_SCHEMA}',
  createAdmissionAdapterResolver () { return () => null }
})
`)
    },
    {
      name: 'methods',
      expected: 'BLIND_ADMISSION_ADAPTER_RESOLUTION_FAILED',
      configure: () => configureProductionAdmissionScript(fixture, 'methods-adapter.js', `
({
  schema: '${ADMISSION_SCRIPT_SCHEMA}',
  createAdmissionAdapterResolver () {
    return () => Object.freeze({ prepare () {}, preparePreflight () {} })
  }
})
`)
    }
  ]

  for (const failure of failures) {
    await failure.configure()
    await rejectsCode(t, runBlindDaemonCli({
      environment: fixture.environment,
      releaseGate: async () => {},
      installSignalHandlers: false
    }), failure.expected)
    await assertPrivateSocketsAbsent(t, fixture)
    t.comment(`${failure.name} failed before listener creation`)
  }
})

test('strict CELL CLI rejects zero required adapters before creating sockets', async t => {
  const fixture = await runtimeFixture({
    cellRuntime: true,
    descriptorSequence: 1,
    excludeCellPutAdmission: true
  })
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  await configureProductionAdmissionScript(fixture, 'admission-adapter.js', productionAdmissionScript())
  await rejectsCode(t, runBlindDaemonCli({
    environment: fixture.environment,
    releaseGate: async () => {},
    installSignalHandlers: false
  }), 'BLIND_RUNTIME_ADMISSION_CAPTURE_INCOMPLETE')
  await assertPrivateSocketsAbsent(t, fixture)
})

test('CELL CLI release gate runs before admission adapter initialization', async t => {
  const fixture = await runtimeFixture({ cellRuntime: true, descriptorSequence: 1 })
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  await configureProductionAdmissionScript(fixture, 'must-not-initialize.js', `
({
  schema: '${ADMISSION_SCRIPT_SCHEMA}',
  createAdmissionAdapterResolver () { throw new Error('adapter initialized before release gate') }
})
`)
  const gateError = new Error('release gate sentinel')
  gateError.code = 'TEST_RELEASE_GATE_FIRST'
  await rejectsCode(t, runBlindDaemonCli({
    environment: fixture.environment,
    releaseGate: async () => { throw gateError },
    installSignalHandlers: false
  }), 'TEST_RELEASE_GATE_FIRST')
  await assertPrivateSocketsAbsent(t, fixture)
})

test('direct production bin preserves the runtime completeness release blocker', async t => {
  const fixture = await runtimeFixture()
  t.teardown(async () => removeBlindBoundaryScratch(fixture.directory))
  const cli = path.resolve('packages/blind-daemon/cli.js')
  const child = spawn(process.execPath, [cli], {
    cwd: path.resolve('.'),
    env: fixture.environment,
    stdio: ['ignore', 'pipe', 'pipe']
  })
  const output = childOutput(child)
  const [code] = await once(child, 'exit')
  t.is(code, 1)
  t.ok(output.stderr().includes('BLIND_RUNTIME_INCOMPLETE'))
  t.absent(output.stderr().includes('BLIND_ABI_INCOMPLETE'))
  t.absent(output.stderr().includes('BLIND_PRIVATE_IPC_INCOMPLETE'))
  t.absent(output.stderr().includes('BLIND_DISPATCHER_MISSING'))
  t.absent(output.stderr().includes('BLIND_READINESS_SNAPSHOT_MISSING'))
})
