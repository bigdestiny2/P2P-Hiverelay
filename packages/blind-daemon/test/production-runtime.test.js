import { spawn } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs/promises'
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
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  admissionParametersV1,
  blake2b256,
  blindErrorV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  decodeDispatchFrame,
  encodeCanonical,
  getCellV1,
  hashStoreFormat,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import { loadDaemonBootstrapConfig } from '../bootstrap-config.js'
import {
  PRODUCTION_RUNTIME_EXCLUSIONS,
  PRODUCTION_RUNTIME_OPERATION_BITS,
  PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS,
  assertProductionRuntimeCompleteness,
  assembleProductionBlindDaemon,
  loadProductionRuntimeConfig
} from '../production-runtime.js'
import { BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS } from '../storage-engine.js'
import {
  bindDurability,
  descriptorValue,
  parameterValue
} from './coordinator-fixtures.js'

const SIX_HOURS_MILLIS = 6 * 60 * 60 * 1000

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
  const temporary = await fs.mkdtemp(path.join(await fs.realpath('/tmp'), 'brt-'))
  const directory = await fs.realpath(temporary)
  await fs.chmod(directory, 0o700)
  const storeRoot = path.join(directory, 'store')
  await fs.mkdir(storeRoot, { mode: 0o700 })

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
  const canonicalParameters = signCanonical(admissionParametersV1, parameters,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, relaySecretKey)

  const descriptor = descriptorValue({
    relayPublicKey: b4a.from(relayPublicKey),
    storeId: b4a.alloc(32, 0x62),
    enabledOperationBits: options.cellRuntime
      ? PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS
      : PRODUCTION_RUNTIME_OPERATION_BITS,
    issuedEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4,
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
  descriptor.durability.storeFormatMinor = 1
  descriptor.durability.storeFormatHash = options.storeFormatHash == null
    ? hashStoreFormat(authorityBytes)
    : b4a.from(options.storeFormatHash)
  descriptor.build.storeFormatHash = options.buildStoreFormatHash == null
    ? b4a.from(descriptor.durability.storeFormatHash)
    : b4a.from(options.buildStoreFormatHash)
  bindDurability(descriptor)
  const canonicalDescriptor = signCanonical(blindServiceDescriptorV1, descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)

  const descriptorFile = path.join(directory, 'descriptor.bin')
  const parametersFile = path.join(directory, 'admission.bin')
  const secretKeyFile = path.join(directory, 'relay-secret.bin')
  const partitionKeyFile = path.join(directory, 'partition-key.bin')
  const ownerFenceFile = path.join(directory, 'owner-fence-hash.bin')
  await Promise.all([
    privateFile(descriptorFile, canonicalDescriptor),
    privateFile(parametersFile, canonicalParameters),
    privateFile(secretKeyFile, relaySecretKey),
    privateFile(partitionKeyFile, b4a.alloc(32, 0x71)),
    privateFile(ownerFenceFile, b4a.alloc(32, 0x72))
  ])
  relaySecretKey.fill(0)

  const uid = process.getuid()
  const gid = process.getgid()
  const edgeUid = uid === 0xffffffff ? uid - 1 : uid + 1
  const environment = {
    ...process.env,
    HIVERELAY_BLIND_UNARY_SOCKET: path.join(directory, 'ipc', 'unary.sock'),
    HIVERELAY_BLIND_STREAM_SOCKET: path.join(directory, 'ipc', 'stream.sock'),
    HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: '81'.repeat(32),
    HIVERELAY_BLIND_ENDPOINT_IDS: '1',
    HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS: `1:${TRANSPORT_SUPPORT.DIRECT_HTTP}`,
    HIVERELAY_BLIND_EDGE_UID: String(edgeUid),
    HIVERELAY_BLIND_DAEMON_UID: String(uid),
    HIVERELAY_BLIND_DAEMON_GID: String(gid),
    HIVERELAY_BLIND_SHARED_GID: String(gid),
    HIVERELAY_BLIND_DESCRIPTOR_FILES: descriptorFile,
    HIVERELAY_BLIND_ADMISSION_PARAMETER_FILES: parametersFile,
    HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE: secretKeyFile,
    HIVERELAY_BLIND_STORE_ROOT: storeRoot,
    HIVERELAY_BLIND_PARTITION_KEY_FILE: partitionKeyFile,
    HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE: ownerFenceFile,
    HIVERELAY_BLIND_MAP_GENERATION: '1',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE: '0',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: b4a.toString(serviceDescriptorHash(canonicalDescriptor), 'hex')
  }
  return { directory, environment }
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

test('production assembler derives signed readiness and exposes only its real surface', async t => {
  const fixture = await runtimeFixture()
  t.teardown(async () => fs.rm(fixture.directory, { recursive: true, force: true }))
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const runtimeConfig = loadProductionRuntimeConfig(fixture.environment, bootstrap.endpointIds)
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

test('production assembler composes the fail-closed CELL tranche and its private staged path', async t => {
  const fixture = await runtimeFixture({ cellRuntime: true })
  t.teardown(async () => fs.rm(fixture.directory, { recursive: true, force: true }))
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
  t.is(readiness.readyOperationBits, PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS)
  t.is(runtime.status().enabledOperationBits, PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS)
  t.is(typeof runtime.daemon.dispatchStagedPut, 'function')
  t.is(typeof runtime.daemon.streamTransportProfileHashForEndpoint, 'function')
  t.absent(runtime.status().exclusions.includes('CELL_PUBLIC_EXECUTION_UNASSEMBLED'))
  t.absent(runtime.status().exclusions.includes('CHARGED_CELL_READ_CHECKPOINT_STATE_UNASSEMBLED'))
  t.is(runtime.status().cell.productionReady, true)
  t.ok(runtime.storage.transactionStore.partitionKey.some(byte => byte !== 0),
    'assembler wipe did not alias the store-owned partition key')
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
  t.alike(runtime.storage.transactionStore.partitionKey, b4a.alloc(32),
    'store-owned partition key is destroyed on close')
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

test('production launch floor and explicit one-hot transport authority fail closed', async t => {
  const fixture = await runtimeFixture()
  t.teardown(async () => fs.rm(fixture.directory, { recursive: true, force: true }))
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
  t.teardown(async () => fs.rm(split.directory, { recursive: true, force: true }))
  const splitBootstrap = loadDaemonBootstrapConfig(split.environment)
  await t.exception(assembleProductionBlindDaemon({
    bootstrap: splitBootstrap,
    runtimeConfig: loadProductionRuntimeConfig(split.environment, splitBootstrap.endpointIds),
    releaseGate: async () => {}
  }), /build and durability profiles name different store-format authorities/)

  const stale = await runtimeFixture({ storeFormatHash: b4a.alloc(32, 0xa2) })
  t.teardown(async () => fs.rm(stale.directory, { recursive: true, force: true }))
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
    await fs.rm(fixture.directory, { recursive: true, force: true })
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

test('direct production bin stops at the draft route-scope authority blocker before runtime assembly', async t => {
  const fixture = await runtimeFixture()
  t.teardown(async () => fs.rm(fixture.directory, { recursive: true, force: true }))
  const cli = path.resolve('packages/blind-daemon/cli.js')
  const child = spawn(process.execPath, [cli], {
    cwd: path.resolve('.'),
    env: fixture.environment,
    stdio: ['ignore', 'pipe', 'pipe']
  })
  const output = childOutput(child)
  const [code] = await once(child, 'exit')
  t.is(code, 1)
  t.ok(output.stderr().includes('BLIND_ABI_INCOMPLETE'))
  t.absent(output.stderr().includes('BLIND_RUNTIME_INCOMPLETE'))
  t.absent(output.stderr().includes('BLIND_PRIVATE_IPC_INCOMPLETE'))
  t.absent(output.stderr().includes('BLIND_DISPATCHER_MISSING'))
  t.absent(output.stderr().includes('BLIND_READINESS_SNAPSHOT_MISSING'))
})
