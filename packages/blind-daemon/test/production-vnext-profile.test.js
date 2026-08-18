import test from 'brittle'
import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  CORE_ACK_RESULT,
  ENDPOINT_ROLE,
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  HEALTH_CLOCK_STATE,
  HEALTH_INTEGRITY_STATE,
  INBOX_APPEND_RESULT,
  INBOX_RECEIPT_RESULT,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  batchGetEntriesCommitment,
  batchGetResultV1,
  batchGetV1,
  blindAdmissionParametersRequestV1,
  blindCoreAckV1,
  blindDescribeGetV1,
  blindErrorV1,
  blindHealthChallengeV1,
  blindHealthResultV1,
  blindServiceDescriptorV1,
  blake2b256,
  coreMirrorRequestV1,
  coreServeChallengeV1,
  decodeCanonical,
  decodeDispatchFrame,
  encodeCanonical,
  getCellV1,
  inboxAppendAckV1,
  inboxAppendV1,
  inboxCreateV1,
  inboxReadEntriesCommitment,
  inboxReadResultV1,
  inboxReadSignaturePayloadV1,
  inboxReadV1,
  inboxReceiptV1,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import {
  BASELINE_COMPLETENESS_EXCLUSIONS,
  PROFILE2_COMPLETENESS_EXCLUSIONS,
  PRODUCTION_RUNTIME_EXCLUSIONS,
  assembleProductionBlindDaemon,
  assertProductionRuntimeReleaseReady,
  bindStoreIdentity,
  bootstrapVnextStoreGenerationFloor,
  encodeRuntimeBinding,
  loadProductionRuntimeConfig,
  productionReleaseGateFor
} from '../production-runtime.js'
import {
  deriveVnextBucketMapHash,
  loadVnextForwardConfig,
  runVnextStoreGenesisCeremony
} from '../production-vnext-profile.js'
import { loadDaemonBootstrapConfig } from '../bootstrap-config.js'
import {
  loadProductionAdmissionAdapter,
  loadProductionEntrypointConfig
} from '../production-entrypoint.js'
import { BlindCellStorageEngine } from '../storage-engine.js'
import { BlindTransactionStore, BlindWalIntegrityError } from '../transaction-store.js'
import { openBlindStoreGenerationFloor } from '../storage-generation-v12.js'
import { loadBundledBlindStoreFormatAuthority } from '../store-format-binding.js'
import { coreMirrorFixture, coreProveFixture } from './production-runtime-core-fixture.js'
import {
  inboxAppendFixture,
  inboxCreateFixture,
  inboxReadFixture
} from './production-runtime-inbox-fixture.js'
import { VNEXT_BASELINE_OPERATION_BITS, vnextSealedFixture } from './production-vnext-profile-fixture.js'

const LOCAL_BINDING = PRODUCTION_RUNTIME_EXCLUSIONS[0]
const FORWARD_EXEC = PRODUCTION_RUNTIME_EXCLUSIONS[6]
const PROFILE2_WITNESS = PRODUCTION_RUNTIME_EXCLUSIONS[9]
const SIX_HOURS_MILLIS = 6 * 60 * 60 * 1000
const PUBLIC_ROLE_BITS = ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY |
  ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER

async function cleanup (directory) {
  await fs.rm(directory, { recursive: true, force: true }).catch(() => {})
}

async function gateError (environment) {
  let error = null
  try {
    await assertProductionRuntimeReleaseReady(environment)
  } catch (failure) {
    error = failure
  }
  return error
}

test('vNext gate genuinely assembles the complete baseline with zero exclusions', async t => {
  const fixture = await vnextSealedFixture()
  t.teardown(() => cleanup(fixture.directory))
  const error = await gateError(fixture.environment)
  t.is(error, null, 'the genuine production release gate passes with zero baseline exclusions')

  // Every baseline item is TRUE-assembled by a real code path (the static
  // binding verification, the entrypoint CELL/INBOX/CORE line, the sealed
  // admission redemption adapter, and the two-slot manifest floor serving
  // integration proven end-to-end below) — never filtered out of the list.
  t.is(BASELINE_COMPLETENESS_EXCLUSIONS.length, 8, 'the baseline completeness scope stays the frozen eight')
})

test('vNext gate fails closed on a forged relay identity binding', async t => {
  const fixture = await vnextSealedFixture()
  t.teardown(() => cleanup(fixture.directory))
  // Replace the sealed relay secret with a different key: the descriptor no
  // longer matches, so FINAL_BUILD_PROFILE_LOCAL_BINDING must fail closed.
  const forgedSecret = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES, 0x5a)
  await fs.writeFile(fixture.environment.HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE, forgedSecret, { mode: 0o600 })
  const error = await gateError(fixture.environment)
  t.is(error && error.code, 'BLIND_RUNTIME_SIGNING_KEY_MISMATCH')
})

test('vNext gate fails closed on a descriptor outside the baseline public-test mask', async t => {
  // A descriptor that does not carry exactly the baseline 0x0001ffff mask
  // (here narrowed to the DESCRIBE-only bits) is refused by the binding check:
  // the public-test profile requires the full baseline and never a FORWARD bit.
  const narrowed = await vnextSealedFixture({ operationBits: 0x00000007 })
  t.teardown(() => cleanup(narrowed.directory))
  const narrowedError = await gateError(narrowed.environment)
  t.is(narrowedError && narrowedError.code, 'BLIND_RUNTIME_DESCRIPTOR_UNSUPPORTED')

  // A durability profile-2 descriptor cannot even be constructed without its
  // nonzero external journal witness topology: the sealed public-test material
  // carries no profile-2 witness, so the profile genuinely stays profile 1.
  let buildError = null
  try {
    await vnextSealedFixture({ durabilityProfileId: 2 })
  } catch (failure) {
    buildError = failure
  }
  t.ok(buildError != null, 'profile-2 descriptor demands an external journal witness tuple')
  t.ok(/external journal/.test(buildError.message), 'profile-2 witness topology is genuinely absent')
})

test('vNext gate fails closed when the admission adapter script is unconfigured', async t => {
  const fixture = await vnextSealedFixture()
  t.teardown(() => cleanup(fixture.directory))
  delete fixture.environment.HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE
  delete fixture.environment.HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256
  // A CELL-line profile requires the sealed adapter script; its absence is a
  // fail-closed entrypoint config error before any exclusion list is computed.
  const error = await gateError(fixture.environment)
  t.is(error && error.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID',
    'unconfigured redemption adapter is refused fail-closed')
})

test('non-vNext profiles keep the strict static completeness gate', async t => {
  const fixture = await vnextSealedFixture()
  t.teardown(() => cleanup(fixture.directory))
  for (const profile of ['DESCRIBE_ONLY_V1', 'CELL_V1', 'CELL_INBOX_V1', 'CELL_INBOX_CORE_V1']) {
    const environment = { ...fixture.environment, HIVERELAY_BLIND_RUNTIME_PROFILE: profile }
    const error = await gateError(environment)
    t.is(error && error.code, 'BLIND_RUNTIME_INCOMPLETE', `${profile} keeps the static gate`)
    t.ok(error.message.includes(LOCAL_BINDING), `${profile} still lists every shipped exclusion`)
    t.ok(error.message.includes(PROFILE2_WITNESS), `${profile} lists all 10 shipped exclusions`)
  }
})

test('completeness scope is frozen: baseline never evaluates profile-2 items, even with FORWARD configured', async t => {
  // The frozen scope: baseline = the 8 baseline exclusions, never FORWARD or
  // the profile-2 witness; profile-2 = exactly those two.
  t.is(BASELINE_COMPLETENESS_EXCLUSIONS.length, 8)
  t.absent(BASELINE_COMPLETENESS_EXCLUSIONS.includes(FORWARD_EXEC))
  t.absent(BASELINE_COMPLETENESS_EXCLUSIONS.includes(PROFILE2_WITNESS))
  t.alike([...PROFILE2_COMPLETENESS_EXCLUSIONS], [FORWARD_EXEC, PROFILE2_WITNESS])

  // With no FORWARD material the baseline gate passes: the baseline set is
  // genuinely assembled and profile-2 items are never evaluated under it.
  const without = await vnextSealedFixture()
  t.teardown(() => cleanup(without.directory))
  t.is(loadVnextForwardConfig(without.environment), null, 'absent FORWARD material parses as unconfigured')
  t.is(await gateError(without.environment), null, 'baseline gate passes with no FORWARD material')

  // Even with a complete FORWARD storage identity configured, the baseline
  // gate still does not evaluate profile-2 items; it passes unchanged.
  const withForward = await vnextSealedFixture({ forward: true })
  t.teardown(() => cleanup(withForward.directory))
  t.ok(loadVnextForwardConfig(withForward.environment), 'complete FORWARD storage identity parses')
  t.is(await gateError(withForward.environment), null,
    'baseline gate passes; FORWARD and the profile-2 witness are never baseline items')
})

test('the profile-2 acceptance profile stays fail-closed (static gate, FORWARD bits zero)', async t => {
  const fixture = await vnextSealedFixture({ forward: true })
  t.teardown(() => cleanup(fixture.directory))
  // Selecting the profile-2 one-hop FORWARD profile does not enter the baseline
  // path; it falls through to the strict static completeness gate and lists all
  // 10 shipped exclusions. FORWARD has no independent acceptance yet, so it can
  // never pass here.
  const environment = {
    ...fixture.environment,
    HIVERELAY_BLIND_RUNTIME_PROFILE: 'LIMITED_PUBLIC_TEST_FORWARD_ONE_HOP_V1'
  }
  const error = await gateError(environment)
  t.is(error && error.code, 'BLIND_RUNTIME_INCOMPLETE', 'profile-2 keeps the strict static gate')
  t.ok(error.message.includes(FORWARD_EXEC), 'profile-2 profile still lists FORWARD as unassembled')
  t.ok(error.message.includes(PROFILE2_WITNESS), 'profile-2 profile still lists the journal witness')
})

test('a half-configured FORWARD class fails closed instead of assembling partially', async t => {
  const fixture = await vnextSealedFixture({ forward: true })
  t.teardown(() => cleanup(fixture.directory))
  delete fixture.environment.HIVERELAY_BLIND_FORWARD_ATREST_KEY_FILE
  let error = null
  try {
    loadVnextForwardConfig(fixture.environment)
  } catch (failure) {
    error = failure
  }
  t.is(error && error.code, 'BLIND_VNEXT_FORWARD_CONFIG_INVALID')
})

// ---------------------------------------------------------------------------
// vNext production serving e2e. The full orchestration — bind (empty store)
// -> store-genesis ceremony -> generation-floor bootstrap -> serve — driven
// against the sealed fixture with the GENUINE production release gate (never a
// seam gate, never replay-journal test overrides).

// Test-local mirror of the exact floorTransitionV1 payload the ceremony seals
// (production-vnext-profile.js floorAdvancePayloadV1): version u8 constant 1,
// oldEpochFloor u32be, newEpochFloor u32be.
function floorAdvancePayloadV1 (oldEpochFloor, newEpochFloor) {
  const payload = b4a.alloc(9)
  payload[0] = 1
  payload.writeUInt32BE(oldEpochFloor, 1)
  payload.writeUInt32BE(newEpochFloor, 5)
  return payload
}

function requestFrame (familyId, operationId, codec, request, requestByte) {
  return {
    frameKind: FRAME_KIND.REQUEST,
    familyId,
    operationId,
    requestId: b4a.alloc(16, requestByte),
    body: encodeCanonical(codec, request)
  }
}

function dispatchContext () {
  const now = process.hrtime.bigint() / 1_000_000n
  return {
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    outerClass: null,
    acceptedMonotonicMillis: now,
    absoluteDeadlineMonotonicMillis: now + 15_000n
  }
}

function responseValue (result, codec) {
  const frame = decodeDispatchFrame(result.dispatch, { copyBody: true })
  if (frame.frameKind !== FRAME_KIND.RESPONSE) {
    const error = decodeCanonical(blindErrorV1, frame.body)
    throw new Error(`expected a response frame, got error code ${error.code}`)
  }
  return decodeCanonical(codec, frame.body, { copyBytes: true })
}

function errorName (result) {
  const frame = decodeDispatchFrame(result.dispatch, { copyBody: true })
  if (frame.frameKind !== FRAME_KIND.ERROR) return null
  const value = decodeCanonical(blindErrorV1, frame.body)
  return Object.keys(ERROR_CODE).find(name => ERROR_CODE[name] === value.code)
}

function verifyResultSignature (t, codec, value, domainId, relayPublicKey) {
  const canonical = encodeCanonical(codec, value)
  const unsigned = canonical.subarray(0, canonical.byteLength - sodium.crypto_sign_BYTES)
  t.ok(sodium.crypto_sign_verify_detached(value.signature,
    resultSignaturePayload(domainId, unsigned), relayPublicKey))
}

function verifyInboxReadSignature (t, value, relayPublicKey) {
  t.alike(value.entriesCommitment, inboxReadEntriesCommitment(value.entries))
  const payload = encodeCanonical(inboxReadSignaturePayloadV1, {
    version: value.version,
    relayBinding: value.relayBinding,
    requestNonce: value.requestNonce,
    requestCommitment: value.requestCommitment,
    snapshotRevision: value.snapshotRevision,
    entriesCommitment: value.entriesCommitment,
    nextCursor: value.nextCursor
  })
  t.ok(sodium.crypto_sign_verify_detached(value.signature,
    resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT, payload), relayPublicKey))
}

async function failure (run) {
  try {
    await run()
  } catch (error) {
    return error
  }
  return null
}

// Orchestrate the vNext serving-store preparation on the fixture's CELL store
// root: bind -> store-genesis ceremony -> generation-floor bootstrap (then a
// bootstrap re-run and a direct frozen-floor reopen to prove idempotence and
// acceptance). Key copies read here are zeroed before returning.
async function orchestrateVnextServingStore (fixture) {
  const environment = fixture.environment
  const storeRoot = environment.HIVERELAY_BLIND_STORE_ROOT
  const manifestKey = await fs.readFile(environment.HIVERELAY_BLIND_STORE_MANIFEST_KEY_FILE)
  const ownerFenceTokenHash = await fs.readFile(environment.HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE)
  try {
    const descriptorCanonicalBytes = await fs.readFile(fixture.successorDescriptorFile)
    const descriptor = decodeCanonical(blindServiceDescriptorV1, descriptorCanonicalBytes, { copyBytes: true })
    const mapGeneration = 1n
    const binding = encodeRuntimeBinding(descriptor, mapGeneration, ownerFenceTokenHash, manifestKey)
    const bound = await bindStoreIdentity(storeRoot, binding)
    const ceremony = await runVnextStoreGenesisCeremony({
      storeRoot,
      descriptor,
      descriptorCanonicalBytes,
      manifestKey,
      ownerFenceTokenHash,
      partitionKey: blake2b256(b4a.concat([
        b4a.from('hiverelay.blind.partition-key.v1', 'ascii'), descriptor.storeId, manifestKey])),
      bucketMapHash: deriveVnextBucketMapHash(descriptor.storeId, mapGeneration),
      mapGeneration
    })
    const bootstrapInput = { storeRoot, descriptor, manifestKey, ownerFenceTokenHash, mapGeneration }
    const floor = await bootstrapVnextStoreGenerationFloor(bootstrapInput)
    const reran = await bootstrapVnextStoreGenerationFloor(bootstrapInput)
    // The frozen generation floor now accepts the manifested store WITHOUT
    // allowCreate when handed the same recovered anchor (previously it threw
    // 'blind store generation evidence is missing').
    const reopened = await openBlindStoreGenerationFloor(path.join(storeRoot, 'control'), {
      manifestKey,
      storeIdentity: binding,
      storeEvidence: {
        walSequence: floor.storeEvidence.walSequence,
        walHash: floor.storeEvidence.walHash
      }
    })
    return Object.freeze({
      descriptor,
      descriptorCanonicalBytes,
      binding,
      bound,
      ceremony,
      floor,
      reran,
      reopened
    })
  } finally {
    manifestKey.fill(0)
    ownerFenceTokenHash.fill(0)
  }
}

// Assemble the production runtime exactly as cli.js does for the vNext
// profile: the genuine production release gate bound to the signed
// environment, the sealed admission redemption adapter loaded through the
// production VM bridge, strict admission capture, and the manifest floor
// required. No test seams.
async function assembleVnextRuntime (fixture, environment = fixture.environment) {
  const bootstrap = loadDaemonBootstrapConfig(environment)
  const entrypointConfig = loadProductionEntrypointConfig(environment)
  const productionAdmission = await loadProductionAdmissionAdapter(entrypointConfig, bootstrap)
  return assembleProductionBlindDaemon({
    bootstrap,
    runtimeConfig: loadProductionRuntimeConfig(environment, bootstrap.endpointIds),
    releaseGate: productionReleaseGateFor(environment),
    enableCellRuntime: true,
    enableInboxRuntime: true,
    enableCoreRuntime: true,
    resolveAdmissionAdapter: input => productionAdmission.resolveAdmissionAdapter(input),
    requireCompleteAdmissionCapture: true,
    requireManifestFloor: true
  })
}

function describeGetFrame (descriptorHash, requestByte) {
  return requestFrame(FAMILY.DESCRIBE, OPERATION.DESCRIBE.GET, blindDescribeGetV1, {
    version: 1,
    descriptorHash,
    clientNonce: b4a.alloc(32, requestByte)
  }, requestByte)
}

test('vNext serving store: genesis floor byte-parity, generation-floor bootstrap, engine open', async t => {
  const fixture = await vnextSealedFixture()
  t.teardown(() => cleanup(fixture.directory))
  const orchestration = await orchestrateVnextServingStore(fixture)
  const { descriptor, bound, ceremony, floor, reran, reopened } = orchestration

  t.is(bound, true, 'bind claims the empty store before genesis')
  t.is(ceremony.walHeadSequence, 1n, 'the genesis WAL head is the sealed floor record')
  t.alike(ceremony.recoveredWalSequences, [1n], 'validated recovery replays exactly the genesis frame')

  t.is(floor.bindingCreated, false, 'the store was already bound when the bootstrap ran')
  t.is(floor.storeEvidence.walSequence, 1n,
    'the generation-floor evidence is the recovered genesis WAL head, read from the engine')
  t.is(floor.firstBlindOnlyWriteAcknowledged, false, 'no blind write is acknowledged at genesis')
  t.is(reran.storeEvidence.walSequence, floor.storeEvidence.walSequence,
    're-running the bootstrap recovers the identical anchor sequence')
  t.ok(b4a.equals(reran.storeEvidence.walHash, floor.storeEvidence.walHash),
    're-running the bootstrap recovers the identical anchor hash')
  t.is(reran.bindingCreated, false, 'bootstrap re-run stays bind-idempotent')
  t.is(reopened.firstBlindOnlyWriteAcknowledged, false,
    'the frozen generation floor accepts the manifested store (no evidence-is-missing)')

  // Engine-open success + byte parity: the serving cell engine opens the
  // manifested store, recovers the genesis floor record as a valid
  // floorTransitionV1 with newEpochFloor === descriptor.issuedEpoch (no
  // RECOVERY_GAP_READ_ONLY), and its recovered WAL head is exactly the anchor
  // the bootstrap recorded.
  const storeFormatAuthority = await loadBundledBlindStoreFormatAuthority({
    expectedStoreFormatHash: descriptor.durability.storeFormatHash,
    expectedFormatMajor: descriptor.durability.storeFormatMajor,
    expectedFormatMinor: descriptor.durability.storeFormatMinor
  })
  const ownerFenceTokenHash = await fs.readFile(fixture.environment.HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE)
  let engine = null
  try {
    engine = new BlindCellStorageEngine({
      root: fixture.environment.HIVERELAY_BLIND_STORE_ROOT,
      relayPublicKey: descriptor.relayPublicKey,
      storeId: descriptor.storeId,
      durabilityProfileId: descriptor.durability.profileId,
      durabilityProfileHash: descriptor.durabilityProfileHash,
      mapGeneration: 1n,
      ownerFenceTokenHash,
      durabilityContinuityHash: descriptor.durabilityContinuityHash,
      storeFormatAuthority
    })
    await engine.open()
    const status = engine.status()
    t.is(status.state, 'READY', 'the manifested store opens READY')
    t.is(status.readOnlyReason, null, 'no recovery-gap read-only fence')
    t.is(status.epochFloor, descriptor.issuedEpoch,
      'recovered epochFloor is exactly the descriptor issued epoch (floorTransitionV1 byte parity)')
    t.is(status.walSequence, 1n, 'the engine adds no frame of its own on the manifested store')
    t.ok(b4a.equals(status.walHash, floor.storeEvidence.walHash),
      'the serving engine recovers exactly the anchor the bootstrap recorded')
    t.ok(status.storeFormat.bound, 'the store format authority is bound')
  } finally {
    ownerFenceTokenHash.fill(0)
    if (engine) await engine.close().catch(() => {})
  }
})

test('vNext serving assembles with zero baseline exclusions and serves signed baseline routes', async t => {
  const fixture = await vnextSealedFixture({ functionalAdmission: true })
  t.teardown(() => cleanup(fixture.directory))
  const { descriptor } = await orchestrateVnextServingStore(fixture)
  const runtime = await assembleVnextRuntime(fixture)
  t.teardown(() => runtime.close().catch(() => {}))

  const status = runtime.status()
  t.alike(BASELINE_COMPLETENESS_EXCLUSIONS.filter(name => status.exclusions.includes(name)), [],
    'no baseline exclusion survives the genuine assembly')
  t.ok(status.manifestFloor != null, 'the two-slot manifest floor is enforced in serving')
  t.is(status.manifestFloor.descriptorSequenceFloor, 1n, 'the enforced floor is the chain head sequence')
  t.ok(b4a.equals(status.manifestFloor.descriptorHashFloor, fixture.successorHash),
    'the enforced floor is the chain head descriptor hash')
  t.is(status.storage.state, 'READY', 'the manifested cell store serves READY')
  t.is(status.storage.epochFloor, descriptor.issuedEpoch,
    'serving recovers the exact descriptor epoch floor')
  t.is(status.inboxStorage.opened, true, 'the INBOX store serves beside it')
  t.is(status.coreStorage.family, 'CORE', 'the CORE store serves beside it')

  const relayPublicKey = fixture.relayPublicKey

  // DESCRIBE.GET: the signed chain head descriptor, and the retained genesis
  // history entry.
  const head = responseValue(await runtime.coordinator.dispatch(
    describeGetFrame(fixture.successorHash, 0x11), dispatchContext()), blindServiceDescriptorV1)
  t.is(head.descriptorSequence, 1n, 'DESCRIBE.GET serves the chain head')
  verifyResultSignature(t, blindServiceDescriptorV1, head, RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relayPublicKey)
  const history = responseValue(await runtime.coordinator.dispatch(
    describeGetFrame(fixture.genesisHash, 0x12), dispatchContext()), blindServiceDescriptorV1)
  t.is(history.descriptorSequence, 0n, 'DESCRIBE.GET serves the retained genesis descriptor')
  verifyResultSignature(t, blindServiceDescriptorV1, history, RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
    relayPublicKey)

  // DESCRIBE.CHALLENGE: the signed health result binds the head, the endpoint
  // and the genuinely-ready baseline surface.
  const health = responseValue(await runtime.coordinator.dispatch(
    requestFrame(FAMILY.DESCRIBE, OPERATION.DESCRIBE.CHALLENGE, blindHealthChallengeV1, {
      version: 1,
      descriptorSequence: 1n,
      descriptorHash: fixture.successorHash,
      endpointId: 1,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
      requestedRoleBits: PUBLIC_ROLE_BITS,
      requestedOperationBits: VNEXT_BASELINE_OPERATION_BITS,
      clientNonce: b4a.alloc(32, 0x13)
    }, 0x13), dispatchContext()), blindHealthResultV1)
  verifyResultSignature(t, blindHealthResultV1, health, RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT, relayPublicKey)
  t.is(health.descriptorSequence, 1n)
  t.ok(b4a.equals(health.descriptorHash, fixture.successorHash))
  t.is(health.clockState, HEALTH_CLOCK_STATE.READY, 'the manifested store reports a safe clock')
  t.is(health.integrityState, HEALTH_INTEGRITY_STATE.VERIFIED, 'the manifested store verifies fully')
  t.is(health.effectiveEpochFloor, descriptor.issuedEpoch)
  t.is(health.readyRoleBits, PUBLIC_ROLE_BITS)
  t.ok(health.readyOperationBits !== 0 && (health.readyOperationBits & ~VNEXT_BASELINE_OPERATION_BITS) === 0,
    'ready operations stay inside the baseline mask')

  // DESCRIBE.ADMISSION_PARAMETERS: the exact sealed parameter bytes.
  const parameters = await runtime.coordinator.dispatch(
    requestFrame(FAMILY.DESCRIBE, OPERATION.DESCRIBE.ADMISSION_PARAMETERS, blindAdmissionParametersRequestV1, {
      version: 1,
      profileId: 7,
      schemeId: 9,
      clientNonce: b4a.alloc(32, 0x14)
    }, 0x14), dispatchContext())
  const parametersBody = decodeDispatchFrame(parameters.dispatch, { copyBody: true }).body
  t.ok(b4a.equals(admissionParametersHash(parametersBody), fixture.parameterHash),
    'DESCRIBE.ADMISSION_PARAMETERS serves the exact sealed parameter set')

  // CELL.BATCH_GET: a signed baseline CELL result over absent slots (status 0
  // entries) through the real cell storage engine.
  const slots = [b4a.alloc(32, 0x91), b4a.alloc(32, 0x92)]
  const batch = responseValue(await runtime.coordinator.dispatch(
    requestFrame(FAMILY.CELL, OPERATION.CELL.BATCH_GET, batchGetV1, {
      version: 1,
      clientNonce: b4a.alloc(32, 0x15),
      slots,
      admission: null
    }, 0x15), dispatchContext()), batchGetResultV1)
  t.alike(batch.entries.map(entry => entry.status), [0, 0], 'both slots are honestly absent')
  t.ok(b4a.equals(batch.entriesCommitment, batchGetEntriesCommitment(batch.entries)),
    'the entries commitment binds the served page')
  verifyResultSignature(t, batchGetResultV1, batch, RESULT_SIGNATURE_DOMAIN_ID.BATCH_GET_RESULT, relayPublicKey)

  // CELL.GET: the same line fails closed honestly on a miss.
  const get = await runtime.coordinator.dispatch(
    requestFrame(FAMILY.CELL, OPERATION.CELL.GET, getCellV1, {
      version: 1,
      storageSlot: slots[0],
      clientNonce: b4a.alloc(32, 0x16),
      admission: null
    }, 0x16), dispatchContext())
  t.is(errorName(get), 'NOT_FOUND', 'CELL.GET serves an honest miss')

  // INBOX: CREATE -> APPEND -> READ, each a signed baseline result redeemed
  // through the sealed production admission adapter (VM bridge).
  const created0 = inboxCreateFixture(relayPublicKey, fixture.parameterHash, fixture.currentEpoch)
  const created = responseValue(await runtime.coordinator.dispatch(
    requestFrame(FAMILY.INBOX, OPERATION.INBOX.CREATE, inboxCreateV1, created0.request, 0x17),
    dispatchContext()), inboxReceiptV1)
  t.is(created.result, INBOX_RECEIPT_RESULT.CREATED)
  t.is(created.stateRevision, 0n)
  verifyResultSignature(t, inboxReceiptV1, created, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, relayPublicKey)
  t.is(runtime.inboxStorage.status().inboxCount, 1, 'the INBOX create is durable in the inbox store')

  const append = inboxAppendFixture(created0, relayPublicKey, fixture.parameterHash, 0xb3)
  const appended = responseValue(await runtime.coordinator.dispatch(
    requestFrame(FAMILY.INBOX, OPERATION.INBOX.APPEND, inboxAppendV1, append, 0x18),
    dispatchContext()), inboxAppendAckV1)
  t.is(appended.result, INBOX_APPEND_RESULT.STORED)
  t.is(appended.appendRevision, 1n)
  verifyResultSignature(t, inboxAppendAckV1, appended, RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK,
    relayPublicKey)

  const page = responseValue(await runtime.coordinator.dispatch(
    requestFrame(FAMILY.INBOX, OPERATION.INBOX.READ, inboxReadV1,
      inboxReadFixture(created0, fixture.parameterHash), 0x19), dispatchContext()), inboxReadResultV1)
  t.is(page.entries.length, 1, 'the appended frame is served')
  t.alike(page.entries[0].frame, append.frame)
  verifyInboxReadSignature(t, page, relayPublicKey)

  const missingInbox = await runtime.coordinator.dispatch(
    requestFrame(FAMILY.INBOX, OPERATION.INBOX.READ, inboxReadV1, {
      version: 1,
      physicalTopic: b4a.alloc(32, 0x93),
      cursor: b4a.alloc(0),
      limit: 1,
      clientNonce: b4a.alloc(32, 0x1a),
      admission: null
    }, 0x1a), dispatchContext())
  t.is(errorName(missingInbox), 'NOT_FOUND', 'INBOX.READ serves an honest miss')

  // CORE: MIRROR durably accepts its sponsorship with a signed acknowledgement
  // redeemed through the same sealed adapter; PROVE stays honest about the
  // unactivated upstream.
  const mirror = coreMirrorFixture(fixture.parameterHash)
  const mirrored = responseValue(await runtime.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.MIRROR, coreMirrorRequestV1, mirror, 0x1b),
    dispatchContext()), blindCoreAckV1)
  t.is(mirrored.result, CORE_ACK_RESULT.MIRROR_ACCEPTED)
  t.is(mirrored.length, mirror.length)
  verifyResultSignature(t, blindCoreAckV1, mirrored, RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK, relayPublicKey)
  t.is(runtime.coreStorage.inspectMirrorSpend(b4a.from(mirror.admission.token)).state, 'RETRY_PENDING',
    'the CORE sponsorship is durably pending in the core store')

  const prove = await runtime.coordinator.dispatch(
    requestFrame(FAMILY.CORE, OPERATION.CORE.PROVE, coreServeChallengeV1,
      coreProveFixture(mirror, fixture.parameterHash), 0x1c), dispatchContext())
  t.is(errorName(prove), 'NOT_FOUND', 'CORE.PROVE serves only an ACTIVE sponsored generation')

  await runtime.close()
})

test('vNext manifest floor persists across restart; a rolled-back descriptor fails closed', async t => {
  const fixture = await vnextSealedFixture({ functionalAdmission: true })
  t.teardown(() => cleanup(fixture.directory))
  await orchestrateVnextServingStore(fixture)

  let runtime = await assembleVnextRuntime(fixture)
  t.is(runtime.status().manifestFloor.descriptorSequenceFloor, 1n, 'the first boot enforces the sealed floor')
  const first = responseValue(await runtime.coordinator.dispatch(
    describeGetFrame(fixture.successorHash, 0x21), dispatchContext()), blindServiceDescriptorV1)
  t.is(first.descriptorSequence, 1n)
  await runtime.close()

  // Restart: the persisted two-slot manifest floor is restored and enforced
  // with zero baseline exclusions, and signed serving continues.
  runtime = await assembleVnextRuntime(fixture)
  t.teardown(() => runtime.close().catch(() => {}))
  const restarted = runtime.status()
  t.alike(BASELINE_COMPLETENESS_EXCLUSIONS.filter(name => restarted.exclusions.includes(name)), [],
    'the restart keeps zero baseline exclusions')
  t.is(restarted.manifestFloor.descriptorSequenceFloor, 1n, 'the persisted floor survives the restart')
  t.ok(b4a.equals(restarted.manifestFloor.descriptorHashFloor, fixture.successorHash))
  t.is(restarted.storage.state, 'READY', 'the manifested store recovers READY across the restart')
  const again = responseValue(await runtime.coordinator.dispatch(
    describeGetFrame(fixture.successorHash, 0x22), dispatchContext()), blindServiceDescriptorV1)
  t.is(again.descriptorSequence, 1n, 'the chain head keeps serving across the restart')
  verifyResultSignature(t, blindServiceDescriptorV1, again, RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
    fixture.relayPublicKey)
  await runtime.close()

  // A rolled-back descriptor (the genesis, sequence 0, below the persisted
  // floor 1) fails closed at the manifest floor.
  const rollbackEnvironment = {
    ...fixture.environment,
    HIVERELAY_BLIND_DESCRIPTOR_FILES: fixture.descriptorFile,
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE: '0',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: b4a.toString(fixture.genesisHash, 'hex')
  }
  const rollback = await failure(async () => {
    const rolled = await assembleVnextRuntime(fixture, rollbackEnvironment)
    await rolled.close()
  })
  t.is(rollback && rollback.code, 'BLIND_RUNTIME_DESCRIPTOR_FLOOR_ROLLBACK',
    'a descriptor below the persisted floor is a rollback, fail closed')
})

test('engine recovery fails closed on a tampered genesis floor record', async t => {
  const currentEpoch = Math.floor(Date.now() / SIX_HOURS_MILLIS)
  // Craft a store whose WAL first frame is a type-9 floor advance written by
  // the REAL BlindTransactionStore pipeline (identical framing/hash chain);
  // only the floor payload is adversarial. The serving cell engine's recovery
  // is what must reject or fence it.
  const craft = async (name, payload) => {
    const root = await fs.realpath(await fs.mkdtemp(path.join('/tmp', name)))
    await fs.chmod(root, 0o700)
    t.teardown(() => cleanup(root))
    const store = new BlindTransactionStore({
      root,
      mapGeneration: 1n,
      ownerFenceTokenHash: b4a.alloc(32, 0x72),
      durabilityContinuityHash: b4a.alloc(32, 0x61)
    })
    await store.open(async () => {})
    await store.append({
      type: 9,
      virtualBucket: 0,
      transactionId: blake2b256(b4a.concat([b4a.from('hiverelay.blind.floor-tamper-probe.v1', 'ascii'), payload])),
      payload
    })
    await store.close()
    return root
  }
  const openEngine = async root => {
    const engine = new BlindCellStorageEngine({
      root,
      relayPublicKey: b4a.alloc(32, 0x41),
      durabilityContinuityHash: b4a.alloc(32, 0x61),
      mapGeneration: 1n,
      ownerFenceTokenHash: b4a.alloc(32, 0x72)
    })
    await engine.open()
    return engine
  }

  // Wrong floor version: the payload is not a decodable floorTransitionV1, so
  // recovery rejects the store outright.
  const wrongVersion = b4a.from(floorAdvancePayloadV1(0, currentEpoch))
  wrongVersion[0] = 2
  const versionError = await failure(async () => openEngine(await craft('hr-vnext-t1-', wrongVersion)))
  t.ok(versionError instanceof BlindWalIntegrityError, 'a wrong floor version fails closed at recovery')
  t.ok(/version must be 1/.test(versionError.message), `version tamper explains itself (${versionError.message})`)

  // Wrong newEpochFloor ahead of the wall clock: the engine recovers the
  // foreign floor and fences the store CLOCK_UNSAFE — it never serves a
  // healthy READY store from the tampered record.
  const unsafe = await openEngine(await craft('hr-vnext-t2-', floorAdvancePayloadV1(0, currentEpoch + 1)))
  t.is(unsafe.status().state, 'CLOCK_UNSAFE', 'a foreign future floor fences the store, fail closed')
  t.is(unsafe.status().epochFloor, currentEpoch + 1, 'the fenced floor is the tampered value')
  await unsafe.close()

  // A floor transition that disagrees with the recovered floor is rejected as
  // a rollback/discontinuity.
  const discontinuity = await failure(async () => openEngine(await craft('hr-vnext-t3-', floorAdvancePayloadV1(1, currentEpoch))))
  t.ok(discontinuity instanceof BlindWalIntegrityError, 'a discontinuous floor fails closed at recovery')
  t.ok(/epoch floor rollback or discontinuity/.test(discontinuity.message),
    `discontinuity explains itself (${discontinuity.message})`)

  // Control: the exact floorTransitionV1 payload recovers READY, proving the
  // tamper harness itself is a valid store pipeline.
  const control = await openEngine(await craft('hr-vnext-ok-', floorAdvancePayloadV1(0, currentEpoch)))
  t.is(control.status().state, 'READY')
  t.is(control.status().epochFloor, currentEpoch)
  await control.close()
})

test('F-01: a serve against a pristine un-sealed root fails coded pre-mutation and leaves it pristine', async t => {
  const fixture = await vnextSealedFixture({ functionalAdmission: true })
  t.teardown(() => cleanup(fixture.directory))
  const storeRoot = fixture.environment.HIVERELAY_BLIND_STORE_ROOT

  // A requireManifestFloor serve against the pristine (un-sealed) root must fail
  // coded BEFORE any runtime-binding / WAL / generation-floor mutation.
  const serveError = await failure(() => assembleVnextRuntime(fixture))
  t.is(serveError && serveError.code, 'BLIND_RUNTIME_MANIFEST_REQUIRED',
    'a pristine un-sealed root is refused with the manifest-required coded error')

  // The root stays pristine: no runtime binding and no control directory (WAL,
  // generation-floor record, manifest slots) was written by the refused serve.
  t.alike(await fs.readdir(storeRoot), [], 'no runtime binding or store content was written')
  const controlStat = await failure(() => fs.lstat(path.join(storeRoot, 'control')))
  t.is(controlStat && controlStat.code, 'ENOENT', 'no control directory was created')

  // The later correct ceremony (bind -> genesis -> generation-floor bootstrap)
  // still succeeds on the same untouched root, and serving then assembles with
  // zero baseline exclusions.
  await orchestrateVnextServingStore(fixture)
  const runtime = await assembleVnextRuntime(fixture)
  t.teardown(() => runtime.close())
  const baselineExcluded = runtime.status().exclusions.filter(name =>
    BASELINE_COMPLETENESS_EXCLUSIONS.includes(name))
  t.alike(baselineExcluded, [], 'the correct ceremony then assembles with zero baseline exclusions')
})
