import test from 'brittle'
import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
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
  blindDescribeGetV1,
  blindErrorV1,
  blindHealthChallengeV1,
  blindHealthResultV1,
  blindServiceDescriptorV1,
  blake2b256,
  decodeCanonical,
  decodeDispatchFrame,
  encodeCanonical,
  inboxAppendAckV1,
  inboxAppendV1,
  inboxCreateV1,
  inboxReadEntriesCommitment,
  inboxReadResultV1,
  inboxReadSignaturePayloadV1,
  inboxReadV1,
  inboxReceiptV1,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import {
  BASELINE_COMPLETENESS_EXCLUSIONS,
  assembleProductionBlindDaemon,
  bindStoreIdentity,
  bootstrapVnextStoreGenerationFloor,
  encodeRuntimeBinding,
  loadProductionRuntimeConfig,
  productionReleaseGateFor
} from '../production-runtime.js'
import { DESCRIPTOR_CLOSED_REASON } from '../descriptor-state.js'
import {
  deriveVnextBucketMapHash,
  runVnextStoreGenesisCeremony
} from '../production-vnext-profile.js'
import { loadDaemonBootstrapConfig } from '../bootstrap-config.js'
import {
  loadProductionAdmissionAdapter,
  loadProductionEntrypointConfig
} from '../production-entrypoint.js'
import {
  inboxAppendFixture,
  inboxCreateFixture,
  inboxReadFixture
} from './production-runtime-inbox-fixture.js'
import { VNEXT_BASELINE_OPERATION_BITS, vnextSealedFixture } from './production-vnext-profile-fixture.js'

const SIX_HOURS_MILLIS = 6 * 60 * 60 * 1000
const PUBLIC_ROLE_BITS = ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY |
  ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER

async function cleanup (directory) {
  await fs.rm(directory, { recursive: true, force: true }).catch(() => {})
}

async function failure (run) {
  try {
    await run()
  } catch (error) {
    return error
  }
  return null
}

function signCanonical (codec, value, domainId, secretKey) {
  value.signature = b4a.alloc(sodium.crypto_sign_BYTES)
  const placeholder = encodeCanonical(codec, value)
  const unsigned = placeholder.subarray(0, placeholder.byteLength - sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(value.signature, resultSignaturePayload(domainId, unsigned), secretKey)
  return encodeCanonical(codec, value)
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

function describeGetFrame (descriptorHash, requestByte) {
  return requestFrame(FAMILY.DESCRIBE, OPERATION.DESCRIBE.GET, blindDescribeGetV1, {
    version: 1,
    descriptorHash,
    clientNonce: b4a.alloc(32, requestByte)
  }, requestByte)
}

function healthChallengeFrame (descriptorSequence, descriptorHash, requestByte) {
  return requestFrame(FAMILY.DESCRIBE, OPERATION.DESCRIBE.CHALLENGE, blindHealthChallengeV1, {
    version: 1,
    descriptorSequence,
    descriptorHash,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: PUBLIC_ROLE_BITS,
    requestedOperationBits: VNEXT_BASELINE_OPERATION_BITS,
    clientNonce: b4a.alloc(32, requestByte)
  }, requestByte)
}

// The same bind -> store-genesis ceremony -> generation-floor bootstrap
// orchestration the accepted vNext serving e2e drives, parameterized on the
// chain link the floor is sealed at (the manifest floor always binds one exact
// chain head). Key copies read here are zeroed before returning.
async function orchestrateVnextServingStore (fixture, headDescriptorFile = fixture.successorDescriptorFile) {
  const environment = fixture.environment
  const storeRoot = environment.HIVERELAY_BLIND_STORE_ROOT
  const manifestKey = await fs.readFile(environment.HIVERELAY_BLIND_STORE_MANIFEST_KEY_FILE)
  const ownerFenceTokenHash = await fs.readFile(environment.HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE)
  try {
    const descriptorCanonicalBytes = await fs.readFile(headDescriptorFile)
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
    const floor = await bootstrapVnextStoreGenerationFloor({
      storeRoot, descriptor, manifestKey, ownerFenceTokenHash, mapGeneration
    })
    return Object.freeze({ descriptor, descriptorCanonicalBytes, binding, bound, ceremony, floor })
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

async function flipByte (file) {
  const bytes = await fs.readFile(file)
  bytes[Math.floor(bytes.byteLength / 2)] ^= 0xff
  await fs.writeFile(file, bytes, { mode: 0o600 })
}

function currentWallEpoch () {
  return Math.floor(Date.now() / SIX_HOURS_MILLIS)
}

// ---------------------------------------------------------------------------
// FLEET-DURABILITY-P1-1 boot-restore regression suite. Every scenario runs the
// GENUINE production boot (release gate + assembly, no seams) against a real
// sealed store under /tmp. The chain windows pin expired historical links
// behind a fresh head without any clock seam: genesis/middle windows lapse
// relative to the wall clock exactly like syd-1's did at the drill.

// (a) The FLEET-DURABILITY-P1-1 scenario end-to-end: an advanced chain whose
// genesis AND middle links are expired, an intact store, and a MAC-verified
// floor at the fresh head -> the daemon boots healthy from the floor, serves,
// and the floor persists across a restart. This exact scenario failed closed
// 'descriptor is expired' before the restore wiring.
test('FLEET-DURABILITY-P1-1: expired genesis + intact sealed store boots from the MAC-verified floor and serves', async t => {
  const fixture = await vnextSealedFixture({
    functionalAdmission: true,
    chainWindows: [[-6, -2], [-4, -1], [-2, 2]]
  })
  t.teardown(() => cleanup(fixture.directory))
  const { descriptor } = await orchestrateVnextServingStore(fixture)

  const nowEpoch = currentWallEpoch()
  const genesis = decodeCanonical(blindServiceDescriptorV1, await fs.readFile(fixture.chainFiles[0]))
  const middle = decodeCanonical(blindServiceDescriptorV1, await fs.readFile(fixture.chainFiles[1]))
  t.ok(genesis.expiresEpoch <= nowEpoch, 'the genesis link is expired (the drill precondition)')
  t.ok(middle.expiresEpoch <= nowEpoch, 'the middle historical link is expired too')
  t.ok(descriptor.issuedEpoch <= nowEpoch && descriptor.expiresEpoch > nowEpoch,
    'the chain head is inside its window')

  const runtime = await assembleVnextRuntime(fixture)
  t.teardown(() => runtime.close().catch(() => {}))
  const status = runtime.status()
  t.is(status.descriptorRestoredFromFloor, true, 'the boot restored from the MAC-verified floor')
  t.is(status.descriptorSequence, 2n, 'the restored head is the chain head')
  t.ok(b4a.equals(status.descriptorHash, fixture.chainHashes[2]))
  t.is(status.manifestFloor.descriptorSequenceFloor, 2n, 'the enforced floor is the chain head')
  t.ok(b4a.equals(status.manifestFloor.descriptorHashFloor, fixture.chainHashes[2]))
  t.is(status.storage.state, 'READY', 'the intact store recovers READY')
  t.alike(BASELINE_COMPLETENESS_EXCLUSIONS.filter(name => status.exclusions.includes(name)), [],
    'zero baseline exclusions survive the restored assembly')

  // DESCRIBE.GET serves the head and both retained expired historical links:
  // expiry supersedes freshness only behind the floor, never continuity.
  const head = responseValue(await runtime.coordinator.dispatch(
    describeGetFrame(fixture.chainHashes[2], 0x11), dispatchContext()), blindServiceDescriptorV1)
  t.is(head.descriptorSequence, 2n, 'DESCRIBE.GET serves the chain head')
  verifyResultSignature(t, blindServiceDescriptorV1, head, RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
    fixture.relayPublicKey)
  for (const [sequence, requestByte] of [[0n, 0x12], [1n, 0x13]]) {
    const history = responseValue(await runtime.coordinator.dispatch(
      describeGetFrame(fixture.chainHashes[Number(sequence)], requestByte), dispatchContext()),
    blindServiceDescriptorV1)
    t.is(history.descriptorSequence, sequence, `the expired seq-${sequence} link stays served as history`)
    verifyResultSignature(t, blindServiceDescriptorV1, history, RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
      fixture.relayPublicKey)
  }

  // Readiness: the restored snapshot carries fullStoreVerificationRequired and
  // the live recovered store verifies, so the daemon reports READY.
  const health = responseValue(await runtime.coordinator.dispatch(
    healthChallengeFrame(2n, fixture.chainHashes[2], 0x14), dispatchContext()), blindHealthResultV1)
  verifyResultSignature(t, blindHealthResultV1, health, RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT,
    fixture.relayPublicKey)
  t.is(health.descriptorSequence, 2n)
  t.is(health.clockState, HEALTH_CLOCK_STATE.READY, 'the restored boot reports a safe clock')
  t.is(health.integrityState, HEALTH_INTEGRITY_STATE.VERIFIED,
    'the restored boot reports the live store fully verified')
  t.ok(health.readyOperationBits !== 0 && (health.readyOperationBits & ~VNEXT_BASELINE_OPERATION_BITS) === 0,
    'ready operations stay inside the baseline mask')

  // Durable serving: INBOX CREATE -> APPEND -> READ, signed and redeemed
  // through the sealed production admission adapter.
  const created0 = inboxCreateFixture(fixture.relayPublicKey, fixture.parameterHash, fixture.currentEpoch)
  const created = responseValue(await runtime.coordinator.dispatch(
    requestFrame(FAMILY.INBOX, OPERATION.INBOX.CREATE, inboxCreateV1, created0.request, 0x15),
    dispatchContext()), inboxReceiptV1)
  t.is(created.result, INBOX_RECEIPT_RESULT.CREATED)
  verifyResultSignature(t, inboxReceiptV1, created, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT,
    fixture.relayPublicKey)
  const append = inboxAppendFixture(created0, fixture.relayPublicKey, fixture.parameterHash, 0xb3)
  const appended = responseValue(await runtime.coordinator.dispatch(
    requestFrame(FAMILY.INBOX, OPERATION.INBOX.APPEND, inboxAppendV1, append, 0x16),
    dispatchContext()), inboxAppendAckV1)
  t.is(appended.result, INBOX_APPEND_RESULT.STORED)
  verifyResultSignature(t, inboxAppendAckV1, appended, RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK,
    fixture.relayPublicKey)
  const page = responseValue(await runtime.coordinator.dispatch(
    requestFrame(FAMILY.INBOX, OPERATION.INBOX.READ, inboxReadV1,
      inboxReadFixture(created0, fixture.parameterHash), 0x17), dispatchContext()), inboxReadResultV1)
  t.is(page.entries.length, 1, 'the appended frame is served after the restored boot')
  verifyInboxReadSignature(t, page, fixture.relayPublicKey)
  await runtime.close()

  // Restart again from the same sealed state: the restore is stable and the
  // floor persists untouched.
  const restarted = await assembleVnextRuntime(fixture)
  t.teardown(() => restarted.close().catch(() => {}))
  const again = restarted.status()
  t.is(again.descriptorRestoredFromFloor, true, 'the restart restores from the floor again')
  t.is(again.manifestFloor.descriptorSequenceFloor, 2n, 'the floor persists across the restored restart')
  t.ok(b4a.equals(again.manifestFloor.descriptorHashFloor, fixture.chainHashes[2]))
  const served = responseValue(await restarted.coordinator.dispatch(
    describeGetFrame(fixture.chainHashes[2], 0x18), dispatchContext()), blindServiceDescriptorV1)
  t.is(served.descriptorSequence, 2n, 'the head keeps serving across the restart')
  await restarted.close()
})

// (b) An expired HEAD fails closed — the restore supersedes freshness only
// behind the MAC-verified floor, never at the chain head.
test('boot restore: an expired HEAD still fails closed', async t => {
  // Fresh genesis, expired head: plain activation dies EXPIRED at the head and
  // the restored state closes EXPIRED at requireCurrent().
  const freshGenesis = await vnextSealedFixture({ chainWindows: [[-2, 2], [-1, 0]] })
  t.teardown(() => cleanup(freshGenesis.directory))
  await orchestrateVnextServingStore(freshGenesis)
  const headError = await failure(() => assembleVnextRuntime(freshGenesis))
  t.is(headError && headError.code, DESCRIPTOR_CLOSED_REASON.EXPIRED,
    'a fresh-genesis chain with an expired head fails closed')

  // Expired genesis AND expired head: the restore runs and still closes
  // EXPIRED at the head.
  const expiredGenesis = await vnextSealedFixture({ chainWindows: [[-5, -2], [-3, -1]] })
  t.teardown(() => cleanup(expiredGenesis.directory))
  await orchestrateVnextServingStore(expiredGenesis)
  const bothError = await failure(() => assembleVnextRuntime(expiredGenesis))
  t.is(bothError && bothError.code, DESCRIPTOR_CLOSED_REASON.EXPIRED,
    'an expired-genesis chain with an expired head fails closed through the restore')
})

// (c) A forked chain fails closed: the persisted floor is not a link of the
// configured fork, even when the fork is same-key, continuous and fresh.
test('boot restore: a forked descriptor chain fails closed', async t => {
  const fixture = await vnextSealedFixture({ chainWindows: [[-5, -2], [-3, 1]] })
  t.teardown(() => cleanup(fixture.directory))
  await orchestrateVnextServingStore(fixture)

  // A same-sequence fork of the genuine seq-1 head: identical continuity and a
  // valid signature under the relay key, but a different nonce/window — never
  // the link the MAC-verified floor pins.
  const relaySecretKey = await fs.readFile(fixture.environment.HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE)
  const fork = decodeCanonical(blindServiceDescriptorV1, await fs.readFile(fixture.successorDescriptorFile),
    { copyBytes: true })
  fork.descriptorNonce = b4a.alloc(32, 0x99)
  fork.expiresEpoch = fixture.currentEpoch + 1
  const forkBytes = signCanonical(blindServiceDescriptorV1, fork,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)
  relaySecretKey.fill(0)
  const forkFile = path.join(fixture.directory, 'descriptor-fork.bin')
  await fs.writeFile(forkFile, forkBytes, { mode: 0o600 })
  const forkHash = serviceDescriptorHash(forkBytes)
  const forkEnvironment = {
    ...fixture.environment,
    HIVERELAY_BLIND_DESCRIPTOR_FILES: `${fixture.descriptorFile},${forkFile}`,
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: b4a.toString(forkHash, 'hex')
  }
  const forkError = await failure(() => assembleVnextRuntime(fixture, forkEnvironment))
  t.is(forkError && forkError.code, DESCRIPTOR_CLOSED_REASON.RESTORE_UNVERIFIED,
    'a configured fork that does not contain the persisted floor fails closed')

  // Control: the genuine chain still restores and boots on the same store.
  const runtime = await assembleVnextRuntime(fixture)
  t.teardown(() => runtime.close().catch(() => {}))
  t.is(runtime.status().descriptorRestoredFromFloor, true, 'the genuine chain restores on the same store')
  await runtime.close()
})

// (d) A rolled-back descriptor fails closed: a configured chain shorter than
// the persisted floor can never contain the floor.
test('boot restore: a rolled-back descriptor fails closed', async t => {
  const fixture = await vnextSealedFixture({ chainWindows: [[-5, -2], [-3, 1]] })
  t.teardown(() => cleanup(fixture.directory))
  await orchestrateVnextServingStore(fixture)
  const rollbackEnvironment = {
    ...fixture.environment,
    HIVERELAY_BLIND_DESCRIPTOR_FILES: fixture.descriptorFile,
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE: '0',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: b4a.toString(fixture.genesisHash, 'hex')
  }
  const rollback = await failure(() => assembleVnextRuntime(fixture, rollbackEnvironment))
  t.is(rollback && rollback.code, DESCRIPTOR_CLOSED_REASON.RESTORE_UNVERIFIED,
    'a chain below the persisted floor is a rollback, fail closed')
})

// (e) A valid fresh head whose floor does not match fails closed: the sealed
// manifest belongs to another relay/store identity, so the launch bindings
// reject it before any restore evidence is accepted.
test('boot restore: a foreign store floor fails closed (floor/head mismatch)', async t => {
  const owner = await vnextSealedFixture({ chainWindows: [[-5, -2], [-3, 1]] })
  t.teardown(() => cleanup(owner.directory))
  await orchestrateVnextServingStore(owner)
  const foreign = await vnextSealedFixture({ chainWindows: [[-5, -2], [-3, 1]] })
  t.teardown(() => cleanup(foreign.directory))
  const mismatched = await failure(() => assembleVnextRuntime(foreign, {
    ...foreign.environment,
    HIVERELAY_BLIND_STORE_ROOT: owner.environment.HIVERELAY_BLIND_STORE_ROOT
  }))
  t.is(mismatched && mismatched.code, 'BLIND_RUNTIME_MANIFEST_REQUIRED',
    'a manifest sealed for another relay/store fails closed against this chain')
})

// (f) A tampered store fails closed — at the manifest MAC layer, at the
// runtime binding MAC layer, and at the data-plane recovery layer (the restore
// never substitutes control-plane evidence for store recovery integrity).
test('boot restore: a tampered store fails closed', async t => {
  // Manifest slot MAC tamper (both slots): the two-slot load finds no valid
  // slot and the boot fails closed before any restore.
  const manifestTamper = await vnextSealedFixture({ chainWindows: [[-5, -2], [-3, 1]] })
  t.teardown(() => cleanup(manifestTamper.directory))
  await orchestrateVnextServingStore(manifestTamper)
  const controlDirectory = path.join(manifestTamper.environment.HIVERELAY_BLIND_STORE_ROOT, 'control')
  await flipByte(path.join(controlDirectory, 'manifest-a.v1'))
  await flipByte(path.join(controlDirectory, 'manifest-b.v1'))
  const manifestError = await failure(() => assembleVnextRuntime(manifestTamper))
  t.is(manifestError && manifestError.code, 'BLIND_RUNTIME_MANIFEST_REQUIRED',
    'a MAC-tampered manifest fails closed')

  // Runtime store binding tamper: the root-level MAC no longer verifies.
  const bindingTamper = await vnextSealedFixture({ chainWindows: [[-5, -2], [-3, 1]] })
  t.teardown(() => cleanup(bindingTamper.directory))
  await orchestrateVnextServingStore(bindingTamper)
  await flipByte(path.join(bindingTamper.environment.HIVERELAY_BLIND_STORE_ROOT, 'runtime-binding.v1'))
  const bindingError = await failure(() => assembleVnextRuntime(bindingTamper))
  t.is(bindingError && bindingError.code, 'BLIND_RUNTIME_STORE_IDENTITY_MISMATCH',
    'a tampered runtime store binding fails closed')

  // WAL tamper with the control plane intact: the floor restore itself
  // verifies, then the unchanged engine recovery / generation-floor layers
  // fail the boot before anything serves.
  const walTamper = await vnextSealedFixture({ chainWindows: [[-5, -2], [-3, 1]] })
  t.teardown(() => cleanup(walTamper.directory))
  await orchestrateVnextServingStore(walTamper)
  await flipByte(path.join(walTamper.environment.HIVERELAY_BLIND_STORE_ROOT, 'control', 'wal.v2'))
  const walError = await failure(() => assembleVnextRuntime(walTamper))
  t.ok(walError != null, 'a WAL-tampered store fails the boot')
  t.ok(!(walError && walError.code === DESCRIPTOR_CLOSED_REASON.EXPIRED),
    `the WAL tamper fails at the store layer, not the descriptor layer (${walError && (walError.code || walError.message)})`)
})

// (g) The first boot of a fresh store with an expired genesis still fails
// closed: there is no floor to restore from, and the pristine root is not
// mutated by the refused boot.
test('boot restore: a fresh store with an expired genesis fails closed pristine', async t => {
  const fixture = await vnextSealedFixture({ chainWindows: [[-5, -2], [-3, 1]] })
  t.teardown(() => cleanup(fixture.directory))
  const storeRoot = fixture.environment.HIVERELAY_BLIND_STORE_ROOT
  const serveError = await failure(() => assembleVnextRuntime(fixture))
  t.is(serveError && serveError.code, 'BLIND_RUNTIME_MANIFEST_REQUIRED',
    'no floor exists on a fresh store, so the expired genesis stays terminal')
  t.alike(await fs.readdir(storeRoot), [], 'the refused restore mutated nothing')
  const controlStat = await failure(() => fs.lstat(path.join(storeRoot, 'control')))
  t.is(controlStat && controlStat.code, 'ENOENT', 'no control directory was created')
})

// (h) The restart cycle is self-sustaining: boot from the floor, refresh the
// chain (the floor advance persists through the normal enforcement), restart
// again — every boot restores against the new floor regardless of genesis age.
test('boot restore: boot -> refresh chain -> restart is self-sustaining', async t => {
  const fixture = await vnextSealedFixture({
    functionalAdmission: true,
    chainWindows: [[-6, -2], [-4, -1], [-2, 2], [-1, 3]]
  })
  t.teardown(() => cleanup(fixture.directory))
  // Seal the floor at seq-2; the seq-3 link is the later refresh.
  await orchestrateVnextServingStore(fixture, fixture.chainFiles[2])
  const environmentFor = headIndex => ({
    ...fixture.environment,
    HIVERELAY_BLIND_DESCRIPTOR_FILES: fixture.chainFiles.slice(0, headIndex + 1).join(','),
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE: String(headIndex),
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: b4a.toString(fixture.chainHashes[headIndex], 'hex')
  })

  // Boot 1: restore against the seq-2 floor behind the expired genesis.
  let runtime = await assembleVnextRuntime(fixture, environmentFor(2))
  t.teardown(() => runtime.close().catch(() => {}))
  let status = runtime.status()
  t.is(status.descriptorRestoredFromFloor, true, 'boot 1 restores from the seq-2 floor')
  t.is(status.manifestFloor.descriptorSequenceFloor, 2n)
  const first = responseValue(await runtime.coordinator.dispatch(
    describeGetFrame(fixture.chainHashes[2], 0x21), dispatchContext()), blindServiceDescriptorV1)
  t.is(first.descriptorSequence, 2n, 'boot 1 serves the seq-2 head')
  await runtime.close()

  // Boot 2: the seq-3 refresh activates on top of the restored floor (full
  // wall-clock checks on the post-floor link), and the floor advance persists.
  runtime = await assembleVnextRuntime(fixture, environmentFor(3))
  status = runtime.status()
  t.is(status.descriptorRestoredFromFloor, true, 'boot 2 restores through the seq-2 floor to the refresh')
  t.is(status.descriptorSequence, 3n, 'boot 2 heads the refreshed chain')
  t.is(status.manifestFloor.descriptorSequenceFloor, 3n, 'the floor advance to seq-3 persists')
  t.ok(b4a.equals(status.manifestFloor.descriptorHashFloor, fixture.chainHashes[3]))
  const refreshed = responseValue(await runtime.coordinator.dispatch(
    describeGetFrame(fixture.chainHashes[3], 0x22), dispatchContext()), blindServiceDescriptorV1)
  t.is(refreshed.descriptorSequence, 3n, 'boot 2 serves the refreshed head')
  verifyResultSignature(t, blindServiceDescriptorV1, refreshed, RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
    fixture.relayPublicKey)
  await runtime.close()

  // Boot 3: the refreshed floor is now the restore checkpoint; the relay boots
  // again from it with zero baseline exclusions.
  runtime = await assembleVnextRuntime(fixture, environmentFor(3))
  status = runtime.status()
  t.is(status.descriptorRestoredFromFloor, true, 'boot 3 restores from the refreshed seq-3 floor')
  t.is(status.manifestFloor.descriptorSequenceFloor, 3n, 'the refreshed floor persists')
  t.alike(BASELINE_COMPLETENESS_EXCLUSIONS.filter(name => status.exclusions.includes(name)), [],
    'the self-sustaining cycle keeps zero baseline exclusions')
  const served = responseValue(await runtime.coordinator.dispatch(
    describeGetFrame(fixture.chainHashes[3], 0x23), dispatchContext()), blindServiceDescriptorV1)
  t.is(served.descriptorSequence, 3n, 'boot 3 keeps serving the refreshed head')
  await runtime.close()
})

// Sanity: the error surface for a miss stays honest on a restored boot.
test('boot restore: restored serving keeps honest error surfaces', async t => {
  const fixture = await vnextSealedFixture({ chainWindows: [[-5, -2], [-3, 1]] })
  t.teardown(() => cleanup(fixture.directory))
  await orchestrateVnextServingStore(fixture)
  const runtime = await assembleVnextRuntime(fixture)
  t.teardown(() => runtime.close().catch(() => {}))
  const missing = await runtime.coordinator.dispatch(
    describeGetFrame(b4a.alloc(32, 0x77), 0x31), dispatchContext())
  t.is(errorName(missing), 'NOT_FOUND', 'an unknown descriptor hash is an honest miss')
  await runtime.close()
})
