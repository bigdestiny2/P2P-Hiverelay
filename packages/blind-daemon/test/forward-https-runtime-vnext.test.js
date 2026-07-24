// Daemon-side evidence for the vNext direct-HTTPS runtime (relock
// activation serial integration). DESCRIBE section: the signed health
// challenge path with degraded and failed dependency integrity, descriptor
// fork/rollback fault behavior, and health result signature binding. Later
// sections cover CELL, INBOX, CORE and the FORWARD one-hop runtime against
// the accepted storage layer. macOS environment: peercred is real
// (getpeereid); Linux SO_PEERCRED, Chromium/IndexedDB and Bare are deferred
// to syd-1 qualification and recorded in the lane evidence.

import test from 'brittle'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ADVERTISED_OPERATION_BITS,
  CLOCK_UNSAFE_OPERATION_BITS,
  HEALTH_CLOCK_STATE,
  HEALTH_INTEGRITY_STATE,
  HEALTH_REBALANCE_STATE,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_SUPPORT,
  allocationCommitment,
  assertForwardHttpsResultForOriginRequestV1,
  blake2b256,
  blindErrorV1,
  blindForwardHttpsOriginForwardTurnRequestV1,
  blindForwardHttpsOriginForwardTurnResultV1,
  blindHealthResultV1,
  blindReceiptV1,
  cellStorageSlot,
  decodeCanonical,
  encodeCanonical,
  forwardHttpsOriginRequestCommitmentV1,
  forwardHttpsStableSessionIdV1,
  forwardHttpsTargetResultChainHashV1,
  putCellV1,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import { decodeDispatchFrame } from '@hiverelay/blind-protocol/dispatch'
import {
  createLocalForwardHttpsOriginAuthorityV4,
  createLocalForwardHttpsTargetIngressV4,
  decodeLocalForwardHttpsTurnV4,
  encodeLocalForwardHttpsSourceOriginTranscriptV4,
  encodeLocalForwardHttpsTargetIngressV4
} from '@hiverelay/blind-ipc'
import {
  forwardHttpsSourceTurnStateV3
} from '../forward-https-source-store-v3.js'
import {
  forwardHttpsTargetTurnStateV3
} from '../forward-https-target-store-v3.js'
import {
  inspectForwardHttpsReplayJournalV4
} from '../forward-https-replay-journal-v4.js'
import {
  DESCRIPTOR_CLOSED_REASON,
  DESCRIPTOR_STATE_KIND,
  DescriptorState
} from '../descriptor-state.js'
import {
  READINESS_STATE_KIND,
  ReadinessCoordinator
} from '../readiness-coordinator.js'
import {
  PINNED_LAUNCH_TOPOLOGY_HASH,
  PINNED_WIRE_V3_ABI_HASH,
  createRelayIdentityFixture,
  createRelayEnvironmentFixture,
  assembleRelayFixture,
  fixtureAdmission,
  removeFixtureScratch,
  signCanonicalFixture
} from '../../blind-edge/test/forward-https-vnext-integration-fixture.mjs'
import {
  DescriptorTrustStore,
  MemoryDescriptorTrustBackend,
  createHealthChallenge,
  verifyDescriptorBytes,
  verifyHealthResultBytes
} from '../../blind-client/describe.js'
import { createNodeCryptoRuntime } from '../../blind-client/runtime/node.js'

const runtime = createNodeCryptoRuntime()

function verifyDetached (input) {
  try {
    return Promise.resolve(sodium.crypto_sign_verify_detached(input.signature, input.payload, input.publicKey))
  } catch {
    return Promise.resolve(false)
  }
}

function relaySigner (secretKey, publicKey) {
  return Object.freeze({
    async sign (input) {
      if (!b4a.equals(input.publicKey, publicKey)) {
        const error = new Error('signing key mismatch')
        error.code = 'BLIND_RUNTIME_SIGNING_REFUSED'
        throw error
      }
      const signature = b4a.alloc(64)
      sodium.crypto_sign_detached(signature, input.payload, secretKey)
      return signature
    },
    async verify (input) {
      return sodium.crypto_sign_verify_detached(input.signature, input.payload, input.publicKey)
    },
    close () {
      secretKey.fill(0)
    }
  })
}

async function activatedDescriptorState (identity) {
  const descriptorState = new DescriptorState({ verifySignature: verifyDetached })
  await descriptorState.activate(identity.genesisBytes)
  const snapshot = await descriptorState.activate(identity.successorBytes)
  return { descriptorState, snapshot }
}

function dependencyFields (identity, snapshot, overrides = {}) {
  return {
    selfVerified: true,
    descriptorSequence: snapshot.descriptorSequence,
    descriptorHash: b4a.from(snapshot.hash),
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    fullStoreVerified: true,
    readyRoleBits: 0x31,
    readyOperationBits: ADVERTISED_OPERATION_BITS,
    clockState: HEALTH_CLOCK_STATE.READY,
    effectiveEpochFloor: identity.currentEpoch,
    integrityState: HEALTH_INTEGRITY_STATE.VERIFIED,
    checkpointAgeBand: 0,
    scrubAgeBand: 0,
    rebalanceState: HEALTH_REBALANCE_STATE.STABLE,
    capacityBand: 0,
    ...overrides
  }
}

function readinessFor (identity, descriptorState, snapshot, overrides = {}) {
  return new ReadinessCoordinator({
    descriptorState,
    admission: {
      descriptorProfilesReady: () => true,
      descriptorParametersAvailable: () => true
    },
    dependencySnapshot: async () => dependencyFields(identity, snapshot, overrides),
    signer: relaySigner(b4a.from(identity.relaySecretKey), identity.relayPublicKey)
  })
}

function challengeFor (snapshot, overrides = {}) {
  return {
    version: 1,
    descriptorSequence: snapshot.descriptorSequence,
    descriptorHash: b4a.from(snapshot.hash),
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 0x31,
    requestedOperationBits: ADVERTISED_OPERATION_BITS,
    clientNonce: b4a.alloc(32, 0xc1),
    ...overrides
  }
}

test('daemon descriptor state faults closed on same-sequence fork and on rollback', async t => {
  const identity = await createRelayIdentityFixture()
  const { descriptorState, snapshot } = await activatedDescriptorState(identity)
  t.is(snapshot.descriptorSequence, 1n)
  t.is(descriptorState.state().kind, DESCRIPTOR_STATE_KIND.READY)

  // Rollback: re-activating the genesis after the successor faults ROLLBACK.
  let rollbackError = null
  try {
    await descriptorState.activate(identity.genesisBytes)
  } catch (error) {
    rollbackError = error
  }
  t.is(rollbackError && rollbackError.code, DESCRIPTOR_CLOSED_REASON.ROLLBACK)
  t.is(descriptorState.state().kind, DESCRIPTOR_STATE_KIND.CLOSED, 'rollback fault is sticky closed')

  // Fork: a fresh state, then a same-sequence different-hash successor.
  const forked = decodeCanonical((await import('@hiverelay/blind-protocol')).blindServiceDescriptorV1,
    identity.successorBytes, { copyBytes: true })
  forked.descriptorNonce = b4a.alloc(32, 0x91)
  const forkedBytes = signCanonicalFixture(
    (await import('@hiverelay/blind-protocol')).blindServiceDescriptorV1, forked,
    (await import('@hiverelay/blind-protocol')).RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, identity.relaySecretKey)
  const second = new DescriptorState({ verifySignature: verifyDetached })
  await second.activate(identity.genesisBytes)
  await second.activate(identity.successorBytes)
  let forkError = null
  try {
    await second.activate(forkedBytes)
  } catch (error) {
    forkError = error
  }
  t.is(forkError && forkError.code, DESCRIPTOR_CLOSED_REASON.FORK)
  t.is(second.state().kind, DESCRIPTOR_STATE_KIND.CLOSED, 'fork fault is sticky closed')
})

test('signed health result binds the current descriptor; failed integrity degrades readiness to DESCRIBE only', async t => {
  const identity = await createRelayIdentityFixture()
  const { descriptorState, snapshot } = await activatedDescriptorState(identity)

  // Positive: verified integrity yields the full advertised operation set.
  const healthy = readinessFor(identity, descriptorState, snapshot)
  const evaluated = await healthy.evaluate({ endpointId: 1, transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP })
  t.is(evaluated.kind, READINESS_STATE_KIND.READY)
  t.is(evaluated.readyOperationBits, ADVERTISED_OPERATION_BITS)
  const result = await healthy.healthResult(challengeFor(snapshot), {
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  const value = decodeCanonical(blindHealthResultV1, result.canonicalBytes, { copyBytes: true })
  t.ok(b4a.equals(value.descriptorHash, snapshot.hash), 'health result binds the exact descriptor hash')
  t.is(value.descriptorSequence, snapshot.descriptorSequence)
  t.ok(sodium.crypto_sign_verify_detached(
    value.signature,
    (await import('@hiverelay/blind-protocol')).resultSignaturePayload(
      (await import('@hiverelay/blind-protocol')).RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT,
      result.canonicalBytes.subarray(0, result.canonicalBytes.byteLength - 64)),
    identity.relayPublicKey), 'health result signature verifies under the relay key')

  // Client-side verification of the same signed result through the exact
  // challenge correlation.
  const trust = new DescriptorTrustStore(new MemoryDescriptorTrustBackend())
  const profiles = {
    nowEpoch: identity.currentEpoch,
    supportedProtocolProfiles: identity.descriptor.protocols.map(entry => ({
      protocolId: entry.protocolId,
      major: entry.major,
      minimumMinor: entry.minor,
      profileHash: b4a.from(entry.profileHash)
    })),
    supportedTransportProfiles: identity.descriptor.endpoints.map(entry => ({
      transportId: entry.transportId,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
      transportProfileHash: b4a.from(entry.transportProfileHash)
    }))
  }
  await trust.accept(verifyDescriptorBytes(identity.genesisBytes, profiles), {
    pinnedDescriptorHash: identity.genesisHash
  })
  const trusted = await trust.accept(verifyDescriptorBytes(identity.successorBytes, profiles), {
    continuityRootRelayPublicKey: identity.relayPublicKey
  })
  const challenge = createHealthChallenge({
    trustedDescriptor: trusted,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 0x31,
    requestedOperationBits: ADVERTISED_OPERATION_BITS,
    runtime
  })
  const served = await healthy.healthResult(challenge.request, {
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
  })
  const health = verifyHealthResultBytes(served.canonicalBytes, trusted, challenge.request, {
    nowEpoch: identity.currentEpoch
  })
  t.is(health.readyOperationBits, ADVERTISED_OPERATION_BITS)

  // Failed integrity: the same coordinator reports readiness collapsed to
  // the required DESCRIBE subset (failing health).
  const failed = readinessFor(identity, descriptorState, snapshot, {
    integrityState: HEALTH_INTEGRITY_STATE.FAILED
  })
  const degraded = await failed.evaluate({ endpointId: 1, transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP })
  t.is(degraded.kind, READINESS_STATE_KIND.READY)
  t.is(degraded.readyOperationBits, 0x7, 'failed integrity degrades health to the DESCRIBE subset')
  t.is(degraded.readyOperationBits & ~0x7, 0, 'no non-DESCRIBE operation survives failed integrity')

  // Unsafe clock strips the clock-unsafe operation subset (degraded health).
  const unsafe = readinessFor(identity, descriptorState, snapshot, {
    clockState: HEALTH_CLOCK_STATE.VERIFYING
  })
  const clockDegraded = await unsafe.evaluate({ endpointId: 1, transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP })
  t.is(clockDegraded.kind, READINESS_STATE_KIND.READY)
  t.is(clockDegraded.readyOperationBits & CLOCK_UNSAFE_OPERATION_BITS, 0,
    'unsafe clock strips the clock-unsafe operations')

  // Bogus challenge credentials fail closed at the coordinator boundary.
  let bogusError = null
  try {
    await healthy.healthResult(challengeFor(snapshot, { descriptorHash: b4a.alloc(32, 0xaa) }), {
      endpointId: 1,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
    })
  } catch (error) {
    bogusError = error
  }
  t.is(bogusError && bogusError.code, 'BAD_ENCODING', 'bogus descriptor hash fails closed')
  let wrongEndpoint = null
  try {
    await healthy.healthResult(challengeFor(snapshot, { endpointId: 2 }), {
      endpointId: 1,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
    })
  } catch (error) {
    wrongEndpoint = error
  }
  t.is(wrongEndpoint && wrongEndpoint.code, 'BAD_ENCODING', 'challenge endpoint must match the accepted channel')
})

// ---------------------------------------------------------------------------
// CELL route daemon evidence (serial route 2/5): unary dispatch through the
// accepted coordinator into the accepted cell storage engine.
// ---------------------------------------------------------------------------

test('daemon CELL.PUT dispatch signs STORED and persists an exact fixed-size cell', async t => {
  const identity = await createRelayIdentityFixture({ port: 61280 })
  const layout = await createRelayEnvironmentFixture(identity)
  const replayOffset = { value: -15_000n }
  const relay = await assembleRelayFixture(identity, layout, {
    replayJournalOptions: { monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset.value }
  })
  replayOffset.value = 0n
  await relay.start()
  t.teardown(async () => {
    await relay.close().catch(() => {})
    await removeFixtureScratch(layout)
  })

  const keys = [0, 1, 2].map(() => {
    const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
    sodium.crypto_sign_keypair(publicKey, secretKey)
    return { publicKey, secretKey }
  })
  const allocationEpoch = relay.unary.storage.status().epochFloor
  const cellBlob = b4a.alloc(4096, 0xc1)
  const declaredBlobHash = blake2b256(cellBlob)
  const storageSlot = cellStorageSlot({ allocationEpoch, createPublicKey: keys[0].publicKey })
  const allocation = allocationCommitment({
    relayPublicKey: identity.relayPublicKey,
    storageSlot,
    allocationEpoch,
    sizeClass: 1,
    leaseClass: 1,
    declaredCellBlobHash: declaredBlobHash,
    createPublicKey: keys[0].publicKey,
    renewPublicKey: keys[1].publicKey,
    dropPublicKey: keys[2].publicKey
  })
  const createSignature = b4a.alloc(64)
  sodium.crypto_sign_detached(createSignature, allocation, keys[0].secretKey)
  const now = process.hrtime.bigint() / 1_000_000n
  const context = () => ({
    endpointId: 1,
    transportId: 1,
    transportSupportBit: 1,
    outerClass: null,
    acceptedMonotonicMillis: now,
    absoluteDeadlineMonotonicMillis: now + 15_000n
  })
  const put = await relay.unary.coordinator.dispatch({
    frameKind: 1,
    familyId: 2,
    operationId: 1,
    requestId: b4a.alloc(16, 0xc2),
    body: encodeCanonical(putCellV1, {
      version: 1,
      storageSlot,
      allocationEpoch,
      sizeClass: 1,
      leaseClass: 1,
      clientNonce: b4a.alloc(32, 0xc3),
      createPublicKey: keys[0].publicKey,
      renewPublicKey: keys[1].publicKey,
      dropPublicKey: keys[2].publicKey,
      declaredBlobHash,
      createSignature,
      admission: fixtureAdmission(identity.parameterHash, 0xc4),
      cellBlob
    })
  }, context())
  const putFrame = decodeDispatchFrame(put.dispatch, { copyBody: true })
  t.is(putFrame.frameKind, 2, 'PUT answers with a response frame')
  const receipt = decodeCanonical(blindReceiptV1, putFrame.body, { copyBytes: true })
  t.is(receipt.result, 1, 'signed STORED acknowledgement')
  const unsignedReceipt = encodeCanonical(blindReceiptV1, { ...receipt, signature: b4a.alloc(64) })
  t.ok(sodium.crypto_sign_verify_detached(receipt.signature,
    resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT,
      unsignedReceipt.subarray(0, unsignedReceipt.byteLength - 64)),
    identity.relayPublicKey), 'receipt signature verifies under the relay key')
  const stored = await relay.unary.storage.readCell(storageSlot)
  t.ok(b4a.equals(stored.cellBlob, cellBlob), 'accepted storage holds the exact fixed-size blob')

  // Bad create signature is rejected closed before any mutation.
  const foreign = { secretKey: b4a.alloc(64), publicKey: b4a.alloc(32) }
  sodium.crypto_sign_keypair(foreign.publicKey, foreign.secretKey)
  const badSignature = b4a.alloc(64)
  sodium.crypto_sign_detached(badSignature, allocation, foreign.secretKey)
  const bad = await relay.unary.coordinator.dispatch({
    frameKind: 1,
    familyId: 2,
    operationId: 1,
    requestId: b4a.alloc(16, 0xc5),
    body: encodeCanonical(putCellV1, {
      version: 1,
      storageSlot,
      allocationEpoch,
      sizeClass: 1,
      leaseClass: 1,
      clientNonce: b4a.alloc(32, 0xc6),
      createPublicKey: keys[0].publicKey,
      renewPublicKey: keys[1].publicKey,
      dropPublicKey: keys[2].publicKey,
      declaredBlobHash,
      createSignature: badSignature,
      admission: fixtureAdmission(identity.parameterHash, 0xc7),
      cellBlob
    })
  }, context())
  const badFrame = decodeDispatchFrame(bad.dispatch, { copyBody: true })
  t.is(badFrame.frameKind, 3, 'bad signature answers with an error frame')
  t.is(decodeCanonical(blindErrorV1, badFrame.body).code, 5, 'BAD_CREATE_SIG')

  // Exact readback after a full daemon restart on the same roots.
  await relay.close()
  const replayOffset2 = { value: -15_000n }
  const relay2 = await assembleRelayFixture(identity, layout, {
    replayJournalOptions: { monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset2.value }
  })
  replayOffset2.value = 0n
  await relay2.start()
  t.teardown(async () => { await relay2.close().catch(() => {}) })
  const restored = await relay2.unary.storage.readCell(storageSlot)
  t.ok(b4a.equals(restored.cellBlob, cellBlob), 'accepted storage preserves the cell across daemon restart')
  await relay2.close()
})

// ---------------------------------------------------------------------------
// FORWARD one-hop daemon evidence (serial route 5/5): the vNext source and
// target runtimes over the accepted storage layer — exact 65536-byte turns,
// signed capabilities/results, idempotent retries, changed-replay terminal,
// durable replay rejection, and restart capability recovery. The TLS exporter
// derivation itself is edge-side (see the edge test file); at the daemon the
// binding is opaque bytes, verified for binding, not re-derived.
// ---------------------------------------------------------------------------

const FORWARD_TEST_CATALOG_ENTRY_ID = b4a.alloc(32, 0x42)

async function forwardRelayPair (t, options = {}) {
  const sourceIdentity = await createRelayIdentityFixture()
  const targetIdentity = await createRelayIdentityFixture()
  const sourceLayout = await createRelayEnvironmentFixture(sourceIdentity, { prefix: 'fhs-' })
  const targetLayout = await createRelayEnvironmentFixture(targetIdentity, { prefix: 'fht-' })
  t.teardown(async () => {
    await removeFixtureScratch(sourceLayout)
    await removeFixtureScratch(targetLayout)
  })

  const targetSnapshot = () => targetRelay.unary.descriptorState.requireCurrent()
  const sourceReplayOffset = { value: -15_000n }
  const targetReplayOffset = { value: -15_000n }
  const targetReplayOffsetRef = targetReplayOffset

  const targetRelay = await assembleRelayFixture(targetIdentity, targetLayout, {
    onError: options.onTargetError,
    replayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + targetReplayOffsetRef.value
    },
    target: {
      socketPath: path.join(targetLayout.socketDirectory, 'target-ingress.sock'),
      resolveCatalogEntry: async catalogEntryId => Object.freeze({
        catalogEntryId,
        relayPublicKey: b4a.from(targetIdentity.relayPublicKey),
        descriptorSequence: targetSnapshot().descriptorSequence,
        descriptorHash: b4a.from(targetSnapshot().hash)
      })
    }
  })
  targetReplayOffsetRef.value = 0n

  const dialTarget = async input => {
    const ingressBytes = buildTargetIngress(input.forwardedBytes, targetIdentity)
    const resultTurn = await targetRelay.targetRuntime.handleTargetIngressTranscript(ingressBytes, {})
    const turn = decodeLocalForwardHttpsTurnV4(resultTurn)
    return b4a.from(turn.body)
  }
  const sourceRelay = await assembleRelayFixture(sourceIdentity, sourceLayout, {
    onError: options.onSourceError,
    replayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + sourceReplayOffset.value
    },
    source: {
      socketPath: path.join(sourceLayout.socketDirectory, 'source-origin.sock'),
      resolveTargetDescriptor: async relayPublicKey => Object.freeze({
        relayPublicKey,
        descriptorSequence: targetSnapshot().descriptorSequence,
        descriptorHash: b4a.from(targetSnapshot().hash)
      }),
      resolveCatalogEntry: async catalogEntryId => Object.freeze({
        catalogEntryId,
        relayPublicKey: b4a.from(targetIdentity.relayPublicKey),
        descriptorSequence: targetSnapshot().descriptorSequence,
        descriptorHash: b4a.from(targetSnapshot().hash)
      }),
      dialTarget
    }
  })
  sourceReplayOffset.value = 0n
  return { sourceIdentity, targetIdentity, sourceLayout, targetLayout, sourceRelay, targetRelay }
}

function originCapability (source, target, overrides = {}) {
  const issuedAtEpoch = overrides.issuedAtEpoch == null
    ? Math.floor(Date.now() / 1000) - 10
    : overrides.issuedAtEpoch
  return {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    sourceRelayPublicKey: b4a.from(source.descriptor.relayPublicKey),
    sourceDescriptorSequence: source.descriptorSequence,
    sourceDescriptorHash: b4a.from(source.hash),
    targetRelayPublicKey: b4a.from(target.descriptor.relayPublicKey),
    targetDescriptorSequence: target.descriptorSequence,
    targetDescriptorHash: b4a.from(target.hash),
    targetCatalogEntryId: b4a.from(FORWARD_TEST_CATALOG_ENTRY_ID),
    routeId: overrides.routeId || b4a.alloc(16, 0x31),
    routePrefixRelayPublicKey: b4a.from(source.descriptor.relayPublicKey),
    maxRelayCount: 2,
    remainingTransitions: 1,
    circuitClass: 1,
    maxCircuitBytes: 16n * 1024n * 1024n,
    initialWindowBytes: 65_536,
    idleMillis: 30_000,
    lifetimeMillis: 600_000,
    issuedAtEpoch,
    expiresAtEpoch: issuedAtEpoch + 600,
    circuitNonce: overrides.circuitNonce || b4a.alloc(32, 0x33),
    tlsExporterBindingHash: b4a.alloc(32),
    signature: b4a.alloc(64)
  }
}

function originTurn (capability, requestKind, sequence, previousTargetResultHash, inner, overrides = {}) {
  const clientSessionNonce = overrides.clientSessionNonce || b4a.alloc(32, 0x34)
  const request = {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    requestRole: 0,
    requestKind,
    flags: 0,
    stableSessionId: forwardHttpsStableSessionIdV1(capability, clientSessionNonce),
    sequence,
    clientSessionNonce,
    requestNonce: overrides.requestNonce || b4a.alloc(32, 0x35),
    previousTargetResultHash,
    parentCapability: capability,
    turnTlsExporterBindingHash: b4a.alloc(32),
    originRequestCommitment: b4a.alloc(32),
    sourceTransformSignature: b4a.alloc(64),
    inner
  }
  return encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, request)
}

function buildSourceOriginTranscript (originBytes, identity, overrides = {}) {
  const commitment = forwardHttpsOriginRequestCommitmentV1(originBytes)
  const decoded = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, originBytes, { copyBytes: true })
  const now = BigInt(Number(process.hrtime.bigint() / 1_000_000n))
  const authority = createLocalForwardHttpsOriginAuthorityV4({
    version: 4,
    authorityKind: 1,
    transportId: 1,
    endpointId: 1,
    flags: 0,
    wireV3AbiHash: overrides.wireV3AbiHash || PINNED_WIRE_V3_ABI_HASH,
    signedLaunchTopologyHash: overrides.signedLaunchTopologyHash || identity.launchTopologyHash || PINNED_LAUNCH_TOPOLOGY_HASH,
    edgeProcessNonce: overrides.edgeProcessNonce || b4a.alloc(32, 0x51),
    localChannelNonce: overrides.localChannelNonce || b4a.alloc(32, 0x52),
    tlsExporterBindingHash: overrides.tlsExporterBindingHash || b4a.alloc(32, 0x53),
    originRequestCommitment: commitment,
    stableSessionId: decoded.stableSessionId,
    sequence: decoded.sequence,
    acceptedMonotonicMillis: overrides.acceptedMonotonicMillis == null ? now : overrides.acceptedMonotonicMillis,
    absoluteDeadlineMonotonicMillis: overrides.absoluteDeadlineMonotonicMillis == null ? now + 10_000n : overrides.absoluteDeadlineMonotonicMillis
  })
  return encodeLocalForwardHttpsSourceOriginTranscriptV4(authority, {
    version: 4,
    direction: 1,
    wireRole: 0,
    flags: 0,
    wireV3AbiHash: overrides.wireV3AbiHash || PINNED_WIRE_V3_ABI_HASH,
    localExchangeId: authority.localExchangeId,
    originRequestCommitment: commitment,
    stableSessionId: decoded.stableSessionId,
    sequence: decoded.sequence,
    body: originBytes
  })
}

function buildTargetIngress (forwardedBytes, targetIdentity, overrides = {}) {
  const now = BigInt(Number(process.hrtime.bigint() / 1_000_000n))
  const ingress = createLocalForwardHttpsTargetIngressV4({
    endpointId: 1,
    wireV3AbiHash: overrides.wireV3AbiHash || PINNED_WIRE_V3_ABI_HASH,
    signedLaunchTopologyHash: overrides.signedLaunchTopologyHash || targetIdentity.launchTopologyHash || PINNED_LAUNCH_TOPOLOGY_HASH,
    edgeProcessNonce: overrides.edgeProcessNonce || b4a.alloc(32, 0x54),
    localChannelNonce: overrides.localChannelNonce || b4a.alloc(32, 0x55),
    targetTlsExporterBindingHash: overrides.targetTlsExporterBindingHash || b4a.alloc(32, 0x56),
    acceptedMonotonicMillis: overrides.acceptedMonotonicMillis == null ? now : overrides.acceptedMonotonicMillis,
    absoluteDeadlineMonotonicMillis: overrides.absoluteDeadlineMonotonicMillis == null ? now + 10_000n : overrides.absoluteDeadlineMonotonicMillis,
    body: forwardedBytes
  })
  return encodeLocalForwardHttpsTargetIngressV4(ingress)
}

function openInner (capability, overrides = {}) {
  return {
    version: 1,
    routeId: b4a.from(capability.routeId),
    nextDescriptorSequence: capability.targetDescriptorSequence,
    nextDescriptorHash: b4a.from(capability.targetDescriptorHash),
    requestedWireClass: 1,
    circuitClass: 1,
    circuitNonce: b4a.from(capability.circuitNonce),
    parentRouteScopeHash: overrides.parentRouteScopeHash || b4a.alloc(32),
    hopAdmission: {
      profileId: 7,
      schemeId: 9,
      parameterHash: b4a.alloc(32, 0x44),
      token: b4a.alloc(32, 0x45)
    },
    innerHandshake: b4a.alloc(32)
  }
}

test('FORWARD one-hop: signed OPEN/DATA/WINDOW/CLOSE turns through source and target runtimes on the accepted storage', async t => {
  const pair = await forwardRelayPair(t)
  const { sourceRelay, targetRelay, sourceIdentity, targetIdentity } = pair
  const sourceSnapshot = sourceRelay.unary.descriptorState.requireCurrent()
  const targetSnapshot = targetRelay.unary.descriptorState.requireCurrent()
  const capability = originCapability(sourceSnapshot, targetSnapshot)

  const openBytes = originTurn(capability, 1, 0n, b4a.alloc(32), openInner(capability))
  const openResult = await sourceRelay.sourceRuntime.handleOriginTranscript(
    buildSourceOriginTranscript(openBytes, sourceIdentity), {})
  const openTurn = decodeLocalForwardHttpsTurnV4(openResult)
  t.is(openTurn.wireRole, 1, 'OPEN answers a TARGET_RESULT turn')
  const openVerified = assertForwardHttpsResultForOriginRequestV1(openBytes, b4a.from(openTurn.body))
  t.is(openVerified.result.responseKind, 1, 'OPEN_ACCEPT')
  t.ok(b4a.equals(openVerified.result.signerPublicKey, targetIdentity.relayPublicKey), 'result signed by the target relay')

  const openChainHash = forwardHttpsTargetResultChainHashV1(b4a.from(openTurn.body))
  const dataInner = { version: 1, circuitNonce: capability.circuitNonce, offset: 0n, bytes: b4a.alloc(64, 0x61) }
  const dataBytes = originTurn(capability, 2, 1n, openChainHash, dataInner, {
    clientSessionNonce: decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, openBytes, { copyBytes: true }).clientSessionNonce
  })
  const dataResult = await sourceRelay.sourceRuntime.handleOriginTranscript(
    buildSourceOriginTranscript(dataBytes, sourceIdentity, { localChannelNonce: b4a.alloc(32, 0x62) }), {})
  const dataTurn = decodeLocalForwardHttpsTurnV4(dataResult)
  const dataVerified = assertForwardHttpsResultForOriginRequestV1(dataBytes, b4a.from(dataTurn.body))
  t.is(dataVerified.result.responseKind, 2, 'DATA answers ACK')

  const windowInner = { version: 1, circuitNonce: capability.circuitNonce, consumedThrough: 64n, creditIncrement: 64 }
  const windowBytes = originTurn(capability, 3, 2n, forwardHttpsTargetResultChainHashV1(b4a.from(dataTurn.body)), windowInner, {
    clientSessionNonce: decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, openBytes, { copyBytes: true }).clientSessionNonce
  })
  const windowResult = await sourceRelay.sourceRuntime.handleOriginTranscript(
    buildSourceOriginTranscript(windowBytes, sourceIdentity, { localChannelNonce: b4a.alloc(32, 0x63) }), {})
  const windowTurn = decodeLocalForwardHttpsTurnV4(windowResult)
  const windowVerified = assertForwardHttpsResultForOriginRequestV1(windowBytes, b4a.from(windowTurn.body))
  t.is(windowVerified.result.responseKind, 2, 'WINDOW answers ACK')

  const closeInner = { version: 1, circuitNonce: capability.circuitNonce, closeKind: 1, finalSendOffset: 64n, reasonCode: 0 }
  const closeBytes = originTurn(capability, 4, 3n, forwardHttpsTargetResultChainHashV1(b4a.from(windowTurn.body)), closeInner, {
    clientSessionNonce: decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, openBytes, { copyBytes: true }).clientSessionNonce
  })
  const closeResult = await sourceRelay.sourceRuntime.handleOriginTranscript(
    buildSourceOriginTranscript(closeBytes, sourceIdentity, { localChannelNonce: b4a.alloc(32, 0x64) }), {})
  const closeTurn = decodeLocalForwardHttpsTurnV4(closeResult)
  const closeVerified = assertForwardHttpsResultForOriginRequestV1(closeBytes, b4a.from(closeTurn.body))
  t.is(closeVerified.result.responseKind, 6, 'CLOSE answers CLOSE')

  // Accepted storage evidence on both sides.
  const stableSessionId = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, openBytes, { copyBytes: true }).stableSessionId
  const sourceState = forwardHttpsSourceTurnStateV3(sourceRelay.sourceRuntime.sourceStore, stableSessionId)
  t.is(sourceState.slotState, 'ALLOCATED', 'source session slot allocated on the accepted store')
  t.ok(sourceState.priorSessionRevision >= 5n, 'source WAL carries prepare plus per-turn results')
  const targetState = forwardHttpsTargetTurnStateV3(targetRelay.targetRuntime.targetStore, stableSessionId)
  t.is(targetState.slotState, 'ALLOCATED', 'target session slot allocated on the accepted store')
  t.ok(targetState.priorSessionRevision >= 3n, 'target WAL carries turn-final and processor work')
  const sourceReplay = inspectForwardHttpsReplayJournalV4(sourceRelay.sourceRuntime.replayJournal)
  t.is(sourceReplay.length, 4, 'source replay journal burned one tuple per turn')
  t.ok(sourceReplay.every(entry => entry.state === 'CONSUMED'), 'source tuples are consumed')
  const targetReplay = inspectForwardHttpsReplayJournalV4(targetRelay.targetRuntime.replayJournal)
  t.is(targetReplay.length, 4, 'target replay journal burned one tuple per turn')
  t.ok(targetReplay.every(entry => entry.state === 'CONSUMED'), 'target tuples are consumed')

  await sourceRelay.close()
  await targetRelay.close()
})

test('FORWARD idempotent retry and changed-replay terminal', async t => {
  const pair = await forwardRelayPair(t)
  const { sourceRelay, targetRelay, sourceIdentity } = pair
  const capability = originCapability(
    sourceRelay.unary.descriptorState.requireCurrent(),
    targetRelay.unary.descriptorState.requireCurrent())
  const openBytes = originTurn(capability, 1, 0n, b4a.alloc(32), openInner(capability))

  const first = await sourceRelay.sourceRuntime.handleOriginTranscript(
    buildSourceOriginTranscript(openBytes, sourceIdentity), {})
  const retry = await sourceRelay.sourceRuntime.handleOriginTranscript(
    buildSourceOriginTranscript(openBytes, sourceIdentity, { localChannelNonce: b4a.alloc(32, 0x71) }), {})
  const firstBody = b4a.from(decodeLocalForwardHttpsTurnV4(first).body)
  const retryBody = b4a.from(decodeLocalForwardHttpsTurnV4(retry).body)
  t.ok(b4a.equals(firstBody, retryBody), 'exact retry returns the byte-identical definitive result')

  // Changed bytes on the same sequence terminalize the session: the source
  // signs a non-definitive RETRY_TERMINAL and later turns stay terminal.
  const sessionNonce = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, openBytes, { copyBytes: true }).clientSessionNonce
  const chainHash = forwardHttpsTargetResultChainHashV1(firstBody)
  const changedBytes = originTurn(capability, 2, 1n, chainHash,
    { version: 1, circuitNonce: capability.circuitNonce, offset: 0n, bytes: b4a.alloc(64, 0x72) },
    { clientSessionNonce: sessionNonce })
  const changedAgain = originTurn(capability, 2, 1n, chainHash,
    { version: 1, circuitNonce: capability.circuitNonce, offset: 0n, bytes: b4a.alloc(64, 0x73) },
    { clientSessionNonce: sessionNonce })
  await sourceRelay.sourceRuntime.handleOriginTranscript(
    buildSourceOriginTranscript(changedBytes, sourceIdentity, { localChannelNonce: b4a.alloc(32, 0x72) }), {})
  const conflict = await sourceRelay.sourceRuntime.handleOriginTranscript(
    buildSourceOriginTranscript(changedAgain, sourceIdentity, { localChannelNonce: b4a.alloc(32, 0x73) }), {})
  const conflictTurn = decodeLocalForwardHttpsTurnV4(conflict)
  t.is(conflictTurn.wireRole, 2, 'changed replay answers a source pre-forward error')
  const conflictResult = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, b4a.from(conflictTurn.body), { copyBytes: true })
  t.is(conflictResult.responseKind, 7, 'ERROR')
  t.is(conflictResult.inner.code, 19, 'RETRY_TERMINAL')
  t.ok(b4a.equals(conflictResult.signerPublicKey, sourceIdentity.relayPublicKey), 'error signed by the source relay')

  // Sequence gap terminalizes a fresh session as well.
  const capability2 = originCapability(
    sourceRelay.unary.descriptorState.requireCurrent(),
    targetRelay.unary.descriptorState.requireCurrent(), { circuitNonce: b4a.alloc(32, 0x81) })
  const gapBytes = originTurn(capability2, 2, 2n, chainHash,
    { version: 1, circuitNonce: capability2.circuitNonce, offset: 0n, bytes: b4a.alloc(64, 0x82) })
  const gap = await sourceRelay.sourceRuntime.handleOriginTranscript(
    buildSourceOriginTranscript(gapBytes, sourceIdentity, { localChannelNonce: b4a.alloc(32, 0x74) }), {})
  const gapTurn = decodeLocalForwardHttpsTurnV4(gap)
  t.is(gapTurn.wireRole, 2, 'sequence gap answers a source pre-forward error')
  const gapResult = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, b4a.from(gapTurn.body), { copyBytes: true })
  t.is(gapResult.inner.code, 19, 'RETRY_TERMINAL')

  await sourceRelay.close()
  await targetRelay.close()
})

test('FORWARD durable replay rejection, authority binding and restart capability recovery', async t => {
  const pair = await forwardRelayPair(t)
  const { sourceRelay, targetRelay, sourceIdentity, targetIdentity, sourceLayout } = pair
  const capability = originCapability(
    sourceRelay.unary.descriptorState.requireCurrent(),
    targetRelay.unary.descriptorState.requireCurrent())
  const openBytes = originTurn(capability, 1, 0n, b4a.alloc(32), openInner(capability))
  const transcript = buildSourceOriginTranscript(openBytes, sourceIdentity)
  const first = await sourceRelay.sourceRuntime.handleOriginTranscript(transcript, {})
  t.ok(first.byteLength === 65684, 'first turn answered')

  // The exact same IPC transcript is durably rejected as replay.
  let replayError = null
  try {
    await sourceRelay.sourceRuntime.handleOriginTranscript(transcript, {})
  } catch (error) {
    replayError = error
  }
  t.is(replayError && replayError.code, 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_REPLAY', 'exact IPC transcript replay is durably rejected')

  // Authority binding: a foreign ABI hash fails closed.
  let abiError = null
  try {
    await sourceRelay.sourceRuntime.handleOriginTranscript(
      buildSourceOriginTranscript(openBytes, sourceIdentity, {
        localChannelNonce: b4a.alloc(32, 0x91),
        wireV3AbiHash: b4a.alloc(32, 0x99)
      }), {})
  } catch (error) {
    abiError = error
  }
  t.is(abiError && abiError.code, 'BLIND_FORWARD_RUNTIME_VNEXT_AUTHORITY_MISMATCH', 'foreign ABI hash fails closed')

  // Expired capability is a signed source pre-forward error (RETRY_TERMINAL).
  const expiredCapability = originCapability(
    sourceRelay.unary.descriptorState.requireCurrent(),
    targetRelay.unary.descriptorState.requireCurrent(),
    { issuedAtEpoch: Math.floor(Date.now() / 1000) - 1200, circuitNonce: b4a.alloc(32, 0x92) })
  const expiredBytes = originTurn(expiredCapability, 1, 0n, b4a.alloc(32), openInner(expiredCapability))
  const expired = await sourceRelay.sourceRuntime.handleOriginTranscript(
    buildSourceOriginTranscript(expiredBytes, sourceIdentity, { localChannelNonce: b4a.alloc(32, 0x93) }), {})
  const expiredTurn = decodeLocalForwardHttpsTurnV4(expired)
  t.is(expiredTurn.wireRole, 2, 'expired capability answers a source pre-forward error')
  const expiredResult = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, b4a.from(expiredTurn.body), { copyBytes: true })
  t.is(expiredResult.inner.code, 19, 'RETRY_TERMINAL')

  // Restart the source relay on the same durable roots; the target relay
  // stays live and keeps its own storage.
  await sourceRelay.close()
  const targetSnapshot = () => targetRelay.unary.descriptorState.requireCurrent()
  const dialTarget = async input => {
    const ingressBytes = buildTargetIngress(input.forwardedBytes, targetIdentity)
    const resultTurn = await targetRelay.targetRuntime.handleTargetIngressTranscript(ingressBytes, {})
    return b4a.from(decodeLocalForwardHttpsTurnV4(resultTurn).body)
  }
  const replayOffset = { value: -15_000n }
  const sourceRelay2 = await assembleRelayFixture(sourceIdentity, sourceLayout, {
    replayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset.value
    },
    source: {
      socketPath: path.join(sourceLayout.socketDirectory, 'source-origin.sock'),
      resolveTargetDescriptor: async relayPublicKey => Object.freeze({
        relayPublicKey,
        descriptorSequence: targetSnapshot().descriptorSequence,
        descriptorHash: b4a.from(targetSnapshot().hash)
      }),
      resolveCatalogEntry: async catalogEntryId => Object.freeze({
        catalogEntryId,
        relayPublicKey: b4a.from(targetIdentity.relayPublicKey),
        descriptorSequence: targetSnapshot().descriptorSequence,
        descriptorHash: b4a.from(targetSnapshot().hash)
      }),
      dialTarget
    }
  })
  replayOffset.value = 0n
  const recovered = inspectForwardHttpsReplayJournalV4(sourceRelay2.sourceRuntime.replayJournal)
  t.is(recovered.length, 2, 'replay journal recovered both burned tuples across restart')
  t.ok(recovered.every(entry => entry.state === 'CONSUMED'), 'the tuples stay consumed')
  const stableSessionId = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, openBytes, { copyBytes: true }).stableSessionId
  const sourceState = forwardHttpsSourceTurnStateV3(sourceRelay2.sourceRuntime.sourceStore, stableSessionId)
  t.is(sourceState.identity, 'PRESENT_ALLOCATED', 'source session identity recovered as allocated')
  let replayedAgain = null
  try {
    await sourceRelay2.sourceRuntime.handleOriginTranscript(transcript, {})
  } catch (error) {
    replayedAgain = error
  }
  t.is(replayedAgain && replayedAgain.code, 'FORWARD_HTTPS_REPLAY_JOURNAL_V4_REPLAY',
    'the pre-restart transcript is still durably rejected after recovery')

  // A fresh session completes end-to-end on the recovered runtime.
  const capability2 = originCapability(
    sourceRelay2.unary.descriptorState.requireCurrent(),
    targetSnapshot(), { circuitNonce: b4a.alloc(32, 0x94) })
  const open2 = originTurn(capability2, 1, 0n, b4a.alloc(32), openInner(capability2))
  const result2 = await sourceRelay2.sourceRuntime.handleOriginTranscript(
    buildSourceOriginTranscript(open2, sourceIdentity, { localChannelNonce: b4a.alloc(32, 0x95) }), {})
  const verified2 = assertForwardHttpsResultForOriginRequestV1(open2, b4a.from(decodeLocalForwardHttpsTurnV4(result2).body))
  t.is(verified2.result.responseKind, 1, 'fresh session completes after restart')

  await sourceRelay2.close()
  await targetRelay.close()
})
