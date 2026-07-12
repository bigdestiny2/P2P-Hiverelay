import test from 'brittle'
import b4a from 'b4a'
import { decodeLocalRequest, encodeLocalReadyProbe } from '@hiverelay/blind-ipc'
import {
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  FAMILY,
  HEALTH_CLOCK_STATE,
  HEALTH_INTEGRITY_STATE,
  HEALTH_REBALANCE_STATE,
  OPERATION,
  STORE_LIFECYCLE_STATE,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  auxiliarySignaturePayload,
  blindHealthResultV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  encodeCanonical,
  relayIdentityTransitionV1,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import { AdmissionCoordinator } from '../admission-coordinator.js'
import {
  DESCRIPTOR_CLOSED_REASON,
  DESCRIPTOR_STATE_KIND,
  DescriptorState,
  DescriptorStateError
} from '../descriptor-state.js'
import { daemonOperationProfile, OPERATION_CATALOG } from '../operation-catalog.js'
import {
  CLOCK_UNSAFE_OPERATION_BITS,
  READINESS_CLOSED_REASON,
  READINESS_STATE_KIND,
  ReadinessCoordinator
} from '../readiness-coordinator.js'
import {
  descriptorAndParameters,
  descriptorBytes,
  descriptorValue,
  fixtureBytes,
  manifestBytes,
  parameterBytes,
  successorBytes,
  successorValue
} from './coordinator-fixtures.js'

function descriptorState (options = {}) {
  return new DescriptorState({
    epochNow: () => 101,
    verifySignature: async () => true,
    ...options
  })
}

test('descriptor authority uses shared hashes and is mutation-proof', async t => {
  let calls = 0
  const state = descriptorState({
    verifySignature: async input => {
      calls++
      input.canonicalBytes[0] ^= 0xff
      input.descriptor.relayPublicKey.fill(0)
      input.payload.fill(0)
      return true
    }
  })
  const bytes = descriptorBytes()
  const snapshot = await state.activate(bytes)
  t.is(calls, 1)
  t.ok(b4a.equals(snapshot.hash, serviceDescriptorHash(bytes)))
  snapshot.hash.fill(0)
  snapshot.canonicalBytes.fill(0)
  snapshot.descriptor.relayPublicKey.fill(0)
  const fresh = state.requireCurrent()
  t.ok(b4a.equals(fresh.hash, serviceDescriptorHash(bytes)))
  t.not(fresh.descriptor.relayPublicKey[0], 0)
  t.ok(state.remainsUsable(fresh))
})

test('descriptor lifecycle fences same-epoch drain/retire and rejects routine same-epoch refresh', async t => {
  const state = descriptorState()
  const active = await state.activate(descriptorBytes())
  const sameEpoch = successorValue(active, {
    issuedEpoch: active.descriptor.issuedEpoch,
    expiresEpoch: active.descriptor.expiresEpoch
  })
  await t.exception(state.activate(encodeCanonical(blindServiceDescriptorV1, sameEpoch)), DescriptorStateError)

  const lifecycle = descriptorState()
  const a = await lifecycle.activate(descriptorBytes())
  const draining = await lifecycle.activate(successorBytes(a, {
    issuedEpoch: a.descriptor.issuedEpoch,
    expiresEpoch: a.descriptor.expiresEpoch,
    storeLifecycleState: STORE_LIFECYCLE_STATE.DRAINING,
    drainStartedEpoch: a.descriptor.issuedEpoch,
    enabledOperationBits: 0x000129d7
  }))
  t.not(draining.lifecycleFence, a.lifecycleFence)
  t.absent(lifecycle.remainsUsable(a))
  const retired = await lifecycle.activate(successorBytes(draining, {
    issuedEpoch: draining.descriptor.issuedEpoch,
    expiresEpoch: draining.descriptor.expiresEpoch,
    storeLifecycleState: STORE_LIFECYCLE_STATE.RETIRED,
    enabledOperationBits: 0
  }))
  t.not(retired.lifecycleFence, draining.lifecycleFence)
  t.is(lifecycle.state().reason, DESCRIPTOR_CLOSED_REASON.RETIRED)
})

test('descriptor gap is explicit, persistent, and readiness-verification forcing', async t => {
  let now = 101
  const planned = descriptorState({ epochNow: () => now })
  const first = await planned.activate(descriptorBytes())
  now = first.descriptor.expiresEpoch
  await t.exception(planned.activate(successorBytes(first, {
    issuedEpoch: first.descriptor.expiresEpoch,
    expiresEpoch: first.descriptor.expiresEpoch + 4
  })), DescriptorStateError)

  now = 101
  const emergency = descriptorState({ allowEmergencyGaps: true, epochNow: () => now })
  const before = await emergency.activate(descriptorBytes())
  now = before.descriptor.expiresEpoch
  const after = await emergency.activate(successorBytes(before, {
    issuedEpoch: before.descriptor.expiresEpoch,
    expiresEpoch: before.descriptor.expiresEpoch + 4
  }), { emergencyGap: true })
  t.ok(after.hadReadinessGap)
  t.ok(after.fullStoreVerificationRequired)
  t.not(after.lifecycleFence, before.lifecycleFence)
})

test('descriptor rollback, same-sequence fork, and durability-hash substitution fault closed', async t => {
  const forked = descriptorState()
  await forked.activate(descriptorBytes())
  const forkValue = descriptorValue({ descriptorNonce: fixtureBytes(32, 0x66) })
  await t.exception(forked.activate(encodeCanonical(blindServiceDescriptorV1, forkValue)), DescriptorStateError)
  t.is(forked.state().reason, DESCRIPTOR_CLOSED_REASON.FORK)

  const rolledBack = descriptorState()
  const first = await rolledBack.activate(descriptorBytes())
  await rolledBack.activate(successorBytes(first))
  await t.exception(rolledBack.activate(descriptorBytes()), DescriptorStateError)
  t.is(rolledBack.state().reason, DESCRIPTOR_CLOSED_REASON.ROLLBACK)

  const substituted = descriptorState()
  const invalid = descriptorValue()
  invalid.durabilityProfileHash = fixtureBytes(32, 0x67)
  await t.exception(substituted.activate(encodeCanonical(blindServiceDescriptorV1, invalid)), DescriptorStateError)
  t.is(substituted.state().kind, DESCRIPTOR_STATE_KIND.CLOSED)
})

test('relay-key rotation verifies both exact identity-transition signatures and requires a fresh store', async t => {
  const seen = []
  const state = descriptorState({
    verifyIdentityTransitionSignature: async input => {
      seen.push(input)
      return true
    }
  })
  const active = await state.activate(descriptorBytes())
  const draining = await state.activate(successorBytes(active, {
    storeLifecycleState: STORE_LIFECYCLE_STATE.DRAINING,
    drainStartedEpoch: 101,
    enabledOperationBits: 0x000129d7
  }))
  const retired = await state.activate(successorBytes(draining, {
    issuedEpoch: draining.descriptor.issuedEpoch,
    expiresEpoch: draining.descriptor.expiresEpoch,
    storeLifecycleState: STORE_LIFECYCLE_STATE.RETIRED,
    enabledOperationBits: 0
  }))
  const newKey = fixtureBytes(32, 0x91)
  const transition = {
    version: 1,
    oldRelayKey: b4a.from(retired.descriptor.relayPublicKey),
    newRelayKey: newKey,
    oldIdentitySequence: retired.descriptor.identitySequence,
    newIdentitySequence: retired.descriptor.identitySequence + 1n,
    validFromEpoch: retired.descriptor.issuedEpoch,
    reasonCode: 1,
    transitionNonce: fixtureBytes(32, 0x92),
    oldSignature: fixtureBytes(64, 0x93),
    newSignature: fixtureBytes(64, 0x94)
  }
  const rotated = await state.activate(successorBytes(retired, {
    relayPublicKey: newKey,
    storeId: fixtureBytes(32, 0x95),
    identitySequence: transition.newIdentitySequence,
    previousRelayKey: b4a.from(retired.descriptor.relayPublicKey),
    identityTransition: transition,
    storeLifecycleState: STORE_LIFECYCLE_STATE.ACTIVE,
    drainStartedEpoch: null,
    enabledOperationBits: 0x003fffff,
    issuedEpoch: transition.validFromEpoch,
    expiresEpoch: retired.descriptor.expiresEpoch
  }))
  t.is(seen.length, 2)
  t.alike(seen.map(entry => entry.signer), ['old', 'new'])
  const transitionBytes = encodeCanonical(relayIdentityTransitionV1, transition)
  const payload = auxiliarySignaturePayload(AUXILIARY_SIGNATURE_DOMAIN_ID.IDENTITY_TRANSITION,
    transitionBytes.subarray(0, transitionBytes.byteLength - 128))
  t.ok(seen.every(entry => b4a.equals(entry.payload, payload)))
  t.is(rotated.descriptor.identitySequence, 1n)

  const invalid = descriptorState({ verifyIdentityTransitionSignature: async () => true })
  const a = await invalid.activate(descriptorBytes())
  const d = await invalid.activate(successorBytes(a, {
    storeLifecycleState: STORE_LIFECYCLE_STATE.DRAINING,
    drainStartedEpoch: 101,
    enabledOperationBits: 0x000129d7
  }))
  const r = await invalid.activate(successorBytes(d, {
    issuedEpoch: d.descriptor.issuedEpoch,
    expiresEpoch: d.descriptor.expiresEpoch,
    storeLifecycleState: STORE_LIFECYCLE_STATE.RETIRED,
    enabledOperationBits: 0
  }))
  await t.exception(invalid.activate(successorBytes(r, {
    relayPublicKey: newKey,
    storeId: b4a.from(r.descriptor.storeId),
    identitySequence: 1n,
    previousRelayKey: b4a.from(r.descriptor.relayPublicKey),
    identityTransition: { ...transition, oldRelayKey: b4a.from(r.descriptor.relayPublicKey) },
    storeLifecycleState: STORE_LIFECYCLE_STATE.ACTIVE,
    drainStartedEpoch: null,
    enabledOperationBits: 0x003fffff,
    issuedEpoch: transition.validFromEpoch,
    expiresEpoch: r.descriptor.expiresEpoch
  })), DescriptorStateError)
})

test('non-genesis restoration rejects trust booleans and accepts exact verified manifest floor', async t => {
  const value = descriptorValue({
    descriptorSequence: 5n,
    previousDescriptorHash: fixtureBytes(32, 0x61)
  })
  const bytes = encodeCanonical(blindServiceDescriptorV1, value)
  const forged = descriptorState()
  await t.exception(forged.activate(bytes, { trustedRestore: true }), DescriptorStateError)

  let restoredInput
  const state = descriptorState({
    verifyRestoration: async input => {
      restoredInput = input
      return Object.freeze({
        verified: true,
        fullStoreVerified: true,
        descriptorSequenceFloor: input.descriptorSequenceFloor,
        descriptorHashFloor: b4a.from(input.descriptorHashFloor),
        relayPublicKey: b4a.from(input.relayPublicKey),
        storeId: b4a.from(input.storeId),
        durabilityProfileId: input.durabilityProfileId,
        durabilityContinuityHash: b4a.from(input.durabilityContinuityHash),
        durabilityProfileHash: b4a.from(input.durabilityProfileHash)
      })
    }
  })
  const synthetic = Object.freeze({
    descriptor: value,
    canonicalBytes: bytes,
    hash: serviceDescriptorHash(bytes)
  })
  const snapshot = await state.restore({
    descriptorChainBytes: [bytes],
    manifestBytes: manifestBytes(synthetic)
  })
  t.ok(restoredInput)
  t.is(snapshot.descriptorSequence, 5n)
  t.ok(snapshot.fullStoreVerificationRequired)
  t.is(state.state().kind, DESCRIPTOR_STATE_KIND.READY)
})

test('admission records are byte-owned and require exact current role/cost/spend echoes', async t => {
  const pair = descriptorAndParameters()
  const state = descriptorState()
  const snapshot = await state.activate(pair.descriptor)
  let adapterInput
  const admission = new AdmissionCoordinator({
    descriptorState: state,
    verifySignature: async input => {
      input.parameters.relayPublicKey.fill(0)
      input.canonicalBytes.fill(0)
      return true
    },
    resolveAdapter: async input => {
      input.parameters.relayPublicKey.fill(0)
      return {
        async prepare (prepared) {
          adapterInput = prepared
          return {
            spendTag: fixtureBytes(32, 0xa1),
            requestCommitment: b4a.from(prepared.requestCommitment),
            profileId: 7,
            schemeId: 9,
            parameterHash: b4a.from(prepared.admission.parameterHash),
            costClass: { ...prepared.costClass },
            walCommitRecord: fixtureBytes(8, 0xa2)
          }
        }
      }
    }
  })
  const installed = await admission.installParameters(pair.parameters)
  installed.canonicalBytes.fill(0)
  installed.value.relayPublicKey.fill(0)
  t.ok(admission.descriptorProfilesReady(snapshot))
  const commitment = fixtureBytes(32, 0xa3)
  const prepared = await admission.prepare({
    profile: daemonOperationProfile(FAMILY.CELL, OPERATION.CELL.PUT),
    admission: {
      profileId: 7,
      schemeId: 9,
      parameterHash: admissionParametersHash(pair.parameters),
      token: fixtureBytes(16, 0xa4)
    },
    cost: { resourceClass: 1, leaseClass: 1 },
    requestCommitment: commitment,
    descriptorSnapshot: snapshot,
    endpoint: snapshot.descriptor.endpoints[0]
  })
  t.ok(adapterInput)
  t.ok(b4a.equals(prepared.requestCommitment, commitment))
  t.is(prepared.costClass.costUnits, 10n)
  t.ok(prepared.spendTag.some(byte => byte !== 0))
})

test('admission never substitutes the current descriptor for a fenced caller snapshot', async t => {
  const pair = descriptorAndParameters()
  const state = descriptorState()
  const active = await state.activate(pair.descriptor)
  let adapters = 0
  const admission = new AdmissionCoordinator({
    descriptorState: state,
    verifySignature: async () => true,
    resolveAdapter: async () => {
      adapters++
      return { async prepare () {} }
    }
  })
  await admission.installParameters(pair.parameters)
  await state.activate(successorBytes(active, {
    issuedEpoch: active.descriptor.issuedEpoch,
    expiresEpoch: active.descriptor.expiresEpoch,
    storeLifecycleState: STORE_LIFECYCLE_STATE.DRAINING,
    drainStartedEpoch: active.descriptor.issuedEpoch,
    enabledOperationBits: 0x000129d7
  }))
  t.absent(admission.descriptorProfilesReady(active))
  let rejected
  try {
    await admission.prepare({
      profile: daemonOperationProfile(FAMILY.CELL, OPERATION.CELL.PUT),
      admission: {
        profileId: 7,
        schemeId: 9,
        parameterHash: admissionParametersHash(pair.parameters),
        token: fixtureBytes(8, 0x70)
      },
      cost: { resourceClass: 1, leaseClass: 1 },
      requestCommitment: fixtureBytes(32, 0x71),
      descriptorSnapshot: active,
      endpoint: active.descriptor.endpoints[0]
    })
  } catch (error) {
    rejected = error
  }
  t.is(rejected.code, 'SPEND_INVALID')
  t.is(adapters, 0)
})

test('future admission parameters remain fetchable but cannot redeem', async t => {
  const relay = fixtureBytes(32, 0x71)
  const parameters = parameterBytes(relay, { validFromEpoch: 102, expiresEpoch: 104 })
  const value = descriptorValue({ relayPublicKey: relay })
  value.admissionProfiles[0].parameterHash = admissionParametersHash(parameters)
  const state = descriptorState()
  const snapshot = await state.activate(encodeCanonical(blindServiceDescriptorV1, value))
  const admission = new AdmissionCoordinator({
    descriptorState: state,
    verifySignature: async () => true,
    resolveAdapter: async () => null
  })
  await admission.installParameters(parameters)
  t.ok(admission.descriptorParametersAvailable(snapshot))
  t.absent(admission.descriptorProfilesReady(snapshot))
  t.ok(admission.parametersForRequest({ profileId: 7, schemeId: 9 }, snapshot))
})

test('admission rejects zero spend tags and adapter cost substitution', async t => {
  const pair = descriptorAndParameters()
  const state = descriptorState()
  const snapshot = await state.activate(pair.descriptor)
  const admission = new AdmissionCoordinator({
    descriptorState: state,
    verifySignature: async () => true,
    resolveAdapter: async () => ({
      async prepare (input) {
        return {
          spendTag: fixtureBytes(32, 0),
          requestCommitment: input.requestCommitment,
          profileId: 7,
          schemeId: 9,
          parameterHash: input.admission.parameterHash,
          costClass: { ...input.costClass, costUnits: input.costClass.costUnits + 1n },
          walCommitRecord: fixtureBytes(1, 1)
        }
      }
    })
  })
  await admission.installParameters(pair.parameters)
  let rejected
  try {
    await admission.prepare({
      profile: daemonOperationProfile(FAMILY.CELL, OPERATION.CELL.PUT),
      admission: {
        profileId: 7,
        schemeId: 9,
        parameterHash: admissionParametersHash(pair.parameters),
        token: fixtureBytes(8, 0x70)
      },
      cost: { resourceClass: 1, leaseClass: 1 },
      requestCommitment: fixtureBytes(32, 0x71),
      descriptorSnapshot: snapshot,
      endpoint: snapshot.descriptor.endpoints[0]
    })
  } catch (error) {
    rejected = error
  }
  t.is(rejected.code, 'SPEND_INVALID')
})

function readinessHarness (options = {}) {
  let dependencyCalls = 0
  const state = options.state
  const supportBit = options.supportBit || TRANSPORT_SUPPORT.DIRECT_HTTP
  const supportedBits = OPERATION_CATALOG.reduce((bits, profile) =>
    profile.ordinal < 3 || (profile.transportSupportBits & supportBit) !== 0 ? bits | profile.operationBit : bits, 0)
  const dependency = options.dependency || (async input => {
    dependencyCalls++
    return {
      selfVerified: true,
      descriptorSequence: input.descriptorSequence,
      descriptorHash: b4a.from(input.descriptorHash),
      endpointId: input.endpointId,
      transportSupportBit: input.transportSupportBit,
      fullStoreVerified: true,
      readyRoleBits: 1,
      readyOperationBits: supportedBits & input.descriptor.enabledOperationBits,
      clockState: HEALTH_CLOCK_STATE.READY,
      effectiveEpochFloor: 101,
      integrityState: HEALTH_INTEGRITY_STATE.VERIFIED,
      checkpointAgeBand: 1,
      scrubAgeBand: 1,
      rebalanceState: HEALTH_REBALANCE_STATE.STABLE,
      capacityBand: input.descriptor.capacityBand
    }
  })
  const readiness = new ReadinessCoordinator({
    descriptorState: state,
    admission: options.admission || {
      descriptorParametersAvailable: () => true,
      descriptorProfilesReady: () => true
    },
    dependencySnapshot: dependency,
    signer: options.signer || {
      sign: async () => fixtureBytes(64, 0xb1),
      verify: async () => true
    }
  })
  return { readiness, supportBit, dependencyCalls: () => dependencyCalls }
}

test('readiness projects the exact adapter and clock mask across the 22-operation catalog', async t => {
  const state = descriptorState()
  const snapshot = await state.activate(descriptorBytes())
  const supportBit = TRANSPORT_SUPPORT.DIRECT_NATIVE
  let clockState = HEALTH_CLOCK_STATE.READY
  const supportedBits = OPERATION_CATALOG.reduce((bits, profile) =>
    profile.ordinal < 3 || (profile.transportSupportBits & supportBit) !== 0 ? bits | profile.operationBit : bits, 0)
  const harness = readinessHarness({
    state,
    supportBit,
    dependency: async input => ({
      selfVerified: true,
      descriptorSequence: input.descriptorSequence,
      descriptorHash: input.descriptorHash,
      endpointId: input.endpointId,
      transportSupportBit: input.transportSupportBit,
      fullStoreVerified: true,
      readyRoleBits: 1,
      readyOperationBits: supportedBits,
      clockState,
      effectiveEpochFloor: 101,
      integrityState: HEALTH_INTEGRITY_STATE.VERIFIED,
      checkpointAgeBand: 1,
      scrubAgeBand: 1,
      rebalanceState: 0,
      capacityBand: snapshot.descriptor.capacityBand
    })
  })
  const ready = await harness.readiness.evaluate({ endpointId: 1, transportSupportBit: supportBit })
  t.is(ready.kind, READINESS_STATE_KIND.READY)
  t.is(ready.readyOperationBits, supportedBits)
  clockState = HEALTH_CLOCK_STATE.UNSAFE
  const unsafe = await harness.readiness.evaluate({ endpointId: 1, transportSupportBit: supportBit })
  t.is(CLOCK_UNSAFE_OPERATION_BITS, 0x00009628)
  t.is(unsafe.readyOperationBits, supportedBits & ~0x00009628)
})

test('readiness dependency hooks cannot mutate signed descriptor or endpoint authority', async t => {
  const state = descriptorState()
  const snapshot = await state.activate(descriptorBytes())
  const endpointUrl = b4a.from(snapshot.descriptor.endpoints[0].canonicalUrl)
  const relayKey = b4a.from(snapshot.descriptor.relayPublicKey)
  const harness = readinessHarness({
    state,
    dependency: async input => {
      input.endpoint.canonicalUrl.fill(0)
      input.descriptor.relayPublicKey.fill(0)
      return {
        selfVerified: true,
        descriptorSequence: input.descriptorSequence,
        descriptorHash: input.descriptorHash,
        endpointId: input.endpointId,
        transportSupportBit: input.transportSupportBit,
        fullStoreVerified: true,
        readyRoleBits: 1,
        readyOperationBits: 0x00000007,
        clockState: HEALTH_CLOCK_STATE.READY,
        effectiveEpochFloor: 101,
        integrityState: HEALTH_INTEGRITY_STATE.VERIFIED,
        checkpointAgeBand: 1,
        scrubAgeBand: 1,
        rebalanceState: HEALTH_REBALANCE_STATE.STABLE,
        capacityBand: snapshot.descriptor.capacityBand
      }
    }
  })
  const ready = await harness.readiness.evaluate({ endpointId: 1, transportSupportBit: harness.supportBit })
  t.is(ready.kind, READINESS_STATE_KIND.READY)
  t.ok(b4a.equals(ready.endpoint.canonicalUrl, endpointUrl))
  t.ok(b4a.equals(state.requireCurrent().descriptor.relayPublicKey, relayKey))
})

test('health proof rejects zero challenge before dependency and revalidates exact nonce/state after signing', async t => {
  const state = descriptorState()
  const snapshot = await state.activate(descriptorBytes())
  const harness = readinessHarness({ state })
  let invalid
  try {
    await harness.readiness.healthResult({
      descriptorSequence: snapshot.descriptorSequence,
      descriptorHash: snapshot.hash,
      endpointId: 1,
      transportSupportBit: harness.supportBit,
      requestedRoleBits: 0,
      requestedOperationBits: 0,
      clientNonce: fixtureBytes(32, 0)
    }, { endpointId: 1, transportSupportBit: harness.supportBit })
  } catch (error) {
    invalid = error
  }
  t.ok(invalid)
  t.is(harness.dependencyCalls(), 0)

  const replayableShape = {
    descriptorSequence: snapshot.descriptorSequence,
    descriptorHash: snapshot.hash,
    endpointId: 1,
    transportSupportBit: harness.supportBit,
    requestedRoleBits: 1,
    requestedOperationBits: 1,
    clientNonce: fixtureBytes(32, 0xc0)
  }
  for (const acceptedTuple of [
    { endpointId: 2, transportSupportBit: harness.supportBit },
    { endpointId: 1, transportSupportBit: TRANSPORT_SUPPORT.DIRECT_NATIVE }
  ]) {
    let replayed
    try {
      await harness.readiness.healthResult(replayableShape, acceptedTuple)
    } catch (error) {
      replayed = error
    }
    t.ok(replayed)
    t.is(replayed.code, 'BAD_ENCODING')
  }
  t.is(harness.dependencyCalls(), 0)

  const nonce = fixtureBytes(32, 0xc1)
  const server = await harness.readiness.serverSnapshot({
    endpointId: 1,
    transportSupportBit: harness.supportBit,
    edgeInstanceNonce: nonce
  })
  const health = decodeCanonical(blindHealthResultV1, server.canonicalHealthResult)
  t.ok(b4a.equals(server.edgeInstanceNonce, nonce))
  t.ok(b4a.equals(health.clientNonce, nonce))
  t.is(health.endpointId, 1)
  t.is(health.transportSupportBit, harness.supportBit)
  t.is(server.endpointId, 1)
  t.is(server.transportSupportBit, harness.supportBit)
  t.ok(b4a.equals(server.descriptorHash, snapshot.hash))
})

test('READY wire support zero is control-only while server snapshots require signed endpoint support', async t => {
  const nonce = fixtureBytes(32, 0xce)
  const decoded = decodeLocalRequest(encodeLocalReadyProbe({
    endpointId: 1,
    acceptedMonotonicMillis: 1000n,
    edgeInstanceNonce: nonce,
    launchTopologyHash: fixtureBytes(32, 0xcf)
  }))
  t.is(decoded.transportSupportBit, 0)
  const state = descriptorState()
  await state.activate(descriptorBytes())
  const harness = readinessHarness({ state })
  let missing
  try {
    await harness.readiness.serverSnapshot({ endpointId: 1, edgeInstanceNonce: nonce })
  } catch (error) {
    missing = error
  }
  t.ok(missing)
  t.is(harness.dependencyCalls(), 0)

  for (const transportSupportBit of [
    0,
    TRANSPORT_SUPPORT.DIRECT_HTTP | TRANSPORT_SUPPORT.DIRECT_NATIVE
  ]) {
    let invalid
    try {
      await harness.readiness.serverSnapshot({
        endpointId: 1,
        transportSupportBit,
        edgeInstanceNonce: nonce
      })
    } catch (error) {
      invalid = error
    }
    t.ok(invalid)
  }
  t.is(harness.dependencyCalls(), 0)

  const ready = await harness.readiness.serverSnapshot({
    endpointId: 1,
    transportSupportBit: harness.supportBit,
    edgeInstanceNonce: nonce
  })
  t.is(ready.transportSupportBit, harness.supportBit)
  t.is(harness.dependencyCalls(), 2)
})

test('health proof fails closed when dependency state flips after signing', async t => {
  const state = descriptorState()
  const snapshot = await state.activate(descriptorBytes())
  let calls = 0
  let signed = 0
  const supportedBits = OPERATION_CATALOG.reduce((bits, profile) =>
    profile.ordinal < 3 || (profile.transportSupportBits & TRANSPORT_SUPPORT.DIRECT_HTTP) !== 0
      ? bits | profile.operationBit
      : bits, 0)
  const harness = readinessHarness({
    state,
    signer: {
      async sign () { signed++; return fixtureBytes(64, 0xd0) },
      async verify () { return true }
    },
    dependency: async input => ({
      selfVerified: true,
      descriptorSequence: input.descriptorSequence,
      descriptorHash: input.descriptorHash,
      endpointId: input.endpointId,
      transportSupportBit: input.transportSupportBit,
      fullStoreVerified: true,
      readyRoleBits: 1,
      readyOperationBits: calls++ === 0 ? supportedBits : supportedBits & ~(1 << 3),
      clockState: 1,
      effectiveEpochFloor: 101,
      integrityState: 1,
      checkpointAgeBand: 1,
      scrubAgeBand: 1,
      rebalanceState: 0,
      capacityBand: snapshot.descriptor.capacityBand
    })
  })
  let changed
  try {
    await harness.readiness.healthResult({
      descriptorSequence: snapshot.descriptorSequence,
      descriptorHash: snapshot.hash,
      endpointId: 1,
      transportSupportBit: harness.supportBit,
      requestedRoleBits: 1,
      requestedOperationBits: 1,
      clientNonce: fixtureBytes(32, 0xd1)
    }, { endpointId: 1, transportSupportBit: harness.supportBit })
  } catch (error) {
    changed = error
  }
  t.ok(changed)
  t.is(signed, 1)
})

test('health proof is not released when signing crosses descriptor expiry', async t => {
  let now = 101
  const state = descriptorState({ epochNow: () => now })
  const snapshot = await state.activate(descriptorBytes())
  let signed = 0
  const harness = readinessHarness({
    state,
    signer: {
      async sign () {
        signed++
        now = snapshot.descriptor.expiresEpoch
        return fixtureBytes(64, 0xda)
      },
      async verify () { return true }
    }
  })
  let expired
  try {
    await harness.readiness.healthResult({
      descriptorSequence: snapshot.descriptorSequence,
      descriptorHash: snapshot.hash,
      endpointId: 1,
      transportSupportBit: harness.supportBit,
      requestedRoleBits: 1,
      requestedOperationBits: 1,
      clientNonce: fixtureBytes(32, 0xdb)
    }, { endpointId: 1, transportSupportBit: harness.supportBit })
  } catch (error) {
    expired = error
  }
  t.ok(expired)
  t.is(signed, 1)
})

test('readiness closes restored/gapped state without full-store dependency verification', async t => {
  let now = 101
  const state = descriptorState({ allowEmergencyGaps: true, epochNow: () => now })
  const first = await state.activate(descriptorBytes())
  now = first.descriptor.expiresEpoch
  await state.activate(successorBytes(first, {
    issuedEpoch: first.descriptor.expiresEpoch,
    expiresEpoch: first.descriptor.expiresEpoch + 4
  }), { emergencyGap: true })
  const harness = readinessHarness({
    state,
    dependency: async input => ({
      selfVerified: true,
      descriptorSequence: input.descriptorSequence,
      descriptorHash: input.descriptorHash,
      endpointId: input.endpointId,
      transportSupportBit: input.transportSupportBit,
      fullStoreVerified: false,
      readyRoleBits: 1,
      readyOperationBits: 0x00000007,
      clockState: 1,
      effectiveEpochFloor: 101,
      integrityState: 1,
      checkpointAgeBand: 1,
      scrubAgeBand: 1,
      rebalanceState: 0,
      capacityBand: state.requireCurrent().descriptor.capacityBand
    })
  })
  const closed = await harness.readiness.evaluate({ endpointId: 1, transportSupportBit: harness.supportBit })
  t.is(closed.kind, READINESS_STATE_KIND.CLOSED)
  t.is(closed.reason, READINESS_CLOSED_REASON.CONTINUITY_UNVERIFIED)
})
