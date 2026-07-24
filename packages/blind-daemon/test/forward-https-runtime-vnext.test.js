// Daemon-side evidence for the vNext direct-HTTPS runtime (relock
// activation serial integration). DESCRIBE section: the signed health
// challenge path with degraded and failed dependency integrity, descriptor
// fork/rollback fault behavior, and health result signature binding. Later
// sections cover CELL, INBOX, CORE and the FORWARD one-hop runtime against
// the accepted storage layer. macOS environment: peercred is real
// (getpeereid); Linux SO_PEERCRED, Chromium/IndexedDB and Bare are deferred
// to syd-1 qualification and recorded in the lane evidence.

import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ADVERTISED_OPERATION_BITS,
  CLOCK_UNSAFE_OPERATION_BITS,
  HEALTH_CLOCK_STATE,
  HEALTH_INTEGRITY_STATE,
  HEALTH_REBALANCE_STATE,
  TRANSPORT_SUPPORT,
  blindHealthResultV1,
  decodeCanonical
} from '@hiverelay/blind-protocol'
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
  createRelayIdentityFixture,
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
