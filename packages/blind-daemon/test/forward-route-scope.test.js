import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  decodeCanonical,
  encodeCanonical,
  blindForwardRouteScopeV1
} from '@hiverelay/blind-protocol'
import {
  createDirectForwardParentContext,
  createForwardedForwardParentContext,
  verifyForwardHopOpenRouteScope
} from '../forward-route-scope.js'
import { ForwardStreamService } from '../forward-stream.js'
import { StreamSessionPlane } from '../stream-session.js'
import {
  fixtureBytes,
  fixtureForwardOpen,
  fixtureForwardResult,
  fixtureHopAccept,
  fixtureHopOpen,
  fixtureReadiness,
  fixtureRoute
} from './stream-fixtures.js'

const EPOCH = 100
const noTimer = {
  schedule: () => ({}),
  cancelSchedule: () => {}
}

function keypair (seed) {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, fixtureBytes(sodium.crypto_sign_SEEDBYTES, seed))
  return { publicKey, secretKey }
}

function relay (name, seed, descriptorSequence) {
  const keys = keypair(seed)
  return {
    name,
    ...keys,
    descriptorSequence: BigInt(descriptorSequence),
    descriptorHash: fixtureBytes(32, seed + 0x30)
  }
}

const RELAYS = Object.freeze({
  A: relay('A', 0x01, 11),
  B: relay('B', 0x02, 12),
  C: relay('C', 0x03, 13),
  D: relay('D', 0x04, 14),
  E: relay('E', 0x05, 15),
  F: relay('F', 0x06, 16)
})

const DESCRIPTORS = new Map(Object.values(RELAYS).map(value => [
  b4a.toString(value.publicKey, 'hex'),
  value
]))

function readiness (value) {
  return fixtureReadiness({
    descriptorSequence: value.descriptorSequence,
    descriptorHash: b4a.from(value.descriptorHash)
  })
}

function verifySignature (input) {
  if (input.domainId !== AUXILIARY_SIGNATURE_DOMAIN_ID.FORWARD_ROUTE_SCOPE) return false
  return sodium.crypto_sign_verify_detached(input.signature, input.payload, input.publicKey)
}

function verifyDescriptorBinding (input) {
  const descriptor = DESCRIPTORS.get(b4a.toString(input.relayPublicKey, 'hex'))
  return descriptor != null && descriptor.descriptorSequence === input.descriptorSequence &&
    b4a.equals(descriptor.descriptorHash, input.descriptorHash)
}

function signFor (value) {
  return input => {
    if (input.domainId !== AUXILIARY_SIGNATURE_DOMAIN_ID.FORWARD_ROUTE_SCOPE ||
        !b4a.equals(input.publicKey, value.publicKey)) {
      throw new Error('test signer refused an unbound route-scope request')
    }
    const signature = b4a.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(signature, input.payload, value.secretKey)
    return signature
  }
}

function link (from, to, seed, options = {}) {
  const request = fixtureForwardOpen({
    routeId: fixtureBytes(16, seed),
    nextDescriptorSequence: to.descriptorSequence,
    nextDescriptorHash: b4a.from(to.descriptorHash),
    circuitNonce: options.circuitNonce || fixtureBytes(32, seed + 1),
    parentRouteScopeHash: options.parentRouteScopeHash || fixtureBytes(32, 0),
    innerHandshake: fixtureBytes(32, seed + 2)
  })
  const route = fixtureRoute(from.publicKey, request, {
    nextRelayKey: b4a.from(to.publicKey),
    nextDescriptorSequence: to.descriptorSequence,
    nextDescriptorHash: b4a.from(to.descriptorHash),
    issuedEpoch: EPOCH,
    expiresEpoch: options.expiresEpoch == null ? EPOCH + 4 : options.expiresEpoch,
    maxRelayCount: options.maxRelayCount == null ? 4 : options.maxRelayCount
  })
  return { request, route }
}

function deferred () {
  let resolve
  const promise = new Promise(_resolve => { resolve = _resolve })
  return { promise, resolve }
}

async function eventually (predicate) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return
    await new Promise(resolve => setImmediate(resolve))
  }
  throw new Error('timed out waiting for test state')
}

function createHarness (from, to, pair, parentContext, overrides = {}) {
  let now = 100n
  let nowEpoch = EPOCH
  let currentParentContext = parentContext
  let nextStreamId = BigInt(100 + Number(from.descriptorSequence))
  let admissions = 0
  let allocations = 0
  let dials = 0
  let signatures = 0
  const events = []
  const persistentRecords = []
  const adjacentContexts = []
  const hopOpens = []
  const parentSessionId = fixtureBytes(16, Number(from.descriptorSequence))
  const plane = new StreamSessionPlane({
    monotonicMillis: () => now,
    randomBytes: length => fixtureBytes(length, Number(nextStreamId & 0xffn)),
    ...noTimer
  })
  const nextPort = {
    async write () {},
    async abort (reason) { events.push(`next-abort:${reason}`) }
  }
  const service = new ForwardStreamService({
    plane,
    relayPublicKey: from.publicKey,
    maxRecords: overrides.maxRecords,
    epochNow: () => nowEpoch,
    authenticateParent: async () => ({
      verified: true,
      parentSessionId,
      readiness: readiness(from),
      forwardParentContext: currentParentContext
    }),
    authorizeRoute: overrides.authorizeRoute || (async () => ({
      verified: true,
      dialPlan: Object.freeze({ adjacent: `${from.name}->${to.name}` }),
      route: pair.route
    })),
    authorizeAdmission: async input => {
      admissions++
      if (overrides.authorizeAdmission) return overrides.authorizeAdmission(input)
      return { accepted: true, spendTag: fixtureBytes(16, Number(from.descriptorSequence)) }
    },
    allocateStreamId: async () => {
      allocations++
      return nextStreamId++
    },
    verifyRouteScopeSignature: overrides.verifyRouteScopeSignature || verifySignature,
    verifyRouteScopeDescriptor: overrides.verifyRouteScopeDescriptor || verifyDescriptorBinding,
    signRouteScope: async input => {
      signatures++
      return signFor(from)(input)
    },
    buildHopOpen: fields => {
      const value = fixtureHopOpen(fields, {
        previousDescriptorSequence: from.descriptorSequence,
        previousDescriptorHash: b4a.from(from.descriptorHash)
      })
      hopOpens.push(value)
      return value
    },
    dialAuthorizedRoute: overrides.dialAuthorizedRoute || (async input => {
      dials++
      const adjacentContext = await verifyForwardHopOpenRouteScope(input.hopOpen, {
        receiverRelayPublicKey: to.publicKey,
        receiverDescriptor: readiness(to),
        nowEpoch,
        verifySignature,
        verifyDescriptorBinding,
        signal: input.signal
      })
      adjacentContexts.push(adjacentContext)
      const terminalHop = input.hopOpen.routeScope.hops[input.hopOpen.routeScope.hops.length - 1]
      const adjacentStreamId = nextStreamId++
      return {
        nextStreamId: adjacentStreamId,
        port: nextPort,
        hopAccept: fixtureHopAccept(from.publicKey, pair.route, pair.request, {
          previousDescriptorSequence: from.descriptorSequence,
          previousDescriptorHash: b4a.from(from.descriptorHash),
          nextStreamId: adjacentStreamId,
          acceptedRouteScopeHash: b4a.from(terminalHop.scopeHash),
          acceptedRelayCount: input.hopOpen.routeScope.hops.length
        })
      }
    }),
    verifyHopAccept: async () => true,
    buildResult: fields => fixtureForwardResult(from.publicKey, fields),
    persistence: {
      async reserve (record) {
        persistentRecords.push(record)
        events.push(`persist:${record.state}`)
      },
      async activate (record) {
        persistentRecords.push(record)
        events.push(`persist:${record.state}`)
      },
      async terminal (record) {
        persistentRecords.push(record)
        events.push(`persist:${record.state}:${record.terminalReason}`)
      }
    }
  })
  return {
    plane,
    service,
    pair,
    events,
    persistentRecords,
    adjacentContexts,
    hopOpens,
    admissions: () => admissions,
    allocations: () => allocations,
    dials: () => dials,
    signatures: () => signatures,
    setEpoch: value => { nowEpoch = value },
    setNow: value => { now = value },
    setParentContext: value => { currentParentContext = value }
  }
}

async function closeHarnesses (harnesses) {
  for (const harness of harnesses.reverse()) {
    await harness.service.close()
    await harness.plane.close()
  }
}

function assertNoAdmissionSideEffects (t, harness) {
  t.is(harness.admissions(), 0, 'no admission spend was accepted')
  t.is(harness.allocations(), 0, 'no stream ID was allocated')
  t.is(harness.dials(), 0, 'no adjacent socket was opened')
  t.is(harness.persistentRecords.length, 0, 'no retry/WAL state was persisted')
  t.is(harness.plane.activeStreams, 0, 'no live session or buffer was reserved')
  t.is(harness.service.routeCounts.size, 0, 'no signed route capacity was consumed')
}

async function openRoot (from, to, seed = 0x20, options = {}) {
  const pair = link(from, to, seed, options)
  const harness = createHarness(from, to, pair, createDirectForwardParentContext())
  const opened = await harness.service.open(pair.request)
  return { pair, harness, opened, context: harness.adjacentContexts[0] }
}

test('V-6 root and continuation append one signed relay each and bind exact scope echoes', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  const root = await openRoot(RELAYS.A, RELAYS.B)
  harnesses.push(root.harness)
  t.is(root.opened.result.acceptedRelayCount, 1)
  t.alike(root.opened.result.acceptedRouteScopeHash, root.context.inheritedScopeHash)
  t.is(root.harness.admissions(), 1)
  t.is(root.harness.dials(), 1)

  const continuationPair = link(RELAYS.B, RELAYS.C, 0x30, {
    parentRouteScopeHash: root.context.inheritedScopeHash
  })
  const continuation = createHarness(RELAYS.B, RELAYS.C, continuationPair, root.context)
  harnesses.push(continuation)
  const opened = await continuation.service.open(continuationPair.request)
  const scope = continuation.hopOpens[0].routeScope
  t.is(opened.result.acceptedRelayCount, 2)
  t.is(scope.hops.length, 2)
  t.alike(scope.hops[0].scopeHash, root.context.inheritedScopeHash)
  t.alike(scope.hops.map(hop => hop.relayPublicKey), [RELAYS.A.publicKey, RELAYS.B.publicKey])
  t.alike(opened.result.acceptedRouteScopeHash, scope.hops[1].scopeHash)
  t.is(continuation.adjacentContexts[0].inheritedRelayCount, 2)
  t.is(continuation.persistentRecords[0].relayCount, 2)
  t.alike(continuation.persistentRecords[0].routeScopeHash, scope.hops[1].scopeHash)

  const adjacentOptions = {
    receiverRelayPublicKey: RELAYS.B.publicKey,
    receiverDescriptor: readiness(RELAYS.B),
    nowEpoch: EPOCH,
    verifySignature,
    verifyDescriptorBinding
  }
  await t.exception(verifyForwardHopOpenRouteScope({
    ...root.harness.hopOpens[0],
    route: { ...root.harness.hopOpens[0].route, maxRelayCount: 3 }
  }, adjacentOptions), /changed the signed root relay-count bound/)
  await t.exception(verifyForwardHopOpenRouteScope(root.harness.hopOpens[0], {
    ...adjacentOptions,
    receiverDescriptor: {
      descriptorSequence: RELAYS.B.descriptorSequence,
      descriptorHash: fixtureBytes(32, 0xee)
    }
  }), /does not bind the receiving relay descriptor/)
})

test('V-6 forwarded reset, zero-root nested OPEN, and changed root proof fail before admission', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  const root = await openRoot(RELAYS.A, RELAYS.B, 0x40)
  harnesses.push(root.harness)

  const zeroPair = link(RELAYS.B, RELAYS.C, 0x41)
  const zero = createHarness(RELAYS.B, RELAYS.C, zeroPair, root.context)
  harnesses.push(zero)
  await t.exception(zero.service.open(zeroPair.request), /route scope was reset or changed/)
  assertNoAdmissionSideEffects(t, zero)

  const badCountContext = {
    ...root.context,
    inheritedRelayCount: root.context.inheritedRelayCount + 1
  }
  const countPair = link(RELAYS.B, RELAYS.C, 0x42, {
    parentRouteScopeHash: root.context.inheritedScopeHash
  })
  const count = createHarness(RELAYS.B, RELAYS.C, countPair, badCountContext)
  harnesses.push(count)
  await t.exception(count.service.open(countPair.request), /does not bind its complete route prefix/)
  assertNoAdmissionSideEffects(t, count)

  const changedRootId = b4a.from(root.context.routeScope.rootRouteId)
  changedRootId[0] ^= 0x80
  const changedContext = createForwardedForwardParentContext({
    ...root.context.routeScope,
    rootRouteId: changedRootId
  })
  const changedPair = link(RELAYS.B, RELAYS.C, 0x43, {
    parentRouteScopeHash: changedContext.inheritedScopeHash
  })
  const changed = createHarness(RELAYS.B, RELAYS.C, changedPair, changedContext)
  harnesses.push(changed)
  await t.exception(changed.service.open(changedPair.request), /prefix hash is invalid/)
  assertNoAdmissionSideEffects(t, changed)
})

test('V-6 max four relay entries rejects the fifth continuation without resource leakage', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  let parent = createDirectForwardParentContext()
  const chain = [RELAYS.A, RELAYS.B, RELAYS.C, RELAYS.D, RELAYS.E]
  for (let index = 0; index < 4; index++) {
    const pair = link(chain[index], chain[index + 1], 0x50 + index, {
      parentRouteScopeHash: parent.inheritedScopeHash || fixtureBytes(32, 0)
    })
    const harness = createHarness(chain[index], chain[index + 1], pair, parent)
    harnesses.push(harness)
    await harness.service.open(pair.request)
    parent = harness.adjacentContexts[0]
  }
  t.is(parent.inheritedRelayCount, 4)

  const overPair = link(RELAYS.E, RELAYS.F, 0x58, {
    parentRouteScopeHash: parent.inheritedScopeHash
  })
  const over = createHarness(RELAYS.E, RELAYS.F, overPair, parent)
  harnesses.push(over)
  await t.exception(over.service.open(overPair.request), /exceeds the signed route relay-count bound/)
  assertNoAdmissionSideEffects(t, over)
})

test('V-6 A-B-A and A-B-C-A route cycles fail before spend, reservation, or dial', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  const root = await openRoot(RELAYS.A, RELAYS.B, 0x60)
  harnesses.push(root.harness)

  const shortPair = link(RELAYS.B, RELAYS.A, 0x61, {
    parentRouteScopeHash: root.context.inheritedScopeHash
  })
  const short = createHarness(RELAYS.B, RELAYS.A, shortPair, root.context)
  harnesses.push(short)
  await t.exception(short.service.open(shortPair.request), /would create a relay cycle/)
  assertNoAdmissionSideEffects(t, short)

  const middlePair = link(RELAYS.B, RELAYS.C, 0x62, {
    parentRouteScopeHash: root.context.inheritedScopeHash
  })
  const middle = createHarness(RELAYS.B, RELAYS.C, middlePair, root.context)
  harnesses.push(middle)
  await middle.service.open(middlePair.request)
  const middleContext = middle.adjacentContexts[0]
  const longPair = link(RELAYS.C, RELAYS.A, 0x63, {
    parentRouteScopeHash: middleContext.inheritedScopeHash
  })
  const long = createHarness(RELAYS.C, RELAYS.A, longPair, middleContext)
  harnesses.push(long)
  await t.exception(long.service.open(longPair.request), /would create a relay cycle/)
  assertNoAdmissionSideEffects(t, long)
})

test('V-6 omitted, reordered, bit-flipped, and signature-mutated prefixes all fail closed', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  const root = await openRoot(RELAYS.A, RELAYS.B, 0x70)
  harnesses.push(root.harness)
  const middlePair = link(RELAYS.B, RELAYS.C, 0x71, {
    parentRouteScopeHash: root.context.inheritedScopeHash
  })
  const middle = createHarness(RELAYS.B, RELAYS.C, middlePair, root.context)
  harnesses.push(middle)
  await middle.service.open(middlePair.request)
  const original = middle.adjacentContexts[0].routeScope

  const omittedHop = {
    ...original.hops[1],
    hopIndex: 0,
    previousScopeHash: fixtureBytes(32, 0)
  }
  const reorderedFirst = { ...original.hops[1], hopIndex: 0, previousScopeHash: fixtureBytes(32, 0) }
  const reorderedSecond = { ...original.hops[0], hopIndex: 1, previousScopeHash: original.hops[1].scopeHash }
  const flippedHash = b4a.from(original.hops[1].scopeHash)
  flippedHash[0] ^= 1
  const flippedSignature = b4a.from(original.hops[1].relaySignature)
  flippedSignature[0] ^= 1
  const cases = [
    { name: 'omitted', scope: { ...original, hops: [omittedHop] } },
    { name: 'reordered', scope: { ...original, hops: [reorderedFirst, reorderedSecond] } },
    {
      name: 'bit-flipped',
      scope: { ...original, hops: [original.hops[0], { ...original.hops[1], scopeHash: flippedHash }] }
    },
    {
      name: 'signature-mutated',
      scope: { ...original, hops: [original.hops[0], { ...original.hops[1], relaySignature: flippedSignature }] }
    }
  ]

  for (let index = 0; index < cases.length; index++) {
    const candidate = createForwardedForwardParentContext(cases[index].scope)
    const pair = link(RELAYS.C, RELAYS.D, 0x74 + index, {
      parentRouteScopeHash: candidate.inheritedScopeHash
    })
    const harness = createHarness(RELAYS.C, RELAYS.D, pair, candidate)
    harnesses.push(harness)
    await t.exception(harness.service.open(pair.request), /prefix hash is invalid|relay signature is invalid/,
      `${cases[index].name} prefix is rejected`)
    assertNoAdmissionSideEffects(t, harness)
  }
})

test('V-6 expired scope and descriptor mismatch reject before admission or adjacent socket', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  const root = await openRoot(RELAYS.A, RELAYS.B, 0x80)
  harnesses.push(root.harness)

  const expiredPair = link(RELAYS.B, RELAYS.C, 0x81, {
    parentRouteScopeHash: root.context.inheritedScopeHash
  })
  const expired = createHarness(RELAYS.B, RELAYS.C, expiredPair, root.context)
  expired.setEpoch(EPOCH + 4)
  harnesses.push(expired)
  await t.exception(expired.service.open(expiredPair.request), /route scope is expired/)
  assertNoAdmissionSideEffects(t, expired)

  const mismatchPair = link(RELAYS.B, RELAYS.C, 0x82, {
    parentRouteScopeHash: root.context.inheritedScopeHash
  })
  const mismatch = createHarness(RELAYS.B, RELAYS.C, mismatchPair, root.context, {
    verifyRouteScopeDescriptor: async () => false
  })
  harnesses.push(mismatch)
  await t.exception(mismatch.service.open(mismatchPair.request), /descriptor binding is invalid/)
  assertNoAdmissionSideEffects(t, mismatch)

  const reducedExpiryPair = link(RELAYS.B, RELAYS.C, 0x83, {
    parentRouteScopeHash: root.context.inheritedScopeHash,
    expiresEpoch: EPOCH + 3
  })
  const reducedExpiry = createHarness(RELAYS.B, RELAYS.C, reducedExpiryPair, root.context)
  harnesses.push(reducedExpiry)
  await t.exception(reducedExpiry.service.open(reducedExpiryPair.request), /changed the signed root expiry/)
  assertNoAdmissionSideEffects(t, reducedExpiry)
})

test('invalid admission allocates nothing and releases its bounded nonce claim', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  const pair = link(RELAYS.A, RELAYS.B, 0x84)
  const harness = createHarness(RELAYS.A, RELAYS.B, pair, createDirectForwardParentContext(), {
    maxRecords: 1,
    authorizeAdmission: async () => ({ accepted: false })
  })
  harnesses.push(harness)
  await t.exception(harness.service.open(pair.request), /admission was not accepted/)
  t.is(harness.admissions(), 1)
  t.is(harness.allocations(), 0)
  t.is(harness.dials(), 0)
  t.is(harness.persistentRecords.length, 0)
  t.is(harness.service.claimsByNonce.size, 0)
  await t.exception(harness.service.open({
    ...pair.request,
    circuitNonce: fixtureBytes(32, 0x85)
  }), /admission was not accepted/)
  t.is(harness.admissions(), 2, 'released claim did not permanently consume maxRecords')
  t.is(harness.allocations(), 0)
  t.is(harness.service.claimsByNonce.size, 0)
})

test('spend replay and saturated route reject before allocating another stream ID', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))

  const replayPair = link(RELAYS.A, RELAYS.B, 0x86)
  const replay = createHarness(RELAYS.A, RELAYS.B, replayPair, createDirectForwardParentContext())
  harnesses.push(replay)
  await replay.service.open(replayPair.request)
  await t.exception(replay.service.open({
    ...replayPair.request,
    circuitNonce: fixtureBytes(32, 0xf7)
  }), /spend tag was already used/)
  t.is(replay.admissions(), 2)
  t.is(replay.allocations(), 1, 'SPEND_REPLAY allocated no replacement stream ID')
  t.is(replay.dials(), 1)
  t.is(replay.service.claimsByNonce.size, 0)
  t.is(replay.service.recordsByNonce.size, 1)

  let spend = 0
  const baseBusyPair = link(RELAYS.C, RELAYS.D, 0x88)
  const busyPair = {
    request: baseBusyPair.request,
    route: { ...baseBusyPair.route, maxConcurrentStreams: 1 }
  }
  const busy = createHarness(RELAYS.C, RELAYS.D, busyPair, createDirectForwardParentContext(), {
    authorizeAdmission: async () => ({
      accepted: true,
      spendTag: fixtureBytes(16, 0x50 + spend++)
    })
  })
  harnesses.push(busy)
  await busy.service.open(busyPair.request)
  await t.exception(busy.service.open({
    ...busyPair.request,
    circuitNonce: fixtureBytes(32, 0xf9)
  }), /route stream capacity is exhausted/)
  t.is(busy.admissions(), 2)
  t.is(busy.allocations(), 1, 'route BUSY allocated no replacement stream ID')
  t.is(busy.dials(), 1)
  t.is(busy.service.claimsByNonce.size, 0)
  t.is(busy.service.recordsByNonce.size, 1)
  t.is(busy.service.routeCounts.size, 1)
})

test('V-6 one circuit nonce cannot retry under another authenticated route scope', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  const firstRoot = await openRoot(RELAYS.A, RELAYS.B, 0x90)
  const secondRoot = await openRoot(RELAYS.D, RELAYS.B, 0x91)
  harnesses.push(firstRoot.harness, secondRoot.harness)
  const nonce = fixtureBytes(32, 0x92)
  const pair = link(RELAYS.B, RELAYS.C, 0x93, {
    circuitNonce: nonce,
    parentRouteScopeHash: firstRoot.context.inheritedScopeHash
  })
  const harness = createHarness(RELAYS.B, RELAYS.C, pair, firstRoot.context)
  harnesses.push(harness)
  await harness.service.open(pair.request)
  const persistedBefore = harness.persistentRecords.length

  const invalidSignature = b4a.from(firstRoot.context.routeScope.hops[0].relaySignature)
  invalidSignature[0] ^= 1
  const invalidContext = createForwardedForwardParentContext({
    ...firstRoot.context.routeScope,
    hops: [{ ...firstRoot.context.routeScope.hops[0], relaySignature: invalidSignature }]
  })
  harness.setParentContext(invalidContext)
  await t.exception(harness.service.open(pair.request), /relay signature is invalid/)
  t.is(harness.admissions(), 1, 'retry fast path did not bypass full-prefix verification')

  harness.setParentContext(secondRoot.context)
  const changed = {
    ...pair.request,
    parentRouteScopeHash: b4a.from(secondRoot.context.inheritedScopeHash)
  }
  await t.exception(harness.service.open(changed), /nonce was reused with another route scope/)
  t.is(harness.admissions(), 1)
  t.is(harness.dials(), 1)
  t.is(harness.persistentRecords.length, persistedBefore, 'conflicting retry added no ambiguous terminal record')
  t.is(harness.plane.activeStreams, 1)
})

test('concurrent exact same-nonce opens share one atomic spend, record, and dial', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  const gate = deferred()
  const admissionStarted = deferred()
  const pair = link(RELAYS.A, RELAYS.B, 0x98)
  const harness = createHarness(RELAYS.A, RELAYS.B, pair, createDirectForwardParentContext(), {
    authorizeAdmission: async () => {
      admissionStarted.resolve()
      await gate.promise
      return { accepted: true, spendTag: fixtureBytes(16, 0x44) }
    }
  })
  harnesses.push(harness)
  const first = harness.service.open(pair.request)
  await admissionStarted.promise
  const second = harness.service.open(pair.request)
  await eventually(() => harness.signatures() === 2)
  t.is(harness.admissions(), 1, 'only the nonce-claim owner entered admission')
  t.is(harness.allocations(), 0, 'admission must settle before stream allocation')
  t.is(harness.dials(), 0)
  gate.resolve()
  const [firstOpened, secondOpened] = await Promise.all([first, second])
  t.alike(secondOpened.result, firstOpened.result)
  t.alike(secondOpened.ticket, firstOpened.ticket)
  t.is(harness.admissions(), 1)
  t.is(harness.allocations(), 1)
  t.is(harness.dials(), 1)
  t.is(harness.persistentRecords.filter(record => record.state === 'FORWARD_RESERVED').length, 1)
  t.is(harness.persistentRecords.filter(record => record.state === 'LIVE').length, 1)
  t.is(harness.service.recordsByNonce.size, 1)
  t.is(harness.service.claimsByNonce.size, 0)
  t.is(harness.service.routeCounts.size, 1)
  t.is(harness.plane.activeStreams, 1)
})

test('concurrent same-nonce different-scope open conflicts before a second spend or allocation', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  const firstRoot = await openRoot(RELAYS.A, RELAYS.B, 0x99)
  const secondRoot = await openRoot(RELAYS.D, RELAYS.B, 0x9a)
  harnesses.push(firstRoot.harness, secondRoot.harness)
  const gate = deferred()
  const admissionStarted = deferred()
  const nonce = fixtureBytes(32, 0x9b)
  const pair = link(RELAYS.B, RELAYS.C, 0x9c, {
    circuitNonce: nonce,
    parentRouteScopeHash: firstRoot.context.inheritedScopeHash
  })
  const harness = createHarness(RELAYS.B, RELAYS.C, pair, firstRoot.context, {
    authorizeAdmission: async () => {
      admissionStarted.resolve()
      await gate.promise
      return { accepted: true, spendTag: fixtureBytes(16, 0x45) }
    }
  })
  harnesses.push(harness)
  const first = harness.service.open(pair.request)
  await admissionStarted.promise
  harness.setParentContext(secondRoot.context)
  const conflicting = {
    ...pair.request,
    parentRouteScopeHash: b4a.from(secondRoot.context.inheritedScopeHash)
  }
  await t.exception(harness.service.open(conflicting), /nonce was reused with another route scope/)
  t.is(harness.admissions(), 1, 'conflicting claimant never entered admission')
  t.is(harness.allocations(), 0, 'blocked owner and conflicting claimant allocated no stream ID')
  t.is(harness.dials(), 0)
  t.is(harness.persistentRecords.length, 0)
  t.is(harness.plane.activeStreams, 0)
  gate.resolve()
  await first
  t.is(harness.admissions(), 1)
  t.is(harness.allocations(), 1)
  t.is(harness.dials(), 1)
  t.is(harness.persistentRecords.filter(record => record.state === 'FORWARD_RESERVED').length, 1)
  t.is(harness.persistentRecords.filter(record => record.state === 'LIVE').length, 1)
  t.is(harness.service.recordsByNonce.size, 1)
  t.is(harness.service.claimsByNonce.size, 0)
  t.is(harness.service.routeCounts.size, 1)
  t.is(harness.plane.activeStreams, 1)
})

test('shutdown terminalizes one unrecorded nonce claim and rejects all exact waiters', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  const gate = deferred()
  const admissionStarted = deferred()
  const pair = link(RELAYS.A, RELAYS.B, 0x9d)
  const harness = createHarness(RELAYS.A, RELAYS.B, pair, createDirectForwardParentContext(), {
    authorizeAdmission: async () => {
      admissionStarted.resolve()
      await gate.promise
      return { accepted: true, spendTag: fixtureBytes(16, 0x46) }
    }
  })
  harnesses.push(harness)
  const owner = harness.service.open(pair.request)
  await admissionStarted.promise
  const waiter = harness.service.open(pair.request)
  await eventually(() => harness.signatures() === 2)
  const waiterRejected = t.exception(waiter, /closed during nonce claim/)
  await harness.service.close('daemon-shutdown')
  await waiterRejected
  gate.resolve()
  await t.exception(owner, /closed during nonce claim/)
  t.is(harness.admissions(), 1)
  t.is(harness.allocations(), 0)
  t.is(harness.dials(), 0)
  t.is(harness.persistentRecords.length, 0)
  t.is(harness.plane.activeStreams, 0)
  t.is(harness.service.recordsByNonce.size, 0)
  t.is(harness.service.claimsByNonce.size, 0)
  t.is(harness.service.routeCounts.size, 0)
})

test('V-6 shutdown racing a valid continuation leaves one terminal record and no resources', async t => {
  const harnesses = []
  t.teardown(() => closeHarnesses(harnesses))
  const root = await openRoot(RELAYS.A, RELAYS.B, 0xa0)
  harnesses.push(root.harness)
  const pair = link(RELAYS.B, RELAYS.C, 0xa1, {
    parentRouteScopeHash: root.context.inheritedScopeHash
  })
  const dialStarted = deferred()
  const harness = createHarness(RELAYS.B, RELAYS.C, pair, root.context, {
    dialAuthorizedRoute: async ({ signal }) => {
      dialStarted.resolve()
      await new Promise((resolve, reject) => {
        if (signal.aborted) return reject(new Error('shutdown'))
        signal.addEventListener('abort', () => reject(new Error('shutdown')), { once: true })
      })
    }
  })
  harnesses.push(harness)
  const opening = harness.service.open(pair.request)
  await dialStarted.promise
  await harness.service.close('daemon-shutdown')
  await t.exception(opening, /authorized dial failed terminally/)
  const terminals = harness.persistentRecords.filter(record => record.state === 'TERMINAL')
  t.is(terminals.length, 1)
  t.is(harness.plane.activeStreams, 0)
  t.is(harness.service.routeCounts.size, 0)
  t.is(harness.plane.bufferedBytes, 0)
  t.is(harness.plane.tickets.size, 0)
})

test('route-scope parent context owns canonical bytes and rejects trailing mutation', t => {
  const root = decodeCanonical(blindForwardRouteScopeV1,
    encodeCanonical(blindForwardRouteScopeV1, {
      version: 1,
      rootRouteId: fixtureBytes(16, 1),
      rootCircuitNonce: fixtureBytes(32, 2),
      rootRequestCommitment: fixtureBytes(32, 3),
      maxRelayCount: 2,
      expiresEpoch: 4,
      hops: [{
        hopIndex: 0,
        relayPublicKey: fixtureBytes(32, 4),
        descriptorSequence: 1n,
        descriptorHash: fixtureBytes(32, 5),
        previousScopeHash: fixtureBytes(32, 0),
        scopeHash: fixtureBytes(32, 6),
        relaySignature: fixtureBytes(64, 7)
      }]
    }), { copyBytes: true })
  const context = createForwardedForwardParentContext(root)
  root.rootRouteId[0] ^= 1
  t.is(context.routeScope.rootRouteId[0], 1, 'context copied the adapter-owned scope bytes')
})
