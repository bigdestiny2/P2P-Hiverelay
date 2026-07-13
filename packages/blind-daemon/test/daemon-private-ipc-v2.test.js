import fs from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'brittle'
import b4a from 'b4a'
import {
  ERROR_CODE,
  FRAME_KIND,
  blindErrorV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  decodeDispatchFrame,
  decodeOuterEnvelope,
  encodeCanonical
} from '@hiverelay/blind-protocol'
import {
  CELL_PUT_ENDPOINT_ROLE_BIT_V2,
  CELL_PUT_OPERATION_BIT_V2,
  LOCAL_STAGED_DIRECTION_V2,
  LOCAL_STAGED_FLAG_V2,
  LOCAL_STAGED_FRAME_KIND_V2,
  OUTER_CLASS,
  PRIVATE_IPC_V2_LIMITS,
  REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
  decodeLocalReadyAckV2,
  decodeLocalStagedCellPutFramesV2,
  decodeLocalTransportBindingV2,
  deriveLocalStagedOpenBindingHashV2,
  encodeLocalReadyProbeV2,
  encodeLocalStagedCellPutFrameV2,
  encodeLocalStagedCellPutOpenV2,
  encodeLocalTransportBindingV2,
  verifyStagedCellPutPublicOuterEnvelopeV2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import {
  BlindDaemon,
  STAGED_PUT_MEMORY_LEDGER_V2,
  STAGED_PUT_SOCKET_RESERVATION_BYTES_V2,
  STAGED_PUT_STREAM_RESERVATION_BYTES_V2,
  V2_WRITE_DISABLED_REASON
} from '../server.js'
import { BlindOperationCoordinator } from '../coordinator.js'
import { DescriptorState } from '../descriptor-state.js'
import { BoundedReplayGuardV2 } from '../private-ipc-v2-runtime.js'
import { ResourceBudget } from '../resource-budget.js'
import { stagedCellPutAuthority } from '../staged-put.js'
import { descriptorValue } from './coordinator-fixtures.js'

const TOPOLOGY_HASH = b4a.alloc(32, 0xa1)
const PROFILE_HASH = b4a.alloc(32, 0xa4)
const DESCRIPTOR_HASH = b4a.alloc(32, 0xd1)
const ENDPOINT_ID = 7
const TEST_TMP_PREFIX = fileURLToPath(new URL('../../../.test-tmp-blind-daemon-v2-', import.meta.url))
const REQUEST_OUTER = readFileSync(new URL(
  '../../blind-ipc/vectors/v2/accepted/public-request-outer-envelope-class-3.bin', import.meta.url))
const RESULT_OUTER = readFileSync(new URL(
  '../../blind-ipc/vectors/v2/accepted/public-result-outer-envelope-class-3.bin', import.meta.url))
const V1_STAGED_OPEN = readFileSync(new URL(
  '../../blind-ipc/vectors/fixtures/stream-open-public-dispatch-class-3.bin', import.meta.url))

function socketPaths (directory) {
  return {
    unarySocketPath: path.join(directory, 'unary.sock'),
    streamSocketPath: path.join(directory, 'stream.sock')
  }
}

function makeOpen (accepted, options = {}) {
  const outerClass = options.outerClass == null ? 3 : options.outerClass
  const edgeProcessNonce = b4a.alloc(32, options.nonceByte == null ? 0xa2 : options.nonceByte)
  const localChannelNonce = b4a.alloc(32, options.channelByte == null ? 0xa3 : options.channelByte)
  const publicSessionBindingHash = b4a.alloc(32, options.sessionByte == null ? 0xa5 : options.sessionByte)
  const fields = Object.freeze({
    endpointId: ENDPOINT_ID,
    outerClass,
    acceptedMonotonicMillis: accepted,
    openDeadlineMonotonicMillis: accepted + (options.deadlineMillis == null ? 15_000n : options.deadlineMillis),
    requestEnvelopeBytes: OUTER_CLASS[outerClass]
  })
  const openBindingHash = deriveLocalStagedOpenBindingHashV2({
    open: fields,
    launchTopologyHash: TOPOLOGY_HASH,
    authorityKind: 1,
    edgeProcessNonce,
    localChannelNonce,
    transportProfileHash: PROFILE_HASH,
    publicSessionBindingHash
  })
  const context = decodeLocalTransportBindingV2(encodeLocalTransportBindingV2({
    authorityKind: 1,
    edgeProcessNonce,
    localChannelNonce,
    transportProfileHash: PROFILE_HASH,
    publicSessionBindingHash,
    openBindingHash
  }))
  return encodeLocalStagedCellPutOpenV2({ ...fields, context })
}

function requestFrames (overrides = {}) {
  const outer = overrides.outer == null ? REQUEST_OUTER : overrides.outer
  const split = 65_515
  return [
    encodeLocalStagedCellPutFrameV2({
      direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
      frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
      sequence: overrides.firstSequence == null ? 0n : overrides.firstSequence,
      flags: 0,
      bytes: outer.subarray(0, split)
    }),
    encodeLocalStagedCellPutFrameV2({
      direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
      frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
      sequence: overrides.secondSequence == null ? 1n : overrides.secondSequence,
      flags: overrides.lastFlags == null ? LOCAL_STAGED_FLAG_V2.FIN : overrides.lastFlags,
      bytes: outer.subarray(split)
    })
  ]
}

function canonicalErrorName (dispatch) {
  const frame = decodeDispatchFrame(dispatch, { copyBody: true })
  const value = decodeCanonical(blindErrorV1, frame.body)
  return Object.keys(ERROR_CODE).find(name => ERROR_CODE[name] === value.code)
}

async function earlyErrorCoordinator (now) {
  const value = descriptorValue()
  value.endpoints[0].endpointId = ENDPOINT_ID
  const state = new DescriptorState({ epochNow: () => 101, verifySignature: async () => true })
  await state.activate(encodeCanonical(blindServiceDescriptorV1, value))
  const unexpected = name => async () => { throw new Error(`unexpected ${name}`) }
  return new BlindOperationCoordinator({
    descriptorState: state,
    admission: {
      prepare: unexpected('admission'),
      parametersForRequest: () => null
    },
    readiness: { evaluate: unexpected('readiness') },
    budget: new ResourceBudget({ maxItems: 4, maxBytes: 1024 * 1024 }),
    relationVerifier: { async verify () { return true } },
    capabilityVerifier: { async verify () { return false } },
    cheapStateVerifier: { inspect: unexpected('cheap-state verification') },
    terminalStateVerifier: { check: unexpected('terminal-state verification') },
    capacityGuard: { check: unexpected('capacity check') },
    operationExecutor: { execute: unexpected('operation execution') },
    resultVerifier: { verify: unexpected('result verification') },
    authenticatedSessionVerifier: { verify: unexpected('session verification') },
    monotonicMillis: () => now + 1n
  })
}

function defaultProjection (input, overrides = {}) {
  const expires = overrides.expiresMonotonicMillis == null
    ? input.absoluteDeadlineMonotonicMillis - 1n
    : overrides.expiresMonotonicMillis
  return {
    selfVerified: true,
    cellRuntimeReady: true,
    storageReady: true,
    admissionReady: true,
    endpointId: ENDPOINT_ID,
    launchTopologyHash: TOPOLOGY_HASH,
    transportProfileHash: PROFILE_HASH,
    descriptorSequence: 9n,
    descriptorHash: DESCRIPTOR_HASH,
    descriptorRoleBits: CELL_PUT_ENDPOINT_ROLE_BIT_V2,
    descriptorEnabledOperationBits: CELL_PUT_OPERATION_BIT_V2,
    readyRoleBits: CELL_PUT_ENDPOINT_ROLE_BIT_V2,
    readyOperationBits: CELL_PUT_OPERATION_BIT_V2,
    readyWriteOperationBits: CELL_PUT_OPERATION_BIT_V2,
    readyIpcFeatureBits: REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
    expiresMonotonicMillis: expires,
    descriptorExpiresMonotonicMillis: input.absoluteDeadlineMonotonicMillis,
    ...overrides
  }
}

function testDurableReplayAuthority (options = {}) {
  const guard = new BoundedReplayGuardV2({
    capacity: options.capacity == null ? 4096 : options.capacity,
    maximumTtlMillis: BigInt(PRIVATE_IPC_V2_LIMITS.OPEN_DEADLINE_MILLIS)
  })
  return Object.freeze({
    async reserve (input) {
      guard.reserve(input.replayTupleHash, input.expiresMonotonicMillis,
        input.nowMonotonicMillis)
      return Object.freeze({
        kind: 'reserved-new',
        durablyCommitted: true,
        replayTupleHash: b4a.from(input.replayTupleHash),
        expiresMonotonicMillis: input.expiresMonotonicMillis
      })
    }
  })
}

async function createDaemon (t, options = {}) {
  const directory = await fs.mkdtemp(TEST_TMP_PREFIX)
  const paths = socketPaths(directory)
  const errors = []
  const durableReplayAuthority = Object.hasOwn(options, 'durableReplayAuthority')
    ? options.durableReplayAuthority
    : options.writeReadinessProjection
      ? testDurableReplayAuthority({ capacity: options.replayCapacity })
      : null
  const profileOptions = Object.hasOwn(options, 'streamTransportProfileHashForEndpoint')
    ? { streamTransportProfileHashForEndpoint: options.streamTransportProfileHashForEndpoint }
    : Object.hasOwn(options, 'streamTransportProfileHash')
      ? { streamTransportProfileHash: options.streamTransportProfileHash }
      : { streamTransportProfileHash: PROFILE_HASH }
  const daemon = new BlindDaemon({
    ...paths,
    expectedPeerUid: options.expectedPeerUid == null ? process.getuid() : options.expectedPeerUid,
    expectedPeerGid: process.getgid(),
    socketGroupGid: process.getgid(),
    launchTopologyHash: TOPOLOGY_HASH,
    endpointIds: [ENDPOINT_ID],
    releaseGate: () => {},
    dispatch: async () => { throw new Error('V2 tests must not enter unary dispatch') },
    readinessSnapshot: async () => ({
      selfVerified: true,
      descriptorSequence: 9n,
      descriptorHash: DESCRIPTOR_HASH,
      readyRoleBits: CELL_PUT_ENDPOINT_ROLE_BIT_V2,
      readyOperationBits: 0x7
    }),
    ...profileOptions,
    dispatchStagedPut: Object.hasOwn(options, 'dispatchStagedPut')
      ? options.dispatchStagedPut
      : async () => { throw new Error('unexpected staged dispatch') },
    durableReplayAuthority,
    writeReadinessProjection: options.writeReadinessProjection,
    monotonicMillis: options.monotonicMillis,
    maxBufferedBytes: options.maxBufferedBytes,
    maxConnections: options.maxConnections,
    onError: error => errors.push(error)
  })
  await daemon.start()
  t.teardown(async () => {
    await daemon.close()
    await fs.rm(directory, { recursive: true, force: true })
  })
  return { daemon, paths, errors }
}

function connectedSocket (socketPath) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath })
    socket.once('connect', () => resolve(socket))
    socket.once('error', reject)
  })
}

function collectSocket (socket, timeout = 3000) {
  const chunks = []
  let total = 0
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (!socket.destroyed) socket.destroy()
      if (error) reject(error)
      else resolve(b4a.concat(chunks, total))
    }
    const timer = setTimeout(() => finish(new Error('private IPC socket exchange timed out')), timeout)
    socket.on('data', chunk => {
      chunks.push(b4a.from(chunk))
      total += chunk.byteLength
    })
    socket.once('end', () => finish())
    socket.once('close', () => finish())
    socket.once('error', error => {
      if (error.code === 'ECONNRESET' || error.code === 'EPIPE') finish()
      else finish(error)
    })
  })
}

async function rejectedStream (socketPath, chunks) {
  const socket = await connectedSocket(socketPath)
  const collected = collectSocket(socket)
  for (const chunk of chunks) socket.write(chunk)
  socket.end()
  return collected
}

async function unaryExchange (socketPath, bytes) {
  const socket = await connectedSocket(socketPath)
  const collected = collectSocket(socket)
  socket.end(bytes)
  return collected
}

function delay (millis) {
  return new Promise(resolve => setTimeout(resolve, millis))
}

function deferred () {
  let release
  const promise = new Promise(resolve => { release = resolve })
  return { promise, resolve: release }
}

async function waitForDaemonRelease (daemon, timeout = 1000) {
  const started = Date.now()
  while (Date.now() - started < timeout) {
    if (daemon.sockets.size === 0 && daemon.tasks.size === 0 &&
        daemon.abortControllers.size === 0 && daemon.bufferedBytes === 0) return
    await delay(10)
  }
  throw new Error('daemon did not release its socket/task/memory state')
}

test('V2 stream memory ledger is frozen and matches the exact-reader structural peak', t => {
  t.ok(Object.isFrozen(STAGED_PUT_MEMORY_LEDGER_V2))
  t.alike(STAGED_PUT_MEMORY_LEDGER_V2, {
    socketReadBytes: 131_070,
    frameReaderBytes: 65_535,
    frameDecoderPeakBytes: 327_635,
    stagedIngressBytes: 87_750,
    resultEncoderPeakBytes: 229_429
  })
  t.is(STAGED_PUT_SOCKET_RESERVATION_BYTES_V2, 131_070)
  t.is(STAGED_PUT_STREAM_RESERVATION_BYTES_V2, 775_884)
})

test('real V2 Unix stream requires FIN plus actual EOF and returns one same-class full outer result', async t => {
  const now = 1_000_000n
  let dispatchCalls = 0
  let commits = 0
  const harness = await createDaemon(t, {
    monotonicMillis: () => now,
    writeReadinessProjection: async input => defaultProjection(input),
    dispatchStagedPut: async (staged, context) => {
      dispatchCalls++
      const authority = stagedCellPutAuthority(staged)
      let bodyBytes = 0
      for await (const chunk of authority.source) bodyBytes += chunk.byteLength
      const validated = await authority.ensureBodyValidated()
      t.is(bodyBytes, authority.sourceByteLength)
      t.is(validated.byteLength, bodyBytes)
      t.is(context.outerClass, 3)
      t.is(context.absoluteDeadlineMonotonicMillis, now + 14_999n)
      t.is(context.signal.aborted, false)
      commits++
      return {
        dispatch: decodeOuterEnvelope(RESULT_OUTER, { copyInner: true }).innerDispatch,
        outerClass: context.outerClass
      }
    }
  })
  t.is(harness.daemon.v2WriteDisabledReason, null)
  const socket = await connectedSocket(harness.paths.streamSocketPath)
  const response = collectSocket(socket)
  const [first, last] = requestFrames()
  socket.write(makeOpen(now))
  socket.write(first)
  socket.write(last)
  await delay(30)
  for (const error of harness.errors) t.comment(`${error.code || 'ERROR'}: ${error.message}`)
  t.is(dispatchCalls, 1, 'metadata may enter dispatch before transport EOF')
  t.is(commits, 0, 'FIN alone cannot close the staged body or commit')
  socket.end()

  const wire = await response
  for (const error of harness.errors) t.comment(`${error.code || 'ERROR'}: ${error.message}`)
  t.is(commits, 1)
  const decoded = decodeLocalStagedCellPutFramesV2(wire)
  t.is(decoded.remainder.byteLength, 0)
  t.is(decoded.frames.length, 2)
  t.is(decoded.frames[0].direction, LOCAL_STAGED_DIRECTION_V2.RESULT)
  t.is(decoded.frames.at(-1).flags, LOCAL_STAGED_FLAG_V2.FIN)
  const outer = b4a.concat(decoded.frames.map(frame => frame.bytes))
  t.is(outer.byteLength, OUTER_CLASS[3])
  const verified = verifyStagedCellPutPublicOuterEnvelopeV2(outer, makeOpen(now),
    LOCAL_STAGED_DIRECTION_V2.RESULT, decodeOuterEnvelope(REQUEST_OUTER).frame.requestId)
  t.is(verified.outerClass, 3)
  t.is(harness.daemon.v2ReplayReservationCount, 1)
})

test('real V2 retains an early coordinator error until valid FIN plus EOF and suppresses it on invalid bodies', async t => {
  const now = 1_250_000n
  const coordinator = await earlyErrorCoordinator(now)
  const harness = await createDaemon(t, {
    monotonicMillis: () => now,
    writeReadinessProjection: async input => defaultProjection(input),
    dispatchStagedPut: coordinator.dispatchStagedCellPut.bind(coordinator)
  })

  const validOpen = makeOpen(now, { nonceByte: 0xa6 })
  const socket = await connectedSocket(harness.paths.streamSocketPath)
  const response = collectSocket(socket)
  let responseBytesBeforeEof = 0
  socket.on('data', chunk => { responseBytesBeforeEof += chunk.byteLength })
  const [first, last] = requestFrames()
  socket.write(validOpen)
  socket.write(first)
  socket.write(last)
  await delay(30)
  t.is(responseBytesBeforeEof, 0, 'early error is retained until authenticated peer EOF')
  socket.end()

  const wire = await response
  const decoded = decodeLocalStagedCellPutFramesV2(wire)
  t.is(decoded.remainder.byteLength, 0)
  t.is(decoded.frames.at(-1).flags, LOCAL_STAGED_FLAG_V2.FIN)
  const resultOuter = b4a.concat(decoded.frames.map(frame => frame.bytes))
  const verified = verifyStagedCellPutPublicOuterEnvelopeV2(resultOuter, validOpen,
    LOCAL_STAGED_DIRECTION_V2.RESULT, decodeOuterEnvelope(REQUEST_OUTER).frame.requestId)
  t.is(verified.outerClass, 3)
  const resultDispatch = decodeOuterEnvelope(resultOuter, { copyInner: true }).innerDispatch
  t.is(decodeDispatchFrame(resultDispatch).frameKind, FRAME_KIND.ERROR)
  t.is(canonicalErrorName(resultDispatch), 'BAD_CREATE_SIG')

  const corrupted = b4a.from(REQUEST_OUTER)
  const inner = decodeOuterEnvelope(corrupted, { copyInner: true }).innerDispatch
  corrupted[6 + inner.byteLength - 1] ^= 1
  const corruptedWire = await rejectedStream(harness.paths.streamSocketPath,
    [makeOpen(now, { nonceByte: 0xa7 }), ...requestFrames({ outer: corrupted })])
  t.is(corruptedWire.byteLength, 0, 'hash-invalid full body suppresses the retained error')

  const truncatedWire = await rejectedStream(harness.paths.streamSocketPath,
    [makeOpen(now, { nonceByte: 0xa8 }), ...requestFrames({ outer: REQUEST_OUTER.subarray(0, -1) })])
  t.is(truncatedWire.byteLength, 0, 'truncated outer body suppresses the retained error')
})

test('coalesced open and body stay unread by daemon mechanisms until binding, readiness and replay pass', async t => {
  const now = 1_500_000n
  const readinessEntered = deferred()
  const releaseReadiness = deferred()
  let dispatchCalls = 0
  const harness = await createDaemon(t, {
    monotonicMillis: () => now,
    writeReadinessProjection: async input => {
      readinessEntered.resolve()
      await releaseReadiness.promise
      return defaultProjection(input)
    },
    dispatchStagedPut: async (staged, context) => {
      dispatchCalls++
      const authority = stagedCellPutAuthority(staged)
      for await (const chunk of authority.source) t.ok(chunk.byteLength > 0)
      await authority.ensureBodyValidated()
      return { dispatch: decodeOuterEnvelope(RESULT_OUTER).innerDispatch, outerClass: context.outerClass }
    }
  })
  const socket = await connectedSocket(harness.paths.streamSocketPath)
  const response = collectSocket(socket)
  socket.end(b4a.concat([makeOpen(now, { nonceByte: 0xaa }), ...requestFrames()]))
  await readinessEntered.promise
  await new Promise(resolve => setImmediate(resolve))
  t.is(harness.daemon.v2ReplayReservationCount, 0)
  t.is(harness.daemon.v2IngressConstructionCount, 0)
  t.is(harness.daemon.bufferedBytes, STAGED_PUT_SOCKET_RESERVATION_BYTES_V2,
    'only the authenticated accept-time socket/HWM reservation exists before readiness')
  t.is(dispatchCalls, 0)

  releaseReadiness.resolve()
  const wire = await response
  t.ok(wire.byteLength > 0)
  t.is(harness.daemon.v2ReplayReservationCount, 1)
  t.is(harness.daemon.v2IngressConstructionCount, 1)
  t.is(dispatchCalls, 1)
  t.is(harness.daemon.bufferedBytes, 0)
})

test('V2 stream budget rejects at boundary minus one and admits at the exact conservative bound', async t => {
  const now = 1_750_000n
  let belowReadinessCalls = 0
  const below = await createDaemon(t, {
    monotonicMillis: () => now,
    maxBufferedBytes: STAGED_PUT_STREAM_RESERVATION_BYTES_V2 - 1,
    writeReadinessProjection: async input => {
      belowReadinessCalls++
      return defaultProjection(input)
    }
  })
  await rejectedStream(below.paths.streamSocketPath, [makeOpen(now, {
    outerClass: 6,
    nonceByte: 0xab
  })])
  t.is(belowReadinessCalls, 1)
  t.is(below.daemon.v2ReplayReservationCount, 0)
  t.is(below.daemon.v2IngressConstructionCount, 0)

  let commits = 0
  const exact = await createDaemon(t, {
    monotonicMillis: () => now,
    maxBufferedBytes: STAGED_PUT_STREAM_RESERVATION_BYTES_V2,
    writeReadinessProjection: async input => defaultProjection(input),
    dispatchStagedPut: async (staged, context) => {
      const authority = stagedCellPutAuthority(staged)
      for await (const chunk of authority.source) t.ok(chunk.byteLength > 0)
      await authority.ensureBodyValidated()
      commits++
      return { dispatch: decodeOuterEnvelope(RESULT_OUTER).innerDispatch, outerClass: context.outerClass }
    }
  })
  const wire = await rejectedStream(exact.paths.streamSocketPath,
    [makeOpen(now, { nonceByte: 0xac }), ...requestFrames()])
  t.ok(wire.byteLength > 0)
  t.is(commits, 1)
  t.is(exact.daemon.v2ReplayReservationCount, 1)
  t.is(exact.daemon.v2IngressConstructionCount, 1)
  t.is(exact.daemon.bufferedBytes, 0)
})

test('one exact replay tuple stays consumed across descriptor rotation', async t => {
  const now = 1_900_000n
  let descriptorSequence = 9n
  let descriptorHash = DESCRIPTOR_HASH
  let readinessCalls = 0
  const harness = await createDaemon(t, {
    monotonicMillis: () => now,
    writeReadinessProjection: async input => {
      readinessCalls++
      return defaultProjection(input, { descriptorSequence, descriptorHash })
    }
  })
  const exactOpen = makeOpen(now, { nonceByte: 0xad, channelByte: 0xae, sessionByte: 0xaf })
  await rejectedStream(harness.paths.streamSocketPath, [exactOpen])
  t.is(harness.daemon.v2ReplayReservationCount, 1)
  t.is(harness.daemon.v2IngressConstructionCount, 1)

  descriptorSequence = 10n
  descriptorHash = b4a.alloc(32, 0xd2)
  await rejectedStream(harness.paths.streamSocketPath, [exactOpen])
  t.is(readinessCalls, 2)
  t.is(harness.daemon.v2ReplayReservationCount, 1)
  t.is(harness.daemon.v2IngressConstructionCount, 1,
    'descriptor rotation cannot make the exact protocol replay tuple fresh')
  t.ok(harness.errors.some(error => error.code === 'PRIVATE_IPC_V2_REPLAY'))
})

test('durable replay authority keeps an exact tuple consumed across daemon restart', async t => {
  const now = 1_950_000n
  const durableReplayAuthority = testDurableReplayAuthority()
  const exactOpen = makeOpen(now, { nonceByte: 0xb4, channelByte: 0xb5, sessionByte: 0xb6 })
  const first = await createDaemon(t, {
    monotonicMillis: () => now,
    durableReplayAuthority,
    writeReadinessProjection: async input => defaultProjection(input)
  })
  await rejectedStream(first.paths.streamSocketPath, [exactOpen])
  t.is(first.daemon.v2ReplayReservationCount, 1)
  await first.daemon.close()

  const restarted = await createDaemon(t, {
    monotonicMillis: () => now,
    durableReplayAuthority,
    writeReadinessProjection: async input => defaultProjection(input)
  })
  await rejectedStream(restarted.paths.streamSocketPath, [exactOpen])
  t.is(restarted.daemon.v2ReplayReservationCount, 0,
    'duplicate durable record cannot mint a daemon-private ingress authority after restart')
  t.is(restarted.daemon.v2IngressConstructionCount, 0)
  t.ok(restarted.errors.some(error => error.code === 'PRIVATE_IPC_V2_REPLAY'))
})

test('replay reservation lasts through open deadline across readiness refresh', async t => {
  let now = 1_975_000n
  const accepted = now
  const exactOpen = makeOpen(accepted, {
    deadlineMillis: 1_000n,
    nonceByte: 0xb7,
    channelByte: 0xb8,
    sessionByte: 0xb9
  })
  let readinessCalls = 0
  const harness = await createDaemon(t, {
    monotonicMillis: () => now,
    writeReadinessProjection: async input => {
      readinessCalls++
      return defaultProjection(input, {
        expiresMonotonicMillis: now + 50n,
        descriptorExpiresMonotonicMillis: input.absoluteDeadlineMonotonicMillis
      })
    }
  })
  await rejectedStream(harness.paths.streamSocketPath, [exactOpen])
  t.is(harness.daemon.v2ReplayReservationCount, 1)
  now += 100n
  await rejectedStream(harness.paths.streamSocketPath, [exactOpen])
  t.is(readinessCalls, 2, 'second attempt receives a refreshed live readiness projection')
  t.is(harness.daemon.v2ReplayReservationCount, 1)
  t.is(harness.daemon.v2IngressConstructionCount, 1,
    'short readiness expiry cannot make a still-live open tuple fresh')
  t.ok(harness.errors.some(error => error.code === 'PRIVATE_IPC_V2_REPLAY'))
})

test('invalid binding, class 2, and memory BUSY fail before readiness or replay reservation', async t => {
  const now = 2_000_000n
  let readinessCalls = 0
  const invalidHarness = await createDaemon(t, {
    monotonicMillis: () => now,
    writeReadinessProjection: async input => { readinessCalls++; return defaultProjection(input) }
  })
  const invalid = b4a.from(makeOpen(now, { nonceByte: 0xb1 }))
  invalid[invalid.byteLength - 1] ^= 1
  await rejectedStream(invalidHarness.paths.streamSocketPath, [invalid])
  t.is(readinessCalls, 0)
  t.is(invalidHarness.daemon.v2ReplayReservationCount, 0)

  await rejectedStream(invalidHarness.paths.streamSocketPath, [makeOpen(now, {
    outerClass: 2,
    nonceByte: 0xb2,
    channelByte: 0xb3
  })])
  t.is(readinessCalls, 0, 'class-fit rejects before profile/readiness')
  t.is(invalidHarness.daemon.v2ReplayReservationCount, 0)

  await rejectedStream(invalidHarness.paths.streamSocketPath, [makeOpen(now, {
    nonceByte: 0xb1
  })])
  t.is(readinessCalls, 1, 'the valid form of the invalid tuple was not poisoned')
  t.is(invalidHarness.daemon.v2ReplayReservationCount, 1)

  let busyReadinessCalls = 0
  const busyHarness = await createDaemon(t, {
    monotonicMillis: () => now,
    maxBufferedBytes: 1,
    writeReadinessProjection: async input => { busyReadinessCalls++; return defaultProjection(input) }
  })
  await rejectedStream(busyHarness.paths.streamSocketPath, [makeOpen(now, { nonceByte: 0xc1 })])
  t.is(busyReadinessCalls, 0, 'socket read memory is reserved before any open bytes are read')
  t.is(busyHarness.daemon.v2ReplayReservationCount, 0, 'transient memory BUSY does not burn the tuple')
})

test('wrong native peer UID prevents V2 decode, readiness, replay, and storage work', async t => {
  const now = 3_000_000n
  let readinessCalls = 0
  let dispatchCalls = 0
  const harness = await createDaemon(t, {
    expectedPeerUid: process.getuid() + 1,
    monotonicMillis: () => now,
    writeReadinessProjection: async input => { readinessCalls++; return defaultProjection(input) },
    dispatchStagedPut: async () => { dispatchCalls++ }
  })
  // If any protocol decoder ran, this impossible V2 declaration would surface
  // through onError. UID policy destroys the socket before attaching a reader.
  await rejectedStream(harness.paths.streamSocketPath, [b4a.from([0xff, 0xff, 0xff, 0xff, 2])])
  t.is(readinessCalls, 0)
  t.is(dispatchCalls, 0)
  t.is(harness.daemon.v2ReplayReservationCount, 0)
  t.is(harness.errors.length, 0)
})

test('V2 frame terminal, sequence, truncation, and V1 staged fallback failures never commit', async t => {
  const now = 4_000_000n
  let commits = 0
  const harness = await createDaemon(t, {
    monotonicMillis: () => now,
    writeReadinessProjection: async input => defaultProjection(input),
    dispatchStagedPut: async (staged, context) => {
      const authority = stagedCellPutAuthority(staged)
      for await (const chunk of authority.source) t.ok(chunk.byteLength > 0)
      await authority.ensureBodyValidated()
      if (context.signal.aborted) throw new Error('operation aborted before commit')
      commits++
      return { dispatch: decodeOuterEnvelope(RESULT_OUTER).innerDispatch, outerClass: context.outerClass }
    }
  })

  const [first, last] = requestFrames()
  const afterFin = encodeLocalStagedCellPutFrameV2({
    direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
    frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
    sequence: 2n,
    flags: LOCAL_STAGED_FLAG_V2.FIN,
    bytes: b4a.alloc(0)
  })
  await rejectedStream(harness.paths.streamSocketPath, [makeOpen(now, { nonceByte: 0xd1 }), first, last, afterFin])
  t.is(commits, 0, 'post-FIN frame cannot commit')

  const missingFin = requestFrames({ lastFlags: 0 })
  await rejectedStream(harness.paths.streamSocketPath, [makeOpen(now, { nonceByte: 0xd2 }), ...missingFin])
  t.is(commits, 0, 'missing FIN cannot commit')

  const replayedSequence = requestFrames({ secondSequence: 0n })
  await rejectedStream(harness.paths.streamSocketPath, [makeOpen(now, { nonceByte: 0xd3 }), ...replayedSequence])
  t.is(commits, 0, 'sequence replay cannot commit')

  await rejectedStream(harness.paths.streamSocketPath, [makeOpen(now, { nonceByte: 0xd4 }), first,
    last.subarray(0, last.byteLength - 1)])
  t.is(commits, 0, 'truncated terminal record cannot commit')

  await rejectedStream(harness.paths.streamSocketPath, [V1_STAGED_OPEN])
  t.is(commits, 0, 'V1 staged write has no fallback')
})

test('V2 ready ACK is emitted only for exact live endpoint/profile/topology/role/operation projection', async t => {
  const now = 5_000_000n
  let mode = 'valid'
  let readinessCalls = 0
  const harness = await createDaemon(t, {
    monotonicMillis: () => now,
    writeReadinessProjection: async input => {
      readinessCalls++
      if (mode === 'profile') return defaultProjection(input, { transportProfileHash: b4a.alloc(32, 0xee) })
      if (mode === 'role') return defaultProjection(input, { readyRoleBits: 0 })
      if (mode === 'storage') return defaultProjection(input, { storageReady: false })
      if (mode === 'expired') return defaultProjection(input, { expiresMonotonicMillis: now })
      return defaultProjection(input)
    }
  })
  const probe = overrides => encodeLocalReadyProbeV2({
    endpointId: overrides && overrides.endpointId != null ? overrides.endpointId : ENDPOINT_ID,
    edgeProcessNonce: b4a.alloc(32, overrides && overrides.nonceByte ? overrides.nonceByte : 0xe1),
    launchTopologyHash: overrides && overrides.launchTopologyHash
      ? overrides.launchTopologyHash
      : TOPOLOGY_HASH,
    edgeFeatureBits: REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
    requestedWriteOperationBits: CELL_PUT_OPERATION_BIT_V2,
    acceptedMonotonicMillis: now,
    absoluteDeadlineMonotonicMillis: now + 2_000n
  })

  const ackBytes = await unaryExchange(harness.paths.unarySocketPath, probe())
  const ack = decodeLocalReadyAckV2(ackBytes)
  t.is(ack.readyWriteOperationBits, CELL_PUT_OPERATION_BIT_V2)
  t.is(ack.readyRoleBits, CELL_PUT_ENDPOINT_ROLE_BIT_V2)

  mode = 'profile'
  t.is((await unaryExchange(harness.paths.unarySocketPath, probe({ nonceByte: 0xe2 }))).byteLength, 0)
  mode = 'role'
  t.is((await unaryExchange(harness.paths.unarySocketPath, probe({ nonceByte: 0xe3 }))).byteLength, 0)
  mode = 'storage'
  t.is((await unaryExchange(harness.paths.unarySocketPath, probe({ nonceByte: 0xe4 }))).byteLength, 0)
  mode = 'expired'
  t.is((await unaryExchange(harness.paths.unarySocketPath, probe({ nonceByte: 0xe5 }))).byteLength, 0)

  const beforeTopology = readinessCalls
  t.is((await unaryExchange(harness.paths.unarySocketPath, probe({
    nonceByte: 0xe6,
    launchTopologyHash: b4a.alloc(32, 0xef)
  }))).byteLength, 0)
  t.is(readinessCalls, beforeTopology, 'topology rejects before readiness callback')
  t.is((await unaryExchange(harness.paths.unarySocketPath, probe({
    nonceByte: 0xe7,
    endpointId: ENDPOINT_ID + 1
  }))).byteLength, 0)
  t.is(readinessCalls, beforeTopology, 'endpoint rejects before readiness callback')

  let defaultDispatchCalls = 0
  const readOnly = await createDaemon(t, {
    monotonicMillis: () => now,
    dispatchStagedPut: async () => { defaultDispatchCalls++ }
  })
  t.is((await unaryExchange(readOnly.paths.unarySocketPath, probe({ nonceByte: 0xe8 }))).byteLength, 0)
  await rejectedStream(readOnly.paths.streamSocketPath, [makeOpen(now, { nonceByte: 0xe8 })])
  t.is(defaultDispatchCalls, 0)
  t.is(readOnly.daemon.v2ReplayReservationCount, 0, 'default daemon assembly stays write-read-only')
  t.is(readOnly.daemon.v2WriteDisabledReason,
    V2_WRITE_DISABLED_REASON.WRITE_READINESS_PROJECTION_MISSING)

  const noReplay = await createDaemon(t, {
    monotonicMillis: () => now,
    durableReplayAuthority: null,
    writeReadinessProjection: async input => defaultProjection(input)
  })
  t.is(noReplay.daemon.v2WriteDisabledReason,
    V2_WRITE_DISABLED_REASON.DURABLE_REPLAY_AUTHORITY_MISSING)
  t.is((await unaryExchange(noReplay.paths.unarySocketPath, probe({ nonceByte: 0xe9 }))).byteLength, 0,
    'missing durable replay authority disables only the V2 write ACK')
  t.is((await rejectedStream(noReplay.paths.streamSocketPath, [])).byteLength, 0,
    'read/legacy daemon stream readiness remains live while V2 writes are disabled')

  const noStagedDispatcher = await createDaemon(t, {
    monotonicMillis: () => now,
    dispatchStagedPut: null,
    writeReadinessProjection: async input => defaultProjection(input)
  })
  t.is(noStagedDispatcher.daemon.v2WriteDisabledReason,
    V2_WRITE_DISABLED_REASON.STAGED_DISPATCHER_MISSING)
  t.ok(noStagedDispatcher.daemon.address(), 'missing V2 staged dispatch does not take read service down')
  t.is((await unaryExchange(noStagedDispatcher.paths.unarySocketPath,
    probe({ nonceByte: 0xea }))).byteLength, 0)
  t.is((await rejectedStream(noStagedDispatcher.paths.streamSocketPath, [])).byteLength, 0,
    'legacy stream readiness survives a missing V2 staged dispatcher')

  const noTransportProfile = await createDaemon(t, {
    monotonicMillis: () => now,
    streamTransportProfileHash: null,
    dispatchStagedPut: async () => { throw new Error('disabled V2 write dispatched') },
    writeReadinessProjection: async input => defaultProjection(input)
  })
  t.is(noTransportProfile.daemon.v2WriteDisabledReason,
    V2_WRITE_DISABLED_REASON.TRANSPORT_PROFILE_MISSING)
  t.ok(noTransportProfile.daemon.address(), 'missing V2 transport profile does not take read service down')
  t.is((await unaryExchange(noTransportProfile.paths.unarySocketPath,
    probe({ nonceByte: 0xeb }))).byteLength, 0)
  t.is((await rejectedStream(noTransportProfile.paths.streamSocketPath, [])).byteLength, 0,
    'legacy stream readiness survives a missing V2 transport profile')
})

test('V2 write descriptor floor rejects rollback and equal-sequence forks across probe and staged paths', async t => {
  const now = 5_500_000n
  let descriptorSequence = 9n
  let descriptorHash = DESCRIPTOR_HASH
  const harness = await createDaemon(t, {
    monotonicMillis: () => now,
    writeReadinessProjection: async input => defaultProjection(input, {
      descriptorSequence,
      descriptorHash
    })
  })
  const probe = nonceByte => encodeLocalReadyProbeV2({
    endpointId: ENDPOINT_ID,
    edgeProcessNonce: b4a.alloc(32, nonceByte),
    launchTopologyHash: TOPOLOGY_HASH,
    edgeFeatureBits: REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
    requestedWriteOperationBits: CELL_PUT_OPERATION_BIT_V2,
    acceptedMonotonicMillis: now,
    absoluteDeadlineMonotonicMillis: now + 2_000n
  })

  t.ok((await unaryExchange(harness.paths.unarySocketPath, probe(0xea))).byteLength > 0)
  descriptorSequence = 8n
  descriptorHash = b4a.alloc(32, 0xd0)
  t.is((await unaryExchange(harness.paths.unarySocketPath, probe(0xeb))).byteLength, 0)
  await rejectedStream(harness.paths.streamSocketPath,
    [makeOpen(now, { nonceByte: 0xec, deadlineMillis: 500n })])
  t.is(harness.daemon.v2ReplayReservationCount, 0)
  t.is(harness.daemon.v2IngressConstructionCount, 0)

  descriptorSequence = 9n
  descriptorHash = b4a.alloc(32, 0xd2)
  t.is((await unaryExchange(harness.paths.unarySocketPath, probe(0xed))).byteLength, 0,
    'equal-sequence different-hash projection is a fork')
  descriptorHash = DESCRIPTOR_HASH
  t.ok((await unaryExchange(harness.paths.unarySocketPath, probe(0xee))).byteLength > 0,
    'equal-sequence same-hash refresh remains valid')

  descriptorSequence = 10n
  descriptorHash = b4a.alloc(32, 0xd2)
  t.ok((await unaryExchange(harness.paths.unarySocketPath, probe(0xef))).byteLength > 0,
    'monotonic descriptor advance becomes the new retained floor')
  descriptorSequence = 9n
  descriptorHash = DESCRIPTOR_HASH
  await rejectedStream(harness.paths.streamSocketPath,
    [makeOpen(now, { nonceByte: 0xf0, deadlineMillis: 500n })])
  t.is(harness.daemon.v2ReplayReservationCount, 0,
    'staged path cannot roll back the floor established by a ready probe')
  t.ok(harness.errors.some(error => /rolled back or forked/.test(error.message)))
})

test('record-derived deadlines release stalled resolver and projection tasks plus connection slots', async t => {
  const never = () => new Promise(() => {})
  let nonce = 0x91
  for (const stalledAt of ['resolver', 'projection']) {
    const now = BigInt(5_700_000 + nonce * 100)
    const harness = await createDaemon(t, {
      monotonicMillis: () => now,
      maxConnections: 1,
      streamTransportProfileHashForEndpoint: stalledAt === 'resolver' ? never : null,
      writeReadinessProjection: stalledAt === 'projection'
        ? never
        : async input => defaultProjection(input)
    })
    const started = Date.now()
    await rejectedStream(harness.paths.streamSocketPath,
      [makeOpen(now, { nonceByte: nonce++, deadlineMillis: 80n })])
    t.ok(Date.now() - started < 800, `${stalledAt} staged-open await obeys its 80ms record budget`)
    await waitForDaemonRelease(harness.daemon)
    t.is((await rejectedStream(harness.paths.streamSocketPath, [])).byteLength, 0,
      `${stalledAt} staged-open await releases maxConnections slot`)
    await waitForDaemonRelease(harness.daemon)
  }

  for (const stalledAt of ['resolver', 'projection']) {
    const now = BigInt(5_800_000 + nonce * 100)
    const harness = await createDaemon(t, {
      monotonicMillis: () => now,
      maxConnections: 1,
      streamTransportProfileHashForEndpoint: stalledAt === 'resolver' ? never : null,
      writeReadinessProjection: stalledAt === 'projection'
        ? never
        : async input => defaultProjection(input)
    })
    const probe = encodeLocalReadyProbeV2({
      endpointId: ENDPOINT_ID,
      edgeProcessNonce: b4a.alloc(32, nonce++),
      launchTopologyHash: TOPOLOGY_HASH,
      edgeFeatureBits: REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
      requestedWriteOperationBits: CELL_PUT_OPERATION_BIT_V2,
      acceptedMonotonicMillis: now,
      absoluteDeadlineMonotonicMillis: now + 2_000n
    })
    const started = Date.now()
    t.is((await unaryExchange(harness.paths.unarySocketPath, probe)).byteLength, 0)
    t.ok(Date.now() - started < 2_800,
      `${stalledAt} ready-probe await obeys its original 2s record budget`)
    await waitForDaemonRelease(harness.daemon)
    t.is((await rejectedStream(harness.paths.streamSocketPath, [])).byteLength, 0,
      `${stalledAt} ready-probe await releases maxConnections slot`)
    await waitForDaemonRelease(harness.daemon)
  }
})

test('absolute deadline detaches a never-settling staged dispatcher and releases daemon resources', async t => {
  const now = 5_950_000n
  let dispatchCalls = 0
  const harness = await createDaemon(t, {
    monotonicMillis: () => now,
    maxConnections: 1,
    writeReadinessProjection: async input => defaultProjection(input),
    dispatchStagedPut: async () => {
      dispatchCalls++
      return new Promise(() => {})
    }
  })
  const wire = await rejectedStream(harness.paths.streamSocketPath,
    [makeOpen(now, { nonceByte: 0xf3, deadlineMillis: 120n }), ...requestFrames()])
  t.is(wire.byteLength, 0)
  t.is(dispatchCalls, 1)
  await waitForDaemonRelease(harness.daemon)
  t.is((await rejectedStream(harness.paths.streamSocketPath, [])).byteLength, 0,
    'stalled dispatcher cannot retain the only connection slot')
  await waitForDaemonRelease(harness.daemon)
})

test('clock advancement during readiness and expiry during ingress grant no extra commit lifetime', async t => {
  let fixedNow = 6_000_000n
  let dispatchCalls = 0
  const advanced = await createDaemon(t, {
    monotonicMillis: () => fixedNow,
    writeReadinessProjection: async input => {
      fixedNow = input.absoluteDeadlineMonotonicMillis
      return defaultProjection(input, {
        expiresMonotonicMillis: input.absoluteDeadlineMonotonicMillis - 1n
      })
    },
    dispatchStagedPut: async () => { dispatchCalls++ }
  })
  await rejectedStream(advanced.paths.streamSocketPath, [makeOpen(6_000_000n, { nonceByte: 0xf1 })])
  t.is(dispatchCalls, 0)
  t.is(advanced.daemon.v2ReplayReservationCount, 0)

  const wallStart = Date.now()
  const base = 7_000_000n
  const wallNow = () => base + BigInt(Date.now() - wallStart)
  let commits = 0
  const expiring = await createDaemon(t, {
    monotonicMillis: wallNow,
    writeReadinessProjection: async input => defaultProjection(input, {
      expiresMonotonicMillis: wallNow() + 120n,
      descriptorExpiresMonotonicMillis: input.absoluteDeadlineMonotonicMillis
    }),
    dispatchStagedPut: async (staged, context) => {
      const authority = stagedCellPutAuthority(staged)
      for await (const chunk of authority.source) t.ok(chunk.byteLength > 0)
      await authority.ensureBodyValidated()
      await delay(160)
      if (context.signal.aborted) throw new Error('expired before commit')
      commits++
      return { dispatch: decodeOuterEnvelope(RESULT_OUTER).innerDispatch, outerClass: context.outerClass }
    }
  })
  const accepted = wallNow()
  const socket = await connectedSocket(expiring.paths.streamSocketPath)
  const closed = collectSocket(socket)
  const [first, last] = requestFrames()
  socket.write(makeOpen(accepted, { nonceByte: 0xf2, deadlineMillis: 1_000n }))
  socket.write(first)
  socket.end(last)
  await closed
  await delay(80)
  t.is(commits, 0, 'write-readiness expiry after actual EOF aborts pending dispatch before commit')
})

test('daemon exposes no caller-mintable V2 authority or dormant V1 staged runtime', async t => {
  const source = await fs.readFile(new URL('../server.js', import.meta.url), 'utf8')
  t.absent(source.includes('_runStagedPutStream'))
  t.absent(source.includes('decodeLocalStreamOpen'))
  t.absent(source.includes('verifyLocalAuthenticatedChannelContext'))
  t.ok(source.includes('V2_DAEMON_AUTHORITIES.delete(authority)'),
    'daemon-private staged authority is consumed before ingress')

  const daemon = Object.create(BlindDaemon.prototype)
  await t.exception(daemon._runStagedPutV2(null, Object.freeze({}),
    new AbortController().signal), /daemon-private peercred authority/)
})
