import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import test from 'brittle'
import b4a from 'b4a'
import {
  FAMILY,
  OPERATION,
  decodeOuterEnvelope
} from '@hiverelay/blind-protocol'
import {
  CELL_PUT_ENDPOINT_ROLE_BIT_V2,
  CELL_PUT_OPERATION_BIT_V2,
  LOCAL_STAGED_DIRECTION_V2,
  LOCAL_STAGED_FLAG_V2,
  LOCAL_STAGED_FRAME_KIND_V2,
  OUTER_CLASS,
  REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
  deriveLocalStagedOpenBindingHashV2,
  encodeLocalStagedCellPutFrameV2,
  encodeLocalStagedCellPutOpenV2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import { BlindDaemon } from '@hiverelay/blind-daemon'
import { exchangeLocalStagedCellPutV2 } from '../ipc-client.js'
import { verifyWriteStreamDialV2 } from '../readiness.js'
import {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'

const REQUEST_OUTER = await fs.readFile(new URL(
  '../../blind-ipc/vectors/v2/accepted/public-request-outer-envelope-class-3.bin', import.meta.url))
const RESULT_OUTER = await fs.readFile(new URL(
  '../../blind-ipc/vectors/v2/accepted/public-result-outer-envelope-class-3.bin', import.meta.url))
const REQUEST_FRAME = decodeOuterEnvelope(REQUEST_OUTER, { copyInner: true, copyBody: true }).frame
const RESULT_DISPATCH = decodeOuterEnvelope(RESULT_OUTER, { copyInner: true, copyBody: true }).innerDispatch

function monotonicMillis () {
  return process.hrtime.bigint() / 1_000_000n
}

function rawStreamExchange (socketPath, firstWrite, lateWrite = null) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath, allowHalfOpen: true })
    const chunks = []
    let total = 0
    let settled = false
    let socketError = null
    const finish = error => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      if (error) reject(error)
      else resolve({ response: b4a.concat(chunks, total), socketError })
    }
    const timer = setTimeout(() => finish(new Error('raw private stream exchange timed out')), 3_000)
    socket.once('connect', () => {
      socket.write(firstWrite, error => {
        if (error) return finish(error)
        if (lateWrite == null) return socket.end()
        setTimeout(() => socket.end(lateWrite), 20)
      })
    })
    socket.on('data', chunk => {
      chunks.push(b4a.from(chunk))
      total += chunk.byteLength
    })
    socket.once('error', error => { socketError = error })
    socket.once('close', () => finish())
  })
}

function durableReplayAuthority () {
  const consumed = new Set()
  return Object.freeze({
    async reserve (input) {
      const key = b4a.toString(input.replayTupleHash, 'hex')
      if (consumed.has(key)) {
        const error = new Error('replay')
        error.code = 'PRIVATE_IPC_V2_REPLAY'
        throw error
      }
      consumed.add(key)
      return Object.freeze({
        kind: 'reserved-new',
        durablyCommitted: true,
        replayTupleHash: b4a.from(input.replayTupleHash),
        expiresMonotonicMillis: input.expiresMonotonicMillis
      })
    }
  })
}

function writeReadinessProjection (launchTopologyHash, transportProfileHash) {
  return async input => Object.freeze({
    selfVerified: true,
    cellRuntimeReady: true,
    storageReady: true,
    admissionReady: true,
    replayJournalReady: true,
    endpointId: 1,
    launchTopologyHash,
    transportProfileHash,
    descriptorSequence: 1n,
    descriptorHash: b4a.alloc(32, 0x34),
    descriptorRoleBits: CELL_PUT_ENDPOINT_ROLE_BIT_V2,
    descriptorEnabledOperationBits: CELL_PUT_OPERATION_BIT_V2,
    readyRoleBits: CELL_PUT_ENDPOINT_ROLE_BIT_V2,
    readyOperationBits: CELL_PUT_OPERATION_BIT_V2,
    readyWriteOperationBits: CELL_PUT_OPERATION_BIT_V2,
    readyIpcFeatureBits: REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
    expiresMonotonicMillis: input.absoluteDeadlineMonotonicMillis - 1n,
    descriptorExpiresMonotonicMillis: input.absoluteDeadlineMonotonicMillis
  })
}

function streamRequestAuthority ({ launchTopologyHash, transportProfileHash, nonceByte = 0x45, fin = true }) {
  const accepted = monotonicMillis()
  const fields = Object.freeze({
    endpointId: 1,
    outerClass: 3,
    acceptedMonotonicMillis: accepted,
    openDeadlineMonotonicMillis: accepted + 5_000n,
    requestEnvelopeBytes: OUTER_CLASS[3]
  })
  const edgeProcessNonce = b4a.alloc(32, nonceByte)
  const localChannelNonce = b4a.alloc(32, nonceByte + 1)
  const publicSessionBindingHash = b4a.alloc(32, nonceByte + 2)
  const openBindingHash = deriveLocalStagedOpenBindingHashV2({
    open: fields,
    launchTopologyHash,
    authorityKind: 1,
    edgeProcessNonce,
    localChannelNonce,
    transportProfileHash,
    publicSessionBindingHash
  })
  const context = Object.freeze({
    authorityKind: 1,
    edgeProcessNonce,
    localChannelNonce,
    transportProfileHash,
    publicSessionBindingHash,
    openBindingHash
  })
  const open = encodeLocalStagedCellPutOpenV2({ ...fields, context })
  const frames = []
  for (let offset = 0, sequence = 0n; offset < REQUEST_OUTER.byteLength;) {
    const end = Math.min(offset + 65_515, REQUEST_OUTER.byteLength)
    frames.push(encodeLocalStagedCellPutFrameV2({
      direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
      frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
      sequence: sequence++,
      flags: fin && end === REQUEST_OUTER.byteLength ? LOCAL_STAGED_FLAG_V2.FIN : 0,
      bytes: REQUEST_OUTER.subarray(offset, end)
    }))
    offset = end
  }
  return { open, frames }
}

function daemonOptions ({
  unarySocketPath,
  streamSocketPath,
  launchTopologyHash,
  transportProfileHash,
  onError,
  dispatchStagedPut
}) {
  return {
    unarySocketPath,
    streamSocketPath,
    releaseGate: () => {},
    expectedPeerUid: process.getuid(),
    expectedPeerGid: process.getgid(),
    socketGroupGid: process.getgid(),
    launchTopologyHash,
    endpointIds: [1],
    streamTransportProfileHash: transportProfileHash,
    stagedPutRelayPublicKey: b4a.alloc(32, 0x38),
    durableReplayAuthority: durableReplayAuthority(),
    writeReadinessProjection: writeReadinessProjection(launchTopologyHash, transportProfileHash),
    onError,
    readinessSnapshot: async () => ({
      selfVerified: true,
      descriptorSequence: 1n,
      descriptorHash: b4a.alloc(32, 0x34),
      readyRoleBits: 1,
      readyOperationBits: 7
    }),
    dispatch: async () => { throw new Error('unary path must not be used') },
    dispatchStagedPut
  }
}

function listenUnixServer (socketPath, onConnection) {
  return new Promise((resolve, reject) => {
    const server = net.createServer(onConnection)
    const onError = error => {
      server.off('listening', onListening)
      reject(error)
    }
    const onListening = () => {
      server.off('error', onError)
      resolve(server)
    }
    server.once('error', onError)
    server.once('listening', onListening)
    server.listen(socketPath)
  })
}

function closeServer (server) {
  return new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
}

test('real V2 stream authenticates the full outer envelope, half-closes, stages, hashes, and reassembles CELL.PUT', async t => {
  const directory = await createBlindBoundaryScratch('blind-stream-put-')
  const unarySocketPath = path.join(directory, 'unary.sock')
  const streamSocketPath = path.join(directory, 'stream.sock')
  const launchTopologyHash = b4a.alloc(32, 0x31)
  const transportProfileHash = b4a.alloc(32, 0x32)
  let streamedBytes = 0
  let stagedBodyWasAbsent = false
  const daemonErrors = []
  const daemon = new BlindDaemon(daemonOptions({
    unarySocketPath,
    streamSocketPath,
    launchTopologyHash,
    transportProfileHash,
    onError: error => daemonErrors.push(error),
    dispatchStagedPut: async staged => {
      stagedBodyWasAbsent = staged.request.cellBlob === undefined
      for await (const chunk of staged.source) streamedBytes += chunk.byteLength
      return { dispatch: RESULT_DISPATCH, outerClass: 3 }
    }
  }))
  await daemon.start()
  t.teardown(async () => {
    await daemon.close()
    await removeBlindBoundaryScratch(directory)
  })

  const authority = streamRequestAuthority({ launchTopologyHash, transportProfileHash })
  let result
  try {
    result = await exchangeLocalStagedCellPutV2(streamSocketPath, REQUEST_OUTER, authority.open, { timeoutMs: 5_000 })
  } catch (error) {
    if (daemonErrors[0]) error.cause = daemonErrors[0]
    throw error
  }
  const response = decodeOuterEnvelope(result, { copyInner: true, copyBody: true }).frame
  t.is(response.familyId, FAMILY.CELL)
  t.is(response.operationId, OPERATION.CELL.PUT)
  t.alike(response.requestId, REQUEST_FRAME.requestId)
  t.is(streamedBytes, 4096)
  t.is(stagedBodyWasAbsent, true)
  await new Promise(resolve => setImmediate(resolve))
  t.is(daemon.bufferedBytes, 0)
})

test('V2 stream rejects a post-readiness socket inode swap before it writes the staged open', async t => {
  const directory = await createBlindBoundaryScratch('blind-stream-dial-swap-')
  const streamSocketPath = path.join(directory, 'stream.sock')
  const launchTopologyHash = b4a.alloc(32, 0x41)
  const transportProfileHash = b4a.alloc(32, 0x42)
  const topology = Object.freeze({
    streamSocketPath,
    daemonUid: process.getuid(),
    daemonGid: process.getgid(),
    socketGroupGid: process.getgid(),
    socketMode: 0o660
  })
  let observedBytes = 0
  let attacker = null
  const qualified = await listenUnixServer(streamSocketPath, socket => socket.destroy())
  await fs.chmod(streamSocketPath, 0o660)
  const qualifiedIdentity = await fs.lstat(streamSocketPath)
  await closeServer(qualified)
  attacker = await listenUnixServer(streamSocketPath, socket => {
    socket.on('data', chunk => { observedBytes += chunk.byteLength })
  })
  await fs.chmod(streamSocketPath, 0o660)
  t.teardown(async () => {
    await closeServer(attacker)
    await removeBlindBoundaryScratch(directory)
  })

  const authority = streamRequestAuthority({ launchTopologyHash, transportProfileHash, nonceByte: 0x43 })
  const error = await exchangeLocalStagedCellPutV2(
    streamSocketPath,
    REQUEST_OUTER,
    authority.open,
    {
      timeoutMs: 5_000,
      verifyConnectedSocket: socket => verifyWriteStreamDialV2(topology, qualifiedIdentity, socket)
    }
  ).then(
    () => new Error('substituted stream socket unexpectedly accepted a staged write'),
    error => error
  )
  t.is(error.code, 'BLIND_WRITE_READINESS_PATH')
  await new Promise(resolve => setImmediate(resolve))
  t.is(observedBytes, 0, 'the substituted socket receives no staged open or public envelope bytes')
})

const terminalAttacks = Object.freeze([
  Object.freeze({ label: 'coalesced post-FIN bytes', kind: 'post-fin', expectedCode: 'BAD_LOCAL_STREAM' }),
  Object.freeze({ label: 'late post-FIN bytes', kind: 'late-post-fin', expectedCode: 'BAD_LOCAL_STREAM' }),
  Object.freeze({ label: 'EOF before FIN', kind: 'missing-fin', expectedCode: 'BAD_LOCAL_STREAM' }),
  Object.freeze({ label: 'FIN followed by authenticated ABORT', kind: 'fin-abort', expectedCode: 'BAD_LOCAL_STREAM' }),
  Object.freeze({ label: 'coalesced post-ABORT bytes', kind: 'post-abort', expectedCode: 'ABORT_ERR' })
])

for (const [attackIndex, attack] of terminalAttacks.entries()) {
  test(`real V2 stream rejects ${attack.label} before staged PUT commit`, async t => {
    const directory = await createBlindBoundaryScratch('blind-stream-terminal-')
    const unarySocketPath = path.join(directory, 'unary.sock')
    const streamSocketPath = path.join(directory, 'stream.sock')
    const launchTopologyHash = b4a.alloc(32, 0x51)
    const transportProfileHash = b4a.alloc(32, 0x52)
    const daemonErrors = []
    let dispatchCalls = 0
    let committed = false
    let sourceFailure = null
    let streamedBytes = 0
    const daemon = new BlindDaemon(daemonOptions({
      unarySocketPath,
      streamSocketPath,
      launchTopologyHash,
      transportProfileHash,
      onError: error => daemonErrors.push(error),
      dispatchStagedPut: async staged => {
        dispatchCalls++
        try {
          for await (const chunk of staged.source) streamedBytes += chunk.byteLength
        } catch (error) {
          sourceFailure = error
          throw error
        }
        committed = true
        return { dispatch: RESULT_DISPATCH, outerClass: 3 }
      }
    }))
    await daemon.start()
    t.teardown(async () => {
      await daemon.close()
      await removeBlindBoundaryScratch(directory)
    })

    const authority = streamRequestAuthority({
      launchTopologyHash,
      transportProfileHash,
      nonceByte: 0x53 + attackIndex,
      fin: attack.kind !== 'missing-fin' && attack.kind !== 'post-abort'
    })
    const extra = encodeLocalStagedCellPutFrameV2({
      direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
      frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
      sequence: BigInt(authority.frames.length),
      flags: LOCAL_STAGED_FLAG_V2.FIN,
      bytes: b4a.alloc(0)
    })
    const abort = encodeLocalStagedCellPutFrameV2({
      direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
      frameKind: LOCAL_STAGED_FRAME_KIND_V2.ABORT,
      sequence: BigInt(authority.frames.length),
      flags: 0,
      bytes: b4a.from([1])
    })
    const valid = b4a.concat([authority.open, ...authority.frames])
    let exchange
    if (attack.kind === 'late-post-fin') {
      exchange = await rawStreamExchange(streamSocketPath, valid, extra)
    } else if (attack.kind === 'post-fin') {
      exchange = await rawStreamExchange(streamSocketPath, b4a.concat([valid, extra]))
    } else if (attack.kind === 'missing-fin') {
      exchange = await rawStreamExchange(streamSocketPath, valid)
    } else if (attack.kind === 'fin-abort') {
      exchange = await rawStreamExchange(streamSocketPath, b4a.concat([valid, abort]))
    } else {
      const postAbort = encodeLocalStagedCellPutFrameV2({
        direction: LOCAL_STAGED_DIRECTION_V2.REQUEST,
        frameKind: LOCAL_STAGED_FRAME_KIND_V2.CONTENT,
        sequence: BigInt(authority.frames.length + 1),
        flags: LOCAL_STAGED_FLAG_V2.FIN,
        bytes: b4a.alloc(0)
      })
      exchange = await rawStreamExchange(streamSocketPath, b4a.concat([valid, abort, postAbort]))
    }

    await new Promise(resolve => setImmediate(resolve))
    t.is(exchange.response.byteLength, 0, 'malformed ingress receives no success response')
    t.is(dispatchCalls, 1, 'the bounded staged parser may begin before terminal validation')
    t.ok(streamedBytes > 0, 'the staged source exercised streaming before terminal rejection')
    t.is(committed, false, 'the staged source cannot complete and commit')
    t.is(sourceFailure && sourceFailure.code, attack.expectedCode)
    t.is(daemonErrors.length, 1)
    t.is(daemonErrors[0].code, attack.expectedCode)
    t.is(daemon.bufferedBytes, 0)
  })
}
