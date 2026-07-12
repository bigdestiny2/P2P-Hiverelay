import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import test from 'brittle'
import b4a from 'b4a'
import {
  FAMILY,
  FRAME_KIND,
  OPERATION,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  decodeDispatchFrame,
  encodeDispatchFrame
} from '@hiverelay/blind-protocol'
import {
  LOCAL_ABORT_CODE,
  LOCAL_STREAM_DIRECTION,
  LOCAL_STREAM_FLAG,
  LOCAL_STREAM_FRAME_KIND,
  LOCAL_STREAM_MODE,
  LOCAL_STREAM_OPEN_KIND,
  createLocalAuthenticatedChannelContext,
  encodeLocalStreamFrame,
  encodeLocalStreamOpen,
  fragmentLocalContent
} from '@hiverelay/blind-ipc'
import { BlindDaemon } from '@hiverelay/blind-daemon'
import { exchangeLocalContent } from '../ipc-client.js'

const putBody = await fs.readFile(new URL(
  '../../blind-protocol/vectors/draft/cell/put-class-1.bin', import.meta.url))

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

function streamRequestAuthority ({ launchTopologyHash, transportProfileHash, requestId, fin = true }) {
  const accepted = monotonicMillis()
  const openInput = {
    openKind: LOCAL_STREAM_OPEN_KIND.PUBLIC_CONTENT_CHANNEL,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    endpointId: 1,
    streamMode: LOCAL_STREAM_MODE.DISPATCH_CONTENT,
    channelClass: 1,
    acceptedMonotonicMillis: accepted,
    openDeadlineMonotonicMillis: accepted + 5_000n,
    adjacentRelayKey: null
  }
  const context = createLocalAuthenticatedChannelContext({
    launchTopologyHash,
    edgeProcessNonce: b4a.alloc(32, 0x45),
    localChannelNonce: b4a.alloc(32, 0x46),
    transportProfileHash,
    finalNoiseHandshakeHash: b4a.alloc(64, 0x47)
  }, openInput)
  const open = encodeLocalStreamOpen({ ...openInput, context })
  const request = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    requestId,
    body: putBody
  })
  const frames = fragmentLocalContent(request, {
    direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
    wireClass: 1,
    sequence: 0n,
    fin
  })
  return { open, request, frames }
}

test('real stream socket authenticates, fragments, stages, hashes, and reassembles CELL.PUT CONTENT', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-stream-put-')
  const unarySocketPath = path.join(directory, 'unary.sock')
  const streamSocketPath = path.join(directory, 'stream.sock')
  const launchTopologyHash = b4a.alloc(32, 0x31)
  const transportProfileHash = b4a.alloc(32, 0x32)
  const request = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    requestId: b4a.alloc(16, 0x33),
    body: putBody
  })
  let streamedBytes = 0
  let stagedBodyWasAbsent = false
  const daemonErrors = []
  const daemon = new BlindDaemon({
    unarySocketPath,
    streamSocketPath,
    releaseGate: () => {},
    expectedPeerUid: process.getuid(),
    expectedPeerGid: process.getgid(),
    socketGroupGid: process.getgid(),
    launchTopologyHash,
    endpointIds: [1],
    streamTransportProfileHash: transportProfileHash,
    onError: error => daemonErrors.push(error),
    readinessSnapshot: async () => ({
      selfVerified: true,
      descriptorSequence: 1n,
      descriptorHash: b4a.alloc(32, 0x34),
      readyRoleBits: 1,
      readyOperationBits: 7
    }),
    dispatch: async () => { throw new Error('unary path must not be used') },
    dispatchStagedPut: async staged => {
      stagedBodyWasAbsent = staged.request.cellBlob === undefined
      for await (const chunk of staged.source) streamedBytes += chunk.byteLength
      return {
        dispatch: encodeDispatchFrame({
          frameKind: FRAME_KIND.RESPONSE,
          familyId: FAMILY.CELL,
          operationId: OPERATION.CELL.PUT,
          requestId: staged.frame.requestId,
          body: b4a.from([1])
        })
      }
    }
  })
  await daemon.start()
  t.teardown(async () => {
    await daemon.close()
    await fs.rm(directory, { recursive: true, force: true })
  })

  const accepted = monotonicMillis()
  const open = {
    openKind: LOCAL_STREAM_OPEN_KIND.PUBLIC_CONTENT_CHANNEL,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    endpointId: 1,
    streamMode: LOCAL_STREAM_MODE.DISPATCH_CONTENT,
    channelClass: 1,
    acceptedMonotonicMillis: accepted,
    openDeadlineMonotonicMillis: accepted + 5_000n,
    adjacentRelayKey: null
  }
  let result
  try {
    result = await exchangeLocalContent(streamSocketPath, request, {
      open,
      channel: {
        launchTopologyHash,
        edgeProcessNonce: b4a.alloc(32, 0x35),
        localChannelNonce: b4a.alloc(32, 0x36),
        transportProfileHash,
        finalNoiseHandshakeHash: b4a.alloc(64, 0x37)
      }
    }, { timeoutMs: 5_000 })
  } catch (error) {
    if (daemonErrors[0]) error.cause = daemonErrors[0]
    throw error
  }
  const response = decodeDispatchFrame(result, { copyBody: true })
  t.is(response.frameKind, FRAME_KIND.RESPONSE)
  t.alike(response.requestId, b4a.alloc(16, 0x33))
  t.is(streamedBytes, 4096)
  t.is(stagedBodyWasAbsent, true)
  await new Promise(resolve => setImmediate(resolve))
  t.is(daemon.bufferedBytes, 0)
})

const terminalAttacks = Object.freeze([
  Object.freeze({ label: 'coalesced post-FIN bytes', kind: 'post-fin', expectedCode: 'BAD_LOCAL_STREAM' }),
  Object.freeze({ label: 'late post-FIN bytes', kind: 'late-post-fin', expectedCode: 'BAD_LOCAL_STREAM' }),
  Object.freeze({ label: 'EOF before FIN', kind: 'missing-fin', expectedCode: 'BAD_LOCAL_STREAM' }),
  Object.freeze({ label: 'FIN followed by authenticated ABORT', kind: 'fin-abort', expectedCode: 'ABORT_ERR' }),
  Object.freeze({ label: 'coalesced post-ABORT bytes', kind: 'post-abort', expectedCode: 'BAD_LOCAL_STREAM' })
])

for (const [attackIndex, attack] of terminalAttacks.entries()) {
  test(`real stream socket rejects ${attack.label} before staged PUT commit`, async t => {
    const directory = await fs.mkdtemp('/private/tmp/blind-stream-terminal-')
    const unarySocketPath = path.join(directory, 'unary.sock')
    const streamSocketPath = path.join(directory, 'stream.sock')
    const launchTopologyHash = b4a.alloc(32, 0x51)
    const transportProfileHash = b4a.alloc(32, 0x52)
    const requestId = b4a.alloc(16, 0x53 + attackIndex)
    const daemonErrors = []
    let dispatchCalls = 0
    let committed = false
    let sourceFailure = null
    let streamedBytes = 0
    const daemon = new BlindDaemon({
      unarySocketPath,
      streamSocketPath,
      releaseGate: () => {},
      expectedPeerUid: process.getuid(),
      expectedPeerGid: process.getgid(),
      socketGroupGid: process.getgid(),
      launchTopologyHash,
      endpointIds: [1],
      streamTransportProfileHash: transportProfileHash,
      onError: error => daemonErrors.push(error),
      readinessSnapshot: async () => ({
        selfVerified: true,
        descriptorSequence: 1n,
        descriptorHash: b4a.alloc(32, 0x55),
        readyRoleBits: 1,
        readyOperationBits: 7
      }),
      dispatch: async () => { throw new Error('unary path must not be used') },
      dispatchStagedPut: async staged => {
        dispatchCalls++
        try {
          for await (const chunk of staged.source) streamedBytes += chunk.byteLength
        } catch (error) {
          sourceFailure = error
          throw error
        }
        committed = true
        return {
          dispatch: encodeDispatchFrame({
            frameKind: FRAME_KIND.RESPONSE,
            familyId: FAMILY.CELL,
            operationId: OPERATION.CELL.PUT,
            requestId: staged.frame.requestId,
            body: b4a.from([1])
          })
        }
      }
    })
    await daemon.start()
    t.teardown(async () => {
      await daemon.close()
      await fs.rm(directory, { recursive: true, force: true })
    })

    const requestFin = attack.kind !== 'missing-fin' && attack.kind !== 'post-abort'
    const authority = streamRequestAuthority({
      launchTopologyHash,
      transportProfileHash,
      requestId,
      fin: requestFin
    })
    const extra = encodeLocalStreamFrame({
      direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
      frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
      sequence: BigInt(authority.frames.length),
      wireClass: 1,
      flags: LOCAL_STREAM_FLAG.FIN,
      body: b4a.alloc(0)
    })
    const abort = encodeLocalStreamFrame({
      direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
      frameKind: LOCAL_STREAM_FRAME_KIND.ABORT,
      sequence: BigInt(authority.frames.length),
      wireClass: 0,
      flags: 0,
      body: b4a.from([LOCAL_ABORT_CODE.TRANSPORT_FAILURE])
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
      const postAbort = encodeLocalStreamFrame({
        direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
        frameKind: LOCAL_STREAM_FRAME_KIND.CONTENT,
        sequence: BigInt(authority.frames.length + 1),
        wireClass: 1,
        flags: LOCAL_STREAM_FLAG.FIN,
        body: b4a.alloc(0)
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
