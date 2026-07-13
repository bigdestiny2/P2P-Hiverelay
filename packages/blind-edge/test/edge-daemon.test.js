import test from 'brittle'
import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import { EventEmitter, once } from 'node:events'
import b4a from 'b4a'
import {
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  PROTOCOL,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  blindErrorV1,
  decodeCanonical,
  decodeOuterEnvelope,
  encodeDispatchFrame,
  encodeOuterEnvelope
} from '@hiverelay/blind-protocol'
import {
  decodeLocalRequest,
  encodeLocalReadyAck,
  localRequestFrameLength
} from '@hiverelay/blind-ipc'
import { BlindDaemon } from '@hiverelay/blind-daemon'
import { BlindEdge, exchangeLocal } from '../index.js'
import { writeBoundedResponse } from '../server.js'
import {
  blindBoundaryScratchPath,
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'

const requestId = value => b4a.alloc(16, value)

function requestEnvelope ({ family = FAMILY.CELL, operation = OPERATION.CELL.GET, id = 1, body = b4a.from('opaque'), outerClass = 1 } = {}) {
  return encodeOuterEnvelope({
    outerClass,
    innerDispatch: encodeDispatchFrame({
      frameKind: FRAME_KIND.REQUEST,
      familyId: family,
      operationId: operation,
      requestId: requestId(id),
      body
    })
  }, { randomFill: padding => padding.fill(0x5a) })
}

async function fixture (t, options = {}) {
  const directory = await createBlindBoundaryScratch('blind-boundary-test-')
  const socketPath = path.join(directory, 'daemon-unary.sock')
  const streamSocketPath = path.join(directory, 'daemon-stream.sock')
  const launchTopologyHash = b4a.alloc(32, 0x41)
  const contexts = []
  const daemon = new BlindDaemon({
    unarySocketPath: socketPath,
    streamSocketPath,
    requestTimeoutMs: 1000,
    releaseGate: () => {},
    expectedPeerUid: options.expectedPeerUid == null ? process.getuid() : options.expectedPeerUid,
    expectedPeerGid: options.expectedPeerGid == null ? process.getgid() : options.expectedPeerGid,
    socketGroupGid: process.getgid(),
    launchTopologyHash,
    endpointIds: [1],
    readinessSnapshot: async () => ({
      selfVerified: true,
      descriptorSequence: 1n,
      descriptorHash: b4a.alloc(32, 0x42),
      readyRoleBits: 1,
      readyOperationBits: 0x7
    }),
    dispatch: options.dispatch || (async (request, context) => {
      contexts.push(context)
      return { body: b4a.from('result') }
    })
  })
  await daemon.start()
  const edge = new BlindEdge({
    socketPath,
    host: '127.0.0.1',
    port: 0,
    requestTimeoutMs: options.requestTimeoutMs || 1000,
    maxInFlight: options.maxInFlight || 8,
    maxBufferedBytes: options.maxBufferedBytes || 32 * 1024 * 1024,
    stageTimeouts: options.stageTimeouts,
    testHooks: options.testHooks,
    allowInsecureLoopback: true,
    allowUnsafeReadinessProbe: true,
    releaseGate: () => {},
    unsafeReadinessProbe: async () => true
  })
  await edge.start()
  const address = edge.address()
  const base = `http://127.0.0.1:${address.port}`
  t.teardown(async () => {
    await edge.close()
    await daemon.close()
    await removeBlindBoundaryScratch(directory)
  })
  return { daemon, edge, socketPath, streamSocketPath, contexts, base, port: address.port }
}

function closeNetServer (server) {
  return new Promise(resolve => {
    if (!server.listening) return resolve()
    server.close(() => resolve())
  })
}

async function listenUnix (server, socketPath) {
  await new Promise((resolve, reject) => {
    const onError = error => {
      server.off('listening', onListening)
      reject(error)
    }
    const onListening = () => {
      server.off('error', onError)
      resolve()
    }
    server.once('error', onError)
    server.once('listening', onListening)
    server.listen(socketPath)
  })
  await fs.chmod(socketPath, 0o660)
}

async function readinessDaemon (options = {}) {
  const directory = await createBlindBoundaryScratch('blind-edge-ready-')
  const unarySocketPath = path.join(directory, 'unary.sock')
  const streamSocketPath = path.join(directory, 'stream.sock')
  const launchTopologyHash = b4a.alloc(32, 0x51)
  const descriptorHash = b4a.alloc(32, 0x52)
  const sockets = new Set()
  const probes = []
  const acknowledgements = []
  const streamAcceptedMonotonicMillis = []
  let streamConnections = 0
  let streamBytes = 0

  const track = socket => {
    sockets.add(socket)
    socket.once('close', () => sockets.delete(socket))
    socket.on('error', () => {})
  }
  const streamServer = net.createServer(socket => {
    track(socket)
    streamConnections++
    streamAcceptedMonotonicMillis.push(process.hrtime.bigint() / 1_000_000n)
    socket.on('data', chunk => { streamBytes += chunk.byteLength })
    socket.once('end', () => socket.end())
  })
  const unaryServer = net.createServer(socket => {
    track(socket)
    const chunks = []
    let total = 0
    let expectedLength = null
    let handling = false
    socket.on('data', chunk => {
      if (handling) return socket.destroy()
      chunks.push(b4a.from(chunk))
      total += chunk.byteLength
      try {
        if (expectedLength == null) expectedLength = localRequestFrameLength(b4a.concat(chunks, total))
      } catch {
        return socket.destroy()
      }
      if (expectedLength == null || total < expectedLength) return
      if (total !== expectedLength) return socket.destroy()
      handling = true
      const probe = decodeLocalRequest(b4a.concat(chunks, total), { copyBody: true })
      const probeIndex = probes.length
      probes.push(probe)
      Promise.resolve(options.reply ? options.reply(probe, probeIndex) : {}).then(overrides => {
        if (overrides === null || socket.destroyed) return
        const acknowledgement = {
          edgeInstanceNonce: probe.readyProbe.edgeInstanceNonce,
          launchTopologyHash: probe.readyProbe.launchTopologyHash,
          endpointId: probe.endpointId,
          descriptorSequence: BigInt(probeIndex + 1),
          descriptorHash,
          readyRoleBits: 1,
          readyOperationBits: 0x7,
          expiresMonotonicMillis: probe.acceptedMonotonicMillis + 1500n,
          ...overrides
        }
        acknowledgements.push(acknowledgement)
        const response = encodeLocalReadyAck(acknowledgement)
        if (options.splitResponse === true) {
          socket.write(response.subarray(0, 3))
          socket.write(response.subarray(3, 17))
          socket.end(response.subarray(17))
        } else {
          socket.end(response)
        }
      }, () => socket.destroy())
    })
  })

  try {
    await listenUnix(streamServer, streamSocketPath)
    await listenUnix(unaryServer, unarySocketPath)
  } catch (error) {
    for (const socket of sockets) socket.destroy()
    await Promise.all([closeNetServer(unaryServer), closeNetServer(streamServer)])
    await removeBlindBoundaryScratch(directory)
    throw error
  }
  const socketGroupGid = (await fs.lstat(unarySocketPath)).gid

  return {
    directory,
    unarySocketPath,
    streamSocketPath,
    launchTopologyHash,
    probes,
    acknowledgements,
    streamAcceptedMonotonicMillis,
    get streamConnections () { return streamConnections },
    get streamBytes () { return streamBytes },
    topology (overrides = {}) {
      return {
        unarySocketPath,
        streamSocketPath,
        launchTopologyHash,
        daemonUid: process.getuid(),
        daemonGid: process.getgid(),
        socketGroupGid,
        socketMode: 0o660,
        ...overrides
      }
    },
    async close () {
      for (const socket of sockets) socket.destroy()
      await Promise.all([closeNetServer(unaryServer), closeNetServer(streamServer)])
      await removeBlindBoundaryScratch(directory)
    }
  }
}

function readinessEdge (daemon, options = {}) {
  const errors = []
  const edge = new BlindEdge({
    host: '127.0.0.1',
    port: 0,
    endpointId: 1,
    allowInsecureLoopback: true,
    releaseGate: () => {},
    readinessTopology: daemon.topology(options.topology),
    onError: error => errors.push(error)
  })
  return { edge, errors }
}

async function waitFor (predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('condition did not become true before timeout')
    await new Promise(resolve => setTimeout(resolve, 5))
  }
}

async function post (base, route, body, headers = {}) {
  return fetch(base + route, {
    method: 'POST',
    headers: { 'content-type': PROTOCOL.mediaType, ...headers },
    body
  })
}

async function rawSession (port) {
  const socket = net.createConnection({ host: '127.0.0.1', port })
  const chunks = []
  let socketError = null
  socket.on('data', chunk => chunks.push(b4a.from(chunk)))
  const complete = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error('raw HTTP session timed out'))
    }, 2000)
    socket.once('error', error => { socketError = error })
    socket.once('close', () => {
      clearTimeout(timer)
      if (chunks.length === 0 && socketError) reject(socketError)
      else resolve(b4a.concat(chunks).toString())
    })
  })
  await once(socket, 'connect')
  return { socket, complete }
}

function rawPostHead (bodyLength, extraHeaders = [], route = '/api/blind/v1/cell') {
  return [
    `POST ${route} HTTP/1.1`,
    'Host: 127.0.0.1',
    `content-type: ${PROTOCOL.mediaType}`,
    `content-length: ${bodyLength}`,
    ...extraHeaders,
    '',
    ''
  ].join('\r\n')
}

function rawStatus (response) {
  const match = /^HTTP\/1\.1 ([0-9]{3}) /.exec(response)
  return match ? Number(match[1]) : null
}

function decodedHeaderBytes (rows) {
  return rows.reduce((total, [name, value]) => total + Buffer.byteLength(name, 'latin1') + Buffer.byteLength(value, 'latin1'), 0)
}

test('public edge refuses to bind when its injected release authority gate fails', async t => {
  const socketPath = await blindBoundaryScratchPath('nonexistent-blind-daemon.sock')
  const edge = new BlindEdge({
    socketPath,
    host: '127.0.0.1',
    port: 0,
    allowInsecureLoopback: true,
    allowUnsafeReadinessProbe: true,
    unsafeReadinessProbe: async () => true,
    releaseGate: () => {
      const error = new Error('injected release authority is incomplete')
      error.code = 'BLIND_TEST_RELEASE_INCOMPLETE'
      throw error
    }
  })
  t.teardown(() => edge.close())
  await t.exception(edge.start(), /injected release authority is incomplete/)
  t.is(edge.address(), null)
})

test('blind edge and daemon preserve canonical bytes while stripping ambient HTTP metadata', async t => {
  const { base, contexts, socketPath } = await fixture(t)
  const stat = await fs.stat(socketPath)
  t.ok(stat.isSocket(), 'daemon exposes a Unix socket, not a public TCP listener')
  t.is(stat.mode & 0o777, 0o660, 'private socket has the frozen group-only mode')

  const response = await post(base, '/api/blind/v1/cell', requestEnvelope(), {
    authorization: 'Bearer must-not-cross',
    cookie: 'session=must-not-cross',
    referer: 'https://peerit.site/post/secret',
    'user-agent': 'semantic-browser',
    'x-peerit-author': 'alice'
  })
  t.is(response.status, 200)
  t.is(response.headers.get('content-type'), PROTOCOL.mediaType)
  t.is(response.headers.get('cache-control'), 'no-store')
  t.is(response.headers.get('access-control-allow-credentials'), null)
  const outer = decodeOuterEnvelope(b4a.from(await response.arrayBuffer()))
  t.is(outer.frame.frameKind, FRAME_KIND.RESPONSE)
  t.is(outer.frame.familyId, FAMILY.CELL)
  t.ok(b4a.equals(outer.frame.requestId, requestId(1)))
  t.ok(b4a.equals(outer.frame.body, b4a.from('result')))

  t.is(contexts.length, 1)
  t.alike(Object.keys(contexts[0]).sort(), [
    'absoluteDeadlineMonotonicMillis',
    'acceptedMonotonicMillis',
    'adjacentRelayKey',
    'endpointId',
    'family',
    'outerClass',
    'signal',
    'transportId',
    'transportSupportBit'
  ])
  t.is(contexts[0].transportId, TRANSPORT_ID.HTTPS_DIRECT)
  t.is(contexts[0].transportSupportBit, TRANSPORT_SUPPORT.DIRECT_HTTP)
  t.is(contexts[0].adjacentRelayKey, null)
  t.absent(contexts[0].headers)
  t.absent(contexts[0].remoteAddress)
  t.absent(contexts[0].appId)
})

test('blind edge exposes only five generic routes and generic credential-free CORS', async t => {
  const { base, contexts } = await fixture(t)
  for (const route of [
    '/api/sync/commit',
    '/api/services/outboxlog',
    '/api/blind/v1/cell/put',
    '/api/notify',
    '/health'
  ]) {
    const response = await post(base, route, requestEnvelope())
    t.is(response.status, 404, `${route} is absent`)
  }
  t.is(contexts.length, 0, 'negative probes never reach the daemon')

  const response = await fetch(base + '/api/blind/v1/cell', {
    method: 'OPTIONS',
    headers: {
      origin: 'https://unrelated.example',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type'
    }
  })
  t.is(response.status, 204)
  t.is(response.headers.get('access-control-allow-origin'), '*')
  t.is(response.headers.get('access-control-allow-methods'), 'POST, OPTIONS')
  t.is(response.headers.get('access-control-allow-headers'), 'content-type')
  t.is(response.headers.get('access-control-allow-credentials'), null)
})

test('route-family mismatch becomes one correlated canonical protocol error', async t => {
  const { base } = await fixture(t)
  const response = await post(base, '/api/blind/v1/inbox', requestEnvelope())
  t.is(response.status, 200)
  const outer = decodeOuterEnvelope(b4a.from(await response.arrayBuffer()))
  t.is(outer.frame.frameKind, FRAME_KIND.ERROR)
  t.is(outer.frame.familyId, FAMILY.CELL)
  t.ok(b4a.equals(outer.frame.requestId, requestId(1)))
  const error = decodeCanonical(blindErrorV1, outer.frame.body)
  t.is(error.code, ERROR_CODE.BAD_ENCODING)
  t.is(error.retryable, 0)
  t.is(error.retryAfterEpoch, null)
})

test('outer transport failures are bounded before private dispatch', async t => {
  const { base, contexts } = await fixture(t)
  let response = await post(base, '/api/blind/v1/cell', b4a.alloc(5))
  t.is(response.status, 400)

  const malformed = requestEnvelope()
  malformed[0] = 2
  response = await post(base, '/api/blind/v1/cell', malformed)
  t.is(response.status, 400)

  response = await fetch(base + '/api/blind/v1/cell', { method: 'GET' })
  t.is(response.status, 405)
  response = await fetch(base + '/api/blind/v1/cell', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}'
  })
  t.is(response.status, 400)
  t.is(contexts.length, 0)
})

test('unavailable private daemon is a generic 503 without semantic fallback', async t => {
  const { base, daemon } = await fixture(t)
  await daemon.close()
  const response = await post(base, '/api/blind/v1/cell', requestEnvelope())
  t.is(response.status, 503)
  t.is(await response.text(), '')
})

test('in-flight cap rejects excess work before daemon allocation', async t => {
  let release
  let entered = 0
  const gate = new Promise(resolve => { release = resolve })
  const { base } = await fixture(t, {
    maxInFlight: 1,
    dispatch: async () => {
      entered++
      await gate
      return { body: b4a.from('done') }
    }
  })
  const first = post(base, '/api/blind/v1/cell', requestEnvelope({ id: 1 }))
  await new Promise(resolve => {
    const poll = () => entered === 0 ? setTimeout(poll, 5) : resolve()
    poll()
  })
  const second = await post(base, '/api/blind/v1/cell', requestEnvelope({ id: 2 }))
  t.is(second.status, 429)
  t.is(entered, 1)
  release()
  t.is((await first).status, 200)
})

test('response preserves the selected class and memory reservations return to zero', async t => {
  const { base, edge, daemon } = await fixture(t, { maxBufferedBytes: 64 * 1024 * 1024 })
  const response = await post(base, '/api/blind/v1/cell', requestEnvelope({ outerClass: 6 }))
  t.is(response.status, 200)
  const bytes = b4a.from(await response.arrayBuffer())
  t.is(bytes.byteLength, 8 * 1024 * 1024)
  t.is(decodeOuterEnvelope(bytes).outerClass, 6)
  await new Promise(resolve => setTimeout(resolve, 5))
  t.is(edge.bufferedBytes, 0)
  t.is(daemon.bufferedBytes, 0)
})

test('dispatcher cannot expand or shrink the selected response class', async t => {
  const { base } = await fixture(t, {
    dispatch: async () => ({ dispatch: { body: b4a.from('result') }, outerClass: 6 })
  })
  const response = await post(base, '/api/blind/v1/cell', requestEnvelope({ outerClass: 1 }))
  t.is(response.status, 200)
  const bytes = b4a.from(await response.arrayBuffer())
  t.is(bytes.byteLength, 4 * 1024)
  const outer = decodeOuterEnvelope(bytes)
  t.is(outer.outerClass, 1)
  const error = decodeCanonical(blindErrorV1, outer.frame.body)
  t.is(error.code, ERROR_CODE.INTERNAL)
})

test('wrong Unix peer credentials fail before request allocation or dispatch', async t => {
  let dispatched = 0
  const { base } = await fixture(t, {
    expectedPeerUid: process.getuid() + 1,
    dispatch: async () => {
      dispatched++
      return { body: b4a.from('should-not-run') }
    }
  })
  const response = await post(base, '/api/blind/v1/cell', requestEnvelope())
  t.is(response.status, 503)
  t.is(dispatched, 0)
})

test('daemon close aborts and settles admitted dispatch work before returning', async t => {
  let entered = false
  let finished = false
  const { base, daemon } = await fixture(t, {
    dispatch: async (_request, context) => {
      entered = true
      await new Promise(resolve => context.signal.addEventListener('abort', resolve, { once: true }))
      finished = true
      throw new Error('aborted by close')
    }
  })
  const request = post(base, '/api/blind/v1/cell', requestEnvelope())
  await new Promise(resolve => {
    const poll = () => entered ? resolve() : setTimeout(poll, 5)
    poll()
  })
  await daemon.close()
  t.is(finished, true)
  t.is((await request).status, 503)
})

test('production bind remains TLS-only outside the explicit loopback seam', async t => {
  const socketPath = await blindBoundaryScratchPath('nonexistent-blind-daemon.sock')
  const unarySocketPath = await blindBoundaryScratchPath('nonexistent-blind-daemon-unary.sock')
  const streamSocketPath = await blindBoundaryScratchPath('nonexistent-blind-daemon-stream.sock')
  const edge = new BlindEdge({
    socketPath,
    host: '0.0.0.0',
    port: 0,
    allowInsecureLoopback: true,
    releaseGate: () => {},
    readinessTopology: {
      unarySocketPath,
      streamSocketPath,
      launchTopologyHash: b4a.alloc(32, 1),
      daemonUid: process.getuid(),
      daemonGid: process.getgid(),
      socketGroupGid: process.getgid(),
      socketMode: 0o660
    }
  })
  t.teardown(() => edge.close())
  let error
  try {
    await edge.start()
  } catch (caught) {
    error = caught
  }
  t.ok(error)
  t.is(error.code, 'BLIND_TLS_REQUIRED')
  t.is(edge.address(), null)
})

test('deadline seams can only tighten bounds in explicit loopback tests', async t => {
  const socketPath = await blindBoundaryScratchPath('test.sock')
  const base = {
    socketPath,
    host: '127.0.0.1',
    port: 0,
    allowUnsafeReadinessProbe: true,
    unsafeReadinessProbe: async () => true
  }
  const capture = fn => {
    try {
      fn()
      return null
    } catch (error) {
      return error
    }
  }
  t.ok(/explicit insecure-loopback/.test(capture(() => new BlindEdge({ ...base, stageTimeouts: { headersMs: 4999 } })).message))
  t.ok(/may only tighten/.test(capture(() => new BlindEdge({ ...base, allowInsecureLoopback: true, stageTimeouts: { headersMs: 5001 } })).message))
  t.ok(/may only tighten/.test(capture(() => new BlindEdge({ ...base, allowInsecureLoopback: true, handshakeTimeoutMs: 5001 })).message))
  t.is(capture(() => new BlindEdge({ ...base, allowInsecureLoopback: true, stageTimeouts: { headersMs: 25 } })), null)
})

test('production readiness mutually authenticates the real daemon on both paths before bind', async t => {
  const directory = await createBlindBoundaryScratch('blind-edge-mutual-ready-')
  const unarySocketPath = path.join(directory, 'unary.sock')
  const streamSocketPath = path.join(directory, 'stream.sock')
  const launchTopologyHash = b4a.alloc(32, 0x61)
  const descriptorHash = b4a.alloc(32, 0x62)
  const daemon = new BlindDaemon({
    unarySocketPath,
    streamSocketPath,
    releaseGate: () => {},
    expectedPeerUid: process.getuid(),
    expectedPeerGid: process.getgid(),
    socketGroupGid: process.getgid(),
    launchTopologyHash,
    endpointIds: [1],
    readinessSnapshot: async () => ({
      selfVerified: true,
      descriptorSequence: 7n,
      descriptorHash,
      readyRoleBits: 1,
      readyOperationBits: 0x7
    }),
    dispatch: async () => ({ body: b4a.from('ready-result') })
  })
  await daemon.start()
  const socketGroupGid = (await fs.lstat(unarySocketPath)).gid
  const edge = new BlindEdge({
    host: '127.0.0.1',
    port: 0,
    endpointId: 1,
    allowInsecureLoopback: true,
    releaseGate: () => {},
    readinessTopology: {
      unarySocketPath,
      streamSocketPath,
      launchTopologyHash,
      daemonUid: process.getuid(),
      daemonGid: process.getgid(),
      socketGroupGid,
      socketMode: 0o660
    }
  })
  t.teardown(async () => {
    await edge.close()
    await daemon.close()
    await removeBlindBoundaryScratch(directory)
  })

  await edge.start()
  t.ok(edge.address(), 'public bind follows a real kind-3 readiness ACK')
  t.is(edge.readinessAck.descriptorSequence, 7n)
  t.ok(b4a.equals(edge.readinessAck.descriptorHash, descriptorHash))
  const response = await post(`http://127.0.0.1:${edge.address().port}`, '/api/blind/v1/cell', requestEnvelope())
  t.is(response.status, 200)
})

test('production edge waits for one exact split ACK and sends no stream frame', async t => {
  const daemon = await readinessDaemon({
    splitResponse: true,
    reply: async () => {
      await new Promise(resolve => setTimeout(resolve, 60))
      return {}
    }
  })
  const { edge } = readinessEdge(daemon)
  t.teardown(async () => {
    await edge.close()
    await daemon.close()
  })

  const starting = edge.start()
  await new Promise(resolve => setTimeout(resolve, 25))
  t.is(edge.address(), null, 'the public listener is absent while the first ACK is pending')
  await starting
  t.ok(edge.address(), 'one exact ACK permits public bind')
  t.is(daemon.streamConnections, 1)
  t.is(daemon.streamBytes, 0, 'the stream readiness authentication sends no PRIVATE_IPC frame')
  t.is(daemon.probes.length, 1)
  t.ok(b4a.equals(daemon.probes[0].readyProbe.launchTopologyHash, daemon.launchTopologyHash))
  t.is(daemon.probes[0].endpointId, 1)
})

test('production readiness rejects missing, aliased, weak-mode, and wrong-identity paths before bind', async t => {
  const cases = [
    {
      name: 'missing stream path',
      prepare: async daemon => fs.unlink(daemon.streamSocketPath),
      topology: () => ({}),
      code: 'BLIND_READINESS_PATH'
    },
    {
      name: 'symlink unary path',
      prepare: async daemon => {
        const alias = path.join(daemon.directory, 'unary-alias.sock')
        await fs.symlink(daemon.unarySocketPath, alias)
        daemon.alias = alias
      },
      topology: daemon => ({ unarySocketPath: daemon.alias }),
      code: 'BLIND_READINESS_PATH'
    },
    {
      name: 'weak stream socket mode',
      prepare: async daemon => fs.chmod(daemon.streamSocketPath, 0o600),
      topology: () => ({}),
      code: 'BLIND_READINESS_PATH'
    },
    {
      name: 'wrong signed socket owner',
      prepare: async () => {},
      topology: () => ({ daemonUid: process.getuid() + 1 }),
      code: 'BLIND_READINESS_PATH'
    },
    {
      name: 'wrong authenticated daemon group',
      prepare: async () => {},
      topology: () => ({ daemonGid: process.getgid() + 1 }),
      code: 'BLIND_READINESS_PEER'
    }
  ]

  for (const item of cases) {
    const daemon = await readinessDaemon()
    let edge = null
    try {
      await item.prepare(daemon)
      ;({ edge } = readinessEdge(daemon, { topology: item.topology(daemon) }))
      let error = null
      try {
        await edge.start()
      } catch (caught) {
        error = caught
      }
      t.is(error && error.code, item.code, item.name)
      t.is(edge.address(), null, `${item.name} cannot expose a public listener`)
    } finally {
      if (edge) await edge.close()
      await daemon.close()
    }
  }

  const daemon = await readinessDaemon()
  try {
    let error = null
    try {
      readinessEdge(daemon, { topology: { streamSocketPath: daemon.unarySocketPath } })
    } catch (caught) {
      error = caught
    }
    t.ok(error && /unequal/.test(error.message), 'one inode path cannot stand in for unary and stream')
  } finally {
    await daemon.close()
  }
})

test('production readiness rejects ACK substitutions, missing DESCRIBE bits, and overlong expiry', async t => {
  const cases = [
    {
      name: 'nonce substitution',
      reply: () => ({ edgeInstanceNonce: b4a.alloc(32, 0x71) })
    },
    {
      name: 'topology substitution',
      reply: () => ({ launchTopologyHash: b4a.alloc(32, 0x72) })
    },
    {
      name: 'endpoint substitution',
      reply: () => ({ endpointId: 2 })
    },
    {
      name: 'missing DESCRIBE bits',
      reply: () => ({ readyOperationBits: 0x3 })
    },
    {
      name: 'expiry beyond probe t0 plus five seconds',
      reply: probe => ({ expiresMonotonicMillis: probe.acceptedMonotonicMillis + 5001n })
    }
  ]

  for (const item of cases) {
    const daemon = await readinessDaemon({ reply: item.reply })
    const { edge } = readinessEdge(daemon)
    try {
      let error = null
      try {
        await edge.start()
      } catch (caught) {
        error = caught
      }
      t.is(error && error.code, 'BLIND_READINESS_ACK', item.name)
      t.is(edge.address(), null, `${item.name} cannot expose a public listener`)
    } finally {
      await edge.close()
      await daemon.close()
    }
  }
})

test('readiness refresh starts at least one second early and advances its tuple and expiry', async t => {
  const daemon = await readinessDaemon({
    reply: (probe, index) => ({
      descriptorSequence: BigInt(index + 10),
      descriptorHash: b4a.alloc(32, 0x73 + index),
      expiresMonotonicMillis: probe.acceptedMonotonicMillis + 1500n
    })
  })
  const { edge } = readinessEdge(daemon)
  t.teardown(async () => {
    await edge.close()
    await daemon.close()
  })
  await edge.start()
  const firstExpiry = edge.readinessAck.expiresMonotonicMillis
  await waitFor(() => daemon.probes.length >= 2, 1200)
  t.ok(daemon.streamAcceptedMonotonicMillis[1] <= firstExpiry - 1000n,
    'the complete two-path refresh begins with at least the required lead')
  await waitFor(() => edge.readinessAck.descriptorSequence === 11n)
  t.ok(edge.readinessAck.expiresMonotonicMillis > firstExpiry)
  t.ok(b4a.equals(edge.readinessAck.descriptorHash, b4a.alloc(32, 0x74)))
  t.is(edge.address() != null, true)
})

test('descriptor rollback or equal-sequence fork closes the listener and accepted sockets', async t => {
  const cases = [
    {
      name: 'lower sequence',
      second: { descriptorSequence: 19n, descriptorHash: b4a.alloc(32, 0x75) }
    },
    {
      name: 'equal-sequence different hash',
      second: { descriptorSequence: 20n, descriptorHash: b4a.alloc(32, 0x76) }
    }
  ]

  for (const item of cases) {
    const firstHash = b4a.alloc(32, 0x75)
    const daemon = await readinessDaemon({
      reply: (probe, index) => ({
        descriptorSequence: index === 0 ? 20n : item.second.descriptorSequence,
        descriptorHash: index === 0 ? firstHash : item.second.descriptorHash,
        expiresMonotonicMillis: probe.acceptedMonotonicMillis + 1400n
      })
    })
    const { edge, errors } = readinessEdge(daemon)
    let publicSocket = null
    try {
      await edge.start()
      publicSocket = net.createConnection({ host: '127.0.0.1', port: edge.address().port })
      await once(publicSocket, 'connect')
      let publicSocketClosed = false
      publicSocket.once('close', () => { publicSocketClosed = true })
      await waitFor(() => edge.address() === null && publicSocketClosed, 1600)
      t.is(edge.readinessFailure && edge.readinessFailure.code, 'BLIND_READINESS_ROLLBACK', item.name)
      t.ok(errors.some(error => error.code === 'BLIND_READINESS_ROLLBACK'))
    } finally {
      if (publicSocket) publicSocket.destroy()
      await edge.close()
      await daemon.close()
    }
  }
})

test('failed refresh closes the listener and every accepted socket by ACK expiry', async t => {
  const daemon = await readinessDaemon({
    reply: (probe, index) => index === 0
      ? { expiresMonotonicMillis: probe.acceptedMonotonicMillis + 1300n }
      : null
  })
  const { edge } = readinessEdge(daemon)
  let publicSocket = null
  t.teardown(async () => {
    if (publicSocket) publicSocket.destroy()
    await edge.close()
    await daemon.close()
  })
  await edge.start()
  const expires = edge.readinessAck.expiresMonotonicMillis
  publicSocket = net.createConnection({ host: '127.0.0.1', port: edge.address().port })
  await once(publicSocket, 'connect')
  let publicSocketClosed = false
  publicSocket.once('close', () => { publicSocketClosed = true })
  await waitFor(() => edge.address() === null && publicSocketClosed, 1800)
  const closedAt = process.hrtime.bigint() / 1_000_000n
  t.ok(closedAt >= expires, 'the prior ACK remains authoritative until its expiry')
  t.ok(closedAt - expires < 100n, 'listener and accepted socket close at the expiry fence')
  t.is(edge.readinessFailure && edge.readinessFailure.code, 'BLIND_READINESS_EXPIRED')
})

test('a refresh completing after its prior ACK expiry cannot resurrect readiness', async t => {
  const unarySocketPath = await blindBoundaryScratchPath('readiness-race-unary.sock')
  const streamSocketPath = await blindBoundaryScratchPath('readiness-race-stream.sock')
  let now = 100n
  const errors = []
  const edge = new BlindEdge({
    host: '127.0.0.1',
    port: 0,
    endpointId: 1,
    allowInsecureLoopback: true,
    releaseGate: () => {},
    monotonicMillis: () => now,
    readinessTopology: {
      unarySocketPath,
      streamSocketPath,
      launchTopologyHash: b4a.alloc(32, 0x77),
      daemonUid: process.getuid(),
      daemonGid: process.getgid(),
      socketGroupGid: process.getgid(),
      socketMode: 0o660
    },
    onError: error => errors.push(error)
  })
  const previous = Object.freeze({
    descriptorSequence: 1n,
    descriptorHash: b4a.alloc(32, 0x78),
    readyRoleBits: 1,
    readyOperationBits: 0x7,
    expiresMonotonicMillis: 150n
  })
  edge._recordReadiness(previous)
  edge._establishReadiness = async () => {
    now = 151n
    return Object.freeze({
      ...previous,
      descriptorSequence: 2n,
      descriptorHash: b4a.alloc(32, 0x79),
      expiresMonotonicMillis: 300n
    })
  }
  await edge._refreshReadiness()
  t.is(edge.readinessAck, previous, 'the expired generation remains fenced')
  t.is(edge.readinessFailure && edge.readinessFailure.code, 'BLIND_READINESS_EXPIRED')
  t.ok(errors.some(error => error.code === 'BLIND_READINESS_EXPIRED'))
  await edge.close()
})

test('HTTP request-line, field-count, and decoded aggregate-header bounds are exact', async t => {
  const { port, contexts } = await fixture(t)
  const body = requestEnvelope()

  let session = await rawSession(port)
  const exactLineTarget = '/' + 'a'.repeat(1010)
  t.is(Buffer.byteLength(`GET ${exactLineTarget} HTTP/1.1`, 'latin1'), 1024)
  session.socket.write(`GET ${exactLineTarget} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`)
  t.is(rawStatus(await session.complete), 404)

  const combinedRows = [
    ['Host', '127.0.0.1'],
    ...Array.from({ length: 30 }, (_, index) => [`x-${index.toString().padStart(2, '0')}`, 'v']),
    ['x-pad', '']
  ]
  const combinedPadLength = 16384 - decodedHeaderBytes(combinedRows)
  combinedRows[combinedRows.length - 1][1] = 'v'.repeat(combinedPadLength)
  t.is(combinedRows.length, 32)
  t.is(decodedHeaderBytes(combinedRows), 16384)
  session = await rawSession(port)
  session.socket.write([
    `GET ${exactLineTarget} HTTP/1.1`,
    ...combinedRows.map(([name, value]) => `${name}: ${value}`),
    '',
    ''
  ].join('\r\n'))
  t.is(rawStatus(await session.complete), 404, 'all three exact maxima pass the parser and edge checks together')

  session = await rawSession(port)
  const overLineTarget = '/' + 'a'.repeat(1011)
  t.is(Buffer.byteLength(`GET ${overLineTarget} HTTP/1.1`, 'latin1'), 1025)
  session.socket.write(`GET ${overLineTarget} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`)
  t.is(rawStatus(await session.complete), 400)

  session = await rawSession(port)
  session.socket.write(`GET ${' '.repeat(1100)}/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`)
  t.is(rawStatus(await session.complete), 400, 'parser whitespace normalization cannot bypass the raw request-line cap')

  const exactCountHeaders = Array.from({ length: 29 }, (_, index) => `x-${index.toString().padStart(2, '0')}: v`)
  session = await rawSession(port)
  session.socket.write(b4a.concat([b4a.from(rawPostHead(body.byteLength, exactCountHeaders)), body]))
  t.is(rawStatus(await session.complete), 200)

  const overCountHeaders = [...exactCountHeaders, 'x-over: v']
  session = await rawSession(port)
  session.socket.write(b4a.concat([b4a.from(rawPostHead(body.byteLength, overCountHeaders)), body]))
  t.is(rawStatus(await session.complete), 400)

  const requiredRows = [
    ['Host', '127.0.0.1'],
    ['content-type', PROTOCOL.mediaType],
    ['content-length', String(body.byteLength)]
  ]
  const padName = 'x-pad'
  const padLength = 16384 - decodedHeaderBytes(requiredRows) - Buffer.byteLength(padName)
  t.ok(padLength > 0)
  session = await rawSession(port)
  session.socket.write(b4a.concat([b4a.from(rawPostHead(body.byteLength, [`${padName}: ${'v'.repeat(padLength)}`])), body]))
  t.is(rawStatus(await session.complete), 200)

  session = await rawSession(port)
  session.socket.write(b4a.concat([b4a.from(rawPostHead(body.byteLength, [`${padName}: ${'v'.repeat(padLength + 1)}`])), body]))
  t.is(rawStatus(await session.complete), 400)
  t.is(contexts.length, 2, 'only the exact field-count and aggregate-byte boundaries dispatch')
})

test('single-request sockets make conservative t0 safe and reject keep-alive reuse', async t => {
  const { port, contexts } = await fixture(t)
  const body = requestEnvelope()
  const request = b4a.concat([b4a.from(rawPostHead(body.byteLength)), body])
  const session = await rawSession(port)
  session.socket.write(b4a.concat([request, request]))
  const response = await session.complete
  t.is(rawStatus(response), 200)
  t.ok(/\r\nConnection: close\r\n/i.test(response))
  t.is(contexts.length, 1, 'a pipelined/reused second request never reaches IPC')
})

test('edge emits exact 15-second and opaque-INBOX 35-second absolute horizons', async t => {
  const { base, contexts } = await fixture(t, { requestTimeoutMs: 35_000 })
  let response = await post(base, '/api/blind/v1/cell', requestEnvelope())
  t.is(response.status, 200)
  response = await post(base, '/api/blind/v1/inbox', requestEnvelope({
    family: FAMILY.INBOX,
    operation: OPERATION.INBOX.READ,
    id: 2
  }))
  t.is(response.status, 200)
  t.is(contexts.length, 2)
  t.is(contexts[0].absoluteDeadlineMonotonicMillis - contexts[0].acceptedMonotonicMillis, 15_000n)
  t.is(contexts[1].absoluteDeadlineMonotonicMillis - contexts[1].acceptedMonotonicMillis, 35_000n)
})

test('header and CORS preflight absolute deadlines fail closed', async t => {
  let instance = await fixture(t, {
    requestTimeoutMs: 500,
    stageTimeouts: { headersMs: 40, familyMs: 500, inboxFamilyMs: 500 }
  })
  let session = await rawSession(instance.port)
  session.socket.write('POST /api/blind/v1/cell HTTP/1.1\r\nHost: 127.0.0.1\r\n')
  t.is(rawStatus(await session.complete), 408)
  t.is(instance.contexts.length, 0)

  instance = await fixture(t, {
    requestTimeoutMs: 500,
    stageTimeouts: { headersMs: 200, corsMs: 30, familyMs: 500, inboxFamilyMs: 500 }
  })
  session = await rawSession(instance.port)
  await new Promise(resolve => setTimeout(resolve, 70))
  session.socket.write([
    'OPTIONS /api/blind/v1/cell HTTP/1.1',
    'Host: 127.0.0.1',
    'Origin: https://example.test',
    'Access-Control-Request-Method: POST',
    '',
    ''
  ].join('\r\n'))
  t.is(rawStatus(await session.complete), 408)
  t.is(instance.contexts.length, 0)
})

test('first-body-byte, body-progress idle, and complete-body deadlines are independent', async t => {
  const instance = await fixture(t, {
    requestTimeoutMs: 500,
    stageTimeouts: {
      headersMs: 200,
      firstBodyByteMs: 50,
      bodyIdleMs: 50,
      bodyCompleteMs: 120,
      familyMs: 500,
      inboxFamilyMs: 500
    }
  })
  const body = requestEnvelope()

  let session = await rawSession(instance.port)
  session.socket.write(rawPostHead(body.byteLength))
  t.is(rawStatus(await session.complete), 408, 'first body byte misses its own deadline')

  session = await rawSession(instance.port)
  session.socket.write(rawPostHead(body.byteLength))
  session.socket.write(body.subarray(0, 1))
  t.is(rawStatus(await session.complete), 408, 'body progress cannot idle')

  session = await rawSession(instance.port)
  session.socket.write(rawPostHead(body.byteLength))
  session.socket.write(body.subarray(0, 1))
  for (let offset = 1; offset < 8 && !session.socket.destroyed; offset++) {
    await new Promise(resolve => setTimeout(resolve, 20))
    session.socket.write(body.subarray(offset, offset + 1))
  }
  t.is(rawStatus(await session.complete), 408, 'frequent progress cannot extend the complete-body deadline')
  t.is(instance.contexts.length, 0)
})

test('edge IPC client rejects absent or ambiguous transport support before dial', async t => {
  const socketPath = await blindBoundaryScratchPath('invalid-transport.sock')
  const body = requestEnvelope()
  const now = process.hrtime.bigint() / 1_000_000n
  const request = {
    family: FAMILY.CELL,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    endpointId: 1,
    outerClass: 1,
    acceptedMonotonicMillis: now,
    absoluteDeadlineMonotonicMillis: now + 1_000n,
    adjacentRelayKey: null,
    body
  }
  let dialed = false
  for (const transportSupportBit of [undefined,
    TRANSPORT_SUPPORT.DIRECT_HTTP | TRANSPORT_SUPPORT.DIRECT_NATIVE]) {
    let error
    try {
      await exchangeLocal(socketPath, { ...request, transportSupportBit }, {
        socketFactory: () => { dialed = true }
      })
    } catch (caught) {
      error = caught
    }
    t.is(error.code, 'BAD_LOCAL_DISPATCH')
    t.ok(/one-hot bit/.test(error.message))
  }
  t.is(dialed, false, 'invalid transport support never reaches the Unix socket')
})

test('IPC connect and complete request write share one hard two-second stage', async t => {
  const socketPath = await blindBoundaryScratchPath('stalled-write.sock')
  const body = requestEnvelope()
  const now = process.hrtime.bigint() / 1_000_000n
  const request = {
    family: FAMILY.CELL,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    endpointId: 1,
    outerClass: 1,
    acceptedMonotonicMillis: now,
    absoluteDeadlineMonotonicMillis: now + 1000n,
    adjacentRelayKey: null,
    body
  }

  class StalledSocket extends EventEmitter {
    write (_bytes, _callback) { return false }
    destroy () { this.destroyed = true }
  }

  let socket = new StalledSocket()
  let error
  try {
    await exchangeLocal(socketPath, request, {
      timeoutMs: 200,
      writeTimeoutMs: 25,
      socketFactory: () => socket
    })
  } catch (caught) {
    error = caught
  }
  t.is(error.code, 'IPC_WRITE_TIMEOUT', 'connect stall is bounded')
  t.is(socket.destroyed, true)

  socket = new StalledSocket()
  queueMicrotask(() => socket.emit('connect'))
  error = null
  try {
    await exchangeLocal(socketPath, request, {
      timeoutMs: 200,
      writeTimeoutMs: 25,
      socketFactory: () => socket
    })
  } catch (caught) {
    error = caught
  }
  t.is(error.code, 'IPC_WRITE_TIMEOUT', 'write callback stall is bounded')
  t.is(socket.destroyed, true)
  error = null
  try {
    await exchangeLocal(socketPath, request, { writeTimeoutMs: 2001 })
  } catch (caught) {
    error = caught
  }
  t.ok(/may only tighten/.test(error.message))
})

test('absolute family deadline wins over daemon work and response-first-byte delay', async t => {
  let entered = false
  let instance = await fixture(t, {
    requestTimeoutMs: 500,
    stageTimeouts: {
      headersMs: 200,
      firstBodyByteMs: 200,
      bodyIdleMs: 200,
      bodyCompleteMs: 500,
      ipcWriteMs: 200,
      responseFirstByteMs: 200,
      publicWriteIdleMs: 200,
      familyMs: 60,
      inboxFamilyMs: 100
    },
    dispatch: async (_request, context) => {
      entered = true
      await new Promise(resolve => context.signal.addEventListener('abort', resolve, { once: true }))
      throw new Error('deadline abort')
    }
  })
  let response = await post(instance.base, '/api/blind/v1/cell', requestEnvelope())
  t.is(entered, true)
  t.is(response.status, 503)

  instance = await fixture(t, {
    requestTimeoutMs: 500,
    stageTimeouts: {
      headersMs: 200,
      firstBodyByteMs: 200,
      bodyIdleMs: 200,
      bodyCompleteMs: 500,
      responseFirstByteMs: 30,
      familyMs: 500,
      inboxFamilyMs: 500
    },
    testHooks: {
      beforeResponseFirstByte: () => new Promise(resolve => setTimeout(resolve, 90))
    }
  })
  response = await post(instance.base, '/api/blind/v1/cell', requestEnvelope())
  t.is(response.status, 503, 'response first byte cannot restart or exceed its stage budget')
})

test('public response write progress has an independent idle deadline', async t => {
  class StalledResponse extends EventEmitter {
    constructor () {
      super()
      this.destroyed = false
      this.writableEnded = false
    }

    flushHeaders () {}
    write (_chunk, _callback) { return false }
    end (_callback) { throw new Error('stalled response must not reach end') }
    destroy () {
      if (this.destroyed) return
      this.destroyed = true
      this.emit('close')
    }
  }

  const response = new StalledResponse()
  const controller = new AbortController()
  const now = () => process.hrtime.bigint() / 1_000_000n
  const started = now()
  let error
  try {
    await writeBoundedResponse(response, b4a.alloc(128 * 1024), {
      now,
      signal: controller.signal,
      firstByteDeadlineMonotonicMillis: started + 100n,
      absoluteDeadlineMonotonicMillis: started + 200n,
      idleMs: 25
    })
  } catch (caught) {
    error = caught
  }
  t.is(error.status, 503)
  t.ok(/write timed out/.test(error.message))
  t.is(response.destroyed, true)
})
