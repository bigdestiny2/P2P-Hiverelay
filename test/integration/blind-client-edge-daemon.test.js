import { execFile } from 'node:child_process'
import fs from 'node:fs/promises'
import https from 'node:https'
import path from 'node:path'
import { promisify } from 'node:util'
import b4a from 'b4a'
import test from 'brittle'
import {
  FAMILY,
  FRAME_KIND,
  OPERATION,
  TRANSPORT_ID,
  decodeCanonical,
  decodeOuterEnvelope,
  encodeCanonical,
  encodeDispatchFrame,
  getCellResultV1,
  getCellV1
} from '@hiverelay/blind-protocol'
import {
  CELL_PUT_ENDPOINT_ROLE_BIT_V2,
  CELL_PUT_OPERATION_BIT_V2,
  REQUIRED_LOCAL_IPC_FEATURE_BITS_V2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import { BlindDirectHttpClient, createGetCellRequest } from '@hiverelay/blind-client'
import { createNodeCryptoRuntime } from '@hiverelay/blind-client/runtime/node'
import { verifiedEndpointFixture } from '../../packages/blind-client/test/endpoint-fixture.js'
import { BlindDaemon } from '@hiverelay/blind-daemon'
import { BlindEdge } from '@hiverelay/blind-edge'

const execFileAsync = promisify(execFile)
const stagedPutBody = await fs.readFile(new URL(
  '../../packages/blind-protocol/vectors/draft/cell/put-class-1.bin', import.meta.url))
const stagedPutResultBody = decodeOuterEnvelope(await fs.readFile(new URL(
  '../../packages/blind-ipc/vectors/v2/accepted/public-result-outer-envelope-class-3.bin', import.meta.url)),
{ copyInner: true, copyBody: true }).frame.body

async function ephemeralLoopbackTls (root) {
  const keyFile = path.join(root, 'loopback-tls-key.pem')
  const certFile = path.join(root, 'loopback-tls-cert.pem')
  await execFileAsync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-subj', '/CN=127.0.0.1', '-days', '1',
    '-keyout', keyFile, '-out', certFile
  ], { timeout: 15_000, maxBuffer: 1024 * 1024 })
  await fs.chmod(keyFile, 0o600)
  return Object.freeze({
    key: await fs.readFile(keyFile),
    cert: await fs.readFile(certFile)
  })
}

function localTlsFetch (url, init = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (error, value) => {
      if (settled) return
      settled = true
      if (init.signal) init.signal.removeEventListener('abort', onAbort)
      if (error) reject(error)
      else resolve(value)
    }
    const headers = {}
    for (const [name, value] of init.headers || []) headers[name] = value
    const request = https.request(url, {
      method: init.method || 'GET',
      headers,
      rejectUnauthorized: false,
      agent: false
    }, response => {
      const chunks = []
      let total = 0
      response.on('data', chunk => {
        total += chunk.byteLength
        if (total > 8 * 1024 * 1024) {
          request.destroy(new Error('local TLS response exceeded the harness bound'))
          return
        }
        chunks.push(b4a.from(chunk))
      })
      response.once('error', finish)
      response.once('end', () => {
        const responseHeaders = new Headers()
        for (const [name, value] of Object.entries(response.headers)) {
          if (Array.isArray(value)) {
            for (const item of value) responseHeaders.append(name, item)
          } else if (value != null) responseHeaders.set(name, String(value))
        }
        finish(null, new Response(b4a.concat(chunks, total), {
          status: response.statusCode,
          statusText: response.statusMessage,
          headers: responseHeaders
        }))
      })
    })
    const onAbort = () => request.destroy(init.signal.reason || new Error('local TLS request aborted'))
    request.once('error', finish)
    if (init.signal) {
      if (init.signal.aborted) return onAbort()
      init.signal.addEventListener('abort', onAbort, { once: true })
    }
    request.end(init.body == null ? undefined : b4a.from(init.body))
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
    descriptorHash: b4a.alloc(32, 53),
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

test('generic blind client reaches daemon through the metadata-stripping edge', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-client-e2e-')
  const unarySocketPath = path.join(directory, 'unary.sock')
  const streamSocketPath = path.join(directory, 'stream.sock')
  const launchTopologyHash = b4a.alloc(32, 45)
  const cellBlob = b4a.alloc(4096, 41)
  let dispatchContext = null
  const daemon = new BlindDaemon({
    unarySocketPath,
    streamSocketPath,
    expectedPeerUid: process.getuid(),
    expectedPeerGid: process.getgid(),
    socketGroupGid: process.getgid(),
    launchTopologyHash,
    endpointIds: [1],
    releaseGate: () => {},
    readinessSnapshot: async () => ({
      selfVerified: true,
      descriptorSequence: 1n,
      descriptorHash: b4a.alloc(32, 46),
      readyRoleBits: 1,
      readyOperationBits: 0x7
    }),
    dispatch (frame, context) {
      dispatchContext = context
      t.is(frame.familyId, FAMILY.CELL)
      t.is(frame.operationId, OPERATION.CELL.GET)
      const request = decodeCanonical(getCellV1, frame.body, { copyBytes: true })
      t.is(request.storageSlot.byteLength, 32)
      return {
        body: encodeCanonical(getCellResultV1, { version: 1, sizeClass: 1, cellBlob })
      }
    }
  })
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
      socketGroupGid: process.getgid(),
      socketMode: 0o660
    }
  })
  t.teardown(async () => {
    await edge.close()
    await daemon.close()
    await fs.rm(directory, { recursive: true, force: true })
  })
  await daemon.start()
  await edge.start()

  const runtime = createNodeCryptoRuntime()
  const readCap = {
    version: 1,
    relayPublicKey: b4a.alloc(32, 42),
    storageSlot: b4a.alloc(32, 43),
    cellKey: b4a.alloc(32, 44),
    sizeClass: 1,
    expectedCellBlobHash: null
  }
  const request = await createGetCellRequest({ runtime, readCap })
  const port = edge.address().port
  const client = new BlindDirectHttpClient({
    runtime,
    allowInsecureLoopback: true
  })
  const response = await client.request({
    endpoint: verifiedEndpointFixture({
      endpointId: 1,
      transportId: TRANSPORT_ID.HTTPS_DIRECT,
      envelopeClassBits: 0x007e,
      canonicalUrl: b4a.from(`http://127.0.0.1:${port}/api/blind/v1/describe`)
    }, FAMILY.CELL, OPERATION.CELL.GET),
    ...request.wire,
    body: request.requestBytes
  })
  t.ok(response.ok)
  const result = decodeCanonical(getCellResultV1, response.body, { copyBytes: true })
  t.alike(result.cellBlob, cellBlob)
  t.ok(dispatchContext)
  t.is(dispatchContext.transportId, TRANSPORT_ID.HTTPS_DIRECT)
  t.absent(dispatchContext.sourceIp)
  t.absent(dispatchContext.origin)
  t.absent(dispatchContext.headers)
  t.absent(dispatchContext.app)
})

test('public CELL.PUT reaches the daemon staged-content path instead of unary IPC', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-client-staged-put-e2e-')
  const unarySocketPath = path.join(directory, 'unary.sock')
  const streamSocketPath = path.join(directory, 'stream.sock')
  const launchTopologyHash = b4a.alloc(32, 51)
  const transportProfileHash = b4a.alloc(32, 52)
  const tls = await ephemeralLoopbackTls(directory)
  let unaryDispatches = 0
  let streamedBytes = 0
  let stagedBodyWasAbsent = false
  const daemonErrors = []
  const daemon = new BlindDaemon({
    unarySocketPath,
    streamSocketPath,
    expectedPeerUid: process.getuid(),
    expectedPeerGid: process.getgid(),
    socketGroupGid: process.getgid(),
    launchTopologyHash,
    endpointIds: [1],
    streamTransportProfileHash: transportProfileHash,
    stagedPutRelayPublicKey: b4a.alloc(32, 0x92),
    durableReplayAuthority: durableReplayAuthority(),
    writeReadinessProjection: writeReadinessProjection(launchTopologyHash, transportProfileHash),
    onError: error => daemonErrors.push(error),
    releaseGate: () => {},
    readinessSnapshot: async () => ({
      selfVerified: true,
      descriptorSequence: 1n,
      descriptorHash: b4a.alloc(32, 53),
      readyRoleBits: 1,
      readyOperationBits: 0x7
    }),
    dispatch: async () => {
      unaryDispatches++
      throw new Error('CELL.PUT must not use unary IPC')
    },
    dispatchStagedPut: async staged => {
      stagedBodyWasAbsent = staged.request.cellBlob === undefined
      for await (const chunk of staged.source) streamedBytes += chunk.byteLength
      return {
        dispatch: encodeDispatchFrame({
          frameKind: FRAME_KIND.RESPONSE,
          familyId: FAMILY.CELL,
          operationId: OPERATION.CELL.PUT,
          requestId: staged.frame.requestId,
          body: stagedPutResultBody
        }),
        outerClass: 3
      }
    }
  })
  const edge = new BlindEdge({
    host: '127.0.0.1',
    port: 0,
    endpointId: 1,
    tls,
    releaseGate: () => {},
    readinessTopology: {
      unarySocketPath,
      streamSocketPath,
      launchTopologyHash,
      streamTransportProfileHash: transportProfileHash,
      daemonUid: process.getuid(),
      daemonGid: process.getgid(),
      socketGroupGid: process.getgid(),
      socketMode: 0o660
    }
  })
  t.teardown(async () => {
    await edge.close()
    await daemon.close()
    await fs.rm(directory, { recursive: true, force: true })
  })
  await daemon.start()
  await edge.start()

  const runtime = createNodeCryptoRuntime()
  const port = edge.address().port
  const client = new BlindDirectHttpClient({ runtime, fetch: localTlsFetch })
  const response = await client.request({
    endpoint: verifiedEndpointFixture({
      endpointId: 1,
      transportId: TRANSPORT_ID.HTTPS_DIRECT,
      envelopeClassBits: 0x007e,
      canonicalUrl: b4a.from(`https://127.0.0.1:${port}/api/blind/v1/describe`)
    }, FAMILY.CELL, OPERATION.CELL.PUT),
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    outerClass: 3,
    expectedResultBodyBytes: stagedPutResultBody.byteLength,
    body: stagedPutBody
  })

  t.ok(response.ok)
  t.alike(response.body, stagedPutResultBody)
  t.is(unaryDispatches, 0)
  t.is(streamedBytes, 4096)
  t.ok(stagedBodyWasAbsent)
  t.is(daemon.v2ReplayReservationCount, 1)
  t.is(daemon.v2IngressConstructionCount, 1)
  t.is(daemonErrors.length, 0)
})
