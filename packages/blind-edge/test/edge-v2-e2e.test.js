import fs from 'node:fs/promises'
import https from 'node:https'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import test from 'brittle'
import b4a from 'b4a'
import {
  FAMILY,
  OPERATION,
  PROTOCOL,
  decodeOuterEnvelope
} from '@hiverelay/blind-protocol'
import {
  CELL_PUT_ENDPOINT_ROLE_BIT_V2,
  CELL_PUT_OPERATION_BIT_V2,
  REQUIRED_LOCAL_IPC_FEATURE_BITS_V2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import { BlindDaemon } from '@hiverelay/blind-daemon'
import { BlindEdge } from '../server.js'
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
const execFileAsync = promisify(execFile)

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
    descriptorHash: b4a.alloc(32, 0x64),
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

function httpsPost (port, body) {
  return new Promise((resolve, reject) => {
    const request = https.request({
      host: '127.0.0.1',
      port,
      path: '/api/blind/v1/cell',
      method: 'POST',
      rejectUnauthorized: false,
      headers: {
        'content-type': PROTOCOL.mediaType,
        'content-length': String(body.byteLength)
      }
    }, response => {
      const chunks = []
      let total = 0
      response.on('data', chunk => {
        chunks.push(b4a.from(chunk))
        total += chunk.byteLength
      })
      response.once('error', reject)
      response.once('end', () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        body: b4a.concat(chunks, total)
      }))
    })
    request.once('error', reject)
    request.end(body)
  })
}

async function ephemeralLoopbackTls (root) {
  const keyFile = path.join(root, 'edge-v2-tls-key.pem')
  const certFile = path.join(root, 'edge-v2-tls-cert.pem')
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

test('owned TLS edge exports real session material and completes staged CELL.PUT over V2 only', async t => {
  const directory = await createBlindBoundaryScratch('blind-edge-v2-e2e-')
  const unarySocketPath = path.join(directory, 'unary.sock')
  const streamSocketPath = path.join(directory, 'stream.sock')
  const launchTopologyHash = b4a.alloc(32, 0x61)
  const transportProfileHash = b4a.alloc(32, 0x62)
  const tls = await ephemeralLoopbackTls(directory)
  const daemonErrors = []
  let stagedBytes = 0
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
    stagedPutRelayPublicKey: b4a.alloc(32, 0x63),
    durableReplayAuthority: durableReplayAuthority(),
    writeReadinessProjection: writeReadinessProjection(launchTopologyHash, transportProfileHash),
    onError: error => daemonErrors.push(error),
    readinessSnapshot: async () => ({
      selfVerified: true,
      descriptorSequence: 1n,
      descriptorHash: b4a.alloc(32, 0x64),
      readyRoleBits: 1,
      readyOperationBits: 7
    }),
    dispatch: async () => { throw new Error('unary public dispatch must not service V2 CELL.PUT') },
    dispatchStagedPut: async staged => {
      for await (const chunk of staged.source) stagedBytes += chunk.byteLength
      return { dispatch: RESULT_DISPATCH, outerClass: 3 }
    }
  })
  await daemon.start()
  const edge = new BlindEdge({
    host: '127.0.0.1',
    port: 0,
    endpointId: 1,
    releaseGate: () => {},
    tls,
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
  await edge.start()
  t.teardown(async () => {
    await edge.close()
    await daemon.close()
    await removeBlindBoundaryScratch(directory)
  })

  const address = edge.address()
  const response = await httpsPost(address.port, REQUEST_OUTER)
  t.is(response.statusCode, 200)
  t.is(response.headers['content-type'], PROTOCOL.mediaType)
  t.is(response.body.byteLength, REQUEST_OUTER.byteLength)
  const frame = decodeOuterEnvelope(response.body, { copyInner: true, copyBody: true }).frame
  t.is(frame.familyId, FAMILY.CELL)
  t.is(frame.operationId, OPERATION.CELL.PUT)
  t.alike(frame.requestId, REQUEST_FRAME.requestId)
  t.is(stagedBytes, 4096)
  t.is(daemon.v2ReplayReservationCount, 1)
  t.is(daemon.v2IngressConstructionCount, 1)
  t.is(daemonErrors.length, 0)
})
