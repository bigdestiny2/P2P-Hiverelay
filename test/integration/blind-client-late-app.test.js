import { execFile } from 'node:child_process'
import fs from 'node:fs/promises'
import https from 'node:https'
import path from 'node:path'
import { promisify } from 'node:util'
import b4a from 'b4a'
import test from 'brittle'
import {
  CELL_RECEIPT_RESULT,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  TRANSPORT_ID,
  allocationCommitment,
  blake2b256,
  blindReceiptV1,
  cellPutRequestCommitment,
  encodeCanonical,
  encodeDispatchFrame
} from '@hiverelay/blind-protocol'
import {
  CELL_PUT_ENDPOINT_ROLE_BIT_V2,
  CELL_PUT_OPERATION_BIT_V2,
  REQUIRED_LOCAL_IPC_FEATURE_BITS_V2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import {
  BlindDirectHttpClient,
  createCellReplica,
  openCell
} from '@hiverelay/blind-client'
import { createNodeCryptoRuntime } from '@hiverelay/blind-client/runtime/node'
import { verifiedEndpointFixture } from '../../packages/blind-client/test/endpoint-fixture.js'
import { BlindDaemon } from '@hiverelay/blind-daemon'
import { BlindEdge } from '@hiverelay/blind-edge'
import {
  encodeFixtureRecord as encodeFieldNotebook,
  sentinels as fieldSentinels
} from '../fixtures/blind-apps/field-notebook/index.js'
import {
  encodeFixtureRecord as encodeBinaryTiles,
  sentinels as tileSentinels
} from '../fixtures/blind-apps/binary-tile-stream/index.js'

const execFileAsync = promisify(execFile)
const runtime = createNodeCryptoRuntime()

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
    descriptorHash: b4a.alloc(32, 0x73),
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

function contains (haystack, needle) {
  return b4a.toString(haystack, 'hex').includes(b4a.toString(b4a.from(needle), 'hex'))
}

test('a running generic relay accepts unrelated and later-created apps without restart or configuration', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-late-app-')
  const unarySocketPath = path.join(directory, 'unary.sock')
  const streamSocketPath = path.join(directory, 'stream.sock')
  const launchTopologyHash = b4a.alloc(32, 0x71)
  const transportProfileHash = b4a.alloc(32, 0x76)
  const relayPublicKey = b4a.alloc(32, 0x72)
  const tls = await ephemeralLoopbackTls(directory)
  const observed = []
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
      descriptorHash: b4a.alloc(32, 0x73),
      readyRoleBits: 1,
      readyOperationBits: 0x7
    }),
    dispatch: async () => {
      throw new Error('CELL.PUT must not use unary IPC')
    },
    async dispatchStagedPut (staged, context) {
      t.is(staged.frame.familyId, FAMILY.CELL)
      t.is(staged.frame.operationId, OPERATION.CELL.PUT)
      t.is(staged.request.cellBlob, undefined)
      const chunks = []
      for await (const chunk of staged.source) chunks.push(b4a.from(chunk))
      observed.push({
        prefix: b4a.from(staged.canonicalRequestPrefixBytes),
        request: staged.request,
        cellBlob: b4a.concat(chunks),
        context
      })
      const committedAllocation = allocationCommitment({
        ...staged.request,
        relayPublicKey: b4a.alloc(32, 0x92),
        declaredCellBlobHash: staged.request.declaredBlobHash
      })
      const receipt = {
        version: 1,
        protocol: b4a.from('hiverelay-blind-cell-v1', 'ascii'),
        relayBinding: {
          version: 1,
          relayPublicKey: b4a.alloc(32, 0x92),
          storeId: b4a.alloc(32, 0x91),
          descriptorSequence: 1n,
          descriptorHash: b4a.alloc(32, 0x73),
          durabilityProfileId: 1,
          durabilityContinuityHash: b4a.alloc(32, 0x90),
          durabilityProfileHash: b4a.alloc(32, 0x8f),
          restoreEvidenceHeadSequence: 0n,
          restoreEvidenceHeadHash: b4a.alloc(32),
          externalCommitWitness: null
        },
        slotCommitment: blake2b256(staged.request.storageSlot),
        cellBlobHash: b4a.from(staged.request.declaredBlobHash),
        allocationCommitment: committedAllocation,
        requestCommitment: cellPutRequestCommitment({
          allocationCommitment: committedAllocation,
          clientNonce: staged.request.clientNonce
        }),
        sizeClass: staged.request.sizeClass,
        allocationEpoch: staged.request.allocationEpoch,
        leaseClass: staged.request.leaseClass,
        leaseEpoch: staged.request.allocationEpoch + 4,
        stateRevision: 0n,
        receiptEpoch: staged.request.allocationEpoch,
        requestNonce: b4a.from(staged.request.clientNonce),
        result: CELL_RECEIPT_RESULT.STORED,
        signature: b4a.alloc(64)
      }
      return {
        dispatch: encodeDispatchFrame({
          frameKind: FRAME_KIND.RESPONSE,
          familyId: FAMILY.CELL,
          operationId: OPERATION.CELL.PUT,
          requestId: staged.frame.requestId,
          body: encodeCanonical(blindReceiptV1, receipt)
        }),
        outerClass: context.outerClass
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

  const endpoint = verifiedEndpointFixture({
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    envelopeClassBits: 0x007e,
    canonicalUrl: b4a.from(`https://127.0.0.1:${edge.address().port}/api/blind/v1/describe`)
  }, FAMILY.CELL, OPERATION.CELL.PUT)
  const admission = {
    profileId: 1,
    schemeId: 1,
    parameterHash: b4a.alloc(32, 0x74),
    token: b4a.alloc(32, 0x75)
  }
  const client = new BlindDirectHttpClient({
    runtime,
    fetch: localTlsFetch
  })
  const fieldContent = encodeFieldNotebook()
  const tileContent = encodeBinaryTiles()
  const thirdSentinel = 'UNKNOWN_AFTER_RELAY_START_PRIVATE_SENTINEL_f4f2db21'
  const thirdContent = b4a.from(JSON.stringify({ producer: thirdSentinel, values: [2, 3, 5, 8] }))
  const producers = [
    { content: fieldContent, sentinels: fieldSentinels, sizeClass: 3, epoch: 901 },
    { content: tileContent, sentinels: tileSentinels, sizeClass: 4, epoch: 902 },
    { content: thirdContent, sentinels: [thirdSentinel], sizeClass: 1, epoch: 903 }
  ]

  const replicas = []
  for (const producer of producers) {
    const replica = await createCellReplica({
      runtime,
      relayPublicKey,
      allocationEpoch: producer.epoch,
      sizeClass: producer.sizeClass,
      leaseClass: 1,
      structuredContent: producer.content,
      admission
    })
    const response = await client.request({
      endpoint,
      ...replica.wire,
      body: replica.requestBytes
    })
    t.ok(response.ok)
    replicas.push(replica)
  }

  t.is(observed.length, 3)
  for (let index = 0; index < observed.length; index++) {
    const relayView = observed[index]
    const producer = producers[index]
    for (const sentinel of producer.sentinels) {
      t.is(contains(relayView.prefix, sentinel), false, `${sentinel} is absent from the live relay frame`)
      t.is(contains(relayView.cellBlob, sentinel), false, `${sentinel} is absent from stored relay bytes`)
    }
    t.absent(relayView.context.sourceIp)
    t.absent(relayView.context.origin)
    t.absent(relayView.context.headers)
    t.absent(relayView.context.app)
    t.alike(await openCell({
      runtime,
      ...replicas[index].readCap,
      cellBlob: relayView.cellBlob
    }), producer.content)
  }
  t.alike(observed.map(value => Object.keys(value.request).sort()), [
    Object.keys(observed[0].request).sort(),
    Object.keys(observed[0].request).sort(),
    Object.keys(observed[0].request).sort()
  ])
  t.alike(daemonErrors, [])
})
