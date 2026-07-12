import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import {
  FAMILY,
  OPERATION,
  TRANSPORT_ID,
  decodeCanonical,
  putCellV1
} from '@hiverelay/blind-protocol'
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

const runtime = createNodeCryptoRuntime()

function contains (haystack, needle) {
  return b4a.toString(haystack, 'hex').includes(b4a.toString(b4a.from(needle), 'hex'))
}

test('a running generic relay accepts unrelated and later-created apps without restart or configuration', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-late-app-')
  const unarySocketPath = path.join(directory, 'unary.sock')
  const streamSocketPath = path.join(directory, 'stream.sock')
  const launchTopologyHash = b4a.alloc(32, 0x71)
  const relayPublicKey = b4a.alloc(32, 0x72)
  const observed = []
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
      descriptorHash: b4a.alloc(32, 0x73),
      readyRoleBits: 1,
      readyOperationBits: 0x7
    }),
    dispatch (frame, context) {
      t.is(frame.familyId, FAMILY.CELL)
      t.is(frame.operationId, OPERATION.CELL.PUT)
      const request = decodeCanonical(putCellV1, frame.body, { copyBytes: true })
      observed.push({ frame: b4a.from(frame.body), request, context })
      return { body: b4a.alloc(0) }
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

  const endpoint = verifiedEndpointFixture({
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    envelopeClassBits: 0x007e,
    canonicalUrl: b4a.from(`http://127.0.0.1:${edge.address().port}/api/blind/v1/describe`)
  }, FAMILY.CELL, OPERATION.CELL.PUT)
  const admission = {
    profileId: 1,
    schemeId: 1,
    parameterHash: b4a.alloc(32, 0x74),
    token: b4a.alloc(32, 0x75)
  }
  const client = new BlindDirectHttpClient({
    runtime,
    allowInsecureLoopback: true
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
      t.is(contains(relayView.frame, sentinel), false, `${sentinel} is absent from the live relay frame`)
      t.is(contains(relayView.request.cellBlob, sentinel), false, `${sentinel} is absent from stored relay bytes`)
    }
    t.absent(relayView.context.sourceIp)
    t.absent(relayView.context.origin)
    t.absent(relayView.context.headers)
    t.absent(relayView.context.app)
    t.alike(await openCell({
      runtime,
      ...replicas[index].readCap,
      cellBlob: relayView.request.cellBlob
    }), producer.content)
  }
  t.alike(observed.map(value => Object.keys(value.request).sort()), [
    Object.keys(observed[0].request).sort(),
    Object.keys(observed[0].request).sort(),
    Object.keys(observed[0].request).sort()
  ])
})
