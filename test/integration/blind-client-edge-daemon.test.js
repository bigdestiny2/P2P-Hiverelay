import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import {
  FAMILY,
  OPERATION,
  TRANSPORT_ID,
  decodeCanonical,
  encodeCanonical,
  getCellResultV1,
  getCellV1
} from '@hiverelay/blind-protocol'
import { BlindDirectHttpClient, createGetCellRequest } from '@hiverelay/blind-client'
import { createNodeCryptoRuntime } from '@hiverelay/blind-client/runtime/node'
import { verifiedEndpointFixture } from '../../packages/blind-client/test/endpoint-fixture.js'
import { BlindDaemon } from '@hiverelay/blind-daemon'
import { BlindEdge } from '@hiverelay/blind-edge'

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
