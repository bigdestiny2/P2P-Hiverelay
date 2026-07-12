import b4a from 'b4a'
import test from 'brittle'
import { decodeCanonical, putCellV1 } from '@hiverelay/blind-protocol'
import { createCellReplica, openCell } from '@hiverelay/blind-client'
import { createNodeCryptoRuntime } from '@hiverelay/blind-client/runtime/node'
import {
  encodeFixtureRecord as encodeFieldNotebook,
  sentinels as fieldSentinels
} from '../fixtures/blind-apps/field-notebook/index.js'
import {
  encodeFixtureRecord as encodeBinaryTiles,
  sentinels as tileSentinels
} from '../fixtures/blind-apps/binary-tile-stream/index.js'

const runtime = createNodeCryptoRuntime()
const relayPublicKey = b4a.alloc(32, 91)
const admission = {
  profileId: 1,
  schemeId: 1,
  parameterHash: b4a.alloc(32, 92),
  token: b4a.alloc(32, 93)
}

function contains (haystack, needle) {
  return b4a.toString(haystack, 'hex').includes(b4a.toString(b4a.from(needle), 'hex'))
}

function assertOpaque (t, encodedRequest, sentinels) {
  for (const sentinel of sentinels) t.is(contains(encodedRequest, sentinel), false, `${sentinel} is absent from relay bytes`)
  const request = decodeCanonical(putCellV1, encodedRequest, { copyBytes: true })
  t.alike(Object.keys(request).sort(), [
    'admission',
    'allocationEpoch',
    'cellBlob',
    'clientNonce',
    'createPublicKey',
    'createSignature',
    'declaredBlobHash',
    'dropPublicKey',
    'leaseClass',
    'renewPublicKey',
    'sizeClass',
    'storageSlot',
    'version'
  ])
  t.absent(request.app)
  t.absent(request.author)
  t.absent(request.type)
  t.absent(request.namespace)
  t.absent(request.logicalId)
}

test('unrelated apps and a later unknown producer use one opaque relay contract', async t => {
  const fieldContent = encodeFieldNotebook()
  const tileContent = encodeBinaryTiles()
  const field = await createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 200,
    sizeClass: 3,
    leaseClass: 2,
    structuredContent: fieldContent,
    admission
  })
  const tiles = await createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 200,
    sizeClass: 4,
    leaseClass: 2,
    structuredContent: tileContent,
    admission
  })
  assertOpaque(t, field.requestBytes, fieldSentinels)
  assertOpaque(t, tiles.requestBytes, tileSentinels)
  t.alike(await openCell({ runtime, ...field.readCap, cellBlob: field.request.cellBlob }), fieldContent)
  t.alike(await openCell({ runtime, ...tiles.readCap, cellBlob: tiles.request.cellBlob }), tileContent)

  const thirdSentinel = 'UNKNOWN_POST_STARTUP_PRODUCER_PRIVATE_SENTINEL_5a4c77e1'
  const thirdContent = b4a.from(JSON.stringify({ producer: thirdSentinel, value: [1, 3, 5, 7] }))
  const third = await createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 201,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: thirdContent,
    admission
  })
  assertOpaque(t, third.requestBytes, [thirdSentinel])
  t.alike(await openCell({ runtime, ...third.readCap, cellBlob: third.request.cellBlob }), thirdContent)
  t.is(field.wire.familyId, tiles.wire.familyId)
  t.is(field.wire.operationId, tiles.wire.operationId)
  t.is(tiles.wire.familyId, third.wire.familyId)
  t.is(tiles.wire.operationId, third.wire.operationId)
  t.not(field.request.sizeClass, tiles.request.sizeClass, 'universal size-class leakage remains visible and is not an anonymity claim')
})
