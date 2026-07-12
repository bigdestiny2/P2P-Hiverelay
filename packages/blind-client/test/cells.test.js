import b4a from 'b4a'
import { webcrypto } from 'node:crypto'
import test from 'brittle'
import {
  CELL_SIZE_CLASS,
  allocationCommitment,
  cellStorageSlot,
  decodeCanonical,
  putCellV1
} from '@hiverelay/blind-protocol'
import {
  BlindClientError,
  createCellReplica,
  createDropCellRequest,
  createGetCellRequest,
  createRenewCellRequest,
  destroyCellWriteCapability,
  generateDistinctCapabilityKeys,
  maximumCellContentBytes,
  openCell,
  publicKeyFromPrivateSeed,
  sealCell,
  verifyCapabilitySignature
} from '../index.js'
import { createBrowserCryptoRuntime } from '../runtime/browser.js'
import { createNodeCryptoRuntime } from '../runtime/node.js'

const runtime = createNodeCryptoRuntime()
const relayPublicKey = b4a.alloc(32, 7)
const admission = {
  profileId: 1,
  schemeId: 1,
  parameterHash: b4a.alloc(32, 8),
  token: b4a.from([9])
}

test('cell encryption is exact-sized, authenticated and randomized across every class', async t => {
  const storageSlot = b4a.alloc(32, 3)
  for (const [id, bytes] of Object.entries(CELL_SIZE_CLASS)) {
    const sizeClass = Number(id)
    const structuredContent = b4a.from(`opaque-app-record-${id}`)
    const first = await import('../cells.js').then(module => module.sealCell({ runtime, storageSlot, sizeClass, structuredContent }))
    const second = await import('../cells.js').then(module => module.sealCell({ runtime, storageSlot, sizeClass, structuredContent }))
    t.is(first.cellBlob.byteLength, bytes)
    t.is(second.cellBlob.byteLength, bytes)
    t.not(first.cellBlob, second.cellBlob)
    t.alike(await openCell({ runtime, storageSlot, sizeClass, cellKey: first.cellKey, cellBlob: first.cellBlob }), structuredContent)
  }
})

test('cell authentication binds key, slot, class and every sealed byte', async t => {
  const created = await createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 100,
    sizeClass: 1,
    leaseClass: 2,
    structuredContent: b4a.from('peerit is only opaque application bytes here'),
    admission
  })
  const opened = await openCell({
    runtime,
    storageSlot: created.readCap.storageSlot,
    sizeClass: created.readCap.sizeClass,
    cellKey: created.readCap.cellKey,
    cellBlob: created.request.cellBlob
  })
  t.alike(opened, b4a.from('peerit is only opaque application bytes here'))

  const tampered = b4a.from(created.request.cellBlob)
  tampered[tampered.byteLength - 1] ^= 1
  await t.exception(openCell({ runtime, ...created.readCap, cellBlob: tampered }), BlindClientError)
  await t.exception(openCell({ runtime, ...created.readCap, storageSlot: b4a.alloc(32, 4), cellBlob: created.request.cellBlob }), BlindClientError)
  await t.exception(openCell({ runtime, ...created.readCap, cellKey: b4a.alloc(32, 5), cellBlob: created.request.cellBlob }), BlindClientError)
  await t.exception(openCell({
    runtime,
    ...created.readCap,
    expectedCellBlobHash: b4a.alloc(32, 6),
    cellBlob: created.request.cellBlob
  }), /read capability/)
})

test('Node and browser runtimes produce byte-identical mandatory cells', async t => {
  const browser = createBrowserCryptoRuntime(webcrypto)
  const storageSlot = b4a.alloc(32, 21)
  const cellKey = b4a.alloc(32, 22)
  const nonce = b4a.alloc(12, 23)
  const structuredContent = b4a.alloc(maximumCellContentBytes(1), 24)
  const nodeCell = await sealCell({ runtime, storageSlot, sizeClass: 1, structuredContent, cellKey, nonce })
  const browserCell = await sealCell({ runtime: browser, storageSlot, sizeClass: 1, structuredContent, cellKey, nonce })
  t.alike(nodeCell.cellBlob, browserCell.cellBlob)
  t.alike(await openCell({ runtime, storageSlot, sizeClass: 1, cellKey, cellBlob: browserCell.cellBlob }), structuredContent)
  t.alike(await openCell({ runtime: browser, storageSlot, sizeClass: 1, cellKey, cellBlob: nodeCell.cellBlob }), structuredContent)
})

test('cell replica creates three distinct relay-bound capabilities and canonical PUT bytes', async t => {
  const created = await createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 321,
    sizeClass: 2,
    leaseClass: 3,
    structuredContent: b4a.from('field-notebook fixture record'),
    admission
  })
  const decoded = decodeCanonical(putCellV1, created.requestBytes, { copyBytes: true })
  t.alike(decoded.storageSlot, created.request.storageSlot)
  t.alike(cellStorageSlot(decoded), created.request.storageSlot)
  t.unlike(decoded.createPublicKey, decoded.renewPublicKey)
  t.unlike(decoded.createPublicKey, decoded.dropPublicKey)
  t.unlike(decoded.renewPublicKey, decoded.dropPublicKey)
  const expectedAllocation = allocationCommitment({
    relayPublicKey,
    ...decoded,
    declaredCellBlobHash: decoded.declaredBlobHash
  })
  t.alike(created.allocationCommitment, expectedAllocation)
  t.ok(verifyCapabilitySignature(decoded.createPublicKey, expectedAllocation, decoded.createSignature))
  t.is(created.readCap.expectedCellBlobHash.byteLength, 32)
  t.is(created.writeCap.createPrivateKey.byteLength, 32)
})

test('destroying cell write authority preserves independent read authority', async t => {
  const created = await createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 322,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: b4a.from('keep reading after write-key destruction'),
    admission
  })
  const cellKey = b4a.from(created.readCap.cellKey)
  destroyCellWriteCapability(created.writeCap)
  t.alike(created.readCap.cellKey, cellKey)
  t.alike(created.writeCap.createPrivateKey, b4a.alloc(32))
  t.alike(await openCell({ runtime, ...created.readCap, cellBlob: created.request.cellBlob }),
    b4a.from('keep reading after write-key destruction'))
})

test('capability generation rejects a relay-key collision and regenerates', t => {
  const forbiddenSeed = b4a.alloc(32, 61)
  const forbiddenPublicKey = publicKeyFromPrivateSeed(forbiddenSeed)
  let call = 0
  const deterministic = {
    randomBytes (length) {
      t.is(length, 32)
      call++
      return call === 1 ? forbiddenSeed : b4a.alloc(32, 61 + call)
    }
  }
  const keys = generateDistinctCapabilityKeys(deterministic, ['create', 'renew', 'drop'], [forbiddenPublicKey])
  t.is(call, 4)
  t.unlike(keys.create.publicKey, forbiddenPublicKey)
  t.unlike(keys.renew.publicKey, forbiddenPublicKey)
  t.unlike(keys.drop.publicKey, forbiddenPublicKey)
})

test('cell content limit is exact and oversized content fails before admission', async t => {
  const limit = maximumCellContentBytes(1)
  let calls = 0
  const created = await createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 50,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: b4a.alloc(limit, 1),
    admissionProvider: async () => { calls++; return admission }
  })
  t.is(created.request.cellBlob.byteLength, CELL_SIZE_CLASS[1])
  t.is(calls, 1)
  await t.exception(createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 50,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: b4a.alloc(limit + 1),
    admissionProvider: async () => { calls++; return admission }
  }), /exceeds sizeClass/)
  t.is(calls, 1)
})

test('renew, drop and read requests bind commitments without application metadata', async t => {
  const created = await createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 10,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: b4a.from([1, 2, 3]),
    admission
  })
  const renew = await createRenewCellRequest({
    runtime,
    writeCap: created.writeCap,
    expectedRevision: 0n,
    expectedLeaseEpoch: 14,
    leaseClass: 2,
    admission
  })
  const drop = createDropCellRequest({
    runtime,
    writeCap: created.writeCap,
    expectedRevision: 1n,
    expectedLeaseEpoch: 38
  })
  const get = await createGetCellRequest({ runtime, readCap: created.readCap })
  t.is(renew.requestCommitment.byteLength, 32)
  t.is(drop.requestCommitment.byteLength, 32)
  t.is(get.requestCommitment.byteLength, 32)
  t.absent(renew.request.app)
  t.absent(drop.request.namespace)
  t.absent(get.request.author)
})
