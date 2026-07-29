import b4a from 'b4a'
import test from 'brittle'
import {
  CELL_SIZE_CLASS,
  FAMILY,
  OPERATION,
  TRANSPORT_ID,
  encodeCanonical,
  getCellResultV1
} from '@hiverelay/blind-protocol'
import {
  VerifiedOperationResult,
  createCellReplica,
  createGetCellRequest,
  openVerifiedCellGetResult,
  verifyOperationResult
} from '../control.js'
import { sealCell } from '../cells.js'
import { createNodeCryptoRuntime } from '../runtime/node.js'
import { verifiedEndpointFixture } from './endpoint-fixture.js'

const runtime = createNodeCryptoRuntime()
const relayPublicKey = b4a.alloc(32, 0x31)
const admission = {
  profileId: 1,
  schemeId: 1,
  parameterHash: b4a.alloc(32, 0x32),
  token: b4a.from([0x33])
}

async function throwsCode (t, pending, code) {
  try {
    await pending
    t.fail(`expected ${code}`)
  } catch (error) {
    t.is(error.code, code)
  }
}

async function fixture () {
  const structuredContent = b4a.from('peerit recovery record')
  const replica = await createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 7,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent,
    admission
  })
  const get = await createGetCellRequest({ runtime, readCap: replica.readCap })
  const endpoint = verifiedEndpointFixture({
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    envelopeClassBits: 0x007e,
    canonicalUrl: b4a.from('https://relay.example:443/api/blind/v1/describe')
  }, FAMILY.CELL, OPERATION.CELL.GET, { relayPublicKey })
  const resultBytes = encodeCanonical(getCellResultV1, {
    version: 1,
    sizeClass: replica.readCap.sizeClass,
    cellBlob: replica.request.cellBlob
  })
  const verifiedResult = verifyOperationResult({
    endpoint,
    request: get.request,
    requestCommitment: get.requestCommitment,
    resultBytes
  })
  return { endpoint, get, replica, resultBytes, structuredContent, verifiedResult }
}

test('control surface opens only a verified CELL.GET result and returns an independent copy', async t => {
  const value = await fixture()
  t.is(typeof createGetCellRequest, 'function')
  t.is(typeof openVerifiedCellGetResult, 'function')

  value.resultBytes.fill(0)
  const opened = await openVerifiedCellGetResult({
    verifiedResult: value.verifiedResult,
    runtime,
    readCap: value.replica.readCap
  })
  t.alike(opened, value.structuredContent)
  opened.fill(0)
  t.alike(await openVerifiedCellGetResult({
    verifiedResult: value.verifiedResult,
    runtime,
    readCap: value.replica.readCap
  }), value.structuredContent)
})

test('CELL.GET readback requires the package-owned verifier brand', async t => {
  const value = await fixture()
  const forged = Object.create(VerifiedOperationResult.prototype)
  t.ok(forged instanceof VerifiedOperationResult)
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult: forged,
    runtime,
    readCap: value.replica.readCap
  }), 'BAD_CLIENT_INPUT')
})

test('CELL.GET readback requires the frozen read capability version', async t => {
  const value = await fixture()
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult: value.verifiedResult,
    runtime,
    readCap: { ...value.replica.readCap, version: 2 }
  }), 'BAD_CLIENT_INPUT')
})

test('CELL.GET readback requires the expected cell-blob hash', async t => {
  const value = await fixture()
  const readCap = { ...value.replica.readCap }
  delete readCap.expectedCellBlobHash
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult: value.verifiedResult,
    runtime,
    readCap
  }), 'BAD_CLIENT_INPUT')
})

test('CELL.GET readback wipes its copied key after success and failure', async t => {
  const value = await fixture()
  let copiedKey
  const observingRuntime = Object.freeze({
    ...runtime,
    async aes256GcmDecrypt (options) {
      copiedKey = options.key
      return runtime.aes256GcmDecrypt(options)
    }
  })
  const originalKey = b4a.from(value.replica.readCap.cellKey)

  t.alike(await openVerifiedCellGetResult({
    verifiedResult: value.verifiedResult,
    runtime: observingRuntime,
    readCap: value.replica.readCap
  }), value.structuredContent)
  t.alike(copiedKey, b4a.alloc(32))
  t.alike(value.replica.readCap.cellKey, originalKey)

  copiedKey = null
  const wrongKey = b4a.alloc(32, 0x43)
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult: value.verifiedResult,
    runtime: observingRuntime,
    readCap: { ...value.replica.readCap, cellKey: wrongKey }
  }), 'CELL_AUTHENTICATION_FAILED')
  t.alike(copiedKey, b4a.alloc(32))
  t.alike(wrongKey, b4a.alloc(32, 0x43))
})

test('CELL.GET readback binds relay, requested slot, result class, key and expected hash', async t => {
  const value = await fixture()
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult: value.verifiedResult,
    runtime,
    readCap: { ...value.replica.readCap, relayPublicKey: b4a.alloc(32, 0x41) }
  }), 'BAD_CLIENT_INPUT')
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult: value.verifiedResult,
    runtime,
    readCap: { ...value.replica.readCap, storageSlot: b4a.alloc(32, 0x42) }
  }), 'BAD_CLIENT_INPUT')
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult: value.verifiedResult,
    runtime,
    readCap: { ...value.replica.readCap, sizeClass: 2 }
  }), 'RELAY_PROTOCOL_VIOLATION')
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult: value.verifiedResult,
    runtime,
    readCap: { ...value.replica.readCap, cellKey: b4a.alloc(32, 0x43) }
  }), 'CELL_AUTHENTICATION_FAILED')
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult: value.verifiedResult,
    runtime,
    readCap: { ...value.replica.readCap, expectedCellBlobHash: b4a.alloc(32, 0x44) }
  }), 'CELL_HASH_MISMATCH')
})

test('CELL.GET verification snapshots an adversarial request slot exactly once', async t => {
  const slotA = await fixture()
  const structuredContentB = b4a.from('slot B must not cross the verified request boundary')
  const replicaB = await createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 8,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: structuredContentB,
    admission
  })
  t.unlike(replicaB.readCap.storageSlot, slotA.replica.readCap.storageSlot)

  let storageSlotReads = 0
  const switchingRequest = new Proxy(slotA.get.request, {
    get (target, property, receiver) {
      if (property === 'storageSlot') {
        storageSlotReads++
        return storageSlotReads === 1 ? slotA.replica.readCap.storageSlot : replicaB.readCap.storageSlot
      }
      return Reflect.get(target, property, receiver)
    }
  })
  const verifiedResult = verifyOperationResult({
    endpoint: slotA.endpoint,
    request: switchingRequest,
    requestCommitment: slotA.get.requestCommitment,
    resultBytes: encodeCanonical(getCellResultV1, {
      version: 1,
      sizeClass: replicaB.readCap.sizeClass,
      cellBlob: replicaB.request.cellBlob
    })
  })

  t.is(storageSlotReads, 1)
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult,
    runtime,
    readCap: replicaB.readCap
  }), 'BAD_CLIENT_INPUT')
})

test('CELL.GET readback rejects a valid but capability-inconsistent result class', async t => {
  const value = await fixture()
  const otherClass = await sealCell({
    runtime,
    storageSlot: value.replica.readCap.storageSlot,
    cellKey: value.replica.readCap.cellKey,
    sizeClass: 2,
    structuredContent: value.structuredContent
  })
  t.is(otherClass.cellBlob.byteLength, CELL_SIZE_CLASS[2])
  const verifiedResult = verifyOperationResult({
    endpoint: value.endpoint,
    request: value.get.request,
    requestCommitment: value.get.requestCommitment,
    resultBytes: encodeCanonical(getCellResultV1, {
      version: 1,
      sizeClass: 2,
      cellBlob: otherClass.cellBlob
    })
  })
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult,
    runtime,
    readCap: value.replica.readCap
  }), 'RELAY_PROTOCOL_VIOLATION')
})

test('CELL.GET readback detects post-verification cell-blob tampering', async t => {
  const value = await fixture()
  const tamperedBytes = encodeCanonical(getCellResultV1, {
    version: 1,
    sizeClass: value.replica.readCap.sizeClass,
    cellBlob: b4a.from(value.replica.request.cellBlob)
  })
  tamperedBytes[tamperedBytes.byteLength - 1] ^= 1
  const verifiedResult = verifyOperationResult({
    endpoint: value.endpoint,
    request: value.get.request,
    requestCommitment: value.get.requestCommitment,
    resultBytes: tamperedBytes
  })
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult,
    runtime,
    readCap: value.replica.readCap
  }), 'CELL_HASH_MISMATCH')
  await throwsCode(t, openVerifiedCellGetResult({
    verifiedResult,
    runtime,
    readCap: { ...value.replica.readCap, expectedCellBlobHash: null }
  }), 'BAD_CLIENT_INPUT')
})
