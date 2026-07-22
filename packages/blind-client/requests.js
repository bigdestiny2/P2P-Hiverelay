import b4a from 'b4a'
import {
  CELL_SIZE_CLASS,
  FAMILY,
  OPERATION
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import {
  allocationCommitment,
  blake2b256,
  cellBatchGetRequestCommitment,
  cellGetRequestCommitment,
  cellManageRequestCommitment,
  cellProveRequestCommitment,
  cellPutRequestCommitment,
  cellStorageSlot
} from '@hiverelay/blind-protocol/hashes'
import {
  batchGetV1,
  dropCellV1,
  getCellV1,
  proveCellV1,
  putCellV1,
  renewCellV1
} from '@hiverelay/blind-protocol/schemas'
import { encodeCanonical } from '@hiverelay/blind-protocol/codec'
import { asBytes, randomBytes, wipe } from './bytes.js'
import {
  destroyCellCapabilities,
  generateDistinctCapabilityKeys,
  signCapability
} from './capabilities.js'
import { sealCell } from './cells.js'
import { fail } from './errors.js'
import { resolveAdmission } from './provider.js'
import { selectedOperationProfile } from './selected-operation-profile.js'

function u32 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) fail('BAD_CLIENT_INPUT', `${field} is outside u32`)
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_CLIENT_INPUT', `${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) fail('BAD_CLIENT_INPUT', `${field} is outside u64`)
  return value
}

function nonce (runtime, value) {
  return value == null ? randomBytes(runtime, 32, 'client nonce') : b4a.from(asBytes(value, 'clientNonce', 32))
}

async function admission (options, context, required) {
  return resolveAdmission(options, context, required,
    'this operation requires an admission provider or admission value')
}

function result (encoding, request, requestCommitment, familyId, operationId, expectedResultBodyBytes = null) {
  const profile = selectedOperationProfile(familyId, operationId)
  return {
    request,
    requestBytes: encodeCanonical(encoding, request),
    requestCommitment,
    wire: Object.freeze({
      familyId,
      operationId,
      expectedResultBodyBytes: expectedResultBodyBytes == null ? profile.maxResultBodyBytes : expectedResultBodyBytes
    })
  }
}

export async function createCellReplica (options) {
  if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'cell replica options are required')
  const runtime = options.runtime
  const relayPublicKey = asBytes(options.relayPublicKey, 'relayPublicKey', 32)
  const allocationEpoch = u32(options.allocationEpoch, 'allocationEpoch')
  const sizeClass = options.sizeClass
  const leaseClass = options.leaseClass
  const capabilities = generateDistinctCapabilityKeys(runtime, ['create', 'renew', 'drop'], [relayPublicKey])
  const storageSlot = cellStorageSlot({ allocationEpoch, createPublicKey: capabilities.create.publicKey })
  let sealed
  let writeCap
  try {
    sealed = await sealCell({
      runtime,
      storageSlot,
      sizeClass,
      structuredContent: options.structuredContent
    })
    const declaredBlobHash = blake2b256(sealed.cellBlob)
    const allocation = allocationCommitment({
      relayPublicKey,
      storageSlot,
      allocationEpoch,
      sizeClass,
      leaseClass,
      declaredCellBlobHash: declaredBlobHash,
      createPublicKey: capabilities.create.publicKey,
      renewPublicKey: capabilities.renew.publicKey,
      dropPublicKey: capabilities.drop.publicKey
    })
    const clientNonce = nonce(runtime, options.clientNonce)
    const requestCommitment = cellPutRequestCommitment({ allocationCommitment: allocation, clientNonce })
    const admissionValue = await admission(options, {
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.PUT,
      requestCommitment,
      relayPublicKey,
      sizeClass,
      leaseClass
    }, true)
    const request = {
      version: 1,
      storageSlot,
      allocationEpoch,
      sizeClass,
      leaseClass,
      clientNonce,
      createPublicKey: capabilities.create.publicKey,
      renewPublicKey: capabilities.renew.publicKey,
      dropPublicKey: capabilities.drop.publicKey,
      declaredBlobHash,
      createSignature: signCapability(capabilities.create.privateSeed, allocation),
      admission: admissionValue,
      cellBlob: sealed.cellBlob
    }
    const readCap = {
      version: 1,
      relayPublicKey: b4a.from(relayPublicKey),
      storageSlot: b4a.from(storageSlot),
      cellKey: sealed.cellKey,
      sizeClass,
      expectedCellBlobHash: b4a.from(declaredBlobHash)
    }
    writeCap = {
      readCap,
      allocationEpoch,
      createPrivateKey: capabilities.create.privateSeed,
      renewPrivateKey: capabilities.renew.privateSeed,
      dropPrivateKey: capabilities.drop.privateSeed
    }
    return {
      ...result(putCellV1, request, requestCommitment, FAMILY.CELL, OPERATION.CELL.PUT),
      allocationCommitment: allocation,
      readCap,
      writeCap
    }
  } catch (error) {
    if (writeCap) destroyCellCapabilities(writeCap)
    else {
      wipe(capabilities.create.privateSeed)
      wipe(capabilities.renew.privateSeed)
      wipe(capabilities.drop.privateSeed)
      if (sealed) wipe(sealed.cellKey)
    }
    throw error
  }
}

function writeFields (options) {
  if (!options || typeof options !== 'object' || !options.writeCap || !options.writeCap.readCap) {
    fail('BAD_CLIENT_INPUT', 'writeCap with readCap is required')
  }
  const readCap = options.writeCap.readCap
  return {
    relayPublicKey: asBytes(readCap.relayPublicKey, 'relayPublicKey', 32),
    storageSlot: asBytes(readCap.storageSlot, 'storageSlot', 32)
  }
}

export async function createRenewCellRequest (options) {
  const runtime = options && options.runtime
  const fields = writeFields(options)
  const clientNonce = nonce(runtime, options.clientNonce)
  const expectedRevision = u64(options.expectedRevision, 'expectedRevision')
  const expectedLeaseEpoch = u32(options.expectedLeaseEpoch, 'expectedLeaseEpoch')
  const leaseClass = options.leaseClass
  const requestCommitment = cellManageRequestCommitment({
    operation: 'cell-renew',
    ...fields,
    expectedRevision,
    expectedLeaseEpoch,
    requestedLeaseClass: leaseClass,
    clientNonce
  })
  const admissionValue = await admission(options, {
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.RENEW,
    requestCommitment,
    relayPublicKey: fields.relayPublicKey,
    leaseClass
  }, true)
  const request = {
    version: 1,
    storageSlot: fields.storageSlot,
    expectedRevision,
    expectedLeaseEpoch,
    leaseClass,
    clientNonce,
    admission: admissionValue,
    signature: signCapability(options.writeCap.renewPrivateKey, requestCommitment)
  }
  return result(renewCellV1, request, requestCommitment, FAMILY.CELL, OPERATION.CELL.RENEW)
}

export function createDropCellRequest (options) {
  const runtime = options && options.runtime
  const fields = writeFields(options)
  const clientNonce = nonce(runtime, options.clientNonce)
  const expectedRevision = u64(options.expectedRevision, 'expectedRevision')
  const expectedLeaseEpoch = u32(options.expectedLeaseEpoch, 'expectedLeaseEpoch')
  const requestCommitment = cellManageRequestCommitment({
    operation: 'cell-drop',
    ...fields,
    expectedRevision,
    expectedLeaseEpoch,
    requestedLeaseClass: 0,
    clientNonce
  })
  const request = {
    version: 1,
    storageSlot: fields.storageSlot,
    expectedRevision,
    expectedLeaseEpoch,
    clientNonce,
    signature: signCapability(options.writeCap.dropPrivateKey, requestCommitment)
  }
  return result(dropCellV1, request, requestCommitment, FAMILY.CELL, OPERATION.CELL.DROP)
}

async function createReadRequest (options, operationId, commitment, encoding) {
  if (!options || typeof options !== 'object' || !options.readCap) fail('BAD_CLIENT_INPUT', 'readCap is required')
  const runtime = options.runtime
  const relayPublicKey = asBytes(options.readCap.relayPublicKey, 'relayPublicKey', 32)
  const storageSlot = asBytes(options.readCap.storageSlot, 'storageSlot', 32)
  const clientNonce = nonce(runtime, options.clientNonce)
  const requestCommitment = commitment({ relayPublicKey, storageSlot, clientNonce })
  const admissionValue = await admission(options, {
    familyId: FAMILY.CELL,
    operationId,
    requestCommitment,
    relayPublicKey
  }, false)
  const request = { version: 1, storageSlot, clientNonce, admission: admissionValue }
  let expectedResultBodyBytes = null
  if (operationId === OPERATION.CELL.GET) {
    const bytes = CELL_SIZE_CLASS[options.readCap.sizeClass]
    if (bytes == null) fail('BAD_CLIENT_INPUT', 'readCap sizeClass is outside the frozen cell classes')
    expectedResultBodyBytes = 2 + bytes
  }
  return result(encoding, request, requestCommitment, FAMILY.CELL, operationId, expectedResultBodyBytes)
}

export const createGetCellRequest = options => createReadRequest(options, OPERATION.CELL.GET, cellGetRequestCommitment, getCellV1)
export const createProveCellRequest = options => createReadRequest(options, OPERATION.CELL.PROVE, cellProveRequestCommitment, proveCellV1)

export async function createBatchGetRequest (options) {
  if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'batch options are required')
  const runtime = options.runtime
  const relayPublicKey = asBytes(options.relayPublicKey, 'relayPublicKey', 32)
  if (!Array.isArray(options.slots)) fail('BAD_CLIENT_INPUT', 'slots must be an array')
  const slots = options.slots.map((slot, index) => b4a.from(asBytes(slot, `slots[${index}]`, 32)))
  const clientNonce = nonce(runtime, options.clientNonce)
  const requestCommitment = cellBatchGetRequestCommitment({ relayPublicKey, slots, clientNonce })
  const admissionValue = await admission(options, {
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.BATCH_GET,
    requestCommitment,
    relayPublicKey,
    count: slots.length
  }, false)
  const request = { version: 1, clientNonce, slots, admission: admissionValue }
  return result(batchGetV1, request, requestCommitment, FAMILY.CELL, OPERATION.CELL.BATCH_GET)
}
