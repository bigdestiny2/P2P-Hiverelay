import b4a from 'b4a'
import {
  FAMILY,
  INBOX_APPEND_AUTH_MODE,
  INBOX_FRAME_CLASS,
  INBOX_MANAGE_OPERATION,
  OPERATION
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import {
  blake2b256,
  inboxAppendRequestCommitment,
  inboxCreateCommitment,
  inboxCreateRequestCommitment,
  inboxManageRequestCommitment,
  inboxPhysicalTopic,
  inboxReadRequestCommitment,
  inboxWatchRequestCommitment
} from '@hiverelay/blind-protocol/hashes'
import {
  inboxAppendV1,
  inboxCreateV1,
  inboxManageV1,
  inboxReadV1,
  inboxWatchV1
} from '@hiverelay/blind-protocol/schemas'
import { encodeCanonical } from '@hiverelay/blind-protocol/codec'
import { asBytes, randomBytes, wipe } from './bytes.js'
import { generateDistinctCapabilityKeys, signCapability } from './capabilities.js'
import { fail } from './errors.js'
import { resolveAdmission } from './provider.js'
import { selectedOperationProfile } from './selected-operation-profile.js'

const MAX_U64 = (1n << 64n) - 1n
const RESULT_OVERHEAD_BOUND = 4096

function integer (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('BAD_CLIENT_INPUT', `${field} must be within ${minimum}..${maximum}`)
  }
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_CLIENT_INPUT', `${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail('BAD_CLIENT_INPUT', `${field} is outside u64`)
  return value
}

function nonce (runtime, value) {
  return value == null ? randomBytes(runtime, 32, 'client nonce') : b4a.from(asBytes(value, 'clientNonce', 32))
}

async function admission (options, context, required) {
  return resolveAdmission(options, context, required,
    'this operation requires an admission provider or admission value')
}

function result (encoding, request, requestCommitment, operationId, expectedResultBodyBytes = null) {
  const profile = selectedOperationProfile(FAMILY.INBOX, operationId)
  return {
    request,
    requestBytes: encodeCanonical(encoding, request),
    requestCommitment,
    wire: Object.freeze({
      familyId: FAMILY.INBOX,
      operationId,
      expectedResultBodyBytes: expectedResultBodyBytes == null ? profile.maxResultBodyBytes : expectedResultBodyBytes
    })
  }
}

function readCap (options) {
  if (!options || typeof options !== 'object' || !options.readCap) fail('BAD_CLIENT_INPUT', 'readCap is required')
  const cap = options.readCap
  const relayPublicKey = b4a.from(asBytes(cap.relayPublicKey, 'relayPublicKey', 32))
  const physicalTopic = b4a.from(asBytes(cap.physicalTopic, 'physicalTopic', 32))
  const frameClassBits = integer(cap.frameClassBits, 1, 0x07, 'frameClassBits')
  if ((frameClassBits & ~0x07) !== 0) fail('BAD_CLIENT_INPUT', 'frameClassBits contains an unknown class')
  const appendAuthMode = integer(cap.appendAuthMode, 0, 1, 'appendAuthMode')
  const appendPublicKey = cap.appendPublicKey == null ? null : b4a.from(asBytes(cap.appendPublicKey, 'appendPublicKey', 32))
  if ((appendAuthMode === INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED) !== (appendPublicKey != null)) {
    fail('BAD_CLIENT_INPUT', 'appendPublicKey presence does not match appendAuthMode')
  }
  return { relayPublicKey, physicalTopic, frameClassBits, appendAuthMode, appendPublicKey }
}

function writeCap (options) {
  if (!options || typeof options !== 'object' || !options.writeCap || !options.writeCap.readCap) {
    fail('BAD_CLIENT_INPUT', 'writeCap with readCap is required')
  }
  return { cap: readCap({ readCap: options.writeCap.readCap }), writeCap: options.writeCap }
}

function expectedReadResultBytes (cap, limit) {
  let largestFrameBytes = 0
  for (const [id, bytes] of Object.entries(INBOX_FRAME_CLASS)) {
    if ((cap.frameClassBits & (1 << (Number(id) - 1))) !== 0) largestFrameBytes = Math.max(largestFrameBytes, bytes)
  }
  if (largestFrameBytes === 0) fail('BAD_CLIENT_INPUT', 'readCap advertises no known frame class')
  const profile = selectedOperationProfile(FAMILY.INBOX, OPERATION.INBOX.READ)
  return Math.min(profile.maxResultBodyBytes, RESULT_OVERHEAD_BOUND + limit * (41 + largestFrameBytes))
}

export async function createInboxReplica (options) {
  if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'inbox replica options are required')
  const runtime = options.runtime
  const relayPublicKey = b4a.from(asBytes(options.relayPublicKey, 'relayPublicKey', 32))
  const allocationEpoch = integer(options.allocationEpoch, 0, 0xffffffff, 'allocationEpoch')
  const frameClassBits = integer(options.frameClassBits, 1, 0x07, 'frameClassBits')
  const appendAuthMode = options.appendAuthMode == null
    ? INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED
    : integer(options.appendAuthMode, 0, 1, 'appendAuthMode')
  const retentionClass = integer(options.retentionClass, 1, 4, 'retentionClass')
  const leaseClass = integer(options.leaseClass, 1, 4, 'leaseClass')
  const names = appendAuthMode === INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED
    ? ['create', 'append', 'renew', 'close']
    : ['create', 'renew', 'close']
  const keys = generateDistinctCapabilityKeys(runtime, names, [relayPublicKey])
  let createdWriteCap
  try {
    const physicalTopic = inboxPhysicalTopic({ allocationEpoch, createPublicKey: keys.create.publicKey })
    const appendPublicKey = keys.append == null ? null : keys.append.publicKey
    const createCommitment = inboxCreateCommitment({
      relayPublicKey,
      allocationEpoch,
      physicalTopic,
      frameClassBits,
      appendAuthMode,
      createPublicKey: keys.create.publicKey,
      appendPublicKey,
      renewPublicKey: keys.renew.publicKey,
      closePublicKey: keys.close.publicKey,
      retentionClass,
      leaseClass
    })
    const clientNonce = nonce(runtime, options.clientNonce)
    const requestCommitment = inboxCreateRequestCommitment({ inboxCreateCommitment: createCommitment, clientNonce })
    const admissionValue = await admission(options, {
      familyId: FAMILY.INBOX,
      operationId: OPERATION.INBOX.CREATE,
      requestCommitment,
      relayPublicKey,
      frameClassBits,
      retentionClass,
      leaseClass
    }, true)
    const request = {
      version: 1,
      allocationEpoch,
      physicalTopic,
      frameClassBits,
      appendAuthMode,
      createPublicKey: keys.create.publicKey,
      appendPublicKey,
      renewPublicKey: keys.renew.publicKey,
      closePublicKey: keys.close.publicKey,
      retentionClass,
      leaseClass,
      clientNonce,
      createSignature: signCapability(keys.create.privateSeed, createCommitment),
      admission: admissionValue
    }
    const createdReadCap = {
      version: 1,
      relayPublicKey,
      physicalTopic: b4a.from(physicalTopic),
      frameClassBits,
      appendAuthMode,
      appendPublicKey: appendPublicKey == null ? null : b4a.from(appendPublicKey)
    }
    createdWriteCap = {
      readCap: createdReadCap,
      allocationEpoch,
      createPrivateKey: keys.create.privateSeed,
      appendPrivateKey: keys.append == null ? null : keys.append.privateSeed,
      renewPrivateKey: keys.renew.privateSeed,
      closePrivateKey: keys.close.privateSeed
    }
    return {
      ...result(inboxCreateV1, request, requestCommitment, OPERATION.INBOX.CREATE),
      createCommitment,
      readCap: createdReadCap,
      writeCap: createdWriteCap
    }
  } catch (error) {
    if (createdWriteCap) destroyInboxWriteCapability(createdWriteCap)
    else for (const key of Object.values(keys)) wipe(key.privateSeed)
    throw error
  }
}

export async function createRenewInboxRequest (options) {
  const { cap, writeCap: secret } = writeCap(options)
  const clientNonce = nonce(options.runtime, options.clientNonce)
  const expectedRevision = u64(options.expectedRevision, 'expectedRevision')
  const expectedLeaseEpoch = integer(options.expectedLeaseEpoch, 0, 0xffffffff, 'expectedLeaseEpoch')
  const leaseClass = integer(options.leaseClass, 1, 4, 'leaseClass')
  const requestCommitment = inboxManageRequestCommitment({
    operation: 'inbox-renew',
    relayPublicKey: cap.relayPublicKey,
    physicalTopic: cap.physicalTopic,
    expectedRevision,
    expectedLeaseEpoch,
    requestedLeaseClass: leaseClass,
    clientNonce
  })
  const admissionValue = await admission(options, {
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.RENEW,
    requestCommitment,
    relayPublicKey: cap.relayPublicKey,
    leaseClass
  }, true)
  const request = {
    version: 1,
    operation: INBOX_MANAGE_OPERATION.RENEW,
    physicalTopic: cap.physicalTopic,
    expectedRevision,
    expectedLeaseEpoch,
    leaseClass,
    clientNonce,
    signature: signCapability(secret.renewPrivateKey, requestCommitment),
    admission: admissionValue
  }
  return result(inboxManageV1, request, requestCommitment, OPERATION.INBOX.RENEW)
}

export function createCloseInboxRequest (options) {
  const { cap, writeCap: secret } = writeCap(options)
  const clientNonce = nonce(options.runtime, options.clientNonce)
  const expectedRevision = u64(options.expectedRevision, 'expectedRevision')
  const expectedLeaseEpoch = integer(options.expectedLeaseEpoch, 0, 0xffffffff, 'expectedLeaseEpoch')
  const requestCommitment = inboxManageRequestCommitment({
    operation: 'inbox-close',
    relayPublicKey: cap.relayPublicKey,
    physicalTopic: cap.physicalTopic,
    expectedRevision,
    expectedLeaseEpoch,
    requestedLeaseClass: 0,
    clientNonce
  })
  const request = {
    version: 1,
    operation: INBOX_MANAGE_OPERATION.CLOSE,
    physicalTopic: cap.physicalTopic,
    expectedRevision,
    expectedLeaseEpoch,
    leaseClass: 0,
    clientNonce,
    signature: signCapability(secret.closePrivateKey, requestCommitment),
    admission: null
  }
  return result(inboxManageV1, request, requestCommitment, OPERATION.INBOX.CLOSE)
}

export async function createAppendInboxRequest (options) {
  const source = options && options.writeCap
    ? writeCap(options)
    : { cap: readCap(options), writeCap: null }
  const cap = source.cap
  const frameClass = integer(options.frameClass, 1, 3, 'frameClass')
  if ((cap.frameClassBits & (1 << (frameClass - 1))) === 0) {
    fail('BAD_CLIENT_INPUT', 'frameClass is not enabled by the inbox capability')
  }
  const frame = b4a.from(asBytes(options.frame, 'opaque inbox frame', INBOX_FRAME_CLASS[frameClass]))
  const frameHash = blake2b256(frame)
  const clientNonce = nonce(options.runtime, options.clientNonce)
  const requestCommitment = inboxAppendRequestCommitment({
    relayPublicKey: cap.relayPublicKey,
    physicalTopic: cap.physicalTopic,
    frameClass,
    frameHash,
    clientNonce
  })
  const signatureRequired = cap.appendAuthMode === INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED
  if (signatureRequired && (!source.writeCap || source.writeCap.appendPrivateKey == null)) {
    fail('BAD_CLIENT_INPUT', 'signed-append inbox requires its append capability')
  }
  const admissionValue = await admission(options, {
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.APPEND,
    requestCommitment,
    relayPublicKey: cap.relayPublicKey,
    frameClass
  }, true)
  const request = {
    version: 1,
    physicalTopic: cap.physicalTopic,
    frameClass,
    frameHash,
    clientNonce,
    appendSignature: signatureRequired
      ? signCapability(source.writeCap.appendPrivateKey, requestCommitment)
      : null,
    admission: admissionValue,
    frame
  }
  return result(inboxAppendV1, request, requestCommitment, OPERATION.INBOX.APPEND)
}

export async function createReadInboxRequest (options) {
  const cap = readCap(options)
  const cursor = options.cursor == null ? b4a.alloc(0) : b4a.from(asBytes(options.cursor, 'cursor'))
  if (cursor.byteLength > 128) fail('BAD_CLIENT_INPUT', 'cursor exceeds 128 bytes')
  const limit = options.limit == null ? 64 : integer(options.limit, 1, 64, 'limit')
  const clientNonce = nonce(options.runtime, options.clientNonce)
  const requestCommitment = inboxReadRequestCommitment({
    relayPublicKey: cap.relayPublicKey,
    physicalTopic: cap.physicalTopic,
    cursor,
    limit,
    clientNonce
  })
  const admissionValue = await admission(options, {
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.READ,
    requestCommitment,
    relayPublicKey: cap.relayPublicKey,
    limit
  }, false)
  const request = { version: 1, physicalTopic: cap.physicalTopic, cursor, limit, clientNonce, admission: admissionValue }
  return result(inboxReadV1, request, requestCommitment, OPERATION.INBOX.READ, expectedReadResultBytes(cap, limit))
}

export async function createWatchInboxRequest (options) {
  const cap = readCap(options)
  const afterRevision = u64(options.afterRevision, 'afterRevision')
  const limit = options.limit == null ? 64 : integer(options.limit, 1, 64, 'limit')
  const maxWaitMillis = integer(options.maxWaitMillis, 1, 30000, 'maxWaitMillis')
  const clientNonce = nonce(options.runtime, options.clientNonce)
  const requestCommitment = inboxWatchRequestCommitment({
    relayPublicKey: cap.relayPublicKey,
    physicalTopic: cap.physicalTopic,
    afterRevision,
    limit,
    maxWaitMillis,
    clientNonce
  })
  const admissionValue = await admission(options, {
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.WATCH,
    requestCommitment,
    relayPublicKey: cap.relayPublicKey,
    limit,
    maxWaitMillis
  }, true)
  const request = {
    version: 1,
    physicalTopic: cap.physicalTopic,
    afterRevision,
    limit,
    maxWaitMillis,
    clientNonce,
    admission: admissionValue
  }
  return result(inboxWatchV1, request, requestCommitment, OPERATION.INBOX.WATCH, expectedReadResultBytes(cap, limit))
}

export function destroyInboxWriteCapability (capability) {
  if (!capability || typeof capability !== 'object') return
  wipe(capability.createPrivateKey)
  wipe(capability.appendPrivateKey)
  wipe(capability.renewPrivateKey)
  wipe(capability.closePrivateKey)
}
