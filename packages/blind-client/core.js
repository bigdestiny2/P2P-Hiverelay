import b4a from 'b4a'
import { FAMILY, OPERATION } from '@hiverelay/blind-protocol/wire-runtime-authority'
import {
  coreMirrorRequestCommitment,
  coreOpenReplicationRequestCommitment,
  coreServeRequestCommitment
} from '@hiverelay/blind-protocol/hashes'
import {
  coreMirrorRequestV1,
  coreOpenReplicationV1,
  coreServeChallengeV1
} from '@hiverelay/blind-protocol/schemas'
import { encodeCanonical } from '@hiverelay/blind-protocol/codec'
import { asBytes, randomBytes } from './bytes.js'
import { fail } from './errors.js'
import { resolveAdmission } from './provider.js'
import { selectedOperationProfile } from './selected-operation-profile.js'

const MAX_U64 = (1n << 64n) - 1n

function integer (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('BAD_CLIENT_INPUT', `${field} must be within ${minimum}..${maximum}`)
  }
  return value
}

function u64 (value, field, nonzero = false) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_CLIENT_INPUT', `${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64 || (nonzero && value === 0n)) {
    fail('BAD_CLIENT_INPUT', `${field} is outside its u64 bounds`)
  }
  return value
}

function fixed (value, length, field, nonzero = false) {
  const bytes = b4a.from(asBytes(value, field, length))
  if (nonzero && bytes.every(byte => byte === 0)) fail('BAD_CLIENT_INPUT', `${field} must be nonzero`)
  return bytes
}

function nonce (runtime, value) {
  return value == null ? randomBytes(runtime, 32, 'client nonce') : fixed(value, 32, 'clientNonce')
}

async function admission (options, context, required) {
  return resolveAdmission(options, context, required,
    'this operation requires an admission provider or admission value')
}

function result (encoding, request, requestCommitment, operationId, extra = {}) {
  const profile = selectedOperationProfile(FAMILY.CORE, operationId)
  return {
    request,
    requestBytes: encodeCanonical(encoding, request),
    requestCommitment,
    wire: Object.freeze({
      familyId: FAMILY.CORE,
      operationId,
      expectedResultBodyBytes: profile.maxResultBodyBytes,
      ...extra
    })
  }
}

function coreHead (options) {
  const relayPublicKey = fixed(options.relayPublicKey, 32, 'relayPublicKey', true)
  const corePublicKey = fixed(options.corePublicKey, 32, 'corePublicKey', true)
  const fork = u64(options.fork, 'fork')
  const length = u64(options.length, 'length', true)
  const signedHeadHash = fixed(options.signedHeadHash, 32, 'signedHeadHash', true)
  return { relayPublicKey, corePublicKey, fork, length, signedHeadHash }
}

export async function createCoreMirrorRequest (options) {
  if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'core mirror options are required')
  const head = coreHead(options)
  const leaseClass = integer(options.leaseClass, 1, 4, 'leaseClass')
  const clientNonce = nonce(options.runtime, options.clientNonce)
  const requestCommitment = coreMirrorRequestCommitment({ ...head, leaseClass, clientNonce })
  const admissionValue = await admission(options, {
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.MIRROR,
    requestCommitment,
    relayPublicKey: head.relayPublicKey,
    length: head.length,
    leaseClass
  }, true)
  const request = {
    version: 1,
    corePublicKey: head.corePublicKey,
    fork: head.fork,
    length: head.length,
    signedHeadHash: head.signedHeadHash,
    leaseClass,
    clientNonce,
    admission: admissionValue
  }
  return result(coreMirrorRequestV1, request, requestCommitment, OPERATION.CORE.MIRROR)
}

export async function createCoreProveRequest (options) {
  if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'core prove options are required')
  const head = coreHead(options)
  if (!Array.isArray(options.blockIndices) || options.blockIndices.length < 1 || options.blockIndices.length > 16) {
    fail('BAD_CLIENT_INPUT', 'blockIndices must contain 1..16 entries')
  }
  const blockIndices = options.blockIndices.map((value, index) => u64(value, `blockIndices[${index}]`))
  for (let index = 0; index < blockIndices.length; index++) {
    if (blockIndices[index] >= head.length || (index > 0 && blockIndices[index] <= blockIndices[index - 1])) {
      fail('BAD_CLIENT_INPUT', 'blockIndices must be strictly sorted, distinct, and below length')
    }
  }
  const clientNonce = nonce(options.runtime, options.clientNonce)
  const requestCommitment = coreServeRequestCommitment({ ...head, blockIndices, clientNonce })
  const admissionValue = await admission(options, {
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.PROVE,
    requestCommitment,
    relayPublicKey: head.relayPublicKey,
    blockCount: blockIndices.length
  }, false)
  const request = {
    version: 1,
    corePublicKey: head.corePublicKey,
    fork: head.fork,
    length: head.length,
    signedHeadHash: head.signedHeadHash,
    blockIndices,
    clientNonce,
    admission: admissionValue
  }
  return result(coreServeChallengeV1, request, requestCommitment, OPERATION.CORE.PROVE)
}

export async function createCoreOpenReplicationRequest (options) {
  if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'core open options are required')
  selectedOperationProfile(FAMILY.CORE, OPERATION.CORE.OPEN_REPLICATION)
  const relayPublicKey = fixed(options.relayPublicKey, 32, 'relayPublicKey', true)
  const wireProfileHash = fixed(options.wireProfileHash, 32, 'wireProfileHash', true)
  const sessionClass = integer(options.sessionClass, 1, 3, 'sessionClass')
  const controlChannelId = u64(options.controlChannelId, 'controlChannelId', true)
  const parentChannelBinding = fixed(options.parentChannelBinding, 32, 'parentChannelBinding', true)
  const clientNonce = nonce(options.runtime, options.clientNonce)
  const requestCommitment = coreOpenReplicationRequestCommitment({
    relayPublicKey,
    wireProfileHash,
    sessionClass,
    controlChannelId,
    parentChannelBinding,
    clientNonce
  })
  const admissionValue = await admission(options, {
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.OPEN_REPLICATION,
    requestCommitment,
    relayPublicKey,
    sessionClass,
    controlChannelId
  }, true)
  const request = {
    version: 1,
    wireProfileHash,
    sessionClass,
    controlChannelId,
    parentChannelBinding,
    clientNonce,
    admission: admissionValue
  }
  return result(coreOpenReplicationV1, request, requestCommitment, OPERATION.CORE.OPEN_REPLICATION, {
    requiresAuthenticatedStream: true,
    controlChannelId
  })
}
