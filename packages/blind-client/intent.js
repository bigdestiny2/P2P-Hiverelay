import b4a from 'b4a'
import { isAdvertisedOperation } from '@hiverelay/blind-protocol/wire-runtime-authority'
import { asBytes, randomBytes, wipe } from './bytes.js'
import { fail } from './errors.js'

const MAGIC = b4a.from('HRINT1', 'ascii')
const VERSION = 1
const HEADER_BYTES = 264
const MAX_OPERATION_BYTES = 4 * 1024 * 1024
const MAX_RESULT_BYTES = 4 * 1024 * 1024
const MAX_U64 = (1n << 64n) - 1n
const INTENT_AAD_DOMAIN = b4a.from('hiverelay.blind.client-intent-aead.v1', 'ascii')

export const INTENT_STATE = Object.freeze({
  JOURNALED: 1,
  TARGET_PREPARED: 2,
  SENT: 3,
  ACKNOWLEDGED: 4,
  PENDING_UNKNOWN: 5,
  RESULT_VERIFIED: 6,
  RETRYABLE: 7,
  TERMINAL: 8
})

const ALLOWED_TRANSITIONS = new Map([
  [INTENT_STATE.JOURNALED, new Set([INTENT_STATE.TARGET_PREPARED, INTENT_STATE.TERMINAL])],
  [INTENT_STATE.TARGET_PREPARED, new Set([INTENT_STATE.SENT, INTENT_STATE.RETRYABLE, INTENT_STATE.TERMINAL])],
  [INTENT_STATE.SENT, new Set([INTENT_STATE.ACKNOWLEDGED, INTENT_STATE.PENDING_UNKNOWN,
    INTENT_STATE.RESULT_VERIFIED, INTENT_STATE.RETRYABLE, INTENT_STATE.TERMINAL])],
  [INTENT_STATE.ACKNOWLEDGED, new Set([INTENT_STATE.RESULT_VERIFIED, INTENT_STATE.PENDING_UNKNOWN])],
  [INTENT_STATE.PENDING_UNKNOWN, new Set([INTENT_STATE.TARGET_PREPARED, INTENT_STATE.RESULT_VERIFIED,
    INTENT_STATE.TERMINAL])],
  [INTENT_STATE.RESULT_VERIFIED, new Set([])],
  [INTENT_STATE.RETRYABLE, new Set([INTENT_STATE.TARGET_PREPARED, INTENT_STATE.TERMINAL])],
  [INTENT_STATE.TERMINAL, new Set([])]
])

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_CLIENT_INPUT', `${field} is outside u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail('BAD_CLIENT_INPUT', `${field} is outside u64`)
  return value
}

function writeU64 (output, offset, value) {
  value = u64(value, 'u64 value')
  for (let index = 7; index >= 0; index--) {
    output[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function readU64 (input, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(input[offset + index])
  return value
}

function writeU16 (output, offset, value) {
  output[offset] = (value >>> 8) & 0xff
  output[offset + 1] = value & 0xff
}

function readU16 (input, offset) {
  return input[offset] * 0x100 + input[offset + 1]
}

function nonzeroBytes (value, field, length = 32) {
  value = b4a.from(asBytes(value, field, length))
  if (value.every(byte => byte === 0)) fail('BAD_CLIENT_INPUT', `${field} must be nonzero`)
  return value
}

function boundedBytes (value, field, maximum, allowEmpty = false) {
  value = b4a.from(asBytes(value, field))
  if ((!allowEmpty && value.byteLength === 0) || value.byteLength > maximum) {
    fail('BAD_CLIENT_INPUT', `${field} is outside its byte bound`)
  }
  return value
}

function integer (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('BAD_CLIENT_INPUT', `${field} must be within ${minimum}..${maximum}`)
  }
  return value
}

function normalizedIntent (value) {
  if (!value || typeof value !== 'object') fail('BAD_CLIENT_INPUT', 'client intent must be an object')
  const state = integer(value.state, INTENT_STATE.JOURNALED, INTENT_STATE.TERMINAL, 'intent state')
  const operationBytes = boundedBytes(value.operationBytes, 'operationBytes', MAX_OPERATION_BYTES)
  const resultBytes = value.resultBytes == null
    ? null
    : boundedBytes(value.resultBytes, 'resultBytes', MAX_RESULT_BYTES, true)
  const mayHaveCommitted = value.mayHaveCommitted === true
  if (state === INTENT_STATE.JOURNALED && mayHaveCommitted) {
    fail('BAD_CLIENT_INPUT', 'newly journaled intent cannot be marked mayHaveCommitted')
  }
  if (state === INTENT_STATE.RESULT_VERIFIED && resultBytes == null) {
    fail('BAD_CLIENT_INPUT', 'verified intent requires exact result bytes')
  }
  if (state !== INTENT_STATE.RESULT_VERIFIED && resultBytes != null) {
    fail('BAD_CLIENT_INPUT', 'result bytes are persisted only after complete verification')
  }
  const transportSupportBit = integer(value.transportSupportBit, 1, 0xffff, 'transportSupportBit')
  const privacyProfileBit = integer(value.privacyProfileBit, 1, 0xffff, 'privacyProfileBit')
  if ((transportSupportBit & (transportSupportBit - 1)) !== 0 ||
      (privacyProfileBit & (privacyProfileBit - 1)) !== 0) {
    fail('BAD_CLIENT_INPUT', 'transport and privacy profiles must each contain one bit')
  }
  const familyId = integer(value.familyId, 1, 5, 'familyId')
  const operationId = integer(value.operationId, 1, 255, 'operationId')
  if (!isAdvertisedOperation(familyId, operationId)) {
    fail('BAD_CLIENT_INPUT', 'client intent operation is unknown or reserved by the active release profile')
  }
  return {
    version: VERSION,
    state,
    mayHaveCommitted,
    intentId: nonzeroBytes(value.intentId, 'intentId'),
    logicalId: nonzeroBytes(value.logicalId, 'logicalId'),
    continuityRoot: nonzeroBytes(value.continuityRoot, 'continuityRoot'),
    storeId: nonzeroBytes(value.storeId, 'storeId'),
    descriptorHash: nonzeroBytes(value.descriptorHash, 'descriptorHash'),
    descriptorSequence: u64(value.descriptorSequence, 'descriptorSequence'),
    endpointId: integer(value.endpointId, 1, 255, 'endpointId'),
    transportId: integer(value.transportId, 1, 255, 'transportId'),
    transportSupportBit,
    privacyProfileBit,
    familyId,
    operationId,
    requestCommitment: nonzeroBytes(value.requestCommitment, 'requestCommitment'),
    clientNonce: b4a.from(asBytes(value.clientNonce, 'clientNonce', 32)),
    operationBytes,
    resultBytes,
    attemptCount: integer(value.attemptCount == null ? 0 : value.attemptCount, 0, 0xffffffff, 'attemptCount'),
    lastErrorCode: integer(value.lastErrorCode == null ? 0 : value.lastErrorCode, 0, 255, 'lastErrorCode')
  }
}

function copyIntent (value) {
  return normalizedIntent(value)
}

export function encodeClientIntent (value) {
  value = normalizedIntent(value)
  const resultLength = value.resultBytes == null ? 0xffffffff : value.resultBytes.byteLength
  const output = b4a.alloc(HEADER_BYTES + value.operationBytes.byteLength + (value.resultBytes == null ? 0 : resultLength))
  b4a.copy(MAGIC, output, 0)
  output[6] = VERSION
  output[7] = value.state
  output[8] = value.mayHaveCommitted ? 1 : 0
  output[9] = value.familyId
  output[10] = value.operationId
  output[11] = value.endpointId
  output[12] = value.transportId
  writeU16(output, 13, value.transportSupportBit)
  writeU16(output, 15, value.privacyProfileBit)
  b4a.writeUInt32BE(output, value.attemptCount, 17)
  output[21] = value.lastErrorCode
  b4a.writeUInt32BE(output, value.operationBytes.byteLength, 22)
  b4a.writeUInt32BE(output, resultLength, 26)
  writeU64(output, 30, value.descriptorSequence)
  b4a.copy(value.intentId, output, 38)
  b4a.copy(value.logicalId, output, 70)
  b4a.copy(value.continuityRoot, output, 102)
  b4a.copy(value.storeId, output, 134)
  b4a.copy(value.descriptorHash, output, 166)
  b4a.copy(value.requestCommitment, output, 198)
  b4a.copy(value.clientNonce, output, 230)
  b4a.copy(value.operationBytes, output, HEADER_BYTES)
  if (value.resultBytes != null) b4a.copy(value.resultBytes, output, HEADER_BYTES + value.operationBytes.byteLength)
  return output
}

export function decodeClientIntent (input) {
  input = b4a.from(asBytes(input, 'encoded client intent'))
  if (input.byteLength < HEADER_BYTES || !b4a.equals(input.subarray(0, 6), MAGIC) || input[6] !== VERSION) {
    fail('INTENT_CORRUPT', 'client intent header is invalid')
  }
  if (input[8] > 1 || input[262] !== 0 || input[263] !== 0) {
    fail('INTENT_CORRUPT', 'client intent flags or reserved bytes are invalid')
  }
  const operationLength = b4a.readUInt32BE(input, 22)
  const encodedResultLength = b4a.readUInt32BE(input, 26)
  const resultLength = encodedResultLength === 0xffffffff ? 0 : encodedResultLength
  if (operationLength === 0 || operationLength > MAX_OPERATION_BYTES || resultLength > MAX_RESULT_BYTES ||
      input.byteLength !== HEADER_BYTES + operationLength + resultLength) {
    fail('INTENT_CORRUPT', 'client intent lengths are invalid')
  }
  return normalizedIntent({
    state: input[7],
    mayHaveCommitted: input[8] === 1,
    familyId: input[9],
    operationId: input[10],
    endpointId: input[11],
    transportId: input[12],
    transportSupportBit: readU16(input, 13),
    privacyProfileBit: readU16(input, 15),
    attemptCount: b4a.readUInt32BE(input, 17),
    lastErrorCode: input[21],
    descriptorSequence: readU64(input, 30),
    intentId: input.subarray(38, 70),
    logicalId: input.subarray(70, 102),
    continuityRoot: input.subarray(102, 134),
    storeId: input.subarray(134, 166),
    descriptorHash: input.subarray(166, 198),
    requestCommitment: input.subarray(198, 230),
    clientNonce: input.subarray(230, 262),
    operationBytes: input.subarray(HEADER_BYTES, HEADER_BYTES + operationLength),
    resultBytes: encodedResultLength === 0xffffffff ? null : input.subarray(HEADER_BYTES + operationLength)
  })
}

function assertTransition (before, after) {
  if (!sameIdentity(before, after)) fail('INTENT_TRANSITION_INVALID', 'immutable intent identity changed during CAS')
  if (before.state !== after.state && !ALLOWED_TRANSITIONS.get(before.state).has(after.state)) {
    fail('INTENT_TRANSITION_INVALID', 'intent state transition is not allowed')
  }
  if (after.attemptCount < before.attemptCount || after.attemptCount > before.attemptCount + 1) {
    fail('INTENT_TRANSITION_INVALID', 'intent attempt count must be monotonic and increment by at most one')
  }
  if (before.mayHaveCommitted && !after.mayHaveCommitted) {
    fail('INTENT_TRANSITION_INVALID', 'mayHaveCommitted cannot be cleared')
  }
}

function sameIdentity (left, right) {
  for (const field of [
    'intentId', 'logicalId', 'continuityRoot', 'storeId', 'descriptorHash', 'requestCommitment', 'clientNonce',
    'operationBytes'
  ]) if (!b4a.equals(left[field], right[field])) return false
  for (const field of [
    'descriptorSequence', 'endpointId', 'transportId', 'transportSupportBit', 'privacyProfileBit', 'familyId', 'operationId'
  ]) if (BigInt(left[field]) !== BigInt(right[field])) return false
  return true
}

function intentKey (intentId) {
  return `intent:${b4a.toString(asBytes(intentId, 'intentId', 32), 'hex')}`
}

function aad (intentId, revision) {
  const revisionBytes = b4a.alloc(8)
  writeU64(revisionBytes, 0, revision)
  return b4a.concat([INTENT_AAD_DOMAIN, asBytes(intentId, 'intentId', 32), revisionBytes])
}

export function createAesGcmIntentSealer (runtime, key) {
  key = b4a.from(asBytes(key, 'intent encryption key', 32))
  if (!runtime || typeof runtime.aes256GcmEncrypt !== 'function' || typeof runtime.aes256GcmDecrypt !== 'function') {
    fail('CRYPTO_UNAVAILABLE', 'intent sealer requires AES-256-GCM runtime methods')
  }
  return Object.freeze({
    async seal ({ intentId, revision, plaintext }) {
      const nonce = randomBytes(runtime, 12, 'intent encryption nonce')
      const sealed = await runtime.aes256GcmEncrypt({ key, nonce, aad: aad(intentId, revision), plaintext })
      return b4a.concat([nonce, b4a.from(sealed)])
    },
    async open ({ intentId, revision, ciphertext }) {
      ciphertext = asBytes(ciphertext, 'intent ciphertext')
      if (ciphertext.byteLength < 28) fail('INTENT_CORRUPT', 'intent ciphertext is truncated')
      try {
        return b4a.from(await runtime.aes256GcmDecrypt({
          key,
          nonce: ciphertext.subarray(0, 12),
          aad: aad(intentId, revision),
          sealed: ciphertext.subarray(12)
        }))
      } catch (error) {
        fail('INTENT_CORRUPT', 'intent ciphertext authentication failed', { cause: error })
      }
    }
  })
}

export class MemoryIntentBackend {
  constructor () {
    this.records = new Map()
  }

  async read (key) {
    const value = this.records.get(key)
    return value == null
      ? { revision: 0n, ciphertext: null }
      : { revision: value.revision, ciphertext: b4a.from(value.ciphertext) }
  }

  async compareAndSwap (key, expectedRevision, ciphertext) {
    const current = this.records.get(key)
    const revision = current == null ? 0n : current.revision
    if (revision !== BigInt(expectedRevision)) return false
    this.records.set(key, { revision: revision + 1n, ciphertext: b4a.from(ciphertext) })
    return true
  }

  async keys () {
    return [...this.records.keys()].sort()
  }
}

export class EncryptedIntentStore {
  constructor (options) {
    if (!options || !options.backend || !options.sealer ||
        typeof options.backend.read !== 'function' || typeof options.backend.compareAndSwap !== 'function' ||
        typeof options.sealer.seal !== 'function' || typeof options.sealer.open !== 'function') {
      fail('BAD_CLIENT_INPUT', 'encrypted intent store requires a CAS backend and authenticated sealer')
    }
    this.backend = options.backend
    this.sealer = options.sealer
  }

  async create (value) {
    const intent = normalizedIntent({
      ...value,
      state: INTENT_STATE.JOURNALED,
      mayHaveCommitted: false,
      attemptCount: 0,
      lastErrorCode: 0,
      resultBytes: null
    })
    const key = intentKey(intent.intentId)
    const plaintext = encodeClientIntent(intent)
    try {
      const ciphertext = await this.sealer.seal({ intentId: intent.intentId, revision: 1n, plaintext })
      if (!await this.backend.compareAndSwap(key, 0n, ciphertext)) fail('INTENT_CONFLICT', 'intent ID already exists')
      return copyIntent(intent)
    } finally {
      wipe(plaintext)
    }
  }

  async read (intentId) {
    const record = await this.backend.read(intentKey(intentId))
    if (record.ciphertext == null) return null
    const plaintext = await this.sealer.open({ intentId, revision: record.revision, ciphertext: record.ciphertext })
    try {
      const value = decodeClientIntent(plaintext)
      if (!b4a.equals(value.intentId, asBytes(intentId, 'intentId', 32))) fail('INTENT_CORRUPT', 'intent key/body mismatch')
      return { revision: record.revision, value }
    } finally {
      wipe(plaintext)
    }
  }

  async update (intentId, mutate) {
    if (typeof mutate !== 'function') fail('BAD_CLIENT_INPUT', 'intent CAS mutate callback is required')
    for (let attempt = 0; attempt < 8; attempt++) {
      const current = await this.read(intentId)
      if (current == null) fail('INTENT_NOT_FOUND', 'intent does not exist')
      const candidate = normalizedIntent(await mutate(copyIntent(current.value)))
      assertTransition(current.value, candidate)
      const plaintext = encodeClientIntent(candidate)
      try {
        const nextRevision = current.revision + 1n
        const ciphertext = await this.sealer.seal({ intentId, revision: nextRevision, plaintext })
        if (await this.backend.compareAndSwap(intentKey(intentId), current.revision, ciphertext)) {
          return { revision: nextRevision, value: copyIntent(candidate) }
        }
      } finally {
        wipe(plaintext)
      }
    }
    fail('INTENT_BUSY', 'intent CAS did not converge')
  }
}

export function createClientIntent (options) {
  return normalizedIntent({
    ...options,
    intentId: options.intentId == null ? randomBytes(options.runtime, 32, 'intentId') : options.intentId,
    state: INTENT_STATE.JOURNALED,
    mayHaveCommitted: false,
    attemptCount: 0,
    lastErrorCode: 0,
    resultBytes: null
  })
}

export async function journalSignedIntent (store, intent, options = {}) {
  if (!(store instanceof EncryptedIntentStore)) fail('BAD_CLIENT_INPUT', 'EncryptedIntentStore is required')
  const ephemeralSecrets = options.ephemeralSecrets || []
  if (!Array.isArray(ephemeralSecrets)) fail('BAD_CLIENT_INPUT', 'ephemeralSecrets must be an array')
  try {
    return await store.create(intent)
  } finally {
    for (const secret of ephemeralSecrets) wipe(secret)
  }
}
