import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE,
  CORE_ACK_RESULT,
  LEASE_CLASS_EPOCHS,
  RESULT_SIGNATURE_DOMAIN_ID,
  blake2b256,
  blindCoreAckV1,
  blindCoreOpenReplicationRetrySnapshotV1,
  boundedBytes,
  constant,
  coreMirrorRequestCommitment,
  coreMirrorRequestV1,
  coreOpenReplicationResultV1,
  coreServeChallengeV1,
  coreServeRequestCommitment,
  coreServeResultV1,
  decodeCanonical,
  encodeCanonical,
  fixedBytes,
  ranged,
  relayResultBindingV1,
  resultSignaturePayload,
  struct,
  u8,
  u16be,
  u32be,
  u64be
} from '@hiverelay/blind-protocol'
import {
  BLIND_STORE_SERVICE_TAG,
  BlindOpaqueBodyError,
  BlindTransactionStore,
  BlindWalIntegrityError
} from './transaction-store.js'

const MAX_U64 = (1n << 64n) - 1n
const MAX_U32 = 0xffffffff
const MAX_PROOF_BYTES = 4 * 1024 * 1024 - 256
const MAX_PROOF_PIN_MILLIS = 15n * 60n * 1000n
const CONTROL_RECORD_BYTES = 512
const PROOF_PIN_RECORD_BYTES = 1024
const SPEND_TOMBSTONE_BYTES = 256
const MEBIBYTE = 1024 * 1024

const MIRROR_TERMINAL_REASON = Object.freeze({
  INVALID_HEAD: 1,
  UPSTREAM_UNAVAILABLE: 2,
  SUPERSEDED: 3,
  CORPUS_INVALID: 4
})

const MIRROR_RETRY_REASON = Object.freeze({
  UPSTREAM_UNAVAILABLE: 1,
  STORAGE_INTERRUPTED: 2
})

export const BLIND_CORE_WAL_TYPE = Object.freeze({
  MIRROR_ACCEPTED: 64,
  MIRROR_ACTIVATED: 65,
  MIRROR_TERMINAL: 66,
  PROVE_PINNED: 67,
  PROVE_PIN_EXPIRED: 68,
  OPEN_STATE: 69,
  MIRROR_RETRY_PENDING: 70,
  CORE_EXPIRED: 71
})

export const BLIND_CORE_STORAGE_BLOCKERS = Object.freeze([
  'FINAL_STORE_FORMAT_AUTHORITY_UNPUBLISHED',
  'ALL_FAMILY_CHECKPOINT_AND_SHADOW_SEMANTIC_AUTHORITY_UNASSEMBLED',
  'PINNED_BLIND_PEER_HYPERCORE_INTEROP_UNPROVEN',
  'CORE_UPSTREAM_SIGNED_HEAD_PROOF_AUTHORITY_UNASSEMBLED',
  'SCALABLE_UPSTREAM_SEGMENTED_CORE_BLOCK_STORE_UNASSEMBLED',
  'CORE_SHARED_CLOCK_FLOOR_AUTHORITY_UNASSEMBLED',
  'CORE_BACKGROUND_ACTIVATION_RETRY_SCHEDULER_UNASSEMBLED',
  'CORE_CONTROL_RETENTION_HORIZON_COMPACTION_UNASSEMBLED',
  'DEDICATED_CORE_STORE_ALL_FAMILY_CHECKPOINT_MERGE_UNASSEMBLED',
  'CORE_LIVE_ORPHAN_SCRUB_ACCOUNTING_UNASSEMBLED',
  'PROFILE2_EXTERNAL_JOURNAL_WITNESS_UNASSEMBLED'
])

export const BLIND_CORE_STORAGE_STATUS = Object.freeze({
  family: 'CORE',
  mirrorAdmissionWalBound: true,
  exactMirrorRetryPersisted: true,
  sponsorshipCasPersisted: true,
  boundedImmutableOpaqueGenerationCorpusPersisted: true,
  proveSourcePinsPersisted: true,
  proveRetryExpiryPersisted: true,
  openLifecyclePersisted: true,
  recoveredOpenForcedTerminal: true,
  boundedActivationRetryState: true,
  sponsorshipExpiryGcPersisted: true,
  boundedAccounting: true,
  productionReady: false,
  blockers: BLIND_CORE_STORAGE_BLOCKERS
})

const version1 = constant(u8, 1, 'version')
const bytes32 = fixedBytes(32)
const preparedAdmissionStoreV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['profileId', ranged(u16be, 1, 0xffff, 'profileId')],
  ['schemeId', ranged(u16be, 1, 0xffff, 'schemeId')],
  ['parameterHash', bytes32],
  ['resourceClass', u16be],
  ['leaseClass', u8],
  ['costUnits', u64be],
  ['walCommitRecord', boundedBytes(1, 16384, 'walCommitRecord')]
], { name: 'BlindCorePreparedAdmissionStoreV1' })

const mirrorAcceptedV1 = struct([
  ['version', version1],
  ['preparedAdmissionBytes', boundedBytes(1, 17408, 'preparedAdmissionBytes')],
  ['requestBytes', boundedBytes(1, 16384, 'requestBytes')],
  ['resultBytes', boundedBytes(1, 16384, 'resultBytes')],
  ['acceptedAtEpoch', u32be],
  ['targetLeaseEpoch', u32be],
  ['candidateRevision', u64be]
], { name: 'BlindCoreMirrorAcceptedStoreV1' })

const mirrorActivatedV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['corePublicKey', bytes32],
  ['fork', u64be],
  ['length', u64be],
  ['signedHeadHash', bytes32],
  ['leaseEpoch', u32be],
  ['stateRevision', u64be],
  ['corpusVirtualBucket', u16be],
  ['corpusObjectId', bytes32],
  ['corpusByteLength', u32be],
  ['corpusHash', bytes32],
  ['activatedAtEpoch', u32be]
], { name: 'BlindCoreMirrorActivatedStoreV1' })

const mirrorTerminalV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['terminalReason', ranged(u8, 1, 4, 'terminalReason')],
  ['terminalAtEpoch', u32be]
], { name: 'BlindCoreMirrorTerminalStoreV1' })

const mirrorRetryPendingV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['retryCount', ranged(u8, 1, 3, 'retryCount')],
  ['retryReason', ranged(u8, 1, 2, 'retryReason')],
  ['recordedAtEpoch', u32be]
], { name: 'BlindCoreMirrorRetryPendingStoreV1' })

const coreExpiredV1 = struct([
  ['version', version1],
  ['corePublicKey', bytes32],
  ['stateRevision', u64be],
  ['leaseEpoch', u32be],
  ['corpusVirtualBucket', u16be],
  ['corpusObjectId', bytes32],
  ['corpusByteLength', u32be],
  ['corpusHash', bytes32],
  ['expiredAtEpoch', u32be]
], { name: 'BlindCoreExpiredStoreV1' })

const provePinV1 = struct([
  ['version', version1],
  ['preparedAdmissionBytes', boundedBytes(1, 17408, 'preparedAdmissionBytes')],
  ['requestBytes', boundedBytes(1, 16384, 'requestBytes')],
  ['acknowledgementBytes', boundedBytes(1, 16384, 'acknowledgementBytes')],
  ['proofByteLength', u32be],
  ['proofHash', bytes32],
  ['sourceStateRevision', u64be],
  ['sourceLeaseEpoch', u32be],
  ['sourceCorpusVirtualBucket', u16be],
  ['sourceCorpusObjectId', bytes32],
  ['sourceCorpusByteLength', u32be],
  ['sourceCorpusHash', bytes32],
  ['pinnedAtUnixMillis', u64be],
  ['expiresAtUnixMillis', u64be]
], { name: 'BlindCoreProvePinStoreV1' })

const provePinExpiredV1 = struct([
  ['version', version1],
  ['spendTag', bytes32],
  ['requestCommitment', bytes32],
  ['expiredAtUnixMillis', u64be]
], { name: 'BlindCoreProvePinExpiredStoreV1' })

const openStateV1 = struct([
  ['version', version1],
  ['preparedAdmissionBytes', boundedBytes(1, 17408, 'preparedAdmissionBytes')],
  ['snapshotBytes', boundedBytes(1, 32768, 'snapshotBytes')]
], { name: 'BlindCoreOpenStateStoreV1' })

const WAL_CODECS = new Map([
  [BLIND_CORE_WAL_TYPE.MIRROR_ACCEPTED, mirrorAcceptedV1],
  [BLIND_CORE_WAL_TYPE.MIRROR_ACTIVATED, mirrorActivatedV1],
  [BLIND_CORE_WAL_TYPE.MIRROR_TERMINAL, mirrorTerminalV1],
  [BLIND_CORE_WAL_TYPE.PROVE_PINNED, provePinV1],
  [BLIND_CORE_WAL_TYPE.PROVE_PIN_EXPIRED, provePinExpiredV1],
  [BLIND_CORE_WAL_TYPE.OPEN_STATE, openStateV1],
  [BLIND_CORE_WAL_TYPE.MIRROR_RETRY_PENDING, mirrorRetryPendingV1],
  [BLIND_CORE_WAL_TYPE.CORE_EXPIRED, coreExpiredV1]
])

function fail (code, message, extras = {}) {
  const error = new Error(message)
  error.code = code
  Object.assign(error, extras)
  throw error
}
function bytes (value, length, field, options = {}) {
  if (!value || typeof value.byteLength !== 'number') fail('BAD_ENCODING', `${field} must be bytes`)
  const output = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (length != null && output.byteLength !== length) fail('BAD_ENCODING', `${field} must be ${length} bytes`)
  if (options.nonzero === true && !nonzero(output)) fail('BAD_ENCODING', `${field} must be nonzero`)
  return output
}

function nonzero (value) {
  for (const byte of value) if (byte !== 0) return true
  return false
}

function same (left, right) {
  return Boolean(left && right && left.byteLength === right.byteLength && b4a.equals(left, right))
}

function hex (value) {
  return b4a.toString(value, 'hex')
}

function u32 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_U32) fail('INTERNAL', `${field} is outside u32`)
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') value = BigInt(value)
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail('INTERNAL', `${field} is outside u64`)
  return value
}

function coreLengthClass (value) {
  let units = (u64(value, 'coreBillableBytes') + BigInt(MEBIBYTE - 1)) / BigInt(MEBIBYTE)
  if (units === 0n) fail('RENEW_NOT_DUE', 'Core sponsorship has no billable advancement')
  let output = 1
  while (units > 1n) {
    units >>= 1n
    output++
  }
  if (output > 45) fail('TOO_LARGE', 'Core sponsorship exceeds the largest admission class')
  return output
}

function resultBand (value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 4 * MEBIBYTE) {
    fail('TOO_LARGE', 'Core proof result exceeds the frozen result cap')
  }
  if (value <= 4 * 1024) return 1
  if (value <= 16 * 1024) return 2
  if (value <= 64 * 1024) return 3
  if (value <= 256 * 1024) return 4
  if (value <= MEBIBYTE) return 5
  return 6
}

function compactLengthBytes (value) {
  if (value <= 0xfc) return 1
  if (value <= 0xffff) return 3
  return 5
}

function coreProofResultByteLength (acknowledgementBytes, proofByteLength) {
  return 1 + acknowledgementBytes.byteLength + compactLengthBytes(proofByteLength) + proofByteLength
}

function canonical (codec, value, field) {
  try {
    if (value && typeof value.byteLength === 'number') {
      const input = b4a.from(value)
      const decoded = decodeCanonical(codec, input, { copyBytes: true })
      if (!same(input, encodeCanonical(codec, decoded))) throw new Error('non-canonical')
      return { value: decoded, bytes: input }
    }
    const encoded = encodeCanonical(codec, value)
    return { value: decodeCanonical(codec, encoded, { copyBytes: true }), bytes: encoded }
  } catch (error) {
    fail('BAD_ENCODING', `${field} is not canonical: ${error.message}`)
  }
}

function preparedAdmission (value, requestCommitment) {
  if (!value || typeof value !== 'object') fail('SPEND_INVALID', 'prepared admission is required')
  const normalized = {
    version: 1,
    spendTag: b4a.from(bytes(value.spendTag, 32, 'spendTag', { nonzero: true })),
    requestCommitment: b4a.from(bytes(value.requestCommitment, 32, 'prepared requestCommitment')),
    profileId: value.profileId,
    schemeId: value.schemeId,
    parameterHash: b4a.from(bytes(value.parameterHash, 32, 'parameterHash', { nonzero: true })),
    resourceClass: value.costClass && value.costClass.resourceClass,
    leaseClass: value.costClass && value.costClass.leaseClass,
    costUnits: value.costClass && u64(value.costClass.costUnits, 'costUnits'),
    walCommitRecord: b4a.from(bytes(value.walCommitRecord, null, 'walCommitRecord'))
  }
  if (!same(normalized.requestCommitment, requestCommitment)) {
    fail('SPEND_INVALID', 'prepared admission binds another request commitment')
  }
  if (normalized.costUnits === 0n) fail('SPEND_INVALID', 'prepared admission costUnits must be nonzero')
  return canonical(preparedAdmissionStoreV1, normalized, 'prepared admission')
}

function relayBindingBytes (value) {
  return canonical(relayResultBindingV1, value, 'relay result binding').bytes
}

function ackFromBytes (input) {
  return canonical(blindCoreAckV1, input, 'Blind Core acknowledgement')
}

function verifySignedValue (codec, value, domainId, publicKey) {
  try {
    const complete = encodeCanonical(codec, value)
    if (!value.signature || value.signature.byteLength !== sodium.crypto_sign_BYTES ||
        complete.byteLength <= sodium.crypto_sign_BYTES) return false
    const unsigned = complete.subarray(0, complete.byteLength - sodium.crypto_sign_BYTES)
    return sodium.crypto_sign_verify_detached(
      value.signature,
      resultSignaturePayload(domainId, unsigned),
      publicKey
    )
  } catch {
    return false
  }
}

function cloneReference (value) {
  return Object.freeze({
    virtualBucket: value.virtualBucket,
    objectId: b4a.from(value.objectId),
    byteLength: value.byteLength,
    hash: b4a.from(value.hash)
  })
}

function generationView (record) {
  if (!record) return null
  return Object.freeze({
    corePublicKey: b4a.from(record.corePublicKey),
    fork: record.fork,
    length: record.length,
    signedHeadHash: b4a.from(record.signedHeadHash),
    leaseEpoch: record.leaseEpoch,
    stateRevision: record.stateRevision,
    corpus: cloneReference(record.corpus),
    activatedAtEpoch: record.activatedAtEpoch
  })
}

function mirrorAttemptView (record, replay = false) {
  return Object.freeze({
    replay,
    state: record.state,
    resultBytes: b4a.from(record.resultBytes),
    requestCommitment: b4a.from(record.requestCommitment),
    spendTag: b4a.from(record.spendTag),
    targetLeaseEpoch: record.targetLeaseEpoch,
    candidateRevision: record.candidateRevision,
    retryCount: record.retryCount,
    terminalReason: record.terminalReason == null ? null : record.terminalReason
  })
}

function proofResult (acknowledgementBytes, proofsAndBlocks) {
  return encodeCanonical(coreServeResultV1, {
    version: 1,
    acknowledgement: decodeCanonical(blindCoreAckV1, acknowledgementBytes, { copyBytes: true }),
    proofsAndBlocks: b4a.from(proofsAndBlocks)
  })
}

function sourceOf (value) {
  if (value && typeof value[Symbol.asyncIterator] === 'function') return value
  if (value && typeof value[Symbol.iterator] === 'function' && typeof value !== 'string' &&
      typeof value.byteLength !== 'number') return value
  return b4a.from(bytes(value, null, 'opaque encrypted Core corpus'))
}

export class BlindCoreStorageEngine {
  constructor (options = {}) {
    if (options.transactionStore != null) {
      throw new TypeError('CORE uses a dedicated transaction store until all-family object GC is composed')
    }
    this.relayPublicKey = b4a.from(bytes(options.relayPublicKey, 32, 'relayPublicKey', { nonzero: true }))
    if (typeof options.nowEpoch !== 'function' || typeof options.nowUnixMillis !== 'function') {
      throw new TypeError('nowEpoch and nowUnixMillis hooks are required')
    }
    this.nowEpoch = options.nowEpoch
    this.nowUnixMillis = options.nowUnixMillis
    this.maximumSponsoredCoreLength = u64(options.maximumSponsoredCoreLength == null
      ? 1_000_000_000n
      : options.maximumSponsoredCoreLength, 'maximumSponsoredCoreLength')
    this.maximumCorpusBytes = options.maximumCorpusBytes == null ? 4 * 1024 * 1024 : options.maximumCorpusBytes
    this.maximumCores = options.maximumCores == null ? 4096 : options.maximumCores
    this.maximumProofPins = options.maximumProofPins == null ? 4096 : options.maximumProofPins
    this.maximumSpendRecords = options.maximumSpendRecords == null ? 65536 : options.maximumSpendRecords
    for (const [field, value, maximum] of [
      ['maximumCorpusBytes', this.maximumCorpusBytes, 64 * 1024 * 1024],
      ['maximumCores', this.maximumCores, 1_000_000],
      ['maximumProofPins', this.maximumProofPins, 1_000_000],
      ['maximumSpendRecords', this.maximumSpendRecords, 1_000_000]
    ]) {
      if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new TypeError(`${field} is out of bounds`)
    }
    this.transactionStore = new BlindTransactionStore({
      root: options.root,
      partitionKey: options.partitionKey,
      ownerFenceTokenHash: options.ownerFenceTokenHash,
      durabilityContinuityHash: options.durabilityContinuityHash,
      maximumWalPayloadBytes: Math.max(1024 * 1024, options.maximumWalPayloadBytes || 1024 * 1024),
      maximumOpaqueBodyBytes: this.maximumCorpusBytes,
      maximumChunkBytes: Math.min(this.maximumCorpusBytes, options.maximumChunkBytes || 256 * 1024),
      faultInjector: options.faultInjector
    })
    this.ownsTransactionStore = true
    this.spends = new Map()
    this.mirrorAttempts = new Map()
    this.activeCores = new Map()
    this.coreFloors = new Map()
    this.proofPins = new Map()
    this.openRecords = new Map()
    this.openSpendIndex = new Map()
    this.opened = false
    this.accounting = {
      corpusBytes: 0,
      controlBytes: 0,
      proofPinBytes: 0,
      mirrorAttempts: 0,
      activeCores: 0,
      proofPins: 0,
      proofSpendTombstones: 0,
      tombstoneBytes: 0,
      openRecords: 0,
      walSequence: 0n
    }
  }

  async open () {
    if (this.opened) throw new Error('Blind Core storage engine is already open')
    await this.transactionStore.open(frame => this.#applyFrame(frame, true))
    this.opened = true
    try {
      await this.#terminalizeRecoveredOpens()
      await this.sweepProofPins()
      await this.sweepExpiredCores()
      const liveReferences = new Set()
      for (const core of this.activeCores.values()) {
        liveReferences.add(this.transactionStore.referenceKey(core.corpus))
        const inspected = await this.transactionStore.inspectOpaque(
          core.corpus,
          core.corpus.byteLength,
          core.corpus.hash
        )
        if (!inspected.ok) throw new BlindWalIntegrityError(`Core corpus integrity failure: ${inspected.reason}`)
      }
      for (const pin of this.proofPins.values()) {
        liveReferences.add(this.transactionStore.referenceKey(pin.sourceCorpus))
        const inspected = await this.transactionStore.inspectOpaque(
          pin.sourceCorpus,
          pin.sourceCorpus.byteLength,
          pin.sourceCorpus.hash
        )
        if (!inspected.ok) throw new BlindWalIntegrityError(`pinned Core corpus integrity failure: ${inspected.reason}`)
      }
      await this.transactionStore.cleanupOrphans(liveReferences)
      return this
    } catch (error) {
      await this.close().catch(() => {})
      throw error
    }
  }

  async close () {
    if (!this.opened) return
    this.opened = false
    if (this.ownsTransactionStore) await this.transactionStore.close()
  }

  status () {
    return Object.freeze({
      ...BLIND_CORE_STORAGE_STATUS,
      accounting: Object.freeze({ ...this.accounting })
    })
  }

  inspectCore (corePublicKey) {
    corePublicKey = bytes(corePublicKey, 32, 'corePublicKey', { nonzero: true })
    return generationView(this.activeCores.get(hex(corePublicKey)))
  }

  inspectCoreFloor (corePublicKey) {
    corePublicKey = bytes(corePublicKey, 32, 'corePublicKey', { nonzero: true })
    const key = hex(corePublicKey)
    const floor = this.coreFloors.get(key)
    if (!floor) return null
    const active = this.activeCores.get(key)
    return Object.freeze({
      corePublicKey: b4a.from(floor.corePublicKey),
      fork: floor.fork,
      length: floor.length,
      signedHeadHash: b4a.from(floor.signedHeadHash),
      leaseEpoch: floor.leaseEpoch,
      stateRevision: floor.stateRevision,
      active: active === floor,
      corpus: active === floor ? cloneReference(floor.corpus) : null
    })
  }

  inspectProofSource (request) {
    request = canonical(coreServeChallengeV1, request, 'Core prove request').value
    const active = this.activeCores.get(hex(request.corePublicKey))
    this.#assertServeGeneration(active, request)
    return generationView(active)
  }

  mirrorBillableBytes (request) {
    request = canonical(coreMirrorRequestV1, request, 'Core mirror request').value
    const current = this.coreFloors.get(hex(request.corePublicKey))
    const pending = this.#highestPendingCandidate(request.corePublicKey)
    const floor = pending == null
      ? current
      : {
          fork: pending.request.fork,
          length: pending.request.length,
          signedHeadHash: pending.request.signedHeadHash,
          leaseEpoch: pending.targetLeaseEpoch,
          stateRevision: pending.candidateRevision
        }
    this.#validateCandidateOrder(floor, request)
    if (!floor || request.fork > floor.fork) return request.length
    const now = u32(this.nowEpoch(), 'nowEpoch')
    const target = Math.max(floor.leaseEpoch, now + LEASE_CLASS_EPOCHS[request.leaseClass])
    if (target > floor.leaseEpoch) return request.length
    if (request.length > floor.length) return request.length - floor.length
    fail('RENEW_NOT_DUE', 'Core sponsorship does not advance head, length, fork, or lease', {
      retryAfterEpoch: floor.leaseEpoch - LEASE_CLASS_EPOCHS[request.leaseClass]
    })
  }

  inspectMirrorSpend (spendTag) {
    const attempt = this.mirrorAttempts.get(hex(bytes(spendTag, 32, 'spendTag')))
    return attempt ? mirrorAttemptView(attempt, true) : null
  }

  inspectOpenRecords () {
    return Object.freeze([...this.openRecords.values()].map(record => Object.freeze({
      ...record,
      logicalRetryKey: b4a.from(record.logicalRetryKey),
      spendTag: b4a.from(record.spendTag),
      requestCommitment: b4a.from(record.requestCommitment),
      wireProfileHash: b4a.from(record.wireProfileHash),
      clientNonce: b4a.from(record.clientNonce),
      parentSessionId: b4a.from(record.parentSessionId),
      parentChannelBinding: b4a.from(record.parentChannelBinding),
      resultBytes: record.resultBytes == null ? null : b4a.from(record.resultBytes),
      terminalReason: record.terminalReason == null ? null : b4a.from(record.terminalReason),
      preparedAdmissionBytes: b4a.from(record.preparedAdmissionBytes)
    })))
  }

  async mirrorState (input) {
    const request = canonical(coreMirrorRequestV1, input.request, 'Core mirror request').value
    const requestCommitment = coreMirrorRequestCommitment({
      ...request,
      relayPublicKey: this.relayPublicKey
    })
    if (!same(requestCommitment, input.requestCommitment)) fail('INTERNAL', 'Core mirror request commitment mismatch')
    const admission = preparedAdmission(input.preparedAdmission, requestCommitment)
    if (admission.value.leaseClass !== request.leaseClass ||
        admission.value.resourceClass < 1 || admission.value.resourceClass > 45) {
      fail('SPEND_INVALID', 'Core mirror prepared cost class is invalid')
    }
    const spend = this.spends.get(hex(admission.value.spendTag))
    if (!spend) return Object.freeze({ kind: 'fresh' })
    if (!same(spend.requestCommitment, requestCommitment) || spend.operation !== 'MIRROR') {
      return Object.freeze({ kind: 'conflict' })
    }
    const attempt = this.mirrorAttempts.get(hex(admission.value.spendTag))
    return Object.freeze({ kind: 'replay', attempt: mirrorAttemptView(attempt, true) })
  }

  async acceptMirror (input) {
    const requestAuthority = canonical(coreMirrorRequestV1, input.request, 'Core mirror request')
    const request = requestAuthority.value
    const commitment = coreMirrorRequestCommitment({ ...request, relayPublicKey: this.relayPublicKey })
    if (!same(commitment, input.requestCommitment)) fail('INTERNAL', 'Core mirror request commitment mismatch')
    const admission = preparedAdmission(input.preparedAdmission, commitment)
    if (admission.value.leaseClass !== request.leaseClass ||
        admission.value.resourceClass < 1 || admission.value.resourceClass > 45) {
      fail('SPEND_INVALID', 'Core mirror prepared cost class is invalid')
    }
    const spendKey = hex(admission.value.spendTag)
    const coreKey = hex(request.corePublicKey)
    return this.transactionStore.withLocks([`core:${coreKey}`, `spend:${spendKey}`], async () => {
      const priorSpend = this.spends.get(spendKey)
      if (priorSpend) {
        if (priorSpend.operation !== 'MIRROR' || !same(priorSpend.requestCommitment, commitment)) {
          fail('SPEND_REPLAY', 'Core admission spend is already bound to another request')
        }
        return mirrorAttemptView(this.mirrorAttempts.get(spendKey), true)
      }
      if (admission.value.resourceClass !== coreLengthClass(this.mirrorBillableBytes(request))) {
        fail('SPEND_INVALID', 'Core mirror prepared resource class does not match billable length')
      }
      if (this.spends.size >= this.maximumSpendRecords) fail('BUSY', 'Core spend-record capacity is exhausted')
      const current = this.coreFloors.get(coreKey) || null
      const pending = this.#highestPendingCandidate(request.corePublicKey)
      const candidateFloor = pending == null
        ? current
        : {
            fork: pending.request.fork,
            length: pending.request.length,
            signedHeadHash: pending.request.signedHeadHash,
            leaseEpoch: pending.targetLeaseEpoch,
            stateRevision: pending.candidateRevision
          }
      const now = u32(this.nowEpoch(), 'nowEpoch')
      this.#validateCandidateOrder(candidateFloor, request)
      const targetLeaseEpoch = Math.max(candidateFloor ? candidateFloor.leaseEpoch : 0,
        now + LEASE_CLASS_EPOCHS[request.leaseClass])
      if (targetLeaseEpoch > MAX_U32) fail('BAD_ENCODING', 'Core mirror target lease overflows u32')
      const generationChanged = !candidateFloor || candidateFloor.fork !== request.fork ||
        candidateFloor.length !== request.length ||
        !same(candidateFloor.signedHeadHash, request.signedHeadHash)
      if (!generationChanged && targetLeaseEpoch === candidateFloor.leaseEpoch) {
        fail('RENEW_NOT_DUE', 'Core sponsorship does not advance head, length, fork, or lease', {
          retryAfterEpoch: candidateFloor.leaseEpoch - LEASE_CLASS_EPOCHS[request.leaseClass]
        })
      }
      if (this.mirrorAttempts.size >= this.maximumCores * 8) fail('BUSY', 'Core mirror retry capacity is exhausted')
      if (!current && this.coreFloors.size >= this.maximumCores) fail('BUSY', 'Core identity-floor capacity is exhausted')
      if (!this.activeCores.has(coreKey) && this.activeCores.size >= this.maximumCores) {
        fail('BUSY', 'Core capacity is exhausted')
      }
      const candidateRevision = candidateFloor ? candidateFloor.stateRevision + 1n : 0n
      const resultBinding = relayBindingBytes(input.resultBinding)
      if (typeof input.buildAcknowledgement !== 'function') fail('INTERNAL', 'Core acknowledgement builder is unavailable')
      const resultAuthority = ackFromBytes(await input.buildAcknowledgement({
        request,
        requestCommitment: b4a.from(commitment),
        relayBinding: decodeCanonical(relayResultBindingV1, resultBinding, { copyBytes: true }),
        observedAtEpoch: now,
        leaseEpoch: targetLeaseEpoch,
        result: CORE_ACK_RESULT.MIRROR_ACCEPTED,
        signal: input.signal
      }))
      this.#validateAck(resultAuthority.value, request, commitment, targetLeaseEpoch,
        now, CORE_ACK_RESULT.MIRROR_ACCEPTED)
      const value = {
        version: 1,
        preparedAdmissionBytes: admission.bytes,
        requestBytes: requestAuthority.bytes,
        resultBytes: resultAuthority.bytes,
        acceptedAtEpoch: now,
        targetLeaseEpoch,
        candidateRevision
      }
      await this.#appendAndApply(BLIND_CORE_WAL_TYPE.MIRROR_ACCEPTED,
        this.transactionStore.newTransactionId(),
        this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CORE, request.corePublicKey),
        value)
      return mirrorAttemptView(this.mirrorAttempts.get(spendKey))
    })
  }

  async completeMirror (spendTag, activation, options = {}) {
    spendTag = b4a.from(bytes(spendTag, 32, 'spendTag', { nonzero: true }))
    const spendKey = hex(spendTag)
    const attempt = this.mirrorAttempts.get(spendKey)
    if (!attempt) fail('NOT_FOUND', 'Core mirror attempt is unavailable')
    if (attempt.state === 'ACTIVE' || attempt.state === 'TERMINAL') return mirrorAttemptView(attempt, true)
    if (!activation || activation.verified !== true) {
      return activation && activation.unavailable
        ? this.#retryMirrorAttempt(attempt, MIRROR_RETRY_REASON.UPSTREAM_UNAVAILABLE)
        : this.#terminalMirrorAttempt(attempt, MIRROR_TERMINAL_REASON.INVALID_HEAD)
    }
    const coreKey = hex(attempt.request.corePublicKey)
    const activeAtStart = this.activeCores.get(coreKey)
    if (activeAtStart && activeAtStart.fork === attempt.request.fork &&
        activeAtStart.length === attempt.request.length &&
        same(activeAtStart.signedHeadHash, attempt.request.signedHeadHash) &&
        activation.reuseActive === true) {
      return this.transactionStore.withLocks([`core:${coreKey}`, `spend:${spendKey}`], async () => {
        const currentAttempt = this.mirrorAttempts.get(spendKey)
        const active = this.activeCores.get(coreKey)
        if (!currentAttempt || (currentAttempt.state !== 'ACCEPTED' &&
            currentAttempt.state !== 'RETRY_PENDING')) return mirrorAttemptView(currentAttempt, true)
        if (this.#hasHigherPendingCandidate(currentAttempt)) {
          await this.#appendMirrorTerminalLocked(currentAttempt, MIRROR_TERMINAL_REASON.SUPERSEDED)
          return mirrorAttemptView(currentAttempt)
        }
        if (!active || active.fork !== currentAttempt.request.fork ||
            active.length !== currentAttempt.request.length ||
            !same(active.signedHeadHash, currentAttempt.request.signedHeadHash)) {
          await this.#appendMirrorTerminalLocked(currentAttempt, MIRROR_TERMINAL_REASON.SUPERSEDED)
          return mirrorAttemptView(currentAttempt)
        }
        await this.#appendAndApply(BLIND_CORE_WAL_TYPE.MIRROR_ACTIVATED,
          this.transactionStore.newTransactionId(), active.corpus.virtualBucket, {
            version: 1,
            spendTag,
            corePublicKey: b4a.from(currentAttempt.request.corePublicKey),
            fork: currentAttempt.request.fork,
            length: currentAttempt.request.length,
            signedHeadHash: b4a.from(currentAttempt.request.signedHeadHash),
            leaseEpoch: currentAttempt.targetLeaseEpoch,
            stateRevision: active.stateRevision + 1n,
            corpusVirtualBucket: active.corpus.virtualBucket,
            corpusObjectId: b4a.from(active.corpus.objectId),
            corpusByteLength: active.corpus.byteLength,
            corpusHash: b4a.from(active.corpus.hash),
            activatedAtEpoch: u32(this.nowEpoch(), 'nowEpoch')
          })
        return mirrorAttemptView(currentAttempt)
      })
    }
    const corpus = sourceOf(activation.corpus)
    const corpusByteLength = activation.corpusByteLength == null
      ? (corpus.byteLength == null ? null : corpus.byteLength)
      : activation.corpusByteLength
    if (!Number.isSafeInteger(corpusByteLength) || corpusByteLength < 1 || corpusByteLength > this.maximumCorpusBytes) {
      return this.#terminalMirrorAttempt(attempt, MIRROR_TERMINAL_REASON.CORPUS_INVALID)
    }
    let corpusHash
    try {
      corpusHash = b4a.from(bytes(activation.corpusHash, 32, 'corpusHash', { nonzero: true }))
    } catch {
      return this.#terminalMirrorAttempt(attempt, MIRROR_TERMINAL_REASON.CORPUS_INVALID)
    }
    const deadlineUnixMillis = u64(options.deadlineUnixMillis == null
      ? u64(this.nowUnixMillis(), 'nowUnixMillis') + MAX_PROOF_PIN_MILLIS
      : options.deadlineUnixMillis, 'deadlineUnixMillis')
    let staged
    let published
    try {
      staged = await this.transactionStore.stageOpaque({
        expectedLength: corpusByteLength,
        expectedHash: corpusHash,
        source: corpus,
        deadlineUnixMillis,
        nowUnixMillis: this.nowUnixMillis,
        signal: options.signal
      })
      published = await this.transactionStore.publishOpaque(staged,
        this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CORE, attempt.request.corePublicKey))
    } catch (error) {
      if (staged) await this.transactionStore.discardStaged(staged).catch(() => {})
      return error instanceof BlindOpaqueBodyError && error.terminal
        ? this.#terminalMirrorAttempt(attempt, MIRROR_TERMINAL_REASON.CORPUS_INVALID)
        : this.#retryMirrorAttempt(attempt, MIRROR_RETRY_REASON.STORAGE_INTERRUPTED)
    }
    return this.transactionStore.withLocks([`core:${coreKey}`, `spend:${spendKey}`], async () => {
      const currentAttempt = this.mirrorAttempts.get(spendKey)
      if (!currentAttempt || (currentAttempt.state !== 'ACCEPTED' &&
          currentAttempt.state !== 'RETRY_PENDING')) {
        await this.transactionStore.removeOpaque(published)
        return mirrorAttemptView(currentAttempt, true)
      }
      const active = this.activeCores.get(coreKey)
      const floor = this.coreFloors.get(coreKey)
      if (this.#hasHigherPendingCandidate(currentAttempt)) {
        await this.transactionStore.removeOpaque(published)
        await this.#appendMirrorTerminalLocked(currentAttempt, MIRROR_TERMINAL_REASON.SUPERSEDED)
        return mirrorAttemptView(currentAttempt)
      }
      try {
        this.#validateCandidateOrder(floor, currentAttempt.request)
      } catch (error) {
        await this.transactionStore.removeOpaque(published)
        if (error.code === 'STALE_REVISION' || error.code === 'CONFLICT') {
          await this.#appendMirrorTerminalLocked(currentAttempt, MIRROR_TERMINAL_REASON.SUPERSEDED)
          return mirrorAttemptView(currentAttempt)
        }
        throw error
      }
      const now = u32(this.nowEpoch(), 'nowEpoch')
      await this.#appendAndApply(BLIND_CORE_WAL_TYPE.MIRROR_ACTIVATED,
        this.transactionStore.newTransactionId(), published.virtualBucket, {
          version: 1,
          spendTag,
          corePublicKey: b4a.from(currentAttempt.request.corePublicKey),
          fork: currentAttempt.request.fork,
          length: currentAttempt.request.length,
          signedHeadHash: b4a.from(currentAttempt.request.signedHeadHash),
          leaseEpoch: currentAttempt.targetLeaseEpoch,
          stateRevision: floor ? floor.stateRevision + 1n : 0n,
          corpusVirtualBucket: published.virtualBucket,
          corpusObjectId: b4a.from(published.objectId),
          corpusByteLength: published.byteLength,
          corpusHash: b4a.from(published.hash),
          activatedAtEpoch: now
        })
      if (active && !this.#corpusPinned(active.corpus)) {
        await this.transactionStore.removeOpaque(active.corpus)
      }
      return mirrorAttemptView(this.mirrorAttempts.get(spendKey))
    })
  }

  async serveProof (input) {
    const requestAuthority = canonical(coreServeChallengeV1, input.request, 'Core prove request')
    const request = requestAuthority.value
    const commitment = coreServeRequestCommitment({ ...request, relayPublicKey: this.relayPublicKey })
    if (!same(commitment, input.requestCommitment)) fail('INTERNAL', 'Core prove request commitment mismatch')
    const admission = input.preparedAdmission == null ? null : preparedAdmission(input.preparedAdmission, commitment)
    if (admission && (admission.value.leaseClass !== 0 || admission.value.resourceClass < 1 ||
        admission.value.resourceClass > 6)) {
      fail('SPEND_INVALID', 'Core proof prepared cost class is invalid')
    }
    if (admission) {
      const replay = await this.#proofReplay(admission.value.spendTag, commitment, request, input)
      if (replay) return replay
      if (this.proofPins.size >= this.maximumProofPins) fail('BUSY', 'Core proof retry-pin capacity is exhausted')
      if (this.spends.size >= this.maximumSpendRecords) fail('BUSY', 'Core spend-record capacity is exhausted')
    }
    const active = this.activeCores.get(hex(request.corePublicKey))
    this.#assertServeGeneration(active, request)
    const proofBytes = await this.#materializeProof(active, request, input)
    const observedAtEpoch = u32(this.nowEpoch(), 'nowEpoch')
    const resultBinding = relayBindingBytes(input.resultBinding)
    if (typeof input.buildAcknowledgement !== 'function') fail('INTERNAL', 'Core acknowledgement builder is unavailable')
    const ack = ackFromBytes(await input.buildAcknowledgement({
      request,
      requestCommitment: b4a.from(commitment),
      relayBinding: decodeCanonical(relayResultBindingV1, resultBinding, { copyBytes: true }),
      observedAtEpoch,
      leaseEpoch: active.leaseEpoch,
      result: CORE_ACK_RESULT.RECENTLY_SERVED,
      signal: input.signal
    }))
    this.#validateAck(ack.value, request, commitment, active.leaseEpoch,
      observedAtEpoch, CORE_ACK_RESULT.RECENTLY_SERVED)
    const completeResult = proofResult(ack.bytes, proofBytes)
    if (!admission) return Object.freeze({ body: completeResult, replay: false })

    const spendKey = hex(admission.value.spendTag)
    return this.transactionStore.withLocks([`proof:${spendKey}`, `core:${hex(request.corePublicKey)}`], async () => {
      const prior = this.spends.get(spendKey)
      if (prior) {
        if (prior.operation !== 'PROVE' || !same(prior.requestCommitment, commitment)) {
          fail('SPEND_REPLAY', 'Core proof spend is already bound to another request')
        }
        return this.#proofReplay(admission.value.spendTag, commitment, request, input, true)
      }
      if (this.spends.size >= this.maximumSpendRecords) fail('BUSY', 'Core spend-record capacity is exhausted')
      if (admission.value.resourceClass !== resultBand(completeResult.byteLength)) {
        fail('SPEND_INVALID', 'Core proof prepared resource class does not match its canonical result band')
      }
      const currentSource = this.activeCores.get(hex(request.corePublicKey))
      if (currentSource !== active || currentSource.stateRevision !== active.stateRevision ||
          !this.#sameCorpus(currentSource.corpus, active.corpus)) {
        fail('STALE_REVISION', 'Core proof source changed before its retry pin committed')
      }
      const now = u64(this.nowUnixMillis(), 'nowUnixMillis')
      const proofHash = blake2b256(proofBytes)
      await this.#appendAndApply(BLIND_CORE_WAL_TYPE.PROVE_PINNED,
        this.transactionStore.newTransactionId(),
        this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CORE, request.corePublicKey), {
          version: 1,
          preparedAdmissionBytes: admission.bytes,
          requestBytes: requestAuthority.bytes,
          acknowledgementBytes: ack.bytes,
          proofByteLength: proofBytes.byteLength,
          proofHash,
          sourceStateRevision: active.stateRevision,
          sourceLeaseEpoch: active.leaseEpoch,
          sourceCorpusVirtualBucket: active.corpus.virtualBucket,
          sourceCorpusObjectId: b4a.from(active.corpus.objectId),
          sourceCorpusByteLength: active.corpus.byteLength,
          sourceCorpusHash: b4a.from(active.corpus.hash),
          pinnedAtUnixMillis: now,
          expiresAtUnixMillis: now + MAX_PROOF_PIN_MILLIS
        })
      return Object.freeze({ body: completeResult, replay: false })
    })
  }

  async proveState (input) {
    const request = canonical(coreServeChallengeV1, input.request, 'Core prove request').value
    const commitment = coreServeRequestCommitment({ ...request, relayPublicKey: this.relayPublicKey })
    if (!same(commitment, input.requestCommitment)) fail('INTERNAL', 'Core prove request commitment mismatch')
    if (input.preparedAdmission == null) return Object.freeze({ kind: 'fresh' })
    const admission = preparedAdmission(input.preparedAdmission, commitment)
    if (admission.value.leaseClass !== 0 || admission.value.resourceClass < 1 ||
        admission.value.resourceClass > 6) {
      fail('SPEND_INVALID', 'Core proof prepared cost class is invalid')
    }
    const spend = this.spends.get(hex(admission.value.spendTag))
    if (!spend) return Object.freeze({ kind: 'fresh' })
    if (spend.operation !== 'PROVE' || !same(spend.requestCommitment, commitment)) {
      return Object.freeze({ kind: 'conflict' })
    }
    return Object.freeze({ kind: this.proofPins.has(hex(admission.value.spendTag)) ? 'replay' : 'terminal' })
  }

  async sweepProofPins () {
    const now = u64(this.nowUnixMillis(), 'nowUnixMillis')
    let expired = 0
    for (const pin of [...this.proofPins.values()]) {
      if (pin.expiresAtUnixMillis <= now) {
        await this.#expireProofPin(pin, now)
        expired++
      }
    }
    return expired
  }

  async sweepExpiredCores () {
    const now = u32(this.nowEpoch(), 'nowEpoch')
    let expired = 0
    for (const core of [...this.activeCores.values()]) {
      if (core.leaseEpoch > now) continue
      const pending = this.#highestPendingCandidate(core.corePublicKey)
      if (pending && pending.targetLeaseEpoch > now && pending.request.fork === core.fork &&
          pending.request.length === core.length && same(pending.request.signedHeadHash, core.signedHeadHash)) {
        continue
      }
      const coreKey = hex(core.corePublicKey)
      await this.transactionStore.withLocks([`core:${coreKey}`], async () => {
        const current = this.activeCores.get(coreKey)
        if (current !== core || current.leaseEpoch > now) return
        await this.#appendAndApply(BLIND_CORE_WAL_TYPE.CORE_EXPIRED,
          this.transactionStore.newTransactionId(), current.corpus.virtualBucket, {
            version: 1,
            corePublicKey: b4a.from(current.corePublicKey),
            stateRevision: current.stateRevision,
            leaseEpoch: current.leaseEpoch,
            corpusVirtualBucket: current.corpus.virtualBucket,
            corpusObjectId: b4a.from(current.corpus.objectId),
            corpusByteLength: current.corpus.byteLength,
            corpusHash: b4a.from(current.corpus.hash),
            expiredAtEpoch: now
          })
        if (!this.#corpusPinned(current.corpus)) await this.transactionStore.removeOpaque(current.corpus)
        expired++
      })
    }
    return expired
  }

  openPersistence () {
    return Object.freeze({
      reserve: record => this.#persistOpen(record, BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.RESERVED),
      activate: record => this.#persistOpen(record, BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.LIVE),
      terminal: record => this.#persistOpen(record, BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.TERMINAL),
      recoveredRecords: () => this.inspectOpenRecords()
    })
  }

  async #proofReplay (spendTag, commitment, request, input, lockHeld = false) {
    const spendKey = hex(spendTag)
    const operation = async () => {
      const spend = this.spends.get(spendKey)
      if (!spend) return null
      if (spend.operation !== 'PROVE' || !same(spend.requestCommitment, commitment)) {
        fail('SPEND_REPLAY', 'Core proof spend is already bound to another request')
      }
      const pin = this.proofPins.get(spendKey)
      if (!pin) fail('RETRY_TERMINAL', 'Core proof retry pin has expired')
      const now = u64(this.nowUnixMillis(), 'nowUnixMillis')
      if (pin.expiresAtUnixMillis <= now) {
        await this.#expireProofPin(pin, now, lockHeld)
        fail('RETRY_TERMINAL', 'Core proof retry pin has expired')
      }
      const source = {
        corePublicKey: b4a.from(request.corePublicKey),
        fork: request.fork,
        length: request.length,
        signedHeadHash: b4a.from(request.signedHeadHash),
        leaseEpoch: pin.sourceLeaseEpoch,
        stateRevision: pin.sourceStateRevision,
        corpus: cloneReference(pin.sourceCorpus),
        activatedAtEpoch: 0
      }
      const proofBytes = await this.#materializeProof(source, request, input)
      if (proofBytes.byteLength !== pin.proofByteLength || !same(blake2b256(proofBytes), pin.proofHash)) {
        throw new BlindWalIntegrityError('Core proof retry source no longer reproduces exact bytes')
      }
      return Object.freeze({ body: proofResult(pin.acknowledgementBytes, proofBytes), replay: true })
    }
    return lockHeld ? operation() : this.transactionStore.withLocks([`proof:${spendKey}`], operation)
  }

  async #materializeProof (active, request, input) {
    if (typeof input.serveProof !== 'function') fail('INTERNAL', 'pinned upstream Core proof adapter is unavailable')
    const corpus = await this.transactionStore.readOpaque(active.corpus,
      active.corpus.byteLength, active.corpus.hash)
    const output = b4a.from(bytes(await input.serveProof({
      generation: generationView(active),
      blockIndices: Object.freeze([...request.blockIndices]),
      corpus,
      signal: input.signal
    }), null, 'upstream proofsAndBlocks'))
    if (output.byteLength < 1 || output.byteLength > MAX_PROOF_BYTES) {
      fail('TOO_LARGE', 'Core proof response is outside the frozen bound')
    }
    return output
  }

  async #expireProofPin (pin, now, lockHeld = false) {
    const spendKey = hex(pin.spendTag)
    const operation = async () => {
      if (this.proofPins.get(spendKey) !== pin) return
      await this.#appendAndApply(BLIND_CORE_WAL_TYPE.PROVE_PIN_EXPIRED,
        this.transactionStore.newTransactionId(), pin.virtualBucket, {
          version: 1,
          spendTag: b4a.from(pin.spendTag),
          requestCommitment: b4a.from(pin.requestCommitment),
          expiredAtUnixMillis: now
        })
      if (!this.#corpusActive(pin.sourceCorpus) && !this.#corpusPinned(pin.sourceCorpus)) {
        await this.transactionStore.removeOpaque(pin.sourceCorpus)
      }
    }
    return lockHeld ? operation() : this.transactionStore.withLocks([`proof:${spendKey}`], operation)
  }

  async #terminalMirrorAttempt (attempt, reason) {
    const spendKey = hex(attempt.spendTag)
    return this.transactionStore.withLocks([`spend:${spendKey}`], async () => {
      const current = this.mirrorAttempts.get(spendKey)
      if (!current || current.state !== 'ACCEPTED') return mirrorAttemptView(current, true)
      await this.#appendMirrorTerminalLocked(current, reason)
      return mirrorAttemptView(this.mirrorAttempts.get(spendKey))
    })
  }

  async #retryMirrorAttempt (attempt, reason) {
    const spendKey = hex(attempt.spendTag)
    return this.transactionStore.withLocks([`spend:${spendKey}`], async () => {
      const current = this.mirrorAttempts.get(spendKey)
      if (!current || (current.state !== 'ACCEPTED' && current.state !== 'RETRY_PENDING')) {
        return mirrorAttemptView(current, true)
      }
      const retryCount = current.retryCount + 1
      if (retryCount > 3) {
        await this.#appendMirrorTerminalLocked(current, MIRROR_TERMINAL_REASON.UPSTREAM_UNAVAILABLE)
      } else {
        await this.#appendAndApply(BLIND_CORE_WAL_TYPE.MIRROR_RETRY_PENDING,
          this.transactionStore.newTransactionId(), current.virtualBucket, {
            version: 1,
            spendTag: b4a.from(current.spendTag),
            requestCommitment: b4a.from(current.requestCommitment),
            retryCount,
            retryReason: reason,
            recordedAtEpoch: u32(this.nowEpoch(), 'nowEpoch')
          })
      }
      return mirrorAttemptView(this.mirrorAttempts.get(spendKey))
    })
  }

  async #appendMirrorTerminalLocked (attempt, reason) {
    await this.#appendAndApply(BLIND_CORE_WAL_TYPE.MIRROR_TERMINAL,
      this.transactionStore.newTransactionId(), attempt.virtualBucket, {
        version: 1,
        spendTag: b4a.from(attempt.spendTag),
        requestCommitment: b4a.from(attempt.requestCommitment),
        terminalReason: reason,
        terminalAtEpoch: u32(this.nowEpoch(), 'nowEpoch')
      })
  }

  #highestPendingCandidate (corePublicKey) {
    let highest = null
    for (const attempt of this.mirrorAttempts.values()) {
      if ((attempt.state !== 'ACCEPTED' && attempt.state !== 'RETRY_PENDING') ||
          !same(attempt.request.corePublicKey, corePublicKey)) continue
      if (!highest || this.#compareCandidates(attempt, highest) > 0) highest = attempt
    }
    return highest
  }

  #hasHigherPendingCandidate (candidate) {
    for (const attempt of this.mirrorAttempts.values()) {
      if (attempt !== candidate && (attempt.state === 'ACCEPTED' || attempt.state === 'RETRY_PENDING') &&
          same(attempt.request.corePublicKey, candidate.request.corePublicKey) &&
          this.#compareCandidates(attempt, candidate) > 0) return true
    }
    return false
  }

  #compareCandidates (left, right) {
    if (left.request.fork !== right.request.fork) return left.request.fork > right.request.fork ? 1 : -1
    if (left.request.length !== right.request.length) return left.request.length > right.request.length ? 1 : -1
    const head = b4a.compare(left.request.signedHeadHash, right.request.signedHeadHash)
    if (head !== 0) return head
    if (left.targetLeaseEpoch !== right.targetLeaseEpoch) return left.targetLeaseEpoch > right.targetLeaseEpoch ? 1 : -1
    return 0
  }

  #sameCorpus (left, right) {
    return left.virtualBucket === right.virtualBucket && same(left.objectId, right.objectId) &&
      left.byteLength === right.byteLength && same(left.hash, right.hash)
  }

  #corpusPinned (corpus) {
    for (const pin of this.proofPins.values()) {
      if (this.#sameCorpus(pin.sourceCorpus, corpus)) return true
    }
    return false
  }

  #corpusActive (corpus) {
    for (const active of this.activeCores.values()) {
      if (this.#sameCorpus(active.corpus, corpus)) return true
    }
    return false
  }

  #validateCandidateOrder (current, request) {
    if (request.length > this.maximumSponsoredCoreLength) fail('TOO_LARGE', 'Core length exceeds signed capacity')
    if (!current) return
    if (request.fork < current.fork) fail('STALE_REVISION', 'Core candidate fork is stale')
    if (request.fork > current.fork) return
    if (request.length < current.length) fail('STALE_REVISION', 'Core candidate length is stale')
    if (request.length === current.length && !same(request.signedHeadHash, current.signedHeadHash)) {
      fail('CONFLICT', 'Core candidate conflicts at the same fork and length')
    }
  }

  #assertServeGeneration (active, request) {
    if (!active || active.leaseEpoch <= u32(this.nowEpoch(), 'nowEpoch')) fail('NOT_FOUND', 'Core sponsorship is unavailable')
    if (active.fork !== request.fork || active.length !== request.length ||
        !same(active.signedHeadHash, request.signedHeadHash)) {
      fail('STALE_REVISION', 'Core prove challenge does not match the active sponsored head')
    }
  }

  #validateAck (ack, request, commitment, leaseEpoch, observedAtEpoch, result) {
    if (!same(ack.relayBinding.relayPublicKey, this.relayPublicKey) ||
        !same(ack.corePublicKey, request.corePublicKey) || ack.fork !== request.fork ||
        ack.length !== request.length || !same(ack.signedHeadHash, request.signedHeadHash) ||
        ack.observedAtEpoch !== observedAtEpoch || ack.leaseEpoch !== leaseEpoch || ack.result !== result ||
        !same(ack.requestNonce, request.clientNonce) || !same(ack.requestCommitment, commitment) ||
        !verifySignedValue(blindCoreAckV1, ack, RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK,
          this.relayPublicKey)) {
      fail('INTERNAL', 'Core acknowledgement builder changed a frozen field')
    }
  }

  #validateOpenResult (result, record) {
    if (!same(result.relayBinding.relayPublicKey, this.relayPublicKey) ||
        !same(result.wireProfileHash, record.wireProfileHash) ||
        result.sessionClass !== record.sessionClass || result.controlChannelId !== record.controlChannelId ||
        !same(result.parentChannelBinding, record.parentChannelBinding) || result.streamId !== record.streamId ||
        result.maxSessionBytes !== record.maxSessionBytes || result.idleMillis !== record.idleMillis ||
        result.lifetimeMillis !== record.lifetimeMillis || result.openedAtEpoch !== record.openedAtEpoch ||
        !same(result.requestNonce, record.clientNonce) ||
        !same(result.requestCommitment, record.requestCommitment) ||
        !verifySignedValue(coreOpenReplicationResultV1, result,
          RESULT_SIGNATURE_DOMAIN_ID.CORE_OPEN_RESULT, this.relayPublicKey)) {
      fail('INTERNAL', 'Core OPEN retained result is invalid')
    }
  }

  async #persistOpen (record, lifecycleState) {
    if (!record || typeof record !== 'object' || !record.preparedAdmission) {
      fail('INTERNAL', 'Core OPEN persistence requires its prepared admission')
    }
    const admission = preparedAdmission(record.preparedAdmission, record.requestCommitment)
    if (admission.value.leaseClass !== 0 || admission.value.resourceClass !== record.sessionClass) {
      fail('SPEND_INVALID', 'Core OPEN prepared cost class is invalid')
    }
    const resultBytes = record.result == null
      ? null
      : canonical(coreOpenReplicationResultV1, record.result, 'Core OPEN result').bytes
    if (resultBytes != null) {
      this.#validateOpenResult(
        decodeCanonical(coreOpenReplicationResultV1, resultBytes, { copyBytes: true }),
        record
      )
    }
    const snapshot = canonical(blindCoreOpenReplicationRetrySnapshotV1, {
      version: 1,
      lifecycleState,
      logicalRetryKey: b4a.from(record.logicalRetryKey),
      spendTag: b4a.from(record.spendTag),
      requestCommitment: b4a.from(record.requestCommitment),
      wireProfileHash: b4a.from(record.wireProfileHash),
      sessionClass: record.sessionClass,
      clientNonce: b4a.from(record.clientNonce),
      parentSessionId: b4a.from(record.parentSessionId),
      controlChannelId: record.controlChannelId,
      parentChannelBinding: b4a.from(record.parentChannelBinding),
      streamId: record.streamId,
      maxSessionBytes: record.maxSessionBytes,
      idleMillis: record.idleMillis,
      lifetimeMillis: record.lifetimeMillis,
      openedAtEpoch: record.openedAtEpoch,
      recordVirtualBucket: this.transactionStore.virtualBucket(
        BLIND_STORE_SERVICE_TAG.CORE, record.logicalRetryKey),
      resultBytes,
      terminalReason: lifecycleState === BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.TERMINAL
        ? b4a.from(String(record.terminalReason || 'terminal').slice(0, 64), 'ascii')
        : null
    }, 'Core OPEN persistence snapshot')
    await this.transactionStore.withLocks([
      `open-logical:${hex(record.logicalRetryKey)}`,
      `spend:${hex(record.spendTag)}`
    ], async () => {
      const priorSpend = this.spends.get(hex(record.spendTag))
      if (priorSpend && (priorSpend.operation !== 'OPEN_REPLICATION' ||
          !same(priorSpend.requestCommitment, record.requestCommitment))) {
        fail('SPEND_REPLAY', 'Core OPEN spend is already bound to another request')
      }
      if (!priorSpend && this.spends.size >= this.maximumSpendRecords) {
        fail('BUSY', 'Core spend-record capacity is exhausted')
      }
      await this.#appendAndApply(BLIND_CORE_WAL_TYPE.OPEN_STATE,
        this.transactionStore.newTransactionId(),
        this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CORE, record.logicalRetryKey), {
          version: 1,
          preparedAdmissionBytes: admission.bytes,
          snapshotBytes: snapshot.bytes
        })
    })
  }

  async #terminalizeRecoveredOpens () {
    const recovered = [...this.openRecords.values()].filter(record =>
      record.lifecycleState !== BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.TERMINAL)
    for (const record of recovered) {
      const snapshot = {
        ...record,
        lifecycleState: BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.TERMINAL,
        terminalReason: b4a.from('restart-terminal', 'ascii')
      }
      await this.#appendAndApply(BLIND_CORE_WAL_TYPE.OPEN_STATE,
        this.transactionStore.newTransactionId(), record.recordVirtualBucket, {
          version: 1,
          preparedAdmissionBytes: b4a.from(record.preparedAdmissionBytes),
          snapshotBytes: encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, snapshot)
        })
    }
  }

  async #appendAndApply (type, transactionId, virtualBucket, value) {
    const codec = WAL_CODECS.get(type)
    if (!codec) throw new TypeError('unknown Core WAL type')
    const payload = encodeCanonical(codec, value)
    return this.transactionStore.appendAndApply({ type, transactionId, virtualBucket, payload },
      frame => this.#applyFrame(frame, false))
  }

  #applyFrame (frame, recovering) {
    const codec = WAL_CODECS.get(frame.type)
    if (!codec) {
      if (this.ownsTransactionStore) throw new BlindWalIntegrityError(`unknown Core WAL frame type ${frame.type}`)
      return
    }
    let value
    try {
      value = decodeCanonical(codec, frame.payload, { copyBytes: true })
      if (!same(frame.payload, encodeCanonical(codec, value))) throw new Error('non-canonical')
    } catch (error) {
      throw new BlindWalIntegrityError(`invalid Core WAL payload: ${error.message}`)
    }
    if (frame.type === BLIND_CORE_WAL_TYPE.MIRROR_ACCEPTED) this.#applyMirrorAccepted(frame, value)
    if (frame.type === BLIND_CORE_WAL_TYPE.MIRROR_ACTIVATED) this.#applyMirrorActivated(frame, value)
    if (frame.type === BLIND_CORE_WAL_TYPE.MIRROR_TERMINAL) this.#applyMirrorTerminal(frame, value)
    if (frame.type === BLIND_CORE_WAL_TYPE.PROVE_PINNED) this.#applyProofPinned(frame, value)
    if (frame.type === BLIND_CORE_WAL_TYPE.PROVE_PIN_EXPIRED) this.#applyProofExpired(frame, value)
    if (frame.type === BLIND_CORE_WAL_TYPE.OPEN_STATE) this.#applyOpenState(frame, value)
    if (frame.type === BLIND_CORE_WAL_TYPE.MIRROR_RETRY_PENDING) this.#applyMirrorRetryPending(frame, value)
    if (frame.type === BLIND_CORE_WAL_TYPE.CORE_EXPIRED) this.#applyCoreExpired(frame, value)
    this.accounting.walSequence = frame.sequence
    if (recovering && this.accounting.controlBytes > Number.MAX_SAFE_INTEGER) {
      throw new BlindWalIntegrityError('Core control accounting exceeds the runtime bound')
    }
  }

  #applyMirrorAccepted (frame, value) {
    const admission = decodeCanonical(preparedAdmissionStoreV1, value.preparedAdmissionBytes, { copyBytes: true })
    const request = decodeCanonical(coreMirrorRequestV1, value.requestBytes, { copyBytes: true })
    const ack = decodeCanonical(blindCoreAckV1, value.resultBytes, { copyBytes: true })
    const expectedCommitment = coreMirrorRequestCommitment({ ...request, relayPublicKey: this.relayPublicKey })
    if (!same(admission.requestCommitment, expectedCommitment) ||
        admission.leaseClass !== request.leaseClass || admission.resourceClass < 1 ||
        admission.resourceClass > 45 || admission.costUnits === 0n ||
        frame.virtualBucket !== this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CORE, request.corePublicKey)) {
      throw new BlindWalIntegrityError('Core mirror accepted frame binding is invalid')
    }
    try {
      this.#validateAck(ack, request, expectedCommitment, value.targetLeaseEpoch,
        value.acceptedAtEpoch, CORE_ACK_RESULT.MIRROR_ACCEPTED)
    } catch (error) {
      throw new BlindWalIntegrityError(`Core mirror acknowledgement is invalid: ${error.message}`)
    }
    const spendKey = hex(admission.spendTag)
    const existing = this.spends.get(spendKey)
    if (existing && (!same(existing.requestCommitment, expectedCommitment) || existing.operation !== 'MIRROR')) {
      throw new BlindWalIntegrityError('Core mirror WAL reuses a spend for another request')
    }
    if (this.mirrorAttempts.has(spendKey)) {
      throw new BlindWalIntegrityError('Core mirror WAL repeats an accepted attempt')
    }
    if (this.spends.size >= this.maximumSpendRecords) {
      throw new BlindWalIntegrityError('Core spend-record recovery exceeds its bound')
    }
    const current = this.coreFloors.get(hex(request.corePublicKey)) || null
    const pending = this.#highestPendingCandidate(request.corePublicKey)
    const floor = pending == null
      ? current
      : {
          fork: pending.request.fork,
          length: pending.request.length,
          signedHeadHash: pending.request.signedHeadHash,
          leaseEpoch: pending.targetLeaseEpoch,
          stateRevision: pending.candidateRevision
        }
    try {
      this.#validateCandidateOrder(floor, request)
    } catch (error) {
      throw new BlindWalIntegrityError(`Core accepted candidate order is invalid: ${error.message}`)
    }
    const expectedRevision = floor ? floor.stateRevision + 1n : 0n
    const minimumLease = value.acceptedAtEpoch + LEASE_CLASS_EPOCHS[request.leaseClass]
    const billableLength = !floor || request.fork > floor.fork || value.targetLeaseEpoch > floor.leaseEpoch
      ? request.length
      : request.length - floor.length
    let expectedResourceClass
    try {
      expectedResourceClass = coreLengthClass(billableLength)
    } catch (error) {
      throw new BlindWalIntegrityError(`Core accepted candidate has no billable advancement: ${error.message}`)
    }
    if (value.candidateRevision !== expectedRevision || value.targetLeaseEpoch < minimumLease ||
        (floor && value.targetLeaseEpoch < floor.leaseEpoch) ||
        admission.resourceClass !== expectedResourceClass) {
      throw new BlindWalIntegrityError('Core accepted candidate revision or lease floor is invalid')
    }
    if (!current && this.coreFloors.size >= this.maximumCores) {
      throw new BlindWalIntegrityError('Core identity-floor recovery exceeds its bound')
    }
    const record = {
      state: 'ACCEPTED',
      spendTag: b4a.from(admission.spendTag),
      requestCommitment: b4a.from(expectedCommitment),
      request,
      resultBytes: b4a.from(value.resultBytes),
      acceptedAtEpoch: value.acceptedAtEpoch,
      targetLeaseEpoch: value.targetLeaseEpoch,
      candidateRevision: value.candidateRevision,
      preparedAdmissionBytes: b4a.from(value.preparedAdmissionBytes),
      virtualBucket: frame.virtualBucket,
      retryCount: 0,
      terminalReason: null
    }
    if (!this.mirrorAttempts.has(spendKey)) {
      this.accounting.mirrorAttempts++
      this.accounting.controlBytes += CONTROL_RECORD_BYTES
    }
    this.mirrorAttempts.set(spendKey, record)
    this.spends.set(spendKey, { operation: 'MIRROR', requestCommitment: b4a.from(expectedCommitment) })
  }

  #applyMirrorActivated (frame, value) {
    const spendKey = hex(value.spendTag)
    const attempt = this.mirrorAttempts.get(spendKey)
    if (!attempt || !same(attempt.requestCommitment,
      coreMirrorRequestCommitment({ ...attempt.request, relayPublicKey: this.relayPublicKey })) ||
      !same(attempt.request.corePublicKey, value.corePublicKey) || attempt.request.fork !== value.fork ||
      attempt.request.length !== value.length || !same(attempt.request.signedHeadHash, value.signedHeadHash) ||
        attempt.targetLeaseEpoch !== value.leaseEpoch ||
        frame.virtualBucket !== value.corpusVirtualBucket) {
      throw new BlindWalIntegrityError('Core activation does not match its accepted candidate')
    }
    const coreKey = hex(value.corePublicKey)
    const previous = this.activeCores.get(coreKey)
    const previousFloor = this.coreFloors.get(coreKey) || null
    if (!previous && this.activeCores.size >= this.maximumCores) {
      throw new BlindWalIntegrityError('Core active sponsorship recovery exceeds its bound')
    }
    if (attempt.state !== 'ACCEPTED' && attempt.state !== 'RETRY_PENDING') {
      throw new BlindWalIntegrityError('Core activation repeats or follows a terminal attempt')
    }
    if (this.#hasHigherPendingCandidate(attempt)) {
      throw new BlindWalIntegrityError('Core activation bypasses a higher ordered candidate')
    }
    try {
      this.#validateCandidateOrder(previousFloor, attempt.request)
    } catch (error) {
      throw new BlindWalIntegrityError(`Core activation candidate is stale: ${error.message}`)
    }
    const expectedRevision = previousFloor ? previousFloor.stateRevision + 1n : 0n
    if (value.stateRevision !== expectedRevision || value.corpusByteLength < 1 ||
        !nonzero(value.corpusObjectId) || !nonzero(value.corpusHash)) {
      throw new BlindWalIntegrityError('Core activation revision or corpus reference is invalid')
    }
    if (!previous) this.accounting.activeCores++
    const record = {
      corePublicKey: b4a.from(value.corePublicKey),
      fork: value.fork,
      length: value.length,
      signedHeadHash: b4a.from(value.signedHeadHash),
      leaseEpoch: value.leaseEpoch,
      stateRevision: value.stateRevision,
      corpus: {
        virtualBucket: value.corpusVirtualBucket,
        objectId: b4a.from(value.corpusObjectId),
        byteLength: value.corpusByteLength,
        hash: b4a.from(value.corpusHash)
      },
      activatedAtEpoch: value.activatedAtEpoch
    }
    const previousSame = previous && this.#sameCorpus(previous.corpus, record.corpus)
    if (previous && !previousSame && !this.#corpusPinned(previous.corpus)) {
      this.accounting.corpusBytes -= previous.corpus.byteLength
    }
    if (!previousSame && !this.#corpusPinned(record.corpus)) {
      this.accounting.corpusBytes += value.corpusByteLength
    }
    this.activeCores.set(coreKey, record)
    this.coreFloors.set(coreKey, record)
    attempt.state = 'ACTIVE'
  }

  #applyMirrorTerminal (frame, value) {
    const attempt = this.mirrorAttempts.get(hex(value.spendTag))
    if (!attempt || !same(attempt.requestCommitment, value.requestCommitment) ||
        attempt.virtualBucket !== frame.virtualBucket) {
      throw new BlindWalIntegrityError('Core terminal mirror frame has no accepted attempt')
    }
    if (attempt.state === 'ACTIVE' || attempt.state === 'TERMINAL') {
      throw new BlindWalIntegrityError('Core terminal frame follows an active or terminal attempt')
    }
    attempt.state = 'TERMINAL'
    attempt.terminalReason = value.terminalReason
  }

  #applyMirrorRetryPending (frame, value) {
    const attempt = this.mirrorAttempts.get(hex(value.spendTag))
    if (!attempt || !same(attempt.requestCommitment, value.requestCommitment) ||
        attempt.virtualBucket !== frame.virtualBucket ||
        (attempt.state !== 'ACCEPTED' && attempt.state !== 'RETRY_PENDING') ||
        value.retryCount !== attempt.retryCount + 1) {
      throw new BlindWalIntegrityError('Core retry-pending frame has no valid predecessor')
    }
    attempt.state = 'RETRY_PENDING'
    attempt.retryCount = value.retryCount
    attempt.retryReason = value.retryReason
  }

  #applyProofPinned (frame, value) {
    const admission = decodeCanonical(preparedAdmissionStoreV1, value.preparedAdmissionBytes, { copyBytes: true })
    const request = decodeCanonical(coreServeChallengeV1, value.requestBytes, { copyBytes: true })
    const ack = decodeCanonical(blindCoreAckV1, value.acknowledgementBytes, { copyBytes: true })
    const commitment = coreServeRequestCommitment({ ...request, relayPublicKey: this.relayPublicKey })
    if (!same(admission.requestCommitment, commitment) || admission.leaseClass !== 0 ||
        admission.resourceClass < 1 || admission.resourceClass > 6 || admission.costUnits === 0n ||
        frame.virtualBucket !== this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CORE, request.corePublicKey) ||
        value.expiresAtUnixMillis <= value.pinnedAtUnixMillis ||
        value.expiresAtUnixMillis - value.pinnedAtUnixMillis > MAX_PROOF_PIN_MILLIS ||
        value.sourceCorpusVirtualBucket !== frame.virtualBucket) {
      throw new BlindWalIntegrityError('Core proof pin binding is invalid')
    }
    try {
      this.#validateAck(ack, request, commitment, ack.leaseEpoch,
        ack.observedAtEpoch, CORE_ACK_RESULT.RECENTLY_SERVED)
    } catch (error) {
      throw new BlindWalIntegrityError(`Core proof acknowledgement is invalid: ${error.message}`)
    }
    if (admission.resourceClass !== resultBand(coreProofResultByteLength(
      value.acknowledgementBytes, value.proofByteLength))) {
      throw new BlindWalIntegrityError('Core proof pin admission band does not match its canonical result size')
    }
    const spendKey = hex(admission.spendTag)
    const prior = this.spends.get(spendKey)
    if (prior && (prior.operation !== 'PROVE' || !same(prior.requestCommitment, commitment))) {
      throw new BlindWalIntegrityError('Core proof pin reuses a spend')
    }
    if (prior || this.proofPins.has(spendKey)) {
      throw new BlindWalIntegrityError('Core proof pin is repeated')
    }
    if (this.spends.size >= this.maximumSpendRecords || this.proofPins.size >= this.maximumProofPins) {
      throw new BlindWalIntegrityError('Core proof recovery exceeds its configured bound')
    }
    const source = this.activeCores.get(hex(request.corePublicKey))
    const sourceReference = {
      virtualBucket: value.sourceCorpusVirtualBucket,
      objectId: value.sourceCorpusObjectId,
      byteLength: value.sourceCorpusByteLength,
      hash: value.sourceCorpusHash
    }
    if (!source || source.fork !== request.fork || source.length !== request.length ||
        !same(source.signedHeadHash, request.signedHeadHash) ||
        source.stateRevision !== value.sourceStateRevision || source.leaseEpoch !== value.sourceLeaseEpoch ||
        !this.#sameCorpus(source.corpus, sourceReference) || value.proofByteLength < 1 ||
        value.proofByteLength > MAX_PROOF_BYTES || !nonzero(value.proofHash)) {
      throw new BlindWalIntegrityError('Core proof pin source generation is invalid')
    }
    const pin = {
      spendTag: b4a.from(admission.spendTag),
      requestCommitment: b4a.from(commitment),
      request,
      acknowledgementBytes: b4a.from(value.acknowledgementBytes),
      proofByteLength: value.proofByteLength,
      proofHash: b4a.from(value.proofHash),
      sourceStateRevision: value.sourceStateRevision,
      sourceLeaseEpoch: value.sourceLeaseEpoch,
      sourceCorpus: {
        virtualBucket: value.sourceCorpusVirtualBucket,
        objectId: b4a.from(value.sourceCorpusObjectId),
        byteLength: value.sourceCorpusByteLength,
        hash: b4a.from(value.sourceCorpusHash)
      },
      sourceCorpusHash: b4a.from(value.sourceCorpusHash),
      pinnedAtUnixMillis: value.pinnedAtUnixMillis,
      expiresAtUnixMillis: value.expiresAtUnixMillis,
      virtualBucket: frame.virtualBucket
    }
    if (!this.proofPins.has(spendKey)) {
      this.accounting.proofPins++
      this.accounting.proofPinBytes += PROOF_PIN_RECORD_BYTES
    }
    this.proofPins.set(spendKey, pin)
    this.spends.set(spendKey, { operation: 'PROVE', requestCommitment: b4a.from(commitment) })
  }

  #applyProofExpired (frame, value) {
    const spendKey = hex(value.spendTag)
    const spend = this.spends.get(spendKey)
    const pin = this.proofPins.get(spendKey)
    if (!spend || !pin || spend.operation !== 'PROVE' ||
        !same(spend.requestCommitment, value.requestCommitment) || pin.virtualBucket !== frame.virtualBucket) {
      throw new BlindWalIntegrityError('Core proof expiry has no matching pin/spend')
    }
    this.proofPins.delete(spendKey)
    this.accounting.proofPins--
    this.accounting.proofPinBytes -= PROOF_PIN_RECORD_BYTES
    this.accounting.proofSpendTombstones++
    this.accounting.tombstoneBytes += SPEND_TOMBSTONE_BYTES
    if (!this.#corpusActive(pin.sourceCorpus) && !this.#corpusPinned(pin.sourceCorpus)) {
      this.accounting.corpusBytes -= pin.sourceCorpus.byteLength
    }
  }

  #applyCoreExpired (frame, value) {
    const coreKey = hex(value.corePublicKey)
    const current = this.activeCores.get(coreKey)
    const floor = this.coreFloors.get(coreKey)
    const pending = this.#highestPendingCandidate(value.corePublicKey)
    if (!current || current.stateRevision !== value.stateRevision ||
        floor !== current ||
        current.leaseEpoch !== value.leaseEpoch || value.expiredAtEpoch < value.leaseEpoch ||
        frame.virtualBucket !== value.corpusVirtualBucket ||
        !this.#sameCorpus(current.corpus, {
          virtualBucket: value.corpusVirtualBucket,
          objectId: value.corpusObjectId,
          byteLength: value.corpusByteLength,
          hash: value.corpusHash
        }) || (pending && pending.targetLeaseEpoch > value.expiredAtEpoch &&
          pending.request.fork === current.fork && pending.request.length === current.length &&
          same(pending.request.signedHeadHash, current.signedHeadHash))) {
      throw new BlindWalIntegrityError('Core expiry frame does not match the active sponsorship')
    }
    this.activeCores.delete(coreKey)
    this.accounting.activeCores--
    if (!this.#corpusPinned(current.corpus)) this.accounting.corpusBytes -= current.corpus.byteLength
  }

  #applyOpenState (frame, value) {
    const admission = decodeCanonical(preparedAdmissionStoreV1, value.preparedAdmissionBytes, { copyBytes: true })
    const snapshot = decodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, value.snapshotBytes, { copyBytes: true })
    if (!same(admission.spendTag, snapshot.spendTag) || admission.leaseClass !== 0 ||
        admission.resourceClass !== snapshot.sessionClass || admission.costUnits === 0n ||
        !same(admission.requestCommitment, snapshot.requestCommitment) ||
        snapshot.recordVirtualBucket !== frame.virtualBucket ||
        frame.virtualBucket !== this.transactionStore.virtualBucket(BLIND_STORE_SERVICE_TAG.CORE,
          snapshot.logicalRetryKey)) {
      throw new BlindWalIntegrityError('Core OPEN state binding is invalid')
    }
    const logicalKey = hex(snapshot.logicalRetryKey)
    const spendKey = hex(snapshot.spendTag)
    const priorLogical = this.openRecords.get(logicalKey)
    const priorSpend = this.openSpendIndex.get(spendKey)
    if ((priorLogical && !same(priorLogical.requestCommitment, snapshot.requestCommitment)) ||
        (priorSpend && priorSpend !== logicalKey)) {
      throw new BlindWalIntegrityError('Core OPEN state forks its logical or spend index')
    }
    if (!priorLogical && this.spends.size >= this.maximumSpendRecords) {
      throw new BlindWalIntegrityError('Core OPEN spend recovery exceeds its bound')
    }
    if (priorLogical) {
      const allowed = (priorLogical.lifecycleState === BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.RESERVED &&
        (snapshot.lifecycleState === BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.LIVE ||
         snapshot.lifecycleState === BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.TERMINAL)) ||
        (priorLogical.lifecycleState === BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.LIVE &&
         snapshot.lifecycleState === BLIND_CORE_OPEN_REPLICATION_LIFECYCLE_STATE.TERMINAL)
      if (!allowed) throw new BlindWalIntegrityError('Core OPEN lifecycle transition is repeated or regresses')
    }
    if (snapshot.resultBytes != null) {
      const result = decodeCanonical(coreOpenReplicationResultV1, snapshot.resultBytes, { copyBytes: true })
      try {
        this.#validateOpenResult(result, snapshot)
      } catch (error) {
        throw new BlindWalIntegrityError(`Core OPEN retained result is invalid: ${error.message}`)
      }
    }
    if (!priorLogical) {
      this.accounting.openRecords++
      this.accounting.controlBytes += CONTROL_RECORD_BYTES
    }
    const record = {
      ...snapshot,
      preparedAdmissionBytes: b4a.from(value.preparedAdmissionBytes)
    }
    this.openRecords.set(logicalKey, record)
    this.openSpendIndex.set(spendKey, logicalKey)
    this.spends.set(spendKey, {
      operation: 'OPEN_REPLICATION',
      requestCommitment: b4a.from(snapshot.requestCommitment)
    })
  }
}
