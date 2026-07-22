import b4a from 'b4a'
import {
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  RESULT_SIGNATURE_DOMAIN_ID,
  STORE_LIFECYCLE_STATE,
  auxiliarySignaturePayload,
  blindServiceDescriptorV1,
  blindStoreManifestV1,
  decodeCanonical,
  durabilityContinuityBindingV1,
  durabilityContinuityHash,
  durabilityProfileHash,
  durabilityProfileV1,
  encodeCanonical,
  relayIdentityTransitionV1,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import { ADVERTISED_OPERATION_BITS } from '@hiverelay/blind-protocol/wire-runtime-authority'

const MAX_U32 = 0xffffffff
const MAX_U64 = (1n << 64n) - 1n
const ZERO32 = b4a.alloc(32)

export const DESCRIPTOR_STATE_KIND = Object.freeze({
  READY: 1,
  CLOSED: 2
})

export const DESCRIPTOR_CLOSED_REASON = Object.freeze({
  NO_DESCRIPTOR: 1,
  NOT_YET_VALID: 2,
  EXPIRED: 3,
  ROLLBACK: 4,
  FORK: 5,
  CHAIN_GAP: 6,
  INVALID_TRANSITION: 7,
  RETIRED: 8,
  RESTORE_UNVERIFIED: 9
})

export class DescriptorStateError extends Error {
  constructor (code, message) {
    super(message)
    this.name = 'DescriptorStateError'
    this.code = code
  }
}

function closedError (reason, message) {
  throw new DescriptorStateError(reason, message)
}

function asBytes (value, field, length = null) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  const bytes = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (length != null && bytes.byteLength !== length) throw new TypeError(`${field} must be exactly ${length} bytes`)
  return bytes
}

function ownedBytes (value, field, length = null) {
  return b4a.from(asBytes(value, field, length))
}

function sameBytes (left, right) {
  return Boolean(left && right && left.byteLength === right.byteLength && b4a.equals(left, right))
}

function byteKey (value) {
  return b4a.toString(value, 'hex')
}

function currentEpoch (epochNow) {
  const value = epochNow()
  if (!Number.isInteger(value) || value < 0 || value > MAX_U32) {
    throw new TypeError('epochNow must return a u32 integer')
  }
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') value = BigInt(value)
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    closedError(DESCRIPTOR_CLOSED_REASON.RESTORE_UNVERIFIED, `${field} is outside u64`)
  }
  return value
}

function defaultEpochNow () {
  return Math.floor(Date.now() / (6 * 60 * 60 * 1000))
}

function decodeExact (codec, canonicalBytes, message) {
  let value
  try {
    value = decodeCanonical(codec, canonicalBytes, { copyBytes: true })
    if (!sameBytes(canonicalBytes, encodeCanonical(codec, value))) throw new Error('non-canonical')
  } catch {
    closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION, message)
  }
  return value
}

function continuityValue (durability) {
  return {
    version: 1,
    profileId: durability.profileId,
    externalJournalId: b4a.from(durability.externalJournalId),
    externalWitnessPublicKey: b4a.from(durability.externalWitnessPublicKey),
    externalJournalReplicationClass: durability.externalJournalReplicationClass,
    externalJournalFailureGroupId: b4a.from(durability.externalJournalFailureGroupId),
    restoreEvidenceFeedId: b4a.from(durability.restoreEvidenceFeedId)
  }
}

function assertDurabilityHashes (descriptor) {
  const profileBytes = encodeCanonical(durabilityProfileV1, descriptor.durability)
  const continuityBytes = encodeCanonical(durabilityContinuityBindingV1, continuityValue(descriptor.durability))
  if (!sameBytes(descriptor.durabilityProfileHash, durabilityProfileHash(profileBytes)) ||
      !sameBytes(descriptor.durabilityContinuityHash, durabilityContinuityHash(continuityBytes))) {
    closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION,
      'descriptor durability hashes do not match their canonical signed values')
  }
}

function assertAdvertisedDescriptorProfile (descriptor) {
  if ((descriptor.enabledOperationBits & ~ADVERTISED_OPERATION_BITS) !== 0) {
    closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION,
      'descriptor enables an operation reserved by the active release profile')
  }
}

function lifecycleTransition (previous, next) {
  if (previous === next) return previous !== STORE_LIFECYCLE_STATE.RETIRED
  if (previous === STORE_LIFECYCLE_STATE.ACTIVE && next === STORE_LIFECYCLE_STATE.DRAINING) return true
  if (previous === STORE_LIFECYCLE_STATE.DRAINING && next === STORE_LIFECYCLE_STATE.RETIRED) return true
  return false
}

function assertGenesis (descriptor) {
  if (descriptor.descriptorSequence !== 0n || descriptor.identitySequence !== 0n ||
      descriptor.previousDescriptorHash != null || descriptor.previousRelayKey != null ||
      descriptor.identityTransition != null || descriptor.storeLifecycleState !== STORE_LIFECYCLE_STATE.ACTIVE) {
    closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION,
      'descriptor genesis must start an unrelated active identity and store at sequence zero')
  }
}

function assertSameKeyTransition (previous, next) {
  if (next.previousRelayKey != null || next.identityTransition != null ||
      next.identitySequence !== previous.identitySequence ||
      !sameBytes(previous.storeId, next.storeId) ||
      previous.durability.profileId !== next.durability.profileId ||
      !sameBytes(previous.durabilityContinuityHash, next.durabilityContinuityHash)) {
    closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION,
      'same-key descriptor refresh changed immutable store or identity continuity')
  }
  if (!lifecycleTransition(previous.storeLifecycleState, next.storeLifecycleState)) {
    closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION, 'store lifecycle skipped, moved backward, or advanced after retirement')
  }
  if (previous.storeLifecycleState === STORE_LIFECYCLE_STATE.ACTIVE &&
      next.storeLifecycleState === STORE_LIFECYCLE_STATE.ACTIVE &&
      next.issuedEpoch <= previous.issuedEpoch) {
    closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION,
      'routine ACTIVE descriptor refresh repeated an issuance epoch')
  }
}

function assertRotationTransition (previous, next) {
  const transition = next.identityTransition
  if (previous.storeLifecycleState !== STORE_LIFECYCLE_STATE.RETIRED ||
      next.storeLifecycleState !== STORE_LIFECYCLE_STATE.ACTIVE || !transition || !next.previousRelayKey ||
      sameBytes(previous.storeId, next.storeId) ||
      !sameBytes(next.previousRelayKey, previous.relayPublicKey) ||
      !sameBytes(transition.oldRelayKey, previous.relayPublicKey) ||
      !sameBytes(transition.newRelayKey, next.relayPublicKey) ||
      transition.oldIdentitySequence !== previous.identitySequence ||
      transition.newIdentitySequence !== next.identitySequence ||
      next.identitySequence !== previous.identitySequence + 1n ||
      transition.validFromEpoch !== next.issuedEpoch) {
    closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION,
      'relay-key rotation does not start a fresh active store from the retired identity')
  }
}

function assertDrainEpoch (previous, next) {
  if ((previous.storeLifecycleState === STORE_LIFECYCLE_STATE.DRAINING ||
       previous.storeLifecycleState === STORE_LIFECYCLE_STATE.RETIRED) &&
      next.storeLifecycleState !== STORE_LIFECYCLE_STATE.ACTIVE &&
      next.drainStartedEpoch !== previous.drainStartedEpoch) {
    closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION,
      'descriptor changed the original store drain epoch')
  }
}

function assertTransition (previousRecord, next, options) {
  const previous = decodeExact(blindServiceDescriptorV1, previousRecord.canonicalBytes,
    'stored descriptor bytes are not canonical')
  if (next.descriptorSequence !== previous.descriptorSequence + 1n ||
      !next.previousDescriptorHash || !sameBytes(next.previousDescriptorHash, previousRecord.hash)) {
    closedError(DESCRIPTOR_CLOSED_REASON.CHAIN_GAP,
      'descriptor must be exact +1 and link the complete prior signed descriptor hash')
  }
  const readinessGap = next.issuedEpoch >= previous.expiresEpoch
  if (readinessGap && options.allowGap !== true) {
    closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION,
      'planned descriptor refreshes must overlap; emergency gaps require explicit policy')
  }
  const sameRelay = sameBytes(previous.relayPublicKey, next.relayPublicKey)
  if (sameRelay) assertSameKeyTransition(previous, next)
  else assertRotationTransition(previous, next)
  assertDrainEpoch(previous, next)
  const lifecycleFenceChanged = readinessGap || !sameRelay || !sameBytes(previous.storeId, next.storeId) ||
    previous.storeLifecycleState !== next.storeLifecycleState
  return { readinessGap, lifecycleFenceChanged }
}

function recordFor (descriptor, canonicalBytes, hash, generation, lifecycleFence,
  hadReadinessGap, restored) {
  return Object.freeze({
    canonicalBytes: b4a.from(canonicalBytes),
    hash: b4a.from(hash),
    descriptorSequence: descriptor.descriptorSequence,
    issuedEpoch: descriptor.issuedEpoch,
    expiresEpoch: descriptor.expiresEpoch,
    storeLifecycleState: descriptor.storeLifecycleState,
    generation,
    lifecycleFence,
    hadReadinessGap,
    restored
  })
}

function snapshotFor (record) {
  const descriptor = decodeExact(blindServiceDescriptorV1, record.canonicalBytes,
    'stored descriptor bytes are not canonical')
  return Object.freeze({
    descriptor,
    canonicalBytes: b4a.from(record.canonicalBytes),
    hash: b4a.from(record.hash),
    descriptorSequence: record.descriptorSequence,
    generation: record.generation,
    lifecycleFence: record.lifecycleFence,
    hadReadinessGap: record.hadReadinessGap,
    fullStoreVerificationRequired: record.hadReadinessGap || record.restored
  })
}

function manifestMatchesDescriptor (manifest, descriptor, hash) {
  return manifest.descriptorSequenceFloor === descriptor.descriptorSequence &&
    sameBytes(manifest.descriptorHashFloor, hash) &&
    sameBytes(manifest.relayPublicKey, descriptor.relayPublicKey) &&
    sameBytes(manifest.storeId, descriptor.storeId) &&
    manifest.durabilityProfileId === descriptor.durability.profileId &&
    sameBytes(manifest.durabilityContinuityHash, descriptor.durabilityContinuityHash) &&
    sameBytes(manifest.durabilityProfileHash, descriptor.durabilityProfileHash) &&
    manifest.formatMajor === descriptor.durability.storeFormatMajor &&
    manifest.formatMinor === descriptor.durability.storeFormatMinor &&
    sameBytes(manifest.storeFormatHash, descriptor.durability.storeFormatHash) &&
    sameBytes(manifest.specHash, descriptor.build.specHash) &&
    sameBytes(manifest.abiHash, descriptor.build.abiHash)
}

export class DescriptorState {
  #currentRecord
  #byHash
  #bySequence
  #generation
  #lifecycleFence
  #fault
  #serial

  constructor (options = {}) {
    if (typeof options.verifySignature !== 'function') {
      throw new TypeError('verifySignature is required for descriptor activation')
    }
    this.verifySignature = options.verifySignature
    this.verifyIdentityTransitionSignature = options.verifyIdentityTransitionSignature || options.verifySignature
    this.verifyRestoration = typeof options.verifyRestoration === 'function' ? options.verifyRestoration : null
    this.epochNow = typeof options.epochNow === 'function' ? options.epochNow : defaultEpochNow
    this.maxHistory = options.maxHistory == null ? 4096 : options.maxHistory
    this.retentionEpochs = options.retentionEpochs == null ? 1460 : options.retentionEpochs
    this.allowEmergencyGaps = options.allowEmergencyGaps === true
    if (!Number.isSafeInteger(this.maxHistory) || this.maxHistory < 1 || this.maxHistory > 4096) {
      throw new TypeError('maxHistory must be within 1..4096')
    }
    if (!Number.isSafeInteger(this.retentionEpochs) || this.retentionEpochs < 1 || this.retentionEpochs > 1460) {
      throw new TypeError('retentionEpochs must be within 1..1460')
    }
    currentEpoch(this.epochNow)
    this.#currentRecord = null
    this.#byHash = new Map()
    this.#bySequence = new Map()
    this.#generation = 0
    this.#lifecycleFence = 0
    this.#fault = null
    this.#serial = Promise.resolve()
  }

  _serialized (operation) {
    const result = this.#serial.then(operation)
    this.#serial = result.catch(() => {})
    return result
  }

  async _verifiedDescriptor (canonicalBytes, signal) {
    let descriptor = decodeExact(blindServiceDescriptorV1, canonicalBytes,
      'descriptor bytes are not canonical')
    assertDurabilityHashes(descriptor)
    assertAdvertisedDescriptorProfile(descriptor)
    const unsignedBytes = canonicalBytes.subarray(0, canonicalBytes.byteLength - 64)
    const payload = resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, unsignedBytes)
    const verified = await this.verifySignature({
      domainId: RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
      publicKey: b4a.from(descriptor.relayPublicKey),
      signature: b4a.from(descriptor.signature),
      payload: b4a.from(payload),
      canonicalBytes: b4a.from(canonicalBytes),
      descriptor: decodeExact(blindServiceDescriptorV1, canonicalBytes, 'descriptor bytes are not canonical'),
      signal
    })
    if (verified !== true) {
      closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION, 'descriptor signature verification failed')
    }
    descriptor = decodeExact(blindServiceDescriptorV1, canonicalBytes,
      'descriptor verifier mutated canonical descriptor authority')
    assertDurabilityHashes(descriptor)
    assertAdvertisedDescriptorProfile(descriptor)
    if (descriptor.identityTransition != null) await this._verifyIdentityTransition(descriptor.identityTransition, signal)
    return descriptor
  }

  async _verifyIdentityTransition (value, signal) {
    const transitionBytes = encodeCanonical(relayIdentityTransitionV1, value)
    const unsignedBytes = transitionBytes.subarray(0, transitionBytes.byteLength - 128)
    const payload = auxiliarySignaturePayload(AUXILIARY_SIGNATURE_DOMAIN_ID.IDENTITY_TRANSITION, unsignedBytes)
    for (const signer of ['old', 'new']) {
      const transition = decodeExact(relayIdentityTransitionV1, transitionBytes,
        'identity transition bytes are not canonical')
      const publicKey = signer === 'old' ? transition.oldRelayKey : transition.newRelayKey
      const signature = signer === 'old' ? transition.oldSignature : transition.newSignature
      const verified = await this.verifyIdentityTransitionSignature({
        domainId: AUXILIARY_SIGNATURE_DOMAIN_ID.IDENTITY_TRANSITION,
        signer,
        publicKey: b4a.from(publicKey),
        signature: b4a.from(signature),
        payload: b4a.from(payload),
        canonicalUnsignedBytes: b4a.from(unsignedBytes),
        canonicalBytes: b4a.from(transitionBytes),
        transition,
        signal
      })
      if (verified !== true) {
        closedError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION,
          `${signer} identity-transition signature verification failed`)
      }
    }
    decodeExact(relayIdentityTransitionV1, transitionBytes,
      'identity transition verifier mutated canonical authority')
  }

  activate (input, options = {}) {
    const canonicalBytes = ownedBytes(input, 'descriptor bytes')
    const activation = {
      signal: options.signal,
      emergencyGap: options.emergencyGap === true,
      trustedRestore: options.trustedRestore === true
    }
    return this._serialized(() => this._activate(canonicalBytes, activation))
  }

  async _activate (canonicalBytes, options) {
    if (this.#fault != null) closedError(this.#fault, 'descriptor state is faulted closed')
    const descriptor = await this._verifiedDescriptor(canonicalBytes, options.signal)
    const hash = serviceDescriptorHash(canonicalBytes)
    const now = currentEpoch(this.epochNow)
    if (descriptor.issuedEpoch > now) closedError(DESCRIPTOR_CLOSED_REASON.NOT_YET_VALID, 'descriptor is not yet valid')
    if (descriptor.expiresEpoch <= now) closedError(DESCRIPTOR_CLOSED_REASON.EXPIRED, 'descriptor is expired')

    let hadReadinessGap = false
    let lifecycleFence = this.#lifecycleFence
    let restored = false
    if (this.#currentRecord == null) {
      if (descriptor.descriptorSequence !== 0n || options.trustedRestore) {
        closedError(DESCRIPTOR_CLOSED_REASON.CHAIN_GAP,
          'non-genesis activation requires verified restoration, never a trusted boolean')
      }
      assertGenesis(descriptor)
    } else if (descriptor.descriptorSequence < this.#currentRecord.descriptorSequence) {
      this.#fault = DESCRIPTOR_CLOSED_REASON.ROLLBACK
      closedError(this.#fault, 'descriptor sequence rolled back')
    } else if (descriptor.descriptorSequence === this.#currentRecord.descriptorSequence) {
      if (!sameBytes(hash, this.#currentRecord.hash)) {
        this.#fault = DESCRIPTOR_CLOSED_REASON.FORK
        closedError(this.#fault, 'same-sequence descriptor fork detected')
      }
      return snapshotFor(this.#currentRecord)
    } else {
      try {
        const transition = assertTransition(this.#currentRecord, descriptor, {
          allowGap: this.allowEmergencyGaps && options.emergencyGap
        })
        hadReadinessGap = this.#currentRecord.hadReadinessGap || transition.readinessGap
        restored = this.#currentRecord.restored
        if (transition.lifecycleFenceChanged) lifecycleFence++
      } catch (error) {
        if (error instanceof DescriptorStateError) this.#fault = error.code
        throw error
      }
    }

    const record = recordFor(descriptor, canonicalBytes, hash, ++this.#generation,
      lifecycleFence, hadReadinessGap, restored)
    this.#lifecycleFence = lifecycleFence
    this._install(record)
    this._prune(now)
    return snapshotFor(record)
  }

  restore (input, options = {}) {
    if (!input || !Array.isArray(input.descriptorChainBytes) || input.descriptorChainBytes.length === 0 ||
        input.descriptorChainBytes.length > this.maxHistory) {
      return Promise.reject(new TypeError('descriptorChainBytes must contain 1..maxHistory entries'))
    }
    const descriptorChainBytes = input.descriptorChainBytes.map((entry, index) =>
      ownedBytes(entry, `descriptorChainBytes[${index}]`))
    const manifestBytes = input.manifestBytes == null
      ? null
      : ownedBytes(input.manifestBytes, 'manifestBytes')
    if (input.trustedRestore === true || options.trustedRestore === true) {
      return Promise.reject(new DescriptorStateError(DESCRIPTOR_CLOSED_REASON.RESTORE_UNVERIFIED,
        'trustedRestore booleans are not restoration evidence'))
    }
    return this._serialized(() => this._restore({ descriptorChainBytes, manifestBytes }, options.signal))
  }

  async _restore (input, signal) {
    if (this.#currentRecord != null || this.#fault != null) {
      closedError(DESCRIPTOR_CLOSED_REASON.RESTORE_UNVERIFIED,
        'restoration requires a new unfaulted descriptor state')
    }
    const pending = []
    let previous = null
    let lifecycleFence = 0
    let hadReadinessGap = false
    for (let index = 0; index < input.descriptorChainBytes.length; index++) {
      const canonicalBytes = input.descriptorChainBytes[index]
      const descriptor = await this._verifiedDescriptor(canonicalBytes, signal)
      const hash = serviceDescriptorHash(canonicalBytes)
      if (previous == null) {
        if (descriptor.descriptorSequence === 0n) assertGenesis(descriptor)
        else hadReadinessGap = true
      } else {
        const transition = assertTransition(previous, descriptor, { allowGap: this.allowEmergencyGaps })
        hadReadinessGap ||= transition.readinessGap
        if (transition.lifecycleFenceChanged) lifecycleFence++
      }
      const record = recordFor(descriptor, canonicalBytes, hash, ++this.#generation,
        lifecycleFence, hadReadinessGap, true)
      pending.push(record)
      previous = record
    }

    const first = decodeExact(blindServiceDescriptorV1, pending[0].canonicalBytes,
      'restored descriptor bytes are not canonical')
    const last = decodeExact(blindServiceDescriptorV1, pending[pending.length - 1].canonicalBytes,
      'restored descriptor bytes are not canonical')
    if (first.descriptorSequence !== 0n || input.manifestBytes != null) {
      if (!input.manifestBytes || !this.verifyRestoration) {
        closedError(DESCRIPTOR_CLOSED_REASON.RESTORE_UNVERIFIED,
          'non-genesis restoration requires a canonical MAC-verified store manifest')
      }
      const manifest = decodeExact(blindStoreManifestV1, input.manifestBytes,
        'store manifest bytes are not canonical')
      if (!manifestMatchesDescriptor(manifest, last, pending[pending.length - 1].hash)) {
        closedError(DESCRIPTOR_CLOSED_REASON.RESTORE_UNVERIFIED,
          'store manifest does not bind the restored descriptor/store/profile floor')
      }
      const evidence = await this.verifyRestoration({
        canonicalManifestBytes: b4a.from(input.manifestBytes),
        manifest: decodeExact(blindStoreManifestV1, input.manifestBytes, 'store manifest bytes are not canonical'),
        descriptorChainBytes: input.descriptorChainBytes.map(bytes => b4a.from(bytes)),
        descriptorSequenceFloor: last.descriptorSequence,
        descriptorHashFloor: b4a.from(pending[pending.length - 1].hash),
        relayPublicKey: b4a.from(last.relayPublicKey),
        storeId: b4a.from(last.storeId),
        durabilityProfileId: last.durability.profileId,
        durabilityContinuityHash: b4a.from(last.durabilityContinuityHash),
        durabilityProfileHash: b4a.from(last.durabilityProfileHash),
        signal
      })
      if (!evidence || evidence.verified !== true || evidence.fullStoreVerified !== true ||
          u64(evidence.descriptorSequenceFloor, 'restoration descriptorSequenceFloor') !== last.descriptorSequence ||
          !sameBytes(evidence.descriptorHashFloor, pending[pending.length - 1].hash) ||
          !sameBytes(evidence.relayPublicKey, last.relayPublicKey) ||
          !sameBytes(evidence.storeId, last.storeId) ||
          evidence.durabilityProfileId !== last.durability.profileId ||
          !sameBytes(evidence.durabilityContinuityHash, last.durabilityContinuityHash) ||
          !sameBytes(evidence.durabilityProfileHash, last.durabilityProfileHash)) {
        closedError(DESCRIPTOR_CLOSED_REASON.RESTORE_UNVERIFIED,
          'restoration verifier did not echo the exact recovered floor and continuity tuple')
      }
      decodeExact(blindStoreManifestV1, input.manifestBytes,
        'restoration verifier mutated manifest authority')
    }

    for (const record of pending) this._install(record)
    this.#lifecycleFence = lifecycleFence
    this._prune(currentEpoch(this.epochNow))
    return snapshotFor(this.#currentRecord)
  }

  _install (record) {
    this.#currentRecord = record
    this.#byHash.set(byteKey(record.hash), record)
    this.#bySequence.set(record.descriptorSequence.toString(), record)
  }

  _prune (now) {
    const floor = Math.max(0, now - this.retentionEpochs)
    const ordered = [...this.#bySequence.values()].sort((a, b) =>
      a.descriptorSequence < b.descriptorSequence ? -1 : a.descriptorSequence > b.descriptorSequence ? 1 : 0)
    while (ordered.length > this.maxHistory ||
      (ordered.length > 1 && ordered[0].expiresEpoch < floor)) {
      const removed = ordered.shift()
      this.#bySequence.delete(removed.descriptorSequence.toString())
      this.#byHash.delete(byteKey(removed.hash))
    }
  }

  state () {
    if (this.#fault != null) return Object.freeze({ kind: DESCRIPTOR_STATE_KIND.CLOSED, reason: this.#fault })
    if (this.#currentRecord == null) {
      return Object.freeze({ kind: DESCRIPTOR_STATE_KIND.CLOSED, reason: DESCRIPTOR_CLOSED_REASON.NO_DESCRIPTOR })
    }
    const now = currentEpoch(this.epochNow)
    if (this.#currentRecord.issuedEpoch > now) {
      return Object.freeze({ kind: DESCRIPTOR_STATE_KIND.CLOSED, reason: DESCRIPTOR_CLOSED_REASON.NOT_YET_VALID })
    }
    if (this.#currentRecord.expiresEpoch <= now) {
      return Object.freeze({ kind: DESCRIPTOR_STATE_KIND.CLOSED, reason: DESCRIPTOR_CLOSED_REASON.EXPIRED })
    }
    if (this.#currentRecord.storeLifecycleState === STORE_LIFECYCLE_STATE.RETIRED) {
      return Object.freeze({ kind: DESCRIPTOR_STATE_KIND.CLOSED, reason: DESCRIPTOR_CLOSED_REASON.RETIRED })
    }
    return Object.freeze({ kind: DESCRIPTOR_STATE_KIND.READY, snapshot: snapshotFor(this.#currentRecord) })
  }

  requireCurrent () {
    const state = this.state()
    if (state.kind !== DESCRIPTOR_STATE_KIND.READY) closedError(state.reason, 'no current usable descriptor')
    return state.snapshot
  }

  historical (hash) {
    hash = asBytes(hash, 'descriptor hash', 32)
    const record = this.#byHash.get(byteKey(hash))
    return record == null ? null : snapshotFor(record)
  }

  selected (hash = null) {
    if (hash == null) return this.requireCurrent()
    return this.historical(hash)
  }

  _recordForSnapshot (snapshot) {
    if (!snapshot || !snapshot.hash) return null
    const record = this.#byHash.get(byteKey(asBytes(snapshot.hash, 'snapshot hash', 32)))
    if (!record || record.descriptorSequence !== snapshot.descriptorSequence ||
        record.generation !== snapshot.generation || record.lifecycleFence !== snapshot.lifecycleFence) return null
    return record
  }

  remainsUsable (snapshot) {
    if (this.#fault != null) return false
    const record = this._recordForSnapshot(snapshot)
    if (!record || !this.#currentRecord || record.lifecycleFence !== this.#currentRecord.lifecycleFence) return false
    const now = currentEpoch(this.epochNow)
    if (record.issuedEpoch > now || record.expiresEpoch <= now ||
        this.#currentRecord.storeLifecycleState === STORE_LIFECYCLE_STATE.RETIRED) return false
    return true
  }

  resultBinding (snapshot, restoreEvidence = {}) {
    const record = this._recordForSnapshot(snapshot)
    if (!record) throw new TypeError('a retained descriptor snapshot is required')
    const descriptor = decodeExact(blindServiceDescriptorV1, record.canonicalBytes,
      'stored descriptor bytes are not canonical')
    const restoreEvidenceHeadSequence = restoreEvidence.restoreEvidenceHeadSequence == null
      ? 0n
      : u64(restoreEvidence.restoreEvidenceHeadSequence, 'restoreEvidenceHeadSequence')
    const restoreEvidenceHeadHash = restoreEvidence.restoreEvidenceHeadHash == null
      ? ZERO32
      : asBytes(restoreEvidence.restoreEvidenceHeadHash, 'restoreEvidenceHeadHash', 32)
    return Object.freeze({
      version: 1,
      relayPublicKey: b4a.from(descriptor.relayPublicKey),
      storeId: b4a.from(descriptor.storeId),
      descriptorSequence: descriptor.descriptorSequence,
      descriptorHash: b4a.from(record.hash),
      durabilityProfileId: descriptor.durability.profileId,
      durabilityContinuityHash: b4a.from(descriptor.durabilityContinuityHash),
      durabilityProfileHash: b4a.from(descriptor.durabilityProfileHash),
      restoreEvidenceHeadSequence,
      restoreEvidenceHeadHash: b4a.from(restoreEvidenceHeadHash),
      externalCommitWitness: null
    })
  }
}

export function assertRelayResultBinding (actual, expected) {
  if (!actual || !expected || actual.version !== 1 || actual.version !== expected.version ||
      actual.descriptorSequence !== expected.descriptorSequence ||
      actual.durabilityProfileId !== expected.durabilityProfileId ||
      actual.restoreEvidenceHeadSequence !== expected.restoreEvidenceHeadSequence) {
    throw new DescriptorStateError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION,
      'result binding scalar fields do not match the operation descriptor snapshot')
  }
  for (const field of [
    'relayPublicKey',
    'storeId',
    'descriptorHash',
    'durabilityContinuityHash',
    'durabilityProfileHash',
    'restoreEvidenceHeadHash'
  ]) {
    if (!actual[field] || !expected[field] || !sameBytes(actual[field], expected[field])) {
      throw new DescriptorStateError(DESCRIPTOR_CLOSED_REASON.INVALID_TRANSITION,
        `result binding ${field} does not match the operation descriptor snapshot`)
    }
  }
}
