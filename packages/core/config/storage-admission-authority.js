import { EventEmitter } from 'events'
import { randomBytes } from 'crypto'
import {
  evaluateStorageAdmission,
  finiteNonNegativeInteger,
  positiveStorageBound,
  sampleStorageFilesystem
} from './storage-cap.js'

export const STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES = 64 * 1024
export const STORAGE_SHARE_BUNDLE_MAX_BYTES = 1024 * 1024
export const STORAGE_DRIVE_AUXILIARY_ALLOWANCE_BYTES = 2 * 1024 * 1024

function commitmentMetadataOverhead (kind, explicit) {
  if (explicit !== undefined) return finiteNonNegativeInteger(explicit)
  if (kind === 'drive') {
    return STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES + STORAGE_DRIVE_AUXILIARY_ALLOWANCE_BYTES
  }
  return kind === 'core' ? STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES : 0
}

function cloneRecord (record) {
  return record ? { ...record } : null
}

function admissionFailure (reason, details = {}) {
  return {
    allowed: false,
    reason,
    availableBytes: 0,
    ...details
  }
}

function sameFilesystemIdentity (left, right) {
  for (const field of ['storagePath', 'realpath', 'device', 'inode']) {
    if (left?.[field] == null && right?.[field] == null) continue
    if (String(left?.[field]) !== String(right?.[field])) return false
  }
  return true
}

function physicalStorageIdentity (sample) {
  if (!sample || sample.ok !== true) return null
  const identity = {}
  for (const field of ['storagePath', 'realpath', 'device', 'inode']) {
    if (sample[field] == null || String(sample[field]).length === 0) return null
    identity[field] = String(sample[field])
  }
  return identity
}

function physicalEnforcementError (reason, cause = null) {
  const err = new Error('physical storage enforcement unavailable: ' + reason)
  err.code = 'STORAGE_PHYSICAL_ENFORCEMENT_UNAVAILABLE'
  err.reason = reason
  if (cause) err.cause = cause
  return err
}

function exactPhysicalIdentity (left, right) {
  if (!left || !right) return false
  return ['storagePath', 'realpath', 'device', 'inode'].every(field =>
    typeof left[field] === 'string' && left[field].length > 0 && left[field] === right[field]
  )
}

function validPhysicalLease (lease, request, previous) {
  if (!lease || typeof lease !== 'object' ||
      lease.operationId !== request.operationId ||
      !exactPhysicalIdentity(lease.rootIdentity, request.storageIdentity)) return false
  for (const field of ['providerId', 'scopeId', 'leaseId', 'operationId']) {
    if (typeof lease[field] !== 'string' || lease[field].length === 0) return false
  }
  if (!Number.isSafeInteger(lease.generation) || lease.generation <= 0 ||
      !Number.isSafeInteger(lease.hardLimitBytes) ||
      lease.hardLimitBytes < request.observedAllocatedBytes ||
      lease.hardLimitBytes > request.ceilingAllocatedBytes) return false
  if (previous && (lease.providerId !== previous.providerId ||
      lease.scopeId !== previous.scopeId || lease.leaseId !== previous.leaseId ||
      !exactPhysicalIdentity(lease.rootIdentity, previous.rootIdentity) ||
      lease.generation <= previous.generation ||
      lease.hardLimitBytes > previous.hardLimitBytes)) return false
  return true
}

function validPhysicalAttestation (attestation, opts) {
  const {
    identity,
    requestedLimit,
    previous,
    expectedOperationId,
    requireGenerationAdvance,
    requestedAt,
    now,
    maxAgeMs,
    expectedLease
  } = opts
  if (!attestation || attestation.schemaVersion !== 1 || attestation.active !== true ||
      attestation.exclusive !== true || !identity ||
      !exactPhysicalIdentity(attestation.rootIdentity, identity)) return false
  for (const field of ['providerId', 'scopeId', 'leaseId', 'operationId']) {
    if (typeof attestation[field] !== 'string' || attestation[field].length === 0) return false
  }
  const used = attestation.usedAllocatedBytes
  const hard = attestation.hardLimitBytes
  const generation = attestation.generation
  const checkedAt = attestation.checkedAt
  if (!Number.isSafeInteger(used) || used < 0 ||
      !Number.isSafeInteger(hard) || hard <= 0 ||
      !Number.isSafeInteger(generation) || generation <= 0 ||
      !Number.isSafeInteger(checkedAt) ||
      used > hard || hard > requestedLimit ||
      attestation.operationId !== expectedOperationId ||
      checkedAt < requestedAt || checkedAt > now + 1000 || now - checkedAt > maxAgeMs) return false
  if (expectedLease && (attestation.providerId !== expectedLease.providerId ||
      attestation.scopeId !== expectedLease.scopeId ||
      attestation.leaseId !== expectedLease.leaseId ||
      attestation.operationId !== expectedLease.operationId ||
      attestation.generation !== expectedLease.generation ||
      attestation.hardLimitBytes !== expectedLease.hardLimitBytes ||
      !exactPhysicalIdentity(attestation.rootIdentity, expectedLease.rootIdentity))) return false
  if (previous) {
    if (attestation.providerId !== previous.providerId ||
        attestation.scopeId !== previous.scopeId ||
        attestation.leaseId !== previous.leaseId ||
        !exactPhysicalIdentity(attestation.rootIdentity, previous.rootIdentity) ||
        hard > previous.hardLimitBytes ||
        (requireGenerationAdvance
          ? generation <= previous.generation
          : generation !== previous.generation)) {
      return false
    }
  }
  return true
}

/**
 * One atomic authority for every storage-producing ingress.
 *
 * A record's `boundBytes` is the maximum total footprint accepted for that
 * pin. Admission charges the complete durable bound plus its fixed metadata /
 * auxiliary allowance; exact tree usage is measured independently and never
 * discounts that promise. This conservative double accounting prevents stale
 * attribution, truncation, compaction, or an unchanged statfs free-space sample
 * from promising the same bytes twice. Pending reservations are installed
 * synchronously before reserve() returns; every later caller observes them even
 * while durable persistence is awaiting I/O.
 */
export class StorageAdmissionAuthority extends EventEmitter {
  constructor (config, opts = {}) {
    super()
    this.config = config
    this.getUsedBytes = typeof opts.getUsedBytes === 'function' ? opts.getUsedBytes : () => 0
    this.getActualBytes = typeof opts.getActualBytes === 'function' ? opts.getActualBytes : () => 0
    this.sampleFilesystem = typeof opts.sampleFilesystem === 'function'
      ? opts.sampleFilesystem
      : () => sampleStorageFilesystem(this.config)
    this.sampleMaxAgeMs = positiveStorageBound(opts.sampleMaxAgeMs) || 60_000
    this._records = new Map()
    this._recoveryPending = new Set(opts.recoveryKinds || ['drives', 'cores'])
    this._tokenSequence = 0
    this._lastFilesystemSample = null
    this._fatalReason = null
    this._acceptingMutations = true
    this._mutationStopReason = null
    this._mutations = new Set()
    this._keyMutationTails = new Map()
    this._ownedHandoffs = new WeakMap()
    this._ownedLeases = new Map()
    this.physicalEnforcer = opts.physicalEnforcer || null
    this._physicalLease = null
    this._physicalAttestation = null
    this._physicalMutationTail = Promise.resolve()
    this._physicalMutations = new Map()
    this._physicalTokenSequence = 0
  }

  setConfig (config) {
    this.config = config
  }

  setResolvers (opts = {}) {
    if (Object.prototype.hasOwnProperty.call(opts, 'physicalEnforcer')) {
      const next = opts.physicalEnforcer || null
      if (next !== this.physicalEnforcer) {
        const err = new Error('physical storage enforcer changes require restart')
        err.code = 'PHYSICAL_ENFORCER_RESTART_REQUIRED'
        throw err
      }
    }
    if (typeof opts.getUsedBytes === 'function') this.getUsedBytes = opts.getUsedBytes
    if (typeof opts.getActualBytes === 'function') this.getActualBytes = opts.getActualBytes
    if (typeof opts.sampleFilesystem === 'function') this.sampleFilesystem = opts.sampleFilesystem
  }

  get physicalEnforcementActive () {
    return this._validPhysicalEnforcer() && !!this._physicalAttestation &&
      this._physicalAttestation.active === true
  }

  physicalEnforcementSnapshot () {
    return this._physicalAttestation
      ? { ...this._physicalAttestation, rootIdentity: { ...this._physicalAttestation.rootIdentity } }
      : null
  }

  async activatePhysicalEnforcement (opts = {}) {
    let validProvider
    try {
      validProvider = this._probePhysicalEnforcer()
    } catch (cause) {
      this.failClosed('storage-physical-enforcement-invalid')
      throw physicalEnforcementError('physical-enforcer-capability-failed', cause)
    }
    if (!validProvider) {
      this._physicalAttestation = null
      return { active: false, reason: 'physical-enforcer-unavailable' }
    }
    try {
      const attestation = await this._installAndInspectPhysicalCeiling(opts.purpose || 'startup')
      return { active: true, attestation: { ...attestation } }
    } catch (err) {
      this.failClosed('storage-physical-enforcement-invalid')
      throw err
    }
  }

  runPhysicalMutation (opts, run) {
    const operation = this._physicalMutationTail.catch(() => {}).then(async () => {
      if (typeof run !== 'function') throw new TypeError('physical mutation callback is required')
      let validProvider
      try {
        validProvider = this._probePhysicalEnforcer()
      } catch (cause) {
        this.failClosed('storage-physical-enforcement-invalid')
        throw physicalEnforcementError('physical-enforcer-capability-failed', cause)
      }
      if (!validProvider || !this.physicalEnforcementActive) {
        throw physicalEnforcementError('physical-enforcer-unavailable')
      }
      if (this._fatalReason || !this._acceptingMutations) {
        throw physicalEnforcementError(this._fatalReason || this._mutationStopReason || 'storage-mutations-stopping')
      }
      const phase = opts?.phase === 'recovery' ? 'recovery' : 'runtime'
      if (phase === 'runtime' && !this.recoveryReady) {
        throw physicalEnforcementError('storage-recovery-inventory-pending')
      }
      let attestation
      try {
        attestation = await this._installAndInspectPhysicalCeiling(opts?.purpose || 'app-registry-mutation')
      } catch (err) {
        this.failClosed('storage-physical-enforcement-invalid')
        throw err
      }
      if (attestation.usedAllocatedBytes >= attestation.hardLimitBytes) {
        throw physicalEnforcementError('physical-ceiling-reached')
      }
      const tokenId = ++this._physicalTokenSequence
      const token = Object.freeze({
        tokenId,
        purpose: opts?.purpose || 'app-registry-mutation',
        phase,
        generation: attestation.generation,
        hardLimitBytes: attestation.hardLimitBytes
      })
      this._physicalMutations.set(tokenId, token)
      let result
      let mutationError = null
      try {
        result = await run(token)
      } catch (err) {
        mutationError = err
      }
      let settlementError = null
      try {
        await this._inspectPhysicalCeiling(attestation.hardLimitBytes)
      } catch (err) {
        settlementError = err
        this.failClosed('storage-physical-enforcement-ambiguous')
      } finally {
        this._physicalMutations.delete(tokenId)
      }
      if (settlementError) {
        settlementError.mutationCause = mutationError
        throw settlementError
      }
      if (mutationError) throw mutationError
      return result
    })
    this._physicalMutationTail = operation.catch(() => {})
    return this.trackMutation(operation)
  }

  _probePhysicalEnforcer () {
    return !!this.physicalEnforcer && this.physicalEnforcer.schemaVersion === 1 &&
      typeof this.physicalEnforcer.installAbsoluteCeiling === 'function' &&
      typeof this.physicalEnforcer.inspectAbsoluteCeiling === 'function'
  }

  _validPhysicalEnforcer () {
    try { return this._probePhysicalEnforcer() } catch (_) { return false }
  }

  async _installAndInspectPhysicalCeiling (purpose) {
    const sample = this.filesystemSample({ refresh: true })
    if (!sample || sample.ok !== true) {
      throw physicalEnforcementError(sample?.reason || 'storage-filesystem-sample-unavailable')
    }
    const storageIdentity = physicalStorageIdentity(sample)
    if (!storageIdentity) throw physicalEnforcementError('physical-storage-identity-invalid')
    let measuredAllocatedBytes
    try {
      measuredAllocatedBytes = this.getUsedBytes()
    } catch (cause) {
      throw physicalEnforcementError('physical-usage-measurement-failed', cause)
    }
    const observedAllocatedBytes = finiteNonNegativeInteger(measuredAllocatedBytes)
    const configuredLimit = positiveStorageBound(this.config?.maxStorageBytes)
    const freeBytes = finiteNonNegativeInteger(sample.freeBytes)
    const reserveBytes = finiteNonNegativeInteger(sample.reserveBytes)
    if (observedAllocatedBytes === null || configuredLimit === null || freeBytes === null || reserveBytes === null) {
      throw physicalEnforcementError('physical-ceiling-input-invalid')
    }
    const physicalHeadroom = Math.max(0, freeBytes - reserveBytes)
    if (!Number.isSafeInteger(observedAllocatedBytes + physicalHeadroom)) {
      throw physicalEnforcementError('physical-ceiling-input-invalid')
    }
    const existingLimit = positiveStorageBound(this._physicalAttestation?.hardLimitBytes)
    if (existingLimit !== null && existingLimit < observedAllocatedBytes) {
      throw physicalEnforcementError('physical-ceiling-exceeded')
    }
    let ceilingAllocatedBytes = Math.max(observedAllocatedBytes, Math.min(
      configuredLimit,
      observedAllocatedBytes + physicalHeadroom
    ))
    if (existingLimit !== null) ceilingAllocatedBytes = Math.min(ceilingAllocatedBytes, existingLimit)
    if (!Number.isSafeInteger(ceilingAllocatedBytes) || ceilingAllocatedBytes < observedAllocatedBytes ||
        ceilingAllocatedBytes <= 0) {
      throw physicalEnforcementError('physical-ceiling-input-invalid')
    }
    const requestedAt = Date.now()
    const request = {
      schemaVersion: 1,
      operationId: `physical-${++this._physicalTokenSequence}-${randomBytes(16).toString('hex')}`,
      requestedAt,
      purpose,
      storageIdentity,
      observedAllocatedBytes,
      filesystem: {
        totalBytes: sample.totalBytes,
        freeBytes,
        reserveBytes,
        checkedAt: sample.checkedAt
      },
      ceilingAllocatedBytes,
      previousHardLimitBytes: existingLimit
    }
    let lease
    try {
      lease = await this.physicalEnforcer.installAbsoluteCeiling(request, this._physicalLease)
    } catch (cause) {
      throw physicalEnforcementError('physical-enforcer-install-failed', cause)
    }
    if (!validPhysicalLease(lease, request, this._physicalAttestation)) {
      throw physicalEnforcementError('physical-enforcer-lease-invalid')
    }
    const attestation = await this._inspectPhysicalCeiling(ceilingAllocatedBytes, {
      lease,
      expectedIdentity: request.storageIdentity,
      expectedOperationId: request.operationId,
      requestedAt,
      previous: this._physicalAttestation,
      requireGenerationAdvance: true,
      expectedLease: lease,
      commit: false
    })
    this._physicalLease = lease
    this._physicalAttestation = attestation
    return attestation
  }

  async _inspectPhysicalCeiling (requestedLimit, opts = {}) {
    const lease = opts.lease || this._physicalLease
    const previous = Object.prototype.hasOwnProperty.call(opts, 'previous')
      ? opts.previous
      : this._physicalAttestation
    if (!lease) throw physicalEnforcementError('physical-enforcer-lease-missing')
    let attestation
    try {
      attestation = await this.physicalEnforcer.inspectAbsoluteCeiling(lease)
    } catch (cause) {
      throw physicalEnforcementError('physical-enforcer-inspect-failed', cause)
    }
    const sample = this.filesystemSample({ refresh: true })
    const identity = physicalStorageIdentity(sample)
    if (!identity || (opts.expectedIdentity && !exactPhysicalIdentity(identity, opts.expectedIdentity))) {
      throw physicalEnforcementError('physical-storage-identity-changed')
    }
    const expectedOperationId = opts.expectedOperationId || previous?.operationId
    const requestedAt = Number.isSafeInteger(opts.requestedAt)
      ? opts.requestedAt
      : previous?.checkedAt
    if (!validPhysicalAttestation(attestation, {
      identity,
      requestedLimit,
      previous,
      expectedOperationId,
      requireGenerationAdvance: opts.requireGenerationAdvance === true,
      requestedAt,
      now: Date.now(),
      maxAgeMs: this.sampleMaxAgeMs,
      expectedLease: lease
    })) {
      throw physicalEnforcementError('physical-enforcer-attestation-invalid')
    }
    let measuredAllocatedBytes
    try {
      measuredAllocatedBytes = this.getUsedBytes()
    } catch (cause) {
      throw physicalEnforcementError('physical-usage-measurement-failed', cause)
    }
    const observedAllocatedBytes = finiteNonNegativeInteger(measuredAllocatedBytes)
    if (observedAllocatedBytes === null || attestation.usedAllocatedBytes !== observedAllocatedBytes) {
      throw physicalEnforcementError('physical-enforcer-usage-mismatch')
    }
    const frozen = Object.freeze({
      ...attestation,
      rootIdentity: Object.freeze({ ...attestation.rootIdentity })
    })
    if (opts.commit !== false) this._physicalAttestation = frozen
    return frozen
  }

  static driveKey (appKey) { return `drive:${appKey}` }
  static coreKey (coreKey) { return `core:${coreKey}` }

  refreshFilesystem () {
    let sample
    try {
      sample = this.sampleFilesystem()
    } catch (err) {
      sample = { ok: false, reason: 'storage-filesystem-sample-error', error: err && err.message, checkedAt: Date.now() }
    }
    if (!sample || sample.ok !== true) {
      this._lastFilesystemSample = {
        ok: false,
        reason: sample?.reason || 'storage-filesystem-sample-unavailable',
        checkedAt: Number.isSafeInteger(sample?.checkedAt) ? sample.checkedAt : Date.now()
      }
      this.emit('filesystem-invalid', this._lastFilesystemSample)
      return this._lastFilesystemSample
    }
    this._lastFilesystemSample = { ...sample }
    return this._lastFilesystemSample
  }

  filesystemSample ({ refresh = false, now = Date.now() } = {}) {
    const sample = refresh ? this.refreshFilesystem() : this._lastFilesystemSample
    if (!sample || sample.ok !== true) return admissionFailure(sample?.reason || 'storage-filesystem-sample-unavailable')
    if (!Number.isSafeInteger(sample.checkedAt) || now - sample.checkedAt > this.sampleMaxAgeMs || sample.checkedAt > now + 1000) {
      return admissionFailure('storage-filesystem-sample-stale', { checkedAt: sample.checkedAt })
    }
    return sample
  }

  markRecoveryReady (kind) {
    this._recoveryPending.delete(kind)
    return this._recoveryPending.size === 0
  }

  get recoveryReady () {
    return this._recoveryPending.size === 0
  }

  recoveryPending () {
    return [...this._recoveryPending].sort()
  }

  beginRecovery (kinds = ['drives', 'cores']) {
    this._records.clear()
    this._ownedLeases.clear()
    this._recoveryPending = new Set(kinds)
    this._fatalReason = null
    this.openMutations()
  }

  openMutations () {
    this._acceptingMutations = true
    this._mutationStopReason = null
  }

  closeMutations (reason = 'storage-mutations-stopping') {
    this._acceptingMutations = false
    this._mutationStopReason = reason
  }

  runMutation (run) {
    const admission = this.mutationAdmission()
    if (!admission.allowed) {
      const err = new Error(admission.reason)
      err.code = 'STORAGE_MUTATIONS_STOPPING'
      return Promise.reject(err)
    }
    let operation
    try {
      operation = Promise.resolve().then(run)
    } catch (err) {
      operation = Promise.reject(err)
    }
    return this.trackMutation(operation)
  }

  trackMutation (operation) {
    operation = Promise.resolve(operation)
    this._mutations.add(operation)
    operation.then(
      () => this._mutations.delete(operation),
      () => this._mutations.delete(operation)
    )
    return operation
  }

  runKeyMutation (key, run) {
    if (!this._acceptingMutations) {
      const err = new Error(this._mutationStopReason || 'storage mutations are stopping')
      err.code = 'STORAGE_MUTATIONS_STOPPING'
      return Promise.reject(err)
    }
    const previous = this._keyMutationTails.get(key) || Promise.resolve()
    const operation = previous.catch(() => {}).then(run)
    const tail = operation.catch(() => {})
    this._keyMutationTails.set(key, tail)
    tail.finally(() => {
      if (this._keyMutationTails.get(key) === tail) this._keyMutationTails.delete(key)
    })
    this._mutations.add(operation)
    operation.then(
      () => this._mutations.delete(operation),
      () => this._mutations.delete(operation)
    )
    return operation
  }

  async drainMutations (opts = {}) {
    const timeoutMs = positiveStorageBound(opts.timeoutMs)
    const deadline = timeoutMs === null ? null : Date.now() + timeoutMs
    while (this._mutations.size > 0) {
      const pending = Promise.allSettled([...this._mutations])
      if (deadline === null) {
        await pending
        continue
      }
      const remaining = deadline - Date.now()
      if (remaining <= 0) {
        const err = new Error('storage mutation drain timeout')
        err.code = 'STORAGE_MUTATION_DRAIN_TIMEOUT'
        throw err
      }
      let timer = null
      try {
        await Promise.race([
          pending,
          new Promise((_resolve, reject) => {
            timer = setTimeout(() => {
              const err = new Error('storage mutation drain timeout')
              err.code = 'STORAGE_MUTATION_DRAIN_TIMEOUT'
              reject(err)
            }, remaining)
          })
        ])
      } finally {
        if (timer) clearTimeout(timer)
      }
    }
  }

  get acceptingMutations () {
    return this._acceptingMutations
  }

  get fatalReason () {
    return this._fatalReason
  }

  mutationAdmission () {
    if (this._fatalReason) return admissionFailure(this._fatalReason)
    if (!this._acceptingMutations) return admissionFailure(this._mutationStopReason || 'storage-mutations-stopping')
    return { allowed: true }
  }

  canAcknowledge (key) {
    if (this._fatalReason) return false
    const record = this._records.get(key)
    return !!record && record.state === 'committed' && record.boundBytes !== null
  }

  /** Register durable state during startup without treating it as new adoption. */
  adoptRecovery (key, boundBytes, opts = {}) {
    const bound = positiveStorageBound(boundBytes)
    const kind = opts.kind || key.split(':', 1)[0]
    const overheadBytes = commitmentMetadataOverhead(kind, opts.metadataOverheadBytes)
    const actual = opts.actualBytes == null ? null : finiteNonNegativeInteger(opts.actualBytes)
    if (overheadBytes === null || (bound !== null && (actual === null ? opts.actualBytes != null : actual > bound))) {
      this.failClosed('storage-recovery-actual-exceeds-commitment')
      return null
    }
    this._records.set(key, bound === null
      ? {
          key,
          kind,
          boundBytes: null,
          overheadBytes,
          state: 'unknown-recovery',
          recovery: true,
          tokenId: null,
          ...(actual !== null ? { actualBytesOverride: actual } : {})
        }
      : {
          key,
          kind,
          boundBytes: bound,
          overheadBytes,
          state: 'committed',
          recovery: true,
          tokenId: null
        })
    return cloneRecord(this._records.get(key))
  }

  _actualBytes (key, record) {
    const override = finiteNonNegativeInteger(record?.actualBytesOverride)
    if (override !== null) return override
    let actual = 0
    try { actual = finiteNonNegativeInteger(this.getActualBytes(key, record)) } catch (_) { actual = null }
    if (actual === null) return 0
    return actual
  }

  _remainingBytes (key, record) {
    if (!record || record.boundBytes === null) return null
    const actual = this._actualBytes(key, record)
    if (actual > record.boundBytes) {
      this.failClosed('storage-actual-exceeds-commitment')
      return null
    }
    // Exact tree usage is sampled independently on every admission. Cached
    // per-drive/per-core attribution is not a safe lower bound: forks,
    // truncation, compaction, and hole clearing can shrink the tree while a
    // paced cache or cumulative counter stays high. Never subtract such an
    // attribution from a durable promise. Charging the full bound as debt is
    // deliberately conservative but cannot understate future growth.
    const overheadBytes = finiteNonNegativeInteger(record.overheadBytes)
    if (overheadBytes === null || !Number.isSafeInteger(record.boundBytes + overheadBytes)) return null
    return record.boundBytes + overheadBytes
  }

  _committedRemainder ({ excluding = null } = {}) {
    let total = 0
    for (const [key, record] of this._records) {
      if (key === excluding) continue
      const remaining = this._remainingBytes(key, record)
      if (remaining === null) return null
      total += remaining
      if (!Number.isSafeInteger(total)) return null
    }
    return total
  }

  admission (additionalBytes = 0, opts = {}) {
    const additional = finiteNonNegativeInteger(additionalBytes)
    if (additional === null) return admissionFailure('storage-bound-invalid')
    if (this._fatalReason) return admissionFailure(this._fatalReason)
    if (!this.recoveryReady) {
      return admissionFailure('storage-recovery-inventory-pending', { pending: this.recoveryPending() })
    }
    const sample = this.filesystemSample({ refresh: opts.refresh !== false })
    if (sample.ok !== true) return sample

    const committedRemainder = this._committedRemainder({ excluding: opts.excluding || null })
    if (committedRemainder === null) return admissionFailure('storage-commitment-unknown')
    const measuredUsed = finiteNonNegativeInteger(this.getUsedBytes())
    if (measuredUsed === null) return admissionFailure('storage-usage-invalid')
    // The exact tree walk may be long. Re-sample after it and bind both sides
    // to the same identity so a same-device mount/root replacement cannot mix
    // capacity from one tree with usage from another.
    const finalSample = this.refreshFilesystem()
    if (!finalSample || finalSample.ok !== true) return admissionFailure(finalSample?.reason || 'storage-filesystem-sample-unavailable')
    if (!sameFilesystemIdentity(sample, finalSample)) {
      return admissionFailure('storage-filesystem-changed-during-usage-measurement')
    }
    const usedBytes = measuredUsed + committedRemainder
    if (!Number.isSafeInteger(usedBytes)) return admissionFailure('storage-usage-invalid')
    return evaluateStorageAdmission(this.config, {
      usedBytes,
      additionalBytes: additional,
      diskInfo: finalSample,
      committedBytes: committedRemainder
    })
  }

  reserve (key, boundBytes, opts = {}) {
    if (!this._acceptingMutations) return admissionFailure(this._mutationStopReason || 'storage-mutations-stopping')
    if (!key || typeof key !== 'string') return admissionFailure('storage-reservation-key-invalid')
    const bound = positiveStorageBound(boundBytes)
    if (bound === null) return admissionFailure('storage-bound-invalid')

    const previous = this._records.get(key) || null
    const kind = opts.kind || previous?.kind || key.split(':', 1)[0]
    const overheadBytes = commitmentMetadataOverhead(kind, opts.metadataOverheadBytes)
    if (overheadBytes === null || !Number.isSafeInteger(bound + overheadBytes)) {
      return admissionFailure('storage-overhead-invalid')
    }
    if (previous && previous.state === 'reserved') {
      return admissionFailure('storage-reservation-in-progress')
    }
    if (previous && previous.state === 'unknown-recovery' && opts.authoritativeSizeBytes == null) {
      return admissionFailure('storage-commitment-unknown')
    }
    const previousBound = positiveStorageBound(previous?.boundBytes)
    if (previousBound !== null && bound < previousBound) {
      return admissionFailure('storage-bound-shrink-requires-release', {
        previousBoundBytes: previousBound,
        boundBytes: bound
      })
    }

    const authoritativeSize = opts.authoritativeSizeBytes == null
      ? null
      : finiteNonNegativeInteger(opts.authoritativeSizeBytes)
    if (opts.authoritativeSizeBytes != null && (authoritativeSize === null || authoritativeSize > bound)) {
      return admissionFailure('storage-bound-below-actual', {
        actualBytes: authoritativeSize,
        boundBytes: bound
      })
    }

    const measuredActual = opts.measuredActualBytes == null
      ? (authoritativeSize === null ? 0 : authoritativeSize)
      : finiteNonNegativeInteger(opts.measuredActualBytes)
    if (measuredActual === null || measuredActual > bound) {
      return admissionFailure('storage-bound-below-actual', { actualBytes: measuredActual, boundBytes: bound })
    }
    // Capacity debt is the whole commitment. `measuredActual` is retained for
    // validation/diagnostics only and is never subtracted from admission.
    const newRemaining = bound + overheadBytes
    const admission = this.admission(newRemaining, { excluding: key, refresh: true })
    if (!admission.allowed) return admission

    const tokenId = ++this._tokenSequence
    const record = {
      key,
      kind,
      boundBytes: bound,
      overheadBytes,
      state: 'reserved',
      recovery: false,
      tokenId,
      measuredActualBytes: measuredActual
    }
    this._records.set(key, record)
    return {
      allowed: true,
      key,
      tokenId,
      boundBytes: bound,
      previous: cloneRecord(previous),
      actualBytes: measuredActual,
      reservedBytes: newRemaining,
      admission
    }
  }

  commit (token, opts = {}) {
    const record = token && this._records.get(token.key)
    if (!record || record.state !== 'reserved' || record.tokenId !== token.tokenId) {
      this._fatalReason = 'storage-reservation-authority-invariant-failed'
      return false
    }
    const previousBound = positiveStorageBound(token.previous?.boundBytes) || 0
    const committedBound = opts.boundBytes == null ? record.boundBytes : positiveStorageBound(opts.boundBytes)
    const actualBytes = opts.actualBytes == null ? null : finiteNonNegativeInteger(opts.actualBytes)
    if (committedBound === null || committedBound > record.boundBytes || committedBound < previousBound ||
        (opts.actualBytes != null && (actualBytes === null || actualBytes > committedBound))) {
      this._fatalReason = 'storage-reservation-authority-invariant-failed'
      return false
    }
    record.boundBytes = committedBound
    if (actualBytes !== null) record.actualBytesOverride = actualBytes
    record.state = 'committed'
    record.tokenId = null
    record.recovery = false
    delete record.measuredActualBytes
    return true
  }

  owns (token) {
    const record = token && this._records.get(token.key)
    return !!record && record.state === 'reserved' && record.tokenId === token.tokenId
  }

  failClosed (reason = 'storage-reservation-authority-invariant-failed') {
    this._fatalReason = reason
  }

  reconcileActual (key, actualBytes) {
    const record = this._records.get(key)
    const actual = finiteNonNegativeInteger(actualBytes)
    if (!record || record.state !== 'committed' || record.boundBytes === null ||
        actual === null || actual > record.boundBytes) {
      this.failClosed('storage-actual-exceeds-commitment')
      return false
    }
    const previous = finiteNonNegativeInteger(record.actualBytesOverride) || 0
    record.actualBytesOverride = Math.max(previous, actual)
    return true
  }

  issueOwnedHandoff (key) {
    const record = this._records.get(key)
    if (this._fatalReason || !this._acceptingMutations || this._ownedLeases.has(key) ||
        !record || record.state !== 'committed' || record.boundBytes === null) return null
    const handoff = Object.freeze({})
    this._ownedHandoffs.set(handoff, key)
    this._ownedLeases.set(key, handoff)
    return handoff
  }

  validateOwnedHandoff (handoff, key = null) {
    if (!handoff || typeof handoff !== 'object' || this._fatalReason || !this._acceptingMutations) return false
    const ownedKey = this._ownedHandoffs.get(handoff)
    if (!ownedKey || this._ownedLeases.get(ownedKey) !== handoff || (key !== null && ownedKey !== key)) return false
    const record = this._records.get(ownedKey)
    return !!record && record.state === 'committed' && record.boundBytes !== null
  }

  releaseOwnedHandoff (handoff) {
    const key = handoff && this._ownedHandoffs.get(handoff)
    if (!key || this._ownedLeases.get(key) !== handoff) return false
    this._ownedLeases.delete(key)
    this._ownedHandoffs.delete(handoff)
    return true
  }

  rollback (token) {
    const record = token && this._records.get(token.key)
    if (!record || record.state !== 'reserved' || record.tokenId !== token.tokenId) return false
    if (token.previous) this._records.set(token.key, cloneRecord(token.previous))
    else this._records.delete(token.key)
    return true
  }

  release (key) {
    const handoff = this._ownedLeases.get(key)
    if (handoff) this.releaseOwnedHandoff(handoff)
    return this._records.delete(key)
  }

  get (key) {
    return cloneRecord(this._records.get(key))
  }

  snapshot () {
    const records = [...this._records.values()].map(cloneRecord)
    return {
      recoveryReady: this.recoveryReady,
      recoveryPending: this.recoveryPending(),
      records,
      committedRemainderBytes: this._committedRemainder(),
      fatalReason: this._fatalReason,
      acceptingMutations: this._acceptingMutations,
      activeMutations: this._mutations.size,
      physicalEnforcement: this.physicalEnforcementSnapshot(),
      activePhysicalMutations: this._physicalMutations.size
    }
  }
}
