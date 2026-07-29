import b4a from 'b4a'
import sodium from './crypto.js'
import { asBytes } from './bytes.js'
import { verifiedEndpointContext } from './verified-endpoint.js'
import { fail } from './errors.js'

const MAX_CANDIDATES = 64
const DEFAULT_TARGETS = 3
const MAX_REPAIRS_PER_RUN = 2

function hex (value) {
  return b4a.toString(value, 'hex')
}

function score (selectionKey, destinationId, continuityRoot) {
  const output = b4a.alloc(32)
  sodium.crypto_generichash(output, b4a.concat([destinationId, continuityRoot]), selectionKey)
  return output
}

function compareScoreDescending (left, right) {
  return -b4a.compare(left.score, right.score) || b4a.compare(left.context.continuityRoot, right.context.continuityRoot)
}

export class RelayCandidatePool {
  constructor (options) {
    this.selectionKey = b4a.from(asBytes(options && options.selectionKey, 'selectionKey', 32))
    this.familyId = options.familyId
    this.operationId = options.operationId
    this.transportSupportBit = options.transportSupportBit
    this.privacyProfileBit = options.privacyProfileBit
    for (const [field, value] of Object.entries({
      familyId: this.familyId,
      operationId: this.operationId,
      transportSupportBit: this.transportSupportBit,
      privacyProfileBit: this.privacyProfileBit
    })) {
      if (!Number.isSafeInteger(value) || value <= 0) fail('BAD_CLIENT_INPUT', `candidate pool ${field} is invalid`)
    }
    this.candidates = new Map()
    this.breakers = new Map()
  }

  add (endpoint, metadata = {}) {
    const context = verifiedEndpointContext(endpoint)
    if (context.familyId !== this.familyId || context.operationId !== this.operationId ||
        context.transportSupportBit !== this.transportSupportBit ||
        context.privacyProfileBit !== this.privacyProfileBit) {
      fail('BAD_CLIENT_INPUT', 'candidate endpoint does not match the pool qualification tuple')
    }
    const key = hex(context.continuityRoot)
    const existing = this.candidates.get(key)
    if (existing && existing.context.descriptorSequence > context.descriptorSequence) return false
    const operatorGroupId = metadata.operatorGroupId == null
      ? existing?.operatorGroupId || null
      : b4a.from(asBytes(metadata.operatorGroupId, 'operatorGroupId', 32))
    if (existing?.operatorGroupId != null && operatorGroupId != null &&
        !b4a.equals(existing.operatorGroupId, operatorGroupId)) {
      fail('BAD_CLIENT_INPUT', 'candidate operator-group evidence changed for one continuity root')
    }
    if (!existing && this.candidates.size >= MAX_CANDIDATES) fail('CANDIDATE_LIMIT', 'relay candidate reservoir is full')
    this.candidates.set(key, Object.freeze({
      endpoint,
      context,
      operatorGroupId,
      externallyWitnessed: existing?.externallyWitnessed === true || metadata.externallyWitnessed === true
    }))
    return true
  }

  recordFailure (endpoint, nowTick, cooldownTicks = 4) {
    const context = verifiedEndpointContext(endpoint)
    if (!Number.isSafeInteger(nowTick) || nowTick < 0 || !Number.isSafeInteger(cooldownTicks) || cooldownTicks < 1) {
      fail('BAD_CLIENT_INPUT', 'breaker ticks are invalid')
    }
    const key = hex(context.continuityRoot)
    const previous = this.breakers.get(key) || { failures: 0, openUntil: 0 }
    const failures = Math.min(previous.failures + 1, 16)
    const backoff = Math.min(cooldownTicks * (2 ** (failures - 1)), 1024)
    this.breakers.set(key, { failures, openUntil: nowTick + backoff })
  }

  recordSuccess (endpoint) {
    this.breakers.delete(hex(verifiedEndpointContext(endpoint).continuityRoot))
  }

  select (destinationId, options = {}) {
    destinationId = b4a.from(asBytes(destinationId, 'destinationId', 32))
    const targetCount = options.targetCount == null ? DEFAULT_TARGETS : options.targetCount
    const nowTick = options.nowTick == null ? 0 : options.nowTick
    if (!Number.isSafeInteger(targetCount) || targetCount < 1 || targetCount > DEFAULT_TARGETS ||
        !Number.isSafeInteger(nowTick) || nowTick < 0) {
      fail('BAD_CLIENT_INPUT', 'selection targetCount/nowTick is invalid')
    }
    const excluded = new Set((options.excludeContinuityRoots || []).map(value => hex(asBytes(value, 'excluded continuity root', 32))))
    return [...this.candidates.entries()]
      .filter(([key]) => !excluded.has(key) && (this.breakers.get(key)?.openUntil || 0) <= nowTick)
      .map(([, candidate]) => ({
        ...candidate,
        score: score(this.selectionKey, destinationId, candidate.context.continuityRoot)
      }))
      .sort(compareScoreDescending)
      .slice(0, targetCount)
      .map(candidate => candidate.endpoint)
  }
}

export class DurabilityTracker {
  constructor () {
    this.records = new Map()
  }

  observe (logicalId, endpoint, evidence = {}) {
    logicalId = hex(asBytes(logicalId, 'logicalId', 32))
    const context = verifiedEndpointContext(endpoint)
    const root = hex(context.continuityRoot)
    let record = this.records.get(logicalId)
    if (!record) {
      record = { replicas: new Map() }
      this.records.set(logicalId, record)
    }
    const previous = record.replicas.get(root)
    const operatorGroupId = evidence.operatorGroupId == null
      ? previous?.operatorGroupId || null
      : b4a.from(asBytes(evidence.operatorGroupId, 'operatorGroupId', 32))
    if (previous?.operatorGroupId != null && operatorGroupId != null &&
        !b4a.equals(previous.operatorGroupId, operatorGroupId)) {
      fail('BAD_CLIENT_INPUT', 'durability operator-group evidence changed for one continuity root')
    }
    const readbackVerified = previous?.readbackVerified === true || evidence.readbackVerified === true
    record.replicas.set(root, {
      continuityRoot: b4a.from(context.continuityRoot),
      acknowledged: previous?.acknowledged === true || evidence.acknowledged === true || readbackVerified,
      readbackVerified,
      externallyWitnessed: previous?.externallyWitnessed === true || evidence.externallyWitnessed === true,
      operatorGroupId
    })
    return this.statusByKey(logicalId)
  }

  status (logicalId) {
    return this.statusByKey(hex(asBytes(logicalId, 'logicalId', 32)))
  }

  statusByKey (logicalId) {
    const replicas = [...(this.records.get(logicalId)?.replicas.values() || [])]
    const stored = replicas.filter(value => value.acknowledged)
    const readback = replicas.filter(value => value.readbackVerified)
    const operatorGroups = new Set(readback.filter(value => value.operatorGroupId).map(value => hex(value.operatorGroupId)))
    const witnessed = readback.filter(value => value.externallyWitnessed).length
    return Object.freeze({
      remoteStored: stored.length >= 1,
      acknowledgedReplicas: stored.length,
      readbackReplicas: readback.length,
      qualifiedIndependentOperators: operatorGroups.size,
      externallyWitnessedReplicas: witnessed,
      label: readback.length >= 3 && operatorGroups.size >= 2
        ? 'resilient-multi-operator'
        : readback.length >= 2
          ? 'replicated'
          : readback.length === 1
            ? 'remote-readback-verified'
            : stored.length === 1
              ? 'remote-stored'
              : 'local-queued'
    })
  }

  repairTargets (logicalId, pool, options = {}) {
    const key = hex(asBytes(logicalId, 'logicalId', 32))
    const existing = [...(this.records.get(key)?.replicas.values() || [])].map(value => value.continuityRoot)
    const count = options.count == null ? MAX_REPAIRS_PER_RUN : options.count
    if (!Number.isSafeInteger(count) || count < 0 || count > MAX_REPAIRS_PER_RUN) {
      fail('BAD_CLIENT_INPUT', 'repair count must be within 0..2')
    }
    if (count === 0) return []
    return pool.select(asBytes(logicalId, 'logicalId', 32), {
      targetCount: count,
      nowTick: options.nowTick,
      excludeContinuityRoots: existing
    })
  }
}

export const CLIENT_SELECTION_LIMITS = Object.freeze({
  maxCandidates: MAX_CANDIDATES,
  defaultTargets: DEFAULT_TARGETS,
  maxRepairsPerRun: MAX_REPAIRS_PER_RUN
})
