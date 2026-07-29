#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const MIB = 1024 * 1024
const FAMILY_NAMES = Object.freeze(['CELL', 'INBOX', 'CORE', 'FORWARD'])
const RESOURCE_QUEUE_NAMES = Object.freeze(['diskWriteBytes', 'diskReadBytes', 'diskIops', 'fsyncs', 'cpuMicros'])
const BLIND_SCENARIO_MANIFEST_SCHEMA = 'hiverelay/blind-scenario-manifest/v1'
const CELL_SIZE_CLASSES = Object.freeze({ 1: 4096, 2: 16384, 3: 65536, 4: 262144, 5: 1048576 })
const INBOX_FRAME_CLASSES = Object.freeze({ 1: 4096, 2: 16384, 3: 65536 })
const LEASE_CLASS_EPOCHS = Object.freeze({ 1: 4, 2: 28, 3: 120, 4: 360 })
const CORE_SESSION_CLASSES = Object.freeze({
  1: Object.freeze({ maxSessionBytes: 16 * MIB, idleMillis: 30000, lifetimeMillis: 600000 }),
  2: Object.freeze({ maxSessionBytes: 64 * MIB, idleMillis: 60000, lifetimeMillis: 1800000 }),
  3: Object.freeze({ maxSessionBytes: 256 * MIB, idleMillis: 120000, lifetimeMillis: 3600000 })
})
const STREAM_WIRE_CLASSES = Object.freeze({ 1: 4096, 2: 16384, 3: 65535 })
const FORWARD_CIRCUIT_CLASSES = Object.freeze({
  1: Object.freeze({ grantedInitialWindow: 64 * 1024, maxCircuitBytes: 16 * MIB, idleMillis: 30000, lifetimeMillis: 600000 }),
  2: Object.freeze({ grantedInitialWindow: 256 * 1024, maxCircuitBytes: 64 * MIB, idleMillis: 60000, lifetimeMillis: 1800000 }),
  3: Object.freeze({ grantedInitialWindow: MIB, maxCircuitBytes: 256 * MIB, idleMillis: 120000, lifetimeMillis: 3600000 })
})

const DEFAULT_FAMILIES = Object.freeze({
  CELL: Object.freeze({
    writesPerSecond: 8,
    readsPerSecond: 12,
    minBytes: 1024,
    maxBytes: 32 * 1024,
    replicas: 3,
    commitQuorum: 2,
    leaseClass: 3,
    weight: 3
  }),
  INBOX: Object.freeze({
    writesPerSecond: 20,
    readsPerSecond: 14,
    minBytes: 256,
    maxBytes: 8 * 1024,
    replicas: 3,
    commitQuorum: 2,
    allocationLeaseClass: 3,
    retentionClass: 2,
    logicalInboxCount: 16,
    weight: 4
  }),
  CORE: Object.freeze({
    writesPerSecond: 1.5,
    readsPerSecond: 3,
    minBytes: 64 * 1024,
    maxBytes: 512 * 1024,
    replicas: 3,
    commitQuorum: 2,
    mirrorLeaseClass: 3,
    sessionClass: 1,
    openReplicationsPerSecond: 0.5,
    openReplicationMinBytes: 64 * 1024,
    openReplicationMaxBytes: 2 * MIB,
    openReplicationTrafficBytesPerSecond: 256 * 1024,
    weight: 2
  }),
  FORWARD: Object.freeze({
    writesPerSecond: 8,
    readsPerSecond: 0,
    minBytes: 64 * 1024,
    maxBytes: 2 * MIB,
    circuitClass: 1,
    wireClass: 2,
    pathHops: 2,
    trafficBytesPerSecond: 128 * 1024,
    weight: 3
  })
})

export const DEFAULT_BLIND_FLEET_CONFIG = Object.freeze({
  seed: 'hiverelay-blind-fleet-v1',
  durationSeconds: 180,
  tickMillis: 1000,
  relayCount: 18,
  operatorCount: 8,
  regionCount: 4,
  relayCapacityBytes: 128 * MIB,
  relayBandwidthMbps: 50,
  relayMaxAdmissionsPerSecond: 220,
  relayDiskWriteMbps: 200,
  relayDiskReadMbps: 500,
  relayDiskIopsPerSecond: 50000,
  relayFsyncsPerSecond: 500,
  relayCpuCores: 4,
  resourceWalRecordBytes: 2048,
  resourceWalRecordsPerMutation: 2,
  resourceWalGroupCommitRecords: 32,
  resourceCpuFixedMicros: 200,
  resourceCpuMicrosPerKiB: 2.5,
  maxResourceBacklogSeconds: 2,
  maxGrowingBacklogTicks: 4,
  maxDurableObjectsPerRelay: 250000,
  maxActiveForwardCircuitsPerRelay: 1024,
  maxActiveCoreReplicationSessionsPerRelay: 1024,
  bandwidthWriteShare: 0.58,
  epochMillis: 1000,
  churnEventsPerRelayHour: 2,
  churnMinSeconds: 2,
  churnMaxSeconds: 7,
  repairGraceSeconds: 3,
  repairScanPerTick: 1600,
  repairSurgeReplicas: 1,
  availabilitySampleSize: 512,
  evidenceSampleSeconds: 10,
  invalidAdmissionProbeEvery: 97,
  families: DEFAULT_FAMILIES,
  objectives: Object.freeze({
    minCommitRate: 0.97,
    minReadAvailability: 0.985,
    minQuorumAvailability: 0.97,
    minTargetReplicaAvailability: 0.90,
    minFinalTargetReplicaRate: 0.97,
    minTargetReplicaRecoveryRate: 0.90,
    minDiversePlacementRate: 0.97,
    maxWriteP99Millis: 2000,
    maxReadP99Millis: 1500,
    maxForwardDataP99Millis: 2000,
    minForwardCompletionAmongTerminal: 0.7,
    minForwardCompletionAmongOpened: 0.35,
    minForwardTerminalCoverageAmongOpened: 0.45,
    maxPeakStorageUtilization: 0.95,
    minFamilyCommitRate: 0.9
  })
})

export function runBlindFleetSimulation (input = {}) {
  const config = normalizeConfig(input)
  const simulation = new BlindFleetSimulation(config)
  return simulation.run()
}

export function stableStringify (value, space = 0) {
  return JSON.stringify(sortValue(value), null, space)
}

export function verifyBlindFleetEvidenceDigest (evidence) {
  if (!evidence || typeof evidence !== 'object' || typeof evidence.evidenceDigest !== 'string') return false
  const { evidenceDigest, ...body } = evidence
  return evidenceDigest === digest(body)
}

export function assertBlindFleetEvidence (evidence) {
  if (!verifyBlindFleetEvidenceDigest(evidence)) throw new Error('blind fleet evidence digest does not verify')
  const failed = evidence.assertions.filter(assertion => !assertion.pass)
  if (failed.length > 0) {
    throw new Error(`blind fleet simulation failed: ${failed.map(assertion => assertion.id).join(', ')}`)
  }
  return evidence
}

class BlindFleetSimulation {
  constructor (config) {
    this.config = config
    this.now = 0
    this.tick = 0
    this.relays = makeRelays(config)
    this.relayById = new Map(this.relays.map(relay => [relay.id, relay]))
    this.items = []
    this.itemById = new Map()
    this.activeForwardCircuits = new Map()
    this.forwardCircuitHistory = []
    this.activeCoreReplicationSessions = new Map()
    this.coreReplicationHistory = []
    this.mirroredCoreIds = new Set()
    this.inboxes = new Map()
    this.expiryBuckets = new Map()
    this.repairCursor = 0
    this.activeItemCount = 0
    this.activeLogicalBytes = 0
    this.familySequence = Object.fromEntries(FAMILY_NAMES.map(name => [name, 0]))
    this.familyWriteRemainder = Object.fromEntries(FAMILY_NAMES.map(name => [name, 0]))
    this.familyReadRemainder = Object.fromEntries(FAMILY_NAMES.map(name => [name, 0]))
    this.familyReadCursor = Object.fromEntries(FAMILY_NAMES.map(name => [name, 0]))
    this.coreOpenRemainder = 0
    this.coreOpenSequence = 0
    this.familyItems = Object.fromEntries(FAMILY_NAMES.map(name => [name, []]))
    this.metrics = makeMetrics(config)
    this.appliedDiskLosses = new Set()
    this.activeFaultIds = new Set()
  }

  run () {
    const tickCount = Math.ceil(this.config.durationMillis / this.config.tickMillis)
    for (this.tick = 0; this.tick < tickCount; this.tick++) {
      this.now = this.tick * this.config.tickMillis
      this.resetRelayTickBudgets()
      this.transitionFaults()
      this.applyChurn()
      this.expireLeases()
      this.runWrites()
      this.runCoreReplicationOpens()
      this.runCoreReplicationTraffic()
      this.runForwardTraffic()
      this.runReads()
      this.repairAndPrune()
      this.sampleReliability()
      this.sampleRelayState()
    }
    this.now = this.config.durationMillis
    this.transitionFaults()
    this.expireLeases()
    return this.buildEvidence()
  }

  resetRelayTickBudgets () {
    const seconds = this.config.tickMillis / 1000
    for (const relay of this.relays) {
      const bytes = relay.bandwidthMbps * 125000 * seconds
      relay.writeBudgetBytes = Math.floor(bytes * this.config.bandwidthWriteShare)
      relay.readBudgetBytes = Math.floor(bytes * (1 - this.config.bandwidthWriteShare))
      relay.admissionsRemaining = Math.max(1, Math.floor(this.config.relayMaxAdmissionsPerSecond * seconds))
    }
  }

  serviceRelayResourceQueues (relay) {
    for (const name of RESOURCE_QUEUE_NAMES) {
      const queue = relay.resourceQueues[name]
      const served = Math.min(queue.backlog, queue.capacityPerTick)
      queue.backlog -= served
      queue.totalServed += served
      queue.demandThisTick = 0
    }
  }

  enqueueRelayWork (relay, familyName, work) {
    for (const name of RESOURCE_QUEUE_NAMES) {
      const amount = Number(work[name] || 0)
      if (!(amount > 0)) continue
      const queue = relay.resourceQueues[name]
      queue.backlog += amount
      queue.demandThisTick += amount
      queue.totalDemand += amount
      queue.peakBacklog = Math.max(queue.peakBacklog, queue.backlog)
      this.metrics.families[familyName].resourceDemand[name] += amount
    }
  }

  durableWriteWork (relay, familyName, bytes) {
    const records = this.config.resourceWalRecordsPerMutation
    const walBytes = records * this.config.resourceWalRecordBytes
    this.enqueueRelayWork(relay, familyName, {
      diskWriteBytes: bytes + walBytes,
      diskIops: 1 + records,
      fsyncs: records / this.config.resourceWalGroupCommitRecords,
      cpuMicros: this.cpuMicros(bytes + walBytes)
    })
  }

  durableReadWork (relay, familyName, bytes) {
    this.enqueueRelayWork(relay, familyName, {
      diskReadBytes: bytes,
      diskIops: 1,
      cpuMicros: this.cpuMicros(bytes)
    })
  }

  controlMutationWork (relay, familyName) {
    const records = this.config.resourceWalRecordsPerMutation
    const bytes = records * this.config.resourceWalRecordBytes
    this.enqueueRelayWork(relay, familyName, {
      diskWriteBytes: bytes,
      diskIops: records,
      fsyncs: records / this.config.resourceWalGroupCommitRecords,
      cpuMicros: this.cpuMicros(bytes)
    })
  }

  streamWork (relay, familyName, bytes) {
    this.enqueueRelayWork(relay, familyName, { cpuMicros: this.cpuMicros(bytes) })
  }

  cpuMicros (bytes) {
    return this.config.resourceCpuFixedMicros + bytes / 1024 * this.config.resourceCpuMicrosPerKiB
  }

  resourceQueueDelayMillis (relay, names) {
    let delay = 0
    for (const name of names) {
      const queue = relay.resourceQueues[name]
      delay = Math.max(delay, queue.backlog / Math.max(1, queue.capacityPerSecond) * 1000)
    }
    return delay
  }

  transitionFaults () {
    for (const fault of this.config.faults) {
      if (fault.atMillis === this.now) {
        this.activeFaultIds.add(fault.id)
        this.metrics.faultTimeline.push({ atMillis: this.now, faultId: fault.id, state: 'START', type: fault.type })
        if (fault.type === 'disk-loss' && !this.appliedDiskLosses.has(fault.id)) {
          this.applyDiskLoss(fault)
          this.appliedDiskLosses.add(fault.id)
        }
      }
      if (fault.endMillis === this.now) {
        this.activeFaultIds.delete(fault.id)
        this.metrics.faultTimeline.push({ atMillis: this.now, faultId: fault.id, state: 'END', type: fault.type })
      }
    }
  }

  applyDiskLoss (fault) {
    const relay = this.relayById.get(fault.relayId)
    if (!relay) return
    const copyIds = [...relay.copyIds]
    let bytesLost = 0
    for (const itemId of copyIds) {
      const item = this.itemById.get(itemId)
      if (!item || !item.copies.has(relay.id)) continue
      item.copies.delete(relay.id)
      relay.copyIds.delete(item.id)
      relay.usedBytes -= item.bytes
      bytesLost += item.bytes
      this.metrics.families[item.family].copiesLostToDiskFailure++
      if (item.copies.size === 0 && item.expiresAtMillis > this.now && !item.dataLossRecorded) {
        item.dataLossRecorded = true
        this.metrics.dataLossItems++
        this.metrics.families[item.family].dataLossItems++
      }
      this.updateTargetReplicaState(item)
    }
    this.metrics.diskLossEvents++
    this.metrics.diskLossCopies += copyIds.length
    this.metrics.diskLossBytes += bytesLost
  }

  applyChurn () {
    const chance = this.config.churnEventsPerRelayHour * this.config.tickMillis / 3600000
    for (const relay of this.relays) {
      if (relay.churnUntilMillis > this.now) continue
      const rng = rngFor(`${this.config.seed}:churn:${this.tick}:${relay.id}`)
      if (rng.next() >= chance) continue
      const seconds = this.config.churnMinSeconds + rng.int(this.config.churnMaxSeconds - this.config.churnMinSeconds + 1)
      relay.churnUntilMillis = this.now + seconds * 1000
      relay.churnEvents++
      this.metrics.churnEvents++
    }
  }

  expireLeases () {
    const bucket = this.expiryBuckets.get(this.now)
    if (!bucket) return
    for (const itemId of bucket) {
      const item = this.itemById.get(itemId)
      if (!item || item.expired || item.expiresAtMillis > this.now) continue
      const family = this.metrics.families[item.family]
      const copies = item.copies.size
      for (const relayId of item.copies.keys()) this.deleteCopy(item, this.relayById.get(relayId))
      item.expired = true
      this.activeItemCount--
      this.activeLogicalBytes -= item.payloadBytes
      family.expiredItems++
      family.expiredCopies += copies
      family.expiredBytes += copies * item.bytes
    }
    this.expiryBuckets.delete(this.now)
  }

  runWrites () {
    const queues = {}
    const seconds = this.config.tickMillis / 1000
    for (const name of FAMILY_NAMES) {
      const family = this.config.families[name]
      this.familyWriteRemainder[name] += family.writesPerSecond * seconds
      const count = Math.floor(this.familyWriteRemainder[name])
      this.familyWriteRemainder[name] -= count
      queues[name] = []
      for (let i = 0; i < count; i++) queues[name].push(this.makeWrite(name))
    }

    const schedule = FAMILY_NAMES.flatMap(name => Array(this.config.families[name].weight).fill(name))
    let remaining = FAMILY_NAMES.reduce((sum, name) => sum + queues[name].length, 0)
    while (remaining > 0) {
      let progressed = false
      for (const name of schedule) {
        const item = queues[name].shift()
        if (!item) continue
        this.placeInitialCopies(item)
        remaining--
        progressed = true
      }
      if (!progressed) break
    }
  }

  makeWrite (familyName) {
    const family = this.config.families[familyName]
    const sequence = ++this.familySequence[familyName]
    const rng = rngFor(`${this.config.seed}:write:${familyName}:${sequence}`)
    const payloadBytes = family.minBytes + rng.int(family.maxBytes - family.minBytes + 1)
    if (familyName === 'FORWARD') {
      const request = {
        id: `forward-${String(sequence).padStart(9, '0')}`,
        family: familyName,
        createdAtMillis: this.now,
        targetBytes: Math.min(payloadBytes, FORWARD_CIRCUIT_CLASSES[family.circuitClass].maxCircuitBytes),
        circuitClass: family.circuitClass,
        wireClass: family.wireClass,
        pathHops: family.pathHops
      }
      const metrics = this.metrics.families.FORWARD
      metrics.generatedWrites++
      metrics.generatedStreamBytes += request.targetBytes
      increment(metrics.generatedResourceClasses, `circuit-${request.circuitClass}/wire-${request.wireClass}`)
      if (sequence % this.config.invalidAdmissionProbeEvery === 0) this.runInvalidAdmissionProbe(request)
      return request
    }

    let bytes = payloadBytes
    let expiresAtMillis = Number.POSITIVE_INFINITY
    const resource = {}
    if (familyName === 'CELL') {
      const selected = selectFixedClass(payloadBytes, CELL_SIZE_CLASSES)
      bytes = selected.bytes
      resource.sizeClass = selected.classId
      resource.leaseClass = family.leaseClass
      expiresAtMillis = this.now + LEASE_CLASS_EPOCHS[family.leaseClass] * this.config.epochMillis
    } else if (familyName === 'INBOX') {
      const selected = selectFixedClass(payloadBytes, INBOX_FRAME_CLASSES)
      bytes = selected.bytes
      resource.frameClass = selected.classId
      resource.allocationLeaseClass = family.allocationLeaseClass
      resource.retentionClass = family.retentionClass
      resource.logicalInboxId = `inbox-${String((sequence - 1) % family.logicalInboxCount).padStart(3, '0')}`
      const inbox = this.ensureInbox(resource.logicalInboxId, family)
      resource.inboxLeaseExpiresAtAppend = inbox.leaseExpiresAtMillis
      resource.frameRetentionExpiresAt = this.now + LEASE_CLASS_EPOCHS[family.retentionClass] * this.config.epochMillis
      expiresAtMillis = Math.min(resource.inboxLeaseExpiresAtAppend, resource.frameRetentionExpiresAt)
    } else {
      resource.operation = 'MIRROR'
      resource.mirrorLeaseClass = family.mirrorLeaseClass
      resource.logicalCoreId = `core-${String(sequence).padStart(9, '0')}`
      expiresAtMillis = this.now + LEASE_CLASS_EPOCHS[family.mirrorLeaseClass] * this.config.epochMillis
    }
    const item = {
      id: `${familyName.toLowerCase()}-${String(sequence).padStart(9, '0')}`,
      family: familyName,
      bytes,
      payloadBytes,
      createdAtMillis: this.now,
      expiresAtMillis,
      targetReplicas: family.replicas,
      commitQuorum: family.commitQuorum,
      copies: new Map(),
      committed: false,
      expired: false,
      firstDegradedAtMillis: null,
      dataLossRecorded: false,
      ...resource
    }
    const metrics = this.metrics.families[familyName]
    metrics.generatedWrites++
    metrics.generatedLogicalBytes += payloadBytes
    metrics.generatedPaddingBytes += bytes - payloadBytes
    increment(metrics.generatedResourceClasses, resourceClassLabel(item))
    if (sequence % this.config.invalidAdmissionProbeEvery === 0) this.runInvalidAdmissionProbe(item)
    return item
  }

  runInvalidAdmissionProbe (item) {
    const metrics = this.metrics.families[item.family]
    this.metrics.invalidAdmissionProbes++
    metrics.invalidAdmissionProbes++
    this.metrics.admissionAttempts++
    metrics.admissionAttempts++
    const relay = this.relays[hash32(item.id) % this.relays.length]
    const invalid = { ...item }
    if (item.family === 'CELL') invalid.leaseClass = 5
    else if (item.family === 'INBOX') invalid.retentionClass = 5
    else if (item.family === 'CORE') invalid.mirrorLeaseClass = 5
    else invalid.circuitClass = 4
    const result = item.family === 'FORWARD'
      ? this.checkForwardAdmission(invalid, relay)
      : this.checkAdmission(invalid, relay, { consume: false })
    if (result.ok) {
      this.metrics.invalidAdmissionAccepted++
      metrics.invalidAdmissionAccepted++
      this.metrics.admissionAccepted++
      metrics.admissionAccepted++
    } else {
      increment(metrics.admissionRejections, result.reason)
      increment(this.metrics.admissionRejections, result.reason)
    }
  }

  placeInitialCopies (item) {
    if (item.family === 'FORWARD') return this.openForwardCircuit(item)
    const attempted = new Set()
    const acceptedLatencies = []
    while (item.copies.size < item.targetReplicas && attempted.size < this.relays.length) {
      const candidate = this.pickPlacementRelay(item, attempted)
      if (!candidate) break
      attempted.add(candidate.id)
      const result = this.addCopy(item, candidate, { repair: false })
      if (result.ok) acceptedLatencies.push(result.latencyMillis)
    }

    const metrics = this.metrics.families[item.family]
    if (item.copies.size < item.commitQuorum) {
      metrics.failedWrites++
      for (const relayId of item.copies.keys()) this.deleteCopy(item, this.relayById.get(relayId))
      return
    }

    item.committed = true
    metrics.committedWrites++
    metrics.logicalBytesCommitted += item.payloadBytes
    metrics.initialPhysicalBytes += item.bytes * item.copies.size
    metrics.initialPaddingBytes += (item.bytes - item.payloadBytes) * item.copies.size
    metrics.initialReplicaCount += item.copies.size
    increment(metrics.committedResourceClasses, resourceClassLabel(item))
    metrics.writeLatency.add(Math.max(...acceptedLatencies))
    if (item.family === 'CORE') this.commitCoreMirror(item)
    this.items.push(item)
    this.itemById.set(item.id, item)
    this.familyItems[item.family].push(item)
    this.activeItemCount++
    this.activeLogicalBytes += item.payloadBytes
    if (Number.isFinite(item.expiresAtMillis)) {
      const bucket = this.expiryBuckets.get(item.expiresAtMillis) || []
      bucket.push(item.id)
      this.expiryBuckets.set(item.expiresAtMillis, bucket)
    }

    if (item.copies.size === item.targetReplicas) {
      const distinctOperators = this.distinctOperators(item)
      if (distinctOperators === item.targetReplicas) metrics.diversePlacements++
      else metrics.nonDiversePlacements++
      metrics.completePlacements++
    } else {
      metrics.underReplicatedCommits++
    }
    this.updateTargetReplicaState(item)
  }

  commitCoreMirror (item) {
    this.mirroredCoreIds.add(item.logicalCoreId)
    this.metrics.families.CORE.coreLogicalCores = this.mirroredCoreIds.size
    this.metrics.families.CORE.coreMirrorsCommitted++
  }

  runCoreReplicationOpens () {
    const family = this.config.families.CORE
    this.coreOpenRemainder += family.openReplicationsPerSecond * this.config.tickMillis / 1000
    const count = Math.floor(this.coreOpenRemainder)
    this.coreOpenRemainder -= count
    for (let index = 0; index < count; index++) this.openCoreReplication(this.makeCoreReplicationOpen())
  }

  makeCoreReplicationOpen () {
    const family = this.config.families.CORE
    const sequence = ++this.coreOpenSequence
    const rng = rngFor(`${this.config.seed}:core-open:${sequence}`)
    const targetBytes = family.openReplicationMinBytes +
      rng.int(family.openReplicationMaxBytes - family.openReplicationMinBytes + 1)
    const request = {
      id: `core-open-${String(sequence).padStart(9, '0')}`,
      family: 'CORE',
      operation: 'OPEN_REPLICATION',
      createdAtMillis: this.now,
      targetBytes,
      sessionClass: family.sessionClass
    }
    const metrics = this.metrics.families.CORE
    metrics.coreOpenGenerated++
    metrics.coreOpenTargetBytes += targetBytes
    increment(metrics.generatedResourceClasses, `open-session-${request.sessionClass}`)
    return request
  }

  openCoreReplication (request) {
    const metrics = this.metrics.families.CORE
    const candidates = this.relays
      .map(relay => ({
        relay,
        score: relay.baseLatencyMillis * 2 + relay.coreReplicationSessionIds.size * 8 +
          hash32(`${this.config.seed}:${request.id}:${relay.id}:core-open`) % 13
      }))
      .sort((left, right) => left.score - right.score || left.relay.id.localeCompare(right.relay.id))
    for (const candidate of candidates) {
      const relay = candidate.relay
      metrics.admissionAttempts++
      this.metrics.admissionAttempts++
      const reason = this.coreOpenAdmissionError(request, relay)
      if (reason) {
        increment(metrics.admissionRejections, reason)
        increment(this.metrics.admissionRejections, reason)
        continue
      }
      const limits = CORE_SESSION_CLASSES[request.sessionClass]
      const session = {
        ...request,
        relayId: relay.id,
        limits,
        openedAtMillis: this.now,
        lastActivityMillis: this.now,
        bytesTransferred: 0,
        terminalReason: null
      }
      relay.admissionsRemaining--
      relay.acceptedAdmissions++
      relay.coreReplicationSessionIds.add(session.id)
      relay.peakCoreReplicationSessions = Math.max(
        relay.peakCoreReplicationSessions, relay.coreReplicationSessionIds.size)
      metrics.admissionAccepted++
      this.metrics.admissionAccepted++
      metrics.coreOpenAccepted++
      metrics.coreOpenPeakActive = Math.max(metrics.coreOpenPeakActive,
        this.activeCoreReplicationSessions.size + 1)
      metrics.writeLatency.add(relay.baseLatencyMillis * 2)
      increment(metrics.committedResourceClasses, `open-session-${request.sessionClass}`)
      this.controlMutationWork(relay, 'CORE')
      this.activeCoreReplicationSessions.set(session.id, session)
      this.coreReplicationHistory.push(session)
      return
    }
    metrics.coreOpenFailed++
  }

  coreOpenAdmissionError (request, relay) {
    const limits = CORE_SESSION_CLASSES[request.sessionClass]
    if (!limits) return 'SESSION_CLASS_INVALID'
    if (request.targetBytes > limits.maxSessionBytes) return 'CORE_SESSION_BYTES'
    if (!this.relayReachable(relay)) return 'RELAY_UNREACHABLE'
    if (relay.coreReplicationSessionIds.size >= this.config.maxActiveCoreReplicationSessionsPerRelay) {
      return 'CORE_SESSION_CAPACITY'
    }
    if (relay.admissionsRemaining <= 0) return 'ADMISSION_RATE'
    return null
  }

  runCoreReplicationTraffic () {
    const family = this.config.families.CORE
    const metrics = this.metrics.families.CORE
    const perTickTarget = Math.max(1, Math.floor(
      family.openReplicationTrafficBytesPerSecond * this.config.tickMillis / 1000))
    for (const session of [...this.activeCoreReplicationSessions.values()]) {
      const relay = this.relayById.get(session.relayId)
      if (this.now - session.openedAtMillis >= session.limits.lifetimeMillis) {
        this.closeCoreReplication(session, 'LIFETIME')
        continue
      }
      if (this.now - session.lastActivityMillis >= session.limits.idleMillis) {
        this.closeCoreReplication(session, 'IDLE')
        continue
      }
      if (!this.relayOnline(relay)) {
        this.closeCoreReplication(session, 'PATH_FAILURE')
        continue
      }
      if (!this.relayReachable(relay)) {
        metrics.coreOpenStalledTicks++
        continue
      }
      const remaining = session.targetBytes - session.bytesTransferred
      if (remaining <= 0) {
        this.closeCoreReplication(session, 'COMPLETE')
        continue
      }
      const bytes = Math.max(0, Math.floor(Math.min(
        remaining, perTickTarget, relay.readBudgetBytes, relay.writeBudgetBytes)))
      if (bytes === 0) {
        metrics.coreOpenStalledTicks++
        continue
      }
      relay.readBudgetBytes -= bytes
      relay.writeBudgetBytes -= bytes
      session.bytesTransferred += bytes
      session.lastActivityMillis = this.now
      metrics.coreOpenBytes += bytes
      this.streamWork(relay, 'CORE', bytes)
      if (session.bytesTransferred >= session.targetBytes) this.closeCoreReplication(session, 'COMPLETE')
    }
  }

  closeCoreReplication (session, reason) {
    if (!this.activeCoreReplicationSessions.delete(session.id)) return
    const relay = this.relayById.get(session.relayId)
    relay.coreReplicationSessionIds.delete(session.id)
    session.terminalReason = reason
    const metrics = this.metrics.families.CORE
    metrics.coreOpenTerminal++
    increment(metrics.coreOpenTerminalReasons, reason)
    this.controlMutationWork(relay, 'CORE')
  }

  ensureInbox (logicalInboxId, family) {
    const allocationMillis = LEASE_CLASS_EPOCHS[family.allocationLeaseClass] * this.config.epochMillis
    const retentionMillis = LEASE_CLASS_EPOCHS[family.retentionClass] * this.config.epochMillis
    let inbox = this.inboxes.get(logicalInboxId)
    if (!inbox || inbox.leaseExpiresAtMillis <= this.now) {
      const generation = inbox ? inbox.generation + 1 : 1
      inbox = {
        id: logicalInboxId,
        generation,
        leaseExpiresAtMillis: this.now + allocationMillis
      }
      this.inboxes.set(logicalInboxId, inbox)
      this.metrics.families.INBOX.inboxesCreated++
    } else if (inbox.leaseExpiresAtMillis < this.now + retentionMillis) {
      inbox.leaseExpiresAtMillis = Math.max(inbox.leaseExpiresAtMillis, this.now + allocationMillis)
      this.metrics.families.INBOX.inboxesRenewed++
    }
    this.metrics.families.INBOX.logicalInboxes = this.inboxes.size
    return inbox
  }

  openForwardCircuit (request) {
    const metrics = this.metrics.families.FORWARD
    const attempted = new Set()
    const path = []
    while (path.length < request.pathHops && attempted.size < this.relays.length) {
      const relay = this.pickForwardRelay(request, path, attempted)
      if (!relay) break
      attempted.add(relay.id)
      metrics.admissionAttempts++
      this.metrics.admissionAttempts++
      const result = this.checkForwardAdmission(request, relay)
      if (!result.ok) {
        increment(metrics.admissionRejections, result.reason)
        increment(this.metrics.admissionRejections, result.reason)
        continue
      }
      path.push(relay)
    }

    if (path.length < request.pathHops) {
      for (let index = 0; index < path.length; index++) {
        increment(metrics.admissionRejections, 'PATH_ROLLBACK')
        increment(this.metrics.admissionRejections, 'PATH_ROLLBACK')
      }
      metrics.failedWrites++
      return
    }

    const limits = FORWARD_CIRCUIT_CLASSES[request.circuitClass]
    const circuit = {
      ...request,
      pathRelayIds: path.map(relay => relay.id),
      limits,
      maxDataBytes: STREAM_WIRE_CLASSES[request.wireClass],
      openedAtMillis: this.now,
      lastActivityMillis: this.now,
      bytesForwarded: 0,
      dataFrames: 0,
      availableWindowBytes: limits.grantedInitialWindow,
      pendingWindowBytes: 0,
      windowBytesGranted: limits.grantedInitialWindow,
      windowBytesConsumed: 0,
      terminalReason: null
    }
    for (const relay of path) {
      relay.admissionsRemaining--
      relay.acceptedAdmissions++
      relay.forwardCircuitIds.add(circuit.id)
      relay.peakForwardCircuits = Math.max(relay.peakForwardCircuits, relay.forwardCircuitIds.size)
      metrics.admissionAccepted++
      this.metrics.admissionAccepted++
      this.controlMutationWork(relay, 'FORWARD')
    }
    this.activeForwardCircuits.set(circuit.id, circuit)
    this.forwardCircuitHistory.push(circuit)
    metrics.committedWrites++
    metrics.completePlacements++
    metrics.forwardCircuitsOpened++
    metrics.forwardWindowBytesGranted += limits.grantedInitialWindow
    increment(metrics.committedResourceClasses, `circuit-${request.circuitClass}/wire-${request.wireClass}`)
    metrics.forwardPeakActive = Math.max(metrics.forwardPeakActive, this.activeForwardCircuits.size)
    const operators = new Set(path.map(relay => relay.operatorId)).size
    if (operators === path.length) metrics.diversePlacements++
    else metrics.nonDiversePlacements++
    metrics.writeLatency.add(sum(path, relay => relay.baseLatencyMillis * 2))
  }

  pickForwardRelay (request, path, attempted) {
    const usedOperators = new Set(path.map(relay => relay.operatorId))
    const candidates = this.relays
      .filter(relay => !attempted.has(relay.id) && !path.includes(relay))
      .map(relay => ({
        relay,
        unusedOperator: !usedOperators.has(relay.operatorId),
        score: relay.baseLatencyMillis * 2 + relay.forwardCircuitIds.size * 8 +
          hash32(`${this.config.seed}:${request.id}:${relay.id}:forward`) % 13
      }))
    if (candidates.length === 0) return null
    const hasUnusedOperator = candidates.some(candidate => candidate.unusedOperator)
    const eligible = hasUnusedOperator ? candidates.filter(candidate => candidate.unusedOperator) : candidates
    eligible.sort((a, b) => a.score - b.score || a.relay.id.localeCompare(b.relay.id))
    return eligible[0].relay
  }

  checkForwardAdmission (request, relay) {
    if (!FORWARD_CIRCUIT_CLASSES[request.circuitClass]) return { ok: false, reason: 'CIRCUIT_CLASS_INVALID' }
    if (!STREAM_WIRE_CLASSES[request.wireClass]) return { ok: false, reason: 'WIRE_CLASS_INVALID' }
    if (!Number.isSafeInteger(request.pathHops) || request.pathHops < 1) return { ok: false, reason: 'PATH_INVALID' }
    if (!this.relayReachable(relay)) return { ok: false, reason: 'RELAY_UNREACHABLE' }
    if (relay.forwardCircuitIds.size >= this.config.maxActiveForwardCircuitsPerRelay) {
      return { ok: false, reason: 'FORWARD_SESSION_CAPACITY' }
    }
    if (relay.admissionsRemaining <= 0) return { ok: false, reason: 'ADMISSION_RATE' }
    return { ok: true }
  }

  runForwardTraffic () {
    const family = this.config.families.FORWARD
    const metrics = this.metrics.families.FORWARD
    const perTickTarget = Math.max(1, Math.floor(family.trafficBytesPerSecond * this.config.tickMillis / 1000))
    for (const circuit of [...this.activeForwardCircuits.values()]) {
      if (this.now - circuit.openedAtMillis >= circuit.limits.lifetimeMillis) {
        this.closeForwardCircuit(circuit, 'LIFETIME')
        continue
      }
      if (this.now - circuit.lastActivityMillis >= circuit.limits.idleMillis) {
        this.closeForwardCircuit(circuit, 'IDLE')
        continue
      }
      const path = circuit.pathRelayIds.map(id => this.relayById.get(id))
      if (path.some(relay => !this.relayOnline(relay))) {
        this.closeForwardCircuit(circuit, 'PATH_FAILURE')
        continue
      }
      if (path.some(relay => !this.relayReachable(relay))) {
        metrics.forwardStalledTicks++
        continue
      }
      if (circuit.pendingWindowBytes > 0) {
        circuit.availableWindowBytes += circuit.pendingWindowBytes
        circuit.windowBytesGranted += circuit.pendingWindowBytes
        metrics.forwardWindowUpdates++
        metrics.forwardWindowBytesGranted += circuit.pendingWindowBytes
        circuit.pendingWindowBytes = 0
      }
      const remaining = circuit.targetBytes - circuit.bytesForwarded
      if (remaining <= 0) {
        this.closeForwardCircuit(circuit, 'COMPLETE')
        continue
      }
      const pathBudget = Math.min(...path.map(relay => Math.min(relay.readBudgetBytes, relay.writeBudgetBytes)))
      const bytes = Math.max(0, Math.floor(Math.min(
        remaining,
        perTickTarget,
        circuit.availableWindowBytes,
        pathBudget
      )))
      if (bytes === 0) {
        metrics.forwardStalledTicks++
        if (circuit.availableWindowBytes === 0) metrics.forwardWindowBlockedTicks++
        continue
      }
      for (const relay of path) {
        relay.readBudgetBytes -= bytes
        relay.writeBudgetBytes -= bytes
        relay.forwardedBytes += bytes
        this.streamWork(relay, 'FORWARD', bytes)
      }
      const frames = Math.ceil(bytes / circuit.maxDataBytes)
      circuit.bytesForwarded += bytes
      circuit.availableWindowBytes -= bytes
      circuit.pendingWindowBytes += bytes
      circuit.windowBytesConsumed += bytes
      circuit.dataFrames += frames
      circuit.lastActivityMillis = this.now
      metrics.forwardBytes += bytes
      metrics.forwardByteHops += bytes * path.length
      metrics.forwardDataFrames += frames
      metrics.forwardWindowBytesConsumed += bytes
      metrics.forwardMaximumOutstandingWindowBytes = Math.max(
        metrics.forwardMaximumOutstandingWindowBytes,
        circuit.limits.grantedInitialWindow - circuit.availableWindowBytes)
      metrics.forwardDataLatency.add(sum(path, relay => {
        const transfer = bytes / Math.max(1, relay.bandwidthMbps * 125000) * 1000
        return relay.baseLatencyMillis * 2 + transfer
      }))
      if (circuit.bytesForwarded >= circuit.targetBytes) this.closeForwardCircuit(circuit, 'COMPLETE')
    }
  }

  closeForwardCircuit (circuit, reason) {
    if (!this.activeForwardCircuits.delete(circuit.id)) return
    for (const relayId of circuit.pathRelayIds) {
      const relay = this.relayById.get(relayId)
      relay.forwardCircuitIds.delete(circuit.id)
      this.controlMutationWork(relay, 'FORWARD')
    }
    circuit.terminalReason = reason
    const metrics = this.metrics.families.FORWARD
    metrics.forwardCircuitsTerminal++
    increment(metrics.forwardTerminalReasons, reason)
  }

  pickPlacementRelay (item, attempted, repair = false) {
    const usedOperators = new Set([...item.copies.keys()].map(id => this.relayById.get(id)?.operatorId))
    const candidates = this.relays
      .filter(relay => !attempted.has(relay.id) && !item.copies.has(relay.id))
      .filter(relay => this.relayReachable(relay))
      .map(relay => ({
        relay,
        unusedOperator: !usedOperators.has(relay.operatorId),
        score: this.placementScore(item, relay, repair)
      }))
    if (candidates.length === 0) return null
    const hasUnusedOperator = candidates.some(candidate => candidate.unusedOperator)
    const eligible = hasUnusedOperator ? candidates.filter(candidate => candidate.unusedOperator) : candidates
    eligible.sort((a, b) => a.score - b.score || a.relay.id.localeCompare(b.relay.id))
    const selected = eligible[0].relay
    if (hasUnusedOperator && usedOperators.has(selected.operatorId)) this.metrics.operatorPlacementViolations++
    return selected
  }

  placementScore (item, relay, repair) {
    const utilization = relay.usedBytes / relay.capacityBytes
    const transferMillis = item.bytes / Math.max(1, relay.bandwidthMbps * 125000) * 1000
    const queue = (this.config.relayMaxAdmissionsPerTick - relay.admissionsRemaining) * 0.35
    const jitter = hash32(`${this.config.seed}:${item.id}:${relay.id}:${repair ? 'repair' : 'write'}`) % 13
    return relay.baseLatencyMillis * 2 + transferMillis + utilization * 500 + queue + jitter
  }

  addCopy (item, relay, options) {
    const metrics = this.metrics.families[item.family]
    metrics.admissionAttempts++
    this.metrics.admissionAttempts++
    const result = this.checkAdmission(item, relay, { consume: true })
    if (!result.ok) {
      increment(metrics.admissionRejections, result.reason)
      increment(this.metrics.admissionRejections, result.reason)
      return result
    }
    item.copies.set(relay.id, { admittedAtMillis: this.now, repair: options.repair === true })
    relay.copyIds.add(item.id)
    relay.usedBytes += item.bytes
    relay.peakUsedBytes = Math.max(relay.peakUsedBytes, relay.usedBytes)
    relay.acceptedAdmissions++
    metrics.admissionAccepted++
    this.metrics.admissionAccepted++
    this.durableWriteWork(relay, item.family, item.bytes)
    if (relay.usedBytes > relay.capacityBytes) this.metrics.capacityViolations++
    return result
  }

  checkAdmission (item, relay, options) {
    const classError = durableResourceClassError(item)
    if (classError) return { ok: false, reason: classError }
    if (!this.relayReachable(relay)) return { ok: false, reason: 'RELAY_UNREACHABLE' }
    if (relay.copyIds.size >= this.config.maxDurableObjectsPerRelay) return { ok: false, reason: 'DURABLE_OBJECT_CAPACITY' }
    if (relay.usedBytes + item.bytes > relay.capacityBytes) return { ok: false, reason: 'STORAGE_CAPACITY' }
    if (relay.admissionsRemaining <= 0) return { ok: false, reason: 'ADMISSION_RATE' }
    if (relay.writeBudgetBytes < item.bytes) return { ok: false, reason: 'WRITE_BANDWIDTH' }
    const latencyMillis = this.writeLatency(item, relay)
    if (options.consume) {
      relay.writeBudgetBytes -= item.bytes
      relay.admissionsRemaining--
    }
    return { ok: true, latencyMillis }
  }

  writeLatency (item, relay) {
    const transfer = item.bytes / Math.max(1, relay.bandwidthMbps * 125000) * 1000
    const disk = item.bytes / Math.max(1, relay.storageWriteMbps * 125000) * 1000
    const queue = (this.config.relayMaxAdmissionsPerTick - relay.admissionsRemaining) * 0.3
    const resourceQueue = this.resourceQueueDelayMillis(relay,
      ['diskWriteBytes', 'diskIops', 'fsyncs', 'cpuMicros'])
    return round3(relay.baseLatencyMillis * 2 + transfer + disk + queue + resourceQueue)
  }

  runReads () {
    const seconds = this.config.tickMillis / 1000
    for (const familyName of FAMILY_NAMES) {
      const family = this.config.families[familyName]
      this.familyReadRemainder[familyName] += family.readsPerSecond * seconds
      const count = Math.floor(this.familyReadRemainder[familyName])
      this.familyReadRemainder[familyName] -= count
      for (let i = 0; i < count; i++) this.readOne(familyName)
    }
  }

  readOne (familyName) {
    const metrics = this.metrics.families[familyName]
    metrics.scheduledReads++
    metrics.readAttempts++
    this.metrics.readAttempts++
    const item = this.pickReadableItem(familyName)
    if (!item) {
      metrics.readFailure++
      this.metrics.readFailure++
      increment(metrics.readFailureReasons, 'NO_ELIGIBLE_ITEM')
      return
    }
    const candidates = [...item.copies.keys()]
      .map(id => this.relayById.get(id))
      .filter(relay => this.relayReachable(relay))
      .sort((a, b) => this.readLatency(item, a) - this.readLatency(item, b) || a.id.localeCompare(b.id))
    for (const relay of candidates) {
      if (relay.readBudgetBytes < item.bytes) continue
      relay.readBudgetBytes -= item.bytes
      const latency = this.readLatency(item, relay)
      this.durableReadWork(relay, familyName, item.bytes)
      metrics.readSuccess++
      this.metrics.readSuccess++
      metrics.readLatency.add(latency)
      return
    }
    metrics.readFailure++
    this.metrics.readFailure++
    increment(metrics.readFailureReasons, candidates.length === 0 ? 'NO_REACHABLE_REPLICA' : 'READ_BANDWIDTH')
  }

  pickReadableItem (familyName) {
    const items = this.familyItems[familyName]
    if (items.length === 0) return null
    let cursor = this.familyReadCursor[familyName]
    for (let i = 0; i < Math.min(items.length, 64); i++) {
      const item = items[cursor % items.length]
      cursor++
      if (item.committed && !item.expired && item.expiresAtMillis > this.now) {
        this.familyReadCursor[familyName] = cursor
        return item
      }
    }
    this.familyReadCursor[familyName] = cursor
    return null
  }

  readLatency (item, relay) {
    const transfer = item.bytes / Math.max(1, relay.bandwidthMbps * 125000) * 1000
    const queueUsed = 1 - relay.readBudgetBytes / Math.max(1, relay.bandwidthBytesPerTick)
    const resourceQueue = this.resourceQueueDelayMillis(relay, ['diskReadBytes', 'diskIops', 'cpuMicros'])
    return round3(relay.baseLatencyMillis * 2 + transfer + Math.max(0, queueUsed) * 20 + resourceQueue)
  }

  repairAndPrune () {
    if (this.items.length === 0) return
    const scans = Math.min(this.config.repairScanPerTick, this.items.length)
    for (let i = 0; i < scans; i++) {
      const item = this.items[this.repairCursor % this.items.length]
      this.repairCursor++
      if (!item.committed || item.expired || item.expiresAtMillis <= this.now) continue
      this.updateTargetReplicaState(item)
      const reachable = [...item.copies.keys()].filter(id => this.relayReachable(this.relayById.get(id)))
      if (reachable.length >= item.commitQuorum) item.firstDegradedAtMillis = null
      else if (item.firstDegradedAtMillis == null) item.firstDegradedAtMillis = this.now

      const degradedLongEnough = item.firstDegradedAtMillis != null &&
        this.now - item.firstDegradedAtMillis >= this.config.repairGraceMillis
      const missingPermanentCopy = item.copies.size < item.targetReplicas
      const maySurge = degradedLongEnough && item.copies.size < item.targetReplicas + this.config.repairSurgeReplicas
      if ((missingPermanentCopy || maySurge) && reachable.length > 0) this.repairOne(item, reachable)
      if (item.copies.size > item.targetReplicas) this.pruneSurplus(item)
      this.updateTargetReplicaState(item)
    }
  }

  updateTargetReplicaState (item) {
    if (!item || !item.committed || item.expired || item.family === 'FORWARD') return
    const reachable = [...item.copies.keys()]
      .filter(id => this.relayReachable(this.relayById.get(id))).length
    const degraded = reachable < item.targetReplicas
    if (degraded && !item.targetReplicaDegraded) {
      item.targetReplicaDegraded = true
      item.everTargetReplicaDegraded = true
      this.metrics.targetReplicaDegradationEvents++
      this.metrics.families[item.family].targetReplicaDegradationEvents++
    } else if (!degraded && item.targetReplicaDegraded) {
      item.targetReplicaDegraded = false
      this.metrics.targetReplicaRecoveryEvents++
      this.metrics.families[item.family].targetReplicaRecoveryEvents++
    }
  }

  repairOne (item, reachableIds) {
    const metrics = this.metrics.families[item.family]
    metrics.repairAttempts++
    this.metrics.repairAttempts++
    const sources = reachableIds
      .map(id => this.relayById.get(id))
      .filter(relay => relay.readBudgetBytes >= item.bytes)
      .sort((a, b) => this.readLatency(item, a) - this.readLatency(item, b) || a.id.localeCompare(b.id))
    if (sources.length === 0) {
      metrics.repairFailure++
      this.metrics.repairFailure++
      return
    }
    const source = sources[0]
    if (!this.relayReachable(source)) {
      this.metrics.repairWithoutSourceViolations++
      metrics.repairFailure++
      this.metrics.repairFailure++
      return
    }
    const attempted = new Set()
    while (attempted.size < this.relays.length) {
      const target = this.pickPlacementRelay(item, attempted, true)
      if (!target) break
      attempted.add(target.id)
      const result = this.addCopy(item, target, { repair: true })
      if (!result.ok) continue
      source.readBudgetBytes -= item.bytes
      this.durableReadWork(source, item.family, item.bytes)
      metrics.repairSuccess++
      metrics.repairBytes += item.bytes
      metrics.repairLatency.add(this.readLatency(item, source) + result.latencyMillis)
      this.metrics.repairSuccess++
      this.metrics.repairBytes += item.bytes
      return
    }
    metrics.repairFailure++
    this.metrics.repairFailure++
  }

  pruneSurplus (item) {
    const copies = [...item.copies.keys()]
      .map(id => this.relayById.get(id))
    // A client cannot truthfully delete a copy while the holding relay is
    // unreachable. Retain the temporary surge until every copy can be
    // addressed again, then reduce to the requested replica count.
    if (copies.some(relay => !this.relayReachable(relay))) return
    copies
      .sort((a, b) => {
        return b.usedBytes / b.capacityBytes - a.usedBytes / a.capacityBytes || b.id.localeCompare(a.id)
      })
    while (item.copies.size > item.targetReplicas && copies.length > 0) {
      const relay = copies.shift()
      this.deleteCopy(item, relay)
      this.metrics.families[item.family].surgeCopiesPruned++
      this.metrics.surgeCopiesPruned++
    }
  }

  deleteCopy (item, relay) {
    if (!relay || !item.copies.has(relay.id)) return false
    item.copies.delete(relay.id)
    relay.copyIds.delete(item.id)
    relay.usedBytes -= item.bytes
    if (relay.usedBytes < 0) this.metrics.accountingViolations++
    return true
  }

  sampleReliability () {
    if (this.activeItemCount === 0 || this.items.length === 0) return
    const count = Math.min(this.activeItemCount, this.config.availabilitySampleSize)
    const start = hash32(`${this.config.seed}:sample:${this.tick}`) % this.items.length
    let step = (hash32(`${this.config.seed}:step:${this.tick}`) % this.items.length) || 1
    while (gcd(step, this.items.length) !== 1) step++
    let sampled = 0
    const maxVisits = Math.min(this.items.length, this.config.availabilitySampleSize * 32)
    for (let visited = 0; visited < maxVisits && sampled < count; visited++) {
      const item = this.items[(start + visited * step) % this.items.length]
      if (!item.committed || item.expired || item.expiresAtMillis <= this.now) continue
      sampled++
      const reachable = [...item.copies.keys()].filter(id => this.relayReachable(this.relayById.get(id))).length
      this.metrics.availabilitySamples++
      this.metrics.families[item.family].availabilitySamples++
      if (reachable > 0) {
        this.metrics.readableSamples++
        this.metrics.families[item.family].readableSamples++
      }
      if (reachable >= item.commitQuorum) {
        this.metrics.quorumSamples++
        this.metrics.families[item.family].quorumSamples++
      }
      if (reachable >= item.targetReplicas) {
        this.metrics.targetReplicaSamples++
        this.metrics.families[item.family].targetReplicaSamples++
      }
      if (item.copies.size === 0 && !item.dataLossRecorded) {
        item.dataLossRecorded = true
        this.metrics.dataLossItems++
        this.metrics.families[item.family].dataLossItems++
      }
    }
  }

  sampleRelayState () {
    const fleetUsedBytes = sum(this.relays, relay => relay.usedBytes)
    this.metrics.fleetPeakUsedBytes = Math.max(this.metrics.fleetPeakUsedBytes, fleetUsedBytes)
    for (const relay of this.relays) {
      this.observeRelayResourceQueues(relay)
      if (!this.relayOnline(relay)) relay.offlineMillis += this.config.tickMillis
      if (!this.relayReachable(relay)) relay.unreachableMillis += this.config.tickMillis
    }
    if (this.config.faults.some(fault => fault.type === 'partition' && this.faultActive(fault))) {
      this.metrics.partitionMillis += this.config.tickMillis
    }
    if (this.tick % this.config.evidenceSampleEveryTicks === 0 || this.now + this.config.tickMillis >= this.config.durationMillis) {
      this.metrics.timeSeries.push({
        atMillis: this.now,
        onlineRelays: this.relays.filter(relay => this.relayOnline(relay)).length,
        reachableRelays: this.relays.filter(relay => this.relayReachable(relay)).length,
        fleetUsedBytes,
        fleetUtilization: ratio(fleetUsedBytes, sum(this.relays, relay => relay.capacityBytes)),
        activeItems: this.activeItemCount,
        activeLogicalBytes: this.activeLogicalBytes,
        activeForwardCircuits: this.activeForwardCircuits.size,
        forwardBytes: this.metrics.families.FORWARD.forwardBytes,
        committedWrites: sum(FAMILY_NAMES, name => this.metrics.families[name].committedWrites),
        readsSucceeded: this.metrics.readSuccess,
        repairsSucceeded: this.metrics.repairSuccess,
        maximumResourceBacklogSeconds: max(this.relays, relay => relay.maximumResourceBacklogSeconds),
        resourceBacklogByKind: Object.fromEntries(RESOURCE_QUEUE_NAMES.map(name => [name,
          round3(sum(this.relays, relay => relay.resourceQueues[name].backlog))])),
        maximumResourceBacklogSecondsByKind: Object.fromEntries(RESOURCE_QUEUE_NAMES.map(name => [name,
          round6(Math.max(...this.relays.map(relay => relay.resourceQueues[name].backlog /
            Math.max(1, relay.resourceQueues[name].capacityPerSecond))))]))
      })
    }
  }

  observeRelayResourceQueues (relay) {
    this.serviceRelayResourceQueues(relay)
    relay.maximumResourceBacklogSeconds = 0
    for (const name of RESOURCE_QUEUE_NAMES) {
      const queue = relay.resourceQueues[name]
      const epsilon = Math.max(1e-9, queue.capacityPerTick * 1e-9)
      if (queue.backlog > queue.previousEndBacklog + epsilon) queue.growthStreak++
      else queue.growthStreak = 0
      queue.maximumGrowthStreak = Math.max(queue.maximumGrowthStreak, queue.growthStreak)
      queue.previousEndBacklog = queue.backlog
      const backlogSeconds = queue.backlog / Math.max(1, queue.capacityPerSecond)
      queue.peakBacklogSeconds = Math.max(queue.peakBacklogSeconds, backlogSeconds)
      relay.maximumResourceBacklogSeconds = Math.max(
        relay.maximumResourceBacklogSeconds, backlogSeconds)
    }
  }

  relayOnline (relay) {
    if (relay.churnUntilMillis > this.now) return false
    for (const fault of this.config.faults) {
      if (!this.faultActive(fault)) continue
      if (fault.type === 'operator-outage' && fault.operatorId === relay.operatorId) return false
      if ((fault.type === 'relay-crash' || fault.type === 'disk-loss') && fault.relayId === relay.id) return false
    }
    return true
  }

  relayReachable (relay) {
    if (!this.relayOnline(relay)) return false
    for (const fault of this.config.faults) {
      if (!this.faultActive(fault) || fault.type !== 'partition') continue
      if (fault.regionIds.includes(relay.regionId)) return false
    }
    return true
  }

  faultActive (fault) {
    return this.now >= fault.atMillis && this.now < fault.endMillis
  }

  distinctOperators (item) {
    return new Set([...item.copies.keys()].map(id => this.relayById.get(id).operatorId)).size
  }

  buildEvidence () {
    this.checkAccounting()
    this.metrics.families.FORWARD.forwardActiveFinal = this.activeForwardCircuits.size
    this.metrics.families.CORE.coreOpenActiveFinal = this.activeCoreReplicationSessions.size
    const forwardCompletedOpened = this.forwardCircuitHistory.filter(circuit => circuit.terminalReason === 'COMPLETE').length
    const forwardTerminalOpened = this.forwardCircuitHistory.filter(circuit => circuit.terminalReason != null).length
    this.metrics.families.FORWARD.forwardCompletionAmongOpened = ratio(
      forwardCompletedOpened, this.forwardCircuitHistory.length)
    this.metrics.families.FORWARD.forwardTerminalCoverageAmongOpened = ratio(
      forwardTerminalOpened, this.forwardCircuitHistory.length)
    const families = Object.fromEntries(FAMILY_NAMES.map(name => [name, summarizeFamily(name, this.metrics.families[name], this.config.durationSeconds)]))
    const committedWrites = sum(FAMILY_NAMES, name => families[name].writes.committed)
    const generatedWrites = sum(FAMILY_NAMES, name => families[name].writes.generated)
    const completePlacements = sum(FAMILY_NAMES, name => families[name].placement.complete)
    const diversePlacements = sum(FAMILY_NAMES, name => families[name].placement.operatorDiverse)
    const finalUsedBytes = sum(this.relays, relay => relay.usedBytes)
    const peakUsedBytes = sum(this.relays, relay => relay.peakUsedBytes)
    const totalCapacityBytes = sum(this.relays, relay => relay.capacityBytes)
    const writeLatency = mergeLatency(FAMILY_NAMES.map(name => this.metrics.families[name].writeLatency))
    const readLatency = mergeLatency(FAMILY_NAMES.map(name => this.metrics.families[name].readLatency))
    const activeLogicalBytes = this.activeLogicalBytes
    const initialPhysicalBytes = sum(FAMILY_NAMES, name => this.metrics.families[name].initialPhysicalBytes)
    const logicalBytesCommitted = sum(FAMILY_NAMES, name => this.metrics.families[name].logicalBytesCommitted)
    const familyCommitRates = FAMILY_NAMES.map(name => ratio(families[name].writes.committed, families[name].writes.generated))
    const activeDurableItems = this.items.filter(item => item.committed && !item.expired &&
      item.expiresAtMillis > this.now)
    for (const item of activeDurableItems) this.updateTargetReplicaState(item)
    const finalTargetItems = activeDurableItems.filter(item => {
      const reachable = [...item.copies.keys()].filter(id =>
        this.relayReachable(this.relayById.get(id))).length
      return reachable >= item.targetReplicas
    })
    const everTargetDegraded = activeDurableItems.filter(item => item.everTargetReplicaDegraded)
    const recoveredTargetItems = everTargetDegraded.filter(item => !item.targetReplicaDegraded)
    const resourceQueues = summarizeResourceQueues(this.relays, this.config)
    const scenarioManifest = buildFleetScenarioManifest(this.config, this.relays)

    const body = {
      schemaVersion: 3,
      kind: 'hiverelay-blind-fleet-simulation-evidence',
      simulatorVersion: '3.0.0',
      deterministic: true,
      seed: this.config.seed,
      virtualTime: {
        startUnixMillis: 0,
        durationMillis: this.config.durationMillis,
        tickMillis: this.config.tickMillis,
        ticks: Math.ceil(this.config.durationMillis / this.config.tickMillis)
      },
      semanticModel: {
        CELL: {
          kind: 'FIXED_PADDED_LEASED_CELL',
          sizeClasses: CELL_SIZE_CLASSES,
          leaseClassEpochs: LEASE_CLASS_EPOCHS
        },
        INBOX: {
          kind: 'FIXED_PADDED_RETENTION_FRAME',
          frameClasses: INBOX_FRAME_CLASSES,
          allocationAndRetentionClassEpochs: LEASE_CLASS_EPOCHS,
          frameExpiry: 'min(inbox allocation lease, append retention horizon)'
        },
        CORE: {
          kind: 'LEASED_MIRROR_CORPUS_AND_EPHEMERAL_UPSTREAM_CHILD',
          sessionClasses: CORE_SESSION_CLASSES,
          mirrorPersistence: 'opaque corpus retained only for the admitted sponsorship lease',
          openReplicationPersistence: 'no application body retention; bounded child bytes are upstream protocol traffic',
          openReplicationWire: 'byte-for-byte upstream blind-peer child stream'
        },
        FORWARD: {
          kind: 'EPHEMERAL_BOUNDED_PATH_STREAM',
          circuitClasses: FORWARD_CIRCUIT_CLASSES,
          wireClasses: STREAM_WIRE_CLASSES,
          maximumOutstandingWindowBytes: MIB,
          durableStorage: false,
          repair: false
        }
      },
      scenarioManifest,
      scenarioDigest: digest(scenarioManifest),
      parameters: {
        nominalRelayCapacityBytes: this.config.relayCapacityBytes,
        nominalRelayBandwidthMbps: this.config.relayBandwidthMbps,
        relayMaxAdmissionsPerSecond: this.config.relayMaxAdmissionsPerSecond,
        resourceQueueLimits: publicResourceQueueConfig(this.config),
        maxDurableObjectsPerRelay: this.config.maxDurableObjectsPerRelay,
        maxActiveForwardCircuitsPerRelay: this.config.maxActiveForwardCircuitsPerRelay,
        maxActiveCoreReplicationSessionsPerRelay: this.config.maxActiveCoreReplicationSessionsPerRelay,
        bandwidthWriteShare: this.config.bandwidthWriteShare,
        epochMillis: this.config.epochMillis,
        churnEventsPerRelayHour: this.config.churnEventsPerRelayHour,
        repairGraceMillis: this.config.repairGraceMillis,
        repairScanPerTick: this.config.repairScanPerTick,
        repairSurgeReplicas: this.config.repairSurgeReplicas,
        availabilitySampleSize: this.config.availabilitySampleSize,
        evidenceSampleEveryTicks: this.config.evidenceSampleEveryTicks,
        invalidAdmissionProbeEvery: this.config.invalidAdmissionProbeEvery,
        families: Object.fromEntries(FAMILY_NAMES.map(name => [name, publicFamilyConfig(this.config.families[name])])),
        objectives: sortValue(this.config.objectives)
      },
      topology: {
        relayCount: this.relays.length,
        operatorCount: new Set(this.relays.map(relay => relay.operatorId)).size,
        regionCount: new Set(this.relays.map(relay => relay.regionId)).size,
        independentFailureDomain: 'operatorId',
        relays: this.relays.map(relay => ({
          id: relay.id,
          operatorId: relay.operatorId,
          regionId: relay.regionId,
          capacityBytes: relay.capacityBytes,
          bandwidthMbps: relay.bandwidthMbps,
          baseLatencyMillis: relay.baseLatencyMillis,
          storageWriteMbps: relay.storageWriteMbps,
          storageReadMbps: relay.storageReadMbps,
          diskIopsPerSecond: relay.diskIopsPerSecond,
          fsyncsPerSecond: relay.fsyncsPerSecond,
          cpuCores: relay.cpuCores,
          finalUsedBytes: relay.usedBytes,
          peakUsedBytes: relay.peakUsedBytes,
          peakUtilization: ratio(relay.peakUsedBytes, relay.capacityBytes),
          activeForwardCircuits: relay.forwardCircuitIds.size,
          peakForwardCircuits: relay.peakForwardCircuits,
          activeCoreReplicationSessions: relay.coreReplicationSessionIds.size,
          peakCoreReplicationSessions: relay.peakCoreReplicationSessions,
          forwardedBytes: relay.forwardedBytes,
          acceptedAdmissions: relay.acceptedAdmissions,
          offlineMillis: relay.offlineMillis,
          unreachableMillis: relay.unreachableMillis,
          churnEvents: relay.churnEvents
        }))
      },
      workload: {
        generatedWrites,
        committedWrites,
        commitRate: ratio(committedWrites, generatedWrites),
        readsAttempted: this.metrics.readAttempts,
        readsSucceeded: this.metrics.readSuccess,
        readsFailed: this.metrics.readFailure,
        readSuccessRate: ratio(this.metrics.readSuccess, this.metrics.readAttempts),
        logicalBytesCommitted,
        initialPhysicalBytes,
        initialReplicationOverhead: ratio(initialPhysicalBytes, logicalBytesCommitted),
        forwardStreamBytes: this.metrics.families.FORWARD.forwardBytes,
        families
      },
      capacity: {
        totalBytes: totalCapacityBytes,
        finalUsedBytes,
        activeLogicalBytes,
        fleetPeakUsedBytes: this.metrics.fleetPeakUsedBytes,
        sumOfRelayIndividualPeaksBytes: peakUsedBytes,
        maximumRelayPeakUtilization: max(this.relays, relay => relay.peakUsedBytes / relay.capacityBytes),
        estimatedLogicalBytesAtObservedReplication: initialPhysicalBytes > 0
          ? Math.floor(totalCapacityBytes / (initialPhysicalBytes / logicalBytesCommitted))
          : 0,
        committedLogicalMiBPerSecond: round3(logicalBytesCommitted / MIB / this.config.durationSeconds),
        committedPhysicalMiBPerSecond: round3(initialPhysicalBytes / MIB / this.config.durationSeconds)
      },
      performance: {
        writeLatencyMillis: writeLatency.summary(),
        readLatencyMillis: readLatency.summary(),
        forwardDataLatencyMillis: this.metrics.families.FORWARD.forwardDataLatency.summary(),
        writesCommittedPerSecond: round3(committedWrites / this.config.durationSeconds),
        readsSucceededPerSecond: round3(this.metrics.readSuccess / this.config.durationSeconds),
        forwardMiBPerSecond: round3(this.metrics.families.FORWARD.forwardBytes / MIB / this.config.durationSeconds)
      },
      resourceQueues,
      reliability: {
        sampledItems: this.metrics.availabilitySamples,
        readableRate: ratio(this.metrics.readableSamples, this.metrics.availabilitySamples),
        quorumAvailableRate: ratio(this.metrics.quorumSamples, this.metrics.availabilitySamples),
        targetReplicaRate: ratio(this.metrics.targetReplicaSamples, this.metrics.availabilitySamples),
        finalTargetReplicaRate: ratio(finalTargetItems.length, activeDurableItems.length),
        activeDurableItems: activeDurableItems.length,
        finalTargetReplicaItems: finalTargetItems.length,
        targetReplicaRecovery: {
          everDegradedActiveItems: everTargetDegraded.length,
          recoveredActiveItems: recoveredTargetItems.length,
          recoveryRate: ratioOrOne(recoveredTargetItems.length, everTargetDegraded.length),
          degradationEvents: this.metrics.targetReplicaDegradationEvents,
          recoveryEvents: this.metrics.targetReplicaRecoveryEvents
        },
        dataLossItems: this.metrics.dataLossItems,
        repairs: {
          attempted: this.metrics.repairAttempts,
          succeeded: this.metrics.repairSuccess,
          failed: this.metrics.repairFailure,
          bytes: this.metrics.repairBytes,
          amplificationAgainstInitialWrites: ratio(this.metrics.repairBytes, initialPhysicalBytes)
        },
        placement: {
          complete: completePlacements,
          operatorDiverse: diversePlacements,
          operatorDiverseRate: ratio(diversePlacements, completePlacements),
          selectionViolations: this.metrics.operatorPlacementViolations
        }
      },
      admissionAndRetention: {
        attempts: this.metrics.admissionAttempts,
        accepted: this.metrics.admissionAccepted,
        rejections: sortedObject(this.metrics.admissionRejections),
        invalidResourceClassProbes: this.metrics.invalidAdmissionProbes,
        invalidResourceClassAccepted: this.metrics.invalidAdmissionAccepted,
        expiredItems: sum(FAMILY_NAMES, name => this.metrics.families[name].expiredItems),
        expiredCopies: sum(FAMILY_NAMES, name => this.metrics.families[name].expiredCopies),
        expiredBytes: sum(FAMILY_NAMES, name => this.metrics.families[name].expiredBytes)
      },
      faults: {
        plan: this.config.faults.map(publicFault),
        timeline: this.metrics.faultTimeline,
        partitionMillis: this.metrics.partitionMillis,
        churnEvents: this.metrics.churnEvents,
        diskLossEvents: this.metrics.diskLossEvents,
        diskLossCopies: this.metrics.diskLossCopies,
        diskLossBytes: this.metrics.diskLossBytes,
        surgeCopiesPruned: this.metrics.surgeCopiesPruned
      },
      timeSeries: this.metrics.timeSeries,
      modelScope: {
        contentVisibility: 'opaque byte counts only; no application semantics are available to relays',
        placementAuthority: 'client-side replica placement across relay operator failure domains',
        repairAuthority: 'CELL, INBOX, and leased CORE MIRROR corpora use client-mediated repair requiring one reachable source; CORE.OPEN_REPLICATION and FORWARD streams never repair or reroute',
        latencyModel: 'deterministic propagation plus bandwidth and explicit disk read/write, IOPS, fsync, CPU, and backlog service time',
        excludedFromClaims: [
          'kernel, filesystem, database, cryptographic, and wire-format benchmark results',
          'real Internet routing and correlated geopolitical failures',
          'signature, spend-tag, WAL, checkpoint, and codec execution costs',
          'Hypercore protocol internals; CORE.MIRROR corpus bytes model the external replicated store while OPEN_REPLICATION carries only upstream child bytes',
          'sub-tick FORWARD WINDOW timing; released credit is delivered deterministically on the next reachable tick',
          'wall-clock lease duration; epochMillis is an explicit simulation-time compression',
          'proof that a production implementation matches this model'
        ]
      }
    }
    body.assertions = makeAssertions(body, this.metrics, this.config, familyCommitRates)
    body.ok = body.assertions.every(assertion => assertion.pass)
    return { ...body, evidenceDigest: digest(body) }
  }

  checkAccounting () {
    const expected = new Map(this.relays.map(relay => [relay.id, 0]))
    for (const item of this.items) {
      if (item.family === 'CELL' && CELL_SIZE_CLASSES[item.sizeClass] !== item.bytes) this.metrics.familySemanticViolations++
      if (item.family === 'INBOX' && (
        INBOX_FRAME_CLASSES[item.frameClass] !== item.bytes ||
        item.expiresAtMillis !== Math.min(item.inboxLeaseExpiresAtAppend, item.frameRetentionExpiresAt)
      )) this.metrics.familySemanticViolations++
      if (item.family === 'CORE' && (item.operation !== 'MIRROR' ||
        item.bytes !== item.payloadBytes || !Number.isFinite(item.expiresAtMillis))) {
        this.metrics.familySemanticViolations++
      }
      if (item.expired) {
        if (item.copies.size > 0) this.metrics.expiredVisibleViolations++
        continue
      }
      for (const relayId of item.copies.keys()) expected.set(relayId, expected.get(relayId) + item.bytes)
    }
    for (const relay of this.relays) {
      if (expected.get(relay.id) !== relay.usedBytes) this.metrics.accountingViolations++
      if (relay.usedBytes > relay.capacityBytes) this.metrics.capacityViolations++
      for (const circuitId of relay.forwardCircuitIds) {
        const circuit = this.activeForwardCircuits.get(circuitId)
        if (!circuit || !circuit.pathRelayIds.includes(relay.id) || relay.copyIds.has(circuitId)) {
          this.metrics.forwardAccountingViolations++
        }
      }
      for (const sessionId of relay.coreReplicationSessionIds) {
        const session = this.activeCoreReplicationSessions.get(sessionId)
        if (!session || session.relayId !== relay.id || relay.copyIds.has(sessionId)) {
          this.metrics.coreOpenAccountingViolations++
        }
      }
    }
    for (const circuit of this.activeForwardCircuits.values()) {
      for (const relayId of circuit.pathRelayIds) {
        if (!this.relayById.get(relayId).forwardCircuitIds.has(circuit.id)) this.metrics.forwardAccountingViolations++
      }
    }
    for (const session of this.activeCoreReplicationSessions.values()) {
      if (!this.relayById.get(session.relayId).coreReplicationSessionIds.has(session.id)) {
        this.metrics.coreOpenAccountingViolations++
      }
    }
    for (const session of this.coreReplicationHistory) {
      for (const relay of this.relays) {
        if (!relay.copyIds.has(session.id)) continue
        this.metrics.coreOpenAccountingViolations++
        this.metrics.families.CORE.coreOpenDurableApplicationBodyBytes += session.targetBytes
      }
    }
  }
}

function makeAssertions (body, metrics, config, familyCommitRates) {
  const objective = config.objectives
  const rejectionCount = Object.values(body.admissionAndRetention.rejections).reduce((total, count) => total + count, 0)
  const assertions = [
    invariant('storage.capacity-not-exceeded', metrics.capacityViolations === 0, metrics.capacityViolations, 0),
    invariant('storage.accounting-exact', metrics.accountingViolations === 0, metrics.accountingViolations, 0),
    invariant('families.fixed-and-persistent-shapes-exact', metrics.familySemanticViolations === 0, metrics.familySemanticViolations, 0),
    invariant('forward.no-durable-storage-or-repair', body.workload.families.FORWARD.durableStorage.initialPhysicalBytes === 0 && body.workload.families.FORWARD.repair.attempted === 0, body.workload.families.FORWARD.durableStorage.initialPhysicalBytes + body.workload.families.FORWARD.repair.attempted, 0),
    invariant('forward.active-reservations-accounted', metrics.forwardAccountingViolations === 0, metrics.forwardAccountingViolations, 0),
    invariant('core.open-replication-reservations-accounted', metrics.coreOpenAccountingViolations === 0, metrics.coreOpenAccountingViolations, 0),
    invariant('core.open-replication-has-no-durable-application-body', body.workload.families.CORE.coreReplication.openReplication.durableApplicationBodyBytes === 0, body.workload.families.CORE.coreReplication.openReplication.durableApplicationBodyBytes, 0),
    invariant('forward.window-credit-conserved', body.workload.families.FORWARD.forward.window.bytesConsumed <= body.workload.families.FORWARD.forward.window.bytesGranted && body.workload.families.FORWARD.forward.window.maximumOutstandingBytes <= body.semanticModel.FORWARD.maximumOutstandingWindowBytes, body.workload.families.FORWARD.forward.window.maximumOutstandingBytes, `<=${body.semanticModel.FORWARD.maximumOutstandingWindowBytes}`),
    invariant('retention.expired-copies-inaccessible', metrics.expiredVisibleViolations === 0, metrics.expiredVisibleViolations, 0),
    invariant('admission.invalid-resource-class-fails-closed', metrics.invalidAdmissionProbes > 0 && metrics.invalidAdmissionAccepted === 0, metrics.invalidAdmissionAccepted, 0),
    invariant('admission.attempts-accounted', body.admissionAndRetention.attempts === body.admissionAndRetention.accepted + rejectionCount, body.admissionAndRetention.attempts - body.admissionAndRetention.accepted - rejectionCount, 0),
    invariant('reads.scheduled-outcomes-accounted', body.workload.readsAttempted === body.workload.readsSucceeded + body.workload.readsFailed && FAMILY_NAMES.every(name => body.workload.families[name].reads.scheduled === body.workload.families[name].reads.succeeded + body.workload.families[name].reads.failed), body.workload.readsAttempted - body.workload.readsSucceeded - body.workload.readsFailed, 0),
    invariant('resources.no-growing-backlog', body.resourceQueues.maximumGrowthStreak < config.maxGrowingBacklogTicks, body.resourceQueues.maximumGrowthStreak, `<${config.maxGrowingBacklogTicks}`),
    invariant('resources.backlog-within-bound', body.resourceQueues.maximumPeakBacklogSeconds <= config.maxResourceBacklogSeconds, body.resourceQueues.maximumPeakBacklogSeconds, `<=${config.maxResourceBacklogSeconds}`),
    invariant('repair.requires-reachable-source', metrics.repairWithoutSourceViolations === 0, metrics.repairWithoutSourceViolations, 0),
    invariant('placement.prefers-unused-operator', metrics.operatorPlacementViolations === 0, metrics.operatorPlacementViolations, 0),
    objectiveAssertion('workload.commit-rate', body.workload.commitRate >= objective.minCommitRate, body.workload.commitRate, `>=${objective.minCommitRate}`),
    objectiveAssertion('workload.minimum-family-commit-rate', Math.min(...familyCommitRates) >= objective.minFamilyCommitRate, round6(Math.min(...familyCommitRates)), `>=${objective.minFamilyCommitRate}`),
    objectiveAssertion('reliability.readable-rate', body.reliability.readableRate >= objective.minReadAvailability, body.reliability.readableRate, `>=${objective.minReadAvailability}`),
    objectiveAssertion('reliability.quorum-available-rate', body.reliability.quorumAvailableRate >= objective.minQuorumAvailability, body.reliability.quorumAvailableRate, `>=${objective.minQuorumAvailability}`),
    objectiveAssertion('reliability.target-replica-rate', body.reliability.targetReplicaRate >= objective.minTargetReplicaAvailability, body.reliability.targetReplicaRate, `>=${objective.minTargetReplicaAvailability}`),
    objectiveAssertion('reliability.final-target-replica-rate', body.reliability.finalTargetReplicaRate >= objective.minFinalTargetReplicaRate, body.reliability.finalTargetReplicaRate, `>=${objective.minFinalTargetReplicaRate}`),
    objectiveAssertion('reliability.target-replica-recovery-rate', body.reliability.targetReplicaRecovery.recoveryRate >= objective.minTargetReplicaRecoveryRate, body.reliability.targetReplicaRecovery.recoveryRate, `>=${objective.minTargetReplicaRecoveryRate}`),
    objectiveAssertion('reliability.operator-diverse-placement', body.reliability.placement.operatorDiverseRate >= objective.minDiversePlacementRate, body.reliability.placement.operatorDiverseRate, `>=${objective.minDiversePlacementRate}`),
    objectiveAssertion('performance.write-p99', body.performance.writeLatencyMillis.p99 <= objective.maxWriteP99Millis, body.performance.writeLatencyMillis.p99, `<=${objective.maxWriteP99Millis}`),
    objectiveAssertion('performance.read-p99', body.performance.readLatencyMillis.p99 <= objective.maxReadP99Millis, body.performance.readLatencyMillis.p99, `<=${objective.maxReadP99Millis}`),
    objectiveAssertion('performance.forward-data-p99', body.performance.forwardDataLatencyMillis.p99 <= objective.maxForwardDataP99Millis, body.performance.forwardDataLatencyMillis.p99, `<=${objective.maxForwardDataP99Millis}`),
    objectiveAssertion('forward.completion-among-terminal', body.workload.families.FORWARD.forward.completionAmongTerminal >= objective.minForwardCompletionAmongTerminal, body.workload.families.FORWARD.forward.completionAmongTerminal, `>=${objective.minForwardCompletionAmongTerminal}`),
    objectiveAssertion('forward.completion-among-opened', body.workload.families.FORWARD.forward.completionAmongOpened >= objective.minForwardCompletionAmongOpened, body.workload.families.FORWARD.forward.completionAmongOpened, `>=${objective.minForwardCompletionAmongOpened}`),
    objectiveAssertion('forward.terminal-coverage-among-opened', body.workload.families.FORWARD.forward.terminalCoverageAmongOpened >= objective.minForwardTerminalCoverageAmongOpened, body.workload.families.FORWARD.forward.terminalCoverageAmongOpened, `>=${objective.minForwardTerminalCoverageAmongOpened}`),
    objectiveAssertion('capacity.maximum-relay-peak', body.capacity.maximumRelayPeakUtilization <= objective.maxPeakStorageUtilization, body.capacity.maximumRelayPeakUtilization, `<=${objective.maxPeakStorageUtilization}`)
  ]
  return assertions
}

function invariant (id, pass, observed, target) {
  return { id, class: 'INVARIANT', pass, observed, target }
}

function objectiveAssertion (id, pass, observed, target) {
  return { id, class: 'OBJECTIVE', pass, observed, target }
}

function summarizeFamily (familyName, metrics, durationSeconds) {
  const result = {
    semantics: familySemantics(familyName),
    writes: {
      generated: metrics.generatedWrites,
      committed: metrics.committedWrites,
      failed: metrics.failedWrites,
      commitRate: ratio(metrics.committedWrites, metrics.generatedWrites),
      committedPerSecond: round3(metrics.committedWrites / durationSeconds),
      generatedLogicalBytes: metrics.generatedLogicalBytes,
      committedLogicalBytes: metrics.logicalBytesCommitted,
      initialPhysicalBytes: metrics.initialPhysicalBytes,
      generatedPaddingBytes: metrics.generatedPaddingBytes,
      initialPaddingBytes: metrics.initialPaddingBytes
    },
    reads: {
      scheduled: metrics.scheduledReads,
      attempted: metrics.readAttempts,
      succeeded: metrics.readSuccess,
      failed: metrics.readFailure,
      successRate: ratio(metrics.readSuccess, metrics.readAttempts),
      failureReasons: sortedObject(metrics.readFailureReasons)
    },
    placement: {
      complete: metrics.completePlacements,
      operatorDiverse: metrics.diversePlacements,
      nonDiverse: metrics.nonDiversePlacements,
      underReplicatedCommits: metrics.underReplicatedCommits,
      initialReplicaCount: metrics.initialReplicaCount
    },
    admission: {
      attempts: metrics.admissionAttempts,
      accepted: metrics.admissionAccepted,
      rejections: sortedObject(metrics.admissionRejections),
      invalidResourceClassProbes: metrics.invalidAdmissionProbes,
      invalidResourceClassAccepted: metrics.invalidAdmissionAccepted
    },
    leaseExpiry: {
      items: metrics.expiredItems,
      copies: metrics.expiredCopies,
      bytes: metrics.expiredBytes
    },
    reliability: {
      sampledItems: metrics.availabilitySamples,
      readableRate: ratio(metrics.readableSamples, metrics.availabilitySamples),
      quorumAvailableRate: ratio(metrics.quorumSamples, metrics.availabilitySamples),
      targetReplicaRate: ratio(metrics.targetReplicaSamples, metrics.availabilitySamples),
      copiesLostToDiskFailure: metrics.copiesLostToDiskFailure,
      dataLossItems: metrics.dataLossItems
    },
    repair: {
      attempted: metrics.repairAttempts,
      succeeded: metrics.repairSuccess,
      failed: metrics.repairFailure,
      bytes: metrics.repairBytes,
      surgeCopiesPruned: metrics.surgeCopiesPruned,
      latencyMillis: metrics.repairLatency.summary()
    },
    latencyMillis: {
      write: metrics.writeLatency.summary(),
      read: metrics.readLatency.summary()
    },
    resourceClasses: {
      generated: sortedObject(metrics.generatedResourceClasses),
      committed: sortedObject(metrics.committedResourceClasses)
    },
    durableStorage: {
      enabled: familyName !== 'FORWARD',
      committedLogicalBytes: metrics.logicalBytesCommitted,
      initialPhysicalBytes: metrics.initialPhysicalBytes,
      initialPaddingBytes: metrics.initialPaddingBytes
    }
  }
  if (familyName === 'CORE') {
    result.coreReplication = {
      mirror: {
        persistentForLease: true,
        logicalCores: metrics.coreLogicalCores,
        mirrorsCommitted: metrics.coreMirrorsCommitted,
        corpusBytesCommitted: metrics.logicalBytesCommitted
      },
      openReplication: {
        upstreamChildBytesOpaque: true,
        durableApplicationBodyBytes: metrics.coreOpenDurableApplicationBodyBytes,
        sessionsGenerated: metrics.coreOpenGenerated,
        sessionsOpened: metrics.coreOpenAccepted,
        sessionsFailed: metrics.coreOpenFailed,
        sessionsTerminal: metrics.coreOpenTerminal,
        sessionsActiveFinal: metrics.coreOpenActiveFinal,
        peakActiveSessions: metrics.coreOpenPeakActive,
        targetBytes: metrics.coreOpenTargetBytes,
        bytesTransferred: metrics.coreOpenBytes,
        stalledTicks: metrics.coreOpenStalledTicks,
        terminalReasons: sortedObject(metrics.coreOpenTerminalReasons)
      }
    }
  }
  if (familyName === 'INBOX') {
    result.inboxRetention = {
      logicalInboxes: metrics.logicalInboxes,
      inboxesCreated: metrics.inboxesCreated,
      inboxesRenewed: metrics.inboxesRenewed,
      expiryRule: 'min(inboxLeaseExpiresAtAppend, frameRetentionExpiresAt)'
    }
  }
  if (familyName === 'FORWARD') {
    const completed = metrics.forwardTerminalReasons.COMPLETE || 0
    result.forward = {
      durableStorageBytes: 0,
      repairAttempts: 0,
      circuitsOpened: metrics.forwardCircuitsOpened,
      circuitsTerminal: metrics.forwardCircuitsTerminal,
      circuitsActiveFinal: metrics.forwardActiveFinal,
      peakActiveCircuits: metrics.forwardPeakActive,
      targetBytes: metrics.generatedStreamBytes,
      bytesForwarded: metrics.forwardBytes,
      relayByteHops: metrics.forwardByteHops,
      dataFrames: metrics.forwardDataFrames,
      stalledTicks: metrics.forwardStalledTicks,
      terminalReasons: sortedObject(metrics.forwardTerminalReasons),
      completionAmongTerminal: ratio(completed, metrics.forwardCircuitsTerminal),
      completionAmongOpened: metrics.forwardCompletionAmongOpened,
      terminalCoverageAmongOpened: metrics.forwardTerminalCoverageAmongOpened,
      throughputMiBPerSecond: round3(metrics.forwardBytes / MIB / durationSeconds),
      dataLatencyMillis: metrics.forwardDataLatency.summary(),
      window: {
        bytesGranted: metrics.forwardWindowBytesGranted,
        bytesConsumed: metrics.forwardWindowBytesConsumed,
        updates: metrics.forwardWindowUpdates,
        blockedTicks: metrics.forwardWindowBlockedTicks,
        maximumOutstandingBytes: metrics.forwardMaximumOutstandingWindowBytes
      }
    }
  }
  return result
}

function makeMetrics () {
  const family = () => ({
    generatedWrites: 0,
    generatedLogicalBytes: 0,
    generatedPaddingBytes: 0,
    initialPaddingBytes: 0,
    generatedResourceClasses: {},
    committedResourceClasses: {},
    generatedStreamBytes: 0,
    committedWrites: 0,
    failedWrites: 0,
    logicalBytesCommitted: 0,
    initialPhysicalBytes: 0,
    initialReplicaCount: 0,
    completePlacements: 0,
    diversePlacements: 0,
    nonDiversePlacements: 0,
    underReplicatedCommits: 0,
    admissionAttempts: 0,
    admissionAccepted: 0,
    admissionRejections: {},
    invalidAdmissionProbes: 0,
    invalidAdmissionAccepted: 0,
    scheduledReads: 0,
    readAttempts: 0,
    readSuccess: 0,
    readFailure: 0,
    readFailureReasons: {},
    resourceDemand: Object.fromEntries(RESOURCE_QUEUE_NAMES.map(name => [name, 0])),
    repairAttempts: 0,
    repairSuccess: 0,
    repairFailure: 0,
    repairBytes: 0,
    surgeCopiesPruned: 0,
    copiesLostToDiskFailure: 0,
    dataLossItems: 0,
    expiredItems: 0,
    expiredCopies: 0,
    expiredBytes: 0,
    availabilitySamples: 0,
    readableSamples: 0,
    quorumSamples: 0,
    targetReplicaSamples: 0,
    targetReplicaDegradationEvents: 0,
    targetReplicaRecoveryEvents: 0,
    coreLogicalCores: 0,
    coreMirrorsCommitted: 0,
    coreOpenGenerated: 0,
    coreOpenAccepted: 0,
    coreOpenFailed: 0,
    coreOpenTerminal: 0,
    coreOpenActiveFinal: 0,
    coreOpenPeakActive: 0,
    coreOpenTargetBytes: 0,
    coreOpenBytes: 0,
    coreOpenDurableApplicationBodyBytes: 0,
    coreOpenStalledTicks: 0,
    coreOpenTerminalReasons: {},
    logicalInboxes: 0,
    inboxesCreated: 0,
    inboxesRenewed: 0,
    forwardCircuitsOpened: 0,
    forwardCircuitsTerminal: 0,
    forwardActiveFinal: 0,
    forwardPeakActive: 0,
    forwardBytes: 0,
    forwardByteHops: 0,
    forwardDataFrames: 0,
    forwardStalledTicks: 0,
    forwardWindowBytesGranted: 0,
    forwardWindowBytesConsumed: 0,
    forwardWindowUpdates: 0,
    forwardWindowBlockedTicks: 0,
    forwardMaximumOutstandingWindowBytes: 0,
    forwardCompletionAmongOpened: 0,
    forwardTerminalCoverageAmongOpened: 0,
    forwardTerminalReasons: {},
    writeLatency: new LatencyHistogram(),
    readLatency: new LatencyHistogram(),
    repairLatency: new LatencyHistogram(),
    forwardDataLatency: new LatencyHistogram()
  })
  return {
    families: Object.fromEntries(FAMILY_NAMES.map(name => [name, family()])),
    admissionAttempts: 0,
    admissionAccepted: 0,
    admissionRejections: {},
    invalidAdmissionProbes: 0,
    invalidAdmissionAccepted: 0,
    readAttempts: 0,
    readSuccess: 0,
    readFailure: 0,
    repairAttempts: 0,
    repairSuccess: 0,
    repairFailure: 0,
    repairBytes: 0,
    repairWithoutSourceViolations: 0,
    operatorPlacementViolations: 0,
    capacityViolations: 0,
    accountingViolations: 0,
    familySemanticViolations: 0,
    forwardAccountingViolations: 0,
    coreOpenAccountingViolations: 0,
    expiredVisibleViolations: 0,
    availabilitySamples: 0,
    readableSamples: 0,
    quorumSamples: 0,
    targetReplicaSamples: 0,
    targetReplicaDegradationEvents: 0,
    targetReplicaRecoveryEvents: 0,
    dataLossItems: 0,
    partitionMillis: 0,
    churnEvents: 0,
    diskLossEvents: 0,
    diskLossCopies: 0,
    diskLossBytes: 0,
    surgeCopiesPruned: 0,
    fleetPeakUsedBytes: 0,
    faultTimeline: [],
    timeSeries: []
  }
}

function makeRelays (config) {
  const relays = []
  for (let i = 0; i < config.relayCount; i++) {
    const id = `relay-${String(i).padStart(3, '0')}`
    const operatorIndex = i % config.operatorCount
    const operatorId = `operator-${String(operatorIndex).padStart(2, '0')}`
    const regionIndex = (operatorIndex + Math.floor(i / config.operatorCount)) % config.regionCount
    const regionId = `region-${regionIndex}`
    const rng = rngFor(`${config.seed}:topology:${id}`)
    const capacityBytes = Math.floor(config.relayCapacityBytes * (0.85 + rng.next() * 0.3))
    const bandwidthMbps = round3(config.relayBandwidthMbps * (0.7 + rng.next() * 0.6))
    const baseLatencyMillis = 12 + regionIndex * 7 + rng.int(75)
    const storageWriteMbps = round3(config.relayDiskWriteMbps * (0.7 + rng.next() * 0.6))
    const storageReadMbps = round3(config.relayDiskReadMbps * (0.7 + rng.next() * 0.6))
    const diskIopsPerSecond = round3(config.relayDiskIopsPerSecond * (0.7 + rng.next() * 0.6))
    const fsyncsPerSecond = round3(config.relayFsyncsPerSecond * (0.7 + rng.next() * 0.6))
    const cpuCores = round3(config.relayCpuCores * (0.8 + rng.next() * 0.4))
    const secondsPerTick = config.tickMillis / 1000
    const resourceCapacity = {
      diskWriteBytes: storageWriteMbps * 125000,
      diskReadBytes: storageReadMbps * 125000,
      diskIops: diskIopsPerSecond,
      fsyncs: fsyncsPerSecond,
      cpuMicros: cpuCores * 1000000
    }
    const resourceQueues = Object.fromEntries(RESOURCE_QUEUE_NAMES.map(name => [name, {
      capacityPerSecond: resourceCapacity[name],
      capacityPerTick: resourceCapacity[name] * secondsPerTick,
      backlog: 0,
      previousEndBacklog: 0,
      peakBacklog: 0,
      peakBacklogSeconds: 0,
      growthStreak: 0,
      maximumGrowthStreak: 0,
      demandThisTick: 0,
      totalDemand: 0,
      totalServed: 0
    }]))
    relays.push({
      id,
      operatorId,
      regionId,
      capacityBytes,
      bandwidthMbps,
      bandwidthBytesPerTick: bandwidthMbps * 125000 * (config.tickMillis / 1000),
      baseLatencyMillis,
      storageWriteMbps,
      storageReadMbps,
      diskIopsPerSecond,
      fsyncsPerSecond,
      cpuCores,
      resourceQueues,
      maximumResourceBacklogSeconds: 0,
      usedBytes: 0,
      peakUsedBytes: 0,
      copyIds: new Set(),
      forwardCircuitIds: new Set(),
      coreReplicationSessionIds: new Set(),
      peakForwardCircuits: 0,
      peakCoreReplicationSessions: 0,
      forwardedBytes: 0,
      writeBudgetBytes: 0,
      readBudgetBytes: 0,
      admissionsRemaining: 0,
      acceptedAdmissions: 0,
      offlineMillis: 0,
      unreachableMillis: 0,
      churnUntilMillis: 0,
      churnEvents: 0
    })
  }
  return relays
}

function normalizeConfig (input) {
  const durationSeconds = positiveNumber(input.durationSeconds, DEFAULT_BLIND_FLEET_CONFIG.durationSeconds)
  const tickMillis = positiveInteger(input.tickMillis, DEFAULT_BLIND_FLEET_CONFIG.tickMillis)
  const relayCount = positiveInteger(input.relayCount, DEFAULT_BLIND_FLEET_CONFIG.relayCount)
  const operatorCount = Math.min(relayCount, positiveInteger(input.operatorCount, DEFAULT_BLIND_FLEET_CONFIG.operatorCount))
  const regionCount = Math.min(relayCount, positiveInteger(input.regionCount, DEFAULT_BLIND_FLEET_CONFIG.regionCount))
  const families = {}
  const rateScale = nonNegativeNumber(input.rateScale, 1)
  for (const name of FAMILY_NAMES) {
    const merged = { ...DEFAULT_FAMILIES[name], ...(input.families?.[name] || {}) }
    const common = {
      writesPerSecond: nonNegativeNumber(merged.writesPerSecond, DEFAULT_FAMILIES[name].writesPerSecond) * rateScale,
      readsPerSecond: name === 'FORWARD' ? 0 : nonNegativeNumber(merged.readsPerSecond, DEFAULT_FAMILIES[name].readsPerSecond) * rateScale,
      minBytes: positiveInteger(merged.minBytes, DEFAULT_FAMILIES[name].minBytes),
      maxBytes: positiveInteger(merged.maxBytes, DEFAULT_FAMILIES[name].maxBytes),
      weight: positiveInteger(merged.weight, DEFAULT_FAMILIES[name].weight)
    }
    if (common.maxBytes < common.minBytes) throw new Error(`${name} maxBytes must be >= minBytes`)
    if (name === 'FORWARD') {
      const circuitClass = exactClass(merged.circuitClass, DEFAULT_FAMILIES.FORWARD.circuitClass, FORWARD_CIRCUIT_CLASSES, 'FORWARD circuitClass')
      const wireClass = exactClass(merged.wireClass, DEFAULT_FAMILIES.FORWARD.wireClass, STREAM_WIRE_CLASSES, 'FORWARD wireClass')
      if (common.maxBytes > FORWARD_CIRCUIT_CLASSES[circuitClass].maxCircuitBytes) {
        throw new Error('FORWARD maxBytes exceeds circuit class byte limit')
      }
      families[name] = {
        ...common,
        replicas: 0,
        commitQuorum: 0,
        circuitClass,
        wireClass,
        pathHops: positiveInteger(merged.pathHops, DEFAULT_FAMILIES.FORWARD.pathHops),
        trafficBytesPerSecond: positiveInteger(merged.trafficBytesPerSecond, DEFAULT_FAMILIES.FORWARD.trafficBytesPerSecond)
      }
      continue
    }
    const replicas = positiveInteger(merged.replicas, DEFAULT_FAMILIES[name].replicas)
    const commitQuorum = positiveInteger(merged.commitQuorum, DEFAULT_FAMILIES[name].commitQuorum)
    if (commitQuorum > replicas) throw new Error(`${name} commitQuorum must be <= replicas`)
    families[name] = { ...common, replicas, commitQuorum }
    if (name === 'CELL') {
      if (common.maxBytes > CELL_SIZE_CLASSES[5]) throw new Error('CELL maxBytes exceeds fixed class 5')
      families[name].leaseClass = exactClass(merged.leaseClass, DEFAULT_FAMILIES.CELL.leaseClass, LEASE_CLASS_EPOCHS, 'CELL leaseClass')
    } else if (name === 'INBOX') {
      if (common.maxBytes > INBOX_FRAME_CLASSES[3]) throw new Error('INBOX maxBytes exceeds fixed frame class 3')
      families[name].allocationLeaseClass = exactClass(merged.allocationLeaseClass, DEFAULT_FAMILIES.INBOX.allocationLeaseClass, LEASE_CLASS_EPOCHS, 'INBOX allocationLeaseClass')
      families[name].retentionClass = exactClass(merged.retentionClass, DEFAULT_FAMILIES.INBOX.retentionClass, LEASE_CLASS_EPOCHS, 'INBOX retentionClass')
      families[name].logicalInboxCount = positiveInteger(merged.logicalInboxCount, DEFAULT_FAMILIES.INBOX.logicalInboxCount)
    } else {
      if (common.maxBytes > 64 * MIB) throw new Error('CORE maxBytes exceeds the maximum admitted mirror corpus')
      families[name].mirrorLeaseClass = exactClass(merged.mirrorLeaseClass, DEFAULT_FAMILIES.CORE.mirrorLeaseClass, LEASE_CLASS_EPOCHS, 'CORE mirrorLeaseClass')
      families[name].sessionClass = exactClass(merged.sessionClass, DEFAULT_FAMILIES.CORE.sessionClass, CORE_SESSION_CLASSES, 'CORE sessionClass')
      families[name].openReplicationsPerSecond = nonNegativeNumber(merged.openReplicationsPerSecond, DEFAULT_FAMILIES.CORE.openReplicationsPerSecond) * rateScale
      families[name].openReplicationMinBytes = positiveInteger(merged.openReplicationMinBytes, DEFAULT_FAMILIES.CORE.openReplicationMinBytes)
      families[name].openReplicationMaxBytes = positiveInteger(merged.openReplicationMaxBytes, DEFAULT_FAMILIES.CORE.openReplicationMaxBytes)
      families[name].openReplicationTrafficBytesPerSecond = positiveInteger(merged.openReplicationTrafficBytesPerSecond, DEFAULT_FAMILIES.CORE.openReplicationTrafficBytesPerSecond)
      if (families[name].openReplicationMaxBytes < families[name].openReplicationMinBytes) {
        throw new Error('CORE openReplicationMaxBytes must be >= openReplicationMinBytes')
      }
      if (families[name].openReplicationMaxBytes > CORE_SESSION_CLASSES[families[name].sessionClass].maxSessionBytes) {
        throw new Error('CORE open replication bytes exceed the selected session class')
      }
    }
  }
  const durationMillis = alignMillis(durationSeconds * 1000, tickMillis)
  const faults = normalizeFaults(input.faults, { durationMillis, tickMillis, relayCount, operatorCount, regionCount })
  const relayMaxAdmissionsPerSecond = positiveInteger(input.relayMaxAdmissionsPerSecond, DEFAULT_BLIND_FLEET_CONFIG.relayMaxAdmissionsPerSecond)
  return {
    seed: String(input.seed || DEFAULT_BLIND_FLEET_CONFIG.seed),
    durationSeconds: durationMillis / 1000,
    durationMillis,
    tickMillis,
    relayCount,
    operatorCount,
    regionCount,
    relayCapacityBytes: positiveInteger(input.relayCapacityBytes, DEFAULT_BLIND_FLEET_CONFIG.relayCapacityBytes),
    relayBandwidthMbps: positiveNumber(input.relayBandwidthMbps, DEFAULT_BLIND_FLEET_CONFIG.relayBandwidthMbps),
    relayDiskWriteMbps: positiveNumber(input.relayDiskWriteMbps, DEFAULT_BLIND_FLEET_CONFIG.relayDiskWriteMbps),
    relayDiskReadMbps: positiveNumber(input.relayDiskReadMbps, DEFAULT_BLIND_FLEET_CONFIG.relayDiskReadMbps),
    relayDiskIopsPerSecond: positiveNumber(input.relayDiskIopsPerSecond, DEFAULT_BLIND_FLEET_CONFIG.relayDiskIopsPerSecond),
    relayFsyncsPerSecond: positiveNumber(input.relayFsyncsPerSecond, DEFAULT_BLIND_FLEET_CONFIG.relayFsyncsPerSecond),
    relayCpuCores: positiveNumber(input.relayCpuCores, DEFAULT_BLIND_FLEET_CONFIG.relayCpuCores),
    resourceWalRecordBytes: positiveInteger(input.resourceWalRecordBytes, DEFAULT_BLIND_FLEET_CONFIG.resourceWalRecordBytes),
    resourceWalRecordsPerMutation: positiveInteger(input.resourceWalRecordsPerMutation, DEFAULT_BLIND_FLEET_CONFIG.resourceWalRecordsPerMutation),
    resourceWalGroupCommitRecords: positiveInteger(input.resourceWalGroupCommitRecords, DEFAULT_BLIND_FLEET_CONFIG.resourceWalGroupCommitRecords),
    resourceCpuFixedMicros: nonNegativeNumber(input.resourceCpuFixedMicros, DEFAULT_BLIND_FLEET_CONFIG.resourceCpuFixedMicros),
    resourceCpuMicrosPerKiB: nonNegativeNumber(input.resourceCpuMicrosPerKiB, DEFAULT_BLIND_FLEET_CONFIG.resourceCpuMicrosPerKiB),
    maxResourceBacklogSeconds: positiveNumber(input.maxResourceBacklogSeconds, DEFAULT_BLIND_FLEET_CONFIG.maxResourceBacklogSeconds),
    maxGrowingBacklogTicks: positiveInteger(input.maxGrowingBacklogTicks, DEFAULT_BLIND_FLEET_CONFIG.maxGrowingBacklogTicks),
    relayMaxAdmissionsPerSecond,
    relayMaxAdmissionsPerTick: Math.max(1, Math.floor(relayMaxAdmissionsPerSecond * tickMillis / 1000)),
    maxDurableObjectsPerRelay: positiveInteger(input.maxDurableObjectsPerRelay, DEFAULT_BLIND_FLEET_CONFIG.maxDurableObjectsPerRelay),
    maxActiveForwardCircuitsPerRelay: positiveInteger(input.maxActiveForwardCircuitsPerRelay, DEFAULT_BLIND_FLEET_CONFIG.maxActiveForwardCircuitsPerRelay),
    maxActiveCoreReplicationSessionsPerRelay: positiveInteger(input.maxActiveCoreReplicationSessionsPerRelay, DEFAULT_BLIND_FLEET_CONFIG.maxActiveCoreReplicationSessionsPerRelay),
    bandwidthWriteShare: probability(input.bandwidthWriteShare, DEFAULT_BLIND_FLEET_CONFIG.bandwidthWriteShare),
    epochMillis: alignMillis(positiveInteger(input.epochMillis, DEFAULT_BLIND_FLEET_CONFIG.epochMillis), tickMillis),
    churnEventsPerRelayHour: nonNegativeNumber(input.churnEventsPerRelayHour, DEFAULT_BLIND_FLEET_CONFIG.churnEventsPerRelayHour),
    churnMinSeconds: positiveInteger(input.churnMinSeconds, DEFAULT_BLIND_FLEET_CONFIG.churnMinSeconds),
    churnMaxSeconds: positiveInteger(input.churnMaxSeconds, DEFAULT_BLIND_FLEET_CONFIG.churnMaxSeconds),
    repairGraceMillis: alignMillis(positiveNumber(input.repairGraceSeconds, DEFAULT_BLIND_FLEET_CONFIG.repairGraceSeconds) * 1000, tickMillis),
    repairScanPerTick: positiveInteger(input.repairScanPerTick, DEFAULT_BLIND_FLEET_CONFIG.repairScanPerTick),
    repairSurgeReplicas: nonNegativeInteger(input.repairSurgeReplicas, DEFAULT_BLIND_FLEET_CONFIG.repairSurgeReplicas),
    availabilitySampleSize: positiveInteger(input.availabilitySampleSize, DEFAULT_BLIND_FLEET_CONFIG.availabilitySampleSize),
    evidenceSampleEveryTicks: Math.max(1, Math.ceil(positiveNumber(input.evidenceSampleSeconds, DEFAULT_BLIND_FLEET_CONFIG.evidenceSampleSeconds) * 1000 / tickMillis)),
    invalidAdmissionProbeEvery: positiveInteger(input.invalidAdmissionProbeEvery, DEFAULT_BLIND_FLEET_CONFIG.invalidAdmissionProbeEvery),
    families,
    faults,
    objectives: { ...DEFAULT_BLIND_FLEET_CONFIG.objectives, ...(input.objectives || {}) }
  }
}

function normalizeFaults (faults, config) {
  const raw = faults === null || faults === false
    ? []
    : Array.isArray(faults)
      ? faults
      : defaultFaults(config)
  return raw.map((fault, index) => {
    const atMillis = alignMillis(nonNegativeNumber(fault.atSeconds, 0) * 1000, config.tickMillis)
    const durationMillis = alignMillis(positiveNumber(fault.durationSeconds, 1) * 1000, config.tickMillis)
    const type = String(fault.type)
    if (!['partition', 'operator-outage', 'relay-crash', 'disk-loss'].includes(type)) throw new Error(`unsupported fault type ${type}`)
    const normalized = {
      id: String(fault.id || `fault-${String(index).padStart(2, '0')}`),
      type,
      atMillis,
      endMillis: Math.min(config.durationMillis, atMillis + durationMillis)
    }
    if (type === 'partition') normalized.regionIds = (fault.regionIds || ['region-0']).map(String).sort()
    if (type === 'operator-outage') normalized.operatorId = String(fault.operatorId || 'operator-00')
    if (type === 'relay-crash' || type === 'disk-loss') normalized.relayId = String(fault.relayId || 'relay-000')
    return normalized
  }).filter(fault => fault.atMillis < config.durationMillis && fault.endMillis > fault.atMillis)
    .sort((a, b) => a.atMillis - b.atMillis || a.id.localeCompare(b.id))
}

function defaultFaults (config) {
  const seconds = config.durationMillis / 1000
  const at = fraction => Math.floor(seconds * fraction)
  const duration = fraction => Math.max(2, Math.floor(seconds * fraction))
  return [
    { id: 'partition-region-0', type: 'partition', atSeconds: at(0.22), durationSeconds: duration(0.08), regionIds: ['region-0'] },
    { id: 'operator-00-outage', type: 'operator-outage', atSeconds: at(0.46), durationSeconds: duration(0.07), operatorId: 'operator-00' },
    { id: 'relay-001-crash', type: 'relay-crash', atSeconds: at(0.62), durationSeconds: duration(0.05), relayId: `relay-${String(Math.min(1, config.relayCount - 1)).padStart(3, '0')}` },
    { id: 'relay-002-disk-loss', type: 'disk-loss', atSeconds: at(0.72), durationSeconds: duration(0.04), relayId: `relay-${String(Math.min(2, config.relayCount - 1)).padStart(3, '0')}` }
  ]
}

function publicFault (fault) {
  const value = {
    id: fault.id,
    type: fault.type,
    atMillis: fault.atMillis,
    durationMillis: fault.endMillis - fault.atMillis
  }
  if (fault.regionIds) value.regionIds = fault.regionIds
  if (fault.operatorId) value.operatorId = fault.operatorId
  if (fault.relayId) value.relayId = fault.relayId
  return value
}

function publicFamilyConfig (family) {
  const value = {
    writesPerSecond: family.writesPerSecond,
    readsPerSecond: family.readsPerSecond,
    minBytes: family.minBytes,
    maxBytes: family.maxBytes,
    replicas: family.replicas,
    commitQuorum: family.commitQuorum,
    weight: family.weight
  }
  for (const field of ['leaseClass', 'allocationLeaseClass', 'retentionClass', 'logicalInboxCount', 'mirrorLeaseClass', 'sessionClass', 'openReplicationsPerSecond', 'openReplicationMinBytes', 'openReplicationMaxBytes', 'openReplicationTrafficBytesPerSecond', 'circuitClass', 'wireClass', 'pathHops', 'trafficBytesPerSecond']) {
    if (family[field] != null) value[field] = family[field]
  }
  return value
}

function familySemantics (familyName) {
  if (familyName === 'CELL') return { kind: 'FIXED_PADDED_LEASED_CELL', durable: true, repaired: true }
  if (familyName === 'INBOX') return { kind: 'FIXED_PADDED_RETENTION_FRAME', durable: true, repaired: true }
  if (familyName === 'CORE') return { kind: 'LEASED_MIRROR_CORPUS_AND_EPHEMERAL_UPSTREAM_CHILD', durable: 'MIRROR_ONLY', repaired: 'MIRROR_ONLY' }
  return { kind: 'EPHEMERAL_BOUNDED_PATH_STREAM', durable: false, repaired: false }
}

function resourceClassLabel (item) {
  if (item.family === 'CELL') return String(item.sizeClass)
  if (item.family === 'INBOX') return String(item.frameClass)
  if (item.family === 'CORE') return `mirror-lease-${item.mirrorLeaseClass}`
  return `circuit-${item.circuitClass}/wire-${item.wireClass}`
}

function publicResourceQueueConfig (config) {
  return {
    nominalDiskWriteMbps: config.relayDiskWriteMbps,
    nominalDiskReadMbps: config.relayDiskReadMbps,
    nominalDiskIopsPerSecond: config.relayDiskIopsPerSecond,
    nominalFsyncsPerSecond: config.relayFsyncsPerSecond,
    nominalCpuCores: config.relayCpuCores,
    walRecordBytes: config.resourceWalRecordBytes,
    walRecordsPerMutation: config.resourceWalRecordsPerMutation,
    walGroupCommitRecords: config.resourceWalGroupCommitRecords,
    cpuFixedMicros: config.resourceCpuFixedMicros,
    cpuMicrosPerKiB: config.resourceCpuMicrosPerKiB,
    maximumBacklogSeconds: config.maxResourceBacklogSeconds,
    maximumGrowingBacklogTicks: config.maxGrowingBacklogTicks
  }
}

function buildFleetScenarioManifest (config, relays) {
  return {
    schema: BLIND_SCENARIO_MANIFEST_SCHEMA,
    source: 'fleet-simulation',
    relayCount: relays.length,
    relays: relays.map(relay => ({
      id: relay.id,
      operatorId: relay.operatorId,
      regionId: relay.regionId,
      storageBytes: relay.capacityBytes,
      networkMbps: relay.bandwidthMbps,
      diskWriteMbps: relay.storageWriteMbps,
      diskReadMbps: relay.storageReadMbps,
      diskIopsPerSecond: relay.diskIopsPerSecond,
      fsyncsPerSecond: relay.fsyncsPerSecond,
      cpuCores: relay.cpuCores
    })),
    durabilityByFamily: Object.fromEntries(FAMILY_NAMES.map(name => [name, {
      replicas: config.families[name].replicas,
      commitQuorum: config.families[name].commitQuorum
    }])),
    offeredLoad: {
      durationSeconds: config.durationSeconds,
      tickMillis: config.tickMillis,
      families: Object.fromEntries(FAMILY_NAMES.map(name => [name, {
        writesPerSecond: config.families[name].writesPerSecond,
        readsPerSecond: config.families[name].readsPerSecond,
        openReplicationsPerSecond: name === 'CORE'
          ? config.families.CORE.openReplicationsPerSecond
          : 0
      }]))
    },
    objectives: sortValue(config.objectives)
  }
}

function summarizeResourceQueues (relays, config) {
  const byResource = {}
  let maximumPeakBacklogSeconds = 0
  let maximumGrowthStreak = 0
  for (const name of RESOURCE_QUEUE_NAMES) {
    const queues = relays.map(relay => relay.resourceQueues[name])
    const resource = {
      unit: name,
      totalDemand: round3(sum(queues, queue => queue.totalDemand)),
      totalServed: round3(sum(queues, queue => queue.totalServed)),
      finalBacklog: round3(sum(queues, queue => queue.backlog)),
      maximumRelayPeakBacklogSeconds: round6(Math.max(...queues.map(queue => queue.peakBacklogSeconds))),
      maximumRelayGrowthStreak: Math.max(...queues.map(queue => queue.maximumGrowthStreak))
    }
    maximumPeakBacklogSeconds = Math.max(maximumPeakBacklogSeconds,
      resource.maximumRelayPeakBacklogSeconds)
    maximumGrowthStreak = Math.max(maximumGrowthStreak, resource.maximumRelayGrowthStreak)
    byResource[name] = resource
  }
  return {
    model: 'per-relay persistent queue serviced once per deterministic tick; accepted work is never discarded at a tick boundary',
    maximumAllowedBacklogSeconds: config.maxResourceBacklogSeconds,
    maximumAllowedGrowingBacklogTicks: config.maxGrowingBacklogTicks,
    maximumPeakBacklogSeconds: round6(maximumPeakBacklogSeconds),
    maximumGrowthStreak,
    byResource
  }
}

function durableResourceClassError (item) {
  if (item.family === 'CELL') {
    if (!CELL_SIZE_CLASSES[item.sizeClass]) return 'SIZE_CLASS_INVALID'
    if (!LEASE_CLASS_EPOCHS[item.leaseClass]) return 'LEASE_CLASS_INVALID'
    if (item.bytes !== CELL_SIZE_CLASSES[item.sizeClass]) return 'FIXED_CLASS_LENGTH_INVALID'
    return null
  }
  if (item.family === 'INBOX') {
    if (!INBOX_FRAME_CLASSES[item.frameClass]) return 'FRAME_CLASS_INVALID'
    if (!LEASE_CLASS_EPOCHS[item.allocationLeaseClass]) return 'ALLOCATION_LEASE_CLASS_INVALID'
    if (!LEASE_CLASS_EPOCHS[item.retentionClass]) return 'RETENTION_CLASS_INVALID'
    if (item.bytes !== INBOX_FRAME_CLASSES[item.frameClass]) return 'FIXED_CLASS_LENGTH_INVALID'
    return null
  }
  if (item.family === 'CORE') {
    if (item.operation !== 'MIRROR') return 'CORE_OPERATION_INVALID'
    if (!LEASE_CLASS_EPOCHS[item.mirrorLeaseClass]) return 'LEASE_CLASS_INVALID'
    if (item.bytes !== item.payloadBytes || item.bytes > 64 * MIB) return 'CORE_CORPUS_INVALID'
    return null
  }
  return 'DURABLE_FAMILY_INVALID'
}

function selectFixedClass (payloadBytes, classes) {
  for (const classId of Object.keys(classes).map(Number).sort((a, b) => a - b)) {
    if (payloadBytes <= classes[classId]) return { classId, bytes: classes[classId] }
  }
  throw new Error('payload exceeds the largest fixed class')
}

function exactClass (value, fallback, classes, field) {
  const selected = value == null ? fallback : Number(value)
  if (!Number.isSafeInteger(selected) || !classes[selected]) throw new Error(`${field} is not registered`)
  return selected
}

class LatencyHistogram {
  constructor () {
    this.buckets = new Map()
    this.count = 0
    this.sum = 0
    this.maximum = 0
  }

  add (value, count = 1) {
    if (!Number.isFinite(value) || count <= 0) return
    const bucket = Math.max(0, Math.ceil(value))
    this.buckets.set(bucket, (this.buckets.get(bucket) || 0) + count)
    this.count += count
    this.sum += value * count
    this.maximum = Math.max(this.maximum, value)
  }

  merge (other) {
    for (const [bucket, count] of other.buckets) this.buckets.set(bucket, (this.buckets.get(bucket) || 0) + count)
    this.count += other.count
    this.sum += other.sum
    this.maximum = Math.max(this.maximum, other.maximum)
    return this
  }

  percentile (p) {
    if (this.count === 0) return 0
    const target = Math.ceil(this.count * p)
    let seen = 0
    for (const [bucket, count] of [...this.buckets.entries()].sort((a, b) => a[0] - b[0])) {
      seen += count
      if (seen >= target) return bucket
    }
    return Math.ceil(this.maximum)
  }

  summary () {
    return {
      samples: this.count,
      average: this.count > 0 ? round3(this.sum / this.count) : 0,
      p50: this.percentile(0.5),
      p95: this.percentile(0.95),
      p99: this.percentile(0.99),
      maximum: round3(this.maximum)
    }
  }
}

function mergeLatency (histograms) {
  const merged = new LatencyHistogram()
  for (const histogram of histograms) merged.merge(histogram)
  return merged
}

class DeterministicRandom {
  constructor (seed) {
    this.state = seed >>> 0
  }

  next () {
    this.state += 0x6D2B79F5
    let t = this.state
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }

  int (maxValue) {
    if (maxValue <= 1) return 0
    return Math.floor(this.next() * maxValue)
  }
}

function rngFor (seed) {
  return new DeterministicRandom(hash32(seed))
}

function hash32 (input) {
  let hash = 2166136261
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return hash >>> 0
}

function digest (value) {
  return createHash('sha256').update(stableStringify(value)).digest('hex')
}

function sortValue (value) {
  if (Array.isArray(value)) return value.map(sortValue)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sortValue(value[key])]))
  }
  return value
}

function sortedObject (value) {
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]]))
}

function increment (object, key) {
  object[key] = (object[key] || 0) + 1
}

function sum (values, project) {
  let total = 0
  for (const value of values) total += project(value)
  return total
}

function max (values, project) {
  let value = 0
  for (const item of values) value = Math.max(value, project(item))
  return round6(value)
}

function ratio (numerator, denominator) {
  return denominator > 0 ? round6(numerator / denominator) : 0
}

function ratioOrOne (numerator, denominator) {
  return denominator > 0 ? round6(numerator / denominator) : 1
}

function round3 (value) {
  return Math.round(value * 1000) / 1000
}

function round6 (value) {
  return Math.round(value * 1000000) / 1000000
}

function gcd (a, b) {
  let x = Math.abs(a)
  let y = Math.abs(b)
  while (y > 0) {
    const next = x % y
    x = y
    y = next
  }
  return x
}

function alignMillis (value, tickMillis) {
  return Math.max(tickMillis, Math.ceil(value / tickMillis) * tickMillis)
}

function positiveInteger (value, fallback) {
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback
}

function nonNegativeInteger (value, fallback) {
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback
}

function positiveNumber (value, fallback) {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

function nonNegativeNumber (value, fallback) {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback
}

function probability (value, fallback) {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= 1 ? parsed : fallback
}

function parseArgs (argv) {
  const result = {}
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index]
    if (!argument.startsWith('--')) continue
    const name = argument.slice(2)
    const next = argv[index + 1]
    if (!next || next.startsWith('--')) result[name] = true
    else {
      result[name] = next
      index++
    }
  }
  return result
}

function cliConfig (args) {
  return {
    seed: args.seed,
    durationSeconds: args.duration,
    relayCount: args.relays,
    operatorCount: args.operators,
    regionCount: args.regions,
    rateScale: args['rate-scale'],
    relayCapacityBytes: args['capacity-mib'] == null ? undefined : Number(args['capacity-mib']) * MIB,
    relayBandwidthMbps: args['bandwidth-mbps'],
    churnEventsPerRelayHour: args['churn-per-hour'],
    faults: args['no-faults'] === true ? false : undefined
  }
}

function printHelp () {
  process.stdout.write('Usage: node scripts/simulate-blind-fleet.mjs [options]\n\n' +
    '  --seed <text>             deterministic seed\n' +
    '  --duration <seconds>      virtual duration\n' +
    '  --relays <count>          relay count\n' +
    '  --operators <count>       independent operator groups\n' +
    '  --regions <count>         relay regions\n' +
    '  --rate-scale <number>     multiply all family read/write rates\n' +
    '  --capacity-mib <number>   nominal capacity per relay\n' +
    '  --bandwidth-mbps <number> nominal relay bandwidth\n' +
    '  --churn-per-hour <number> stochastic churn rate per relay\n' +
    '  --no-faults               disable the deterministic fault plan\n' +
    '  --compact                 emit compact JSON\n' +
    '  --out <path>              write the same JSON evidence to a file\n' +
    '  --assert                  exit non-zero if any assertion fails\n')
}

function main () {
  const args = parseArgs(process.argv.slice(2))
  if (args.help === true) {
    printHelp()
    return
  }
  const evidence = runBlindFleetSimulation(cliConfig(args))
  const json = stableStringify(evidence, args.compact === true ? 0 : 2) + '\n'
  if (args.out) writeFileSync(String(args.out), json, { flag: 'w' })
  process.stdout.write(json)
  if (args.assert === true && !evidence.ok) process.exitCode = 1
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : ''
if (import.meta.url === invokedPath) main()
