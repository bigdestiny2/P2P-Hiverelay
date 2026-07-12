#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  BLIND_SCENARIO_MANIFEST_SCHEMA,
  CAPACITY_LAB_CONFIG_SCHEMA,
  normalizeCapacityLabConfig,
  runCapacityLab
} from './blind-capacity-lab.mjs'
import {
  runBlindFleetSimulation,
  stableStringify,
  verifyBlindFleetEvidenceDigest
} from './simulate-blind-fleet.mjs'
import {
  BLIND_RELEASE_LAB_PROFILES,
  buildFleetAlignedCapacityConfig
} from './run-blind-release-lab.mjs'

export const CAPACITY_SIZING_PLAN_SCHEMA = 'hiverelay/blind-capacity-sizing-plan/v1'
export const CAPACITY_SIZING_SEARCH_SCHEMA = 'hiverelay/blind-capacity-sizing-search/v1'

const SCALE_KEYS = Object.freeze([
  'storageBytes',
  'diskWrite',
  'diskRead',
  'diskIops',
  'walFsyncThroughput',
  'networkIngress',
  'networkEgress',
  'cpu',
  'streamBuffer',
  'streamSlots',
  'inboxWaiterMemory',
  'inboxWaiterSlots'
])

const BASELINE_SCALES = Object.freeze(Object.fromEntries(SCALE_KEYS.map(key => [key, 1])))

function scaledProfile (id, label, performanceScale, storageScale = performanceScale) {
  return Object.freeze({
    id,
    label,
    scales: Object.freeze({
      storageBytes: storageScale,
      diskWrite: performanceScale,
      diskRead: performanceScale,
      diskIops: performanceScale,
      walFsyncThroughput: performanceScale,
      networkIngress: performanceScale,
      networkEgress: performanceScale,
      cpu: performanceScale,
      streamBuffer: performanceScale,
      streamSlots: performanceScale,
      inboxWaiterMemory: performanceScale,
      inboxWaiterSlots: performanceScale
    })
  })
}

export const DEFAULT_CAPACITY_SIZING_SEARCH = deepFreeze({
  schema: CAPACITY_SIZING_SEARCH_SCHEMA,
  relayCounts: [24, 48, 72, 96, 144],
  hardwareProfiles: [
    { id: 'source-envelope', label: 'Source model envelope', scales: BASELINE_SCALES },
    {
      id: 'storage-64x',
      label: 'Storage-only 64x target',
      scales: { ...BASELINE_SCALES, storageBytes: 64 }
    },
    scaledProfile('balanced-8x-storage-64x', 'Balanced 8x target with 64x storage', 8, 64),
    scaledProfile('balanced-16x-storage-64x', 'Balanced 16x target with 64x storage', 16, 64),
    scaledProfile('balanced-32x-storage-64x', 'Balanced 32x target with 64x storage', 32, 64),
    scaledProfile('balanced-64x-storage-64x', 'Balanced 64x target with 64x storage', 64, 64),
    scaledProfile('balanced-128x', 'Balanced 128x target', 128)
  ],
  minimumModeledLogicalObjects: 0,
  minimumModeledLogicalPayloadBytes: 0
})

export class CapacitySizingError extends Error {
  constructor (violations) {
    super(`invalid blind capacity sizing input: ${violations.join('; ')}`)
    this.name = 'CapacitySizingError'
    this.code = 'INVALID_CAPACITY_SIZING_INPUT'
    this.violations = violations
  }
}

/**
 * Construct the externally-bound input used by the CLI. The source is the exact
 * fleet-to-capacity mapping already owned by the release lab. It remains
 * deterministic model evidence; neither the fleet nor the target hardware is
 * represented as observed production hardware.
 */
export function buildReleaseCapacitySizingInput (profileName = 'release', search = {}) {
  const profile = BLIND_RELEASE_LAB_PROFILES[profileName]
  if (!profile) throw new CapacitySizingError([`unknown release profile ${profileName}`])
  const fleet = runBlindFleetSimulation(profile.fleet)
  if (!verifyBlindFleetEvidenceDigest(fleet)) {
    throw new CapacitySizingError(['source fleet evidence checksum does not verify'])
  }
  const capacityConfig = normalizeCapacityLabConfig(buildFleetAlignedCapacityConfig(fleet))
  return {
    capacityConfig,
    sourceAuthority: {
      kind: fleet.kind,
      schemaVersion: fleet.schemaVersion,
      scenarioSchema: fleet.scenarioManifest.schema,
      scenarioDigest: fleet.scenarioDigest,
      evidenceDigest: fleet.evidenceDigest,
      capacityConfigDigest: sha256(stableStringify(capacityConfig)),
      sourceProfile: profileName,
      evidenceClass: 'deterministic-simulation-not-observed',
      authenticityProven: false
    },
    search
  }
}

export function runCapacitySizingPlan (input) {
  const normalized = normalizeSizingInput(input)
  const source = normalized.capacityConfig
  const authority = buildWorkloadAuthority(source, normalized.sourceAuthority)
  const sourceBaseline = runCapacityLab(source)
  const candidates = []

  for (let relayIndex = 0; relayIndex < normalized.search.relayCounts.length; relayIndex++) {
    const relayCount = normalized.search.relayCounts[relayIndex]
    for (let profileIndex = 0; profileIndex < normalized.search.hardwareProfiles.length; profileIndex++) {
      const profile = normalized.search.hardwareProfiles[profileIndex]
      const config = buildCandidateConfig(source, relayCount, profile)
      const capacity = runCapacityLab(config)
      candidates.push(buildCandidate({
        capacity,
        config,
        authority,
        relayCount,
        relayIndex,
        profile,
        profileIndex,
        search: normalized.search
      }))
    }
  }

  const answers = buildSizingAnswers(candidates, normalized.search)
  const transitions = buildBottleneckTransitions(candidates, normalized.search)
  const sourceRelayCount = source.fleet.relayCount
  const conservativeSourceMinCandidate = candidates.find(candidate =>
    candidate.relayCount === sourceRelayCount && candidate.profileIndex === 0)
  if (!conservativeSourceMinCandidate) throw new CapacitySizingError(['internal source-envelope candidate is missing'])

  const body = {
    schema: CAPACITY_SIZING_PLAN_SCHEMA,
    status: 'complete',
    planningStatus: answers.modeledTargetFoundInSearch
      ? 'modeled-fit-found-in-enumerated-search'
      : 'no-modeled-fit-in-enumerated-search',
    evidenceClass: 'modeled-target-hardware-not-observed',
    claimBoundary: 'This deterministic sizing sweep compares enumerated target assumptions. It is not a hardware benchmark, observation of any relay, production capacity evidence, release authorization, or a universal minimum-hardware proof.',
    authority,
    search: normalized.search,
    searchDigest: sha256(stableStringify(normalized.search)),
    sourceRelayCountInjectedIntoSearch: normalized.sourceRelayCountInjectedIntoSearch,
    baselineReference: {
      sourceCapacityConfigDigest: sourceBaseline.configDigest,
      sourceCapacityScenarioDigest: sourceBaseline.scenarioDigest,
      relayCount: source.fleet.relayCount,
      storageBytesByRelay: sourceBaseline.scenarioManifest.storageBytesByRelay,
      capacityModelStatus: sourceBaseline.status,
      modeledSustainableLogicalOpsPerSecond: sourceBaseline.throughput.modeledSustainableLogicalOpsPerSecond,
      bottleneck: sourceBaseline.throughput.bottleneck,
      conservativeHomogeneousSourceMinimumCandidateId: conservativeSourceMinCandidate.id,
      releaseGateStatus: 'unchanged-not-evaluated'
    },
    releaseAuthority: {
      authorizesRelease: false,
      changesBaselineReleaseGate: false,
      productionHardwareObserved: false,
      signedByOperator: false,
      instruction: 'Treat a modeled fit as a procurement/benchmark target only. The existing composite release and mainnet gates must consume separately verified observed evidence.'
    },
    answers,
    bottleneckAnalysis: transitions,
    candidates,
    limitations: [
      'Minimum means the first fit in the explicitly ordered, component-wise nondecreasing search lattice; it is not an optimizer over every possible hardware combination.',
      'Every candidate preserves the exact source workload, operation weights, offered logical rate, quorum and durability contract. Only relay count and enumerated per-relay resources change.',
      'Target resource values are assumptions. Operators must benchmark the exact storage engine, filesystem, kernel, transport, host contention and network path.',
      'The analytical model treats relay performance as homogeneous and reports the worst modeled relay; independent failure domains, correlated outages and adversarial routing require the fleet simulation and multi-host drills.',
      'Content capacity is the configured retained CELL mix. INBOX and CORE dedicated projections remain mutually exclusive surfaces in the underlying capacity report.',
      'A report checksum detects byte drift only when the expected checksum is trusted. Authenticity requires a separate verified signature and trust root.'
    ]
  }
  return { ...body, reportDigest: sha256(stableStringify(body)) }
}

export function verifyCapacitySizingPlanDigest (report) {
  if (!isPlainObject(report) || typeof report.reportDigest !== 'string') return false
  const { reportDigest, ...body } = report
  return reportDigest === sha256(stableStringify(body))
}

/**
 * Owning verification requires the expected input from outside the report and
 * reruns the complete deterministic search. Rehashing fields taken from the
 * report itself would be a self-sealing checksum, not an authority check.
 */
export function verifyCapacitySizingPlan (report, expectedInput) {
  const checks = []
  checks.push(check('REPORT_DIGEST', verifyCapacitySizingPlanDigest(report), report?.reportDigest, 'digest(recomputed report body)'))
  let expected = null
  try {
    expected = runCapacitySizingPlan(expectedInput)
    checks.push(check('EXTERNAL_SOURCE_SCENARIO',
      report?.authority?.source?.scenarioDigest === expected.authority.source.scenarioDigest,
      report?.authority?.source?.scenarioDigest,
      expected.authority.source.scenarioDigest))
    checks.push(check('EXACT_WORKLOAD_AUTHORITY',
      report?.authority?.workloadDigest === expected.authority.workloadDigest,
      report?.authority?.workloadDigest,
      expected.authority.workloadDigest))
    checks.push(check('EXACT_DETERMINISTIC_PLAN', stableStringify(report) === stableStringify(expected),
      report?.reportDigest, expected.reportDigest))
  } catch (error) {
    checks.push(check('EXPECTED_INPUT_VALID', false, error.message, 'valid externally supplied sizing input'))
  }
  const blockers = checks.filter(item => !item.passed).map(item => item.id)
  return {
    evidenceClass: 'externally-bound-deterministic-rerun',
    authenticReleaseEvidence: false,
    authorizesRelease: false,
    passed: blockers.length === 0,
    blockers,
    checks
  }
}

function normalizeSizingInput (input) {
  const violations = []
  if (!isPlainObject(input)) throw new CapacitySizingError(['input must be an object'])
  rejectUnknownFields(input, ['capacityConfig', 'sourceAuthority', 'search'], 'input', violations)
  let capacityConfig = null
  try {
    capacityConfig = normalizeCapacityLabConfig(input.capacityConfig)
  } catch (error) {
    violations.push(error.message)
  }
  validateSourceAuthority(input.sourceAuthority, violations)
  const search = normalizeSearch(input.search, capacityConfig, violations)
  if (capacityConfig?.schema !== CAPACITY_LAB_CONFIG_SCHEMA) {
    violations.push(`capacityConfig.schema must be ${CAPACITY_LAB_CONFIG_SCHEMA}`)
  }
  if (!(capacityConfig?.workload?.offeredLogicalOpsPerSecond > 0)) {
    violations.push('capacityConfig.workload.offeredLogicalOpsPerSecond must be explicit and positive')
  }
  if (capacityConfig && input.sourceAuthority?.capacityConfigDigest !== sha256(stableStringify(capacityConfig))) {
    violations.push('sourceAuthority.capacityConfigDigest must bind the exact normalized capacityConfig')
  }
  if (violations.length) throw new CapacitySizingError(violations)
  const requestedRelayCounts = Array.isArray(input.search?.relayCounts)
    ? input.search.relayCounts
    : DEFAULT_CAPACITY_SIZING_SEARCH.relayCounts
  const injected = !requestedRelayCounts.includes(capacityConfig.fleet.relayCount)
  return {
    capacityConfig,
    sourceAuthority: clone(input.sourceAuthority),
    search,
    sourceRelayCountInjectedIntoSearch: injected
  }
}

function normalizeSearch (input, capacityConfig, violations) {
  if (input !== undefined && !isPlainObject(input)) {
    violations.push('search must be an object')
    input = {}
  }
  const supplied = input || {}
  rejectUnknownFields(supplied, [
    'schema',
    'relayCounts',
    'hardwareProfiles',
    'minimumModeledLogicalObjects',
    'minimumModeledLogicalPayloadBytes'
  ], 'search', violations)
  const search = deepMerge(DEFAULT_CAPACITY_SIZING_SEARCH, supplied)
  if (search.schema !== CAPACITY_SIZING_SEARCH_SCHEMA) {
    violations.push(`search.schema must be ${CAPACITY_SIZING_SEARCH_SCHEMA}`)
  }

  if (!Array.isArray(search.relayCounts) || search.relayCounts.length === 0) {
    violations.push('search.relayCounts must be a non-empty array')
  } else {
    const minimum = Math.max(
      capacityConfig?.fleet?.replicationFactor || 1,
      capacityConfig?.workload?.readFanout || 1,
      capacityConfig?.workload?.writeAcks || 1
    )
    for (let i = 0; i < search.relayCounts.length; i++) {
      integer(search.relayCounts[i], `search.relayCounts[${i}]`, minimum, 10_000, violations)
      if (i > 0 && search.relayCounts[i] <= search.relayCounts[i - 1]) {
        violations.push('search.relayCounts must be strictly increasing')
      }
    }
  }

  const sourceRelayCount = capacityConfig?.fleet?.relayCount
  if (Number.isSafeInteger(sourceRelayCount) && Array.isArray(search.relayCounts)) {
    search.relayCounts = [...new Set([...search.relayCounts, sourceRelayCount])].sort((a, b) => a - b)
  }
  validateHardwareProfiles(search.hardwareProfiles, violations)
  nonNegativeInteger(search.minimumModeledLogicalObjects, 'search.minimumModeledLogicalObjects', violations)
  nonNegativeInteger(search.minimumModeledLogicalPayloadBytes, 'search.minimumModeledLogicalPayloadBytes', violations)
  return search
}

function validateSourceAuthority (authority, violations) {
  if (!isPlainObject(authority)) {
    violations.push('sourceAuthority must be an object')
    return
  }
  rejectUnknownFields(authority, [
    'kind',
    'schemaVersion',
    'scenarioSchema',
    'scenarioDigest',
    'evidenceDigest',
    'capacityConfigDigest',
    'sourceProfile',
    'evidenceClass',
    'authenticityProven'
  ], 'sourceAuthority', violations)
  for (const field of ['kind', 'scenarioSchema', 'sourceProfile']) {
    if (typeof authority[field] !== 'string' || authority[field].length === 0) {
      violations.push(`sourceAuthority.${field} must be a non-empty string`)
    }
  }
  integer(authority.schemaVersion, 'sourceAuthority.schemaVersion', 1, 1000, violations)
  if (authority.kind !== 'hiverelay-blind-fleet-simulation-evidence') {
    violations.push('sourceAuthority.kind must be hiverelay-blind-fleet-simulation-evidence')
  }
  if (authority.schemaVersion !== 3) {
    violations.push('sourceAuthority.schemaVersion must be the current fleet evidence schema 3')
  }
  if (authority.scenarioSchema !== BLIND_SCENARIO_MANIFEST_SCHEMA) {
    violations.push(`sourceAuthority.scenarioSchema must be ${BLIND_SCENARIO_MANIFEST_SCHEMA}`)
  }
  for (const field of ['scenarioDigest', 'evidenceDigest', 'capacityConfigDigest']) {
    if (typeof authority[field] !== 'string' || !/^[0-9a-f]{64}$/.test(authority[field])) {
      violations.push(`sourceAuthority.${field} must be a lowercase SHA-256 digest`)
    }
  }
  if (authority.evidenceClass !== 'deterministic-simulation-not-observed') {
    violations.push('sourceAuthority.evidenceClass must be deterministic-simulation-not-observed')
  }
  if (authority.authenticityProven !== false) {
    violations.push('sourceAuthority.authenticityProven must be false for the modeled source')
  }
}

function validateHardwareProfiles (profiles, violations) {
  if (!Array.isArray(profiles) || profiles.length === 0) {
    violations.push('search.hardwareProfiles must be a non-empty array')
    return
  }
  const ids = new Set()
  let previous = null
  for (let index = 0; index < profiles.length; index++) {
    const profile = profiles[index]
    const path = `search.hardwareProfiles[${index}]`
    if (!isPlainObject(profile)) {
      violations.push(`${path} must be an object`)
      continue
    }
    rejectUnknownFields(profile, ['id', 'label', 'scales'], path, violations)
    if (typeof profile.id !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(profile.id) || ids.has(profile.id)) {
      violations.push(`${path}.id must be a unique lowercase slug`)
    } else ids.add(profile.id)
    if (typeof profile.label !== 'string' || profile.label.length === 0 || profile.label.length > 120) {
      violations.push(`${path}.label must be a non-empty string no longer than 120 characters`)
    }
    if (!isPlainObject(profile.scales)) {
      violations.push(`${path}.scales must be an object`)
      continue
    }
    rejectUnknownFields(profile.scales, SCALE_KEYS, `${path}.scales`, violations)
    for (const key of SCALE_KEYS) {
      positive(profile.scales[key], `${path}.scales.${key}`, violations)
      if (index === 0 && profile.scales[key] !== 1) {
        violations.push(`the first hardware profile must be the unmodified source envelope (${key}=1)`)
      }
      if (previous && Number.isFinite(profile.scales[key]) && profile.scales[key] < previous[key]) {
        violations.push(`${path}.scales.${key} must not decrease from the previous profile`)
      }
    }
    previous = profile.scales
  }
}

function buildWorkloadAuthority (config, sourceAuthority) {
  const workload = clone(config.workload)
  const operationMix = workload.operations.map(operation => clone(operation))
  const durability = {
    replicationFactor: config.fleet.replicationFactor,
    readFanout: workload.readFanout,
    readQuorum: workload.readQuorum,
    writeAcks: workload.writeAcks
  }
  const storageSemantics = {
    objects: clone(config.objects),
    checkpoint: clone(config.checkpoint),
    repair: clone(config.repair),
    walFormatAllowances: {
      recordOverheadBytes: config.wal.recordOverheadBytes,
      alignmentBytes: config.wal.alignmentBytes,
      effectiveGroupCommitRecords: config.wal.effectiveGroupCommitRecords,
      reserveFractionOfDisk: config.wal.reserveFractionOfDisk,
      retentionSeconds: config.wal.retentionSeconds
    }
  }
  return {
    source: clone(sourceAuthority),
    capacityConfigSchema: config.schema,
    sourceCapacityConfigDigest: sha256(stableStringify(config)),
    offeredLogicalOpsPerSecond: workload.offeredLogicalOpsPerSecond,
    operationKinds: operationMix.map(operation => `${operation.family}:${operation.operation}`),
    operationMixDigest: sha256(stableStringify(operationMix)),
    workloadDigest: sha256(stableStringify(workload)),
    durability,
    durabilityDigest: sha256(stableStringify(durability)),
    storageSemanticsDigest: sha256(stableStringify(storageSemantics)),
    binding: 'Every candidate is regenerated from this normalized capacity config and must preserve the exact workload and durability digests.'
  }
}

function buildCandidateConfig (source, relayCount, profile) {
  const baseDiskBytes = source.fleet.diskBytesByRelay === null
    ? source.fleet.diskBytesPerRelay
    : Math.min(...source.fleet.diskBytesByRelay)
  const scales = profile.scales
  const diskBytesPerRelay = Math.ceil(baseDiskBytes * scales.storageBytes)
  const aggregateDiskBytes = diskBytesPerRelay * relayCount
  if (!Number.isSafeInteger(diskBytesPerRelay) || !Number.isSafeInteger(aggregateDiskBytes)) {
    throw new CapacitySizingError([`candidate ${relayCount}:${profile.id} disk sizing exceeds safe integer report bounds`])
  }
  return normalizeCapacityLabConfig(deepMerge(source, {
    seed: `${source.seed}:sizing:${relayCount}:${profile.id}`,
    simulation: {
      sampleObjects: Math.max(source.simulation.sampleObjects, relayCount * 100),
      scaleRelayCounts: []
    },
    fleet: {
      relayCount,
      diskBytesPerRelay,
      diskBytesByRelay: null,
      unavailableRelays: Math.min(source.fleet.unavailableRelays, relayCount - 1)
    },
    disk: {
      sequentialWriteBytesPerSecond: source.disk.sequentialWriteBytesPerSecond * scales.diskWrite,
      sequentialReadBytesPerSecond: source.disk.sequentialReadBytesPerSecond * scales.diskRead,
      randomIopsPerSecond: source.disk.randomIopsPerSecond * scales.diskIops
    },
    wal: {
      fsyncLatencyMs: source.wal.fsyncLatencyMs / scales.walFsyncThroughput
    },
    network: {
      ingressBitsPerSecond: source.network.ingressBitsPerSecond * scales.networkIngress,
      egressBitsPerSecond: source.network.egressBitsPerSecond * scales.networkEgress
    },
    cpu: {
      coresPerRelay: source.cpu.coresPerRelay * scales.cpu
    },
    streams: {
      maxBufferedBytesPerRelay: Math.ceil(source.streams.maxBufferedBytesPerRelay * scales.streamBuffer),
      maxConcurrentStreamsPerRelay: Math.ceil(source.streams.maxConcurrentStreamsPerRelay * scales.streamSlots)
    },
    surfaces: {
      inboxWaiterMemoryBytesPerRelay: Math.ceil(source.surfaces.inboxWaiterMemoryBytesPerRelay * scales.inboxWaiterMemory),
      inboxMaxWaitersPerRelay: Math.ceil(source.surfaces.inboxMaxWaitersPerRelay * scales.inboxWaiterSlots)
    }
  }))
}

function buildCandidate (context) {
  const { capacity, config, authority, relayCount, relayIndex, profile, profileIndex, search } = context
  const sustainable = capacity.throughput.modeledSustainableLogicalOpsPerSecond
  const target = authority.offeredLogicalOpsPerSecond
  const contentChecks = [
    {
      id: 'minimum-modeled-logical-objects',
      basis: 'planned-fill-retained-cell-mix',
      passed: capacity.storage.plannedLogicalObjects >= search.minimumModeledLogicalObjects,
      observed: capacity.storage.plannedLogicalObjects,
      required: search.minimumModeledLogicalObjects
    },
    {
      id: 'minimum-modeled-logical-payload-bytes',
      basis: 'planned-fill-retained-cell-mix',
      passed: capacity.storage.plannedLogicalPayloadBytes >= search.minimumModeledLogicalPayloadBytes,
      observed: capacity.storage.plannedLogicalPayloadBytes,
      required: search.minimumModeledLogicalPayloadBytes
    }
  ]
  const planningFit = capacity.status === 'pass' && contentChecks.every(item => item.passed)
  const orderedResources = [...capacity.throughput.resources]
    .filter(resource => resource.modeledLogicalOpsPerSecondLimit !== null)
    .sort((left, right) => left.modeledLogicalOpsPerSecondLimit - right.modeledLogicalOpsPerSecondLimit ||
      left.resource.localeCompare(right.resource))
  const constraints = orderedResources.slice(0, 4).map(resource => ({
    resource: resource.resource,
    modeledLogicalOpsPerSecondLimit: resource.modeledLogicalOpsPerSecondLimit,
    modeledUtilizationAtTarget: resource.modeledUtilizationAtOfferedLoad,
    targetShortfallFraction: fixed(Math.max(0, target / resource.modeledLogicalOpsPerSecondLimit - 1))
  }))
  const workloadDigest = sha256(stableStringify(config.workload))
  const durability = {
    replicationFactor: config.fleet.replicationFactor,
    readFanout: config.workload.readFanout,
    readQuorum: config.workload.readQuorum,
    writeAcks: config.workload.writeAcks
  }
  const durabilityDigest = sha256(stableStringify(durability))
  const operationMixDigest = sha256(stableStringify(config.workload.operations))
  if (workloadDigest !== authority.workloadDigest ||
      durabilityDigest !== authority.durabilityDigest ||
      operationMixDigest !== authority.operationMixDigest) {
    throw new CapacitySizingError([`candidate ${relayCount}:${profile.id} drifted from the exact workload authority`])
  }
  return {
    id: `r${relayCount}-${profile.id}`,
    relayCount,
    relayIndex,
    hardwareProfileId: profile.id,
    hardwareProfileLabel: profile.label,
    profileIndex,
    hardware: resolvedHardware(config),
    hardwareEvidenceClass: 'enumerated-modeled-target-not-observed',
    targetLogicalOpsPerSecond: target,
    capacityModelStatus: capacity.status,
    planningFit,
    authorizesRelease: false,
    modeledSustainableLogicalOpsPerSecond: sustainable,
    modeledHeadroomFractionAtTarget: fixed(sustainable / target - 1),
    bottleneck: capacity.throughput.bottleneck,
    nearestConstraints: constraints,
    modeledContentCapacity: {
      scope: capacity.storage.capacityScope,
      maximumModelCeiling: {
        logicalObjects: capacity.storage.modeledLogicalObjectCapacity,
        logicalPayloadBytes: capacity.storage.modeledLogicalPayloadCapacityBytes,
        physicalResidentBytes: capacity.storage.modeledPhysicalResidentBytesAtCapacity,
        limitingRelayIndex: capacity.storage.limitingRelayIndex
      },
      plannedFillCapacity: {
        plannedFillFraction: capacity.storage.plannedFillFraction,
        logicalObjects: capacity.storage.plannedLogicalObjects,
        logicalPayloadBytes: capacity.storage.plannedLogicalPayloadBytes,
        physicalResidentBytes: Math.floor(
          capacity.storage.modeledPhysicalResidentBytesAtCapacity * capacity.storage.plannedFillFraction
        ),
        relayPhysicalResidentBytes: capacity.storage.relayAtPlannedFill.physicalResidentBytes
      }
    },
    contentChecks,
    rejectionCodes: capacity.rejectionReasons.map(reason => reason.code),
    binding: {
      sourceScenarioDigest: authority.source.scenarioDigest,
      workloadDigest,
      operationMixDigest,
      durabilityDigest,
      capacityConfigDigest: capacity.configDigest,
      capacityScenarioDigest: capacity.scenarioDigest
    }
  }
}

function resolvedHardware (config) {
  return {
    provenance: 'enumerated-target-assumption',
    diskBytesPerRelay: config.fleet.diskBytesPerRelay,
    diskSequentialWriteBytesPerSecond: config.disk.sequentialWriteBytesPerSecond,
    diskSequentialReadBytesPerSecond: config.disk.sequentialReadBytesPerSecond,
    diskRandomIopsPerSecond: config.disk.randomIopsPerSecond,
    walFsyncLatencyMs: config.wal.fsyncLatencyMs,
    walFsyncsPerSecond: fixed(1000 / config.wal.fsyncLatencyMs),
    networkIngressBitsPerSecond: config.network.ingressBitsPerSecond,
    networkEgressBitsPerSecond: config.network.egressBitsPerSecond,
    cpuCoresPerRelay: config.cpu.coresPerRelay,
    streamBufferedBytesPerRelay: config.streams.maxBufferedBytesPerRelay,
    streamSlotsPerRelay: config.streams.maxConcurrentStreamsPerRelay,
    inboxWaiterBytesPerRelay: config.surfaces.inboxWaiterMemoryBytesPerRelay,
    inboxWaiterSlotsPerRelay: config.surfaces.inboxMaxWaitersPerRelay
  }
}

function buildSizingAnswers (candidates, search) {
  const byRelayCount = search.relayCounts.map(relayCount => {
    const options = candidates.filter(candidate => candidate.relayCount === relayCount)
    const fit = options.find(candidate => candidate.planningFit)
    return {
      relayCount,
      found: Boolean(fit),
      candidateId: fit?.id || null,
      minimumEnumeratedHardwareProfileId: fit?.hardwareProfileId || null,
      hardware: fit?.hardware || null,
      modeledSustainableLogicalOpsPerSecond: fit?.modeledSustainableLogicalOpsPerSecond || null,
      bottleneck: fit?.bottleneck || options.at(-1)?.bottleneck || null,
      modeledContentCapacity: fit?.modeledContentCapacity || null
    }
  })
  const byHardwareProfile = search.hardwareProfiles.map(profile => {
    const options = candidates.filter(candidate => candidate.hardwareProfileId === profile.id)
    const fit = options.find(candidate => candidate.planningFit)
    return {
      hardwareProfileId: profile.id,
      found: Boolean(fit),
      candidateId: fit?.id || null,
      minimumEnumeratedRelayCount: fit?.relayCount || null,
      hardware: fit?.hardware || options[0]?.hardware || null,
      modeledSustainableLogicalOpsPerSecond: fit?.modeledSustainableLogicalOpsPerSecond || null,
      bottleneck: fit?.bottleneck || options.at(-1)?.bottleneck || null,
      modeledContentCapacity: fit?.modeledContentCapacity || null
    }
  })
  const fits = candidates.filter(candidate => candidate.planningFit)
  const pareto = fits.filter(candidate => !fits.some(other =>
    other.id !== candidate.id &&
    other.relayIndex <= candidate.relayIndex &&
    other.profileIndex <= candidate.profileIndex &&
    (other.relayIndex < candidate.relayIndex || other.profileIndex < candidate.profileIndex)
  ))
  return {
    definitionOfMinimum: 'first modeled fit in the ordered relay-count and component-wise nondecreasing hardware-profile search lattice',
    modeledTargetFoundInSearch: fits.length > 0,
    minimumEnumeratedHardwareByRelayCount: byRelayCount,
    minimumEnumeratedRelayCountByHardwareProfile: byHardwareProfile,
    paretoFrontierCandidateIds: pareto.map(candidate => candidate.id),
    searchCeiling: {
      relayCount: search.relayCounts.at(-1),
      hardwareProfileId: search.hardwareProfiles.at(-1).id,
      candidateId: candidates.at(-1).id,
      planningFit: candidates.at(-1).planningFit,
      bottleneck: candidates.at(-1).bottleneck,
      modeledSustainableLogicalOpsPerSecond: candidates.at(-1).modeledSustainableLogicalOpsPerSecond,
      modeledContentCapacity: candidates.at(-1).modeledContentCapacity
    }
  }
}

function buildBottleneckTransitions (candidates, search) {
  const transitions = []
  for (const relayCount of search.relayCounts) {
    const points = candidates.filter(candidate => candidate.relayCount === relayCount)
    addTransitions(transitions, 'hardware-profile-sweep', `relay:${relayCount}`, points)
  }
  for (const profile of search.hardwareProfiles) {
    const points = candidates.filter(candidate => candidate.hardwareProfileId === profile.id)
    addTransitions(transitions, 'relay-count-sweep', `profile:${profile.id}`, points)
  }
  const regions = {}
  for (const candidate of candidates) {
    if (!regions[candidate.bottleneck]) regions[candidate.bottleneck] = []
    regions[candidate.bottleneck].push(candidate.id)
  }
  return {
    transitionDefinition: 'Adjacent points are recorded when the limiting modeled resource changes or the point crosses the modeled-fit threshold.',
    noTransitionsObserved: transitions.length === 0,
    observedBottlenecks: Object.keys(regions).sort(),
    regions,
    transitions
  }
}

function addTransitions (target, dimension, series, points) {
  for (let index = 1; index < points.length; index++) {
    const from = points[index - 1]
    const to = points[index]
    const changes = []
    if (from.bottleneck !== to.bottleneck) changes.push('bottleneck')
    if (from.planningFit !== to.planningFit) changes.push('modeled-fit-threshold')
    if (changes.length === 0) continue
    target.push({
      dimension,
      series,
      fromCandidateId: from.id,
      toCandidateId: to.id,
      changes,
      fromBottleneck: from.bottleneck,
      toBottleneck: to.bottleneck,
      fromPlanningFit: from.planningFit,
      toPlanningFit: to.planningFit
    })
  }
}

function check (id, passed, observed, expected) {
  return { id, passed: passed === true, observed, expected }
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function fixed (value) {
  if (!Number.isFinite(value)) return value
  return Math.round(value * 1_000_000) / 1_000_000
}

function clone (value) {
  if (Array.isArray(value)) return value.map(clone)
  if (isPlainObject(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, clone(item)]))
  return value
}

function deepMerge (base, override) {
  if (Array.isArray(override)) return override.map(clone)
  if (!isPlainObject(override)) return override === undefined ? clone(base) : override
  const result = {}
  for (const key of new Set([...Object.keys(base || {}), ...Object.keys(override)])) {
    if (override[key] === undefined) result[key] = clone(base?.[key])
    else if (isPlainObject(base?.[key]) && isPlainObject(override[key])) result[key] = deepMerge(base[key], override[key])
    else result[key] = clone(override[key])
  }
  return result
}

function deepFreeze (value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value)
    for (const item of Object.values(value)) deepFreeze(item)
  }
  return value
}

function isPlainObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function rejectUnknownFields (value, allowed, path, violations) {
  if (!isPlainObject(value)) return
  const set = new Set(allowed)
  for (const key of Object.keys(value)) {
    if (!set.has(key)) violations.push(`unknown field ${path}.${key}`)
  }
}

function positive (value, path, violations) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    violations.push(`${path} must be a positive finite number`)
  }
}

function integer (value, path, minimum, maximum, violations) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    violations.push(`${path} must be an integer between ${minimum} and ${maximum}`)
  }
}

function nonNegativeInteger (value, path, violations) {
  integer(value, path, 0, Number.MAX_SAFE_INTEGER, violations)
}

async function readStdin () {
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  return Buffer.concat(chunks).toString('utf8')
}

function usage () {
  return [
    'Usage: node scripts/plan-blind-capacity.mjs [options]',
    '',
    'Options:',
    '  --release-profile NAME  Source exact workload from smoke or release (default: release)',
    '  --search FILE|-         Override the enumerated sizing search JSON',
    '  --out FILE              Write the report to FILE instead of stdout',
    '  --pretty | --compact    Select JSON formatting',
    '  --assert-fit            Exit 2 when no enumerated target is a modeled fit',
    '',
    'The result is modeled target sizing, not observed hardware or release evidence.'
  ].join('\n')
}

async function main (argv) {
  let profileName = 'release'
  let searchPath = null
  let outPath = null
  let pretty = true
  let assertFit = false
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]
    if (arg === '--release-profile') {
      profileName = argv[++index]
      if (!profileName) throw new CapacitySizingError(['--release-profile requires a name'])
    } else if (arg === '--search') {
      searchPath = argv[++index]
      if (!searchPath) throw new CapacitySizingError(['--search requires a file path or -'])
    } else if (arg === '--out') {
      outPath = argv[++index]
      if (!outPath) throw new CapacitySizingError(['--out requires a file path'])
    } else if (arg === '--pretty') pretty = true
    else if (arg === '--compact') pretty = false
    else if (arg === '--assert-fit') assertFit = true
    else if (arg === '--help' || arg === '-h') {
      process.stdout.write(`${usage()}\n`)
      return
    } else throw new CapacitySizingError([`unknown argument ${arg}`])
  }
  let search = {}
  if (searchPath) {
    const source = searchPath === '-' ? await readStdin() : await readFile(resolve(searchPath), 'utf8')
    search = JSON.parse(source)
  }
  const input = buildReleaseCapacitySizingInput(profileName, search)
  const report = runCapacitySizingPlan(input)
  const output = `${JSON.stringify(report, null, pretty ? 2 : 0)}\n`
  if (outPath) await writeFile(resolve(outPath), output)
  else process.stdout.write(output)
  if (assertFit && !report.answers.modeledTargetFoundInSearch) process.exitCode = 2
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv.slice(2)).catch(error => {
    const known = error instanceof CapacitySizingError
    const output = {
      schema: CAPACITY_SIZING_PLAN_SCHEMA,
      status: 'error',
      evidenceClass: 'modeled-target-hardware-not-observed',
      error: {
        code: known ? error.code : 'CAPACITY_SIZING_FAILED',
        message: error.message,
        violations: known ? error.violations : []
      },
      authorizesRelease: false
    }
    process.stdout.write(`${JSON.stringify(output)}\n`)
    process.exitCode = 1
  })
}
