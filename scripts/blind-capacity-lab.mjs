#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import {
  CELL_SIZE_CLASS,
  CORE_SESSION_CLASS,
  DISPATCH_LIMITS,
  FORWARD_CIRCUIT_CLASS,
  INBOX_FRAME_CLASS,
  STREAM_WIRE_CLASS
} from '../packages/blind-protocol/registry.js'

export const CAPACITY_LAB_SCHEMA = 'hiverelay/blind-capacity-lab-report/v2'
export const CAPACITY_LAB_CONFIG_SCHEMA = 'hiverelay/blind-capacity-lab-config/v2'
export const BLIND_SCENARIO_MANIFEST_SCHEMA = 'hiverelay/blind-scenario-manifest/v1'

const KIB = 1024
const MIB = 1024 * KIB
const GIB = 1024 * MIB
const TIB = 1024 * GIB
const YEAR_SECONDS = 365.25 * 24 * 60 * 60

export const DEFAULT_CAPACITY_LAB_CONFIG = deepFreeze({
  schema: CAPACITY_LAB_CONFIG_SCHEMA,
  seed: 'hiverelay-blind-capacity-v1',
  simulation: {
    sampleObjects: 25000,
    virtualBuckets: 65536,
    scaleRelayCounts: [3, 6, 12, 24]
  },
  fleet: {
    relayCount: 12,
    diskBytesPerRelay: 4 * TIB,
    diskBytesByRelay: null,
    replicationFactor: 3,
    storageReserveFraction: 0.15,
    plannedFillFraction: 0.65,
    unavailableRelays: 2
  },
  objects: {
    mix: [
      { name: 'small-cell', family: 'CELL', sizeClass: 1, weight: 0.70, payloadBytes: 2 * KIB },
      { name: 'medium-cell', family: 'CELL', sizeClass: 3, weight: 0.25, payloadBytes: 64 * KIB - 33 },
      { name: 'max-cell-structured-content', family: 'CELL', sizeClass: 5, weight: 0.05, payloadBytes: MIB - 33 }
    ],
    applicationFramingBytes: 33,
    objectMetadataBytes: 512,
    indexBytes: 96,
    filesystemAllocationBytes: 4096,
    diskReadGranularityBytes: 4096
  },
  workload: {
    operations: [
      { name: 'cell-put', family: 'CELL', operation: 'PUT', weight: 0.12, storageClass: 'weighted-cell-mix', walPayloadBytesPerRecord: 1024 },
      { name: 'cell-get', family: 'CELL', operation: 'GET', weight: 0.35, storageClass: 'weighted-cell-mix' },
      { name: 'inbox-append-4k', family: 'INBOX', operation: 'APPEND', weight: 0.10, frameClass: 1, logicalPayloadBytes: 4096 - 33, walPayloadBytesPerRecord: 1536 },
      { name: 'inbox-read-8x4k', family: 'INBOX', operation: 'READ', weight: 0.09, frameClass: 1, batchFrames: 8, walPayloadBytesPerRecord: 1024 },
      { name: 'inbox-watch-4k', family: 'INBOX', operation: 'WATCH', weight: 0.03, frameClass: 1, batchFrames: 1, meanWaitMillis: 15000, maxWaitMillis: 30000, walPayloadBytesPerRecord: 1024 },
      { name: 'core-mirror-4mib', family: 'CORE', operation: 'MIRROR', weight: 0.06, corpusBytes: 4 * MIB, transferFraction: 1, walPayloadBytesPerRecord: 4096 },
      { name: 'core-prove-256k', family: 'CORE', operation: 'PROVE', weight: 0.06, resultBytes: 256 * KIB, walPayloadBytesPerRecord: 2048 },
      { name: 'core-open-replication-4mib', family: 'CORE', operation: 'OPEN_REPLICATION', weight: 0.05, sessionClass: 1, ingressBytes: 2 * MIB, egressBytes: 2 * MIB, meanDurationSeconds: 30, meanBufferedBytes: MIB, walPayloadBytesPerRecord: 2048 },
      { name: 'forward-circuit-4mib', family: 'FORWARD', operation: 'CIRCUIT', weight: 0.14, circuitClass: 1, wireClass: 3, meanCircuitBytes: 4 * MIB, meanDataFrameBytes: 32 * KIB, hopCount: 1, meanDurationSeconds: 30, meanBufferedBytes: 64 * KIB, walPayloadBytesPerRecord: 1024 }
    ],
    readFanout: 1,
    readQuorum: 1,
    writeAcks: 2,
    requestOverheadBytes: 256,
    responseOverheadBytes: 192,
    ackBytes: 192,
    offeredLogicalOpsPerSecond: 40,
    operatingFractionOfSustainable: 0.60,
    targetResourceUtilization: 0.70
  },
  objectives: {
    requireExplicitOfferedLoad: true,
    requiredFamilies: ['CELL', 'INBOX', 'CORE', 'FORWARD'],
    requiredOperationKinds: [
      'CELL:PUT',
      'CELL:GET',
      'INBOX:APPEND',
      'INBOX:READ',
      'INBOX:WATCH',
      'CORE:MIRROR',
      'CORE:PROVE',
      'CORE:OPEN_REPLICATION',
      'FORWARD:CIRCUIT'
    ],
    minimumFamilyBlendFraction: 0.01,
    maximumModeledUnaryP99Millis: 35000,
    maximumModeledStreamOpenP99Millis: 2000,
    minimumFailureReadableFraction: 0.98,
    minimumFailureWriteQuorumFraction: 0.90
  },
  surfaces: {
    inboxControlBytes: 512,
    inboxFrameIndexBytes: 256,
    inboxReadPinBytes: 1024,
    inboxReadResultOverheadBytes: 4096,
    coreControlBytes: 512,
    coreProofPinBytes: 1024,
    coreAdditionalIndexBytes: 128,
    coreMaximumCorpusBytes: 4 * MIB,
    streamFrameOverheadBytes: 96,
    inboxWaiterMemoryBytesPerRelay: 64 * MIB,
    inboxMaxWaitersPerRelay: 4096
  },
  streams: {
    maxBufferedBytesPerRelay: 64 * MIB,
    maxConcurrentStreamsPerRelay: 1024
  },
  disk: {
    sequentialWriteBytesPerSecond: 500 * MIB,
    sequentialReadBytesPerSecond: 1 * GIB,
    randomIopsPerSecond: 70000,
    writeBaseLatencyMs: 0.45,
    readBaseLatencyMs: 0.30
  },
  wal: {
    recordOverheadBytes: 256,
    alignmentBytes: 512,
    effectiveGroupCommitRecords: 64,
    fsyncLatencyMs: 3,
    maxGroupDelayMs: 2,
    reserveFractionOfDisk: 0.04,
    retentionSeconds: 3600
  },
  checkpoint: {
    intervalSeconds: 1800,
    bytesPerLiveObject: 160,
    retainedCopies: 2,
    writesPerInterval: 1,
    ioChunkBytes: 1 * MIB
  },
  repair: {
    annualReplicaLossFraction: 0.10,
    annualScrubFraction: 0.25,
    networkOverheadFraction: 0.04,
    hashMicrosPerKiB: 0.20
  },
  network: {
    ingressBitsPerSecond: 1_000_000_000,
    egressBitsPerSecond: 1_000_000_000,
    medianRttMs: 35,
    p99RttMs: 110
  },
  cpu: {
    coresPerRelay: 8,
    fixedMicrosPerReplicaOperation: 200,
    microsPerKiB: 2.5
  }
})

export class CapacityConfigError extends Error {
  constructor (violations) {
    super(`invalid blind capacity lab configuration: ${violations.join('; ')}`)
    this.name = 'CapacityConfigError'
    this.code = 'INVALID_CAPACITY_LAB_CONFIG'
    this.violations = violations
  }
}

export function normalizeCapacityLabConfig (input = {}) {
  if (!isPlainObject(input)) throw new CapacityConfigError(['configuration root must be a JSON object'])
  const unknown = []
  collectUnknownKeys(input, DEFAULT_CAPACITY_LAB_CONFIG, '', unknown)
  if (unknown.length) throw new CapacityConfigError(unknown)
  const config = deepMerge(DEFAULT_CAPACITY_LAB_CONFIG, input)
  if (config.fleet.diskBytesByRelay !== null) {
    config.fleet.diskBytesByRelay = [...config.fleet.diskBytesByRelay]
  }
  config.objects.mix = config.objects.mix.map(item => ({ ...item }))
  config.workload.operations = config.workload.operations.map(item => ({ ...item }))
  config.simulation.scaleRelayCounts = [...config.simulation.scaleRelayCounts]
  config.objectives.requiredFamilies = [...config.objectives.requiredFamilies]
  config.objectives.requiredOperationKinds = [...config.objectives.requiredOperationKinds]
  validateConfig(config)
  return config
}

export function runCapacityLab (input = {}) {
  const config = normalizeCapacityLabConfig(input)
  const scenario = modelScenario(config)
  const scaling = buildScalingSweep(config)
  const rejectionReasons = []
  const scenarioManifest = buildCapacityScenarioManifest(config, scenario)

  if (!(scenario.throughput.modeledSustainableLogicalOpsPerSecond > 0)) {
    rejectionReasons.push({
      code: 'NO_SUSTAINABLE_FOREGROUND_CAPACITY',
      message: 'checkpoint, repair, or scrub background demand consumes the configured safe resource envelope'
    })
  }
  if (scenario.throughput.offeredLogicalOpsPerSecond > scenario.throughput.modeledSustainableLogicalOpsPerSecond) {
    rejectionReasons.push({
      code: 'OFFERED_LOAD_EXCEEDS_SUSTAINABLE_MODEL',
      message: 'the configured offered rate has no modeled steady state below the target resource utilization',
      offeredLogicalOpsPerSecond: scenario.throughput.offeredLogicalOpsPerSecond,
      modeledSustainableLogicalOpsPerSecond: scenario.throughput.modeledSustainableLogicalOpsPerSecond
    })
  }
  if (scenario.storage.modeledLogicalObjectCapacity < config.simulation.sampleObjects) {
    rejectionReasons.push({
      code: 'SAMPLE_DOES_NOT_FIT_ON_FLEET',
      message: 'the configured fleet cannot hold even one placement sample at the requested durability and reserve levels'
    })
  }

  if (config.objectives.requireExplicitOfferedLoad && config.workload.offeredLogicalOpsPerSecond === null) {
    rejectionReasons.push({
      code: 'EXPLICIT_OFFERED_LOAD_REQUIRED',
      message: 'release capacity evidence requires an explicit offered logical operation rate'
    })
  }

  const familyCoverage = evaluateFamilyCoverage(config, scenario.operationModel)
  if (!familyCoverage.passed) {
    rejectionReasons.push({
      code: 'WORKLOAD_COVERAGE_INCOMPLETE',
      message: 'the configured workload does not exercise every required family and operation kind',
      missingFamilies: familyCoverage.missingFamilies,
      underweightFamilies: familyCoverage.underweightFamilies,
      missingOperationKinds: familyCoverage.missingOperationKinds
    })
  }

  const overloaded = rejectionReasons.some(reason => reason.code === 'OFFERED_LOAD_EXCEEDS_SUSTAINABLE_MODEL')
  const noSustainableCapacity = rejectionReasons.some(reason => reason.code === 'NO_SUSTAINABLE_FOREGROUND_CAPACITY')
  const serviceObjectives = evaluateServiceObjectives(config, scenario, {
    latencyDefined: !overloaded && !noSustainableCapacity
  })
  if (!serviceObjectives.passed) {
    rejectionReasons.push({
      code: 'SERVICE_OBJECTIVE_NOT_MET',
      message: 'one or more explicit modeled service objectives are not met',
      failed: serviceObjectives.checks.filter(check => !check.passed).map(check => check.id)
    })
  }

  const status = rejectionReasons.length === 0 ? 'pass' : 'rejected'
  return stripPrivate({
    schema: CAPACITY_LAB_SCHEMA,
    status,
    modelKind: 'deterministic-placement-simulation-and-analytical-resource-model',
    evidenceClass: 'modeled-not-benchmarked',
    disclaimer: 'All throughput and latency values are model estimates derived from supplied costs. Placement/failure counts are deterministic simulation results. This report is not a hardware benchmark and is not production performance evidence.',
    configDigest: sha256(stableStringify(config)),
    assumptions: buildAssumptions(config),
    config,
    scenarioManifest,
    scenarioDigest: sha256(stableStringify(scenarioManifest)),
    workloadCoverage: familyCoverage,
    serviceObjectives,
    rejectionReasons,
    objectModel: scenario.objectModel,
    operationModel: scenario.operationModel,
    familySurfaces: scenario.familySurfaces,
    placement: scenario.placement,
    storage: scenario.storage,
    background: scenario.background,
    throughput: scenario.throughput,
    latency: noSustainableCapacity
      ? {
          status: 'undefined-without-sustainable-capacity',
          reason: 'No finite foreground steady-state latency is reported when background work consumes the modeled safe resource envelope.'
        }
      : overloaded
        ? {
            status: 'undefined-under-overload',
            reason: 'No finite steady-state queueing latency is reported when offered load exceeds the modeled sustainable envelope.'
          }
        : scenario.latency,
    failureScenario: scenario.failureScenario,
    scaling,
    optimizationCandidates: buildOptimizationCandidates(config, scenario),
    limitations: [
      'Storage projections honor each relay disk budget and deterministic replica count; throughput still assumes homogeneous disk speed, network, CPU, WAL, and memory limits across relays.',
      'Relay placement is uniform over distinct relays; operator, region, correlated failure, and adversarial selection policies need a separate topology simulation.',
      'Resource queues are approximated independently and do not model kernel, filesystem, garbage-collector, DHT, TLS, transport framing implementation, or lock contention.',
      'The effective WAL group size is an input, not a claim that the runtime achieves that batch size.',
      'Configured WAL payload sizes are planning allowances; format-2 encoded record sizes must be measured and substituted before a release claim.',
      'Successful mutation paths are charged two or three WAL records by family; error, retry, terminal, floor, map, and compaction records are not included in foreground averages.',
      'Network latency inputs must include the deployment path; the relay cannot infer Internet tail latency from bandwidth.',
      'Configured bandwidth is treated as continuously available; TLS, CORS gateway, packet loss, retransmission, congestion, and competing host traffic require shaped-network measurement.',
      'Capacity is limited by the first sampled relay to reach its safe disk budget and therefore includes deterministic placement skew.',
      'The primary retained-capacity simulation is the configured CELL mix. INBOX and CORE dedicated-capacity surfaces are mutually exclusive projections, not extra capacity that can be added to the CELL result.',
      'INBOX and CORE dedicated projections apply their exact resident size to every sampled per-relay replica count and stop at the first relay budget; they remain mutually exclusive rather than a combined live-set placement.',
      'Tombstone retention, retry indexes, descriptor/map state, bucket relocation copies, filesystem metadata, compaction scratch space, and backup checkpoints beyond configured allowances can reduce usable capacity.',
      'The blended foreground model does not predict application arrival rates, retained-data growth, cache hit rate, Core delta reuse, or circuit path-length distribution beyond the explicit inputs.',
      'Repair and scrub costs are annual averages; burst loss, degraded-source reads, repair backlog, and rebalance traffic can dominate the steady-state estimate.',
      'Replica requests are treated as balanced and parallel; acknowledgement order statistics and slowest-replica tails are not modeled.',
      'CORE and FORWARD stream transfer estimates omit congestion-control dynamics and remote-hop bottlenecks.',
      'Signed per-route FORWARD concurrency/byte caps may be lower than the shared stream-plane limits modeled here.',
      'A production release still requires real multi-host benchmarks, crash/fault injection, long-running soak tests, and comparison against these estimates.'
    ]
  })
}

function modelScenario (config) {
  const objectModel = buildObjectModel(config)
  const operationModel = buildOperationModel(config, objectModel)
  const placement = simulatePlacement(config, objectModel)
  const storage = buildStorageModel(config, objectModel, placement)
  const background = buildBackgroundModel(config, objectModel, placement, storage)
  const throughput = buildThroughputModel(config, operationModel, placement, background)
  const latency = buildLatencyModel(config, operationModel, throughput)
  const failureScenario = buildFailureScenario(config, placement)
  const familySurfaces = buildFamilySurfaces(config, objectModel, operationModel, placement, storage)
  return {
    objectModel,
    operationModel,
    familySurfaces,
    placement: placement.report,
    storage,
    background,
    throughput,
    latency,
    failureScenario
  }
}

function buildCapacityScenarioManifest (config, scenario) {
  return {
    schema: BLIND_SCENARIO_MANIFEST_SCHEMA,
    source: 'capacity-model',
    relayCount: config.fleet.relayCount,
    storageBytesByRelay: relayDiskBytes(config),
    performanceShape: {
      homogeneousAcrossRelays: true,
      diskSequentialWriteBytesPerSecond: config.disk.sequentialWriteBytesPerSecond,
      diskSequentialReadBytesPerSecond: config.disk.sequentialReadBytesPerSecond,
      diskRandomIopsPerSecond: config.disk.randomIopsPerSecond,
      walFsyncLatencyMs: config.wal.fsyncLatencyMs,
      cpuCoresPerRelay: config.cpu.coresPerRelay,
      networkIngressBitsPerSecond: config.network.ingressBitsPerSecond,
      networkEgressBitsPerSecond: config.network.egressBitsPerSecond
    },
    durability: {
      replicationFactor: config.fleet.replicationFactor,
      writeAcks: config.workload.writeAcks,
      readFanout: config.workload.readFanout,
      readQuorum: config.workload.readQuorum,
      unavailableRelays: config.fleet.unavailableRelays
    },
    offeredLoad: {
      logicalOperationsPerSecond: config.workload.offeredLogicalOpsPerSecond,
      source: scenario.throughput.offeredLoadSource,
      operations: scenario.operationModel.operations.map(operation => ({
        name: operation.name,
        family: operation.family,
        operation: operation.operation,
        probability: operation.probability
      })),
      familyProbability: scenario.operationModel.familyProbability
    },
    objectives: clone(config.objectives)
  }
}

function evaluateFamilyCoverage (config, operationModel) {
  const minimum = config.objectives.minimumFamilyBlendFraction
  const requiredFamilies = [...config.objectives.requiredFamilies]
  const presentKinds = new Set(operationModel.operations.map(operation => `${operation.family}:${operation.operation}`))
  const missingFamilies = requiredFamilies.filter(family => !(family in operationModel.familyProbability))
  const underweightFamilies = requiredFamilies.filter(family =>
    (operationModel.familyProbability[family] || 0) < minimum)
  const missingOperationKinds = config.objectives.requiredOperationKinds.filter(kind => !presentKinds.has(kind))
  return {
    passed: missingFamilies.length === 0 && underweightFamilies.length === 0 && missingOperationKinds.length === 0,
    minimumFamilyBlendFraction: minimum,
    requiredFamilies,
    requiredOperationKinds: [...config.objectives.requiredOperationKinds],
    observedFamilyProbability: operationModel.familyProbability,
    observedOperationKinds: [...presentKinds].sort(),
    missingFamilies,
    underweightFamilies,
    missingOperationKinds
  }
}

function evaluateServiceObjectives (config, scenario, options) {
  const objectives = config.objectives
  const checks = []
  if (options.latencyDefined) {
    const unary = scenario.latency.byOperation.filter(operation => operation.modeledP99Ms != null)
    const streams = scenario.latency.byOperation.filter(operation => operation.modeledOpenP99Ms != null)
    const maximumUnary = unary.length === 0 ? 0 : Math.max(...unary.map(operation => operation.modeledP99Ms))
    const maximumStreamOpen = streams.length === 0 ? 0 : Math.max(...streams.map(operation => operation.modeledOpenP99Ms))
    checks.push({
      id: 'latency.unary-p99',
      passed: maximumUnary <= objectives.maximumModeledUnaryP99Millis,
      observed: fixed(maximumUnary),
      target: `<=${objectives.maximumModeledUnaryP99Millis}`
    })
    checks.push({
      id: 'latency.stream-open-p99',
      passed: maximumStreamOpen <= objectives.maximumModeledStreamOpenP99Millis,
      observed: fixed(maximumStreamOpen),
      target: `<=${objectives.maximumModeledStreamOpenP99Millis}`
    })
  } else {
    checks.push({ id: 'latency.steady-state-defined', passed: false, observed: false, target: true })
  }
  const failure = scenario.failureScenario.existingReplicaSets
  checks.push({
    id: 'failure.readable-fraction',
    passed: failure.simulatedReadableFraction >= objectives.minimumFailureReadableFraction,
    observed: failure.simulatedReadableFraction,
    target: `>=${objectives.minimumFailureReadableFraction}`
  })
  checks.push({
    id: 'failure.write-quorum-fraction',
    passed: failure.simulatedWriteQuorumFraction >= objectives.minimumFailureWriteQuorumFraction,
    observed: failure.simulatedWriteQuorumFraction,
    target: `>=${objectives.minimumFailureWriteQuorumFraction}`
  })
  return { passed: checks.every(check => check.passed), checks }
}

function buildObjectModel (config) {
  const totalWeight = sum(config.objects.mix.map(item => item.weight))
  const mix = config.objects.mix.map(item => {
    const probability = item.weight / totalWeight
    const opaqueCellBytes = CELL_SIZE_CLASS[item.sizeClass]
    const storedBytesPerReplica = roundUp(
      opaqueCellBytes +
      config.objects.objectMetadataBytes +
      config.objects.indexBytes,
      config.objects.filesystemAllocationBytes
    )
    const checkpointResidentBytesPerReplica = config.checkpoint.bytesPerLiveObject * config.checkpoint.retainedCopies
    const readBytesPerReplica = roundUp(
      opaqueCellBytes,
      config.objects.diskReadGranularityBytes
    )
    return {
      name: item.name,
      family: item.family,
      sizeClass: item.sizeClass,
      probability: fixed(probability),
      payloadBytes: item.payloadBytes,
      applicationFramingBytes: config.objects.applicationFramingBytes,
      opaqueCellBytes,
      opaquePaddingBytes: opaqueCellBytes - item.payloadBytes - config.objects.applicationFramingBytes,
      storedBytesPerReplica,
      checkpointResidentBytesPerReplica,
      physicalResidentBytesPerReplica: storedBytesPerReplica + checkpointResidentBytesPerReplica,
      readBytesPerReplica
    }
  })

  return {
    mix,
    weightedMeanPayloadBytes: weightedMean(mix, 'payloadBytes'),
    weightedMeanOpaqueCellBytes: weightedMean(mix, 'opaqueCellBytes'),
    weightedMeanStoredBytesPerReplica: weightedMean(mix, 'storedBytesPerReplica'),
    weightedMeanCheckpointResidentBytesPerReplica: weightedMean(mix, 'checkpointResidentBytesPerReplica'),
    weightedMeanPhysicalResidentBytesPerReplica: weightedMean(mix, 'physicalResidentBytesPerReplica'),
    weightedMeanReadBytesPerReplica: weightedMean(mix, 'readBytesPerReplica'),
    capacityScope: 'configured retained CELL mix only',
    exactCellSizeClasses: { ...CELL_SIZE_CLASS },
    analyticPhysicalToLogicalRatio: fixed(
      config.fleet.replicationFactor * weightedMean(mix, 'physicalResidentBytesPerReplica') /
      weightedMean(mix, 'payloadBytes')
    )
  }
}

function buildOperationModel (config, objectModel) {
  const totalWeight = sum(config.workload.operations.map(item => item.weight))
  const operations = config.workload.operations.map(item => {
    const probability = item.weight / totalWeight
    const base = {
      name: item.name,
      family: item.family,
      operation: item.operation,
      probability: fixed(probability),
      relayTouches: 0,
      serialHops: 1,
      diskWriteBytesPerTouch: 0,
      diskReadBytesPerTouch: 0,
      diskIopsPerTouch: 0,
      networkIngressBytesPerTouch: 0,
      networkEgressBytesPerTouch: 0,
      walRecordsPerTouch: 0,
      walBytesPerTouch: 0,
      cpuOperationUnitsPerTouch: 1,
      cpuBytesPerTouch: 0,
      activeSecondsPerTouch: 0,
      bufferedBytesPerActiveStream: 0,
      concurrencyKind: 'NONE',
      latencyKind: 'unary-completion'
    }
    const requestBytes = config.workload.requestOverheadBytes
    const responseBytes = config.workload.responseOverheadBytes

    if (item.family === 'CELL') {
      const cell = resolveCellCost(item.storageClass, objectModel)
      base.exactClassSemantics = item.storageClass
      if (item.operation === 'PUT') {
        setWalCost(base, item, 2, config)
        base.relayTouches = config.fleet.replicationFactor
        base.diskWriteBytesPerTouch = cell.storedBytes + base.walBytesPerTouch
        base.diskIopsPerTouch = 1 + base.walRecordsPerTouch
        base.networkIngressBytesPerTouch = cell.opaqueBytes + requestBytes
        base.networkEgressBytesPerTouch = config.workload.ackBytes
      } else {
        base.relayTouches = config.workload.readFanout
        base.diskReadBytesPerTouch = cell.readBytes
        base.diskIopsPerTouch = 1
        base.networkIngressBytesPerTouch = requestBytes
        base.networkEgressBytesPerTouch = cell.opaqueBytes + responseBytes
      }
    } else if (item.family === 'INBOX') {
      const frameBytes = INBOX_FRAME_CLASS[item.frameClass]
      const frameResidentBytes = roundUp(
        frameBytes + config.surfaces.inboxControlBytes + config.surfaces.inboxFrameIndexBytes,
        config.objects.filesystemAllocationBytes
      )
      base.frameClass = item.frameClass
      base.exactFrameBytes = frameBytes
      if (item.operation === 'APPEND') {
        setWalCost(base, item, 2, config)
        base.relayTouches = config.fleet.replicationFactor
        base.diskWriteBytesPerTouch = frameResidentBytes + base.walBytesPerTouch
        base.diskIopsPerTouch = 1 + base.walRecordsPerTouch
        base.networkIngressBytesPerTouch = frameBytes + requestBytes
        base.networkEgressBytesPerTouch = config.workload.ackBytes
      } else {
        setWalCost(base, item, 2, config)
        base.relayTouches = config.workload.readFanout
        base.diskReadBytesPerTouch = item.batchFrames * roundUp(frameBytes, config.objects.diskReadGranularityBytes)
        base.diskWriteBytesPerTouch = config.surfaces.inboxReadPinBytes + base.walBytesPerTouch
        base.diskIopsPerTouch = item.batchFrames + base.walRecordsPerTouch
        base.networkIngressBytesPerTouch = requestBytes
        base.networkEgressBytesPerTouch = item.batchFrames * (frameBytes + 41) +
          Math.max(responseBytes, config.surfaces.inboxReadResultOverheadBytes)
        base.batchFrames = item.batchFrames
        if (item.operation === 'WATCH') {
          base.activeSecondsPerTouch = item.meanWaitMillis / 1000
          base.bufferedBytesPerActiveStream = config.surfaces.inboxReadPinBytes
          base.meanWaitMillis = item.meanWaitMillis
          base.maxWaitMillis = item.maxWaitMillis
          base.concurrencyKind = 'INBOX_WAITER'
          base.latencyKind = 'bounded-watch-completion'
        }
      }
    } else if (item.family === 'CORE') {
      if (item.operation === 'MIRROR') {
        setWalCost(base, item, 2, config)
        const residentBytes = roundUp(
          item.corpusBytes + config.surfaces.coreControlBytes + config.surfaces.coreAdditionalIndexBytes,
          config.objects.filesystemAllocationBytes
        )
        base.relayTouches = config.fleet.replicationFactor
        base.diskWriteBytesPerTouch = residentBytes + base.walBytesPerTouch
        base.diskIopsPerTouch = Math.ceil(item.corpusBytes / config.checkpoint.ioChunkBytes) + base.walRecordsPerTouch
        base.networkIngressBytesPerTouch = item.corpusBytes * item.transferFraction + requestBytes
        base.networkEgressBytesPerTouch = config.workload.ackBytes
        base.corpusBytes = item.corpusBytes
        base.transferFraction = item.transferFraction
      } else if (item.operation === 'PROVE') {
        setWalCost(base, item, 2, config)
        base.relayTouches = config.workload.readFanout
        base.diskReadBytesPerTouch = item.resultBytes
        base.diskWriteBytesPerTouch = config.surfaces.coreProofPinBytes + base.walBytesPerTouch
        base.diskIopsPerTouch = Math.ceil(item.resultBytes / config.objects.diskReadGranularityBytes) + base.walRecordsPerTouch
        base.networkIngressBytesPerTouch = requestBytes
        base.networkEgressBytesPerTouch = item.resultBytes + responseBytes
        base.resultBytes = item.resultBytes
      } else {
        setWalCost(base, item, 3, config)
        base.relayTouches = 1
        base.diskWriteBytesPerTouch = base.walBytesPerTouch
        base.diskIopsPerTouch = base.walRecordsPerTouch
        base.networkIngressBytesPerTouch = item.ingressBytes + requestBytes
        base.networkEgressBytesPerTouch = item.egressBytes + responseBytes
        base.cpuOperationUnitsPerTouch = Math.max(1, Math.ceil((item.ingressBytes + item.egressBytes) / STREAM_WIRE_CLASS[3]))
        base.activeSecondsPerTouch = item.meanDurationSeconds
        base.bufferedBytesPerActiveStream = item.meanBufferedBytes
        base.concurrencyKind = 'STREAM'
        base.sessionClass = item.sessionClass
        base.maximumSessionBytes = CORE_SESSION_CLASS[item.sessionClass].maxSessionBytes
        base.latencyKind = 'stream-open-and-transfer-floor'
      }
    } else {
      setWalCost(base, item, 3, config)
      const frames = Math.ceil(item.meanCircuitBytes / item.meanDataFrameBytes)
      const transferredBytes = item.meanCircuitBytes + frames * config.surfaces.streamFrameOverheadBytes
      base.relayTouches = item.hopCount
      base.serialHops = item.hopCount
      base.diskWriteBytesPerTouch = base.walBytesPerTouch
      base.diskIopsPerTouch = base.walRecordsPerTouch
      base.networkIngressBytesPerTouch = transferredBytes + requestBytes
      base.networkEgressBytesPerTouch = transferredBytes + responseBytes
      base.cpuOperationUnitsPerTouch = frames
      base.activeSecondsPerTouch = item.meanDurationSeconds
      base.bufferedBytesPerActiveStream = item.meanBufferedBytes
      base.concurrencyKind = 'STREAM'
      base.circuitClass = item.circuitClass
      base.wireClass = item.wireClass
      base.meanCircuitBytes = item.meanCircuitBytes
      base.meanDataFrameBytes = item.meanDataFrameBytes
      base.meanDataFrames = frames
      base.maximumCircuitBytes = FORWARD_CIRCUIT_CLASS[item.circuitClass].maxCircuitBytes
      base.maximumDataFrameBytes = STREAM_WIRE_CLASS[item.wireClass]
      base.latencyKind = 'stream-open-and-transfer-floor'
    }
    base.cpuBytesPerTouch = base.networkIngressBytesPerTouch + base.networkEgressBytesPerTouch +
      base.diskWriteBytesPerTouch + base.diskReadBytesPerTouch
    return base
  })

  return {
    mixScope: 'blended foreground logical operations; one logical operation is one configured operation-mix draw',
    operations,
    familyProbability: Object.fromEntries(['CELL', 'INBOX', 'CORE', 'FORWARD'].map(family => [
      family,
      fixed(sum(operations.filter(operation => operation.family === family).map(operation => operation.probability)))
    ])),
    exactWireLimits: {
      cellSizeClasses: { ...CELL_SIZE_CLASS },
      inboxFrameClasses: { ...INBOX_FRAME_CLASS },
      coreSessionClasses: clone(CORE_SESSION_CLASS),
      forwardCircuitClasses: clone(FORWARD_CIRCUIT_CLASS),
      streamWireClasses: { ...STREAM_WIRE_CLASS },
      maximumCoreProveOpaqueProofsAndBlocksBytes: 4 * MIB - 256,
      maximumCoreProveOperationResultBytes: 4 * MIB,
      maximumForwardDataBytes: DISPATCH_LIMITS.MAX_FORWARD_DATA_BYTES
    }
  }
}

function resolveCellCost (storageClass, objectModel) {
  if (storageClass === 'weighted-cell-mix') {
    return {
      opaqueBytes: objectModel.weightedMeanOpaqueCellBytes,
      storedBytes: objectModel.weightedMeanStoredBytesPerReplica,
      readBytes: objectModel.weightedMeanReadBytesPerReplica
    }
  }
  const item = objectModel.mix.find(candidate => candidate.name === storageClass)
  if (!item) throw new CapacityConfigError([`CELL operation references unknown storageClass ${storageClass}`])
  return {
    opaqueBytes: item.opaqueCellBytes,
    storedBytes: item.storedBytesPerReplica,
    readBytes: item.readBytesPerReplica
  }
}

function setWalCost (target, item, recordCount, config) {
  target.walRecordsPerTouch = recordCount
  target.walBytesPerTouch = recordCount * roundUp(
    config.wal.recordOverheadBytes + item.walPayloadBytesPerRecord,
    config.wal.alignmentBytes
  )
}

function buildFamilySurfaces (config, objectModel, operationModel, placement, storage) {
  const checkpointResident = config.checkpoint.bytesPerLiveObject * config.checkpoint.retainedCopies
  const dedicatedProjection = (logicalBytes, residentBytes) => {
    const physicalResidentBytesPerReplica = residentBytes + checkpointResident
    let scale = Infinity
    let limitingRelayIndex = -1
    const sampleResidentBytesByRelay = placement.replicaCounts.map(count =>
      count * physicalResidentBytesPerReplica)
    for (let relayIndex = 0; relayIndex < sampleResidentBytesByRelay.length; relayIndex++) {
      const resident = sampleResidentBytesByRelay[relayIndex]
      if (!(resident > 0)) continue
      const relayScale = storage._safeDataBudgetBytesByRelay[relayIndex] / resident
      if (relayScale < scale) {
        scale = relayScale
        limitingRelayIndex = relayIndex
      }
    }
    const unitCount = Math.floor(config.simulation.sampleObjects * scale)
    return {
      modeledLogicalUnitCapacity: unitCount,
      modeledLogicalPayloadCapacityBytes: Math.floor(unitCount * logicalBytes),
      residentBytesPerReplica: physicalResidentBytesPerReplica,
      limitingRelayIndex,
      limitingRelaySafeDataBudgetBytes: Math.floor(storage._safeDataBudgetBytesByRelay[limitingRelayIndex]),
      placementBasis: 'family resident bytes applied to the deterministic sampled replica count on every relay',
      relayResidentBytesAtCapacity: summarize(sampleResidentBytesByRelay.map(bytes => bytes * scale))
    }
  }
  const inboxClasses = [...new Set(operationModel.operations
    .filter(operation => operation.family === 'INBOX')
    .map(operation => operation.frameClass))].sort((a, b) => a - b)
  const coreCorpora = [...new Set(operationModel.operations
    .filter(operation => operation.family === 'CORE' && operation.operation === 'MIRROR')
    .map(operation => operation.corpusBytes))].sort((a, b) => a - b)

  return {
    projectionRule: 'Each retained-capacity projection assumes the entire safe fleet data budget is dedicated to that one surface; projections are mutually exclusive and must not be added.',
    sharedLiveStreamPlane: {
      configuredMaxBufferedBytesPerRelay: config.streams.maxBufferedBytesPerRelay,
      configuredMaxConcurrentStreamsPerRelay: config.streams.maxConcurrentStreamsPerRelay,
      currentImplementationDefaultBufferedBytes: 64 * MIB,
      currentImplementationDefaultConcurrentStreams: 1024
    },
    CELL: {
      persistence: 'exact padded cellBlob plus relay control/index/checkpoint accounting',
      exactSizeClasses: { ...CELL_SIZE_CLASS },
      configuredApplicationFramingBytesInsideCell: config.objects.applicationFramingBytes,
      configuredMixCapacity: {
        modeledLogicalObjectCapacity: storage.modeledLogicalObjectCapacity,
        modeledLogicalPayloadCapacityBytes: storage.modeledLogicalPayloadCapacityBytes,
        weightedMeanOpaqueCellBytes: objectModel.weightedMeanOpaqueCellBytes
      }
    },
    INBOX: {
      persistence: 'exact padded frames plus a conservatively unshared control record, frame index, and checkpoint accounting per frame',
      exactFrameClasses: { ...INBOX_FRAME_CLASS },
      readLimitMaximumFrames: 64,
      configuredReadResultOverheadBoundBytes: config.surfaces.inboxReadResultOverheadBytes,
      dedicatedCapacityByFrameClass: inboxClasses.map(frameClass => {
        const frameBytes = INBOX_FRAME_CLASS[frameClass]
        const residentBytes = roundUp(
          frameBytes + config.surfaces.inboxControlBytes + config.surfaces.inboxFrameIndexBytes,
          config.objects.filesystemAllocationBytes
        )
        return {
          frameClass,
          exactFrameBytes: frameBytes,
          ...dedicatedProjection(Math.max(0, frameBytes - config.objects.applicationFramingBytes), residentBytes)
        }
      })
    },
    CORE: {
      persistence: 'opaque immutable corpus plus control/index/checkpoint accounting; OPEN_REPLICATION session classes are transfer caps, not corpus size classes',
      exactSessionClasses: clone(CORE_SESSION_CLASS),
      configuredMaximumCorpusBytes: config.surfaces.coreMaximumCorpusBytes,
      currentImplementationDefaultMaximumCorpusBytes: 4 * MIB,
      currentImplementationAllowedMaximumCorpusBytes: 64 * MIB,
      proveOpaqueProofsAndBlocksMaximumBytes: 4 * MIB - 256,
      proveOperationResultMaximumBytes: 4 * MIB,
      dedicatedCapacityByCorpusSize: coreCorpora.map(corpusBytes => {
        const residentBytes = roundUp(
          corpusBytes + config.surfaces.coreControlBytes + config.surfaces.coreAdditionalIndexBytes,
          config.objects.filesystemAllocationBytes
        )
        return { corpusBytes, ...dedicatedProjection(corpusBytes, residentBytes) }
      })
    },
    FORWARD: {
      persistence: 'no application body retention; only modeled OPEN/activation/terminal WAL records and bounded live buffers',
      exactCircuitClasses: clone(FORWARD_CIRCUIT_CLASS),
      exactWireClasses: { ...STREAM_WIRE_CLASS },
      maximumDispatchDataBytes: DISPATCH_LIMITS.MAX_FORWARD_DATA_BYTES,
      retainedApplicationBodyCapacityBytes: 0
    }
  }
}

function simulatePlacement (config, objectModel) {
  const relayCount = config.fleet.relayCount
  const replication = config.fleet.replicationFactor
  const physicalBytes = new Array(relayCount).fill(0)
  const objectBytes = new Array(relayCount).fill(0)
  const replicaCounts = new Array(relayCount).fill(0)
  const bucketOwners = buildBucketOwners(config.seed, relayCount, config.simulation.virtualBuckets)
  const failedRelays = chooseDistinct(
    new Rng(hash32(`${config.seed}:failed-relays:${relayCount}`)),
    relayCount,
    config.fleet.unavailableRelays
  )
  const failedSet = new Set(failedRelays)
  let sampleLogicalPayloadBytes = 0
  let samplePhysicalResidentBytes = 0
  let readableObjects = 0
  let writeQuorumObjects = 0
  let survivingObjects = 0

  for (let i = 0; i < config.simulation.sampleObjects; i++) {
    const rng = new Rng(hash32(`${config.seed}:object:${i}`))
    const object = chooseMix(objectModel.mix, rng.next())
    const relays = chooseRelaysViaBuckets(rng, bucketOwners, replication)
    let available = 0
    for (const relay of relays) {
      physicalBytes[relay] += object.physicalResidentBytesPerReplica
      objectBytes[relay] += object.storedBytesPerReplica
      replicaCounts[relay]++
      samplePhysicalResidentBytes += object.physicalResidentBytesPerReplica
      if (!failedSet.has(relay)) available++
    }
    sampleLogicalPayloadBytes += object.payloadBytes
    if (available >= config.workload.readQuorum) readableObjects++
    if (available >= config.workload.writeAcks) writeQuorumObjects++
    if (available >= 1) survivingObjects++
  }

  const physicalStats = summarize(physicalBytes)
  const countStats = summarize(replicaCounts)
  const objectStats = summarize(objectBytes)
  const report = {
    seed: config.seed,
    sampledObjects: config.simulation.sampleObjects,
    sampledReplicas: config.simulation.sampleObjects * replication,
    virtualBuckets: config.simulation.virtualBuckets,
    sampledLogicalPayloadBytes: sampleLogicalPayloadBytes,
    sampledPhysicalResidentBytes: samplePhysicalResidentBytes,
    virtualBucketOwnershipCounts: summarize(ownerCounts(bucketOwners, relayCount)),
    relayPhysicalResidentBytes: physicalStats,
    relayStoredObjectBytes: objectStats,
    relayReplicaCounts: countStats,
    maximumByteSkewOverMean: fixed(physicalStats.max / physicalStats.mean),
    maximumReplicaCountSkewOverMean: fixed(countStats.max / countStats.mean),
    failedRelayIndices: failedRelays,
    failureSample: {
      readableObjects,
      writeQuorumObjects,
      survivingObjects
    }
  }
  return {
    physicalBytes,
    objectBytes,
    replicaCounts,
    sampleLogicalPayloadBytes,
    samplePhysicalResidentBytes,
    report
  }
}

function buildStorageModel (config, objectModel, placement) {
  const disks = relayDiskBytes(config)
  const dataBudgets = disks.map(bytes => bytes * (
    1 - config.fleet.storageReserveFraction - config.wal.reserveFractionOfDisk
  ))
  const walReserves = disks.map(bytes => bytes * config.wal.reserveFractionOfDisk)
  let capacityScale = Infinity
  let limitingRelayIndex = -1
  for (let i = 0; i < disks.length; i++) {
    const scale = dataBudgets[i] / placement.physicalBytes[i]
    if (scale < capacityScale) {
      capacityScale = scale
      limitingRelayIndex = i
    }
  }
  const logicalObjectCapacity = Math.floor(config.simulation.sampleObjects * capacityScale)
  const logicalPayloadCapacity = Math.floor(placement.sampleLogicalPayloadBytes * capacityScale)
  const physicalResidentAtCapacity = Math.floor(placement.samplePhysicalResidentBytes * capacityScale)
  const plannedScale = capacityScale * config.fleet.plannedFillFraction
  const plannedRelayPhysicalBytes = placement.physicalBytes.map(value => value * plannedScale)
  const plannedRelayObjectBytes = placement.objectBytes.map(value => value * plannedScale)
  const plannedRelayReplicaCounts = placement.replicaCounts.map(value => value * plannedScale)

  return {
    capacityScope: 'configured retained CELL mix only; see familySurfaces for mutually exclusive INBOX and CORE projections',
    rawFleetDiskBytes: sum(disks),
    safeDataBudgetBytes: Math.floor(sum(dataBudgets)),
    walReservedBytes: Math.floor(sum(walReserves)),
    modeledLogicalObjectCapacity: logicalObjectCapacity,
    modeledLogicalPayloadCapacityBytes: logicalPayloadCapacity,
    modeledPhysicalResidentBytesAtCapacity: physicalResidentAtCapacity,
    modeledPhysicalToLogicalRatio: fixed(physicalResidentAtCapacity / logicalPayloadCapacity),
    limitingRelayIndex,
    capacityPlacementScale: fixed(capacityScale),
    plannedFillFraction: config.fleet.plannedFillFraction,
    plannedLogicalObjects: Math.floor(logicalObjectCapacity * config.fleet.plannedFillFraction),
    plannedLogicalPayloadBytes: Math.floor(logicalPayloadCapacity * config.fleet.plannedFillFraction),
    perReplica: {
      weightedMeanPayloadBytes: objectModel.weightedMeanPayloadBytes,
      weightedMeanOpaqueCellBytes: objectModel.weightedMeanOpaqueCellBytes,
      weightedMeanStoredObjectBytes: objectModel.weightedMeanStoredBytesPerReplica,
      weightedMeanCheckpointResidentBytes: objectModel.weightedMeanCheckpointResidentBytesPerReplica
    },
    relayAtPlannedFill: {
      physicalResidentBytes: summarize(plannedRelayPhysicalBytes),
      storedObjectBytes: summarize(plannedRelayObjectBytes),
      replicaCounts: summarize(plannedRelayReplicaCounts)
    },
    _plannedRelayObjectBytes: plannedRelayObjectBytes,
    _plannedRelayReplicaCounts: plannedRelayReplicaCounts,
    _safeDataBudgetBytesByRelay: dataBudgets,
    _walReserves: walReserves
  }
}

function buildBackgroundModel (config, objectModel, placement, storage) {
  const relays = []
  for (let i = 0; i < config.fleet.relayCount; i++) {
    const objectBytes = storage._plannedRelayObjectBytes[i]
    const replicaCount = storage._plannedRelayReplicaCounts[i]
    const repairObjectRate = replicaCount * config.repair.annualReplicaLossFraction / YEAR_SECONDS
    const scrubObjectRate = replicaCount * config.repair.annualScrubFraction / YEAR_SECONDS
    const repairBytesPerSecond = objectBytes * config.repair.annualReplicaLossFraction / YEAR_SECONDS
    const scrubBytesPerSecond = objectBytes * config.repair.annualScrubFraction / YEAR_SECONDS
    const checkpointBytesPerSecond = (
      replicaCount * config.checkpoint.bytesPerLiveObject * config.checkpoint.writesPerInterval /
      config.checkpoint.intervalSeconds
    )
    const checkpointIops = checkpointBytesPerSecond / config.checkpoint.ioChunkBytes
    const networkRepairBytes = repairBytesPerSecond * (1 + config.repair.networkOverheadFraction)
    const hashCpuSeconds = (
      (repairBytesPerSecond + scrubBytesPerSecond) / KIB * config.repair.hashMicrosPerKiB / 1_000_000
    )
    relays.push({
      relayIndex: i,
      repairObjectsPerSecond: repairObjectRate,
      scrubObjectsPerSecond: scrubObjectRate,
      repairBytesPerSecond,
      scrubBytesPerSecond,
      checkpointBytesPerSecond,
      diskWriteBytesPerSecond: repairBytesPerSecond + checkpointBytesPerSecond,
      diskReadBytesPerSecond: repairBytesPerSecond + scrubBytesPerSecond,
      diskIopsPerSecond: repairObjectRate + scrubObjectRate + checkpointIops,
      networkIngressBytesPerSecond: networkRepairBytes,
      networkEgressBytesPerSecond: networkRepairBytes,
      cpuSecondsPerSecond: hashCpuSeconds
    })
  }
  const worst = {}
  for (const key of [
    'repairObjectsPerSecond',
    'scrubObjectsPerSecond',
    'repairBytesPerSecond',
    'scrubBytesPerSecond',
    'checkpointBytesPerSecond',
    'diskWriteBytesPerSecond',
    'diskReadBytesPerSecond',
    'diskIopsPerSecond',
    'networkIngressBytesPerSecond',
    'networkEgressBytesPerSecond',
    'cpuSecondsPerSecond'
  ]) {
    worst[key] = fixed(Math.max(...relays.map(relay => relay[key])))
  }
  return {
    basis: 'planned-fill-live-set',
    annualReplicaLossFraction: config.repair.annualReplicaLossFraction,
    annualScrubFraction: config.repair.annualScrubFraction,
    worstRelayPerSecond: worst,
    relayCount: relays.length,
    _relays: relays
  }
}

function buildThroughputModel (config, operationModel, placement, background) {
  const workload = config.workload
  const routingSkew = Math.max(
    placement.report.maximumByteSkewOverMean,
    placement.report.maximumReplicaCountSkewOverMean
  )
  const demand = emptyResourceDemand()
  const perOperationDemand = []
  for (const operation of operationModel.operations) {
    const standalone = operationResourceDemand(config, operation, routingSkew)
    perOperationDemand.push({ name: operation.name, family: operation.family, probability: operation.probability, demand: standalone })
    addScaledDemand(demand, standalone, operation.probability)
  }

  const ingressBytes = config.network.ingressBitsPerSecond / 8
  const egressBytes = config.network.egressBitsPerSecond / 8
  const capacities = {
    diskWriteBytesPerSecond: config.disk.sequentialWriteBytesPerSecond,
    diskReadBytesPerSecond: config.disk.sequentialReadBytesPerSecond,
    diskIopsPerSecond: config.disk.randomIopsPerSecond,
    networkIngressBytesPerSecond: ingressBytes,
    networkEgressBytesPerSecond: egressBytes,
    cpuSecondsPerSecond: config.cpu.coresPerRelay,
    walFsyncCommitsPerSecond: 1000 / config.wal.fsyncLatencyMs,
    walRetainedBytesPerSecond: Math.min(...relayDiskBytes(config)) *
      config.wal.reserveFractionOfDisk / config.wal.retentionSeconds,
    streamBufferedBytes: config.streams.maxBufferedBytesPerRelay,
    streamSlots: config.streams.maxConcurrentStreamsPerRelay,
    inboxWaiterBytes: config.surfaces.inboxWaiterMemoryBytesPerRelay,
    inboxWaiterSlots: config.surfaces.inboxMaxWaitersPerRelay
  }
  const backgroundValues = {
    diskWriteBytesPerSecond: background.worstRelayPerSecond.diskWriteBytesPerSecond,
    diskReadBytesPerSecond: background.worstRelayPerSecond.diskReadBytesPerSecond,
    diskIopsPerSecond: background.worstRelayPerSecond.diskIopsPerSecond,
    networkIngressBytesPerSecond: background.worstRelayPerSecond.networkIngressBytesPerSecond,
    networkEgressBytesPerSecond: background.worstRelayPerSecond.networkEgressBytesPerSecond,
    cpuSecondsPerSecond: background.worstRelayPerSecond.cpuSecondsPerSecond,
    walFsyncCommitsPerSecond: 0,
    walRetainedBytesPerSecond: 0,
    streamBufferedBytes: 0,
    streamSlots: 0,
    inboxWaiterBytes: 0,
    inboxWaiterSlots: 0
  }

  const resources = []
  for (const name of Object.keys(capacities)) {
    const rawCapacity = capacities[name]
    const safeCapacity = name === 'walRetainedBytesPerSecond'
      ? rawCapacity
      : rawCapacity * workload.targetResourceUtilization
    const backgroundDemand = backgroundValues[name]
    const foregroundDemandPerLogicalOp = demand[name]
    const available = Math.max(0, safeCapacity - backgroundDemand)
    const sustainable = foregroundDemandPerLogicalOp > 0
      ? available / foregroundDemandPerLogicalOp
      : null
    resources.push({
      resource: name,
      rawCapacityPerRelay: fixed(rawCapacity),
      safeCapacityPerRelay: fixed(safeCapacity),
      backgroundDemandPerRelay: fixed(backgroundDemand),
      foregroundDemandPerLogicalOpAtWorstRelay: fixed(foregroundDemandPerLogicalOp),
      modeledLogicalOpsPerSecondLimit: sustainable === null ? null : fixed(sustainable)
    })
  }

  const boundedResources = resources.filter(resource => resource.modeledLogicalOpsPerSecondLimit !== null)
  boundedResources.sort((a, b) => a.modeledLogicalOpsPerSecondLimit - b.modeledLogicalOpsPerSecondLimit ||
    a.resource.localeCompare(b.resource))
  const sustainable = boundedResources[0].modeledLogicalOpsPerSecondLimit
  const offered = workload.offeredLogicalOpsPerSecond === null
    ? sustainable * workload.operatingFractionOfSustainable
    : workload.offeredLogicalOpsPerSecond
  for (const resource of resources) {
    const foreground = resource.foregroundDemandPerLogicalOpAtWorstRelay * offered
    resource.modeledUtilizationAtOfferedLoad = fixed(
      (resource.backgroundDemandPerRelay + foreground) / resource.rawCapacityPerRelay
    )
  }

  const operationCeilings = perOperationDemand.map(entry => ({
    name: entry.name,
    family: entry.family,
    modeledStandaloneLogicalOpsPerSecond: fixed(standaloneLimit(resources, entry.demand)),
    bottleneck: standaloneBottleneck(resources, entry.demand)
  }))
  const familyCeilings = []
  for (const family of ['CELL', 'INBOX', 'CORE', 'FORWARD']) {
    const entries = perOperationDemand.filter(entry => entry.family === family)
    const probability = sum(entries.map(entry => entry.probability))
    if (probability === 0) continue
    const familyDemand = emptyResourceDemand()
    for (const entry of entries) addScaledDemand(familyDemand, entry.demand, entry.probability / probability)
    familyCeilings.push({
      family,
      configuredBlendProbability: fixed(probability),
      modeledStandaloneLogicalOpsPerSecond: fixed(standaloneLimit(resources, familyDemand)),
      bottleneck: standaloneBottleneck(resources, familyDemand)
    })
  }

  return {
    modeledSustainableLogicalOpsPerSecond: fixed(sustainable),
    offeredLogicalOpsPerSecond: fixed(offered),
    offeredLoadSource: workload.offeredLogicalOpsPerSecond === null
      ? 'operatingFractionOfSustainable'
      : 'explicit-config',
    targetResourceUtilization: workload.targetResourceUtilization,
    bottleneck: boundedResources[0].resource,
    foregroundDemandUnits: 'worst-relay resource demand at one blended logical operation per second',
    routingSkewProxy: fixed(routingSkew),
    resources,
    operationCeilings,
    familyCeilings,
    _resourceByName: Object.fromEntries(resources.map(resource => [resource.resource, resource]))
  }
}

function emptyResourceDemand () {
  return {
    diskWriteBytesPerSecond: 0,
    diskReadBytesPerSecond: 0,
    diskIopsPerSecond: 0,
    networkIngressBytesPerSecond: 0,
    networkEgressBytesPerSecond: 0,
    cpuSecondsPerSecond: 0,
    walFsyncCommitsPerSecond: 0,
    walRetainedBytesPerSecond: 0,
    streamBufferedBytes: 0,
    streamSlots: 0,
    inboxWaiterBytes: 0,
    inboxWaiterSlots: 0
  }
}

function operationResourceDemand (config, operation, routingSkew) {
  const demand = emptyResourceDemand()
  const factor = operation.relayTouches / config.fleet.relayCount * routingSkew
  demand.diskWriteBytesPerSecond = factor * operation.diskWriteBytesPerTouch
  demand.diskReadBytesPerSecond = factor * operation.diskReadBytesPerTouch
  demand.diskIopsPerSecond = factor * operation.diskIopsPerTouch
  demand.networkIngressBytesPerSecond = factor * operation.networkIngressBytesPerTouch
  demand.networkEgressBytesPerSecond = factor * operation.networkEgressBytesPerTouch
  demand.cpuSecondsPerSecond = factor * (
    operation.cpuOperationUnitsPerTouch * config.cpu.fixedMicrosPerReplicaOperation +
    operation.cpuBytesPerTouch / KIB * config.cpu.microsPerKiB
  ) / 1_000_000
  demand.walFsyncCommitsPerSecond = factor * operation.walRecordsPerTouch /
    config.wal.effectiveGroupCommitRecords
  demand.walRetainedBytesPerSecond = factor * operation.walBytesPerTouch
  if (operation.concurrencyKind === 'INBOX_WAITER') {
    demand.inboxWaiterBytes = factor * operation.activeSecondsPerTouch * operation.bufferedBytesPerActiveStream
    demand.inboxWaiterSlots = factor * operation.activeSecondsPerTouch
  } else if (operation.concurrencyKind === 'STREAM') {
    demand.streamBufferedBytes = factor * operation.activeSecondsPerTouch * operation.bufferedBytesPerActiveStream
    demand.streamSlots = factor * operation.activeSecondsPerTouch
  }
  return demand
}

function addScaledDemand (target, source, scale) {
  for (const key of Object.keys(target)) target[key] += source[key] * scale
}

function standaloneLimit (resources, demand) {
  let limit = Infinity
  for (const resource of resources) {
    const resourceDemand = demand[resource.resource]
    if (!(resourceDemand > 0)) continue
    const available = Math.max(0, resource.safeCapacityPerRelay - resource.backgroundDemandPerRelay)
    limit = Math.min(limit, available / resourceDemand)
  }
  return limit
}

function standaloneBottleneck (resources, demand) {
  let name = null
  let limit = Infinity
  for (const resource of resources) {
    const resourceDemand = demand[resource.resource]
    if (!(resourceDemand > 0)) continue
    const available = Math.max(0, resource.safeCapacityPerRelay - resource.backgroundDemandPerRelay)
    const next = available / resourceDemand
    if (next < limit) {
      limit = next
      name = resource.resource
    }
  }
  return name
}

function buildLatencyModel (config, operationModel, throughput) {
  const resource = throughput._resourceByName
  const diskWriteQueue = queueMultiplier(resource.diskWriteBytesPerSecond.modeledUtilizationAtOfferedLoad)
  const diskReadQueue = queueMultiplier(resource.diskReadBytesPerSecond.modeledUtilizationAtOfferedLoad)
  const iopsQueue = queueMultiplier(resource.diskIopsPerSecond.modeledUtilizationAtOfferedLoad)
  const walQueue = queueMultiplier(resource.walFsyncCommitsPerSecond.modeledUtilizationAtOfferedLoad)
  const ingressQueue = queueMultiplier(resource.networkIngressBytesPerSecond.modeledUtilizationAtOfferedLoad)
  const egressQueue = queueMultiplier(resource.networkEgressBytesPerSecond.modeledUtilizationAtOfferedLoad)
  const cpuQueue = queueMultiplier(resource.cpuSecondsPerSecond.modeledUtilizationAtOfferedLoad)
  const writeDiskQueue = Math.max(diskWriteQueue, iopsQueue)
  const readDiskQueue = Math.max(diskReadQueue, iopsQueue)
  const networkQueue = Math.max(ingressQueue, egressQueue)
  const ingressBytesPerSecond = config.network.ingressBitsPerSecond / 8
  const egressBytesPerSecond = config.network.egressBitsPerSecond / 8
  const byOperation = operationModel.operations.map(operation => {
    const networkSerializationMs = Math.max(
      operation.networkIngressBytesPerTouch / ingressBytesPerSecond,
      operation.networkEgressBytesPerTouch / egressBytesPerSecond
    ) * 1000 * networkQueue * operation.serialHops
    const diskSerializationMs = (
      operation.diskWriteBytesPerTouch / config.disk.sequentialWriteBytesPerSecond * writeDiskQueue +
      operation.diskReadBytesPerTouch / config.disk.sequentialReadBytesPerSecond * readDiskQueue
    ) * 1000
    const diskBaseP50 = operation.diskWriteBytesPerTouch > 0
      ? config.disk.writeBaseLatencyMs * writeDiskQueue
      : operation.diskReadBytesPerTouch > 0
        ? config.disk.readBaseLatencyMs * readDiskQueue
        : 0
    const diskBaseP99 = operation.diskWriteBytesPerTouch > 0
      ? config.disk.writeBaseLatencyMs * 4 * writeDiskQueue
      : operation.diskReadBytesPerTouch > 0
        ? config.disk.readBaseLatencyMs * 4 * readDiskQueue
        : 0
    const cpuServiceMs = (
      operation.cpuOperationUnitsPerTouch * config.cpu.fixedMicrosPerReplicaOperation +
      operation.cpuBytesPerTouch / KIB * config.cpu.microsPerKiB
    ) / 1000 * cpuQueue
    const walP50 = operation.walRecordsPerTouch > 0
      ? config.wal.maxGroupDelayMs / 2 + config.wal.fsyncLatencyMs * walQueue
      : 0
    const walP99 = operation.walRecordsPerTouch > 0
      ? config.wal.maxGroupDelayMs + config.wal.fsyncLatencyMs * 3 * walQueue
      : 0
    const base = {
      name: operation.name,
      family: operation.family,
      operation: operation.operation,
      latencyKind: operation.latencyKind
    }
    if (operation.latencyKind === 'stream-open-and-transfer-floor') {
      return {
        ...base,
        modeledOpenP50Ms: fixed(config.network.medianRttMs * operation.serialHops * networkQueue + diskBaseP50 + walP50),
        modeledOpenP99Ms: fixed(config.network.p99RttMs * operation.serialHops * networkQueue + diskBaseP99 + walP99),
        modeledTransferSerializationFloorMs: fixed(networkSerializationMs),
        configuredMeanActiveSeconds: operation.activeSecondsPerTouch,
        note: 'Open latency and transfer serialization floor are separate; no stream completion percentile is inferred.'
      }
    }
    const waitP50 = operation.meanWaitMillis || 0
    const waitP99 = operation.maxWaitMillis || 0
    return {
      ...base,
      modeledP50Ms: fixed(
        config.network.medianRttMs * operation.serialHops * networkQueue +
        networkSerializationMs + diskSerializationMs + diskBaseP50 + cpuServiceMs + walP50 + waitP50
      ),
      modeledP99Ms: fixed(
        config.network.p99RttMs * operation.serialHops * networkQueue +
        networkSerializationMs * 2 + diskSerializationMs * 2 + diskBaseP99 + cpuServiceMs * 4 + walP99 + waitP99
      )
    }
  })

  return {
    status: 'modeled-steady-state',
    estimator: 'family-specific configured bytes, transfer serialization floors, independent resource queue multipliers, RTT, disk service, CPU, and WAL costs',
    byOperation,
    resourceQueueMultipliers: {
      diskWrite: fixed(writeDiskQueue),
      diskRead: fixed(readDiskQueue),
      network: fixed(networkQueue),
      walFsync: fixed(walQueue),
      cpu: fixed(cpuQueue)
    }
  }
}

function buildFailureScenario (config, placement) {
  const failed = config.fleet.unavailableRelays
  const total = config.simulation.sampleObjects
  const replication = config.fleet.replicationFactor
  const analyticRead = hypergeometricAvailability(
    config.fleet.relayCount,
    failed,
    replication,
    config.workload.readQuorum
  )
  const analyticWrite = hypergeometricAvailability(
    config.fleet.relayCount,
    failed,
    replication,
    config.workload.writeAcks
  )
  return {
    unavailableRelayCount: failed,
    selectedFailedRelayIndices: placement.report.failedRelayIndices,
    existingReplicaSets: {
      simulatedReadableFraction: fixed(placement.report.failureSample.readableObjects / total),
      analyticReadableProbability: fixed(analyticRead),
      simulatedWriteQuorumFraction: fixed(placement.report.failureSample.writeQuorumObjects / total),
      analyticWriteQuorumProbability: fixed(analyticWrite),
      simulatedAtLeastOneReplicaFraction: fixed(placement.report.failureSample.survivingObjects / total),
      analyticAtLeastOneReplicaProbability: fixed(hypergeometricAvailability(
        config.fleet.relayCount,
        failed,
        replication,
        1
      ))
    },
    guaranteedArbitraryRelayFailureTolerance: {
      retainAtLeastOneReplica: replication - 1,
      retainReadQuorum: replication - config.workload.readQuorum,
      retainWriteQuorum: replication - config.workload.writeAcks
    },
    scope: 'temporary unavailability of uniformly placed existing replicas; this is not a correlated-operator or permanent-loss proof'
  }
}

function buildScalingSweep (config) {
  if (config.fleet.diskBytesByRelay !== null) {
    return {
      status: 'not-run-for-heterogeneous-disk-list',
      reason: 'A heterogeneous disk list defines exactly one fleet size; supply separate configs to compare other topologies.',
      points: []
    }
  }
  const counts = [...new Set([...config.simulation.scaleRelayCounts, config.fleet.relayCount])]
    .filter(count => count >= config.fleet.replicationFactor)
    .sort((a, b) => a - b)
  const points = []
  for (const relayCount of counts) {
    const scenarioConfig = deepMerge(config, {
      simulation: { scaleRelayCounts: [] },
      fleet: {
        relayCount,
        unavailableRelays: Math.min(config.fleet.unavailableRelays, relayCount - 1)
      }
    })
    validateConfig(scenarioConfig)
    const scenario = modelScenario(scenarioConfig)
    points.push({
      relayCount,
      rawFleetDiskBytes: scenario.storage.rawFleetDiskBytes,
      modeledLogicalPayloadCapacityBytes: scenario.storage.modeledLogicalPayloadCapacityBytes,
      modeledLogicalObjectCapacity: scenario.storage.modeledLogicalObjectCapacity,
      modeledSustainableLogicalOpsPerSecond: scenario.throughput.modeledSustainableLogicalOpsPerSecond,
      bottleneck: scenario.throughput.bottleneck,
      maximumPlacementByteSkewOverMean: scenario.placement.maximumByteSkewOverMean
    })
  }
  return {
    status: 'modeled',
    invariant: 'homogeneous per-relay resources and independent uniform placement; control-plane coordination cost is excluded',
    points
  }
}

function buildOptimizationCandidates (config, scenario) {
  const candidates = []
  const bottleneck = scenario.throughput.bottleneck
  const byResource = {
    walFsyncCommitsPerSecond: {
      id: 'wal-group-commit-and-fsync',
      action: 'Measure achieved group size and fsync tails; increase bounded group commit only if crash tests preserve the acknowledgement durability point.',
      validateWith: 'real segmented-WAL benchmark plus power-loss/fdatasync fault injection'
    },
    walRetainedBytesPerSecond: {
      id: 'checkpoint-certified-wal-pruning',
      action: 'Shorten retained WAL only through authenticated checkpoint and retention-certificate pruning; do not delete recovery history speculatively.',
      validateWith: 'checkpoint crash matrix, rollback-slot recovery, and one-million-record restart test'
    },
    diskWriteBytesPerSecond: {
      id: 'disk-write-amplification',
      action: 'Batch metadata, stream checkpoints, and inspect allocation/write amplification before adding disks or relays.',
      validateWith: 'filesystem-level byte counters and fio-calibrated multi-process benchmark'
    },
    diskReadBytesPerSecond: {
      id: 'read-locality-and-cache',
      action: 'Measure hot-set locality and bounded verified caches; never bypass content or capability verification for cache hits.',
      validateWith: 'cold/warm trace replay with integrity-negative cases'
    },
    diskIopsPerSecond: {
      id: 'small-object-packing',
      action: 'Evaluate authenticated internal packing for small opaque cells while preserving independent expiry, accounting, and crash recovery.',
      validateWith: 'small-object benchmark, tombstone churn, compaction crash, and space-reclamation evidence'
    },
    networkIngressBytesPerSecond: {
      id: 'ingress-bandwidth',
      action: 'Use bounded streaming, client-side chunk sizing, and additional independent relays; opaque encrypted payloads must not rely on relay-side semantic compression.',
      validateWith: 'multi-region shaped-network test with slowloris and backpressure cases'
    },
    networkEgressBytesPerSecond: {
      id: 'egress-bandwidth',
      action: 'Tune bounded parallel reads and add relays close to demand while retaining client-side verification and relay diversity.',
      validateWith: 'multi-region fanout benchmark and malicious/slow replica race'
    },
    cpuSecondsPerSecond: {
      id: 'cpu-profile',
      action: 'Profile hashing, framing, signatures, and copies before changing cryptographic work or worker count.',
      validateWith: 'CPU profile plus cross-runtime canonical-vector and adversarial verification tests'
    },
    streamBufferedBytes: {
      id: 'stream-buffer-backpressure',
      action: 'Reduce per-stream buffering, bound active durations, and enforce backpressure before increasing relay memory.',
      validateWith: 'CORE/FORWARD slow-consumer, stalled-hop, cancellation, and heap-pressure load tests'
    },
    streamSlots: {
      id: 'stream-lifecycle-capacity',
      action: 'Shorten idle reclamation and make terminal cleanup constant-space before increasing concurrent stream limits.',
      validateWith: 'high-churn circuit/session test with recovery and terminal-map exhaustion checks'
    },
    inboxWaiterBytes: {
      id: 'inbox-watch-memory',
      action: 'Bound WATCH state per topic and return resumable cursors under memory pressure.',
      validateWith: '100k Inbox WATCH churn, cancellation, timeout, and per-topic fairness tests'
    },
    inboxWaiterSlots: {
      id: 'inbox-watch-slots',
      action: 'Enforce global and per-topic waiter quotas with fair rejection and prompt timeout cleanup.',
      validateWith: 'global/per-topic waiter saturation and recovery tests'
    }
  }
  if (byResource[bottleneck]) candidates.push({ priority: 1, bottleneck, ...byResource[bottleneck] })
  if (scenario.placement.maximumByteSkewOverMean > 1.10) {
    candidates.push({
      priority: 2,
      id: 'placement-skew',
      action: 'Increase placement samples and test virtual-bucket rebalancing; capacity is currently limited by the fullest relay rather than fleet mean.',
      validateWith: 'bucket-map rebalance with crash points before, during, and after signed map commit'
    })
  }
  const small = scenario.objectModel.mix.find(item => item.name === 'small-cell')
  if (small && small.storedBytesPerReplica / small.payloadBytes >= 2) {
    candidates.push({
      priority: 3,
      id: 'allocation-overhead',
      action: 'Measure filesystem allocation overhead for small cells and consider an authenticated append arena with per-cell garbage collection.',
      validateWith: 'one-million-small-cell capacity benchmark and deletion/compaction recovery tests'
    })
  }
  if (config.fleet.replicationFactor > 1) {
    candidates.push({
      priority: 4,
      id: 'replication-policy-evidence',
      action: 'Compare replication and later client-side erasure profiles using common availability and repair evidence; never lower replication solely to improve a modeled number.',
      validateWith: 'independent-operator outage, correlated failure, repair backlog, and permanent-loss simulations'
    })
  }
  return candidates
}

function buildAssumptions (config) {
  return [
    `${config.fleet.replicationFactor} distinct full opaque replicas are placed uniformly across ${config.fleet.relayCount} relays.`,
    `Each relay reserves ${fixed(config.fleet.storageReserveFraction * 100)}% of disk outside the data budget and ${fixed(config.wal.reserveFractionOfDisk * 100)}% for retained WAL.`,
    `Capacity is planned at ${fixed(config.fleet.plannedFillFraction * 100)}% of the sampled first-full-relay limit.`,
    `Throughput uses the most-loaded sampled relay and a ${fixed(config.workload.targetResourceUtilization * 100)}% safe resource ceiling.`,
    `CELL bodies consume one exact frozen size class (${Object.values(CELL_SIZE_CLASS).join('/')}); ${config.objects.applicationFramingBytes} application framing bytes are inside, not outside, each cellBlob.`,
    `The foreground mix explicitly separates CELL, INBOX, CORE, and FORWARD operations; its configured family weights are ${familyMixSummary(config.workload.operations)}.`,
    `Persistent writes contact ${config.fleet.replicationFactor} relays in parallel and acknowledge after ${config.workload.writeAcks}; reads fan out to ${config.workload.readFanout} and require ${config.workload.readQuorum}.`,
    `The WAL averages ${config.wal.effectiveGroupCommitRecords} records per durable sync and retains ${config.wal.retentionSeconds} seconds at steady state.`,
    `A checkpoint rewrites ${config.checkpoint.bytesPerLiveObject} bytes per live replica every ${config.checkpoint.intervalSeconds} seconds and retains ${config.checkpoint.retainedCopies} complete copies.`,
    `Repair replaces ${fixed(config.repair.annualReplicaLossFraction * 100)}% of replicas per year and scrubs ${fixed(config.repair.annualScrubFraction * 100)}% per year at the planned live-set size.`,
    'Modeled p50/p99 latency combines configured RTT/service costs with independent queue multipliers; it is not sampled wall-clock latency.',
    'No claim about anonymity, durability, availability, or speed is inferred from encryption or signatures alone.'
  ]
}

function familyMixSummary (operations) {
  const total = sum(operations.map(operation => operation.weight))
  return ['CELL', 'INBOX', 'CORE', 'FORWARD']
    .map(family => `${family}=${fixed(sum(operations.filter(operation => operation.family === family).map(operation => operation.weight)) / total * 100)}%`)
    .join(', ')
}

function validateConfig (config) {
  const violations = []
  if (config.schema !== CAPACITY_LAB_CONFIG_SCHEMA) violations.push(`schema must equal ${CAPACITY_LAB_CONFIG_SCHEMA}`)
  integer(config.fleet.relayCount, 'fleet.relayCount', 1, 10000, violations)
  integer(config.fleet.replicationFactor, 'fleet.replicationFactor', 1, 10000, violations)
  if (Number.isInteger(config.fleet.relayCount) && Number.isInteger(config.fleet.replicationFactor) &&
      config.fleet.replicationFactor > config.fleet.relayCount) {
    violations.push('fleet.replicationFactor cannot exceed fleet.relayCount')
  }
  integer(config.fleet.unavailableRelays, 'fleet.unavailableRelays', 0, 9999, violations)
  if (Number.isInteger(config.fleet.unavailableRelays) && config.fleet.unavailableRelays >= config.fleet.relayCount) {
    violations.push('fleet.unavailableRelays must be less than fleet.relayCount')
  }
  fraction(config.fleet.storageReserveFraction, 'fleet.storageReserveFraction', violations)
  openFraction(config.fleet.plannedFillFraction, 'fleet.plannedFillFraction', violations)
  fraction(config.wal.reserveFractionOfDisk, 'wal.reserveFractionOfDisk', violations)
  if (isFiniteNumber(config.fleet.storageReserveFraction) && isFiniteNumber(config.wal.reserveFractionOfDisk) &&
      config.fleet.storageReserveFraction + config.wal.reserveFractionOfDisk >= 1) {
    violations.push('fleet.storageReserveFraction + wal.reserveFractionOfDisk must be less than 1')
  }
  positive(config.fleet.diskBytesPerRelay, 'fleet.diskBytesPerRelay', violations)
  if (config.fleet.diskBytesByRelay !== null) {
    if (!Array.isArray(config.fleet.diskBytesByRelay) || config.fleet.diskBytesByRelay.length !== config.fleet.relayCount) {
      violations.push('fleet.diskBytesByRelay must be null or contain exactly fleet.relayCount entries')
    } else {
      config.fleet.diskBytesByRelay.forEach((value, index) => positive(value, `fleet.diskBytesByRelay[${index}]`, violations))
    }
  }
  if (!Array.isArray(config.objects.mix) || config.objects.mix.length === 0) {
    violations.push('objects.mix must contain at least one object class')
  } else {
    const names = new Set()
    for (let i = 0; i < config.objects.mix.length; i++) {
      const item = config.objects.mix[i]
      rejectUnknownFields(item, ['name', 'family', 'sizeClass', 'weight', 'payloadBytes'], `objects.mix[${i}]`, violations)
      if (!item || typeof item.name !== 'string' || item.name.length === 0 || names.has(item.name)) {
        violations.push(`objects.mix[${i}].name must be a unique non-empty string`)
      } else names.add(item.name)
      if (item?.family !== 'CELL') violations.push(`objects.mix[${i}].family must be CELL; retained INBOX/CORE projections use their family surfaces`)
      integer(item?.sizeClass, `objects.mix[${i}].sizeClass`, 1, 5, violations)
      positive(item?.weight, `objects.mix[${i}].weight`, violations)
      integer(item?.payloadBytes, `objects.mix[${i}].payloadBytes`, 1, Number.MAX_SAFE_INTEGER, violations)
      const exactBytes = CELL_SIZE_CLASS[item?.sizeClass]
      if (exactBytes && Number.isSafeInteger(item?.payloadBytes) &&
          item.payloadBytes + config.objects.applicationFramingBytes > exactBytes) {
        violations.push(`objects.mix[${i}] payload plus application framing exceeds exact CELL size class ${item.sizeClass} (${exactBytes} bytes)`)
      }
    }
  }
  for (const [path, value] of [
    ['objects.applicationFramingBytes', config.objects.applicationFramingBytes],
    ['objects.objectMetadataBytes', config.objects.objectMetadataBytes],
    ['objects.indexBytes', config.objects.indexBytes],
    ['surfaces.inboxControlBytes', config.surfaces.inboxControlBytes],
    ['surfaces.inboxFrameIndexBytes', config.surfaces.inboxFrameIndexBytes],
    ['surfaces.inboxReadPinBytes', config.surfaces.inboxReadPinBytes],
    ['surfaces.inboxReadResultOverheadBytes', config.surfaces.inboxReadResultOverheadBytes],
    ['surfaces.coreControlBytes', config.surfaces.coreControlBytes],
    ['surfaces.coreProofPinBytes', config.surfaces.coreProofPinBytes],
    ['surfaces.coreAdditionalIndexBytes', config.surfaces.coreAdditionalIndexBytes],
    ['surfaces.streamFrameOverheadBytes', config.surfaces.streamFrameOverheadBytes]
  ]) integer(value, path, 0, Number.MAX_SAFE_INTEGER, violations)
  integer(config.surfaces.coreMaximumCorpusBytes, 'surfaces.coreMaximumCorpusBytes', 1, 64 * MIB, violations)
  integer(config.surfaces.inboxWaiterMemoryBytesPerRelay, 'surfaces.inboxWaiterMemoryBytesPerRelay', 1, Number.MAX_SAFE_INTEGER, violations)
  integer(config.surfaces.inboxMaxWaitersPerRelay, 'surfaces.inboxMaxWaitersPerRelay', 1, Number.MAX_SAFE_INTEGER, violations)
  integer(config.streams.maxBufferedBytesPerRelay, 'streams.maxBufferedBytesPerRelay', 1, Number.MAX_SAFE_INTEGER, violations)
  integer(config.streams.maxConcurrentStreamsPerRelay, 'streams.maxConcurrentStreamsPerRelay', 1, Number.MAX_SAFE_INTEGER, violations)
  validateOperations(config, violations)
  for (const [path, value] of [
    ['disk.sequentialWriteBytesPerSecond', config.disk.sequentialWriteBytesPerSecond],
    ['disk.sequentialReadBytesPerSecond', config.disk.sequentialReadBytesPerSecond],
    ['disk.randomIopsPerSecond', config.disk.randomIopsPerSecond],
    ['wal.fsyncLatencyMs', config.wal.fsyncLatencyMs],
    ['wal.retentionSeconds', config.wal.retentionSeconds],
    ['checkpoint.intervalSeconds', config.checkpoint.intervalSeconds],
    ['network.ingressBitsPerSecond', config.network.ingressBitsPerSecond],
    ['network.egressBitsPerSecond', config.network.egressBitsPerSecond],
    ['network.medianRttMs', config.network.medianRttMs],
    ['network.p99RttMs', config.network.p99RttMs],
    ['cpu.coresPerRelay', config.cpu.coresPerRelay]
  ]) positive(value, path, violations)
  for (const [path, value] of [
    ['objects.filesystemAllocationBytes', config.objects.filesystemAllocationBytes],
    ['objects.diskReadGranularityBytes', config.objects.diskReadGranularityBytes],
    ['wal.alignmentBytes', config.wal.alignmentBytes],
    ['wal.effectiveGroupCommitRecords', config.wal.effectiveGroupCommitRecords],
    ['checkpoint.bytesPerLiveObject', config.checkpoint.bytesPerLiveObject],
    ['checkpoint.retainedCopies', config.checkpoint.retainedCopies],
    ['checkpoint.writesPerInterval', config.checkpoint.writesPerInterval],
    ['checkpoint.ioChunkBytes', config.checkpoint.ioChunkBytes]
  ]) integer(value, path, 1, Number.MAX_SAFE_INTEGER, violations)
  for (const [path, value] of [
    ['disk.writeBaseLatencyMs', config.disk.writeBaseLatencyMs],
    ['disk.readBaseLatencyMs', config.disk.readBaseLatencyMs],
    ['wal.recordOverheadBytes', config.wal.recordOverheadBytes],
    ['wal.maxGroupDelayMs', config.wal.maxGroupDelayMs],
    ['workload.requestOverheadBytes', config.workload.requestOverheadBytes],
    ['workload.responseOverheadBytes', config.workload.responseOverheadBytes],
    ['workload.ackBytes', config.workload.ackBytes],
    ['cpu.fixedMicrosPerReplicaOperation', config.cpu.fixedMicrosPerReplicaOperation],
    ['cpu.microsPerKiB', config.cpu.microsPerKiB],
    ['repair.hashMicrosPerKiB', config.repair.hashMicrosPerKiB]
  ]) nonNegative(value, path, violations)
  fraction(config.repair.annualReplicaLossFraction, 'repair.annualReplicaLossFraction', violations)
  fraction(config.repair.annualScrubFraction, 'repair.annualScrubFraction', violations)
  fraction(config.repair.networkOverheadFraction, 'repair.networkOverheadFraction', violations)
  integer(config.workload.readFanout, 'workload.readFanout', 1, 10000, violations)
  integer(config.workload.readQuorum, 'workload.readQuorum', 1, 10000, violations)
  integer(config.workload.writeAcks, 'workload.writeAcks', 1, 10000, violations)
  if (config.workload.readQuorum > config.workload.readFanout) violations.push('workload.readQuorum cannot exceed workload.readFanout')
  if (config.workload.readFanout > config.fleet.replicationFactor) violations.push('workload.readFanout cannot exceed fleet.replicationFactor')
  if (config.workload.writeAcks > config.fleet.replicationFactor) violations.push('workload.writeAcks cannot exceed fleet.replicationFactor')
  if (config.workload.offeredLogicalOpsPerSecond !== null) {
    nonNegative(config.workload.offeredLogicalOpsPerSecond, 'workload.offeredLogicalOpsPerSecond', violations)
  }
  openFraction(config.workload.operatingFractionOfSustainable, 'workload.operatingFractionOfSustainable', violations)
  openFraction(config.workload.targetResourceUtilization, 'workload.targetResourceUtilization', violations)
  if (typeof config.objectives.requireExplicitOfferedLoad !== 'boolean') {
    violations.push('objectives.requireExplicitOfferedLoad must be boolean')
  }
  validateUniqueStrings(config.objectives.requiredFamilies, 'objectives.requiredFamilies', violations)
  validateUniqueStrings(config.objectives.requiredOperationKinds, 'objectives.requiredOperationKinds', violations)
  fraction(config.objectives.minimumFamilyBlendFraction, 'objectives.minimumFamilyBlendFraction', violations)
  positive(config.objectives.maximumModeledUnaryP99Millis, 'objectives.maximumModeledUnaryP99Millis', violations)
  positive(config.objectives.maximumModeledStreamOpenP99Millis, 'objectives.maximumModeledStreamOpenP99Millis', violations)
  fraction(config.objectives.minimumFailureReadableFraction, 'objectives.minimumFailureReadableFraction', violations)
  fraction(config.objectives.minimumFailureWriteQuorumFraction, 'objectives.minimumFailureWriteQuorumFraction', violations)
  integer(config.simulation.sampleObjects, 'simulation.sampleObjects', 1, 5_000_000, violations)
  integer(config.simulation.virtualBuckets, 'simulation.virtualBuckets', 1, 1_048_576, violations)
  if (Number.isInteger(config.simulation.virtualBuckets) && Number.isInteger(config.fleet.relayCount) &&
      config.simulation.virtualBuckets < config.fleet.relayCount) {
    violations.push('simulation.virtualBuckets must be at least fleet.relayCount so every relay can own a bucket')
  }
  if (Number.isInteger(config.simulation.sampleObjects) && Number.isInteger(config.fleet.relayCount) &&
      config.simulation.sampleObjects < config.fleet.relayCount * 100) {
    violations.push('simulation.sampleObjects must be at least 100 times fleet.relayCount to bound placement sampling noise')
  }
  if (!Array.isArray(config.simulation.scaleRelayCounts)) {
    violations.push('simulation.scaleRelayCounts must be an array')
  } else {
    config.simulation.scaleRelayCounts.forEach((value, index) => integer(value, `simulation.scaleRelayCounts[${index}]`, 1, 10000, violations))
  }
  if (config.network.p99RttMs < config.network.medianRttMs) violations.push('network.p99RttMs must be at least network.medianRttMs')
  const disks = config.fleet.diskBytesByRelay || new Array(config.fleet.relayCount).fill(config.fleet.diskBytesPerRelay)
  if (Array.isArray(disks) && disks.every(isFiniteNumber) && sum(disks) > Number.MAX_SAFE_INTEGER) {
    violations.push('aggregate fleet disk bytes must not exceed Number.MAX_SAFE_INTEGER in report v1')
  }
  if (violations.length) throw new CapacityConfigError(violations)
}

function validateUniqueStrings (value, path, violations) {
  if (!Array.isArray(value) || value.length === 0) {
    violations.push(`${path} must be a non-empty array`)
    return
  }
  const seen = new Set()
  for (let index = 0; index < value.length; index++) {
    const item = value[index]
    if (typeof item !== 'string' || item.length === 0 || seen.has(item)) {
      violations.push(`${path}[${index}] must be a unique non-empty string`)
    } else {
      seen.add(item)
    }
  }
}

function validateOperations (config, violations) {
  if (!Array.isArray(config.workload.operations) || config.workload.operations.length === 0) {
    violations.push('workload.operations must contain at least one family operation')
    return
  }
  const common = ['name', 'family', 'operation', 'weight', 'walPayloadBytesPerRecord']
  const names = new Set()
  const cellNames = new Set(config.objects.mix.map(item => item?.name))
  for (let index = 0; index < config.workload.operations.length; index++) {
    const item = config.workload.operations[index]
    const path = `workload.operations[${index}]`
    if (!isPlainObject(item)) {
      violations.push(`${path} must be an object`)
      continue
    }
    if (typeof item.name !== 'string' || item.name.length === 0 || names.has(item.name)) {
      violations.push(`${path}.name must be a unique non-empty string`)
    } else names.add(item.name)
    positive(item.weight, `${path}.weight`, violations)

    if (item.family === 'CELL' && (item.operation === 'PUT' || item.operation === 'GET')) {
      rejectUnknownFields(item, [...common, 'storageClass'], path, violations)
      if (item.storageClass !== 'weighted-cell-mix' && !cellNames.has(item.storageClass)) {
        violations.push(`${path}.storageClass must be weighted-cell-mix or a configured CELL object name`)
      }
      if (item.operation === 'PUT') validateWalAllowance(item, path, violations)
      else if (item.walPayloadBytesPerRecord !== undefined) violations.push(`${path}.walPayloadBytesPerRecord is invalid for non-mutating CELL.GET`)
      continue
    }

    if (item.family === 'INBOX' && ['APPEND', 'READ', 'WATCH'].includes(item.operation)) {
      const fields = item.operation === 'APPEND'
        ? [...common, 'frameClass', 'logicalPayloadBytes']
        : item.operation === 'READ'
          ? [...common, 'frameClass', 'batchFrames']
          : [...common, 'frameClass', 'batchFrames', 'meanWaitMillis', 'maxWaitMillis']
      rejectUnknownFields(item, fields, path, violations)
      integer(item.frameClass, `${path}.frameClass`, 1, 3, violations)
      const frameBytes = INBOX_FRAME_CLASS[item.frameClass]
      validateWalAllowance(item, path, violations)
      if (item.operation === 'APPEND') {
        integer(item.logicalPayloadBytes, `${path}.logicalPayloadBytes`, 1, Number.MAX_SAFE_INTEGER, violations)
        if (frameBytes && Number.isSafeInteger(item.logicalPayloadBytes) &&
            item.logicalPayloadBytes + config.objects.applicationFramingBytes > frameBytes) {
          violations.push(`${path} logical payload plus application framing exceeds exact INBOX frame class ${item.frameClass} (${frameBytes} bytes)`)
        }
      } else {
        integer(item.batchFrames, `${path}.batchFrames`, 1, 64, violations)
        if (frameBytes && Number.isSafeInteger(item.batchFrames) &&
            item.batchFrames * (41 + frameBytes) + config.surfaces.inboxReadResultOverheadBytes > 4 * MIB) {
          violations.push(`${path} modeled result exceeds the frozen 4 MiB INBOX result cap`)
        }
        if (item.operation === 'WATCH') {
          integer(item.meanWaitMillis, `${path}.meanWaitMillis`, 1, 30000, violations)
          integer(item.maxWaitMillis, `${path}.maxWaitMillis`, 1, 30000, violations)
          if (item.meanWaitMillis > item.maxWaitMillis) violations.push(`${path}.meanWaitMillis cannot exceed maxWaitMillis`)
        }
      }
      continue
    }

    if (item.family === 'CORE' && ['MIRROR', 'PROVE', 'OPEN_REPLICATION'].includes(item.operation)) {
      const fields = item.operation === 'MIRROR'
        ? [...common, 'corpusBytes', 'transferFraction']
        : item.operation === 'PROVE'
          ? [...common, 'resultBytes']
          : [...common, 'sessionClass', 'ingressBytes', 'egressBytes', 'meanDurationSeconds', 'meanBufferedBytes']
      rejectUnknownFields(item, fields, path, violations)
      validateWalAllowance(item, path, violations)
      if (item.operation === 'MIRROR') {
        integer(item.corpusBytes, `${path}.corpusBytes`, 1, config.surfaces.coreMaximumCorpusBytes, violations)
        fraction(item.transferFraction, `${path}.transferFraction`, violations)
      } else if (item.operation === 'PROVE') {
        integer(item.resultBytes, `${path}.resultBytes`, 1, 4 * MIB - 256, violations)
      } else {
        integer(item.sessionClass, `${path}.sessionClass`, 1, 3, violations)
        integer(item.ingressBytes, `${path}.ingressBytes`, 0, Number.MAX_SAFE_INTEGER, violations)
        integer(item.egressBytes, `${path}.egressBytes`, 0, Number.MAX_SAFE_INTEGER, violations)
        positive(item.meanDurationSeconds, `${path}.meanDurationSeconds`, violations)
        integer(item.meanBufferedBytes, `${path}.meanBufferedBytes`, 1, MIB + 65535, violations)
        const limits = CORE_SESSION_CLASS[item.sessionClass]
        if (limits && Number.isSafeInteger(item.ingressBytes) && Number.isSafeInteger(item.egressBytes) &&
            item.ingressBytes + item.egressBytes > limits.maxSessionBytes) {
          violations.push(`${path} ingressBytes + egressBytes exceeds CORE session class ${item.sessionClass}`)
        }
        if (limits && item.meanDurationSeconds > limits.lifetimeMillis / 1000) {
          violations.push(`${path}.meanDurationSeconds exceeds CORE session class lifetime`)
        }
      }
      continue
    }

    if (item.family === 'FORWARD' && item.operation === 'CIRCUIT') {
      rejectUnknownFields(item, [...common, 'circuitClass', 'wireClass', 'meanCircuitBytes', 'meanDataFrameBytes',
        'hopCount', 'meanDurationSeconds', 'meanBufferedBytes'], path, violations)
      validateWalAllowance(item, path, violations)
      integer(item.circuitClass, `${path}.circuitClass`, 1, 3, violations)
      integer(item.wireClass, `${path}.wireClass`, 1, 3, violations)
      const circuit = FORWARD_CIRCUIT_CLASS[item.circuitClass]
      const wireBytes = STREAM_WIRE_CLASS[item.wireClass]
      integer(item.meanCircuitBytes, `${path}.meanCircuitBytes`, 1,
        circuit?.maxCircuitBytes || Number.MAX_SAFE_INTEGER, violations)
      integer(item.meanDataFrameBytes, `${path}.meanDataFrameBytes`, 1,
        wireBytes || DISPATCH_LIMITS.MAX_FORWARD_DATA_BYTES, violations)
      if (wireBytes && item.meanDataFrameBytes > DISPATCH_LIMITS.MAX_FORWARD_DATA_BYTES) {
        violations.push(`${path}.meanDataFrameBytes exceeds MAX_FORWARD_DATA_BYTES`)
      }
      integer(item.hopCount, `${path}.hopCount`, 1, config.fleet.relayCount, violations)
      positive(item.meanDurationSeconds, `${path}.meanDurationSeconds`, violations)
      integer(item.meanBufferedBytes, `${path}.meanBufferedBytes`, 1, DISPATCH_LIMITS.MAX_FORWARD_WINDOW_BYTES, violations)
      if (circuit && item.meanDurationSeconds > circuit.lifetimeMillis / 1000) {
        violations.push(`${path}.meanDurationSeconds exceeds FORWARD circuit class lifetime`)
      }
      if (circuit && wireBytes && item.meanBufferedBytes > circuit.grantedInitialWindow + wireBytes) {
        violations.push(`${path}.meanBufferedBytes exceeds the class initial window plus one negotiated DATA frame`)
      }
      continue
    }

    violations.push(`${path} has unsupported family/operation ${String(item.family)}/${String(item.operation)}`)
  }
}

function validateWalAllowance (item, path, violations) {
  integer(item.walPayloadBytesPerRecord, `${path}.walPayloadBytesPerRecord`, 1, 4 * MIB, violations)
}

function rejectUnknownFields (value, allowed, path, violations) {
  if (!isPlainObject(value)) return
  const accepted = new Set(allowed)
  for (const key of Object.keys(value)) {
    if (!accepted.has(key)) violations.push(`unknown configuration field ${path}.${key}`)
  }
}

function relayDiskBytes (config) {
  return config.fleet.diskBytesByRelay === null
    ? new Array(config.fleet.relayCount).fill(config.fleet.diskBytesPerRelay)
    : [...config.fleet.diskBytesByRelay]
}

function chooseMix (mix, value) {
  let cursor = 0
  for (const item of mix) {
    cursor += item.probability
    if (value < cursor) return item
  }
  return mix[mix.length - 1]
}

function chooseDistinct (rng, upperBound, count) {
  const values = []
  const seen = new Set()
  while (values.length < count) {
    const value = rng.int(upperBound)
    if (seen.has(value)) continue
    seen.add(value)
    values.push(value)
  }
  values.sort((a, b) => a - b)
  return values
}

function buildBucketOwners (seed, relayCount, virtualBuckets) {
  const offset = hash32(`${seed}:bucket-offset:${relayCount}`) % relayCount
  const step = coprimeStep(hash32(`${seed}:bucket-step:${relayCount}`), relayCount)
  const owners = new Array(virtualBuckets)
  for (let bucket = 0; bucket < virtualBuckets; bucket++) {
    owners[bucket] = (bucket * step + offset) % relayCount
  }
  return owners
}

function chooseRelaysViaBuckets (rng, bucketOwners, count) {
  const relays = []
  const seen = new Set()
  const randomAttemptLimit = Math.max(128, count * 32)
  for (let i = 0; i < randomAttemptLimit && relays.length < count; i++) {
    const owner = bucketOwners[rng.int(bucketOwners.length)]
    if (seen.has(owner)) continue
    seen.add(owner)
    relays.push(owner)
  }
  const start = rng.int(bucketOwners.length)
  for (let i = 0; i < bucketOwners.length && relays.length < count; i++) {
    const owner = bucketOwners[(start + i) % bucketOwners.length]
    if (seen.has(owner)) continue
    seen.add(owner)
    relays.push(owner)
  }
  if (relays.length !== count) {
    throw new CapacityConfigError(['virtual bucket map cannot provide the configured number of distinct replica relays'])
  }
  relays.sort((a, b) => a - b)
  return relays
}

function ownerCounts (owners, relayCount) {
  const counts = new Array(relayCount).fill(0)
  for (const owner of owners) counts[owner]++
  return counts
}

function coprimeStep (seed, modulo) {
  if (modulo <= 1) return 1
  let step = (seed % (modulo - 1)) + 1
  while (greatestCommonDivisor(step, modulo) !== 1) {
    step++
    if (step >= modulo) step = 1
  }
  return step
}

function greatestCommonDivisor (left, right) {
  let a = left
  let b = right
  while (b !== 0) {
    const remainder = a % b
    a = b
    b = remainder
  }
  return a
}

function hypergeometricAvailability (relayCount, failedCount, replicas, quorum) {
  let probability = 0
  const maxFailedReplicas = Math.min(failedCount, replicas)
  for (let failedReplicas = 0; failedReplicas <= maxFailedReplicas; failedReplicas++) {
    const survivors = replicas - failedReplicas
    if (survivors < quorum) continue
    if (replicas - failedReplicas > relayCount - failedCount) continue
    probability += Math.exp(
      logChoose(failedCount, failedReplicas) +
      logChoose(relayCount - failedCount, replicas - failedReplicas) -
      logChoose(relayCount, replicas)
    )
  }
  return Math.min(1, probability)
}

function logChoose (n, k) {
  if (k < 0 || k > n) return -Infinity
  const selected = Math.min(k, n - k)
  let value = 0
  for (let i = 1; i <= selected; i++) value += Math.log(n - selected + i) - Math.log(i)
  return value
}

function queueMultiplier (utilization) {
  if (!(utilization >= 0) || utilization >= 1) return Infinity
  return 1 / (1 - utilization)
}

function weightedMean (mix, property) {
  return sum(mix.map(item => item.probability * item[property]))
}

function summarize (values) {
  const sorted = [...values].sort((a, b) => a - b)
  return {
    min: fixed(sorted[0]),
    mean: fixed(sum(sorted) / sorted.length),
    p50: fixed(quantile(sorted, 0.50)),
    p95: fixed(quantile(sorted, 0.95)),
    max: fixed(sorted[sorted.length - 1])
  }
}

function quantile (sorted, q) {
  if (sorted.length === 1) return sorted[0]
  const index = (sorted.length - 1) * q
  const lower = Math.floor(index)
  const upper = Math.ceil(index)
  if (lower === upper) return sorted[lower]
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower)
}

function roundUp (value, alignment) {
  return Math.ceil(value / alignment) * alignment
}

function fixed (value) {
  return Math.round(value * 1_000_000) / 1_000_000
}

function sum (values) {
  return values.reduce((total, value) => total + value, 0)
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function stableStringify (value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

function hash32 (text) {
  let hash = 2166136261
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return hash >>> 0
}

class Rng {
  constructor (seed) {
    this.state = seed >>> 0
  }

  next () {
    let value = this.state += 0x6D2B79F5
    value = Math.imul(value ^ value >>> 15, value | 1)
    value ^= value + Math.imul(value ^ value >>> 7, value | 61)
    return ((value ^ value >>> 14) >>> 0) / 4294967296
  }

  int (upperBound) {
    return Math.floor(this.next() * upperBound)
  }
}

function deepMerge (base, override) {
  if (Array.isArray(override)) return override.map(clone)
  if (!override || typeof override !== 'object') return override === undefined ? clone(base) : override
  const result = {}
  for (const key of new Set([...Object.keys(base || {}), ...Object.keys(override)])) {
    const left = base?.[key]
    const right = override[key]
    if (right === undefined) result[key] = clone(left)
    else if (isPlainObject(left) && isPlainObject(right)) result[key] = deepMerge(left, right)
    else result[key] = clone(right)
  }
  return result
}

function clone (value) {
  if (Array.isArray(value)) return value.map(clone)
  if (isPlainObject(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, clone(item)]))
  return value
}

function isPlainObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function collectUnknownKeys (input, shape, prefix, violations) {
  for (const [key, value] of Object.entries(input)) {
    const path = prefix ? `${prefix}.${key}` : key
    if (!Object.prototype.hasOwnProperty.call(shape, key)) {
      violations.push(`unknown configuration field ${path}`)
      continue
    }
    if (isPlainObject(value) && isPlainObject(shape[key])) {
      collectUnknownKeys(value, shape[key], path, violations)
    }
  }
}

function deepFreeze (value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value)
    for (const item of Object.values(value)) deepFreeze(item)
  }
  return value
}

function isFiniteNumber (value) {
  return typeof value === 'number' && Number.isFinite(value)
}

function positive (value, path, violations) {
  if (!isFiniteNumber(value) || value <= 0) violations.push(`${path} must be a positive finite number`)
}

function nonNegative (value, path, violations) {
  if (!isFiniteNumber(value) || value < 0) violations.push(`${path} must be a non-negative finite number`)
}

function fraction (value, path, violations) {
  if (!isFiniteNumber(value) || value < 0 || value > 1) violations.push(`${path} must be between 0 and 1 inclusive`)
}

function openFraction (value, path, violations) {
  if (!isFiniteNumber(value) || value <= 0 || value >= 1) violations.push(`${path} must be greater than 0 and less than 1`)
}

function integer (value, path, min, max, violations) {
  if (!Number.isSafeInteger(value) || value < min || value > max) violations.push(`${path} must be an integer between ${min} and ${max}`)
}

async function readStdin () {
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  return Buffer.concat(chunks).toString('utf8')
}

function usage () {
  return [
    'Usage: node scripts/blind-capacity-lab.mjs [--config FILE|-] [--pretty|--compact]',
    '',
    'The command emits one JSON document. Values are deterministic model estimates,',
    'not measured hardware performance. Use --config - to read JSON from stdin.'
  ].join('\n')
}

async function main (argv) {
  let configPath = null
  let pretty = true
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--config') {
      configPath = argv[++i]
      if (!configPath) throw new CapacityConfigError(['--config requires a file path or -'])
    } else if (arg === '--pretty') pretty = true
    else if (arg === '--compact') pretty = false
    else if (arg === '--help' || arg === '-h') {
      process.stdout.write(`${usage()}\n`)
      return
    } else throw new CapacityConfigError([`unknown argument ${arg}`])
  }

  let input = {}
  if (configPath) {
    const source = configPath === '-' ? await readStdin() : await readFile(resolve(configPath), 'utf8')
    input = JSON.parse(source)
  }
  const report = runCapacityLab(input)
  process.stdout.write(`${JSON.stringify(stripPrivate(report), null, pretty ? 2 : 0)}\n`)
  if (report.status !== 'pass') process.exitCode = 2
}

function stripPrivate (value) {
  if (Array.isArray(value)) return value.map(stripPrivate)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value)
      .filter(([key]) => !key.startsWith('_'))
      .map(([key, item]) => [key, stripPrivate(item)]))
  }
  return value
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv.slice(2)).catch(error => {
    const known = error instanceof CapacityConfigError
    const output = {
      schema: CAPACITY_LAB_SCHEMA,
      status: 'error',
      evidenceClass: 'modeled-not-benchmarked',
      error: {
        code: known ? error.code : 'CAPACITY_LAB_FAILED',
        message: error.message,
        violations: known ? error.violations : []
      }
    }
    process.stdout.write(`${JSON.stringify(output)}\n`)
    process.exitCode = 1
  })
}
