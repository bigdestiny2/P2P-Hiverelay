import test from 'brittle'
import b4a from 'b4a'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { encodeCanonical } from '../../packages/blind-protocol/codec.js'
import { blake2b256, cellStorageSlot } from '../../packages/blind-protocol/hashes.js'
import { getCellV1, putCellV1 } from '../../packages/blind-protocol/schemas.js'
import {
  CAPACITY_LAB_MODEL_REVISION,
  CAPACITY_LAB_SCHEMA,
  CapacityConfigError,
  runCapacityLab
} from '../../scripts/blind-capacity-lab.mjs'

const SCRIPT = fileURLToPath(new URL('../../scripts/blind-capacity-lab.mjs', import.meta.url))

test('blind capacity lab is deterministic and labels every performance value as modeled', t => {
  const config = compactConfig()
  const first = runCapacityLab(config)
  const second = runCapacityLab(config)

  t.alike(first, second)
  t.is(first.schema, CAPACITY_LAB_SCHEMA)
  t.is(first.modelProvenance.revision, CAPACITY_LAB_MODEL_REVISION)
  t.is(first.status, 'pass')
  t.is(first.evidenceClass, 'modeled-not-benchmarked')
  t.ok(first.disclaimer.includes('not a hardware benchmark'))
  t.ok(first.assumptions.some(value => value.includes('Modeled p50/p99')))
  t.is(first.latency.status, 'modeled-steady-state')
  t.is(first.latency.byOperation.length, 9)
  t.alike([...new Set(first.operationModel.operations.map(operation => operation.family))], ['CELL', 'INBOX', 'CORE', 'FORWARD'])
  t.ok(first.throughput.modeledSustainableLogicalOpsPerSecond > 0)
  t.ok(first.storage.modeledLogicalPayloadCapacityBytes > 0)
  t.absent(first.storage._plannedRelayObjectBytes)
  t.absent(first.background._relays)
  t.absent(first.throughput._resourceByName)
})

test('blind capacity lab exposes storage overhead and relay scaling', t => {
  const report = runCapacityLab(compactConfig({
    simulation: { scaleRelayCounts: [3, 6, 12] },
    fleet: { relayCount: 6, unavailableRelays: 1 }
  }))
  const points = report.scaling.points

  t.alike(points.map(point => point.relayCount), [3, 6, 12])
  t.ok(points[1].modeledLogicalPayloadCapacityBytes > points[0].modeledLogicalPayloadCapacityBytes)
  t.ok(points[2].modeledLogicalPayloadCapacityBytes > points[1].modeledLogicalPayloadCapacityBytes)
  t.ok(points[1].modeledSustainableLogicalOpsPerSecond > points[0].modeledSustainableLogicalOpsPerSecond)
  t.ok(report.storage.modeledPhysicalToLogicalRatio >= 3)
  t.ok(report.placement.maximumByteSkewOverMean >= 1)
})

test('replication durability cost reduces modeled content capacity', t => {
  const base = compactConfig({
    simulation: { scaleRelayCounts: [] },
    fleet: { relayCount: 6, unavailableRelays: 0 }
  })
  const single = runCapacityLab({
    ...base,
    fleet: { ...base.fleet, replicationFactor: 1 },
    workload: { ...base.workload, writeAcks: 1 }
  })
  const triple = runCapacityLab({
    ...base,
    fleet: { ...base.fleet, replicationFactor: 3 },
    workload: { ...base.workload, writeAcks: 2 }
  })

  t.ok(single.storage.modeledLogicalPayloadCapacityBytes > triple.storage.modeledLogicalPayloadCapacityBytes * 2)
  t.ok(single.objectModel.analyticPhysicalToLogicalRatio < triple.objectModel.analyticPhysicalToLogicalRatio)
})

test('invalid and structurally impossible capacity configurations are rejected', t => {
  const invalid = [
    compactConfig({ fleet: { relayCount: 2, replicationFactor: 3, unavailableRelays: 0 } }),
    compactConfig({ objects: { mix: [{ name: 'bad', weight: 0, payloadBytes: 1 }] } }),
    compactConfig({ workload: { writeFraction: 0.8, readFraction: 0.8 } }),
    compactConfig({ fleet: { diskBytesByRelay: [1024] } }),
    compactConfig({ wal: { fsincLatencyMs: 3 } }),
    null
  ]

  for (const config of invalid) {
    let error = null
    try {
      runCapacityLab(config)
    } catch (caught) {
      error = caught
    }
    t.ok(error instanceof CapacityConfigError)
    t.ok(error.violations.length > 0)
  }
})

test('CELL storage uses exact frozen classes and application framing stays inside cellBlob', t => {
  const report = runCapacityLab(compactConfig())
  const medium = report.objectModel.mix.find(item => item.name === 'medium-cell')
  const maximum = report.objectModel.mix.find(item => item.name === 'max-cell-structured-content')

  t.alike(report.objectModel.exactCellSizeClasses, {
    1: 4096,
    2: 16384,
    3: 65536,
    4: 262144,
    5: 1048576
  })
  t.is(medium.opaqueCellBytes, 65536)
  t.is(medium.payloadBytes, 65536 - 33)
  t.is(medium.opaquePaddingBytes, 0)
  t.is(maximum.opaqueCellBytes, 1048576)
  t.is(maximum.payloadBytes, 1048576 - 33)
  t.is(maximum.opaquePaddingBytes, 0)
})

test('CELL network accounting applies exact v1 symmetric outer-envelope cliffs', t => {
  const report = runCapacityLab(compactConfig())
  const put = report.operationModel.operations.find(operation => operation.name === 'cell-put')
  const get = report.operationModel.operations.find(operation => operation.name === 'cell-get')

  t.alike(report.operationModel.exactWireLimits.outerClasses, {
    1: 4096,
    2: 16384,
    3: 65536,
    4: 262144,
    5: 1048576,
    6: 8388608
  })
  t.alike(report.operationModel.exactWireLimits.cellBodyBounds, {
    maximumAdmissionBytes: 4135,
    maximumPutFixedBytes: 263,
    maximumPutOverheadBytes: 4398,
    maximumGetRequestBytes: 4201,
    getResultOverheadBytes: 2
  })
  t.is(put.wireAccounting, 'exact-minimum-v1-symmetric-outer-envelope')
  t.is(put.meanOuterClassBytesPerDirection, 530841.6)
  t.is(put.meanOuterRoundTripBytesPerTouch, 1061683.2)
  t.is(put.networkIngressBytesPerTouch, put.meanOuterClassBytesPerDirection)
  t.is(put.networkEgressBytesPerTouch, put.meanOuterClassBytesPerDirection)
  t.is(put.meanOuterIngressBytesPerLogicalOperation, 1592524.8)
  t.is(put.meanOuterEgressBytesPerLogicalOperation, 1592524.8)
  t.is(put.meanOuterRoundTripBytesPerLogicalOperation, 3185049.6)
  t.is(put.usefulByteAmplificationPerLogicalOperation, 45.347499)
  t.is(get.meanOuterClassBytesPerDirection, 496435.2)
  t.is(get.meanOuterRoundTripBytesPerTouch, 992870.4)
  t.is(get.networkIngressBytesPerTouch, get.meanOuterClassBytesPerDirection)
  t.is(get.networkEgressBytesPerTouch, get.meanOuterClassBytesPerDirection)
  t.is(get.meanOuterRoundTripBytesPerLogicalOperation, get.meanOuterRoundTripBytesPerTouch)
  t.is(get.usefulByteAmplificationPerLogicalOperation, get.usefulByteAmplificationPerTouch)
  t.ok(put.usefulByteAmplificationPerTouch > 14)
  t.ok(get.usefulByteAmplificationPerTouch > 13)
})

test('CELL wire accounting matches canonical maximum bodies at every frozen class cliff', t => {
  const rows = [
    { sizeClass: 1, cellBytes: 4096, putOuterBytes: 65536, getOuterBytes: 16384 },
    { sizeClass: 2, cellBytes: 16384, putOuterBytes: 65536, getOuterBytes: 65536 },
    { sizeClass: 3, cellBytes: 65536, putOuterBytes: 262144, getOuterBytes: 262144 },
    { sizeClass: 4, cellBytes: 262144, putOuterBytes: 1048576, getOuterBytes: 1048576 },
    { sizeClass: 5, cellBytes: 1048576, putOuterBytes: 8388608, getOuterBytes: 8388608 }
  ]
  const admission = maximumAdmission()

  t.is(encodeCanonical(getCellV1, {
    version: 1,
    storageSlot: b4a.alloc(32),
    clientNonce: b4a.alloc(32),
    admission: null
  }).byteLength, 66)
  t.is(encodeCanonical(getCellV1, {
    version: 1,
    storageSlot: b4a.alloc(32),
    clientNonce: b4a.alloc(32),
    admission
  }).byteLength, 4201)

  for (const row of rows) {
    const cellBlob = b4a.alloc(row.cellBytes)
    const createPublicKey = b4a.alloc(32)
    const putBody = encodeCanonical(putCellV1, {
      version: 1,
      storageSlot: cellStorageSlot({ allocationEpoch: 0, createPublicKey }),
      allocationEpoch: 0,
      sizeClass: row.sizeClass,
      leaseClass: 1,
      clientNonce: b4a.alloc(32),
      createPublicKey,
      renewPublicKey: b4a.alloc(32),
      dropPublicKey: b4a.alloc(32),
      declaredBlobHash: blake2b256(cellBlob),
      createSignature: b4a.alloc(64),
      admission,
      cellBlob
    })
    const report = runCapacityLab(compactConfig({
      objects: {
        mix: [{
          name: `cell-class-${row.sizeClass}`,
          family: 'CELL',
          sizeClass: row.sizeClass,
          weight: 1,
          payloadBytes: row.cellBytes - 33
        }]
      }
    }))
    const put = report.operationModel.operations.find(operation => operation.name === 'cell-put')
    const get = report.operationModel.operations.find(operation => operation.name === 'cell-get')

    t.is(putBody.byteLength, row.cellBytes + 4398, `class ${row.sizeClass} PUT canonical maximum`)
    t.is(put.meanOuterClassBytesPerDirection, row.putOuterBytes, `class ${row.sizeClass} PUT outer class`)
    t.is(get.meanOuterClassBytesPerDirection, row.getOuterBytes, `class ${row.sizeClass} GET outer class`)
  }

  const classOne = runCapacityLab(compactConfig({
    objects: {
      mix: [{ name: 'cell-class-1', family: 'CELL', sizeClass: 1, weight: 1, payloadBytes: 4096 - 33 }]
    }
  })).operationModel.operations.find(operation => operation.name === 'cell-put')
  t.is(classOne.meanOuterRoundTripBytesPerLogicalOperation, 384 * 1024)
  t.is(classOne.usefulByteAmplificationPerLogicalOperation, 96.779719)
})

test('family surfaces distinguish retained frames/corpora from transient streams', t => {
  const report = runCapacityLab(compactConfig())
  const forward = report.operationModel.operations.find(operation => operation.family === 'FORWARD')
  const coreStream = report.operationModel.operations.find(operation => operation.operation === 'OPEN_REPLICATION')

  t.is(report.familySurfaces.INBOX.exactFrameClasses[3], 65536)
  t.is(report.familySurfaces.CORE.exactSessionClasses[3].maxSessionBytes, 256 * 1024 * 1024)
  t.is(report.familySurfaces.CORE.proveOpaqueProofsAndBlocksMaximumBytes, 4 * 1024 * 1024 - 256)
  t.is(report.familySurfaces.FORWARD.retainedApplicationBodyCapacityBytes, 0)
  t.is(report.familySurfaces.FORWARD.maximumDispatchDataBytes, 65535)
  t.ok(forward.networkIngressBytesPerTouch > forward.meanCircuitBytes)
  t.is(forward.concurrencyKind, 'STREAM')
  t.is(coreStream.concurrencyKind, 'STREAM')
  t.ok(report.throughput.resources.some(resource => resource.resource === 'inboxWaiterSlots'))
  t.ok(report.throughput.familyCeilings.every(family => family.modeledStandaloneLogicalOpsPerSecond > 0))
  t.is(report.familySurfaces.sharedLiveStreamPlane.configuredMaxBufferedBytesPerRelay, 64 * 1024 * 1024)
  t.is(report.familySurfaces.sharedLiveStreamPlane.configuredMaxConcurrentStreamsPerRelay, 1024)
  t.is(report.familySurfaces.CORE.configuredMaximumCorpusBytes, 4 * 1024 * 1024)
})

test('family-specific impossible wire and stream costs fail closed', t => {
  const mib = 1024 * 1024
  const invalid = [
    compactConfig({
      objects: {
        mix: [{ name: 'too-large', family: 'CELL', sizeClass: 5, weight: 1, payloadBytes: mib - 32 }]
      }
    }),
    compactConfig({
      workload: {
        operations: [{ name: 'oversize-inbox-result', family: 'INBOX', operation: 'READ', weight: 1, frameClass: 3, batchFrames: 64, walPayloadBytesPerRecord: 1024 }]
      }
    }),
    compactConfig({
      workload: {
        operations: [{ name: 'oversize-core-session', family: 'CORE', operation: 'OPEN_REPLICATION', weight: 1, sessionClass: 1, ingressBytes: 16 * mib, egressBytes: 1, meanDurationSeconds: 1, meanBufferedBytes: 4096, walPayloadBytesPerRecord: 1024 }]
      }
    }),
    compactConfig({
      workload: {
        operations: [{ name: 'oversize-forward', family: 'FORWARD', operation: 'CIRCUIT', weight: 1, circuitClass: 1, wireClass: 3, meanCircuitBytes: 16 * mib + 1, meanDataFrameBytes: 4096, hopCount: 1, meanDurationSeconds: 1, meanBufferedBytes: 4096, walPayloadBytesPerRecord: 1024 }]
      }
    }),
    compactConfig({
      workload: {
        operations: [{ name: 'oversize-core-corpus', family: 'CORE', operation: 'MIRROR', weight: 1, corpusBytes: 4 * mib + 1, transferFraction: 1, walPayloadBytesPerRecord: 1024 }]
      }
    }),
    compactConfig({
      workload: {
        operations: [{ name: 'oversize-forward-frame', family: 'FORWARD', operation: 'CIRCUIT', weight: 1, circuitClass: 1, wireClass: 3, meanCircuitBytes: mib, meanDataFrameBytes: 65536, hopCount: 1, meanDurationSeconds: 1, meanBufferedBytes: 4096, walPayloadBytesPerRecord: 1024 }]
      }
    })
  ]

  for (const config of invalid) {
    let error = null
    try {
      runCapacityLab(config)
    } catch (caught) {
      error = caught
    }
    t.ok(error instanceof CapacityConfigError)
    t.ok(error.violations.length > 0)
  }
})

test('background work that consumes the safe envelope rejects finite latency claims', t => {
  const report = runCapacityLab(compactConfig({
    checkpoint: { intervalSeconds: 0.001 }
  }))

  t.is(report.status, 'rejected')
  t.ok(report.rejectionReasons.some(reason => reason.code === 'NO_SUSTAINABLE_FOREGROUND_CAPACITY'))
  t.is(report.latency.status, 'undefined-without-sustainable-capacity')
  t.absent(report.latency.write)
})

test('an offered load above the modeled envelope has no reported steady-state latency', t => {
  const report = runCapacityLab(compactConfig({
    workload: { offeredLogicalOpsPerSecond: 1_000_000_000 }
  }))

  t.is(report.status, 'rejected')
  t.ok(report.rejectionReasons.some(reason => reason.code === 'OFFERED_LOAD_EXCEEDS_SUSTAINABLE_MODEL'))
  t.is(report.latency.status, 'undefined-under-overload')
  t.absent(report.latency.write)
})

test('WAL durable-sync costs can be isolated as the throughput bottleneck', t => {
  const report = runCapacityLab(compactConfig({
    workload: {
      operations: [{
        name: 'cell-put-only',
        family: 'CELL',
        operation: 'PUT',
        weight: 1,
        storageClass: 'weighted-cell-mix',
        walPayloadBytesPerRecord: 1024
      }],
      writeAcks: 2
    },
    disk: {
      sequentialWriteBytesPerSecond: 100 * 1024 * 1024 * 1024,
      sequentialReadBytesPerSecond: 100 * 1024 * 1024 * 1024,
      randomIopsPerSecond: 10_000_000
    },
    wal: {
      effectiveGroupCommitRecords: 1,
      fsyncLatencyMs: 100
    },
    network: {
      ingressBitsPerSecond: 100_000_000_000,
      egressBitsPerSecond: 100_000_000_000
    },
    cpu: { coresPerRelay: 1024 }
  }))

  t.is(report.throughput.bottleneck, 'walFsyncCommitsPerSecond')
  t.is(report.optimizationCandidates[0].id, 'wal-group-commit-and-fsync')
})

test('failure simulation agrees with uniform-placement probability within sampling error', t => {
  const report = runCapacityLab(compactConfig({
    fleet: { relayCount: 8, unavailableRelays: 3, replicationFactor: 3 },
    workload: { writeAcks: 2 }
  }))
  const existing = report.failureScenario.existingReplicaSets

  t.ok(Math.abs(existing.simulatedReadableFraction - existing.analyticReadableProbability) < 0.02)
  t.ok(Math.abs(existing.simulatedWriteQuorumFraction - existing.analyticWriteQuorumProbability) < 0.02)
  t.is(report.failureScenario.guaranteedArbitraryRelayFailureTolerance.retainAtLeastOneReplica, 2)
  t.is(report.failureScenario.guaranteedArbitraryRelayFailureTolerance.retainWriteQuorum, 1)
})

test('heterogeneous disk fleets use the smallest relay budget and require separate scale configs', t => {
  const gib = 1024 * 1024 * 1024
  const report = runCapacityLab(compactConfig({
    fleet: {
      relayCount: 3,
      unavailableRelays: 0,
      diskBytesByRelay: [32 * gib, 64 * gib, 64 * gib]
    }
  }))

  t.is(report.scaling.status, 'not-run-for-heterogeneous-disk-list')
  t.is(report.scaling.points.length, 0)
  t.ok(report.storage.rawFleetDiskBytes === 160 * gib)
  t.ok(report.storage.modeledLogicalPayloadCapacityBytes > 0)
  for (const projection of report.familySurfaces.INBOX.dedicatedCapacityByFrameClass) {
    t.is(projection.limitingRelayIndex, 0)
  }
  for (const projection of report.familySurfaces.CORE.dedicatedCapacityByCorpusSize) {
    t.is(projection.limitingRelayIndex, 0)
  }
})

test('release evidence requires explicit offered load, complete family coverage, and passing SLOs', t => {
  const implicit = runCapacityLab(compactConfig({
    workload: { offeredLogicalOpsPerSecond: null }
  }))
  t.is(implicit.status, 'rejected')
  t.ok(implicit.rejectionReasons.some(reason => reason.code === 'EXPLICIT_OFFERED_LOAD_REQUIRED'))

  const partial = runCapacityLab(compactConfig({
    workload: {
      operations: [{
        name: 'cell-get-only',
        family: 'CELL',
        operation: 'GET',
        weight: 1,
        storageClass: 'weighted-cell-mix'
      }]
    }
  }))
  t.is(partial.status, 'rejected')
  t.is(partial.workloadCoverage.passed, false)
  t.ok(partial.rejectionReasons.some(reason => reason.code === 'WORKLOAD_COVERAGE_INCOMPLETE'))

  const impossibleTail = runCapacityLab(compactConfig({
    objectives: { maximumModeledUnaryP99Millis: 1 }
  }))
  t.is(impossibleTail.status, 'rejected')
  t.ok(impossibleTail.rejectionReasons.some(reason => reason.code === 'SERVICE_OBJECTIVE_NOT_MET'))
  t.is(impossibleTail.serviceObjectives.passed, false)
})

test('scenario manifest binds explicit workload, quorum, and heterogeneous capacity assumptions', t => {
  const report = runCapacityLab(compactConfig())
  t.is(report.scenarioManifest.schema, 'hiverelay/blind-scenario-manifest/v1')
  t.is(report.scenarioManifest.model.revision, CAPACITY_LAB_MODEL_REVISION)
  t.is(report.scenarioManifest.model.cellWireAccounting, 'exact-minimum-v1-symmetric-outer-envelope')
  t.is(report.scenarioManifest.model.wireAuthority.profile, 'wire-authority-v1')
  t.is(report.scenarioManifest.model.wireAuthority.specHash, 'c9ddd235c3963461174e3de13c25a4c995b53ff320be822d8304f870766b6592')
  t.is(report.scenarioManifest.model.wireAuthority.abiHash, '199ba15d94d4d112cfac520a67055ce15ec870f0f6f7bd9adaaf47d552334567')
  t.is(report.scenarioManifest.model.wireAuthority.vectorSetHash, 'fa54012cd0d7e4e620878c67e61f435ecb31ddec05a6283917987cc84279ee05')
  t.alike(report.modelProvenance, report.scenarioManifest.model)
  t.is(report.scenarioManifest.offeredLoad.logicalOperationsPerSecond, 40)
  t.is(report.scenarioManifest.offeredLoad.source, 'explicit-config')
  t.is(report.scenarioManifest.durability.replicationFactor, 3)
  t.is(report.scenarioManifest.durability.writeAcks, 2)
  t.is(report.scenarioManifest.storageBytesByRelay.length, 3)
  t.is(typeof report.scenarioDigest, 'string')
  t.is(report.scenarioDigest.length, 64)
})

test('CLI emits one machine-readable JSON document and nonzero status for overload', t => {
  const pass = spawnSync(process.execPath, [SCRIPT, '--compact'], { encoding: 'utf8' })
  t.is(pass.status, 0)
  t.is(JSON.parse(pass.stdout).schema, CAPACITY_LAB_SCHEMA)
  t.is(pass.stderr, '')

  const overloaded = spawnSync(process.execPath, [SCRIPT, '--config', '-', '--compact'], {
    encoding: 'utf8',
    input: JSON.stringify(compactConfig({ workload: { offeredLogicalOpsPerSecond: 1_000_000_000 } }))
  })
  const report = JSON.parse(overloaded.stdout)
  t.is(overloaded.status, 2)
  t.is(report.status, 'rejected')
  t.is(report.latency.status, 'undefined-under-overload')
  t.is(overloaded.stderr, '')
})

function compactConfig (override = {}) {
  return merge({
    seed: 'capacity-lab-test-v1',
    simulation: {
      sampleObjects: 2400,
      scaleRelayCounts: []
    },
    fleet: {
      relayCount: 3,
      diskBytesPerRelay: 32 * 1024 * 1024 * 1024,
      unavailableRelays: 0
    }
  }, override)
}

function maximumAdmission () {
  return {
    profileId: 1,
    schemeId: 1,
    parameterHash: b4a.alloc(32),
    token: b4a.alloc(4096)
  }
}

function merge (left, right) {
  const output = { ...left }
  for (const [key, value] of Object.entries(right)) {
    if (plain(left[key]) && plain(value)) output[key] = merge(left[key], value)
    else output[key] = value
  }
  return output
}

function plain (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}
