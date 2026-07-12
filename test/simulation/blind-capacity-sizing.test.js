import test from 'brittle'
import { createHash } from 'node:crypto'
import {
  CAPACITY_SIZING_PLAN_SCHEMA,
  CAPACITY_SIZING_SEARCH_SCHEMA,
  CapacitySizingError,
  buildReleaseCapacitySizingInput,
  runCapacitySizingPlan,
  verifyCapacitySizingPlan,
  verifyCapacitySizingPlanDigest
} from '../../scripts/plan-blind-capacity.mjs'
import { normalizeCapacityLabConfig } from '../../scripts/blind-capacity-lab.mjs'
import { stableStringify } from '../../scripts/simulate-blind-fleet.mjs'

const SOURCE_AUTHORITY = Object.freeze({
  kind: 'hiverelay-blind-fleet-simulation-evidence',
  schemaVersion: 3,
  scenarioSchema: 'hiverelay/blind-scenario-manifest/v1',
  scenarioDigest: '1'.repeat(64),
  sourceProfile: 'capacity-sizing-test',
  evidenceClass: 'deterministic-simulation-not-observed',
  authenticityProven: false
})

const BASELINE_SCALES = Object.freeze({
  storageBytes: 1,
  diskWrite: 1,
  diskRead: 1,
  diskIops: 1,
  walFsyncThroughput: 1,
  networkIngress: 1,
  networkEgress: 1,
  cpu: 1,
  streamBuffer: 1,
  streamSlots: 1,
  inboxWaiterMemory: 1,
  inboxWaiterSlots: 1
})

test('capacity sizing is deterministic, binds the exact workload, and exposes modeled target boundaries', t => {
  const input = sizingInput()
  const first = runCapacitySizingPlan(input)
  const second = runCapacitySizingPlan(input)

  t.alike(first, second)
  t.is(first.schema, CAPACITY_SIZING_PLAN_SCHEMA)
  t.is(first.reportDigest.length, 64)
  t.is(verifyCapacitySizingPlanDigest(first), true)
  t.is(first.evidenceClass, 'modeled-target-hardware-not-observed')
  t.is(first.releaseAuthority.productionHardwareObserved, false)
  t.is(first.releaseAuthority.authorizesRelease, false)
  t.is(first.releaseAuthority.changesBaselineReleaseGate, false)
  t.is(first.baselineReference.releaseGateStatus, 'unchanged-not-evaluated')
  t.ok(first.candidates.every(candidate => candidate.authorizesRelease === false))
  t.ok(first.candidates.every(candidate =>
    candidate.binding.workloadDigest === first.authority.workloadDigest &&
    candidate.binding.operationMixDigest === first.authority.operationMixDigest &&
    candidate.binding.durabilityDigest === first.authority.durabilityDigest))
  t.alike(first.authority.operationKinds, [
    'CELL:PUT',
    'CELL:GET',
    'INBOX:APPEND',
    'INBOX:READ',
    'INBOX:WATCH',
    'CORE:MIRROR',
    'CORE:PROVE',
    'CORE:OPEN_REPLICATION',
    'FORWARD:CIRCUIT'
  ])
})

test('sizing answers enumerate relay and per-relay hardware tradeoffs and bottleneck transitions', t => {
  const report = runCapacitySizingPlan(sizingInput())

  t.is(report.answers.modeledTargetFoundInSearch, true)
  t.is(report.answers.minimumEnumeratedHardwareByRelayCount.length, 2)
  t.is(report.answers.minimumEnumeratedRelayCountByHardwareProfile.length, 3)
  t.ok(report.answers.paretoFrontierCandidateIds.length > 0)
  t.ok(report.candidates.some(candidate => candidate.planningFit))
  t.ok(report.candidates.some(candidate => !candidate.planningFit))
  t.ok(report.bottleneckAnalysis.observedBottlenecks.length > 0)
  t.ok(report.bottleneckAnalysis.transitions.some(transition =>
    transition.changes.includes('modeled-fit-threshold')))
  const fit = report.candidates.find(candidate => candidate.planningFit)
  t.ok(fit.hardware.diskBytesPerRelay > 0)
  t.ok(fit.hardware.diskRandomIopsPerSecond > 0)
  t.ok(fit.hardware.walFsyncsPerSecond > 0)
  t.ok(fit.hardware.networkIngressBitsPerSecond > 0)
  t.ok(fit.hardware.cpuCoresPerRelay > 0)
  t.ok(fit.modeledContentCapacity.maximumModelCeiling.logicalPayloadBytes > 0)
  t.ok(fit.modeledContentCapacity.plannedFillCapacity.logicalPayloadBytes > 0)
  t.ok(fit.modeledContentCapacity.plannedFillCapacity.logicalPayloadBytes <
    fit.modeledContentCapacity.maximumModelCeiling.logicalPayloadBytes)
  t.is(fit.modeledContentCapacity.scope.startsWith('configured retained CELL mix only'), true)
  t.alike(
    report.answers.minimumEnumeratedHardwareByRelayCount.find(answer => answer.found).modeledContentCapacity,
    report.candidates.find(candidate =>
      candidate.id === report.answers.minimumEnumeratedHardwareByRelayCount.find(answer => answer.found).candidateId
    ).modeledContentCapacity
  )
  t.alike(
    report.answers.minimumEnumeratedRelayCountByHardwareProfile.find(answer => answer.found).modeledContentCapacity,
    report.candidates.find(candidate =>
      candidate.id === report.answers.minimumEnumeratedRelayCountByHardwareProfile.find(answer => answer.found).candidateId
    ).modeledContentCapacity
  )
  t.alike(report.answers.searchCeiling.modeledContentCapacity, report.candidates.at(-1).modeledContentCapacity)
})

test('owning verifier rejects a modified and self-resealed sizing report', t => {
  const input = sizingInput()
  const report = runCapacitySizingPlan(input)
  const altered = structuredClone(report)
  altered.candidates[0].modeledSustainableLogicalOpsPerSecond++
  const { reportDigest: ignored, ...body } = altered
  altered.reportDigest = createHash('sha256').update(stableStringify(body)).digest('hex')

  t.is(verifyCapacitySizingPlanDigest(altered), true)
  const verification = verifyCapacitySizingPlan(altered, input)
  t.is(verification.passed, false)
  t.ok(verification.blockers.includes('EXACT_DETERMINISTIC_PLAN'))
  t.is(verification.authorizesRelease, false)
})

test('search validation rejects unknown fields and capability-decreasing profiles', t => {
  const unknown = sizingInput()
  unknown.search.typoReleaseReady = true
  t.exception(() => runCapacitySizingPlan(unknown), CapacitySizingError)

  const decreasing = sizingInput()
  decreasing.search.hardwareProfiles[2].scales.storageBytes = 2
  t.exception(() => runCapacitySizingPlan(decreasing), CapacitySizingError)

  const sourceDrift = sizingInput()
  sourceDrift.capacityConfig.workload.offeredLogicalOpsPerSecond++
  t.exception(() => runCapacitySizingPlan(sourceDrift), CapacitySizingError)
})

test('release source binds the exact production operation mix without changing its red baseline', t => {
  const input = buildReleaseCapacitySizingInput('release', {
    schema: CAPACITY_SIZING_SEARCH_SCHEMA,
    relayCounts: [72],
    hardwareProfiles: [{
      id: 'source-envelope',
      label: 'Source model envelope',
      scales: BASELINE_SCALES
    }],
    minimumModeledLogicalObjects: 0,
    minimumModeledLogicalPayloadBytes: 0
  })
  const report = runCapacitySizingPlan(input)

  t.is(report.authority.offeredLogicalOpsPerSecond, 1340)
  t.alike(report.authority.operationKinds, [
    'CELL:PUT',
    'CELL:GET',
    'INBOX:APPEND',
    'INBOX:READ',
    'CORE:MIRROR',
    'CORE:PROVE',
    'CORE:OPEN_REPLICATION',
    'FORWARD:CIRCUIT'
  ])
  t.is(report.authority.source.scenarioSchema, 'hiverelay/blind-scenario-manifest/v1')
  t.is(report.baselineReference.capacityModelStatus, 'rejected')
  t.is(report.answers.modeledTargetFoundInSearch, false)
  t.is(report.releaseAuthority.changesBaselineReleaseGate, false)
  t.is(report.releaseAuthority.authorizesRelease, false)
})

function sizingInput () {
  const capacityConfig = normalizeCapacityLabConfig({
    seed: 'capacity-sizing-test-v1',
    simulation: {
      sampleObjects: 600,
      scaleRelayCounts: []
    },
    fleet: {
      relayCount: 3,
      diskBytesPerRelay: 512 * 1024 * 1024,
      unavailableRelays: 0
    },
    workload: {
      offeredLogicalOpsPerSecond: 300
    }
  })
  return {
    capacityConfig,
    sourceAuthority: {
      ...SOURCE_AUTHORITY,
      evidenceDigest: '2'.repeat(64),
      capacityConfigDigest: createHash('sha256').update(stableStringify(capacityConfig)).digest('hex')
    },
    search: {
      schema: CAPACITY_SIZING_SEARCH_SCHEMA,
      relayCounts: [3, 6],
      hardwareProfiles: [
        {
          id: 'source-envelope',
          label: 'Source envelope',
          scales: { ...BASELINE_SCALES }
        },
        {
          id: 'storage-64x',
          label: 'Storage 64x',
          scales: { ...BASELINE_SCALES, storageBytes: 64 }
        },
        {
          id: 'balanced-128x',
          label: 'Balanced 128x',
          scales: Object.fromEntries(Object.keys(BASELINE_SCALES).map(key => [key, 128]))
        }
      ],
      minimumModeledLogicalObjects: 0,
      minimumModeledLogicalPayloadBytes: 0
    }
  }
}
