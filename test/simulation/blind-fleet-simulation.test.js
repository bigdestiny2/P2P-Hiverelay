import test from 'brittle'
import {
  assertBlindFleetEvidence,
  runBlindFleetSimulation,
  stableStringify,
  verifyBlindFleetEvidenceDigest
} from '../../scripts/simulate-blind-fleet.mjs'

const QUICK_CONFIG = {
  seed: 'blind-fleet-test-v1',
  durationSeconds: 36,
  relayCount: 12,
  operatorCount: 6,
  regionCount: 3,
  churnEventsPerRelayHour: 0,
  rateScale: 0.45,
  repairScanPerTick: 800,
  invalidAdmissionProbeEvery: 31
}

test('blind fleet evidence is byte-deterministic, digest bound, and covers every generic family', t => {
  const first = runBlindFleetSimulation(QUICK_CONFIG)
  const second = runBlindFleetSimulation(QUICK_CONFIG)

  t.is(stableStringify(first), stableStringify(second))
  t.is(first.evidenceDigest, second.evidenceDigest)
  t.is(verifyBlindFleetEvidenceDigest(first), true)
  t.is(assertBlindFleetEvidence(first), first)
  t.is(first.ok, true)
  t.is(first.topology.independentFailureDomain, 'operatorId')
  t.is(first.topology.operatorCount, 6)

  for (const familyName of ['CELL', 'INBOX', 'CORE', 'FORWARD']) {
    const family = first.workload.families[familyName]
    t.ok(family.writes.generated > 0, `${familyName} writes were simulated`)
    t.ok(family.writes.committed > 0, `${familyName} commits were simulated`)
    t.ok(family.placement.operatorDiverse > 0, `${familyName} used independent operators`)
    if (familyName === 'FORWARD') t.ok(family.forward.dataFrames > 0, 'FORWARD data frames were streamed')
    else t.ok(family.reads.attempted > 0, `${familyName} reads were simulated`)
  }

  const altered = structuredClone(first)
  altered.capacity.finalUsedBytes++
  t.is(verifyBlindFleetEvidenceDigest(altered), false)
  t.exception(() => assertBlindFleetEvidence(altered), /digest does not verify/)
})

test('exact family semantics keep padded stores, leased MIRROR corpora, upstream children, and ephemeral paths separate', t => {
  const evidence = runBlindFleetSimulation({
    ...QUICK_CONFIG,
    families: { INBOX: { allocationLeaseClass: 2, retentionClass: 2 } }
  })
  const cell = evidence.workload.families.CELL
  const inbox = evidence.workload.families.INBOX
  const core = evidence.workload.families.CORE
  const forward = evidence.workload.families.FORWARD

  t.alike(evidence.semanticModel.CELL.sizeClasses, { 1: 4096, 2: 16384, 3: 65536, 4: 262144, 5: 1048576 })
  t.alike(evidence.semanticModel.INBOX.frameClasses, { 1: 4096, 2: 16384, 3: 65536 })
  t.ok(cell.writes.generatedPaddingBytes > 0)
  t.ok(cell.writes.initialPaddingBytes > cell.writes.generatedPaddingBytes)
  t.ok(Object.keys(cell.resourceClasses.committed).every(value => Number(value) >= 1 && Number(value) <= 5))
  t.ok(inbox.writes.generatedPaddingBytes > 0)
  t.ok(Object.keys(inbox.resourceClasses.committed).every(value => Number(value) >= 1 && Number(value) <= 3))
  t.ok(inbox.leaseExpiry.items > 0)
  t.is(inbox.inboxRetention.logicalInboxes, 16)
  t.ok(inbox.inboxRetention.inboxesRenewed > 0)
  t.is(core.coreReplication.mirror.persistentForLease, true)
  t.ok(core.coreReplication.mirror.logicalCores > 0)
  t.is(core.coreReplication.mirror.mirrorsCommitted, core.writes.committed)
  t.ok(core.coreReplication.openReplication.sessionsOpened > 0)
  t.ok(core.coreReplication.openReplication.bytesTransferred > 0)
  t.is(core.coreReplication.openReplication.durableApplicationBodyBytes, 0)
  t.is(core.leaseExpiry.items, 0)
  t.is(forward.durableStorage.enabled, false)
  t.is(forward.durableStorage.initialPhysicalBytes, 0)
  t.is(forward.repair.attempted, 0)
  t.ok(forward.forward.bytesForwarded > 0)
  t.ok(forward.forward.relayByteHops >= forward.forward.bytesForwarded * 2)
  t.is(forward.reads.attempted, 0)
  t.is(assertion(evidence, 'families.fixed-and-persistent-shapes-exact').pass, true)
  t.is(assertion(evidence, 'forward.no-durable-storage-or-repair').pass, true)
  t.is(assertion(evidence, 'forward.active-reservations-accounted').pass, true)
  t.is(assertion(evidence, 'core.open-replication-reservations-accounted').pass, true)
  t.is(assertion(evidence, 'core.open-replication-has-no-durable-application-body').pass, true)
  t.is(assertion(evidence, 'forward.window-credit-conserved').pass, true)
})

test('partitions, operator outage, crash, disk loss, repair, churn, and retention preserve invariants', t => {
  const evidence = runBlindFleetSimulation({
    ...QUICK_CONFIG,
    seed: 'blind-fleet-fault-test-v1',
    durationSeconds: 54,
    churnEventsPerRelayHour: 120,
    faults: [
      { id: 'partition', type: 'partition', atSeconds: 8, durationSeconds: 7, regionIds: ['region-0'] },
      { id: 'operator', type: 'operator-outage', atSeconds: 18, durationSeconds: 5, operatorId: 'operator-00' },
      { id: 'crash', type: 'relay-crash', atSeconds: 28, durationSeconds: 4, relayId: 'relay-001' },
      { id: 'disk', type: 'disk-loss', atSeconds: 38, durationSeconds: 4, relayId: 'relay-002' }
    ],
    families: {
      FORWARD: { circuitClass: 1, wireClass: 2, pathHops: 3 },
      INBOX: { allocationLeaseClass: 3, retentionClass: 1 }
    }
  })

  t.ok(evidence.faults.partitionMillis > 0)
  t.ok(evidence.faults.churnEvents > 0)
  t.is(evidence.faults.diskLossEvents, 1)
  t.ok(evidence.faults.diskLossCopies > 0)
  t.ok(evidence.reliability.repairs.succeeded > 0)
  t.ok(evidence.admissionAndRetention.expiredItems > 0)
  t.ok((evidence.workload.families.FORWARD.forward.terminalReasons.PATH_FAILURE || 0) > 0)
  t.is(assertion(evidence, 'storage.capacity-not-exceeded').pass, true)
  t.is(assertion(evidence, 'storage.accounting-exact').pass, true)
  t.is(assertion(evidence, 'retention.expired-copies-inaccessible').pass, true)
  t.is(assertion(evidence, 'repair.requires-reachable-source').pass, true)
  t.is(assertion(evidence, 'placement.prefers-unused-operator').pass, true)
})

test('saturation fails objectives honestly while capacity, accounting, and class admission fail closed', t => {
  const evidence = runBlindFleetSimulation({
    ...QUICK_CONFIG,
    seed: 'blind-fleet-saturation-test-v1',
    durationSeconds: 30,
    relayCount: 6,
    operatorCount: 3,
    regionCount: 2,
    relayCapacityBytes: 512 * 1024,
    relayBandwidthMbps: 1,
    relayMaxAdmissionsPerSecond: 20,
    rateScale: 5,
    faults: false
  })

  const rejected = evidence.admissionAndRetention.rejections
  t.ok((rejected.WRITE_BANDWIDTH || 0) > 0)
  t.ok((rejected.STORAGE_CAPACITY || 0) > 0)
  t.ok(evidence.workload.commitRate < 1)
  t.is(evidence.ok, false)
  t.is(assertion(evidence, 'storage.capacity-not-exceeded').pass, true)
  t.is(assertion(evidence, 'storage.accounting-exact').pass, true)
  t.is(assertion(evidence, 'admission.invalid-resource-class-fails-closed').pass, true)
  t.is(assertion(evidence, 'admission.attempts-accounted').pass, true)
  t.exception(() => assertBlindFleetEvidence(evidence), /simulation failed/)
})

test('every scheduled read has a per-family outcome even when no eligible object exists', t => {
  const evidence = runBlindFleetSimulation({
    ...QUICK_CONFIG,
    durationSeconds: 10,
    faults: false,
    families: { CELL: { writesPerSecond: 0, readsPerSecond: 10 } }
  })
  const reads = evidence.workload.families.CELL.reads

  t.ok(reads.scheduled > 0)
  t.is(reads.attempted, reads.scheduled)
  t.is(reads.succeeded, 0)
  t.is(reads.failed, reads.scheduled)
  t.is(reads.failureReasons.NO_ELIGIBLE_ITEM, reads.scheduled)
  t.is(assertion(evidence, 'reads.scheduled-outcomes-accounted').pass, true)
})

test('accepted demand cannot disappear at tick boundaries and a growing resource backlog fails closed', t => {
  const evidence = runBlindFleetSimulation({
    ...QUICK_CONFIG,
    seed: 'blind-fleet-resource-overload-v1',
    durationSeconds: 12,
    rateScale: 3,
    faults: false,
    relayDiskIopsPerSecond: 0.1,
    relayFsyncsPerSecond: 0.1,
    maxResourceBacklogSeconds: 1,
    maxGrowingBacklogTicks: 3
  })

  t.ok(evidence.resourceQueues.byResource.diskIops.finalBacklog > 0)
  t.ok(evidence.resourceQueues.byResource.fsyncs.finalBacklog > 0)
  t.ok(evidence.resourceQueues.maximumGrowthStreak >= 3)
  t.is(assertion(evidence, 'resources.no-growing-backlog').pass, false)
  t.is(assertion(evidence, 'resources.backlog-within-bound').pass, false)
  t.is(evidence.ok, false)
})

test('target replica recovery is an explicit sampled and final release gate', t => {
  const recovered = runBlindFleetSimulation({
    ...QUICK_CONFIG,
    seed: 'blind-fleet-target-recovery-v1',
    durationSeconds: 30,
    faults: [{ id: 'disk', type: 'disk-loss', atSeconds: 12, durationSeconds: 2, relayId: 'relay-001' }]
  })
  t.ok(recovered.reliability.targetReplicaRecovery.degradationEvents > 0)
  t.is(assertion(recovered, 'reliability.target-replica-rate').pass, true)
  t.is(assertion(recovered, 'reliability.final-target-replica-rate').pass, true)
  t.is(assertion(recovered, 'reliability.target-replica-recovery-rate').pass, true)

  const lateLoss = runBlindFleetSimulation({
    ...QUICK_CONFIG,
    seed: 'late',
    durationSeconds: 30,
    repairScanPerTick: 1,
    faults: [{ id: 'late-disk', type: 'disk-loss', atSeconds: 28, durationSeconds: 1, relayId: 'relay-001' }]
  })
  t.is(assertion(lateLoss, 'reliability.target-replica-rate').pass, true)
  t.is(assertion(lateLoss, 'reliability.final-target-replica-rate').pass, false)
  t.is(assertion(lateLoss, 'reliability.target-replica-recovery-rate').pass, false)
  t.is(lateLoss.ok, false)
})

test('FORWARD reports completion against every opened circuit and conserves explicit WINDOW credit', t => {
  const evidence = runBlindFleetSimulation(QUICK_CONFIG)
  const forward = evidence.workload.families.FORWARD.forward

  t.ok(forward.circuitsActiveFinal > 0)
  t.ok(forward.completionAmongOpened < forward.completionAmongTerminal)
  t.is(forward.terminalCoverageAmongOpened,
    Math.round(forward.circuitsTerminal / forward.circuitsOpened * 1_000_000) / 1_000_000)
  t.ok(forward.window.updates > 0)
  t.ok(forward.window.bytesConsumed <= forward.window.bytesGranted)
  t.ok(forward.window.maximumOutstandingBytes <= evidence.semanticModel.FORWARD.maximumOutstandingWindowBytes)
  t.is(assertion(evidence, 'forward.completion-among-opened').pass, true)
})

test('scenario manifest binds realized relay resources and explicit family load', t => {
  const evidence = runBlindFleetSimulation(QUICK_CONFIG)
  t.is(evidence.scenarioManifest.schema, 'hiverelay/blind-scenario-manifest/v1')
  t.is(evidence.scenarioManifest.relayCount, 12)
  t.is(evidence.scenarioManifest.relays.length, 12)
  t.is(evidence.scenarioManifest.durabilityByFamily.CELL.replicas, 3)
  t.is(evidence.scenarioManifest.offeredLoad.families.CORE.openReplicationsPerSecond, 0.225)
  t.is(typeof evidence.scenarioDigest, 'string')
  t.is(evidence.scenarioDigest.length, 64)
})

test('changing seed or operator count changes evidence and placement remains operator-aware', t => {
  const baseline = runBlindFleetSimulation(QUICK_CONFIG)
  const otherSeed = runBlindFleetSimulation({ ...QUICK_CONFIG, seed: 'blind-fleet-test-v2' })
  const fewerOperators = runBlindFleetSimulation({ ...QUICK_CONFIG, operatorCount: 3 })

  t.not(baseline.evidenceDigest, otherSeed.evidenceDigest)
  t.not(baseline.evidenceDigest, fewerOperators.evidenceDigest)
  t.is(baseline.reliability.placement.selectionViolations, 0)
  t.is(fewerOperators.reliability.placement.selectionViolations, 0)
  t.is(fewerOperators.topology.operatorCount, 3)
  t.is(fewerOperators.parameters.families.CELL.replicas, 3)
  t.exception(() => runBlindFleetSimulation({ families: { FORWARD: { circuitClass: 4 } } }), /not registered/)
})

function assertion (evidence, id) {
  return evidence.assertions.find(assertion => assertion.id === id)
}
