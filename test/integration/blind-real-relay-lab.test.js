import test from 'brittle'
import { runRealBlindRelayLab } from '../../scripts/run-real-blind-relay-lab.mjs'
import {
  REAL_BLIND_RELAY_FAMILY_SCOPE,
  REAL_BLIND_RELAY_LOCAL_PERFORMANCE_THRESHOLDS,
  REAL_BLIND_RELAY_MANDATORY_BLOCKERS,
  REAL_BLIND_RELAY_RUNTIME_EXCLUSIONS,
  sealRealBlindRelayReport,
  verifyRealBlindRelayReport
} from '../../scripts/verify-real-blind-relay-report.mjs'

function resealMutation (report, mutate) {
  const body = JSON.parse(JSON.stringify(report))
  delete body.evidenceDigest
  mutate(body)
  return sealRealBlindRelayReport(body)
}

test('real local relay lab executes two isolated store copies and proves retained reads after restart', async t => {
  const report = await runRealBlindRelayLab({
    relayCount: 2,
    recordsPerRelay: 2,
    concurrency: 2,
    contentBytes: 96
  })

  t.is(report.evidenceClass, 'MEASURED_LOCAL_REAL_HTTP_IPC_FILESYSTEM')
  t.is(report.releaseReady, false)
  t.is(report.correctnessGateReady, true)
  t.is(report.performanceGateReady, false)
  t.is(report.localGateReady, false)
  t.is(report.gates.performance.checks.sufficientOperationSample, false)
  t.is(report.scope.relayInstances, 2)
  t.is(report.scope.independentStoreRoots, 2)
  t.is(report.scope.realImplementationsOnly, false)
  t.is(report.scope.syntheticAdmissionAdapter, true)
  t.is(report.scope.economicSettlementMeasured, false)
  t.is(report.scope.networkReplicaProtocolMeasured, false)
  t.is(report.scope.processIsolation, false)
  t.is(report.load.attemptedCellWrites, 4)
  t.is(report.load.independentCellCopiesPerLogicalRecord, 2)
  t.is(report.load.replicaProtocolMeasured, false)
  t.is(report.families.DESCRIBE.measured, true)
  t.is(report.families.CELL.measured, true)
  t.is(report.families.CELL.publicHttpPutMeasured, false)
  t.is(report.families.INBOX.measured, false)
  t.is(report.families.CORE.measured, false)
  t.is(report.families.FORWARD.measured, false)
  t.is(report.metrics.stagedCellPut.count, 4)
  t.is(report.metrics.publicCellGet.count, 4)
  t.is(report.metrics.recoveredPublicCellGet.count, 4)
  t.is(report.integrity.contentChecksBeforeRestart, 4)
  t.is(report.integrity.contentChecksAfterRestart, 4)
  t.is(report.integrity.allCountsExact, true)
  t.is(report.integrity.uniqueRelaySigningKeys, 2)
  t.is(report.integrity.uniqueStoreIds, 2)
  t.is(report.integrity.independentlyAllocatedLogicalRecords, 2)
  t.is(report.integrity.allCopiesIndependentlyAllocatedAndEncrypted, true)
  t.is(report.recovery.relaysStopped, 2)
  t.is(report.recovery.relaysRestarted, 2)
  t.is(report.recovery.diskBytesStableAcrossRestart, true)
  t.is(report.runtimeErrors.length, 0)
  t.ok(report.blockers.includes('SYNTHETIC_ADMISSION_NO_ECONOMIC_SETTLEMENT'))
  t.ok(report.blockers.includes('INDEPENDENT_CELL_COPIES_NOT_REPLICA_PROTOCOL'))
  t.ok(report.blockers.includes('PUBLIC_EDGE_STAGED_CELL_PUT_BRIDGE_UNASSEMBLED'))
  t.ok(report.blockers.includes('LOCAL_PERFORMANCE_SMOKE_GATE_NOT_MET'))
  t.is(typeof report.evidenceDigest, 'string')
  t.is(report.evidenceDigest.length, 64)

  const verification = verifyRealBlindRelayReport(report, { requireCorrectness: true })
  t.is(verification.verified, true)
  t.is(verification.checksumVerified, true)
  t.is(verification.checksumOnly, true)
  t.is(verification.authenticityProven, false)
  t.is(verification.authorizesRelease, false)
  t.is(verification.correctnessReady, true)
  t.is(verification.performanceReady, false)
  t.ok(Object.isFrozen(REAL_BLIND_RELAY_LOCAL_PERFORMANCE_THRESHOLDS))
  t.ok(Object.isFrozen(REAL_BLIND_RELAY_FAMILY_SCOPE))
  t.ok(Object.isFrozen(REAL_BLIND_RELAY_FAMILY_SCOPE.CELL))
  t.ok(Object.isFrozen(REAL_BLIND_RELAY_RUNTIME_EXCLUSIONS))
  t.ok(Object.isFrozen(REAL_BLIND_RELAY_MANDATORY_BLOCKERS))

  const reordered = Object.fromEntries(Object.entries(JSON.parse(JSON.stringify(report))).reverse())
  t.is(verifyRealBlindRelayReport(reordered).checksumVerified, true)
  const tampered = JSON.parse(JSON.stringify(report))
  tampered.metrics.stagedCellPut.count++
  t.exception(() => verifyRealBlindRelayReport(tampered), /checksum mismatch/)
  const misleadingBody = JSON.parse(JSON.stringify(report))
  delete misleadingBody.evidenceDigest
  misleadingBody.scope.syntheticAdmissionAdapter = false
  const misleading = sealRealBlindRelayReport(misleadingBody)
  t.exception(() => verifyRealBlindRelayReport(misleading), /scope\.syntheticAdmissionAdapter/)

  const inboxBroadened = resealMutation(report, body => { body.families.INBOX.measured = true })
  t.exception(() => verifyRealBlindRelayReport(inboxBroadened), /families\.INBOX\.measured/)
  const clearedBlockers = resealMutation(report, body => { body.blockers = [] })
  t.exception(() => verifyRealBlindRelayReport(clearedBlockers), /blockers/)
  const clearedRuntimeExclusions = resealMutation(report, body => { body.runtimeExclusions = [] })
  t.exception(() => verifyRealBlindRelayReport(clearedRuntimeExclusions), /runtimeExclusions/)
  const weakenedThreshold = resealMutation(report, body => {
    body.gates.performance.thresholds.minimumOperationsPerPath = 1
  })
  t.exception(() => verifyRealBlindRelayReport(weakenedThreshold), /gates\.performance\.thresholds\.minimumOperationsPerPath/)
  const broadenedCopyCount = resealMutation(report, body => {
    body.load.independentCellCopiesPerLogicalRecord++
  })
  t.exception(() => verifyRealBlindRelayReport(broadenedCopyCount), /copy count must equal relayInstances/)
  const unknownRoot = resealMutation(report, body => { body.releaseAuthorized = true })
  t.exception(() => verifyRealBlindRelayReport(unknownRoot), /report fields are inconsistent/)
  const missingRoot = resealMutation(report, body => { delete body.resources })
  t.exception(() => verifyRealBlindRelayReport(missingRoot), /report fields are inconsistent/)
  const unknownNested = resealMutation(report, body => { body.scope.productionCoverage = true })
  t.exception(() => verifyRealBlindRelayReport(unknownNested), /scope fields are inconsistent/)
  const missingNested = resealMutation(report, body => { delete body.families.CORE.blocker })
  t.exception(() => verifyRealBlindRelayReport(missingNested), /families\.CORE fields are inconsistent/)
})
