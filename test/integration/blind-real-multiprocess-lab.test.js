import test from 'brittle'
import { runLocalMultiprocessBlindRelayLab } from '../../scripts/run-multiprocess-blind-relay-lab.mjs'
import {
  LOCAL_MULTIPROCESS_BLIND_MANDATORY_BLOCKERS,
  sealLocalMultiprocessBlindReport,
  verifyLocalMultiprocessBlindReport
} from '../../scripts/verify-multiprocess-blind-relay-report.mjs'

function resealMutation (report, mutate) {
  const body = JSON.parse(JSON.stringify(report))
  delete body.evidenceDigest
  mutate(body)
  return sealLocalMultiprocessBlindReport(body)
}

test('three concurrent local OS processes run scoped real relay labs without identity collisions', {
  timeout: 120_000
}, async t => {
  const report = await runLocalMultiprocessBlindRelayLab({
    processCount: 3,
    relaysPerProcess: 2,
    recordsPerRelay: 1,
    concurrencyPerProcess: 1,
    contentBytes: 96,
    childTimeoutMs: 100_000
  })

  t.is(report.evidenceClass, 'MEASURED_LOCAL_MULTI_PROCESS_REAL_HTTP_IPC_FILESYSTEM')
  t.is(report.releaseReady, false)
  t.is(report.correctnessGateReady, true)
  t.is(report.scope.childProcessCount, 3)
  t.is(report.scope.logicalOperatorScopeProcesses, 3)
  t.is(report.scope.crossChildProcessIsolationMeasured, true)
  t.is(report.scope.sameHost, true)
  t.is(report.scope.sameUid, true)
  t.is(report.scope.claimedIndependentOperators, false)
  t.is(report.scope.realIndependentOwnershipMeasured, false)
  t.is(report.scope.multiHostNetworkMeasured, false)
  t.is(report.scope.publicCaTlsValidationMeasured, false)
  t.is(report.scope.syntheticAdmissionAdapter, true)
  t.is(report.scope.soakMeasured, false)
  t.is(report.processExecution.uniqueChildPids, 3)
  t.is(report.processExecution.concurrentOverlapObserved, true)
  t.ok(report.processExecution.concurrentOverlapMillis > 0)
  t.is(report.children.length, 3)
  t.is(new Set(report.children.map(child => child.observedPid)).size, 3)
  t.ok(report.children.every(child => child.exitCode === 0 && child.signal === null))
  t.ok(report.children.every(child => child.stderrBytes === 0))
  t.ok(report.children.every(child => child.envelope.process.parentPid ===
    report.processExecution.supervisorPid))
  t.ok(report.children.every(child => child.envelope.labReport.correctnessGateReady === true))
  t.is(report.summary.totalRelayInstances, 6)
  t.is(report.summary.globalUniqueRelaySigningKeys, 6)
  t.is(report.summary.globalUniqueStoreIds, 6)
  t.is(report.summary.totalAttemptedCellWrites, 6)
  t.is(report.summary.totalPublicReadChecks, 6)
  t.is(report.summary.totalRecoveredReadChecks, 6)
  t.is(report.summary.totalRelaysStopped, 6)
  t.is(report.summary.totalRelaysRestarted, 6)
  t.is(report.summary.totalActualStoreRecordsBeforeRestart, 6)
  t.is(report.summary.totalActualStoreRecordsAfterRestart, 6)
  t.is(report.summary.allStoreCountsExact, true)
  t.is(report.summary.childLabEvidenceDigests.length, 3)
  t.is(report.summary.childEnvelopeEvidenceDigests.length, 3)
  t.is(report.summary.sourceCommits.length, 3)
  t.is(report.summary.latencies.stagedCellPut.count, 6)
  t.is(report.summary.latencies.publicCellGet.count, 6)
  t.is(report.summary.latencies.recoveredPublicCellGet.count, 6)
  t.ok(report.blockers.includes('SAME_HOST_LOCAL_PROCESSES'))
  t.ok(report.blockers.includes('SAME_UID_TEST_TOPOLOGY'))
  t.ok(report.blockers.includes('LOGICAL_OPERATOR_SCOPES_NOT_INDEPENDENT_OWNERSHIP'))
  t.ok(report.blockers.includes('SYNTHETIC_ADMISSION_NO_ECONOMIC_SETTLEMENT'))
  t.ok(report.blockers.includes('MULTI_HOST_NETWORK_UNMEASURED'))
  t.ok(report.blockers.includes('PUBLIC_CA_TLS_VALIDATION_UNMEASURED'))
  t.ok(report.blockers.includes('LONG_DURATION_SOAK_UNMEASURED'))
  t.ok(Object.isFrozen(LOCAL_MULTIPROCESS_BLIND_MANDATORY_BLOCKERS))

  const verification = verifyLocalMultiprocessBlindReport(report, { requireCorrectness: true })
  t.is(verification.verified, true)
  t.is(verification.checksumVerified, true)
  t.is(verification.checksumOnly, true)
  t.is(verification.authenticityProven, false)
  t.is(verification.authorizesRelease, false)
  t.is(verification.claimsIndependentOperators, false)
  t.is(verification.correctnessReady, true)

  const reordered = Object.fromEntries(Object.entries(JSON.parse(JSON.stringify(report))).reverse())
  t.is(verifyLocalMultiprocessBlindReport(reordered).checksumVerified, true)
  const tampered = JSON.parse(JSON.stringify(report))
  tampered.summary.totalAttemptedCellWrites++
  t.exception(() => verifyLocalMultiprocessBlindReport(tampered), /checksum mismatch/)
  const ownershipOverclaim = resealMutation(report, body => {
    body.scope.claimedIndependentOperators = true
  })
  t.exception(() => verifyLocalMultiprocessBlindReport(ownershipOverclaim),
    /scope\.claimedIndependentOperators/)
  const clearedBlockers = resealMutation(report, body => { body.blockers = [] })
  t.exception(() => verifyLocalMultiprocessBlindReport(clearedBlockers), /blockers/)
  const dirtyChildReport = resealMutation(report, body => {
    body.children[0].envelope.labReport.metrics.stagedCellPut.count++
  })
  t.exception(() => verifyLocalMultiprocessBlindReport(dirtyChildReport),
    /child\.evidenceDigest checksum mismatch/)
})
