import { createHash } from 'node:crypto'
import test from 'brittle'
import {
  BLIND_RELEASE_LAB_PROFILES,
  BLIND_RELEASE_LAB_SCHEMA,
  runBlindReleaseLab,
  validatePeeritLocalScaleReport,
  validatePeeritBrowserFullMatrix,
  validatePeeritFaultFullProfile,
  validateRealRelayEvidence,
  verifyBlindReleaseLabDigest
} from '../../scripts/run-blind-release-lab.mjs'
import {
  REAL_BLIND_RELAY_FAMILY_SCOPE,
  REAL_BLIND_RELAY_LAB_SCHEMA,
  REAL_BLIND_RELAY_LOCAL_PERFORMANCE_THRESHOLDS,
  REAL_BLIND_RELAY_RUNTIME_EXCLUSIONS,
  realBlindRelayExpectedBlockers,
  sealRealBlindRelayReport
} from '../../scripts/verify-real-blind-relay-report.mjs'
import { stableStringify } from '../../scripts/simulate-blind-fleet.mjs'

const LOCAL_GATE_IDS = [
  'JOURNAL_COUNT_EXACT',
  'INDEX_COUNT_EXACT',
  'JOURNAL_COMMIT_P99',
  'INDEX_BUILD_PROJECTED_100K',
  'FEED_READ_P99',
  'JOURNAL_VIEW_RANGE_PAGE_P99',
  'RETRY_TARGET_INDEX_LOCAL_FAIRNESS',
  'NODE_MEMORY_RSS_DELTA'
]

const RETRY_GATE_IDS = [
  'HARNESS_EXECUTION',
  'FIXTURE_INTENT_COUNT_EXACT',
  'COMPLETED_INTENT_COUNT_EXACT',
  'RETRY_TARGET_COVERAGE_EXACT',
  'RETRY_TARGET_CLAIMS_EXACT',
  'RETRY_BATCH_CONVERGENCE',
  'RETRY_LANE_FAIRNESS',
  'RETRY_TRUNCATION_SIGNAL',
  'EXPIRED_ACTIVE_CLAIM_RECOVERY',
  'LOCAL_MEMORY_WALL_TIME'
]

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function jsonClone (value) {
  return JSON.parse(JSON.stringify(value))
}

function peeritFixture (profile = BLIND_RELEASE_LAB_PROFILES.smoke.peerit) {
  const batchSize = 256
  const maximumRounds = Math.ceil(profile.intents / batchSize) + 2
  const retry = {
    schema: 'peerit-retry-fairness-lab-v1',
    evidenceClass: 'MEASURED_LOCAL_NODE_MEMORY_BACKEND',
    workload: {
      targets: profile.intents,
      batchSize,
      maximumRounds,
      maxElapsedMs: 30_000
    },
    summary: {
      uniqueTargetsSeen: profile.intents,
      selectedRows: profile.intents,
      claimsSucceeded: profile.intents,
      claimsFailed: 0,
      stateResetsSucceeded: profile.intents,
      unknownIntentIds: 0,
      rounds: Math.ceil(profile.intents / batchSize),
      truncatedPages: profile.intents > batchSize ? 1 : 0,
      laneFairnessViolations: 0,
      expiredClaimsRecovered: 1,
      expiredTargetState: 'pending-unknown'
    },
    timing: { elapsedMs: 1 },
    gates: RETRY_GATE_IDS.map(id => ({ id, passed: true })),
    blockers: [],
    localGateReady: true,
    releaseReady: false
  }
  return {
    schema: 'peerit-scale-lab-v1',
    evidenceClass: 'MEASURED_LOCAL_NODE_MEMORY_BACKEND',
    claimBoundary: 'Not browser/IndexedDB, network, disk, multi-process, or production capacity evidence.',
    workload: {
      intents: profile.intents,
      viewRecords: profile.viewRecords,
      communities: profile.communities,
      pageSize: profile.pageSize,
      recordsPerIntent: Math.ceil(profile.viewRecords / profile.intents),
      retryTargets: profile.intents
    },
    journal: {
      backend: 'deterministic-node-memory',
      writeTransactions: profile.intents,
      summary: {
        intentCount: profile.intents,
        viewRecordCount: profile.viewRecords
      },
      scannedIntentIds: profile.intents,
      rangedViewRecords: profile.viewRecords,
      nextWakeWithoutTargets: null,
      commit: { count: profile.intents, p99Ms: 1 },
      pendingIndexPage: { count: Math.ceil(profile.intents / profile.pageSize) },
      viewRangePage: { count: Math.ceil(profile.viewRecords / 1_000), p99Ms: 1 }
    },
    materializedIndex: {
      records: profile.viewRecords,
      totalFeedRows: profile.viewRecords,
      projectedBuildMsPer100k: 1,
      feedRead: { count: profile.communities, p99Ms: 1 }
    },
    retryFairness: retry,
    memory: { rssDeltaBytes: 0 },
    gates: LOCAL_GATE_IDS.map(id => ({ id, passed: true })),
    blockers: [],
    localGateReady: true,
    releaseReady: false
  }
}

function browserVerifierModule () {
  const full = Object.freeze({
    intents: 10_000,
    records: 100_000,
    communities: 100,
    pageSize: 1_000,
    timeoutMs: 300_000
  })
  return {
    BROWSER_SCALE_PROFILES: { full },
    verifyBrowserScaleEvidence (report) {
      const body = { ...report }
      delete body.evidenceDigest
      const expectedDigest = sha256(stableStringify(body))
      const verified = report?.evidenceDigest === expectedDigest
      return {
        verified,
        checksumVerified: verified,
        authentic: false,
        authorizesRelease: false,
        expectedDigest,
        observedDigest: report?.evidenceDigest,
        blockers: verified ? [] : ['EVIDENCE_DIGEST_MISMATCH']
      }
    },
    validatePageReport ({ report, workload, profile }) {
      const passed = report?.schema === 'peerit-browser-scale-gate-v1' &&
        report?.profile === profile && JSON.stringify(report?.workload) === JSON.stringify({
        intents: workload.intents,
        records: workload.records,
        communities: workload.communities,
        pageSize: workload.pageSize
      })
      return {
        gates: [{ id: 'PAGE_REVALIDATED', passed }],
        blockers: passed ? [] : ['PAGE_REVALIDATED'],
        passed
      }
    }
  }
}

function sealBrowser (body) {
  return { ...body, evidenceDigest: sha256(stableStringify(body)) }
}

function browserFixture (module = browserVerifierModule()) {
  const full = module.BROWSER_SCALE_PROFILES.full
  const workload = {
    intents: full.intents,
    records: full.records,
    communities: full.communities,
    pageSize: full.pageSize
  }
  const workloadDefinition = {
    schema: 'peerit-browser-scale-workload-v1',
    profile: 'full',
    ...workload,
    generator: 'sequential-intents-round-robin-communities-v1'
  }
  const results = ['chromium', 'firefox', 'webkit'].map(engine => {
    const pageReport = {
      schema: 'peerit-browser-scale-gate-v1',
      profile: 'full',
      workload,
      summary: {},
      timing: {},
      storage: {},
      memory: {},
      observability: {}
    }
    return {
      engine,
      status: 'passed',
      executionError: null,
      diagnostics: {},
      blockers: [],
      harnessGates: [
        { id: 'HARNESS_EXECUTION', passed: true },
        { id: 'PAGE_REVALIDATED', passed: true }
      ],
      metrics: {
        workload: pageReport.workload,
        summary: pageReport.summary,
        timing: pageReport.timing,
        storage: pageReport.storage,
        memory: pageReport.memory,
        observability: pageReport.observability
      },
      pageReport
    }
  })
  return sealBrowser({
    schema: 'peerit-browser-scale-matrix-v1',
    evidenceDigestPurpose: 'content-address-only-not-authenticity-or-release-authorization',
    profile: 'full',
    workload,
    workloadDefinition,
    workloadSha256: sha256(JSON.stringify(workloadDefinition)),
    requestedEngines: ['chromium', 'firefox', 'webkit'],
    coverage: {
      desktopEnginesPassed: ['chromium', 'firefox', 'webkit'],
      desktopFullProfileEnginesPassed: ['chromium', 'firefox', 'webkit'],
      desktopEnginesRequired: ['chromium', 'firefox', 'webkit'],
      mobile: false,
      crashRecovery: false,
      quotaExhaustion: false,
      network: false,
      production: false
    },
    results,
    selectedRunPassed: true,
    selectedBrowserGateReady: true,
    localDesktopMatrixReady: true,
    releaseReady: false
  })
}

function faultVerifierModule () {
  return {
    PERSISTENCE_FAULT_PROFILES: {
      full: {
        baselineIntents: 256,
        crashRecords: 64,
        quotaPayloadBytes: 1_000_000,
        timeoutMs: 180_000
      }
    },
    verifyPersistenceFaultEvidence (report) {
      const body = { ...report }
      delete body.contentChecksum
      const expectedChecksum = sha256(stableStringify(body))
      const verified = report?.contentChecksum === expectedChecksum
      return {
        verified,
        expectedChecksum,
        observedChecksum: report?.contentChecksum,
        blockers: verified ? [] : ['CHECKSUM_MISMATCH']
      }
    }
  }
}

function sealFault (body) {
  return { ...body, contentChecksum: sha256(stableStringify(body)) }
}

function faultFixture (module = faultVerifierModule()) {
  const full = module.PERSISTENCE_FAULT_PROFILES.full
  return sealFault({
    schema: 'peerit-browser-persistence-fault-v1',
    profile: 'full',
    workload: {
      baselineIntents: full.baselineIntents,
      crashRecords: full.crashRecords,
      quotaPayloadBytes: full.quotaPayloadBytes
    },
    authenticityProven: false,
    coverage: {
      realQuotaExhaustion: false,
      mobile: false,
      production: false
    },
    gates: [{ id: 'FAULTS', passed: true }],
    blockers: [],
    localFaultGateReady: true,
    fullProfileGateReady: true,
    releaseReady: false
  })
}

function realRelayFixture () {
  const relayCount = 2
  const logicalRecords = 32
  const attempted = relayCount * logicalRecords
  const correctness = {
    exactStoreCounts: true,
    stableDiskBytesAcrossRestart: true,
    noRuntimeErrors: true,
    allStagedWritesCompleted: true,
    allPublicReadsCompleted: true,
    allRecoveredReadsCompleted: true,
    declaredQualificationOutcomeObserved: true,
    independentRelayIdentitiesObserved: true,
    independentStoreIdsObserved: true,
    independentCopiesObserved: true,
    restartV2WriteRecoveryObserved: true
  }
  const performance = {
    sufficientOperationSample: true,
    stagedPutThroughput: true,
    stagedPutP99: true,
    publicGetThroughput: true,
    publicGetP99: true,
    recoveredGetThroughput: true,
    recoveredGetP99: true,
    restartRecoveryWall: true
  }
  const metric = (count, wallMs) => ({
    count,
    meanMs: 2,
    p50Ms: 1,
    p95Ms: 2,
    p99Ms: 3,
    maxMs: 4,
    wallMs,
    operationsPerSecond: count * 1_000 / wallMs
  })
  const stores = Array.from({ length: relayCount }, (_, relayIndex) => ({
    relayIndex,
    expectedCellRecords: logicalRecords,
    actualCellRecords: logicalRecords,
    storedBytes: 3_200,
    exact: true
  }))
  const disks = Array.from({ length: relayCount }, (_, relayIndex) => ({
    relayIndex,
    files: 3,
    bytes: 4_000
  }))
  const qualificationAttempts = Array.from({ length: relayCount * 3 }, () => ({
    qualified: false,
    code: 'RELAY_NOT_QUALIFIED',
    message: 'fresh health does not prove requested readiness'
  }))
  return sealRealBlindRelayReport({
    schema: REAL_BLIND_RELAY_LAB_SCHEMA,
    generatedAt: '2026-07-12T00:00:00.000Z',
    evidenceClass: 'MEASURED_LOCAL_REAL_HTTP_IPC_FILESYSTEM',
    evidenceBinding: {
      algorithm: 'sha256',
      canonicalization: 'HIVERELAY_SORTED_JSON_V1',
      checksumOnly: true,
      signed: false,
      authenticityProven: false
    },
    releaseReady: false,
    localGateReady: true,
    correctnessGateReady: true,
    performanceGateReady: true,
    gates: {
      correctness: {
        ready: true,
        claimClass: 'LOCAL_CORRECTNESS_ONLY',
        checks: correctness
      },
      performance: {
        ready: true,
        claimClass: 'LOCAL_LOOPBACK_SMOKE_NOT_CAPACITY_OR_SLO',
        capacityClaim: false,
        serviceLevelObjectiveClaim: false,
        thresholds: REAL_BLIND_RELAY_LOCAL_PERFORMANCE_THRESHOLDS,
        checks: performance
      }
    },
    scope: {
      realImplementationsOnly: false,
      realHttpIpcWalFilesystemDataPlane: true,
      modelDataPlane: false,
      syntheticAdmissionAdapter: true,
      economicSettlementMeasured: false,
      relayInstances: relayCount,
      independentStoreRoots: relayCount,
      independentRelaySigningKeys: relayCount,
      independentlyEncryptedCellCopies: true,
      networkReplicaProtocolMeasured: false,
      processIsolation: false,
      hostIsolation: false,
      transport: 'ephemeral self-signed loopback TLS plus authenticated Unix IPC',
      testFetchCertificateValidation: false,
      productionReleaseGateBypassed: true,
      sameUidTestTopology: true
    },
    load: {
      logicalRecords,
      attemptedCellWrites: attempted,
      independentCellCopiesPerLogicalRecord: relayCount,
      replicaProtocolMeasured: false,
      contentBytesPerRecord: 256,
      concurrency: 8
    },
    families: REAL_BLIND_RELAY_FAMILY_SCOPE,
    metrics: {
      qualification: {
        count: relayCount * 3,
        meanMs: 2,
        p50Ms: 1,
        p95Ms: 2,
        p99Ms: 3,
        maxMs: 4
      },
      stagedCellPut: metric(attempted, 8_000),
      publicCellGet: metric(attempted, 1_000),
      recoveredPublicCellGet: metric(attempted, 1_000)
    },
    integrity: {
      contentChecksBeforeRestart: attempted,
      contentChecksAfterRestart: attempted,
      exactStoreCountsBeforeRestart: stores,
      exactStoreCountsAfterRestart: stores,
      allCountsExact: true,
      uniqueRelaySigningKeys: relayCount,
      uniqueStoreIds: relayCount,
      deterministicLogicalCorpus: true,
      independentlyAllocatedLogicalRecords: logicalRecords,
      allCopiesIndependentlyAllocatedAndEncrypted: true,
      replicaProtocolMeasured: false,
      ordinaryClientQualificationFailedClosed: true,
      qualificationAttempts
    },
    recovery: {
      relaysStopped: relayCount,
      relaysRestarted: relayCount,
      cleanStopWallMs: 10,
      retainedStateReadChecks: attempted,
      diskBytesStableAcrossRestart: true,
      initialV2WriteStartupQuarantineObserved: true,
      initialV2WritePathReadyBeforeWrites: true,
      initialV2WriteReadinessWaitMs: 15000,
      restartV2WriteStartupQuarantineObserved: true,
      restartV2WritePathReadyBeforeWrites: true,
      restartV2WriteReadinessWaitMs: 15000,
      restartV2PublicHttpsExactPutAttempts: relayCount,
      restartV2RetainedReadChecks: relayCount,
      restartAndRecoveryWallMs: 100
    },
    resources: {
      processRssBytesBefore: 1_000,
      processRssBytesAfterWrite: 2_000,
      processRssBytesAfterRestart: 1_500,
      processRssDeltaBytes: 500,
      perRelayRssUnavailableReason: 'RELAYS_SHARE_ONE_NODE_PROCESS',
      storesBeforeRestart: disks,
      storesAfterRestart: disks,
      aggregateStoredPayloadBytes: 6_400
    },
    runtimeErrors: [],
    runtimeExclusions: REAL_BLIND_RELAY_RUNTIME_EXCLUSIONS,
    blockers: realBlindRelayExpectedBlockers({ correctnessReady: true, performanceReady: true })
  })
}

test('release lab v2 aligns capacity mechanically to the realized fleet and fails closed without measured evidence', async t => {
  const report = await runBlindReleaseLab({ profile: 'smoke' })
  t.is(report.schema, BLIND_RELEASE_LAB_SCHEMA)
  t.ok(verifyBlindReleaseLabDigest(report))
  t.is(report.evidenceBinding.purpose, 'content-integrity-only')
  t.is(report.evidenceBinding.authenticityProven, false)
  t.ok(report.fleet.ok)
  t.is(report.fleet.virtualTime.durationMillis, 60_000)
  t.ok(report.scenarioAlignment.passed)
  t.alike(report.capacity.config.fleet.diskBytesByRelay,
    report.fleet.scenarioManifest.relays.map(relay => relay.storageBytes))
  t.is(report.capacity.config.network.ingressBitsPerSecond,
    Math.min(...report.fleet.scenarioManifest.relays.map(relay => relay.networkMbps)) * 1_000_000)
  t.is(report.capacity.config.workload.offeredLogicalOpsPerSecond, 16.75)
  t.is(report.capacity.status, 'rejected')
  t.absent(report.labReady)
  for (const blocker of [
    'CAPACITY_MODEL_STEADY_STATE',
    'PEERIT_LOCAL_SCALE',
    'PEERIT_DESKTOP_FULL_MATRIX',
    'PEERIT_CHROMIUM_FULL_FAULT',
    'REAL_ASSEMBLED_CELL_RELAY'
  ]) t.ok(report.labBlockers.includes(blocker))
  t.absent(report.mainnetReady)
  for (const blocker of [
    'ALL_FAMILY_PRODUCTION_RUNTIME',
    'REAL_BROWSER_QUOTA_EXHAUSTION',
    'MOBILE_BROWSER_SCALE_AND_FAULT',
    'PRODUCTION_BROWSER_SCALE_AND_FAULT',
    'CROSS_BROWSER_RELAY_DELIVERY',
    'REAL_MULTI_PROCESS_RELAY_BENCHMARK',
    'REAL_MULTI_HOST_HARDWARE_BENCHMARK',
    'INDEPENDENT_OPERATOR_FAILURE_DRILL',
    'SEVEN_DAY_MIXED_FAULT_SOAK',
    'SIGNED_RELEASE_ATTESTATION_AND_ROLLBACK'
  ]) t.ok(report.mainnetBlockers.includes(blocker))
})

test('scenario alignment rejects a capacity report whose offered load drifts from its fleet', async t => {
  const report = await runBlindReleaseLab({
    profile: 'smoke',
    capacity: { workload: { offeredLogicalOpsPerSecond: 1 } }
  })
  t.absent(report.scenarioAlignment.passed)
  t.ok(report.scenarioAlignment.blockers.includes('EXACT_TOTAL_OFFERED_LOAD'))
  t.ok(report.labBlockers.includes('FLEET_CAPACITY_SCENARIO_ALIGNED'))
})

test('Peerit local evidence is validated from exact counts, profile, and derived gates', t => {
  const profile = BLIND_RELEASE_LAB_PROFILES.smoke.peerit
  const valid = peeritFixture(profile)
  t.ok(validatePeeritLocalScaleReport(valid, profile).passed)

  const dishonestCount = jsonClone(valid)
  dishonestCount.journal.summary.intentCount--
  const countValidation = validatePeeritLocalScaleReport(dishonestCount, profile)
  t.absent(countValidation.passed)
  t.ok(countValidation.blockers.includes('EXACT_GATE_SET_AND_RESULTS'))

  const wrongProfile = jsonClone(valid)
  wrongProfile.workload.intents++
  t.absent(validatePeeritLocalScaleReport(wrongProfile, profile).passed)
})

test('exact full browser/fault and pinned real-relay evidence satisfy their content-only local validators', t => {
  const browserModule = browserVerifierModule()
  const faultModule = faultVerifierModule()
  const browserReport = browserFixture(browserModule)
  const faultReport = faultFixture(faultModule)
  const browserValidation = validatePeeritBrowserFullMatrix(
    browserReport,
    browserModule,
    browserModule.verifyBrowserScaleEvidence(browserReport)
  )
  const faultValidation = validatePeeritFaultFullProfile(
    faultReport,
    faultModule,
    faultModule.verifyPersistenceFaultEvidence(faultReport)
  )
  t.ok(browserValidation.passed)
  t.ok(faultValidation.passed)
  t.ok(validateRealRelayEvidence(realRelayFixture()).passed)
  t.is(browserValidation.authenticityProven, false)
  t.is(browserValidation.authorizesRelease, false)
  t.is(faultValidation.authenticityProven, false)
  t.is(faultValidation.authorizesRelease, false)
})

test('tampered and resealed evidence fails through owning and semantic verification', t => {
  const browserModule = browserVerifierModule()
  const faultModule = faultVerifierModule()

  const tamperedBrowser = browserFixture(browserModule)
  tamperedBrowser.results[0].status = 'failed'
  const tampered = validatePeeritBrowserFullMatrix(
    tamperedBrowser,
    browserModule,
    browserModule.verifyBrowserScaleEvidence(tamperedBrowser)
  )
  t.absent(tampered.passed)
  t.ok(tampered.blockers.includes('OWNING_CONTENT_VERIFIER'))

  const browserBody = browserFixture(browserModule)
  delete browserBody.evidenceDigest
  browserBody.profile = 'smoke'
  const resealedBrowser = sealBrowser(browserBody)
  const browserMismatch = validatePeeritBrowserFullMatrix(
    resealedBrowser,
    browserModule,
    browserModule.verifyBrowserScaleEvidence(resealedBrowser)
  )
  t.absent(browserMismatch.passed)
  t.ok(browserMismatch.blockers.includes('EXACT_FULL_PROFILE'))

  const faultBody = faultFixture(faultModule)
  delete faultBody.contentChecksum
  faultBody.workload.baselineIntents--
  const resealedFault = sealFault(faultBody)
  const faultMismatch = validatePeeritFaultFullProfile(
    resealedFault,
    faultModule,
    faultModule.verifyPersistenceFaultEvidence(resealedFault)
  )
  t.absent(faultMismatch.passed)
  t.ok(faultMismatch.blockers.includes('EXACT_FULL_PROFILE'))

  const weakBody = jsonClone(realRelayFixture())
  delete weakBody.evidenceDigest
  weakBody.gates.performance.thresholds.stagedPutMinimumOperationsPerSecond = 0.01
  const weakReal = validateRealRelayEvidence(sealRealBlindRelayReport(weakBody))
  t.absent(weakReal.passed)
  t.ok(weakReal.blockers.includes('PINNED_LOCAL_THRESHOLDS'))

  const falseFamilyBody = jsonClone(realRelayFixture())
  delete falseFamilyBody.evidenceDigest
  falseFamilyBody.families.INBOX.measured = true
  const falseFamily = validateRealRelayEvidence(sealRealBlindRelayReport(falseFamilyBody))
  t.absent(falseFamily.passed)
  t.ok(falseFamily.blockers.includes('PINNED_MEASURED_FAMILY_BOUNDARY'))
})

test('browser evidence cannot substitute a caller-injected verifier for Peerit ownership', async t => {
  await t.exception(runBlindReleaseLab({
    profile: 'smoke',
    peeritReport: peeritFixture(),
    peeritBrowserReport: browserFixture()
  }), /--peerit-root is required/)
})

test('release lab rejects an unknown profile', async t => {
  await t.exception(runBlindReleaseLab({ profile: 'imaginary' }), /unknown blind release-lab profile/)
})
