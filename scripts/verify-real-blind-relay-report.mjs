#!/usr/bin/env node
import { createHash, timingSafeEqual } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const REAL_BLIND_RELAY_LAB_SCHEMA = 'hiverelay.blind.real-relay-lab.v5'
export const REAL_BLIND_RELAY_CANONICALIZATION = 'HIVERELAY_SORTED_JSON_V1'
export const REAL_BLIND_RELAY_LOCAL_PERFORMANCE_THRESHOLDS = Object.freeze({
  minimumOperationsPerPath: 32,
  stagedPutMinimumOperationsPerSecond: 5,
  stagedPutMaximumP99Millis: 5000,
  publicGetMinimumOperationsPerSecond: 20,
  publicGetMaximumP99Millis: 2000,
  recoveredGetMinimumOperationsPerSecond: 20,
  recoveredGetMaximumP99Millis: 2000,
  restartRecoveryMaximumWallMillis: 15000
})
export const REAL_BLIND_RELAY_RUNTIME_EXCLUSIONS = Object.freeze([
  'CORE_PUBLIC_EXECUTION_UNASSEMBLED',
  'DESCRIPTOR_REFRESH_PERSISTED_FLOOR_UNASSEMBLED',
  'FINAL_BUILD_PROFILE_LOCAL_BINDING_UNASSEMBLED',
  'FORWARD_PUBLIC_EXECUTION_UNASSEMBLED',
  'INBOX_PUBLIC_EXECUTION_UNASSEMBLED',
  'PRODUCTION_ADMISSION_ADAPTER_CAPTURE_REQUIRED',
  'PRODUCTION_DURABLE_REPLAY_AUTHORITY_REQUIRED',
  'PROFILE2_EXTERNAL_JOURNAL_WITNESS_UNASSEMBLED',
  'TWO_SLOT_MANIFEST_RUNTIME_INTEGRATION_UNASSEMBLED'
])
export const REAL_BLIND_RELAY_MANDATORY_BLOCKERS = Object.freeze([
  'SYNTHETIC_ADMISSION_NO_ECONOMIC_SETTLEMENT',
  'PRODUCTION_RELEASE_GATE_BYPASSED',
  'INDEPENDENT_CELL_COPIES_NOT_REPLICA_PROTOCOL',
  'SINGLE_PROCESS_RELAY_ISOLATION_UNMEASURED',
  'SINGLE_HOST_RELAY_ISOLATION_UNMEASURED',
  'SAME_UID_TEST_TOPOLOGY',
  'MULTI_HOST_NETWORK_UNMEASURED',
  'PUBLIC_CA_TLS_VALIDATION_UNMEASURED',
  'INDEPENDENT_OPERATOR_FAILURE_DOMAINS_UNMEASURED',
  'INTERNET_LATENCY_AND_PACKET_LOSS_UNMEASURED',
  'MULTI_RELAY_REPLICATION_REPAIR_PROTOCOL_UNMEASURED',
  'RELAY_CHURN_AND_PARTITION_UNMEASURED',
  'LONG_DURATION_SOAK_UNMEASURED',
  'CRASH_KILL_DURING_COMMIT_UNMEASURED',
  'DISK_FULL_AND_CORRUPTION_INJECTION_UNMEASURED',
  'RESOURCE_SATURATION_UNMEASURED',
  'SIGNED_RELEASE_AND_ROLLBACK_UNMEASURED'
])
export const REAL_BLIND_RELAY_FAMILY_SCOPE = deepFreeze({
  DESCRIBE: {
    measured: true,
    path: 'BlindRelayQualifier -> public HTTP BlindEdge -> private unary IPC -> BlindDaemon',
    operations: ['GET', 'CHALLENGE']
  },
  CELL: {
    measured: true,
    putPath: 'public HTTPS BlindEdge -> V2 full outer-envelope staged private IPC with TLS-exporter binding -> BlindDaemon -> filesystem store',
    getPath: 'qualified BlindDirectHttpClient -> public HTTPS BlindEdge -> private unary IPC -> BlindDaemon -> filesystem store -> authenticated result verifier and cell open',
    ordinaryClientQualified: true,
    unqualifiedWireTestSeam: false,
    publicHttpPutMeasured: true,
    publicHttpPutAdmissionEvidence: 'synthetic split adapter only; no packaged production-admission or economic-settlement claim'
  },
  INBOX: {
    measured: false,
    blocker: 'INBOX_PUBLIC_EXECUTION_UNASSEMBLED'
  },
  CORE: {
    measured: false,
    blocker: 'CORE_PUBLIC_EXECUTION_UNASSEMBLED'
  },
  FORWARD: {
    measured: false,
    blocker: 'FORWARD_PUBLIC_EXECUTION_UNASSEMBLED'
  }
})

const ROOT_KEYS = Object.freeze([
  'blockers',
  'correctnessGateReady',
  'evidenceBinding',
  'evidenceClass',
  'evidenceDigest',
  'families',
  'gates',
  'generatedAt',
  'integrity',
  'load',
  'localGateReady',
  'metrics',
  'performanceGateReady',
  'recovery',
  'releaseReady',
  'resources',
  'runtimeErrors',
  'runtimeExclusions',
  'schema',
  'scope'
])

function deepFreeze (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function fail (message) {
  const error = new Error(message)
  error.code = 'BLIND_REAL_RELAY_REPORT_INVALID'
  throw error
}

function canonicalValue (value, seen, field) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail(`${field} contains a non-canonical number`)
    return JSON.stringify(value)
  }
  if (!value || typeof value !== 'object') fail(`${field} contains a non-JSON value`)
  if (seen.has(value)) fail(`${field} contains a cycle`)
  seen.add(value)
  try {
    if (Array.isArray(value)) {
      const items = []
      for (let index = 0; index < value.length; index++) {
        if (!Object.hasOwn(value, index)) fail(`${field} contains a sparse array`)
        items.push(canonicalValue(value[index], seen, `${field}[${index}]`))
      }
      return `[${items.join(',')}]`
    }
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) fail(`${field} contains a non-plain object`)
    const keys = Object.keys(value).sort()
    if (Reflect.ownKeys(value).length !== keys.length) fail(`${field} contains hidden or symbolic fields`)
    return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalValue(value[key], seen, `${field}.${key}`)}`).join(',')}}`
  } finally {
    seen.delete(value)
  }
}

export function canonicalRealBlindRelayReportJson (value) {
  return canonicalValue(value, new Set(), 'report')
}

function reportBody (report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) fail('report must be an object')
  const body = {}
  for (const [key, value] of Object.entries(report)) {
    if (key !== 'evidenceDigest') body[key] = value
  }
  return body
}

export function realBlindRelayReportDigest (report) {
  return createHash('sha256')
    .update(canonicalRealBlindRelayReportJson(reportBody(report)), 'utf8')
    .digest('hex')
}

export function sealRealBlindRelayReport (body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) fail('report body must be an object')
  if (Object.hasOwn(body, 'evidenceDigest')) fail('report body must not contain evidenceDigest before sealing')
  const report = { ...body }
  return Object.freeze({ ...report, evidenceDigest: realBlindRelayReportDigest(report) })
}

function record (value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${field} must be an object`)
  return value
}

function exactKeys (value, expectedKeys, field) {
  record(value, field)
  const actual = Object.keys(value).sort()
  const expected = [...expectedKeys].sort()
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${field} fields are inconsistent; expected ${expected.join(',')}, got ${actual.join(',')}`)
  }
}

function exactAuthority (actual, expected, field) {
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual) || actual.length !== expected.length) fail(`${field} does not match verifier authority`)
    for (let index = 0; index < expected.length; index++) {
      exactAuthority(actual[index], expected[index], `${field}[${index}]`)
    }
    return
  }
  if (expected && typeof expected === 'object') {
    exactKeys(actual, Object.keys(expected), field)
    for (const [key, value] of Object.entries(expected)) exactAuthority(actual[key], value, `${field}.${key}`)
    return
  }
  if (actual !== expected) fail(`${field} does not match verifier authority`)
}

function safeInteger (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${field} must be an integer within ${minimum}..${maximum}`)
  }
  return value
}

function finiteNumber (value, minimum, field) {
  if (!Number.isFinite(value) || value < minimum) fail(`${field} must be a finite number >= ${minimum}`)
  return value
}

function exactChecks (actual, expected, field) {
  exactKeys(actual, Object.keys(expected), `${field}.checks`)
  for (const [name, value] of Object.entries(expected)) {
    if (actual[name] !== value) fail(`${field}.checks.${name} is inconsistent with measured evidence`)
  }
}

function metricSummary (value, field, withRate) {
  const keys = ['count', 'meanMs', 'p50Ms', 'p95Ms', 'p99Ms', 'maxMs']
  if (withRate) keys.push('wallMs', 'operationsPerSecond')
  exactKeys(value, keys, field)
  const count = safeInteger(value.count, 1, Number.MAX_SAFE_INTEGER, `${field}.count`)
  const mean = finiteNumber(value.meanMs, 0, `${field}.meanMs`)
  const p50 = finiteNumber(value.p50Ms, 0, `${field}.p50Ms`)
  const p95 = finiteNumber(value.p95Ms, 0, `${field}.p95Ms`)
  const p99 = finiteNumber(value.p99Ms, 0, `${field}.p99Ms`)
  const maximum = finiteNumber(value.maxMs, 0, `${field}.maxMs`)
  if (p50 > p95 || p95 > p99 || p99 > maximum || mean > maximum) {
    fail(`${field} latency percentiles are inconsistent`)
  }
  if (withRate) {
    const wall = finiteNumber(value.wallMs, Number.EPSILON, `${field}.wallMs`)
    const rate = finiteNumber(value.operationsPerSecond, Number.EPSILON, `${field}.operationsPerSecond`)
    const derivedRate = count * 1000 / wall
    if (Math.abs(rate - derivedRate) > Math.max(0.01, derivedRate * 0.0001)) {
      fail(`${field}.operationsPerSecond is inconsistent with count and wallMs`)
    }
  }
}

function storeCountRows (rows, relayCount, logicalRecords, field) {
  if (!Array.isArray(rows) || rows.length !== relayCount) fail(`${field} must contain one row per relay`)
  const byIndex = new Map()
  for (const row of rows) {
    exactKeys(row, ['relayIndex', 'expectedCellRecords', 'actualCellRecords', 'storedBytes', 'exact'], `${field}[]`)
    const relayIndex = safeInteger(row.relayIndex, 0, relayCount - 1, `${field}[].relayIndex`)
    if (byIndex.has(relayIndex)) fail(`${field} contains a duplicate relay index`)
    if (row.expectedCellRecords !== logicalRecords) fail(`${field}[${relayIndex}].expectedCellRecords is inconsistent`)
    safeInteger(row.actualCellRecords, 0, Number.MAX_SAFE_INTEGER, `${field}[${relayIndex}].actualCellRecords`)
    safeInteger(row.storedBytes, 0, Number.MAX_SAFE_INTEGER, `${field}[${relayIndex}].storedBytes`)
    if (row.exact !== (row.actualCellRecords === logicalRecords)) fail(`${field}[${relayIndex}].exact is inconsistent`)
    byIndex.set(relayIndex, row)
  }
  for (let index = 0; index < relayCount; index++) if (!byIndex.has(index)) fail(`${field} is missing relay ${index}`)
  return byIndex
}

function diskRows (rows, relayCount, field) {
  if (!Array.isArray(rows) || rows.length !== relayCount) fail(`${field} must contain one row per relay`)
  const byIndex = new Map()
  for (const row of rows) {
    exactKeys(row, ['relayIndex', 'files', 'bytes'], `${field}[]`)
    const relayIndex = safeInteger(row.relayIndex, 0, relayCount - 1, `${field}[].relayIndex`)
    if (byIndex.has(relayIndex)) fail(`${field} contains a duplicate relay index`)
    safeInteger(row.files, 0, Number.MAX_SAFE_INTEGER, `${field}[${relayIndex}].files`)
    safeInteger(row.bytes, 0, Number.MAX_SAFE_INTEGER, `${field}[${relayIndex}].bytes`)
    byIndex.set(relayIndex, row)
  }
  for (let index = 0; index < relayCount; index++) if (!byIndex.has(index)) fail(`${field} is missing relay ${index}`)
  return byIndex
}

export function realBlindRelayExpectedBlockers ({ correctnessReady, performanceReady }) {
  if (typeof correctnessReady !== 'boolean' || typeof performanceReady !== 'boolean') {
    fail('blocker computation requires boolean gate outcomes')
  }
  const blockers = [...REAL_BLIND_RELAY_MANDATORY_BLOCKERS, ...REAL_BLIND_RELAY_RUNTIME_EXCLUSIONS]
  if (!correctnessReady) blockers.push('LOCAL_CORRECTNESS_GATE_NOT_MET')
  if (!performanceReady) blockers.push('LOCAL_PERFORMANCE_SMOKE_GATE_NOT_MET')
  return Object.freeze(blockers)
}

function validateFixedBoundary (report) {
  exactKeys(report, ROOT_KEYS, 'report')
  if (report.schema !== REAL_BLIND_RELAY_LAB_SCHEMA) fail(`unsupported report schema ${JSON.stringify(report.schema)}`)
  if (typeof report.generatedAt !== 'string' || Number.isNaN(Date.parse(report.generatedAt)) ||
      new Date(report.generatedAt).toISOString() !== report.generatedAt) {
    fail('generatedAt must be a canonical ISO timestamp')
  }
  if (report.evidenceClass !== 'MEASURED_LOCAL_REAL_HTTP_IPC_FILESYSTEM') {
    fail('evidenceClass exceeds or changes the measured local boundary')
  }
  exactAuthority(report.evidenceBinding, {
    algorithm: 'sha256',
    canonicalization: REAL_BLIND_RELAY_CANONICALIZATION,
    checksumOnly: true,
    signed: false,
    authenticityProven: false
  }, 'evidenceBinding')
  if (report.releaseReady !== false) fail('the local relay lab cannot claim release readiness')
  exactKeys(report.scope, [
    'realImplementationsOnly',
    'realHttpIpcWalFilesystemDataPlane',
    'modelDataPlane',
    'syntheticAdmissionAdapter',
    'economicSettlementMeasured',
    'relayInstances',
    'independentStoreRoots',
    'independentRelaySigningKeys',
    'independentlyEncryptedCellCopies',
    'networkReplicaProtocolMeasured',
    'processIsolation',
    'hostIsolation',
    'transport',
    'testFetchCertificateValidation',
    'productionReleaseGateBypassed',
    'sameUidTestTopology'
  ], 'scope')
  for (const [field, expected] of Object.entries({
    realImplementationsOnly: false,
    realHttpIpcWalFilesystemDataPlane: true,
    modelDataPlane: false,
    syntheticAdmissionAdapter: true,
    economicSettlementMeasured: false,
    networkReplicaProtocolMeasured: false,
    processIsolation: false,
    hostIsolation: false,
    transport: 'ephemeral self-signed loopback TLS plus authenticated Unix IPC',
    testFetchCertificateValidation: false,
    productionReleaseGateBypassed: true,
    sameUidTestTopology: true
  })) exactAuthority(report.scope[field], expected, `scope.${field}`)
  exactAuthority(report.families, REAL_BLIND_RELAY_FAMILY_SCOPE, 'families')
  exactAuthority(report.runtimeExclusions, REAL_BLIND_RELAY_RUNTIME_EXCLUSIONS, 'runtimeExclusions')
}

function validateMeasuredRelationships (report) {
  const relayCount = safeInteger(report.scope.relayInstances, 2, 8, 'scope.relayInstances')
  if (report.scope.independentStoreRoots !== relayCount) fail('scope.independentStoreRoots must equal relayInstances')
  exactKeys(report.load, [
    'logicalRecords',
    'independentCellCopiesPerLogicalRecord',
    'replicaProtocolMeasured',
    'attemptedCellWrites',
    'contentBytesPerRecord',
    'concurrency'
  ], 'load')
  const logicalRecords = safeInteger(report.load.logicalRecords, 1, 250000, 'load.logicalRecords')
  if (report.load.independentCellCopiesPerLogicalRecord !== relayCount) {
    fail('independent CELL copy count must equal relayInstances')
  }
  if (report.load.replicaProtocolMeasured !== false) {
    fail('independent CELL copies must not be represented as a measured replica protocol')
  }
  const attempted = safeInteger(report.load.attemptedCellWrites, 1, Number.MAX_SAFE_INTEGER, 'load.attemptedCellWrites')
  if (attempted !== relayCount * logicalRecords) fail('attemptedCellWrites must equal relayInstances * logicalRecords')
  safeInteger(report.load.contentBytesPerRecord, 32, 4000, 'load.contentBytesPerRecord')
  safeInteger(report.load.concurrency, 1, 128, 'load.concurrency')

  exactKeys(report.metrics, ['qualification', 'stagedCellPut', 'publicCellGet', 'recoveredPublicCellGet'], 'metrics')
  metricSummary(report.metrics.qualification, 'metrics.qualification', false)
  metricSummary(report.metrics.stagedCellPut, 'metrics.stagedCellPut', true)
  metricSummary(report.metrics.publicCellGet, 'metrics.publicCellGet', true)
  metricSummary(report.metrics.recoveredPublicCellGet, 'metrics.recoveredPublicCellGet', true)
  if (report.metrics.qualification.count !== relayCount * 3) fail('qualification count must cover PUT/GET and recovered GET per relay')

  exactKeys(report.integrity, [
    'contentChecksBeforeRestart',
    'contentChecksAfterRestart',
    'exactStoreCountsBeforeRestart',
    'exactStoreCountsAfterRestart',
    'allCountsExact',
    'uniqueRelaySigningKeys',
    'uniqueStoreIds',
    'deterministicLogicalCorpus',
    'independentlyAllocatedLogicalRecords',
    'allCopiesIndependentlyAllocatedAndEncrypted',
    'replicaProtocolMeasured',
    'ordinaryClientQualificationSucceeded',
    'qualificationAttempts'
  ], 'integrity')
  safeInteger(report.integrity.contentChecksBeforeRestart, 0, attempted, 'integrity.contentChecksBeforeRestart')
  safeInteger(report.integrity.contentChecksAfterRestart, 0, attempted, 'integrity.contentChecksAfterRestart')
  const beforeCounts = storeCountRows(
    report.integrity.exactStoreCountsBeforeRestart,
    relayCount,
    logicalRecords,
    'integrity.exactStoreCountsBeforeRestart'
  )
  const afterCounts = storeCountRows(
    report.integrity.exactStoreCountsAfterRestart,
    relayCount,
    logicalRecords,
    'integrity.exactStoreCountsAfterRestart'
  )
  const allCountsExact = [...beforeCounts.values(), ...afterCounts.values()].every(row => row.exact)
  if (report.integrity.allCountsExact !== allCountsExact) fail('integrity.allCountsExact is inconsistent')
  for (let index = 0; index < relayCount; index++) {
    if (beforeCounts.get(index).storedBytes !== afterCounts.get(index).storedBytes) {
      fail(`stored payload bytes changed across restart for relay ${index}`)
    }
  }
  safeInteger(report.integrity.uniqueRelaySigningKeys, 0, relayCount, 'integrity.uniqueRelaySigningKeys')
  safeInteger(report.integrity.uniqueStoreIds, 0, relayCount, 'integrity.uniqueStoreIds')
  if (report.scope.independentRelaySigningKeys !== report.integrity.uniqueRelaySigningKeys) {
    fail('scope.independentRelaySigningKeys is inconsistent with observed relay identities')
  }
  if (report.integrity.deterministicLogicalCorpus !== true || report.integrity.replicaProtocolMeasured !== false) {
    fail('integrity corpus and replica-protocol boundary are inconsistent')
  }
  const independentRecords = safeInteger(
    report.integrity.independentlyAllocatedLogicalRecords,
    0,
    logicalRecords,
    'integrity.independentlyAllocatedLogicalRecords'
  )
  const independentCopies = independentRecords === logicalRecords
  if (report.integrity.allCopiesIndependentlyAllocatedAndEncrypted !== independentCopies ||
      report.scope.independentlyEncryptedCellCopies !== independentCopies) {
    fail('independently encrypted copy claims are inconsistent with observed logical records')
  }
  if (!Array.isArray(report.integrity.qualificationAttempts) ||
      report.integrity.qualificationAttempts.length !== relayCount * 3) {
    fail('integrity.qualificationAttempts must contain PUT/GET and recovered GET per relay')
  }
  const expectedQualificationPhases = new Set()
  for (let relayIndex = 0; relayIndex < relayCount; relayIndex++) {
    expectedQualificationPhases.add(`${relayIndex}:initial-put`)
    expectedQualificationPhases.add(`${relayIndex}:initial-get`)
    expectedQualificationPhases.add(`${relayIndex}:recovered-get`)
  }
  for (const attempt of report.integrity.qualificationAttempts) {
    exactKeys(attempt, ['relayIndex', 'phase', 'qualified', 'code', 'message'], 'integrity.qualificationAttempts[]')
    const relayIndex = safeInteger(
      attempt.relayIndex,
      0,
      relayCount - 1,
      'integrity.qualificationAttempts[].relayIndex'
    )
    if (typeof attempt.phase !== 'string' || attempt.qualified !== true || attempt.code !== null ||
        attempt.message !== null) fail('qualification attempt must record an exact successful outcome')
    const key = `${relayIndex}:${attempt.phase}`
    if (!expectedQualificationPhases.delete(key)) {
      fail('qualification attempts contain an unknown or duplicate relay phase')
    }
  }
  if (expectedQualificationPhases.size !== 0) {
    fail('qualification attempts are missing a required relay phase')
  }
  if (report.integrity.ordinaryClientQualificationSucceeded !== true) {
    fail('ordinaryClientQualificationSucceeded must be proven by every qualification attempt')
  }

  exactKeys(report.recovery, [
    'relaysStopped',
    'relaysRestarted',
    'cleanStopWallMs',
    'restartAndRecoveryWallMs',
    'retainedStateReadChecks',
    'diskBytesStableAcrossRestart',
    'initialV2WriteStartupQuarantineObserved',
    'initialV2WritePathReadyBeforeWrites',
    'initialV2WriteReadinessWaitMs',
    'restartV2WriteStartupQuarantineObserved',
    'restartV2WritePathReadyBeforeWrites',
    'restartV2WriteReadinessWaitMs',
    'restartV2PublicHttpsExactPutAttempts',
    'restartV2RetainedReadChecks'
  ], 'recovery')
  if (report.recovery.relaysStopped !== relayCount || report.recovery.relaysRestarted !== relayCount) {
    fail('recovery stop/restart counts must equal relayInstances')
  }
  finiteNumber(report.recovery.cleanStopWallMs, 0, 'recovery.cleanStopWallMs')
  finiteNumber(report.recovery.restartAndRecoveryWallMs, 0, 'recovery.restartAndRecoveryWallMs')
  if (report.recovery.initialV2WriteStartupQuarantineObserved !== true ||
      report.recovery.initialV2WritePathReadyBeforeWrites !== true ||
      report.recovery.restartV2WriteStartupQuarantineObserved !== true ||
      report.recovery.restartV2WritePathReadyBeforeWrites !== true) {
    fail('recovery must retain the observed V2 replay-journal quarantine and pre-write readiness evidence')
  }
  finiteNumber(report.recovery.initialV2WriteReadinessWaitMs, 0, 'recovery.initialV2WriteReadinessWaitMs')
  finiteNumber(report.recovery.restartV2WriteReadinessWaitMs, 0, 'recovery.restartV2WriteReadinessWaitMs')
  if (report.recovery.restartV2PublicHttpsExactPutAttempts !== relayCount ||
      report.recovery.restartV2RetainedReadChecks !== relayCount) {
    fail('recovery must prove one exact public V2 CELL.PUT and retained read per restarted relay')
  }
  if (report.recovery.retainedStateReadChecks !== report.metrics.recoveredPublicCellGet.count) {
    fail('recovery.retainedStateReadChecks is inconsistent with recovered reads')
  }

  exactKeys(report.resources, [
    'processRssBytesBefore',
    'processRssBytesAfterWrite',
    'processRssBytesAfterRestart',
    'processRssDeltaBytes',
    'perRelayRssUnavailableReason',
    'storesBeforeRestart',
    'storesAfterRestart',
    'aggregateStoredPayloadBytes'
  ], 'resources')
  safeInteger(report.resources.processRssBytesBefore, 0, Number.MAX_SAFE_INTEGER, 'resources.processRssBytesBefore')
  safeInteger(report.resources.processRssBytesAfterWrite, 0, Number.MAX_SAFE_INTEGER, 'resources.processRssBytesAfterWrite')
  safeInteger(report.resources.processRssBytesAfterRestart, 0, Number.MAX_SAFE_INTEGER, 'resources.processRssBytesAfterRestart')
  if (!Number.isSafeInteger(report.resources.processRssDeltaBytes) ||
      report.resources.processRssDeltaBytes !== report.resources.processRssBytesAfterRestart - report.resources.processRssBytesBefore) {
    fail('resources.processRssDeltaBytes is inconsistent')
  }
  if (report.resources.perRelayRssUnavailableReason !== 'RELAYS_SHARE_ONE_NODE_PROCESS') {
    fail('resources.perRelayRssUnavailableReason must retain the process-isolation limitation')
  }
  const diskBefore = diskRows(report.resources.storesBeforeRestart, relayCount, 'resources.storesBeforeRestart')
  const diskAfter = diskRows(report.resources.storesAfterRestart, relayCount, 'resources.storesAfterRestart')
  const diskStable = [...diskBefore].every(([index, row]) => diskAfter.get(index).bytes === row.bytes)
  if (report.recovery.diskBytesStableAcrossRestart !== diskStable) {
    fail('recovery.diskBytesStableAcrossRestart is inconsistent with store resources')
  }
  const aggregateStoredPayloadBytes = [...beforeCounts.values()].reduce((sum, row) => sum + row.storedBytes, 0)
  if (report.resources.aggregateStoredPayloadBytes !== aggregateStoredPayloadBytes) {
    fail('resources.aggregateStoredPayloadBytes is inconsistent with store counts')
  }

  if (!Array.isArray(report.runtimeErrors)) fail('runtimeErrors must be an array')
  for (const error of report.runtimeErrors) {
    exactKeys(error, ['code', 'message'], 'runtimeErrors[]')
    if ((error.code !== null && typeof error.code !== 'string') || typeof error.message !== 'string') {
      fail('runtimeErrors entries have invalid types')
    }
  }
  return { relayCount, logicalRecords, attempted, independentCopies }
}

function performanceChecks (report) {
  exactAuthority(
    report.gates.performance.thresholds,
    REAL_BLIND_RELAY_LOCAL_PERFORMANCE_THRESHOLDS,
    'gates.performance.thresholds'
  )
  const thresholds = REAL_BLIND_RELAY_LOCAL_PERFORMANCE_THRESHOLDS
  const staged = report.metrics.stagedCellPut
  const get = report.metrics.publicCellGet
  const recovered = report.metrics.recoveredPublicCellGet
  return {
    sufficientOperationSample: staged.count >= thresholds.minimumOperationsPerPath &&
      get.count >= thresholds.minimumOperationsPerPath && recovered.count >= thresholds.minimumOperationsPerPath,
    stagedPutThroughput: staged.operationsPerSecond >= thresholds.stagedPutMinimumOperationsPerSecond,
    stagedPutP99: staged.p99Ms <= thresholds.stagedPutMaximumP99Millis,
    publicGetThroughput: get.operationsPerSecond >= thresholds.publicGetMinimumOperationsPerSecond,
    publicGetP99: get.p99Ms <= thresholds.publicGetMaximumP99Millis,
    recoveredGetThroughput: recovered.operationsPerSecond >= thresholds.recoveredGetMinimumOperationsPerSecond,
    recoveredGetP99: recovered.p99Ms <= thresholds.recoveredGetMaximumP99Millis,
    restartRecoveryWall: report.recovery.restartAndRecoveryWallMs <= thresholds.restartRecoveryMaximumWallMillis
  }
}

export function verifyRealBlindRelayReport (report, options = {}) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) fail('report must be an object')
  validateFixedBoundary(report)
  if (typeof report.evidenceDigest !== 'string' || !/^[0-9a-f]{64}$/.test(report.evidenceDigest)) {
    fail('evidenceDigest must be a lowercase sha256 checksum')
  }
  const expectedDigest = realBlindRelayReportDigest(report)
  if (!timingSafeEqual(Buffer.from(report.evidenceDigest, 'hex'), Buffer.from(expectedDigest, 'hex'))) {
    fail('evidence checksum mismatch')
  }
  const measured = validateMeasuredRelationships(report)

  exactKeys(report.gates, ['correctness', 'performance'], 'gates')
  exactKeys(report.gates.correctness, ['ready', 'claimClass', 'checks'], 'gates.correctness')
  exactKeys(report.gates.performance, [
    'ready',
    'claimClass',
    'capacityClaim',
    'serviceLevelObjectiveClaim',
    'thresholds',
    'checks'
  ], 'gates.performance')
  exactAuthority(report.gates.correctness.claimClass, 'LOCAL_CORRECTNESS_ONLY', 'gates.correctness.claimClass')
  exactAuthority(
    report.gates.performance.claimClass,
    'LOCAL_LOOPBACK_SMOKE_NOT_CAPACITY_OR_SLO',
    'gates.performance.claimClass'
  )
  exactAuthority(report.gates.performance.capacityClaim, false, 'gates.performance.capacityClaim')
  exactAuthority(
    report.gates.performance.serviceLevelObjectiveClaim,
    false,
    'gates.performance.serviceLevelObjectiveClaim'
  )

  const attempted = measured.attempted
  const correctness = {
    exactStoreCounts: report.integrity.allCountsExact === true,
    stableDiskBytesAcrossRestart: report.recovery.diskBytesStableAcrossRestart === true,
    noRuntimeErrors: report.runtimeErrors.length === 0,
    allStagedWritesCompleted: report.metrics.stagedCellPut.count === attempted,
    allPublicReadsCompleted: report.metrics.publicCellGet.count === attempted &&
      report.integrity.contentChecksBeforeRestart === attempted,
    allRecoveredReadsCompleted: report.metrics.recoveredPublicCellGet.count === attempted &&
      report.integrity.contentChecksAfterRestart === attempted,
    restartV2WriteRecoveryObserved: report.recovery.restartV2WriteStartupQuarantineObserved === true &&
      report.recovery.restartV2WritePathReadyBeforeWrites === true &&
      report.recovery.restartV2PublicHttpsExactPutAttempts === measured.relayCount &&
      report.recovery.restartV2RetainedReadChecks === measured.relayCount,
    ordinaryClientQualificationSucceeded: report.integrity.ordinaryClientQualificationSucceeded === true,
    independentRelayIdentitiesObserved: report.integrity.uniqueRelaySigningKeys === measured.relayCount,
    independentStoreIdsObserved: report.integrity.uniqueStoreIds === measured.relayCount,
    independentCopiesObserved: measured.independentCopies
  }
  const measuredPerformance = performanceChecks(report)
  exactChecks(report.gates.correctness.checks, correctness, 'correctness')
  exactChecks(report.gates.performance.checks, measuredPerformance, 'performance')
  const correctnessReady = Object.values(correctness).every(Boolean)
  const performanceReady = Object.values(measuredPerformance).every(Boolean)
  if (report.gates.correctness.ready !== correctnessReady || report.correctnessGateReady !== correctnessReady) {
    fail('correctness gate result is inconsistent')
  }
  if (report.gates.performance.ready !== performanceReady || report.performanceGateReady !== performanceReady) {
    fail('performance gate result is inconsistent')
  }
  if (report.localGateReady !== (correctnessReady && performanceReady)) fail('localGateReady must require both local gates')
  exactAuthority(
    report.blockers,
    realBlindRelayExpectedBlockers({ correctnessReady, performanceReady }),
    'blockers'
  )
  if (options.requireCorrectness === true && !correctnessReady) fail('correctness gate is not ready')
  if (options.requirePerformance === true && !performanceReady) fail('performance gate is not ready')
  return Object.freeze({
    verified: true,
    checksumVerified: true,
    checksumOnly: true,
    contentAddress: `sha256:${report.evidenceDigest}`,
    authenticityProven: false,
    authorizesRelease: false,
    correctnessReady,
    performanceReady,
    releaseReady: false
  })
}

function parseCli (argv) {
  const options = {}
  for (let index = 0; index < argv.length; index++) {
    const value = argv[index]
    if (value === '--input') options.input = argv[++index]
    else if (value === '--require-correctness') options.requireCorrectness = true
    else if (value === '--require-performance') options.requirePerformance = true
    else if (value === '--pretty') options.pretty = true
    else fail(`unknown argument ${value}`)
  }
  if (!options.input) fail('--input is required')
  return options
}

async function main () {
  const options = parseCli(process.argv.slice(2))
  const input = path.resolve(options.input)
  const stat = await fs.stat(input)
  if (!stat.isFile() || stat.size > 64 * 1024 * 1024) fail('input must be a report file no larger than 64 MiB')
  const report = JSON.parse(await fs.readFile(input, 'utf8'))
  const result = verifyRealBlindRelayReport(report, options)
  process.stdout.write(JSON.stringify(result, null, options.pretty ? 2 : 0) + '\n')
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] || '')) {
  main().catch(error => {
    process.stderr.write(`[verify-blind-real-relay-report] ${error.code || 'ERROR'}: ${error.message}\n`)
    process.exitCode = 1
  })
}
