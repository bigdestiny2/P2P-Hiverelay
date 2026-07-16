#!/usr/bin/env node
import { createHash, timingSafeEqual } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  REAL_BLIND_RELAY_CANONICALIZATION,
  canonicalRealBlindRelayReportJson,
  verifyRealBlindRelayReport
} from './verify-real-blind-relay-report.mjs'

export const LOCAL_MULTIPROCESS_BLIND_CHILD_SCHEMA =
  'hiverelay.blind.local-multiprocess-child.v1'
export const LOCAL_MULTIPROCESS_BLIND_REPORT_SCHEMA =
  'hiverelay.blind.local-multiprocess-relay-lab.v1'
export const LOCAL_MULTIPROCESS_BLIND_MANDATORY_BLOCKERS = Object.freeze([
  'CHECKSUM_ONLY_NOT_AUTHENTICATED_EVIDENCE',
  'SAME_HOST_LOCAL_PROCESSES',
  'SAME_UID_TEST_TOPOLOGY',
  'LOGICAL_OPERATOR_SCOPES_NOT_INDEPENDENT_OWNERSHIP',
  'SYNTHETIC_ADMISSION_NO_ECONOMIC_SETTLEMENT',
  'PRODUCTION_RELEASE_GATE_BYPASSED',
  'INDEPENDENT_OPERATOR_FAILURE_DOMAINS_UNMEASURED',
  'MULTI_HOST_NETWORK_UNMEASURED',
  'PUBLIC_CA_TLS_VALIDATION_UNMEASURED',
  'INTERNET_LATENCY_AND_PACKET_LOSS_UNMEASURED',
  'MULTI_RELAY_REPLICATION_REPAIR_PROTOCOL_UNMEASURED',
  'RELAY_CHURN_AND_PARTITION_UNMEASURED',
  'LONG_DURATION_SOAK_UNMEASURED',
  'CRASH_KILL_DURING_COMMIT_UNMEASURED',
  'DISK_FULL_AND_CORRUPTION_INJECTION_UNMEASURED',
  'RESOURCE_SATURATION_UNMEASURED',
  'SIGNED_RELEASE_AND_ROLLBACK_UNMEASURED'
])

const EMPTY_SHA256 = createHash('sha256').update('').digest('hex')
const CHILD_ROOT_KEYS = Object.freeze([
  'evidenceDigest',
  'generatedAt',
  'identity',
  'labReport',
  'process',
  'schema',
  'source'
])
const REPORT_ROOT_KEYS = Object.freeze([
  'blockers',
  'children',
  'correctnessGateReady',
  'evidenceBinding',
  'evidenceClass',
  'evidenceDigest',
  'gates',
  'generatedAt',
  'localGateReady',
  'processExecution',
  'releaseReady',
  'schema',
  'scope',
  'sourceCommit',
  'summary',
  'workload'
])

function fail (message) {
  const error = new Error(message)
  error.code = 'BLIND_LOCAL_MULTIPROCESS_REPORT_INVALID'
  throw error
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

function boolean (value, field) {
  if (typeof value !== 'boolean') fail(`${field} must be boolean`)
  return value
}

function lowerHex (value, bytes, field) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) {
    fail(`${field} must be ${bytes}-byte lowercase hex`)
  }
  return value
}

function scopeName (value, field) {
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(value)) {
    fail(`${field} must match ^[a-z0-9][a-z0-9-]{0,63}$`)
  }
  return value
}

function isoMillis (value, field) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value)) ||
      new Date(value).toISOString() !== value) {
    fail(`${field} must be a canonical ISO timestamp`)
  }
  return Date.parse(value)
}

function exactArray (actual, expected, field) {
  if (!Array.isArray(actual) || JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${field} is inconsistent with measured evidence`)
  }
}

function exactObject (actual, expected, field) {
  exactKeys(actual, Object.keys(expected), field)
  for (const [key, value] of Object.entries(expected)) {
    if (Array.isArray(value)) exactArray(actual[key], value, `${field}.${key}`)
    else if (value && typeof value === 'object') exactObject(actual[key], value, `${field}.${key}`)
    else if (actual[key] !== value) fail(`${field}.${key} is inconsistent with measured evidence`)
  }
}

function uniqueCount (values) {
  return new Set(values).size
}

function checksum (value) {
  return createHash('sha256').update(value).digest('hex')
}

function reportBody (report) {
  record(report, 'report')
  const body = { ...report }
  delete body.evidenceDigest
  return body
}

function digestReport (report) {
  return checksum(canonicalRealBlindRelayReportJson(reportBody(report)))
}

function assertDigest (report, field = 'evidenceDigest') {
  lowerHex(report.evidenceDigest, 32, field)
  const expected = digestReport(report)
  if (!timingSafeEqual(Buffer.from(report.evidenceDigest, 'hex'), Buffer.from(expected, 'hex'))) {
    fail(`${field} checksum mismatch`)
  }
}

export function sealLocalMultiprocessBlindChild (body) {
  record(body, 'child body')
  if (Object.hasOwn(body, 'evidenceDigest')) fail('child body must not contain evidenceDigest before sealing')
  const report = { ...body }
  return Object.freeze({ ...report, evidenceDigest: digestReport(report) })
}

export function sealLocalMultiprocessBlindReport (body) {
  record(body, 'aggregate body')
  if (Object.hasOwn(body, 'evidenceDigest')) fail('aggregate body must not contain evidenceDigest before sealing')
  const report = { ...body }
  return Object.freeze({ ...report, evidenceDigest: digestReport(report) })
}

function validateEvidenceBinding (binding) {
  exactObject(binding, {
    algorithm: 'sha256',
    canonicalization: REAL_BLIND_RELAY_CANONICALIZATION,
    checksumOnly: true,
    signed: false,
    authenticityProven: false
  }, 'evidenceBinding')
}

export function verifyLocalMultiprocessBlindChild (child, options = {}) {
  exactKeys(child, CHILD_ROOT_KEYS, 'child')
  if (child.schema !== LOCAL_MULTIPROCESS_BLIND_CHILD_SCHEMA) {
    fail(`unsupported child schema ${JSON.stringify(child.schema)}`)
  }
  const generatedAtMillis = isoMillis(child.generatedAt, 'child.generatedAt')
  assertDigest(child, 'child.evidenceDigest')

  exactKeys(child.source, ['gitCommit', 'trackedWorktreeClean'], 'child.source')
  lowerHex(child.source.gitCommit, 20, 'child.source.gitCommit')
  boolean(child.source.trackedWorktreeClean, 'child.source.trackedWorktreeClean')

  exactKeys(child.process, [
    'finishedAt',
    'gid',
    'identityScope',
    'logicalOperatorScope',
    'parentPid',
    'pid',
    'rootPathSha256',
    'startedAt',
    'uid',
    'wallMs'
  ], 'child.process')
  const pid = safeInteger(child.process.pid, 1, Number.MAX_SAFE_INTEGER, 'child.process.pid')
  safeInteger(child.process.parentPid, 1, Number.MAX_SAFE_INTEGER, 'child.process.parentPid')
  safeInteger(child.process.uid, 0, Number.MAX_SAFE_INTEGER, 'child.process.uid')
  safeInteger(child.process.gid, 0, Number.MAX_SAFE_INTEGER, 'child.process.gid')
  scopeName(child.process.logicalOperatorScope, 'child.process.logicalOperatorScope')
  const identityScope = scopeName(child.process.identityScope, 'child.process.identityScope')
  lowerHex(child.process.rootPathSha256, 32, 'child.process.rootPathSha256')
  const startedAtMillis = isoMillis(child.process.startedAt, 'child.process.startedAt')
  const finishedAtMillis = isoMillis(child.process.finishedAt, 'child.process.finishedAt')
  if (finishedAtMillis < startedAtMillis) fail('child process finished before it started')
  if (generatedAtMillis !== finishedAtMillis) fail('child.generatedAt must equal child.process.finishedAt')
  if (child.process.wallMs !== finishedAtMillis - startedAtMillis) {
    fail('child.process.wallMs is inconsistent with its timestamps')
  }

  exactKeys(child.identity, [
    'identityScope',
    'relayCount',
    'relayPublicKeys',
    'storeIds',
    'uniqueRelayPublicKeys',
    'uniqueStoreIds'
  ], 'child.identity')
  if (child.identity.identityScope !== identityScope) fail('child identity scope does not match process scope')
  const relayCount = safeInteger(child.identity.relayCount, 2, 8, 'child.identity.relayCount')
  for (const [field, values] of [
    ['relayPublicKeys', child.identity.relayPublicKeys],
    ['storeIds', child.identity.storeIds]
  ]) {
    if (!Array.isArray(values) || values.length !== relayCount) {
      fail(`child.identity.${field} must contain one value per relay`)
    }
    values.forEach((value, index) => lowerHex(value, 32, `child.identity.${field}[${index}]`))
  }
  const uniqueRelayPublicKeys = uniqueCount(child.identity.relayPublicKeys)
  const uniqueStoreIds = uniqueCount(child.identity.storeIds)
  if (child.identity.uniqueRelayPublicKeys !== uniqueRelayPublicKeys ||
      child.identity.uniqueStoreIds !== uniqueStoreIds) {
    fail('child identity uniqueness counts are inconsistent')
  }
  if (uniqueRelayPublicKeys !== relayCount || uniqueStoreIds !== relayCount) {
    fail('child relay signing keys and store IDs must be unique')
  }

  const labVerification = verifyRealBlindRelayReport(child.labReport, { requireCorrectness: true })
  if (child.labReport.scope.relayInstances !== relayCount) {
    fail('child identity count does not match the real relay report')
  }
  if (options.expectedPid != null && pid !== options.expectedPid) fail('child PID differs from supervisor observation')
  if (options.expectedParentPid != null && child.process.parentPid !== options.expectedParentPid) {
    fail('child parent PID differs from supervisor PID')
  }
  if (options.expectedGitCommit != null && child.source.gitCommit !== options.expectedGitCommit) {
    fail('child source commit differs from supervisor source commit')
  }
  if (options.requireCleanSource === true && child.source.trackedWorktreeClean !== true) {
    fail('child tracked source is not clean')
  }
  return Object.freeze({
    verified: true,
    checksumVerified: true,
    checksumOnly: true,
    authenticityProven: false,
    authorizesRelease: false,
    correctnessReady: labVerification.correctnessReady,
    performanceReady: labVerification.performanceReady,
    pid,
    gitCommit: child.source.gitCommit,
    trackedWorktreeClean: child.source.trackedWorktreeClean
  })
}

function latencyAggregate (children, metric) {
  const rows = children.map(child => child.envelope.labReport.metrics[metric])
  const count = rows.reduce((sum, row) => sum + row.count, 0)
  const weightedMean = rows.reduce((sum, row) => sum + row.meanMs * row.count, 0) / count
  return {
    count,
    weightedMeanMs: Number(weightedMean.toFixed(3)),
    maximumChildP99Ms: Number(Math.max(...rows.map(row => row.p99Ms)).toFixed(3)),
    maximumObservedMs: Number(Math.max(...rows.map(row => row.maxMs)).toFixed(3)),
    minimumChildOperationsPerSecond: Number(
      Math.min(...rows.map(row => row.operationsPerSecond)).toFixed(3)
    )
  }
}

function expectedSummary (children) {
  const reports = children.map(child => child.envelope.labReport)
  const beforeRows = reports.flatMap(report => report.integrity.exactStoreCountsBeforeRestart)
  const afterRows = reports.flatMap(report => report.integrity.exactStoreCountsAfterRestart)
  const relayPublicKeys = children.flatMap(child => child.envelope.identity.relayPublicKeys)
  const storeIds = children.flatMap(child => child.envelope.identity.storeIds)
  return {
    childLabEvidenceDigests: reports.map(report => report.evidenceDigest),
    childEnvelopeEvidenceDigests: children.map(child => child.envelope.evidenceDigest),
    sourceCommits: children.map(child => child.envelope.source.gitCommit),
    totalRelayInstances: reports.reduce((sum, report) => sum + report.scope.relayInstances, 0),
    totalAttemptedCellWrites: reports.reduce((sum, report) => sum + report.load.attemptedCellWrites, 0),
    totalPublicReadChecks: reports.reduce((sum, report) =>
      sum + report.integrity.contentChecksBeforeRestart, 0),
    totalRecoveredReadChecks: reports.reduce((sum, report) =>
      sum + report.integrity.contentChecksAfterRestart, 0),
    totalRelaysStopped: reports.reduce((sum, report) => sum + report.recovery.relaysStopped, 0),
    totalRelaysRestarted: reports.reduce((sum, report) => sum + report.recovery.relaysRestarted, 0),
    totalExpectedStoreRecordsBeforeRestart: beforeRows.reduce((sum, row) =>
      sum + row.expectedCellRecords, 0),
    totalActualStoreRecordsBeforeRestart: beforeRows.reduce((sum, row) =>
      sum + row.actualCellRecords, 0),
    totalExpectedStoreRecordsAfterRestart: afterRows.reduce((sum, row) =>
      sum + row.expectedCellRecords, 0),
    totalActualStoreRecordsAfterRestart: afterRows.reduce((sum, row) =>
      sum + row.actualCellRecords, 0),
    allStoreCountsExact: [...beforeRows, ...afterRows].every(row => row.exact === true),
    globalUniqueRelaySigningKeys: uniqueCount(relayPublicKeys),
    globalUniqueStoreIds: uniqueCount(storeIds),
    latencies: {
      stagedCellPut: latencyAggregate(children, 'stagedCellPut'),
      publicCellGet: latencyAggregate(children, 'publicCellGet'),
      recoveredPublicCellGet: latencyAggregate(children, 'recoveredPublicCellGet')
    },
    childBlockers: [...new Set(reports.flatMap(report => report.blockers))].sort()
  }
}

function expectedCorrectnessChecks (report, childResults, summary) {
  const processCount = report.workload.processCount
  const allKeys = report.children.flatMap(child => child.envelope.identity.relayPublicKeys)
  const allStoreIds = report.children.flatMap(child => child.envelope.identity.storeIds)
  return {
    allChildEnvelopesVerified: childResults.length === processCount &&
      childResults.every(result => result.verified === true),
    allChildCorrectnessGatesReady: report.children.every(child =>
      child.envelope.labReport.correctnessGateReady === true),
    allChildrenExitedZero: report.children.every(child => child.exitCode === 0),
    noChildSignals: report.children.every(child => child.signal === null),
    uniqueChildPids: report.processExecution.uniqueChildPids === processCount,
    parentPidIsolationObserved: report.children.every(child =>
      child.envelope.process.parentPid === report.processExecution.supervisorPid &&
      child.observedPid === child.envelope.process.pid &&
      child.observedPid !== report.processExecution.supervisorPid),
    sameUidAndGidObserved: report.children.every(child =>
      child.envelope.process.uid === report.processExecution.supervisorUid &&
      child.envelope.process.gid === report.processExecution.supervisorGid),
    concurrentExecutionObserved: report.processExecution.concurrentOverlapObserved === true &&
      report.processExecution.concurrentOverlapMillis > 0,
    uniqueLogicalOperatorScopes: uniqueCount(report.children.map(child =>
      child.envelope.process.logicalOperatorScope)) === processCount,
    uniqueIdentityScopes: uniqueCount(report.children.map(child =>
      child.envelope.process.identityScope)) === processCount,
    globalRelaySigningKeysUnique: uniqueCount(allKeys) === summary.totalRelayInstances,
    globalStoreIdsUnique: uniqueCount(allStoreIds) === summary.totalRelayInstances,
    exactWrites: summary.totalAttemptedCellWrites === report.workload.expectedCellWrites,
    exactReadsBeforeRestart: summary.totalPublicReadChecks === report.workload.expectedCellWrites,
    exactReadsAfterRestart: summary.totalRecoveredReadChecks === report.workload.expectedCellWrites,
    exactRestarts: summary.totalRelaysStopped === report.workload.totalRelayInstances &&
      summary.totalRelaysRestarted === report.workload.totalRelayInstances,
    exactStoreCounts: summary.allStoreCountsExact === true &&
      summary.totalActualStoreRecordsBeforeRestart ===
        summary.totalExpectedStoreRecordsBeforeRestart &&
      summary.totalActualStoreRecordsAfterRestart ===
        summary.totalExpectedStoreRecordsAfterRestart,
    noChildRuntimeErrors: report.children.every(child =>
      child.envelope.labReport.runtimeErrors.length === 0),
    sourceCommitConsistent: report.children.every(child =>
      child.envelope.source.gitCommit === report.sourceCommit)
  }
}

function expectedReproducibilityChecks (report) {
  return {
    allTrackedSourceClean: report.children.every(child =>
      child.envelope.source.trackedWorktreeClean === true),
    childStdoutDigestsExact: report.children.every(child =>
      child.stdoutSha256 === checksum(JSON.stringify(child.envelope) + '\n')),
    childStderrEmpty: report.children.every(child =>
      child.stderrBytes === 0 && child.stderrSha256 === EMPTY_SHA256),
    exactChildCommitRecorded: report.children.every(child =>
      child.envelope.source.gitCommit === report.sourceCommit),
    exactChildEvidenceDigestsRecorded: JSON.stringify(report.summary.childLabEvidenceDigests) ===
      JSON.stringify(report.children.map(child => child.envelope.labReport.evidenceDigest))
  }
}

export function localMultiprocessBlindExpectedBlockers (report, correctnessReady, reproducibilityReady) {
  const childBlockers = report?.summary?.childBlockers || []
  const blockers = [...LOCAL_MULTIPROCESS_BLIND_MANDATORY_BLOCKERS]
  for (const blocker of childBlockers) if (!blockers.includes(blocker)) blockers.push(blocker)
  if (!correctnessReady) blockers.push('LOCAL_MULTIPROCESS_CORRECTNESS_GATE_NOT_MET')
  if (!reproducibilityReady) blockers.push('LOCAL_MULTIPROCESS_REPRODUCIBILITY_GATE_NOT_MET')
  if (report?.children?.some(child => child.envelope.source.trackedWorktreeClean !== true)) {
    blockers.push('TRACKED_SOURCE_DIRTY')
  }
  return Object.freeze(blockers)
}

export function buildLocalMultiprocessBlindReport (input) {
  record(input, 'aggregate input')
  if (!Array.isArray(input.children) || input.children.length < 3 || input.children.length > 8) {
    fail('aggregate input requires 3..8 child process records')
  }
  const processCount = input.children.length
  const relaysPerProcess = safeInteger(input.relaysPerProcess, 2, 8, 'relaysPerProcess')
  const recordsPerRelay = safeInteger(input.recordsPerRelay, 1, 250000, 'recordsPerRelay')
  const concurrencyPerProcess = safeInteger(input.concurrencyPerProcess, 1, 128,
    'concurrencyPerProcess')
  const contentBytes = safeInteger(input.contentBytes, 32, 4000, 'contentBytes')
  const sourceCommit = lowerHex(input.sourceCommit, 20, 'sourceCommit')
  const supervisorPid = safeInteger(input.supervisorPid, 1, Number.MAX_SAFE_INTEGER, 'supervisorPid')
  const supervisorUid = safeInteger(input.supervisorUid, 0, Number.MAX_SAFE_INTEGER, 'supervisorUid')
  const supervisorGid = safeInteger(input.supervisorGid, 0, Number.MAX_SAFE_INTEGER, 'supervisorGid')
  const earliestSpawn = Math.min(...input.children.map(child => child.observedSpawnUnixMillis))
  const latestSpawn = Math.max(...input.children.map(child => child.observedSpawnUnixMillis))
  const earliestExit = Math.min(...input.children.map(child => child.observedExitUnixMillis))
  const latestExit = Math.max(...input.children.map(child => child.observedExitUnixMillis))
  const overlap = Math.max(0, earliestExit - latestSpawn)
  const processExecution = {
    supervisorPid,
    supervisorUid,
    supervisorGid,
    uniqueChildPids: uniqueCount(input.children.map(child => child.observedPid)),
    observedWallMillis: latestExit - earliestSpawn,
    concurrentOverlapObserved: overlap > 0,
    concurrentOverlapMillis: overlap
  }
  const workload = {
    processCount,
    relaysPerProcess,
    recordsPerRelay,
    concurrencyPerProcess,
    contentBytes,
    totalRelayInstances: processCount * relaysPerProcess,
    expectedCellWrites: processCount * relaysPerProcess * recordsPerRelay
  }
  const summary = expectedSummary(input.children)
  const partial = {
    schema: LOCAL_MULTIPROCESS_BLIND_REPORT_SCHEMA,
    generatedAt: input.generatedAt || new Date().toISOString(),
    evidenceClass: 'MEASURED_LOCAL_MULTI_PROCESS_REAL_HTTP_IPC_FILESYSTEM',
    evidenceBinding: {
      algorithm: 'sha256',
      canonicalization: REAL_BLIND_RELAY_CANONICALIZATION,
      checksumOnly: true,
      signed: false,
      authenticityProven: false
    },
    releaseReady: false,
    sourceCommit,
    scope: {
      childProcessCount: processCount,
      logicalOperatorScopeProcesses: processCount,
      crossChildProcessIsolationMeasured: true,
      sameHost: true,
      sameUid: true,
      hostIsolationMeasured: false,
      claimedIndependentOperators: false,
      realIndependentOwnershipMeasured: false,
      multiHostNetworkMeasured: false,
      publicCaTlsValidationMeasured: false,
      syntheticAdmissionAdapter: true,
      economicSettlementMeasured: false,
      soakMeasured: false,
      transport: 'ephemeral self-signed loopback TLS plus authenticated same-UID Unix IPC'
    },
    workload,
    processExecution,
    summary,
    children: input.children
  }
  const childResults = input.children.map(child => verifyLocalMultiprocessBlindChild(child.envelope, {
    expectedPid: child.observedPid,
    expectedParentPid: supervisorPid,
    expectedGitCommit: sourceCommit
  }))
  const correctnessChecks = expectedCorrectnessChecks(partial, childResults, summary)
  const reproducibilityChecks = expectedReproducibilityChecks(partial)
  const correctnessReady = Object.values(correctnessChecks).every(Boolean)
  const reproducibilityReady = Object.values(reproducibilityChecks).every(Boolean)
  partial.gates = {
    correctness: {
      ready: correctnessReady,
      claimClass: 'LOCAL_MULTI_PROCESS_CORRECTNESS_ONLY',
      checks: correctnessChecks
    },
    reproducibility: {
      ready: reproducibilityReady,
      claimClass: 'COMMIT_BOUND_CHECKSUM_ONLY',
      checks: reproducibilityChecks
    }
  }
  partial.correctnessGateReady = correctnessReady
  partial.localGateReady = correctnessReady && reproducibilityReady
  partial.blockers = localMultiprocessBlindExpectedBlockers(
    partial,
    correctnessReady,
    reproducibilityReady
  )
  const report = sealLocalMultiprocessBlindReport(partial)
  verifyLocalMultiprocessBlindReport(report)
  return report
}

export function verifyLocalMultiprocessBlindReport (report, options = {}) {
  exactKeys(report, REPORT_ROOT_KEYS, 'report')
  if (report.schema !== LOCAL_MULTIPROCESS_BLIND_REPORT_SCHEMA) {
    fail(`unsupported aggregate schema ${JSON.stringify(report.schema)}`)
  }
  isoMillis(report.generatedAt, 'generatedAt')
  if (report.evidenceClass !== 'MEASURED_LOCAL_MULTI_PROCESS_REAL_HTTP_IPC_FILESYSTEM') {
    fail('evidenceClass exceeds or changes the local multi-process boundary')
  }
  validateEvidenceBinding(report.evidenceBinding)
  if (report.releaseReady !== false) fail('local multi-process evidence cannot authorize release')
  lowerHex(report.sourceCommit, 20, 'sourceCommit')
  assertDigest(report)

  exactKeys(report.scope, [
    'childProcessCount',
    'claimedIndependentOperators',
    'economicSettlementMeasured',
    'hostIsolationMeasured',
    'logicalOperatorScopeProcesses',
    'multiHostNetworkMeasured',
    'crossChildProcessIsolationMeasured',
    'publicCaTlsValidationMeasured',
    'realIndependentOwnershipMeasured',
    'sameHost',
    'sameUid',
    'soakMeasured',
    'syntheticAdmissionAdapter',
    'transport'
  ], 'scope')
  const processCount = safeInteger(report.scope.childProcessCount, 3, 8, 'scope.childProcessCount')
  exactObject(report.scope, {
    childProcessCount: processCount,
    logicalOperatorScopeProcesses: processCount,
    crossChildProcessIsolationMeasured: true,
    sameHost: true,
    sameUid: true,
    hostIsolationMeasured: false,
    claimedIndependentOperators: false,
    realIndependentOwnershipMeasured: false,
    multiHostNetworkMeasured: false,
    publicCaTlsValidationMeasured: false,
    syntheticAdmissionAdapter: true,
    economicSettlementMeasured: false,
    soakMeasured: false,
    transport: 'ephemeral self-signed loopback TLS plus authenticated same-UID Unix IPC'
  }, 'scope')

  exactKeys(report.workload, [
    'concurrencyPerProcess',
    'contentBytes',
    'expectedCellWrites',
    'processCount',
    'recordsPerRelay',
    'relaysPerProcess',
    'totalRelayInstances'
  ], 'workload')
  if (report.workload.processCount !== processCount) fail('workload process count is inconsistent')
  const relaysPerProcess = safeInteger(report.workload.relaysPerProcess, 2, 8,
    'workload.relaysPerProcess')
  const recordsPerRelay = safeInteger(report.workload.recordsPerRelay, 1, 250000,
    'workload.recordsPerRelay')
  safeInteger(report.workload.concurrencyPerProcess, 1, 128, 'workload.concurrencyPerProcess')
  safeInteger(report.workload.contentBytes, 32, 4000, 'workload.contentBytes')
  const totalRelayInstances = processCount * relaysPerProcess
  const expectedCellWrites = totalRelayInstances * recordsPerRelay
  if (report.workload.totalRelayInstances !== totalRelayInstances ||
      report.workload.expectedCellWrites !== expectedCellWrites) {
    fail('workload totals are inconsistent')
  }

  exactKeys(report.processExecution, [
    'concurrentOverlapMillis',
    'concurrentOverlapObserved',
    'observedWallMillis',
    'supervisorGid',
    'supervisorPid',
    'supervisorUid',
    'uniqueChildPids'
  ], 'processExecution')
  const supervisorPid = safeInteger(report.processExecution.supervisorPid, 1, Number.MAX_SAFE_INTEGER,
    'processExecution.supervisorPid')
  safeInteger(report.processExecution.supervisorUid, 0, Number.MAX_SAFE_INTEGER,
    'processExecution.supervisorUid')
  safeInteger(report.processExecution.supervisorGid, 0, Number.MAX_SAFE_INTEGER,
    'processExecution.supervisorGid')
  const uniqueChildPids = safeInteger(report.processExecution.uniqueChildPids, 1, processCount,
    'processExecution.uniqueChildPids')
  finiteNumber(report.processExecution.observedWallMillis, Number.EPSILON,
    'processExecution.observedWallMillis')
  finiteNumber(report.processExecution.concurrentOverlapMillis, 0,
    'processExecution.concurrentOverlapMillis')
  boolean(report.processExecution.concurrentOverlapObserved,
    'processExecution.concurrentOverlapObserved')

  if (!Array.isArray(report.children) || report.children.length !== processCount) {
    fail('children must contain one child record per process')
  }
  const seenIndexes = new Set()
  const childResults = []
  for (const child of report.children) {
    exactKeys(child, [
      'envelope',
      'exitCode',
      'observedExitUnixMillis',
      'observedPid',
      'observedSpawnUnixMillis',
      'processIndex',
      'signal',
      'stderrBytes',
      'stderrSha256',
      'stdoutSha256'
    ], 'children[]')
    const processIndex = safeInteger(child.processIndex, 0, processCount - 1, 'children[].processIndex')
    if (seenIndexes.has(processIndex)) fail('children contains a duplicate processIndex')
    seenIndexes.add(processIndex)
    const observedPid = safeInteger(child.observedPid, 1, Number.MAX_SAFE_INTEGER,
      `children[${processIndex}].observedPid`)
    const spawnMillis = safeInteger(child.observedSpawnUnixMillis, 0, Number.MAX_SAFE_INTEGER,
      `children[${processIndex}].observedSpawnUnixMillis`)
    const exitMillis = safeInteger(child.observedExitUnixMillis, spawnMillis, Number.MAX_SAFE_INTEGER,
      `children[${processIndex}].observedExitUnixMillis`)
    if (child.exitCode !== 0) fail(`children[${processIndex}] did not exit zero`)
    if (child.signal !== null) fail(`children[${processIndex}] exited due to a signal`)
    safeInteger(child.stderrBytes, 0, 64 * 1024 * 1024, `children[${processIndex}].stderrBytes`)
    lowerHex(child.stdoutSha256, 32, `children[${processIndex}].stdoutSha256`)
    lowerHex(child.stderrSha256, 32, `children[${processIndex}].stderrSha256`)
    const result = verifyLocalMultiprocessBlindChild(child.envelope, {
      expectedPid: observedPid,
      expectedParentPid: supervisorPid,
      expectedGitCommit: report.sourceCommit
    })
    const lab = child.envelope.labReport
    if (lab.scope.relayInstances !== relaysPerProcess ||
        lab.load.logicalRecords !== recordsPerRelay ||
        lab.load.concurrency !== report.workload.concurrencyPerProcess ||
        lab.load.contentBytesPerRecord !== report.workload.contentBytes) {
      fail(`children[${processIndex}] workload differs from the aggregate workload`)
    }
    const childStart = Date.parse(child.envelope.process.startedAt)
    const childFinish = Date.parse(child.envelope.process.finishedAt)
    if (childStart < spawnMillis || childFinish > exitMillis + 10) {
      fail(`children[${processIndex}] timestamps fall outside its observed process lifetime`)
    }
    childResults.push(result)
  }
  if (seenIndexes.size !== processCount) fail('children process indexes are incomplete')
  const observedUniquePids = uniqueCount(report.children.map(child => child.observedPid))
  if (uniqueChildPids !== observedUniquePids) fail('uniqueChildPids is inconsistent')
  const earliestSpawn = Math.min(...report.children.map(child => child.observedSpawnUnixMillis))
  const latestSpawn = Math.max(...report.children.map(child => child.observedSpawnUnixMillis))
  const earliestExit = Math.min(...report.children.map(child => child.observedExitUnixMillis))
  const latestExit = Math.max(...report.children.map(child => child.observedExitUnixMillis))
  const overlap = Math.max(0, earliestExit - latestSpawn)
  const wall = latestExit - earliestSpawn
  if (report.processExecution.concurrentOverlapMillis !== overlap ||
      report.processExecution.concurrentOverlapObserved !== (overlap > 0) ||
      report.processExecution.observedWallMillis !== wall) {
    fail('process execution timing summary is inconsistent')
  }

  const summary = expectedSummary(report.children)
  exactObject(report.summary, summary, 'summary')
  if (summary.totalRelayInstances !== totalRelayInstances) fail('summary relay count is inconsistent')

  exactKeys(report.gates, ['correctness', 'reproducibility'], 'gates')
  exactKeys(report.gates.correctness, ['checks', 'claimClass', 'ready'], 'gates.correctness')
  exactKeys(report.gates.reproducibility, ['checks', 'claimClass', 'ready'], 'gates.reproducibility')
  if (report.gates.correctness.claimClass !== 'LOCAL_MULTI_PROCESS_CORRECTNESS_ONLY') {
    fail('gates.correctness.claimClass exceeds the local boundary')
  }
  if (report.gates.reproducibility.claimClass !== 'COMMIT_BOUND_CHECKSUM_ONLY') {
    fail('gates.reproducibility.claimClass exceeds checksum evidence')
  }
  const correctnessChecks = expectedCorrectnessChecks(report, childResults, summary)
  const reproducibilityChecks = expectedReproducibilityChecks(report)
  exactObject(report.gates.correctness.checks, correctnessChecks, 'gates.correctness.checks')
  exactObject(report.gates.reproducibility.checks, reproducibilityChecks,
    'gates.reproducibility.checks')
  const correctnessReady = Object.values(correctnessChecks).every(Boolean)
  const reproducibilityReady = Object.values(reproducibilityChecks).every(Boolean)
  if (report.gates.correctness.ready !== correctnessReady ||
      report.correctnessGateReady !== correctnessReady) {
    fail('aggregate correctness gate result is inconsistent')
  }
  if (report.gates.reproducibility.ready !== reproducibilityReady) {
    fail('aggregate reproducibility gate result is inconsistent')
  }
  if (report.localGateReady !== (correctnessReady && reproducibilityReady)) {
    fail('localGateReady must require correctness and reproducibility')
  }
  exactArray(report.blockers,
    localMultiprocessBlindExpectedBlockers(report, correctnessReady, reproducibilityReady),
    'blockers')
  if (options.requireCorrectness === true && !correctnessReady) {
    fail('aggregate correctness gate is not ready')
  }
  if (options.requireLocal === true && !report.localGateReady) {
    fail('aggregate local multi-process gate is not ready')
  }
  return Object.freeze({
    verified: true,
    checksumVerified: true,
    checksumOnly: true,
    contentAddress: `sha256:${report.evidenceDigest}`,
    authenticityProven: false,
    authorizesRelease: false,
    claimsIndependentOperators: false,
    correctnessReady,
    reproducibilityReady,
    localGateReady: report.localGateReady,
    releaseReady: false
  })
}

function parseCli (argv) {
  const options = {}
  for (let index = 0; index < argv.length; index++) {
    const value = argv[index]
    if (value === '--input') options.input = argv[++index]
    else if (value === '--require-correctness') options.requireCorrectness = true
    else if (value === '--require-local') options.requireLocal = true
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
  if (!stat.isFile() || stat.size > 64 * 1024 * 1024) {
    fail('input must be a report file no larger than 64 MiB')
  }
  const report = JSON.parse(await fs.readFile(input, 'utf8'))
  const result = verifyLocalMultiprocessBlindReport(report, options)
  process.stdout.write(JSON.stringify(result, null, options.pretty ? 2 : 0) + '\n')
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] || '')) {
  main().catch(error => {
    process.stderr.write(`[verify-blind-local-multiprocess-report] ${error.code || 'ERROR'}: ${error.message}\n`)
    process.exitCode = 1
  })
}
