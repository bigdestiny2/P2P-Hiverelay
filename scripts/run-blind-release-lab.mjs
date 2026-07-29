#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { readFile, stat, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  assertBlindFleetEvidence,
  runBlindFleetSimulation,
  stableStringify,
  verifyBlindFleetEvidenceDigest
} from './simulate-blind-fleet.mjs'
import {
  DEFAULT_CAPACITY_LAB_CONFIG,
  normalizeCapacityLabConfig,
  runCapacityLab
} from './blind-capacity-lab.mjs'
import {
  evaluateLegacyRetirement,
  loadLegacyRetirementPolicy
} from './verify-blind-legacy-retirement-policy.mjs'
import {
  evaluateEcosystemMigration,
  loadEcosystemMigrationMatrix
} from './verify-blind-ecosystem-migration.mjs'
import {
  REAL_BLIND_RELAY_FAMILY_SCOPE,
  REAL_BLIND_RELAY_LOCAL_PERFORMANCE_THRESHOLDS,
  REAL_BLIND_RELAY_RUNTIME_EXCLUSIONS,
  realBlindRelayExpectedBlockers,
  verifyRealBlindRelayReport
} from './verify-real-blind-relay-report.mjs'
import {
  PRODUCTION_RUNTIME_EXCLUSIONS
} from '../packages/blind-daemon/production-runtime.js'
import { BLIND_CELL_RUNTIME_BLOCKERS } from '../packages/blind-daemon/cell-runtime-adapter.js'
import { BLIND_INBOX_RUNTIME_BLOCKERS } from '../packages/blind-daemon/inbox-runtime-adapter.js'
import { BLIND_CORE_RUNTIME_BLOCKERS } from '../packages/blind-daemon/core-runtime-adapter.js'
import { BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS } from '../packages/blind-daemon/storage-engine.js'

export const BLIND_RELEASE_LAB_SCHEMA = 'hiverelay/blind-release-lab/v2'

const MIB = 1024 * 1024
const MAX_EVIDENCE_FILE_BYTES = 64 * MIB
const DESKTOP_ENGINES = Object.freeze(['chromium', 'firefox', 'webkit'])
const LOCAL_GATE_IDS = Object.freeze([
  'JOURNAL_COUNT_EXACT',
  'INDEX_COUNT_EXACT',
  'JOURNAL_COMMIT_P99',
  'INDEX_BUILD_PROJECTED_100K',
  'FEED_READ_P99',
  'JOURNAL_VIEW_RANGE_PAGE_P99',
  'RETRY_TARGET_INDEX_LOCAL_FAIRNESS',
  'NODE_MEMORY_RSS_DELTA'
])

export const BLIND_RELEASE_LAB_PROFILES = Object.freeze({
  smoke: Object.freeze({
    fleet: Object.freeze({
      seed: 'blind-release-lab-smoke-v1',
      // Thirty seconds ended while half of the deliberately disrupted FORWARD
      // circuits were still active. Sixty seconds gives opened circuits a
      // complete lifecycle while remaining a bounded deterministic smoke run.
      durationSeconds: 60,
      relayCount: 12,
      operatorCount: 6,
      regionCount: 3,
      rateScale: 0.25
    }),
    peerit: Object.freeze({
      intents: 80,
      viewRecords: 800,
      communities: 20,
      pageSize: 31,
      maxCommitP99Ms: 1_000,
      maxIndexBuildMsPer100k: 60_000,
      maxFeedReadP99Ms: 1_000,
      maxViewPageP99Ms: 1_000,
      maxRssDeltaMiB: 1_024
    })
  }),
  release: Object.freeze({
    fleet: Object.freeze({
      seed: 'blind-release-lab-release-v1',
      durationSeconds: 60,
      relayCount: 72,
      operatorCount: 24,
      regionCount: 8,
      rateScale: 20,
      relayCapacityBytes: 512 * MIB
    }),
    peerit: Object.freeze({
      intents: 10_000,
      viewRecords: 100_000,
      communities: 1_000,
      pageSize: 256,
      maxCommitP99Ms: 25,
      maxIndexBuildMsPer100k: 4_000,
      maxFeedReadP99Ms: 50,
      maxViewPageP99Ms: 250,
      maxRssDeltaMiB: 768
    })
  })
})

const FLEET_OPERATION_MAPPING = Object.freeze([
  Object.freeze({ name: 'cell-put', family: 'CELL', operation: 'PUT', rate: 'writesPerSecond' }),
  Object.freeze({ name: 'cell-get', family: 'CELL', operation: 'GET', rate: 'readsPerSecond' }),
  Object.freeze({ name: 'inbox-append-4k', family: 'INBOX', operation: 'APPEND', rate: 'writesPerSecond' }),
  Object.freeze({ name: 'inbox-read-8x4k', family: 'INBOX', operation: 'READ', rate: 'readsPerSecond' }),
  Object.freeze({ name: 'core-mirror-4mib', family: 'CORE', operation: 'MIRROR', rate: 'writesPerSecond' }),
  Object.freeze({ name: 'core-prove-256k', family: 'CORE', operation: 'PROVE', rate: 'readsPerSecond' }),
  Object.freeze({ name: 'core-open-replication-4mib', family: 'CORE', operation: 'OPEN_REPLICATION', rate: 'openReplicationsPerSecond' }),
  Object.freeze({ name: 'forward-circuit-4mib', family: 'FORWARD', operation: 'CIRCUIT', rate: 'writesPerSecond' })
])

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function uniqueSorted (values) {
  return [...new Set(values)].sort()
}

function isObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function finiteNonNegative (value) {
  return Number.isFinite(value) && value >= 0
}

function sameValue (left, right) {
  try {
    return stableStringify(left) === stableStringify(right)
  } catch {
    return false
  }
}

function clone (value) {
  if (Array.isArray(value)) return value.map(clone)
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, clone(item)]))
  return value
}

function deepMerge (base, override) {
  if (Array.isArray(override)) return override.map(clone)
  if (!isObject(override)) return override === undefined ? clone(base) : override
  const result = {}
  for (const key of new Set([...Object.keys(base || {}), ...Object.keys(override)])) {
    if (override[key] === undefined) result[key] = clone(base?.[key])
    else if (isObject(base?.[key]) && isObject(override[key])) result[key] = deepMerge(base[key], override[key])
    else result[key] = clone(override[key])
  }
  return result
}

function gate (id, passed, evidenceClass, detail) {
  return Object.freeze({ id, passed: passed === true, evidenceClass, detail })
}

function check (id, passed, observed, expected) {
  return Object.freeze({ id, passed: passed === true, observed, expected })
}

function checked (checks, extra = {}) {
  const blockers = checks.filter(item => !item.passed).map(item => item.id)
  return Object.freeze({ ...extra, checks, blockers, passed: blockers.length === 0 })
}

function missingEvidence (blocker) {
  return checked([
    check(blocker, false, null, 'verified report')
  ], {
    evidenceClass: 'missing',
    authenticityProven: false,
    authorizesRelease: false
  })
}

function implementationBlockers () {
  return uniqueSorted([
    ...PRODUCTION_RUNTIME_EXCLUSIONS,
    ...BLIND_CELL_RUNTIME_BLOCKERS,
    ...BLIND_INBOX_RUNTIME_BLOCKERS,
    ...BLIND_CORE_RUNTIME_BLOCKERS,
    ...BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS
  ])
}

function fleetOperationRates (manifest) {
  return FLEET_OPERATION_MAPPING.map(mapping => ({
    ...mapping,
    weight: manifest.offeredLoad?.families?.[mapping.family]?.[mapping.rate]
  })).filter(item => item.weight > 0)
}

function uniformDurability (manifest, field) {
  const values = ['CELL', 'INBOX', 'CORE']
    .map(family => manifest.durabilityByFamily?.[family]?.[field])
  return {
    uniform: values.length > 0 && values.every(value => value === values[0]),
    value: Math.max(...values),
    values
  }
}

function minimumRelayValue (relays, field) {
  return Math.min(...relays.map(relay => relay[field]))
}

function capacityOperationTemplates () {
  return new Map(DEFAULT_CAPACITY_LAB_CONFIG.workload.operations.map(operation => [
    `${operation.family}:${operation.operation}`,
    operation
  ]))
}

export function buildFleetAlignedCapacityConfig (fleet, override = {}) {
  const manifest = fleet?.scenarioManifest
  if (!isObject(manifest) || !Array.isArray(manifest.relays) || manifest.relays.length === 0) {
    throw new Error('fleet scenario manifest with realized relays is required')
  }
  const relays = manifest.relays
  const operations = fleetOperationRates(manifest)
  if (operations.length !== FLEET_OPERATION_MAPPING.length || operations.some(item => !finiteNonNegative(item.weight))) {
    throw new Error('fleet scenario manifest does not contain the complete positive family operation mix')
  }
  const templates = capacityOperationTemplates()
  const capacityOperations = operations.map(operation => {
    const template = templates.get(`${operation.family}:${operation.operation}`)
    if (!template) throw new Error(`capacity operation template missing for ${operation.family}:${operation.operation}`)
    return { ...clone(template), name: operation.name, weight: operation.weight }
  })
  const replication = uniformDurability(manifest, 'replicas')
  const writeAcks = uniformDurability(manifest, 'commitQuorum')
  const offeredLogicalOpsPerSecond = operations.reduce((total, operation) => total + operation.weight, 0)
  const storageBytesByRelay = relays.map(relay => relay.storageBytes)
  const aligned = {
    seed: `${fleet.seed}:capacity-aligned-v2`,
    simulation: {
      sampleObjects: Math.max(manifest.relayCount * 100, 1_000),
      scaleRelayCounts: [manifest.relayCount]
    },
    fleet: {
      relayCount: manifest.relayCount,
      diskBytesPerRelay: Math.min(...storageBytesByRelay),
      diskBytesByRelay: storageBytesByRelay,
      replicationFactor: replication.value,
      unavailableRelays: Math.min(DEFAULT_CAPACITY_LAB_CONFIG.fleet.unavailableRelays, manifest.relayCount - 1)
    },
    workload: {
      operations: capacityOperations,
      offeredLogicalOpsPerSecond,
      writeAcks: writeAcks.value
    },
    objectives: {
      requiredOperationKinds: operations.map(operation => `${operation.family}:${operation.operation}`)
    },
    disk: {
      sequentialWriteBytesPerSecond: minimumRelayValue(relays, 'diskWriteMbps') * 125_000,
      sequentialReadBytesPerSecond: minimumRelayValue(relays, 'diskReadMbps') * 125_000,
      randomIopsPerSecond: minimumRelayValue(relays, 'diskIopsPerSecond')
    },
    wal: {
      fsyncLatencyMs: 1_000 / minimumRelayValue(relays, 'fsyncsPerSecond')
    },
    network: {
      ingressBitsPerSecond: minimumRelayValue(relays, 'networkMbps') * 1_000_000,
      egressBitsPerSecond: minimumRelayValue(relays, 'networkMbps') * 1_000_000
    },
    cpu: {
      coresPerRelay: minimumRelayValue(relays, 'cpuCores')
    }
  }
  return deepMerge(aligned, override)
}

function roundedProbability (weight, total) {
  return Math.round(weight / total * 1_000_000) / 1_000_000
}

export function verifyFleetCapacityScenarioAlignment (fleet, capacity) {
  const manifest = fleet?.scenarioManifest
  const relays = Array.isArray(manifest?.relays) ? manifest.relays : []
  const expectedOperations = relays.length > 0 ? fleetOperationRates(manifest) : []
  const expectedTotal = expectedOperations.reduce((total, operation) => total + operation.weight, 0)
  const expectedCapacityOperations = expectedOperations.map(operation => ({
    name: operation.name,
    family: operation.family,
    operation: operation.operation,
    weight: operation.weight
  }))
  const observedCapacityOperations = Array.isArray(capacity?.config?.workload?.operations)
    ? capacity.config.workload.operations.map(operation => ({
      name: operation.name,
      family: operation.family,
      operation: operation.operation,
      weight: operation.weight
    }))
    : []
  const expectedManifestOperations = expectedOperations.map(operation => ({
    name: operation.name,
    family: operation.family,
    operation: operation.operation,
    probability: roundedProbability(operation.weight, expectedTotal)
  }))
  const replication = relays.length > 0 ? uniformDurability(manifest, 'replicas') : { uniform: false, value: null, values: [] }
  const writeAcks = relays.length > 0 ? uniformDurability(manifest, 'commitQuorum') : { uniform: false, value: null, values: [] }
  const expectedStorage = relays.map(relay => relay.storageBytes)
  const expectedEnvelope = relays.length > 0
    ? {
        diskSequentialWriteBytesPerSecond: minimumRelayValue(relays, 'diskWriteMbps') * 125_000,
        diskSequentialReadBytesPerSecond: minimumRelayValue(relays, 'diskReadMbps') * 125_000,
        diskRandomIopsPerSecond: minimumRelayValue(relays, 'diskIopsPerSecond'),
        walFsyncLatencyMs: 1_000 / minimumRelayValue(relays, 'fsyncsPerSecond'),
        cpuCoresPerRelay: minimumRelayValue(relays, 'cpuCores'),
        networkIngressBitsPerSecond: minimumRelayValue(relays, 'networkMbps') * 1_000_000,
        networkEgressBitsPerSecond: minimumRelayValue(relays, 'networkMbps') * 1_000_000
      }
    : null
  let exactAlignedConfig = null
  try {
    exactAlignedConfig = normalizeCapacityLabConfig(buildFleetAlignedCapacityConfig(fleet))
  } catch {}
  const checks = [
    check('SOURCE_FLEET_SCENARIO_DIGEST', fleet?.scenarioDigest === sha256(stableStringify(manifest)), fleet?.scenarioDigest, 'digest(realized fleet scenario manifest)'),
    check('EXACT_RELAY_COUNT', capacity?.scenarioManifest?.relayCount === manifest?.relayCount, capacity?.scenarioManifest?.relayCount, manifest?.relayCount),
    check('EXACT_RELAY_STORAGE_LIST', sameValue(capacity?.scenarioManifest?.storageBytesByRelay, expectedStorage), capacity?.scenarioManifest?.storageBytesByRelay, expectedStorage),
    check('MINIMUM_REALIZED_RESOURCE_ENVELOPE', sameValue(capacity?.scenarioManifest?.performanceShape && {
      diskSequentialWriteBytesPerSecond: capacity.scenarioManifest.performanceShape.diskSequentialWriteBytesPerSecond,
      diskSequentialReadBytesPerSecond: capacity.scenarioManifest.performanceShape.diskSequentialReadBytesPerSecond,
      diskRandomIopsPerSecond: capacity.scenarioManifest.performanceShape.diskRandomIopsPerSecond,
      walFsyncLatencyMs: capacity.scenarioManifest.performanceShape.walFsyncLatencyMs,
      cpuCoresPerRelay: capacity.scenarioManifest.performanceShape.cpuCoresPerRelay,
      networkIngressBitsPerSecond: capacity.scenarioManifest.performanceShape.networkIngressBitsPerSecond,
      networkEgressBitsPerSecond: capacity.scenarioManifest.performanceShape.networkEgressBitsPerSecond
    }, expectedEnvelope), capacity?.scenarioManifest?.performanceShape, expectedEnvelope),
    check('UNIFORM_DURABLE_REPLICATION_CONTRACT', replication.uniform && capacity?.scenarioManifest?.durability?.replicationFactor === replication.value, capacity?.scenarioManifest?.durability?.replicationFactor, replication),
    check('UNIFORM_DURABLE_COMMIT_QUORUM_CONTRACT', writeAcks.uniform && capacity?.scenarioManifest?.durability?.writeAcks === writeAcks.value, capacity?.scenarioManifest?.durability?.writeAcks, writeAcks),
    check('EXACT_TOTAL_OFFERED_LOAD', capacity?.scenarioManifest?.offeredLoad?.logicalOperationsPerSecond === expectedTotal, capacity?.scenarioManifest?.offeredLoad?.logicalOperationsPerSecond, expectedTotal),
    check('EXACT_CONFIGURED_OPERATION_RATES', sameValue(observedCapacityOperations, expectedCapacityOperations), observedCapacityOperations, expectedCapacityOperations),
    check('EXACT_MODELED_OPERATION_MIX', sameValue(capacity?.scenarioManifest?.offeredLoad?.operations, expectedManifestOperations), capacity?.scenarioManifest?.offeredLoad?.operations, expectedManifestOperations),
    check('EXPLICIT_OFFERED_LOAD_SOURCE', capacity?.scenarioManifest?.offeredLoad?.source === 'explicit-config', capacity?.scenarioManifest?.offeredLoad?.source, 'explicit-config'),
    check('CONSERVATIVE_ALIGNED_CONFIG_UNMODIFIED', exactAlignedConfig !== null &&
      sameValue(capacity?.config, exactAlignedConfig), capacity?.configDigest,
    exactAlignedConfig && sha256(stableStringify(exactAlignedConfig)))
  ]
  return checked(checks, {
    evidenceClass: 'mechanically-checked-model-scenario-alignment',
    sourceScenarioDigest: fleet?.scenarioDigest || null,
    capacityScenarioDigest: capacity?.scenarioDigest || null,
    mappingBoundary: 'Fleet writes/reads map to CELL PUT/GET, INBOX APPEND/READ, CORE MIRROR/PROVE, and FORWARD CIRCUIT; CORE openReplications map separately to OPEN_REPLICATION. No unoffered WATCH traffic is invented.'
  })
}

async function loadPeeritReport (root, profile) {
  const script = join(root, 'scripts', 'peerit-scale-lab.mjs')
  const info = await stat(script)
  if (!info.isFile()) throw new Error(`Peerit scale lab is not a file: ${script}`)
  const module = await import(pathToFileURL(script).href)
  if (typeof module.runPeeritScaleLab !== 'function') {
    throw new Error(`Peerit scale lab does not export runPeeritScaleLab: ${script}`)
  }
  return module.runPeeritScaleLab(profile)
}

async function loadJsonEvidence (filename, label) {
  const path = resolve(String(filename))
  const info = await stat(path)
  if (!info.isFile() || info.size > MAX_EVIDENCE_FILE_BYTES) {
    throw new Error(`${label} must be a JSON file no larger than ${MAX_EVIDENCE_FILE_BYTES} bytes: ${path}`)
  }
  let value
  try {
    value = JSON.parse(await readFile(path, 'utf8'))
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`)
  }
  return value
}

async function loadPeeritEvidenceModule (root, filename, exports) {
  if (!root) throw new Error(`--peerit-root is required to verify ${filename} evidence`)
  const script = join(root, 'scripts', filename)
  const info = await stat(script)
  if (!info.isFile()) throw new Error(`Peerit evidence verifier is not a file: ${script}`)
  const module = await import(pathToFileURL(script).href)
  for (const name of exports) {
    if (!(name in module)) throw new Error(`Peerit evidence verifier does not export ${name}: ${script}`)
  }
  return module
}

function retryFairnessShapePasses (report, expectedTargets) {
  const workload = report?.workload
  const summary = report?.summary
  if (report?.schema !== 'peerit-retry-fairness-lab-v1' ||
      report?.evidenceClass !== 'MEASURED_LOCAL_NODE_MEMORY_BACKEND' ||
      workload?.targets !== expectedTargets || !Number.isSafeInteger(workload?.batchSize) ||
      workload.batchSize <= 0 || !Number.isSafeInteger(workload?.maximumRounds) ||
      !isObject(summary)) return false
  const maximumSelections = Math.ceil(expectedTargets / workload.batchSize) * workload.batchSize
  const mechanicallyReady = summary.uniqueTargetsSeen === expectedTargets &&
    summary.selectedRows >= expectedTargets && summary.selectedRows <= maximumSelections &&
    summary.claimsSucceeded === summary.selectedRows && summary.claimsFailed === 0 &&
    summary.stateResetsSucceeded === summary.selectedRows && summary.unknownIntentIds === 0 &&
    summary.rounds <= workload.maximumRounds && summary.laneFairnessViolations === 0 &&
    (expectedTargets <= workload.batchSize || summary.truncatedPages > 0) &&
    summary.expiredClaimsRecovered >= 1 && summary.expiredTargetState === 'pending-unknown' &&
    finiteNonNegative(report?.timing?.elapsedMs) && report.timing.elapsedMs <= workload.maxElapsedMs
  const gates = Array.isArray(report.gates) ? report.gates : []
  const gateIds = gates.map(item => item?.id)
  const blockers = gates.filter(item => item?.passed !== true).map(item => item?.id)
  return mechanicallyReady && gates.length === 10 && new Set(gateIds).size === 10 &&
    gates.every(item => item?.passed === true) && sameValue(report.blockers, blockers) &&
    report.localGateReady === true && report.releaseReady === false
}

export function validatePeeritLocalScaleReport (report, profile) {
  const workload = report?.workload
  const journal = report?.journal
  const index = report?.materializedIndex
  const retryReady = retryFairnessShapePasses(report?.retryFairness, profile.intents)
  const expectedGateResults = new Map([
    ['JOURNAL_COUNT_EXACT', journal?.summary?.intentCount === profile.intents &&
      journal?.summary?.viewRecordCount === profile.viewRecords &&
      journal?.scannedIntentIds === profile.intents && journal?.rangedViewRecords === profile.viewRecords],
    ['INDEX_COUNT_EXACT', index?.records === profile.viewRecords && index?.totalFeedRows === profile.viewRecords],
    ['JOURNAL_COMMIT_P99', finiteNonNegative(journal?.commit?.p99Ms) && journal.commit.p99Ms <= profile.maxCommitP99Ms],
    ['INDEX_BUILD_PROJECTED_100K', finiteNonNegative(index?.projectedBuildMsPer100k) && index.projectedBuildMsPer100k <= profile.maxIndexBuildMsPer100k],
    ['FEED_READ_P99', finiteNonNegative(index?.feedRead?.p99Ms) && index.feedRead.p99Ms <= profile.maxFeedReadP99Ms],
    ['JOURNAL_VIEW_RANGE_PAGE_P99', finiteNonNegative(journal?.viewRangePage?.p99Ms) && journal.viewRangePage.p99Ms <= profile.maxViewPageP99Ms],
    ['RETRY_TARGET_INDEX_LOCAL_FAIRNESS', retryReady],
    ['NODE_MEMORY_RSS_DELTA', Number.isFinite(report?.memory?.rssDeltaBytes) && report.memory.rssDeltaBytes <= profile.maxRssDeltaMiB * MIB]
  ])
  const gates = Array.isArray(report?.gates) ? report.gates : []
  const observedGateResults = gates.map(item => ({ id: item?.id, passed: item?.passed === true }))
  const expectedGateList = LOCAL_GATE_IDS.map(id => ({ id, passed: expectedGateResults.get(id) === true }))
  const expectedBlockers = expectedGateList.filter(item => !item.passed).map(item => item.id)
  const checks = [
    check('REPORT_SHAPE', isObject(report), typeof report, 'object'),
    check('REPORT_SCHEMA_AND_BOUNDARY', report?.schema === 'peerit-scale-lab-v1' &&
      report?.evidenceClass === 'MEASURED_LOCAL_NODE_MEMORY_BACKEND' && report?.releaseReady === false &&
      typeof report?.claimBoundary === 'string' && ['Not browser', 'network', 'disk', 'multi-process', 'production capacity'].every(term => report.claimBoundary.includes(term)),
    { schema: report?.schema, evidenceClass: report?.evidenceClass, releaseReady: report?.releaseReady }, 'Peerit local Node memory-backend boundary'),
    check('EXACT_PROFILE', sameValue(workload && {
      intents: workload.intents,
      viewRecords: workload.viewRecords,
      communities: workload.communities,
      pageSize: workload.pageSize
    }, {
      intents: profile.intents,
      viewRecords: profile.viewRecords,
      communities: profile.communities,
      pageSize: profile.pageSize
    }), workload, profile),
    check('DERIVED_WORKLOAD_COUNTS', workload?.recordsPerIntent === Math.ceil(profile.viewRecords / profile.intents) &&
      workload?.retryTargets === profile.intents, workload, {
      recordsPerIntent: Math.ceil(profile.viewRecords / profile.intents),
      retryTargets: profile.intents
    }),
    check('JOURNAL_TRANSACTION_AND_SAMPLE_COUNTS', journal?.backend === 'deterministic-node-memory' &&
      journal?.writeTransactions === profile.intents && journal?.commit?.count === profile.intents &&
      journal?.pendingIndexPage?.count === Math.ceil(profile.intents / profile.pageSize) &&
      journal?.viewRangePage?.count === Math.ceil(profile.viewRecords / 1_000) && journal?.nextWakeWithoutTargets === null,
    journal, 'exact generated local journal transactions and pages'),
    check('MATERIALIZED_INDEX_SAMPLE_COUNTS', index?.feedRead?.count === profile.communities &&
      index?.records === profile.viewRecords && index?.totalFeedRows === profile.viewRecords,
    index, 'exact generated materialized-index records and community reads'),
    check('RETRY_FAIRNESS_MECHANICALLY_CONSISTENT', retryReady, report?.retryFairness, 'mechanically consistent local retry-index evidence'),
    check('EXACT_GATE_SET_AND_RESULTS', sameValue(observedGateResults, expectedGateList), observedGateResults, expectedGateList),
    check('BLOCKERS_AND_READY_DERIVED', sameValue(report?.blockers, expectedBlockers) &&
      report?.localGateReady === (expectedBlockers.length === 0), {
      blockers: report?.blockers,
      localGateReady: report?.localGateReady
    }, {
      blockers: expectedBlockers,
      localGateReady: expectedBlockers.length === 0
    })
  ]
  return checked(checks, {
    evidenceClass: 'strict-shape-and-derived-gate-validation',
    authenticityProven: false,
    contentChecksumVerified: false
  })
}

export function validatePeeritBrowserFullMatrix (report, module, owningVerification) {
  const expected = module.BROWSER_SCALE_PROFILES.full
  const expectedWorkload = {
    intents: expected.intents,
    records: expected.records,
    communities: expected.communities,
    pageSize: expected.pageSize
  }
  const expectedDefinition = {
    schema: 'peerit-browser-scale-workload-v1',
    profile: 'full',
    ...expectedWorkload,
    generator: 'sequential-intents-round-robin-communities-v1'
  }
  const results = Array.isArray(report?.results) ? report.results : []
  const resultEngines = results.map(result => result?.engine)
  const resultChecks = results.map(result => {
    let pageValidation = { passed: false, blockers: ['PAGE_VALIDATOR_NOT_RUN'] }
    try {
      pageValidation = module.validatePageReport({
        report: result?.pageReport,
        workload: expected,
        profile: 'full',
        diagnostics: result?.diagnostics,
        // The runner did not persist bodyStatus separately. The stored harness
        // gate must still be exact below; page content is revalidated here.
        bodyStatus: 'passed'
      })
    } catch (error) {
      pageValidation = { passed: false, blockers: [String(error.message || error)] }
    }
    const expectedHarness = ['HARNESS_EXECUTION', ...pageValidation.gates.map(item => item.id)]
    return {
      engine: result?.engine,
      passed: DESKTOP_ENGINES.includes(result?.engine) && result?.status === 'passed' &&
        result?.executionError == null && Array.isArray(result?.blockers) && result.blockers.length === 0 &&
        pageValidation.passed && sameValue(result?.harnessGates?.map(item => item?.id), expectedHarness) &&
        result.harnessGates.every(item => item?.passed === true) &&
        sameValue(result?.metrics, result?.pageReport && {
          workload: result.pageReport.workload,
          summary: result.pageReport.summary,
          timing: result.pageReport.timing,
          storage: result.pageReport.storage,
          memory: result.pageReport.memory,
          observability: result.pageReport.observability
        }),
      pageBlockers: pageValidation.blockers
    }
  })
  const checks = [
    check('OWNING_CONTENT_VERIFIER', owningVerification?.verified === true &&
      owningVerification?.checksumVerified === true && owningVerification?.authentic === false &&
      owningVerification?.authorizesRelease === false, owningVerification, 'verified checksum only; no authenticity or release authority'),
    check('CHECKSUM_PURPOSE_BOUNDARY', report?.evidenceDigestPurpose === 'content-address-only-not-authenticity-or-release-authorization', report?.evidenceDigestPurpose, 'content-address-only-not-authenticity-or-release-authorization'),
    check('EXACT_FULL_PROFILE', report?.profile === 'full' && sameValue(report?.workload, expectedWorkload) &&
      sameValue(report?.workloadDefinition, expectedDefinition) && report?.workloadSha256 === sha256(JSON.stringify(expectedDefinition)), {
      profile: report?.profile,
      workload: report?.workload,
      workloadDefinition: report?.workloadDefinition,
      workloadSha256: report?.workloadSha256
    }, { profile: 'full', workload: expectedWorkload, workloadDefinition: expectedDefinition }),
    check('EXACT_DESKTOP_ENGINE_COVERAGE', sameValue(report?.requestedEngines, DESKTOP_ENGINES) &&
      sameValue(resultEngines, DESKTOP_ENGINES) &&
      sameValue(report?.coverage?.desktopEnginesPassed, DESKTOP_ENGINES) &&
      sameValue(report?.coverage?.desktopFullProfileEnginesPassed, DESKTOP_ENGINES) &&
      sameValue(report?.coverage?.desktopEnginesRequired, DESKTOP_ENGINES), {
      requested: report?.requestedEngines,
      results: resultEngines,
      coverage: report?.coverage
    }, DESKTOP_ENGINES),
    check('EACH_ENGINE_PAGE_REVALIDATED', resultChecks.length === DESKTOP_ENGINES.length && resultChecks.every(item => item.passed), resultChecks, 'all three stored page reports revalidate'),
    check('MATRIX_READY_DERIVED', report?.selectedRunPassed === true && report?.selectedBrowserGateReady === true &&
      report?.localDesktopMatrixReady === true && report?.releaseReady === false, {
      selectedRunPassed: report?.selectedRunPassed,
      selectedBrowserGateReady: report?.selectedBrowserGateReady,
      localDesktopMatrixReady: report?.localDesktopMatrixReady,
      releaseReady: report?.releaseReady
    }, 'full local desktop matrix only'),
    check('COVERAGE_BOUNDARY', report?.coverage?.mobile === false && report?.coverage?.crashRecovery === false &&
      report?.coverage?.quotaExhaustion === false && report?.coverage?.network === false &&
      report?.coverage?.production === false, report?.coverage, 'desktop IndexedDB only')
  ]
  return checked(checks, {
    evidenceClass: 'measured-local-desktop-browser-content-verified',
    checksumOnly: true,
    authenticityProven: false,
    authorizesRelease: false,
    owningVerification
  })
}

export function validatePeeritFaultFullProfile (report, module, owningVerification) {
  const expected = module.PERSISTENCE_FAULT_PROFILES.full
  const expectedWorkload = {
    baselineIntents: expected.baselineIntents,
    crashRecords: expected.crashRecords,
    quotaPayloadBytes: expected.quotaPayloadBytes
  }
  const gates = Array.isArray(report?.gates) ? report.gates : []
  const checks = [
    check('OWNING_CONTENT_VERIFIER', owningVerification?.verified === true &&
      owningVerification?.expectedChecksum === owningVerification?.observedChecksum,
    owningVerification, 'verified checksum only; no authenticity or release authority'),
    check('EXACT_FULL_PROFILE', report?.profile === 'full' && sameValue(report?.workload, expectedWorkload), {
      profile: report?.profile,
      workload: report?.workload
    }, { profile: 'full', workload: expectedWorkload }),
    check('ALL_FAULT_GATES_PASS', gates.length > 0 && gates.every(item => item?.passed === true) &&
      Array.isArray(report?.blockers) && report.blockers.length === 0, gates, 'all owning fault gates pass'),
    check('FULL_FAULT_READY_DERIVED', report?.localFaultGateReady === true &&
      report?.fullProfileGateReady === true && report?.releaseReady === false, {
      localFaultGateReady: report?.localFaultGateReady,
      fullProfileGateReady: report?.fullProfileGateReady,
      releaseReady: report?.releaseReady
    }, 'full local Chromium fault gate only'),
    check('AUTHENTICITY_AND_QUOTA_BOUNDARY', report?.authenticityProven === false &&
      report?.coverage?.realQuotaExhaustion === false && report?.coverage?.mobile === false &&
      report?.coverage?.production === false, {
      authenticityProven: report?.authenticityProven,
      coverage: report?.coverage
    }, 'injected quota on one local Chromium build; no authenticity')
  ]
  return checked(checks, {
    evidenceClass: 'measured-local-chromium-fault-content-verified',
    checksumOnly: true,
    authenticityProven: false,
    authorizesRelease: false,
    owningVerification
  })
}

export function validateRealRelayEvidence (report) {
  const pinnedThresholds = REAL_BLIND_RELAY_LOCAL_PERFORMANCE_THRESHOLDS
  const expectedBlockers = realBlindRelayExpectedBlockers({
    correctnessReady: true,
    performanceReady: true
  })
  let owningVerification = null
  let verifierError = null
  try {
    owningVerification = verifyRealBlindRelayReport(report, {
      requireCorrectness: true,
      requirePerformance: true
    })
  } catch (error) {
    verifierError = String(error.message || error)
  }
  const checks = [
    check('OWNING_CONTENT_VERIFIER', owningVerification?.verified === true &&
      owningVerification?.checksumVerified === true && owningVerification?.checksumOnly === true &&
      owningVerification?.authenticityProven === false && owningVerification?.authorizesRelease === false,
    owningVerification || verifierError, 'verified checksum only; no authenticity'),
    check('REAL_RELAY_CORRECTNESS_AND_PERFORMANCE', owningVerification?.correctnessReady === true &&
      owningVerification?.performanceReady === true && report?.localGateReady === true,
    owningVerification, 'local correctness and performance gates'),
    check('PINNED_LOCAL_THRESHOLDS', sameValue(report?.gates?.performance?.thresholds, pinnedThresholds),
      report?.gates?.performance?.thresholds, pinnedThresholds),
    check('PINNED_LOCAL_SCOPE_BOUNDARY', report?.evidenceClass === 'MEASURED_LOCAL_REAL_HTTP_IPC_FILESYSTEM' &&
      report?.releaseReady === false && report?.scope?.realImplementationsOnly === false &&
      report?.scope?.realHttpIpcWalFilesystemDataPlane === true && report?.scope?.modelDataPlane === false &&
      report?.scope?.syntheticAdmissionAdapter === true && report?.scope?.economicSettlementMeasured === false &&
      report?.scope?.networkReplicaProtocolMeasured === false && report?.scope?.processIsolation === false &&
      report?.scope?.hostIsolation === false && report?.scope?.productionReleaseGateBypassed === true &&
      report?.scope?.sameUidTestTopology === true,
    report?.scope, 'same-process/same-host synthetic-admission local relay evidence only'),
    check('PINNED_MEASURED_FAMILY_BOUNDARY', sameValue(report?.families, REAL_BLIND_RELAY_FAMILY_SCOPE),
      report?.families, REAL_BLIND_RELAY_FAMILY_SCOPE),
    check('MANDATORY_LOCAL_LIMITATIONS_RETAINED', sameValue(report?.runtimeExclusions, REAL_BLIND_RELAY_RUNTIME_EXCLUSIONS) &&
      sameValue(report?.blockers, expectedBlockers), {
      blockers: report?.blockers,
      runtimeExclusions: report?.runtimeExclusions
    }, { blockers: expectedBlockers, runtimeExclusions: REAL_BLIND_RELAY_RUNTIME_EXCLUSIONS })
  ]
  return checked(checks, {
    evidenceClass: 'measured-local-real-relay-content-verified',
    checksumOnly: true,
    authenticityProven: false,
    authorizesRelease: false,
    owningVerification,
    verifierError
  })
}

export function verifyBlindReleaseLabDigest (report) {
  if (!report || typeof report !== 'object' || typeof report.evidenceDigest !== 'string') return false
  const { evidenceDigest, ...body } = report
  return evidenceDigest === sha256(stableStringify(body))
}

export async function runBlindReleaseLab (options = {}) {
  const profileName = String(options.profile || 'smoke')
  const profile = BLIND_RELEASE_LAB_PROFILES[profileName]
  if (!profile) throw new Error(`unknown blind release-lab profile: ${profileName}`)

  const fleet = runBlindFleetSimulation(profile.fleet)
  assertBlindFleetEvidence(fleet)
  const capacityConfig = buildFleetAlignedCapacityConfig(fleet, options.capacity || {})
  const capacity = runCapacityLab(capacityConfig)
  const scenarioAlignment = verifyFleetCapacityScenarioAlignment(fleet, capacity)
  const peeritRoot = options.peeritRoot ? resolve(String(options.peeritRoot)) : null
  const peerit = options.peeritReport || (peeritRoot ? await loadPeeritReport(peeritRoot, profile.peerit) : null)
  const peeritValidation = peerit
    ? validatePeeritLocalScaleReport(peerit, profile.peerit)
    : missingEvidence('PEERIT_SCALE_LAB_NOT_RUN')

  const browserReport = options.peeritBrowserReport ||
    (options.peeritBrowserReportFile ? await loadJsonEvidence(options.peeritBrowserReportFile, 'Peerit browser report') : null)
  const faultReport = options.peeritFaultReport ||
    (options.peeritFaultReportFile ? await loadJsonEvidence(options.peeritFaultReportFile, 'Peerit fault report') : null)
  const realRelayReport = options.realRelayReport ||
    (options.realRelayReportFile ? await loadJsonEvidence(options.realRelayReportFile, 'real relay report') : null)

  let browserValidation = missingEvidence('PEERIT_BROWSER_REPORT_NOT_RUN')
  if (browserReport) {
    const module = await loadPeeritEvidenceModule(
      peeritRoot,
      'browser-peerit-scale-matrix.mjs',
      ['BROWSER_SCALE_PROFILES', 'validatePageReport', 'verifyBrowserScaleEvidence']
    )
    const owningVerification = module.verifyBrowserScaleEvidence(browserReport)
    browserValidation = validatePeeritBrowserFullMatrix(browserReport, module, owningVerification)
  }

  let faultValidation = missingEvidence('PEERIT_FAULT_REPORT_NOT_RUN')
  if (faultReport) {
    const module = await loadPeeritEvidenceModule(
      peeritRoot,
      'browser-peerit-persistence-fault.mjs',
      ['PERSISTENCE_FAULT_PROFILES', 'verifyPersistenceFaultEvidence']
    )
    const owningVerification = module.verifyPersistenceFaultEvidence(faultReport)
    faultValidation = validatePeeritFaultFullProfile(faultReport, module, owningVerification)
  }
  const realRelayValidation = realRelayReport
    ? validateRealRelayEvidence(realRelayReport)
    : missingEvidence('REAL_RELAY_REPORT_NOT_RUN')

  const runtimeBlockers = implementationBlockers()
  const retirementPolicy = await loadLegacyRetirementPolicy()
  const legacyRetirement = evaluateLegacyRetirement(retirementPolicy)
  const ecosystemMigration = evaluateEcosystemMigration(
    await loadEcosystemMigrationMatrix(undefined, retirementPolicy),
    retirementPolicy
  )

  const labGates = [
    gate('FLEET_SIMULATION_INVARIANTS', fleet.ok && verifyBlindFleetEvidenceDigest(fleet),
      'deterministic-model', fleet.evidenceDigest),
    gate('FLEET_CAPACITY_SCENARIO_ALIGNED', scenarioAlignment.passed,
      scenarioAlignment.evidenceClass, scenarioAlignment.blockers),
    gate('CAPACITY_MODEL_STEADY_STATE', capacity.status === 'pass',
      'modeled-not-benchmarked', capacity.rejectionReasons),
    gate('PEERIT_LOCAL_SCALE', peeritValidation.passed,
      peeritValidation.evidenceClass, peeritValidation.blockers),
    gate('PEERIT_DESKTOP_FULL_MATRIX', browserValidation.passed,
      browserValidation.evidenceClass, browserValidation.blockers),
    gate('PEERIT_CHROMIUM_FULL_FAULT', faultValidation.passed,
      faultValidation.evidenceClass, faultValidation.blockers),
    gate('REAL_ASSEMBLED_CELL_RELAY', realRelayValidation.passed,
      realRelayValidation.evidenceClass, realRelayValidation.blockers)
  ]
  const labBlockers = labGates.filter(item => !item.passed).map(item => item.id)

  const mainnetGates = [
    ...labGates,
    gate('ALL_FAMILY_PRODUCTION_RUNTIME', runtimeBlockers.length === 0,
      'implementation-authority', runtimeBlockers),
    gate('LEGACY_RETIREMENT_AUTHORIZED', legacyRetirement.authorized,
      'code-owned-retirement-authority', legacyRetirement.blockingCodes),
    gate('ECOSYSTEM_CUTOVERS_AUTHORIZED', ecosystemMigration.allApplicationCutoversAuthorized &&
      ecosystemMigration.allLegacyComponentCutoversAuthorized,
    'code-owned-ecosystem-migration-authority', {
      applications: ecosystemMigration.applications.filter(row => !row.cutoverAuthorized).map(row => row.id),
      components: ecosystemMigration.legacyComponents.filter(row => !row.cutoverAuthorized).map(row => row.id)
    }),
    gate('REAL_BROWSER_QUOTA_EXHAUSTION', false,
      'measured-browser-storage-fault', ['ONLY_TEST_INJECTED_CDP_QUOTA_EVIDENCE_WIRED']),
    gate('MOBILE_BROWSER_SCALE_AND_FAULT', false,
      'measured-mobile-browser', ['VERIFIED_MOBILE_REPORT_NOT_WIRED']),
    gate('PRODUCTION_BROWSER_SCALE_AND_FAULT', false,
      'measured-production-browser', ['VERIFIED_PRODUCTION_BROWSER_REPORT_NOT_WIRED']),
    gate('CROSS_BROWSER_RELAY_DELIVERY', false,
      'measured-browser-network-adapter', ['VERIFIED_BROWSER_RELAY_DELIVERY_REPORT_NOT_WIRED']),
    gate('REAL_MULTI_PROCESS_RELAY_BENCHMARK', false,
      'measured-process-isolation', ['VERIFIED_MULTI_PROCESS_REPORT_NOT_WIRED']),
    gate('REAL_MULTI_HOST_HARDWARE_BENCHMARK', false,
      'measured-production-hardware', ['VERIFIED_MULTI_HOST_REPORT_NOT_WIRED']),
    gate('INDEPENDENT_OPERATOR_FAILURE_DRILL', false,
      'measured-live-multi-operator', ['VERIFIED_OPERATOR_DRILL_NOT_WIRED']),
    gate('SEVEN_DAY_MIXED_FAULT_SOAK', false,
      'measured-live-soak', ['VERIFIED_SEVEN_DAY_SOAK_NOT_WIRED']),
    gate('SIGNED_RELEASE_ATTESTATION_AND_ROLLBACK', false,
      'signed-release-evidence', ['SIGNED_PRODUCTION_ATTESTATION_AND_ROLLBACK_NOT_WIRED'])
  ]
  const mainnetBlockers = mainnetGates.filter(item => !item.passed).map(item => item.id)

  const report = {
    schema: BLIND_RELEASE_LAB_SCHEMA,
    profile: profileName,
    evidenceClass: 'composite-model-and-local-measurement',
    evidenceBinding: {
      algorithm: 'sha256',
      purpose: 'content-integrity-only',
      signed: false,
      authenticityProven: false,
      authorizesRelease: false
    },
    claimBoundary: 'Deterministic models and checksum-bound local measurements are planning evidence, not authenticity or release authority. Mainnet remains blocked on complete production composition, real quota exhaustion, mobile and relay-delivery browser evidence, process/host/operator isolation, soak, migration/retirement authority, and signed release/rollback evidence.',
    fleet,
    capacity,
    scenarioAlignment,
    peerit,
    peeritValidation,
    browserReport,
    browserValidation,
    faultReport,
    faultValidation,
    realRelayReport,
    realRelayValidation,
    implementation: {
      runtimeBlockers,
      productionFamiliesComplete: runtimeBlockers.length === 0
    },
    legacyRetirement,
    ecosystemMigration,
    labGates,
    labBlockers,
    labReady: labBlockers.length === 0,
    mainnetGates,
    mainnetBlockers,
    mainnetReady: mainnetBlockers.length === 0
  }
  return { ...report, evidenceDigest: sha256(stableStringify(report)) }
}

function parseArgs (argv) {
  const options = {
    profile: 'smoke',
    peeritRoot: process.env.PEERIT_ROOT || '',
    peeritBrowserReportFile: '',
    peeritFaultReportFile: '',
    realRelayReportFile: '',
    out: '',
    compact: false,
    assertLab: false,
    assertMainnet: false
  }
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]
    if (arg === '--profile') options.profile = argv[++index] || ''
    else if (arg === '--peerit-root') options.peeritRoot = argv[++index] || ''
    else if (arg === '--peerit-browser-report') options.peeritBrowserReportFile = argv[++index] || ''
    else if (arg === '--peerit-fault-report') options.peeritFaultReportFile = argv[++index] || ''
    else if (arg === '--real-relay-report') options.realRelayReportFile = argv[++index] || ''
    else if (arg === '--out') options.out = argv[++index] || ''
    else if (arg === '--compact') options.compact = true
    else if (arg === '--assert-lab') options.assertLab = true
    else if (arg === '--assert-mainnet') options.assertMainnet = true
    else if (arg === '--help' || arg === '-h') return null
    else throw new Error(`unknown argument: ${arg}`)
  }
  return options
}

function help () {
  return [
    'Usage: node scripts/run-blind-release-lab.mjs [options]',
    '',
    '  --profile smoke|release        bounded workload profile',
    '  --peerit-root <path>           Peerit checkout and owning verifier source',
    '  --peerit-browser-report <file> checksum-bound full desktop matrix JSON',
    '  --peerit-fault-report <file>   checksum-bound full Chromium fault JSON',
    '  --real-relay-report <file>     checksum-bound real local relay JSON',
    '  --out <path>                   write composite JSON evidence',
    '  --compact                      emit compact JSON',
    '  --assert-lab                   fail when any model/local gate fails',
    '  --assert-mainnet               fail unless every production/live gate passes',
    '',
    'Checksums prove content integrity only, never authenticity or release authority.',
    'PEERIT_ROOT may supply --peerit-root. --assert-mainnet is intentionally red',
    'until verified external evidence and the complete production runtime exist.'
  ].join('\n')
}

async function main () {
  const options = parseArgs(process.argv.slice(2))
  if (!options) {
    process.stdout.write(help() + '\n')
    return
  }
  const report = await runBlindReleaseLab(options)
  const encoded = stableStringify(report, options.compact ? 0 : 2) + '\n'
  if (options.out) await writeFile(resolve(options.out), encoded)
  process.stdout.write(encoded)
  if ((options.assertLab && !report.labReady) || (options.assertMainnet && !report.mainnetReady)) {
    process.exitCode = 1
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch(error => {
    process.stderr.write(String(error && error.stack ? error.stack : error) + '\n')
    process.exitCode = 1
  })
}
