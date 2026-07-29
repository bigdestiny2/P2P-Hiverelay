#!/usr/bin/env node

import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  LEGACY_RETIREMENT_EVIDENCE_BLOCKERS,
  evaluateLegacyRetirement,
  loadLegacyRetirementPolicy,
  productionRetirementBlockers
} from './verify-blind-legacy-retirement-policy.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))

export const ECOSYSTEM_MIGRATION_MATRIX_PATH = path.resolve(
  here,
  '../deploy/blind/ecosystem-migration-matrix.json'
)

const GATE_IDS = Object.freeze(['G0', 'G1', 'G2', 'G3', 'G4', 'G5', 'G6', 'G7', 'G8'])
const FAMILY_IDS = Object.freeze(['CELL', 'INBOX', 'CORE', 'FORWARD'])
const BOUNDARY_IDS = Object.freeze([
  'blind-relay-base',
  'application-client',
  'nonblind-provider',
  'nonblind-index',
  'operator-control'
])
const EXTERNAL_DEPENDENCY_IDS = Object.freeze([
  'client-derived-index',
  'signed-app-catalog',
  'native-push-bridge',
  'semantic-index-provider',
  'ai-compute-provider',
  'payment-settlement-provider',
  'mobility-provider',
  'realtime-media-provider',
  'device-automation-provider',
  'sports-data-provider',
  'git-ci-provider',
  'identity-arbitration-provider',
  'operator-admin-plane',
  'operator-accounting-plane'
])
const EXTERNAL_DEPENDENCY_BOUNDARIES = Object.freeze({
  'client-derived-index': 'application-client',
  'signed-app-catalog': 'application-client',
  'native-push-bridge': 'nonblind-provider',
  'semantic-index-provider': 'nonblind-index',
  'ai-compute-provider': 'nonblind-provider',
  'payment-settlement-provider': 'nonblind-provider',
  'mobility-provider': 'nonblind-provider',
  'realtime-media-provider': 'nonblind-provider',
  'device-automation-provider': 'nonblind-provider',
  'sports-data-provider': 'nonblind-provider',
  'git-ci-provider': 'nonblind-provider',
  'identity-arbitration-provider': 'nonblind-provider',
  'operator-admin-plane': 'operator-control',
  'operator-accounting-plane': 'operator-control'
})
const ROLLOUT_TRACK_IDS = Object.freeze([
  'data-log-consumer',
  'content-publication',
  'marketplace-transaction',
  'private-coordination',
  'realtime-application',
  'provider-mediated',
  'registry-distribution',
  'operator-infrastructure'
])
const COMPONENT_IDS = Object.freeze([
  'legacy-service-plane',
  'outboxlog',
  'witness-repair',
  'shard-custody',
  'seed-storage-gateway',
  'catalog-federation-index',
  'notify',
  'poker',
  'compute-trust-services',
  'legacy-circuit-forward',
  'edge-transports',
  'legacy-client-verifier',
  'operator-control-economics',
  'peerit-legacy-consumer-plane'
])
const APPLICATION_IDS = Object.freeze([
  'peerit',
  'p2pbuilders',
  'pearfeed',
  'bazaar',
  'exchange',
  'rides',
  'stays',
  'comms',
  'dealroom',
  'home',
  'openclaw',
  'pos',
  'sahifa',
  'sanduq',
  'tickets',
  'matchday-mesh',
  'pearpaste',
  'peartube',
  'ultimate-sports',
  'pearcup',
  'hiveworm',
  'pear-registry',
  'opengit',
  'anongpt',
  'platforms'
])
const EVIDENCE_IDS = Object.freeze([
  'final-authorities',
  'all-family-runtime',
  'blindness-sentinel',
  'semantic-parity',
  'durability-scale',
  'independent-operators',
  'cross-runtime-consumers',
  'migration-restore',
  'zero-legacy-traffic'
])
const EVIDENCE_BY_GATE = Object.freeze(Object.fromEntries(
  GATE_IDS.map((gate, index) => [gate, EVIDENCE_IDS[index]])
))

const FINAL_AUTHORITY_PRODUCTION_SOURCES = new Set([
  'blind-protocol.ABI_RELEASE_BLOCKERS',
  'blind-ipc.PRIVATE_IPC_STATUS.releaseBlockers',
  'blind-client.BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.releaseBlockers',
  'blind-daemon.BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS',
  'blind-daemon.BLIND_INBOX_STORAGE_BLOCKERS',
  'blind-daemon.BLIND_CORE_STORAGE_BLOCKERS'
])
const FINAL_AUTHORITY_RUNTIME_CODES = new Set([
  'FINAL_BUILD_PROFILE_LOCAL_BINDING_UNASSEMBLED',
  'TWO_SLOT_MANIFEST_RUNTIME_INTEGRATION_UNASSEMBLED',
  'DESCRIPTOR_REFRESH_PERSISTED_FLOOR_UNASSEMBLED'
])
const CROSS_RUNTIME_PRODUCTION_SOURCES = new Set([
  'blind-protocol.ABI_RELEASE_BLOCKERS',
  'blind-client.BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.releaseBlockers'
])
const BROWSER_ARTIFACT_PRODUCTION_SOURCE =
  'blind-client.BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.releaseBlockers'

// A row cannot become eligible merely because the shared gates turn green.
// Each row remains blocked until its own executable parity authority replaces
// this code-owned placeholder. Nothing in deployment JSON can clear it.
export const APPLICATION_MIGRATION_EVIDENCE_BLOCKERS = Object.freeze(Object.fromEntries(
  APPLICATION_IDS.map(id => [id, Object.freeze([
    `APPLICATION_${blockerToken(id)}_SEMANTIC_PARITY_AUTHORITY_UNASSEMBLED`
  ])])
))

export const COMPONENT_MIGRATION_EVIDENCE_BLOCKERS = Object.freeze(Object.fromEntries(
  COMPONENT_IDS.map(id => [id, Object.freeze([
    `COMPONENT_${blockerToken(id)}_MIGRATION_PARITY_AUTHORITY_UNASSEMBLED`
  ])])
))

export async function loadEcosystemMigrationMatrix (
  matrixPath = ECOSYSTEM_MIGRATION_MATRIX_PATH,
  retirementPolicy
) {
  const bytes = await fs.readFile(matrixPath)
  if (bytes.byteLength === 0 || bytes.byteLength > 2 * 1024 * 1024) {
    matrixFailure('ecosystem migration matrix must be 1..2097152 bytes')
  }
  let matrix
  try {
    matrix = JSON.parse(bytes.toString('utf8'))
  } catch (error) {
    matrixFailure(`ecosystem migration matrix is not valid JSON: ${error.message}`)
  }
  const policy = retirementPolicy || await loadLegacyRetirementPolicy()
  return validateEcosystemMigrationMatrix(matrix, policy)
}

export function validateEcosystemMigrationMatrix (matrix, retirementPolicy) {
  assertPlainObject(matrix, 'matrix')
  assertAllowedKeys(matrix, [
    'matrixVersion',
    'matrixId',
    'decisionAuthority',
    'authorizationRule',
    'boundaries',
    'externalDependencies',
    'rolloutTracks',
    'legacyComponents',
    'applications',
    'evidenceProfiles',
    'evidenceCatalog'
  ], 'matrix')
  rejectAuthorizationBooleans(matrix)
  if (matrix.matrixVersion !== 1) matrixFailure('matrixVersion must equal 1')
  if (matrix.matrixId !== 'hiverelay.blind.ecosystem-migration.v1') {
    matrixFailure('matrixId does not match the registered ecosystem migration matrix')
  }
  if (matrix.decisionAuthority !== 'computed-code-owned-blockers-only') {
    matrixFailure('decisionAuthority must remain computed-code-owned-blockers-only')
  }

  assertPlainObject(matrix.authorizationRule, 'authorizationRule')
  assertAllowedKeys(matrix.authorizationRule, [
    'computedBy', 'editableDecisionFields', 'legacyRemovalPolicy', 'rule'
  ], 'authorizationRule')
  if (matrix.authorizationRule.computedBy !== 'scripts/verify-blind-ecosystem-migration.mjs') {
    matrixFailure('authorizationRule.computedBy does not name the registered verifier')
  }
  if (matrix.authorizationRule.editableDecisionFields !== 'forbidden') {
    matrixFailure('authorizationRule.editableDecisionFields must equal forbidden')
  }
  if (matrix.authorizationRule.legacyRemovalPolicy !== 'deploy/blind/legacy-retirement-policy.json') {
    matrixFailure('authorizationRule.legacyRemovalPolicy does not name the registered policy')
  }
  assertNonEmptyString(matrix.authorizationRule.rule, 'authorizationRule.rule')

  assertExactIdRows(matrix.boundaries, BOUNDARY_IDS, 'boundaries', row => {
    const keys = ['id', 'allowedSurface', 'owner', 'visibility']
    if (row.id === 'blind-relay-base') keys.push('forbiddenResponsibilities')
    assertAllowedKeys(row, keys, `boundary ${row.id}`)
    assertNonEmptyStringArray(row.allowedSurface, `boundary ${row.id}.allowedSurface`)
    assertNonEmptyString(row.owner, `boundary ${row.id}.owner`)
    assertNonEmptyString(row.visibility, `boundary ${row.id}.visibility`)
    if (row.id === 'blind-relay-base') {
      assertExactStringArray(
        row.allowedSurface,
        ['DESCRIBE', ...FAMILY_IDS],
        'blind-relay-base.allowedSurface'
      )
      assertNonEmptyStringArray(row.forbiddenResponsibilities, 'blind-relay-base.forbiddenResponsibilities')
    }
  })

  assertExactIdRows(matrix.externalDependencies, EXTERNAL_DEPENDENCY_IDS, 'externalDependencies', row => {
    assertAllowedKeys(row, ['id', 'boundary', 'purpose'], `external dependency ${row.id}`)
    if (row.boundary !== EXTERNAL_DEPENDENCY_BOUNDARIES[row.id]) {
      matrixFailure(`external dependency ${row.id} is assigned to the wrong boundary`)
    }
    if (row.boundary === 'blind-relay-base') {
      matrixFailure(`external dependency ${row.id} cannot be assigned to blind-relay-base`)
    }
    assertNonEmptyString(row.purpose, `external dependency ${row.id}.purpose`)
  })

  assertExactIdRows(matrix.rolloutTracks, ROLLOUT_TRACK_IDS, 'rolloutTracks', row => {
    assertAllowedKeys(row, ['id', 'sequence'], `rollout track ${row.id}`)
    assertNonEmptyStringArray(row.sequence, `rollout track ${row.id}.sequence`)
    if (row.sequence[0] !== 'inventory' || row.sequence.at(-1) !== 'legacy-drain') {
      matrixFailure(`rollout track ${row.id} must begin at inventory and end at legacy-drain`)
    }
  })

  assertRetirementPolicy(retirementPolicy)
  const retirementComponents = new Map(retirementPolicy.components.map(row => [row.id, row]))
  const dependencyIds = new Set(EXTERNAL_DEPENDENCY_IDS)
  const rolloutIds = new Set(ROLLOUT_TRACK_IDS)
  assertExactIdRows(matrix.legacyComponents, COMPONENT_IDS, 'legacyComponents', row => {
    assertAllowedKeys(row, [
      'id',
      'semanticOwner',
      'families',
      'outsideBaseDependencies',
      'retainedSemantics',
      'rolloutTrack',
      'cutoverGates',
      'requiredEvidenceIds'
    ], `legacy component ${row.id}`)
    assertNonEmptyString(row.semanticOwner, `legacy component ${row.id}.semanticOwner`)
    assertFamilyArray(row.families, `legacy component ${row.id}.families`, row.id === 'operator-control-economics')
    assertReferences(row.outsideBaseDependencies, dependencyIds, `legacy component ${row.id}.outsideBaseDependencies`, true)
    assertNonEmptyStringArray(row.retainedSemantics, `legacy component ${row.id}.retainedSemantics`)
    if (!rolloutIds.has(row.rolloutTrack)) matrixFailure(`legacy component ${row.id} has an unknown rolloutTrack`)
    const retirementRow = retirementComponents.get(row.id)
    const expectedCutoverGates = retirementRow.deletionGates.filter(gate => gate !== 'G8')
    assertExactStringArray(row.cutoverGates, expectedCutoverGates, `legacy component ${row.id}.cutoverGates`)
    assertExactStringArray(
      row.requiredEvidenceIds,
      expectedCutoverGates.map(gate => EVIDENCE_BY_GATE[gate]),
      `legacy component ${row.id}.requiredEvidenceIds`
    )
  })

  assertExactIdRows(matrix.evidenceCatalog, EVIDENCE_IDS, 'evidenceCatalog', (row, index) => {
    assertAllowedKeys(row, ['id', 'gate'], `evidence ${row.id}`)
    if (row.gate !== GATE_IDS[index]) matrixFailure(`evidence ${row.id} is bound to the wrong gate`)
  })
  assertExactIdRows(matrix.evidenceProfiles, ['full-application-cutover'], 'evidenceProfiles', row => {
    assertAllowedKeys(row, ['id', 'requiredGates', 'requiredEvidenceIds'], `evidence profile ${row.id}`)
    assertExactStringArray(row.requiredGates, GATE_IDS.slice(0, 8), `evidence profile ${row.id}.requiredGates`)
    assertExactStringArray(row.requiredEvidenceIds, EVIDENCE_IDS.slice(0, 8),
      `evidence profile ${row.id}.requiredEvidenceIds`)
  })

  const componentIds = new Set(COMPONENT_IDS)
  assertExactIdRows(matrix.applications, APPLICATION_IDS, 'applications', row => {
    assertAllowedKeys(row, [
      'id',
      'name',
      'families',
      'retainedSemantics',
      'outsideBaseDependencies',
      'legacyDependencies',
      'rolloutTrack',
      'evidenceProfile'
    ], `application ${row.id}`)
    assertNonEmptyString(row.name, `application ${row.id}.name`)
    assertFamilyArray(row.families, `application ${row.id}.families`)
    assertNonEmptyStringArray(row.retainedSemantics, `application ${row.id}.retainedSemantics`)
    assertReferences(row.outsideBaseDependencies, dependencyIds, `application ${row.id}.outsideBaseDependencies`, true)
    assertReferences(row.legacyDependencies, componentIds, `application ${row.id}.legacyDependencies`, true)
    if (!rolloutIds.has(row.rolloutTrack)) matrixFailure(`application ${row.id} has an unknown rolloutTrack`)
    if (row.evidenceProfile !== 'full-application-cutover') {
      matrixFailure(`application ${row.id} must use full-application-cutover evidence`)
    }
  })
  return matrix
}

export function ecosystemMigrationGateReports () {
  const productionBlockers = productionRetirementBlockers()
  const retirementEvidenceByGate = new Map(GATE_IDS.map(gate => [gate, []]))
  for (const code of LEGACY_RETIREMENT_EVIDENCE_BLOCKERS) {
    const match = /^(G[2-8])_/.exec(code)
    if (!match) matrixFailure(`retirement evidence blocker has no registered gate: ${code}`)
    retirementEvidenceByGate.get(match[1]).push(blocker(
      'blind-legacy-retirement.LEGACY_RETIREMENT_EVIDENCE_BLOCKERS',
      code
    ))
  }

  const gateBlockers = {
    G0: productionBlockers.filter(row =>
      FINAL_AUTHORITY_PRODUCTION_SOURCES.has(row.source) || FINAL_AUTHORITY_RUNTIME_CODES.has(row.code)
    ),
    G1: productionBlockers.filter(row => row.source !== BROWSER_ARTIFACT_PRODUCTION_SOURCE),
    G2: retirementEvidenceByGate.get('G2'),
    G3: retirementEvidenceByGate.get('G3'),
    G4: retirementEvidenceByGate.get('G4'),
    G5: retirementEvidenceByGate.get('G5'),
    G6: [
      ...productionBlockers.filter(row => CROSS_RUNTIME_PRODUCTION_SOURCES.has(row.source)),
      ...retirementEvidenceByGate.get('G6')
    ],
    G7: retirementEvidenceByGate.get('G7'),
    G8: retirementEvidenceByGate.get('G8')
  }

  return Object.freeze(GATE_IDS.map(gate => {
    const blockers = uniqueBlockers(gateBlockers[gate])
    return Object.freeze({
      gate,
      evidenceId: EVIDENCE_BY_GATE[gate],
      status: blockers.length === 0 ? 'satisfied' : 'blocked',
      satisfied: blockers.length === 0,
      blockerCount: blockers.length,
      blockers
    })
  }))
}

export function evaluateEcosystemMigration (matrix, retirementPolicy) {
  validateEcosystemMigrationMatrix(matrix, retirementPolicy)
  const gates = ecosystemMigrationGateReports()
  const gatesById = new Map(gates.map(row => [row.gate, row]))
  const profile = matrix.evidenceProfiles[0]

  const applications = Object.freeze(matrix.applications.map(row => {
    const rowBlockers = APPLICATION_MIGRATION_EVIDENCE_BLOCKERS[row.id].map(code => blocker(
      `blind-ecosystem-migration.APPLICATION_MIGRATION_EVIDENCE_BLOCKERS.${row.id}`,
      code
    ))
    const blockers = uniqueBlockers([
      ...profile.requiredGates.flatMap(gate => gatesById.get(gate).blockers),
      ...rowBlockers
    ])
    const blockedGates = profile.requiredGates.filter(gate => !gatesById.get(gate).satisfied)
    return Object.freeze({
      id: row.id,
      status: blockers.length === 0 ? 'cutover-authorized' : 'cutover-blocked',
      cutoverAuthorized: blockers.length === 0,
      rolloutTrack: row.rolloutTrack,
      families: Object.freeze([...row.families]),
      blockedGates: Object.freeze(blockedGates),
      blockerCount: blockers.length,
      blockers
    })
  }))

  const retirementReport = evaluateLegacyRetirement(retirementPolicy)
  const components = Object.freeze(matrix.legacyComponents.map(row => {
    const rowBlockers = COMPONENT_MIGRATION_EVIDENCE_BLOCKERS[row.id].map(code => blocker(
      `blind-ecosystem-migration.COMPONENT_MIGRATION_EVIDENCE_BLOCKERS.${row.id}`,
      code
    ))
    const cutoverBlockers = uniqueBlockers([
      ...row.cutoverGates.flatMap(gate => gatesById.get(gate).blockers),
      ...rowBlockers
    ])
    const removalBlockers = uniqueBlockers([...retirementReport.blockers, ...rowBlockers])
    return Object.freeze({
      id: row.id,
      cutoverStatus: cutoverBlockers.length === 0 ? 'cutover-authorized' : 'cutover-blocked',
      cutoverAuthorized: cutoverBlockers.length === 0,
      removalStatus: removalBlockers.length === 0 ? 'removal-authorized' : 'removal-blocked',
      removalAuthorized: removalBlockers.length === 0,
      blockedGates: Object.freeze(row.cutoverGates.filter(gate => !gatesById.get(gate).satisfied)),
      cutoverBlockerCount: cutoverBlockers.length,
      removalBlockerCount: removalBlockers.length,
      cutoverBlockers,
      removalBlockers
    })
  }))

  const allApplicationCutoversAuthorized = applications.every(row => row.cutoverAuthorized)
  const allLegacyComponentCutoversAuthorized = components.every(row => row.cutoverAuthorized)
  const allLegacyRemovalsAuthorized = components.every(row => row.removalAuthorized)
  const authorized = allApplicationCutoversAuthorized && allLegacyComponentCutoversAuthorized &&
    allLegacyRemovalsAuthorized
  return Object.freeze({
    matrixId: matrix.matrixId,
    matrixVersion: matrix.matrixVersion,
    decisionAuthority: matrix.decisionAuthority,
    status: authorized ? 'authorized' : 'blocked',
    authorized,
    allApplicationCutoversAuthorized,
    allLegacyComponentCutoversAuthorized,
    allLegacyRemovalsAuthorized,
    applicationCount: applications.length,
    legacyComponentCount: components.length,
    externalDependencyCount: matrix.externalDependencies.length,
    boundaryCount: matrix.boundaries.length,
    productionBlockerCount: productionRetirementBlockers().length,
    retirementBlockerCount: retirementReport.blockerCount,
    gates,
    applications,
    legacyComponents: components
  })
}

export function assertAllApplicationCutoversAuthorized (matrix, retirementPolicy) {
  const report = evaluateEcosystemMigration(matrix, retirementPolicy)
  if (report.allApplicationCutoversAuthorized) return report
  const error = new Error('one or more ecosystem application cutovers are blocked by code-owned evidence')
  error.code = 'BLIND_ECOSYSTEM_APPLICATION_CUTOVER_BLOCKED'
  error.report = report
  throw error
}

export function assertAllLegacyRemovalsAuthorized (matrix, retirementPolicy) {
  const report = evaluateEcosystemMigration(matrix, retirementPolicy)
  if (report.allLegacyRemovalsAuthorized) return report
  const error = new Error('one or more legacy component removals are blocked by code-owned evidence')
  error.code = 'BLIND_ECOSYSTEM_LEGACY_REMOVAL_BLOCKED'
  error.report = report
  throw error
}

function assertRetirementPolicy (policy) {
  assertPlainObject(policy, 'retirementPolicy')
  if (!Array.isArray(policy.components)) matrixFailure('retirementPolicy.components must be an array')
  assertExactStringArray(
    policy.components.map(row => row.id),
    COMPONENT_IDS,
    'retirementPolicy component ids'
  )
}

function assertFamilyArray (families, field, allowEmpty = false) {
  if (!Array.isArray(families) || (!allowEmpty && families.length === 0)) {
    matrixFailure(`${field} must be ${allowEmpty ? 'an array' : 'a non-empty array'}`)
  }
  const expected = FAMILY_IDS.filter(family => families.includes(family))
  assertExactStringArray(families, expected, field)
}

function assertReferences (values, authority, field, allowEmpty = false) {
  if (!Array.isArray(values) || (!allowEmpty && values.length === 0)) {
    matrixFailure(`${field} must be ${allowEmpty ? 'an array' : 'a non-empty array'}`)
  }
  const seen = new Set()
  for (const value of values) {
    assertNonEmptyString(value, field)
    if (!authority.has(value)) matrixFailure(`${field} references unknown value ${value}`)
    if (seen.has(value)) matrixFailure(`${field} contains a duplicate value`)
    seen.add(value)
  }
}

function rejectAuthorizationBooleans (value, at = 'matrix') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => rejectAuthorizationBooleans(entry, `${at}[${index}]`))
    return
  }
  if (!value || typeof value !== 'object') return
  for (const [key, entry] of Object.entries(value)) {
    const normalized = key.replace(/[^a-z0-9]/gi, '').toLowerCase()
    if (typeof entry === 'boolean' &&
        /(authorized|authorization|approved|ready|candelete|canremove|canmigrate|cancutover)/.test(normalized)) {
      matrixFailure(`${at}.${key} is a forbidden hand-editable decision boolean`)
    }
    rejectAuthorizationBooleans(entry, `${at}.${key}`)
  }
}

function assertAllowedKeys (value, allowed, field) {
  assertPlainObject(value, field)
  const allowedSet = new Set(allowed)
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) matrixFailure(`${field} contains unknown field ${key}`)
  }
  for (const key of allowed) {
    if (!Object.hasOwn(value, key)) matrixFailure(`${field} is missing field ${key}`)
  }
}

function assertExactIdRows (rows, expectedIds, field, inspect) {
  if (!Array.isArray(rows)) matrixFailure(`${field} must be an array`)
  assertExactStringArray(rows.map(row => {
    assertPlainObject(row, `${field} row`)
    assertNonEmptyString(row.id, `${field} row id`)
    return row.id
  }), expectedIds, `${field} ids`)
  rows.forEach(inspect)
}

function assertExactStringArray (actual, expected, field) {
  if (!Array.isArray(actual) || actual.length !== expected.length ||
      actual.some((value, index) => value !== expected[index])) {
    matrixFailure(`${field} must equal the registered ordered values`)
  }
}

function assertNonEmptyStringArray (value, field) {
  if (!Array.isArray(value) || value.length === 0) matrixFailure(`${field} must be a non-empty array`)
  const seen = new Set()
  for (const entry of value) {
    assertNonEmptyString(entry, field)
    if (seen.has(entry)) matrixFailure(`${field} contains a duplicate value`)
    seen.add(entry)
  }
}

function assertNonEmptyString (value, field) {
  if (typeof value !== 'string' || value.length === 0 || value !== value.trim()) {
    matrixFailure(`${field} must be a non-empty trimmed string`)
  }
}

function assertPlainObject (value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    matrixFailure(`${field} must be a plain object`)
  }
}

function blockerToken (id) {
  return id.replace(/[^a-z0-9]/gi, '_').toUpperCase()
}

function blocker (source, code) {
  return Object.freeze({ source, code })
}

function uniqueBlockers (rows) {
  const byKey = new Map()
  for (const row of rows) {
    const normalized = blocker(row.source, row.code)
    byKey.set(`${normalized.source}\0${normalized.code}`, normalized)
  }
  return Object.freeze([...byKey.values()].sort((left, right) =>
    left.source.localeCompare(right.source) || left.code.localeCompare(right.code)
  ))
}

function matrixFailure (message) {
  const error = new Error(message)
  error.code = 'BLIND_ECOSYSTEM_MIGRATION_MATRIX_INVALID'
  throw error
}

async function main () {
  const args = new Set(process.argv.slice(2))
  for (const arg of args) {
    if (arg !== '--json' && arg !== '--require-cutovers' && arg !== '--require-removals') {
      throw new Error(`unknown argument: ${arg}`)
    }
  }
  const retirementPolicy = await loadLegacyRetirementPolicy()
  const matrix = await loadEcosystemMigrationMatrix(ECOSYSTEM_MIGRATION_MATRIX_PATH, retirementPolicy)
  const report = evaluateEcosystemMigration(matrix, retirementPolicy)
  process.stdout.write(`${JSON.stringify(report, null, args.has('--json') ? 2 : 0)}\n`)
  if (args.has('--require-cutovers') &&
      (!report.allApplicationCutoversAuthorized || !report.allLegacyComponentCutoversAuthorized)) {
    process.exitCode = 1
  }
  if (args.has('--require-removals') && !report.allLegacyRemovalsAuthorized) process.exitCode = 1
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(`${error.stack || error.message}\n`)
    process.exitCode = 1
  })
}
