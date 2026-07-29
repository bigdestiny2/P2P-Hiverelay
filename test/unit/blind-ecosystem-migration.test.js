import test from 'brittle'
import {
  APPLICATION_MIGRATION_EVIDENCE_BLOCKERS,
  COMPONENT_MIGRATION_EVIDENCE_BLOCKERS,
  assertAllApplicationCutoversAuthorized,
  assertAllLegacyRemovalsAuthorized,
  ecosystemMigrationGateReports,
  evaluateEcosystemMigration,
  loadEcosystemMigrationMatrix,
  validateEcosystemMigrationMatrix
} from '../../scripts/verify-blind-ecosystem-migration.mjs'
import { loadLegacyRetirementPolicy } from '../../scripts/verify-blind-legacy-retirement-policy.mjs'

function clone (value) {
  return JSON.parse(JSON.stringify(value))
}

function thrown (operation) {
  try {
    operation()
  } catch (error) {
    return error
  }
  throw new Error('expected operation to throw')
}

test('blind ecosystem matrix registers the complete app, component and boundary inventory', async t => {
  const policy = await loadLegacyRetirementPolicy()
  const matrix = await loadEcosystemMigrationMatrix(undefined, policy)

  t.is(matrix.matrixId, 'hiverelay.blind.ecosystem-migration.v1')
  t.is(matrix.applications.length, 25)
  t.is(matrix.legacyComponents.length, 14)
  t.is(matrix.externalDependencies.length, 14)
  t.alike(matrix.boundaries.map(row => row.id), [
    'blind-relay-base',
    'application-client',
    'nonblind-provider',
    'nonblind-index',
    'operator-control'
  ])
  t.alike(matrix.boundaries[0].allowedSurface, ['DESCRIBE', 'CELL', 'INBOX', 'CORE', 'FORWARD'])
  t.ok(matrix.applications.some(row => row.id === 'peerit'))
  t.ok(matrix.applications.some(row => row.id === 'anongpt'))
  t.ok(matrix.applications.some(row => row.id === 'platforms'))
  t.alike(matrix.legacyComponents.map(row => row.id), policy.components.map(row => row.id))
})

test('blind ecosystem decisions are computed from current blockers and fail closed', async t => {
  const policy = await loadLegacyRetirementPolicy()
  const matrix = await loadEcosystemMigrationMatrix(undefined, policy)
  const report = evaluateEcosystemMigration(matrix, policy)

  t.is(report.status, 'blocked')
  t.is(report.authorized, false)
  t.is(report.allApplicationCutoversAuthorized, false)
  t.is(report.allLegacyComponentCutoversAuthorized, false)
  t.is(report.allLegacyRemovalsAuthorized, false)
  t.ok(report.productionBlockerCount > 0)
  t.is(report.applicationCount, 25)
  t.is(report.legacyComponentCount, 14)

  const runtimeGate = report.gates.find(row => row.gate === 'G1')
  t.is(runtimeGate.satisfied, false)
  t.ok(runtimeGate.blockers.some(row => row.code === 'INBOX_PUBLIC_EXECUTION_UNASSEMBLED'))
  t.ok(runtimeGate.blockers.some(row => row.code === 'CORE_PUBLIC_EXECUTION_UNASSEMBLED'))
  t.ok(runtimeGate.blockers.some(row => row.code === 'FORWARD_PUBLIC_EXECUTION_UNASSEMBLED'))

  const peerit = report.applications.find(row => row.id === 'peerit')
  t.is(peerit.cutoverAuthorized, false)
  t.ok(peerit.blockers.some(row =>
    row.code === 'APPLICATION_PEERIT_SEMANTIC_PARITY_AUTHORITY_UNASSEMBLED'
  ))
  const outboxlog = report.legacyComponents.find(row => row.id === 'outboxlog')
  t.is(outboxlog.cutoverAuthorized, false)
  t.is(outboxlog.removalAuthorized, false)
  t.ok(outboxlog.removalBlockers.some(row =>
    row.code === 'G8_ZERO_TRAFFIC_RETIREMENT_EVIDENCE_AUTHORITY_UNASSEMBLED'
  ))
})

test('every application and component has a separate code-owned parity authority', async t => {
  const policy = await loadLegacyRetirementPolicy()
  const matrix = await loadEcosystemMigrationMatrix(undefined, policy)

  t.alike(Object.keys(APPLICATION_MIGRATION_EVIDENCE_BLOCKERS), matrix.applications.map(row => row.id))
  t.alike(Object.keys(COMPONENT_MIGRATION_EVIDENCE_BLOCKERS), matrix.legacyComponents.map(row => row.id))
  for (const blockers of Object.values(APPLICATION_MIGRATION_EVIDENCE_BLOCKERS)) t.is(blockers.length, 1)
  for (const blockers of Object.values(COMPONENT_MIGRATION_EVIDENCE_BLOCKERS)) t.is(blockers.length, 1)
})

test('matrix rejects editable readiness and deletion decisions', async t => {
  const policy = await loadLegacyRetirementPolicy()
  const matrix = clone(await loadEcosystemMigrationMatrix(undefined, policy))
  matrix.applications[0].cutoverReady = true

  const error = thrown(() => validateEcosystemMigrationMatrix(matrix, policy))
  t.is(error.code, 'BLIND_ECOSYSTEM_MIGRATION_MATRIX_INVALID')
  t.ok(error.message.includes('forbidden hand-editable decision boolean'))
})

test('matrix rejects app semantics in DESCRIBE or undeclared blind-base dependencies', async t => {
  const policy = await loadLegacyRetirementPolicy()

  const semanticDescribe = clone(await loadEcosystemMigrationMatrix(undefined, policy))
  semanticDescribe.applications[0].families.unshift('DESCRIBE')
  const familyError = thrown(() => validateEcosystemMigrationMatrix(semanticDescribe, policy))
  t.is(familyError.code, 'BLIND_ECOSYSTEM_MIGRATION_MATRIX_INVALID')

  const dependencyInBase = clone(await loadEcosystemMigrationMatrix(undefined, policy))
  dependencyInBase.externalDependencies[0].boundary = 'blind-relay-base'
  const boundaryError = thrown(() => validateEcosystemMigrationMatrix(dependencyInBase, policy))
  t.is(boundaryError.code, 'BLIND_ECOSYSTEM_MIGRATION_MATRIX_INVALID')
  t.ok(boundaryError.message.includes('wrong boundary'))
})

test('matrix cannot omit an app, component, gate-derived evidence row or legacy dependency', async t => {
  const policy = await loadLegacyRetirementPolicy()

  const noApp = clone(await loadEcosystemMigrationMatrix(undefined, policy))
  noApp.applications.pop()
  t.is(thrown(() => validateEcosystemMigrationMatrix(noApp, policy)).code,
    'BLIND_ECOSYSTEM_MIGRATION_MATRIX_INVALID')

  const noComponent = clone(await loadEcosystemMigrationMatrix(undefined, policy))
  noComponent.legacyComponents.pop()
  t.is(thrown(() => validateEcosystemMigrationMatrix(noComponent, policy)).code,
    'BLIND_ECOSYSTEM_MIGRATION_MATRIX_INVALID')

  const noEvidence = clone(await loadEcosystemMigrationMatrix(undefined, policy))
  noEvidence.legacyComponents[1].requiredEvidenceIds.pop()
  t.is(thrown(() => validateEcosystemMigrationMatrix(noEvidence, policy)).code,
    'BLIND_ECOSYSTEM_MIGRATION_MATRIX_INVALID')

  const unknownLegacy = clone(await loadEcosystemMigrationMatrix(undefined, policy))
  unknownLegacy.applications[0].legacyDependencies[0] = 'invented-relay-service'
  t.is(thrown(() => validateEcosystemMigrationMatrix(unknownLegacy, policy)).code,
    'BLIND_ECOSYSTEM_MIGRATION_MATRIX_INVALID')
})

test('strict cutover and removal assertions expose computed reports', async t => {
  const policy = await loadLegacyRetirementPolicy()
  const matrix = await loadEcosystemMigrationMatrix(undefined, policy)

  const cutoverError = thrown(() => assertAllApplicationCutoversAuthorized(matrix, policy))
  t.is(cutoverError.code, 'BLIND_ECOSYSTEM_APPLICATION_CUTOVER_BLOCKED')
  t.is(cutoverError.report.allApplicationCutoversAuthorized, false)

  const removalError = thrown(() => assertAllLegacyRemovalsAuthorized(matrix, policy))
  t.is(removalError.code, 'BLIND_ECOSYSTEM_LEGACY_REMOVAL_BLOCKED')
  t.is(removalError.report.allLegacyRemovalsAuthorized, false)
})

test('gate evidence remains one-to-one and all current gates fail closed', t => {
  const gates = ecosystemMigrationGateReports()

  t.alike(gates.map(row => row.gate), ['G0', 'G1', 'G2', 'G3', 'G4', 'G5', 'G6', 'G7', 'G8'])
  t.alike(gates.map(row => row.evidenceId), [
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
  t.ok(gates.every(row => row.satisfied === false))

  const finalAuthorities = gates.find(row => row.gate === 'G0')
  for (const source of [
    'blind-daemon.BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS',
    'blind-daemon.BLIND_INBOX_STORAGE_BLOCKERS',
    'blind-daemon.BLIND_CORE_STORAGE_BLOCKERS'
  ]) {
    t.ok(finalAuthorities.blockers.some(row =>
      row.source === source && row.code === 'FINAL_STORE_FORMAT_AUTHORITY_UNPUBLISHED'
    ), `${source} remains bound to G0`)
  }
})
