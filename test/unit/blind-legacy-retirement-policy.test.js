import test from 'brittle'
import {
  LEGACY_RETIREMENT_EVIDENCE_BLOCKERS,
  assertLegacyRetirementAuthorized,
  evaluateLegacyRetirement,
  loadLegacyRetirementPolicy,
  productionRetirementBlockers,
  validateLegacyRetirementPolicy
} from '../../scripts/verify-blind-legacy-retirement-policy.mjs'

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

test('blind legacy retirement policy validates the complete registered matrix', async t => {
  const policy = await loadLegacyRetirementPolicy()

  t.is(policy.policyId, 'hiverelay.blind.legacy-retirement.v1')
  t.alike(policy.gates.map(gate => gate.id), ['G0', 'G1', 'G2', 'G3', 'G4', 'G5', 'G6', 'G7', 'G8'])
  t.is(policy.components.length, 14)
  t.is(policy.forbiddenClaims.length, 10)
  t.is(policy.realEvidence.length, 10)
  for (const component of policy.components) t.ok(component.deletionGates.includes('G8'))
})

test('blind legacy retirement authorization is derived from live production blockers and is false now', async t => {
  const policy = await loadLegacyRetirementPolicy()
  const productionBlockers = productionRetirementBlockers()
  const report = evaluateLegacyRetirement(policy)

  t.ok(productionBlockers.length > 0)
  t.ok(productionBlockers.some(row => row.source === 'blind-daemon.PRODUCTION_RUNTIME_EXCLUSIONS'))
  t.ok(productionBlockers.some(row => row.code === 'INBOX_PUBLIC_EXECUTION_UNASSEMBLED'))
  t.ok(productionBlockers.some(row => row.code === 'CORE_PUBLIC_EXECUTION_UNASSEMBLED'))
  t.ok(productionBlockers.some(row => row.code === 'FORWARD_PUBLIC_EXECUTION_UNASSEMBLED'))
  t.is(report.authorized, false)
  t.is(report.status, 'blocked')
  t.is(report.productionBlockerCount, productionBlockers.length)
  t.is(report.retirementEvidenceBlockerCount, LEGACY_RETIREMENT_EVIDENCE_BLOCKERS.length)
  t.ok(report.blockerCount >= productionBlockers.length + LEGACY_RETIREMENT_EVIDENCE_BLOCKERS.length)
})

test('blind legacy retirement policy rejects hand-editable deletion authorization booleans', async t => {
  const policy = clone(await loadLegacyRetirementPolicy())
  policy.retirementAuthorized = true

  const error = thrown(() => validateLegacyRetirementPolicy(policy))
  t.is(error.code, 'BLIND_LEGACY_RETIREMENT_POLICY_INVALID')
  t.ok(error.message.includes('forbidden hand-editable authorization boolean'))
})

test('blind legacy retirement policy rejects misleading or unknown fields at every object level', async t => {
  const policy = await loadLegacyRetirementPolicy()
  const mutations = [
    value => { value.status = 'authorized' },
    value => { value.authorizationRule.gatePassed = 'yes' },
    value => { value.gates[0].status = 'satisfied' },
    value => { value.components[0].gatePassed = 'true' },
    value => { value.forbiddenClaims[0].unknown = 'ignored' },
    value => { value.realEvidence[0].status = 'verified' },
    value => { value.retirementSequence[0].gatePassed = 'yes' }
  ]

  for (const mutate of mutations) {
    const changed = clone(policy)
    mutate(changed)
    const error = thrown(() => validateLegacyRetirementPolicy(changed))
    t.is(error.code, 'BLIND_LEGACY_RETIREMENT_POLICY_INVALID')
    t.ok(error.message.includes('exactly the registered fields'))
  }
})

test('blind legacy retirement policy cannot authorize by deleting gates or blocker sources', async t => {
  const noGate = clone(await loadLegacyRetirementPolicy())
  noGate.gates.pop()
  const gateError = thrown(() => validateLegacyRetirementPolicy(noGate))
  t.is(gateError.code, 'BLIND_LEGACY_RETIREMENT_POLICY_INVALID')

  const noSource = clone(await loadLegacyRetirementPolicy())
  noSource.authorizationRule.blockerSources.pop()
  const sourceError = thrown(() => validateLegacyRetirementPolicy(noSource))
  t.is(sourceError.code, 'BLIND_LEGACY_RETIREMENT_POLICY_INVALID')
})

test('blind legacy retirement assertion fails closed with the computed report', async t => {
  const policy = await loadLegacyRetirementPolicy()
  const error = thrown(() => assertLegacyRetirementAuthorized(policy))

  t.is(error.code, 'BLIND_LEGACY_RETIREMENT_BLOCKED')
  t.is(error.report.authorized, false)
  t.ok(error.report.blockingCodes.includes('G8_ZERO_TRAFFIC_RETIREMENT_EVIDENCE_AUTHORITY_UNASSEMBLED'))
})
