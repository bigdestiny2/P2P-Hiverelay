import test from 'brittle'
import { readFile } from 'fs/promises'
import {
  buildWitnessQuorumPolicy,
  evaluateWitnessQuorum,
  validateWitnessQuorumPolicy
} from 'p2p-hiverelay/core/protocol/witness-quorum-policy.js'

const VECTOR_URL = new URL(
  '../fixtures/relaykernel-profile/witness-quorum-policy-v1-5-of-7-diverse.json',
  import.meta.url
)

async function loadVector () {
  return JSON.parse(await readFile(VECTOR_URL, 'utf8'))
}

function hex (byte) {
  return byte.repeat(32)
}

function witness (n, overrides = {}) {
  return {
    witnessPubkey: String(n).padStart(2, '0').repeat(32),
    operator: 'operator-' + n,
    region: ['us-east', 'eu-west', 'ap-south', 'sa-east', 'me-central', 'af-south', 'ca-central'][n - 1] || 'moon',
    ...overrides
  }
}

function baseInput (overrides = {}) {
  return {
    intentId: hex('aa'),
    subjectRelayPubkey: hex('bb'),
    publisherPubkey: hex('cc'),
    selectedBy: 'publisher',
    witnessCount: 7,
    requiredWitnesses: 5,
    minOperators: 5,
    minRegions: 5,
    witnesses: [1, 2, 3, 4, 5, 6, 7].map(n => witness(n)),
    ...overrides
  }
}

function entryFor (policy, witnessPubkey, overrides = {}) {
  return {
    type: 'custody-expiry-witness',
    intentId: policy.intentId,
    relayPubkey: policy.subjectRelayPubkey,
    witnessPubkey,
    catalogPresent: false,
    gatewayServing: false,
    activeSwarmObserved: false,
    ...overrides
  }
}

test('witness quorum policy vector pins publisher-selected 5-of-7 diversity', async (t) => {
  const vector = await loadVector()
  const policy = buildWitnessQuorumPolicy(vector.input)
  const verdict = validateWitnessQuorumPolicy(policy)
  const quorum = evaluateWitnessQuorum(
    policy,
    policy.witnesses.slice(0, 5).map(w => entryFor(policy, w.witnessPubkey))
  )

  t.alike(verdict, vector.verdict, 'policy verdict matches fixture')
  t.alike(quorum, vector.quorum, 'quorum verdict matches fixture')
  t.is(policy.summary.operators.length, 7, 'all witnesses are operator-diverse')
  t.is(policy.summary.regions.length, 7, 'all witnesses are region-diverse')
})

test('witness quorum policy requires publisher-selected witness set', (t) => {
  const policy = buildWitnessQuorumPolicy(baseInput({ selectedBy: 'vault' }))
  const verdict = validateWitnessQuorumPolicy(policy)

  t.absent(verdict.valid)
  t.ok(verdict.errors.includes('witness set must be publisher-selected'))
})

test('witness quorum policy rejects subject self-witness and duplicate witnesses', (t) => {
  const policy = buildWitnessQuorumPolicy(baseInput({
    witnesses: [
      witness(1, { witnessPubkey: hex('bb') }),
      witness(2),
      witness(2),
      witness(4),
      witness(5),
      witness(6),
      witness(7)
    ]
  }))
  const verdict = validateWitnessQuorumPolicy(policy)

  t.absent(verdict.valid)
  t.ok(verdict.errors.includes('subject relay cannot witness itself'))
  t.ok(verdict.errors.some(error => error.startsWith('duplicate witnessPubkey:')))
})

test('witness quorum policy rejects weak operator or region diversity', (t) => {
  const lowOperator = buildWitnessQuorumPolicy(baseInput({
    witnesses: [1, 2, 3, 4, 5, 6, 7].map(n => witness(n, { operator: 'same-operator' }))
  }))
  const lowOperatorVerdict = validateWitnessQuorumPolicy(lowOperator)
  t.absent(lowOperatorVerdict.valid)
  t.ok(lowOperatorVerdict.errors.includes('insufficient witness operator diversity'))

  const lowRegion = buildWitnessQuorumPolicy(baseInput({
    witnesses: [1, 2, 3, 4, 5, 6, 7].map(n => witness(n, { region: 'same-region' }))
  }))
  const lowRegionVerdict = validateWitnessQuorumPolicy(lowRegion)
  t.absent(lowRegionVerdict.valid)
  t.ok(lowRegionVerdict.errors.includes('insufficient witness region diversity'))
})

test('witness quorum policy fails closed on malformed witness policy shape', (t) => {
  const policy = buildWitnessQuorumPolicy(baseInput())
  policy.witnesses[0] = null
  policy.minOperators = -1
  policy.minRegions = -1
  const verdict = validateWitnessQuorumPolicy(policy)

  t.absent(verdict.valid)
  t.ok(verdict.errors.includes('witness object required'))
  t.ok(verdict.errors.includes('minOperators must be a non-negative integer'))
  t.ok(verdict.errors.includes('minRegions must be a non-negative integer'))
})

test('witness quorum policy requires T3 witness role by default', (t) => {
  const badTierProfile = {
    kind: 'hivemesh-tier-profile',
    version: 1,
    tier: 't3',
    role: 'witness',
    keyPrefix: 'rk1',
    capabilities: ['tombstone-signing', 'non-serving-observation', 'gateway'],
    network: { gateway: true, circuit: false, publicDht: false, publicDirectory: false, httpSurfaces: [] },
    storage: { storesContent: false, storesCiphertext: false, storesPlaintext: false },
    compatibility: { blindsparkHttpGateway: { present: false, surfaces: [] } }
  }
  const policy = buildWitnessQuorumPolicy(baseInput({
    witnesses: [witness(1, { tierProfile: badTierProfile }), ...[2, 3, 4, 5, 6, 7].map(n => witness(n))]
  }))
  const verdict = validateWitnessQuorumPolicy(policy)

  t.absent(verdict.valid)
  t.ok(verdict.errors.some(error => error.startsWith('invalid T3 witness profile for')))
})

test('evaluateWitnessQuorum counts only selected, matching, non-serving witnesses', (t) => {
  const policy = buildWitnessQuorumPolicy(baseInput())
  const entries = [
    entryFor(policy, policy.witnesses[0].witnessPubkey),
    entryFor(policy, policy.witnesses[1].witnessPubkey),
    entryFor(policy, policy.witnesses[2].witnessPubkey),
    entryFor(policy, policy.witnesses[3].witnessPubkey),
    entryFor(policy, policy.witnesses[3].witnessPubkey),
    entryFor(policy, hex('99')),
    entryFor(policy, policy.witnesses[4].witnessPubkey, { gatewayServing: true }),
    entryFor(policy, policy.witnesses[5].witnessPubkey, { intentId: hex('dd') })
  ]
  const result = evaluateWitnessQuorum(policy, entries)

  t.absent(result.valid, 'quorum not reached after rejecting bad witnesses')
  t.is(result.count, 4)
  t.is(result.required, 5)
  t.ok(result.rejected.find(row => row.reason === 'duplicate witness'))
  t.ok(result.rejected.find(row => row.reason === 'witness not publisher-selected'))
  t.ok(result.rejected.find(row => row.reason === 'witness observed active serving'))
  t.ok(result.rejected.find(row => row.reason === 'intentId mismatch'))
})

test('evaluateWitnessQuorum fails closed when policy is invalid', (t) => {
  const policy = buildWitnessQuorumPolicy(baseInput({ selectedBy: 'relay' }))
  const result = evaluateWitnessQuorum(policy, [])

  t.absent(result.valid)
  t.is(result.reason, 'invalid-policy')
})
