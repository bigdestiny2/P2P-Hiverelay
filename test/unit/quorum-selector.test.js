import test from 'brittle'
import {
  selectQuorum,
  describeQuorum,
  VALID_STRATEGIES,
  DEFAULT_QUORUM_SIZE,
  DEFAULT_MIN_REGIONS,
  DEFAULT_MIN_OPERATORS
} from 'p2p-hiverelay/core/quorum-selector.js'

// Helper — build a synthetic candidate list
function r (pubkey, region, operator, opts = {}) {
  return {
    pubkey,
    region,
    operator: operator || pubkey,
    features: opts.features || [],
    latencyMs: opts.latencyMs,
    score: opts.score
  }
}

const sampleCandidates = [
  r('aa', 'us-east-1', 'opA', { score: 0.9, latencyMs: 30 }),
  r('bb', 'us-east-1', 'opA', { score: 0.85, latencyMs: 20 }), // same op as aa
  r('cc', 'eu-west', 'opB', { score: 0.8 }),
  r('dd', 'asia-tokyo', 'opC', { score: 0.7 }),
  r('ee', 'sa-east', 'opD', { score: 0.6 }),
  r('ff', 'us-west', 'opA', { score: 0.55 }), // same op as aa+bb, new region
  r('gg', 'me-uae', 'opE', { score: 0.5 })
]

test('exports expected strategies and defaults', async (t) => {
  t.alike([...VALID_STRATEGIES].sort(), ['diverse', 'foundation', 'pinned', 'wide'])
  t.is(DEFAULT_QUORUM_SIZE, 5)
  t.is(DEFAULT_MIN_REGIONS, 3)
  t.is(DEFAULT_MIN_OPERATORS, 3)
})

test('throws on unknown strategy', async (t) => {
  try {
    selectQuorum(sampleCandidates, { strategy: 'mystery' })
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('Unknown quorum strategy'))
  }
})

test('diverse strategy maximizes distinct (region, operator) tuples', async (t) => {
  const selected = selectQuorum(sampleCandidates, { strategy: 'diverse', size: 5 })
  t.is(selected.length, 5)
  const regions = new Set(selected.map(s => s.region))
  const operators = new Set(selected.map(s => s.operator))
  t.ok(regions.size >= 4, 'should hit at least 4 distinct regions')
  t.ok(operators.size >= 4, 'should hit at least 4 distinct operators')
})

test('diverse strategy attaches warning when minRegions not met', async (t) => {
  // Force a low-diversity candidate set
  const monoRegion = [
    r('aa', 'us-east-1', 'opA', { score: 0.9 }),
    r('bb', 'us-east-1', 'opB', { score: 0.85 }),
    r('cc', 'us-east-1', 'opC', { score: 0.8 })
  ]
  const selected = selectQuorum(monoRegion, { strategy: 'diverse', size: 3, minRegions: 3 })
  t.ok(selected.diversityWarning, 'warning should be attached')
  t.is(selected.diversityWarning.observedRegions, 1)
  t.is(selected.diversityWarning.requiredRegions, 3)
})

test('diverse strategy fills with non-diverse picks if pool is small', async (t) => {
  // Only 3 candidates, asked for 5 — should still return 3
  const tiny = sampleCandidates.slice(0, 3)
  const selected = selectQuorum(tiny, { strategy: 'diverse', size: 5 })
  t.is(selected.length, 3)
})

test('diverse strategy ranks by score then latency then pubkey for stability', async (t) => {
  const ranked = selectQuorum(sampleCandidates, { strategy: 'diverse', size: 7 })
  // Highest scorer (aa @ 0.9) should appear first
  t.is(ranked[0].pubkey, 'aa')
})

test('diverse strategy prefers a new operator over a same-operator region-only pick', async (t) => {
  const selected = selectQuorum(sampleCandidates, { strategy: 'diverse', size: 5 })
  t.ok(selected.find(s => s.pubkey === 'gg'), 'lower-score relay adds a fifth operator')
  t.absent(selected.find(s => s.pubkey === 'ff'), 'same-operator region-only relay waits for fill phase')
  t.is(new Set(selected.map(s => s.operator)).size, 5)
})

test('diverse strategy warns when operator diversity is below the floor', async (t) => {
  const oneOperator = [
    r('aa', 'us-east-1', 'opA', { score: 0.9 }),
    r('bb', 'eu-west', 'opA', { score: 0.85 }),
    r('cc', 'asia-tokyo', 'opA', { score: 0.8 })
  ]
  const selected = selectQuorum(oneOperator, {
    strategy: 'diverse',
    size: 3,
    minRegions: 3,
    minOperators: 3
  })
  t.ok(selected.diversityWarning, 'warning should be attached')
  t.is(selected.diversityWarning.reason, 'insufficient-operator-diversity')
  t.is(selected.diversityWarning.observedOperators, 1)
  t.is(selected.diversityWarning.requiredOperators, 3)
})

test('foundation strategy restricts to specified pubkeys', async (t) => {
  const selected = selectQuorum(sampleCandidates, {
    strategy: 'foundation',
    foundationPubkeys: ['cc', 'dd', 'gg'],
    size: 5
  })
  t.is(selected.length, 3)
  t.alike(selected.map(s => s.pubkey).sort(), ['cc', 'dd', 'gg'])
})

test('foundation strategy is case-insensitive on pubkey matching', async (t) => {
  const selected = selectQuorum(sampleCandidates, {
    strategy: 'foundation',
    foundationPubkeys: ['CC', 'Dd'],
    size: 5
  })
  t.is(selected.length, 2)
})

test('pinned strategy preserves caller-supplied order', async (t) => {
  const selected = selectQuorum(sampleCandidates, {
    strategy: 'pinned',
    pinnedPubkeys: ['gg', 'aa', 'cc'],
    size: 5
  })
  t.alike(selected.map(s => s.pubkey), ['gg', 'aa', 'cc'])
})

test('pinned strategy honors size cap', async (t) => {
  const selected = selectQuorum(sampleCandidates, {
    strategy: 'pinned',
    pinnedPubkeys: ['aa', 'bb', 'cc', 'dd', 'ee', 'ff', 'gg'],
    size: 3
  })
  t.is(selected.length, 3)
})

test('wide strategy returns top-N by score regardless of diversity', async (t) => {
  const selected = selectQuorum(sampleCandidates, { strategy: 'wide', size: 4 })
  t.is(selected.length, 4)
  t.alike(selected.map(s => s.pubkey), ['aa', 'bb', 'cc', 'dd'])
})

test('wide strategy ignores malformed or unnormalized score claims', async (t) => {
  const candidates = [
    r('aa', 'moon-1', 'opA', { score: Infinity, latencyMs: 1 }),
    r('bb', 'moon-2', 'opB', { score: 99, latencyMs: 1 }),
    r('cc', 'moon-3', 'opC', { score: -1, latencyMs: 1 }),
    r('dd', 'eu-west', 'opD', { score: 0.4, latencyMs: 100 }),
    r('ee', 'us-east', 'opE', { score: 0.7, latencyMs: 200 })
  ]
  const selected = selectQuorum(candidates, { strategy: 'wide', size: 2 })
  t.alike(selected.map(s => s.pubkey), ['ee', 'dd'])
})

test('wide strategy ignores malformed latency claims when scores tie', async (t) => {
  const candidates = [
    r('aa', 'us-east', 'opA', { score: 0.5, latencyMs: -1 }),
    r('bb', 'eu-west', 'opB', { score: 0.5, latencyMs: Infinity }),
    r('cc', 'asia-tokyo', 'opC', { score: 0.5, latencyMs: 25 })
  ]
  const selected = selectQuorum(candidates, { strategy: 'wide', size: 3 })
  t.is(selected[0].pubkey, 'cc')
})

test('requireFeatures filters out relays missing required capabilities', async (t) => {
  const candidates = [
    r('aa', 'us-east-1', 'opA', { score: 0.9, features: ['payment-required', 'ai-inference'] }),
    r('bb', 'eu-west', 'opB', { score: 0.85, features: ['payment-required'] }),
    r('cc', 'asia-tokyo', 'opC', { score: 0.8, features: ['ai-inference'] })
  ]
  const selected = selectQuorum(candidates, {
    strategy: 'diverse',
    size: 5,
    requireFeatures: ['payment-required']
  })
  t.is(selected.length, 2)
  t.ok(selected.every(s => s.features.includes('payment-required')))
})

test('handles empty candidate pool gracefully', async (t) => {
  const selected = selectQuorum([], { strategy: 'diverse' })
  t.is(selected.length, 0)
})

test('handles null/undefined candidate entries', async (t) => {
  const messy = [null, undefined, r('aa', 'us-east-1', 'opA', { score: 0.9 }), { not: 'a real entry' }]
  const selected = selectQuorum(messy, { strategy: 'diverse', size: 5 })
  t.is(selected.length, 1)
  t.is(selected[0].pubkey, 'aa')
})

test('describeQuorum summarizes selection clearly', async (t) => {
  const selected = selectQuorum(sampleCandidates, { strategy: 'diverse', size: 5 })
  const desc = describeQuorum(selected)
  t.is(desc.size, 5)
  t.ok(desc.regions.length >= 4)
  t.ok(desc.operators.length >= 4)
  t.is(desc.warning, null)
})

test('describeQuorum surfaces diversity warning', async (t) => {
  const monoRegion = [
    r('aa', 'us-east-1', 'opA', { score: 0.9 }),
    r('bb', 'us-east-1', 'opB', { score: 0.85 })
  ]
  const selected = selectQuorum(monoRegion, { strategy: 'diverse', size: 2, minRegions: 3, minOperators: 1 })
  const desc = describeQuorum(selected)
  t.ok(desc.warning)
  t.is(desc.warning.reason, 'insufficient-region-diversity')
})

test('describeQuorum on empty selection returns size 0', async (t) => {
  const desc = describeQuorum([])
  t.is(desc.size, 0)
  t.is(desc.regions.length, 0)
})

test('relays missing region are bucketed as __unknown__', async (t) => {
  const noRegion = [
    r('aa', undefined, 'opA', { score: 0.9 }),
    r('bb', undefined, 'opB', { score: 0.85 })
  ]
  const selected = selectQuorum(noRegion, { strategy: 'diverse', size: 2, minRegions: 3 })
  // Should still select both (different operators count as diversity)
  t.is(selected.length, 2)
})

// ── operator vs failure domain ───────────────────────────────────────────
// These two were one field. The fleet deploy script gave each box a distinct
// "operator" id (hive-foundation-utah, -utah-us, -singapore, -singapore-2 …)
// with a comment stating they existed so the replica scheduler would treat the
// boxes as separate nodes. Correct goal, wrong field: it made a single-owner
// fleet report as many operators and clear any minOperators floor for free.

test('one owner across many hosts counts as ONE operator', async (t) => {
  // The real fleet shape: one owner, boxes in different datacenters.
  const fleet = [
    { pubkey: 'a1', region: 'NA', operator: 'hive-foundation', failureDomain: 'cloudzy-utah', score: 0.9 },
    { pubkey: 'a2', region: 'NA', operator: 'hive-foundation', failureDomain: 'cloudzy-utah-us', score: 0.85 },
    { pubkey: 'a3', region: 'APAC', operator: 'hive-foundation', failureDomain: 'cloudzy-singapore-1', score: 0.8 },
    { pubkey: 'a4', region: 'APAC', operator: 'hive-foundation', failureDomain: 'cloudzy-singapore-2', score: 0.75 },
    { pubkey: 'a5', region: 'ME', operator: 'hive-foundation', failureDomain: 'cloudzy-dubai', score: 0.7 }
  ]
  const selected = selectQuorum(fleet, { strategy: 'diverse', size: 5, minOperators: 3 })
  const desc = describeQuorum(selected)

  t.is(desc.operators.length, 1, 'one owner is one operator, however many boxes')
  t.ok(desc.failureDomains.length >= 4, 'but replicas still spread across hosts')
  t.ok(selected.diversityWarning, 'and the independence floor honestly fails')
  t.is(selected.diversityWarning.reason, 'insufficient-operator-diversity')
  t.is(selected.diversityWarning.observedOperators, 1)
})

test('spreading still works when only failure domains differ', async (t) => {
  // Two boxes, same owner, same region, different hosts. Losing one host must
  // not lose both replicas, so the scheduler must still treat them as distinct.
  const pair = [
    { pubkey: 'b1', region: 'NA', operator: 'hive-foundation', failureDomain: 'host-1', score: 0.9 },
    { pubkey: 'b2', region: 'NA', operator: 'hive-foundation', failureDomain: 'host-1', score: 0.8 },
    { pubkey: 'b3', region: 'NA', operator: 'hive-foundation', failureDomain: 'host-2', score: 0.7 }
  ]
  const selected = selectQuorum(pair, { strategy: 'diverse', size: 2, minRegions: 1, minOperators: 1 })
  const domains = new Set(selected.map(s => s.failureDomain))
  t.is(domains.size, 2, 'picks across two hosts rather than doubling up on one')
})

test('an undeclared operator is unknown, not independent', async (t) => {
  // The old fallback was `operator || pubkey`, which minted a fresh operator
  // identity from every relay key — manufacturing independence out of silence.
  const anon = [
    { pubkey: 'c1', region: 'NA', score: 0.9 },
    { pubkey: 'c2', region: 'EU', score: 0.8 },
    { pubkey: 'c3', region: 'APAC', score: 0.7 }
  ]
  const selected = selectQuorum(anon, { strategy: 'diverse', size: 3, minRegions: 3, minOperators: 3 })
  const desc = describeQuorum(selected)

  t.is(desc.operators.length, 1, 'three undeclared relays are not three operators')
  t.ok(selected.diversityWarning, 'undeclared operators cannot satisfy an independence floor')
  t.is(selected.diversityWarning.operatorsUndeclared, true)
  t.is(desc.failureDomains.length, 3, 'they are still spread, falling back to pubkey')
})

test('an anonymous fleet forfeits diversity credit rather than leaking identity', async (t) => {
  // This is an anonymity network, and the capability doc is unauthenticated.
  // Declaring an operator publishes a linkage set naming every relay one party
  // runs — the exact correlation the Tor path and blind cells exist to prevent.
  // So the fleet declares nothing, and the selector must respond by refusing to
  // credit independence, NOT by inventing it from relay keys.
  const anonFleet = [
    { pubkey: 'd1', region: 'NA', failureDomain: 'fd-a1', score: 0.9 },
    { pubkey: 'd2', region: 'EU', failureDomain: 'fd-c1', score: 0.8 },
    { pubkey: 'd3', region: 'APAC', failureDomain: 'fd-b1', score: 0.7 }
  ]
  const selected = selectQuorum(anonFleet, { strategy: 'diverse', size: 3, minRegions: 3, minOperators: 2 })
  const desc = describeQuorum(selected)

  t.is(desc.regions.length, 3, 'region diversity is real and still counted')
  t.is(desc.failureDomains.length, 3, 'spreading still works with no operator declared')
  t.is(desc.operators.length, 1, 'three anonymous relays are one unknown, not three operators')
  t.is(selected.diversityWarning.reason, 'insufficient-operator-diversity')
  t.is(selected.diversityWarning.operatorsUndeclared, true,
    'the caller can tell "undeclared" from "declared but concentrated"')
})
