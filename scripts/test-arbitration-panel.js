#!/usr/bin/env node

/**
 * test-arbitration-panel.js
 *
 * End-to-end test of the opt-in verifiable arbitrator panel: a real
 * ArbitrationService talking to a real VRFService through a real
 * ServiceRegistry, over a real ReputationSystem pool.
 *
 *   - panels are OFF by default (dispute.panel === null, open voting)
 *   - when enabled, submit draws a reputation-weighted committee via VRF
 *   - the committee is independently reproducible: verify(pubkey, alpha, pi) →
 *     beta → weightedSample(candidates) == members (and via select-verify)
 *   - only panel members may vote; eligible non-members are rejected
 *   - a panel dispute resolves on a panel quorum and slashes as usual
 *   - graceful fallback to open voting when: pool < panel size, or no VRF
 *   - per-dispute override (params.panel true/false) wins over the default
 */

import { ArbitrationService } from '../packages/services/builtin/arbitration-service.js'
import { VRFService } from '../packages/services/builtin/vrf-service.js'
import { ServiceRegistry } from '../packages/core/core/services/registry.js'
import { ReputationSystem } from '../packages/core/incentive/reputation/index.js'
import { weightedSample } from '../packages/services/builtin/vrf/sortition.js'
import { verify, proofToHash, toHex } from '../packages/services/builtin/vrf/ecvrf.js'

let passed = 0
let failed = 0
function assert (cond, label) {
  if (cond) { console.log(`  PASS  ${label}`); passed++ } else { console.log(`  FAIL  ${label}`); failed++ }
}
async function rejectsWith (fn, code, label) {
  try { await fn(); assert(false, label + ' (expected throw)') } catch (e) { assert(String(e.message).includes(code), label + (String(e.message).includes(code) ? '' : ` (got "${e.message}")`)) }
}

function eligibleRecord (score, total, passed, latency) {
  return {
    score, totalChallenges: total, passedChallenges: passed, failedChallenges: total - passed,
    avgLatencyMs: latency, totalBytesServed: 0, totalUptimeHours: 0,
    region: null, geoBonus: false, firstSeen: Date.now(), lastActivity: Date.now()
  }
}

/** Build a node with N eligible arbitrators and an optional VRF service. */
async function makeNode ({ nEligible = 8, withVrf = true, vrfSeed = '11'.repeat(32) } = {}) {
  const reputation = new ReputationSystem()
  for (let i = 0; i < nEligible; i++) {
    // Vary score/reliability a little so weighting has something to bite on.
    reputation.records.set('arb' + i, eligibleRecord(120 + i * 20, 60 + i, 58 + i, 400 + i * 10))
  }
  // An ineligible peer that must never be drawn or allowed to vote.
  reputation.records.set('weak', eligibleRecord(10, 5, 3, 4000))

  const slashed = []
  const published = []
  const registry = new ServiceRegistry()
  const node = {
    reputation,
    serviceRegistry: registry,
    paymentManager: { slash: (pubkey, amount, reason) => slashed.push({ pubkey, amount, reason }) },
    router: { pubsub: { publish: (topic, data) => published.push({ topic, data }) } },
    _slashed: slashed,
    _published: published
  }
  if (withVrf) {
    registry.register(new VRFService({ seed: vrfSeed }))
    await registry.startAll({ node })
  }
  return node
}

async function main () {
  // ── 1. default OFF: no panel, open voting ───────────────────────────────────
  console.log('── default (panels off) ──')
  {
    const node = await makeNode()
    const arb = new ArbitrationService()
    await arb.start({ node })
    const d = await arb.submit({ type: 'sla-violation', respondent: 'relayZ', penalty: 1000 }, { remotePubkey: 'claimantX' })
    assert(d.panel === null, 'panel is null by default')
    // any eligible arbitrator may vote (open voting)
    const v = await arb.vote({ id: d.id, verdict: 'claimant' }, { remotePubkey: 'arb3' })
    assert(v.status === 'voting', 'open voting accepts any eligible arbitrator')
  }

  // ── 2. enabled: a committee is drawn and is reproducible ────────────────────
  console.log('\n── panel enabled (weighted draw) ──')
  const node = await makeNode()
  const arb = new ArbitrationService({ panel: { enabled: true, size: 5, weighted: true } })
  await arb.start({ node })

  const d = await arb.submit({ type: 'sla-violation', respondent: 'relayZ', penalty: 5000 }, { remotePubkey: 'claimantX' })
  assert(d.panel && d.panel.active === true, 'panel formed and active')
  assert(d.panel.members.length === 5, 'committee has the configured size')
  assert(new Set(d.panel.members).size === 5, 'committee members are distinct')
  assert(d.panel.members.every(m => m.startsWith('arb')), 'members come from the eligible pool')
  assert(!d.panel.members.includes('weak'), 'ineligible peer is never drawn')
  assert(!d.panel.members.includes('claimantX') && !d.panel.members.includes('relayZ'), 'parties are excluded from the panel')
  assert(d.panel.pi.length === 160 && d.panel.beta.length === 128, 'panel carries the VRF proof + beta')
  assert(d.minVotes === 3, 'quorum capped to min(minVotes, panelSize)')

  // Reproduce the draw independently from the recorded proof + candidate snapshot.
  assert(verify(d.panel.vrfPubkey, d.panel.alpha, d.panel.pi) === true, 'panel VRF proof verifies under the relay VRF key')
  const betaBytes = proofToHash(d.panel.pi)
  assert(toHex(betaBytes) === d.panel.beta, 'recomputed beta matches the recorded beta')
  const replay = weightedSample({ seed: betaBytes, candidates: d.panel.candidates, count: 5, weighted: true })
  assert(JSON.stringify(replay) === JSON.stringify(d.panel.members), 'third party reproduces the exact committee from beta + candidate snapshot')

  // And via the service's own select-verify capability.
  const sv = await node.serviceRegistry.handleRequest('vrf', 'select-verify', {
    pubkey: d.panel.vrfPubkey, alpha: d.panel.alpha, pi: d.panel.pi,
    candidates: d.panel.candidates, count: 5, weighted: true, committee: d.panel.members
  }, { caller: 'local' })
  assert(sv.valid === true && sv.vrfValid && sv.committeeValid, 'select-verify accepts the committee')

  // determinism: a second dispute with identical immutable content draws the
  // same alpha → but ids are random so alpha differs; instead re-derive on the
  // same dispute object to confirm alpha binding is stable.
  assert(arb._panelAlpha(arb.disputes.get(d.id)) === d.panel.alpha, 'panel alpha is a stable function of dispute content')

  // ── 3. only panel members may vote ──────────────────────────────────────────
  console.log('\n── panel voting gate ──')
  const allArbs = Array.from({ length: 8 }, (_, i) => 'arb' + i)
  const offPanel = allArbs.filter(a => !d.panel.members.includes(a))
  assert(offPanel.length === 3, 'there are eligible arbitrators not on the panel')
  await rejectsWith(() => arb.vote({ id: d.id, verdict: 'claimant' }, { remotePubkey: offPanel[0] }),
    'ARBITRATOR_NOT_ON_PANEL', 'eligible non-member is rejected by the panel gate')
  // ineligible peer still rejected by the eligibility bar first
  await rejectsWith(() => arb.vote({ id: d.id, verdict: 'claimant' }, { remotePubkey: 'weak' }),
    'ARBITRATOR_INELIGIBLE', 'ineligible peer rejected even though panels are active')

  // ── 4. panel resolves + slashes ─────────────────────────────────────────────
  console.log('\n── panel resolution ──')
  const m = d.panel.members
  await arb.vote({ id: d.id, verdict: 'claimant' }, { remotePubkey: m[0] })
  await arb.vote({ id: d.id, verdict: 'claimant' }, { remotePubkey: m[1] })
  const resolved = await arb.vote({ id: d.id, verdict: 'respondent' }, { remotePubkey: m[2] })
  assert(resolved.status === 'resolved', 'panel dispute resolves at quorum')
  assert(resolved.verdict === 'claimant', 'majority verdict recorded')
  assert(node._slashed.length === 1 && node._slashed[0].amount === 5000 && node._slashed[0].pubkey === 'relayZ', 'respondent slashed on claimant win')
  assert(node._published.some(p => p.topic === 'arbitration/submitted' && Array.isArray(p.data.panel)), 'submitted event advertises the panel')

  // ── 5. fallback: pool smaller than panel size ───────────────────────────────
  console.log('\n── fallback: insufficient pool ──')
  {
    const small = await makeNode({ nEligible: 3 })
    const arb2 = new ArbitrationService({ panel: { enabled: true, size: 5 } })
    await arb2.start({ node: small })
    const dd = await arb2.submit({ type: 'proof-failure', respondent: 'relayZ' }, { remotePubkey: 'claimantX' })
    assert(dd.panel && dd.panel.active === false && dd.panel.reason === 'insufficient-eligible-pool', 'small pool falls back (inactive panel with reason)')
    // open voting still works for eligible arbitrators
    const vv = await arb2.vote({ id: dd.id, verdict: 'claimant' }, { remotePubkey: 'arb1' })
    assert(vv.status === 'voting', 'fallback dispute uses open voting')
  }

  // ── 6. fallback: no VRF service ─────────────────────────────────────────────
  console.log('\n── fallback: no VRF service ──')
  {
    const noVrf = await makeNode({ withVrf: false })
    const arb3 = new ArbitrationService({ panel: { enabled: true, size: 5 } })
    await arb3.start({ node: noVrf })
    const dd = await arb3.submit({ type: 'proof-failure', respondent: 'relayZ' }, { remotePubkey: 'claimantX' })
    assert(dd.panel && dd.panel.active === false && String(dd.panel.reason).startsWith('vrf-unavailable'), 'missing VRF service falls back')
  }

  // ── 7. per-dispute override ─────────────────────────────────────────────────
  console.log('\n── per-dispute override ──')
  {
    // service default OFF, but this dispute forces a panel ON
    const n2 = await makeNode()
    const arbOff = new ArbitrationService() // panels off
    await arbOff.start({ node: n2 })
    const forced = await arbOff.submit({ type: 'sla-violation', respondent: 'relayZ', panel: true }, { remotePubkey: 'claimantX' })
    assert(forced.panel && forced.panel.active === true, 'params.panel=true forces a panel even when the service default is off')

    // service default ON, but this dispute forces open voting
    const arbOn = new ArbitrationService({ panel: { enabled: true, size: 5 } })
    await arbOn.start({ node: n2 })
    const opened = await arbOn.submit({ type: 'sla-violation', respondent: 'relayZ', panel: false }, { remotePubkey: 'claimantX' })
    assert(opened.panel === null, 'params.panel=false forces open voting even when the service default is on')
  }

  console.log(`\n${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch(err => { console.error(err); process.exit(1) })
