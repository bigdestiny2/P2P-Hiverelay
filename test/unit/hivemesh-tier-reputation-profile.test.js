import test from 'brittle'
import { readFile } from 'fs/promises'
import {
  HIVEMESH_TIER_REPUTATION_PROFILE_KIND,
  HIVEMESH_TIER_REPUTATION_TIERS,
  scoreHiveMeshTierReputation
} from 'p2p-hiverelay/core/protocol/hivemesh-tier-reputation-profile.js'

const VECTOR_URL = new URL(
  '../fixtures/relaykernel-profile/hivemesh-tier-reputation-profile-v1-no-global-score.json',
  import.meta.url
)

async function loadVector () {
  return JSON.parse(await readFile(VECTOR_URL, 'utf8'))
}

function hex32 (byte) {
  return byte.repeat(32)
}

test('HiveMesh tier reputation vector pins separate T1/T2/T3 scores', async (t) => {
  const vector = await loadVector()
  const profile = scoreHiveMeshTierReputation(vector.input)

  t.alike(profile, vector.profile, 'tier reputation profile matches fixture')
  t.is(profile.kind, HIVEMESH_TIER_REPUTATION_PROFILE_KIND)
  t.is(profile.globalScore, null, 'there is no global reputation score')
  t.alike(Object.keys(profile.tiers), HIVEMESH_TIER_REPUTATION_TIERS)
  t.is(profile.tiers.t1[0].keyPrefix, 'rk1')
  t.is(profile.tiers.t2[0].keyPrefix, 'rk2')
  t.is(profile.tiers.t3[0].keyPrefix, 'rk3')
  t.is(profile.tiers.t1[0].score, 1.440055)
  t.is(profile.tiers.t2[0].score, -53.933333)
  t.is(profile.tiers.t3[1].score, -100.99)
})

test('HiveMesh tier reputation ignores self-attestation and cross-tier evidence', async (t) => {
  const vector = await loadVector()
  const profile = scoreHiveMeshTierReputation(vector.input)
  const t1 = profile.tiers.t1[0]
  const t2 = profile.tiers.t2[0]
  const sharedT3 = profile.tiers.t3.find(node => node.nodePubkey === hex32('dd'))

  t.is(t1.ignored.selfAttestedScore, 999)
  t.is(t1.ignored.selfAttestedUptimeHours, 500)
  t.is(t1.ignored.selfAttestedBandwidthBytes, 10 * 1024 * 1024 * 1024)
  t.is(t1.ignored.unwitnessedBandwidthBytes, 50 * 1024 * 1024)
  t.is(t1.ignored.crossTierEvidence, 1, 'T2 evidence aimed at T1 is ignored')
  t.is(t2.ignored.crossTierEvidence, 1, 'T3 evidence aimed at T2 is ignored')
  t.is(sharedT3.ignored.crossTierEvidence, 1, 'T1 evidence aimed at T3 is ignored')
  t.is(profile.ignored.crossTierEvidence, 3)
})

test('HiveMesh tier reputation warns on cross-tier operator reuse and verifier disagreement', async (t) => {
  const vector = await loadVector()
  const profile = scoreHiveMeshTierReputation(vector.input)

  t.alike(profile.warnings.crossTierOperators, [{
    operator: 'op-shared',
    tiers: ['t1', 't2', 't3'],
    nodePubkeys: [hex32('aa'), hex32('bb'), hex32('dd')]
  }])
  t.is(profile.warnings.verifierDisagreements.length, 1)
  t.is(profile.warnings.verifierDisagreements[0].tier, 't2')
  t.is(profile.warnings.verifierDisagreements[0].delta, 20)
})

test('HiveMesh tier reputation does not infer trust for unknown nodes', (t) => {
  const now = 1800000000000
  const profile = scoreHiveMeshTierReputation({
    now,
    nodes: [{ nodePubkey: hex32('aa'), tier: 't1' }],
    t1AnchorProofs: [
      { nodePubkey: hex32('ff'), verifierPubkey: hex32('01'), blockIndex: 1, at: now, passed: true }
    ],
    t2CustodyReceipts: [
      { nodePubkey: hex32('aa'), at: now }
    ]
  })

  t.is(profile.tiers.t1[0].score, 0)
  t.is(profile.ignored.unknownNodeEvidence, 1)
  t.is(profile.ignored.crossTierEvidence, 1)
  t.is(profile.tiers.t1[0].ignored.crossTierEvidence, 1)
})
