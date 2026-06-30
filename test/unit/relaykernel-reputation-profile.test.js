import test from 'brittle'
import { readFile } from 'fs/promises'
import {
  RELAYKERNEL_REPUTATION_PROFILE_KIND,
  RELAYKERNEL_REPUTATION_WINDOW_MS,
  scoreRelayKernelReputation
} from 'p2p-hiverelay/core/protocol/relaykernel-reputation-profile.js'

const VECTOR_URL = new URL(
  '../fixtures/relaykernel-profile/relaykernel-reputation-profile-v1-no-self-attestation.json',
  import.meta.url
)

async function loadVector () {
  return JSON.parse(await readFile(VECTOR_URL, 'utf8'))
}

function hex (byte) {
  return byte.repeat(32)
}

test('RelayKernel reputation profile vector ignores self-attestation', async (t) => {
  const vector = await loadVector()
  const profile = scoreRelayKernelReputation(vector.input)

  t.alike(profile, vector.profile, 'reputation profile matches fixture')
  t.is(profile.kind, RELAYKERNEL_REPUTATION_PROFILE_KIND)
  t.is(profile.relays[0].relayPubkey, hex('aa'), 'observed relay ranks first')
  t.is(profile.relays[2].score, 0, 'self-only relay scores zero')
  t.is(profile.relays[2].ignored.selfAttestedUptimeHours, 999, 'self uptime is reported but ignored')
  t.is(profile.relays[2].ignored.selfAttestedBandwidthBytes, 10 * 1024 * 1024 * 1024, 'self bandwidth is reported but ignored')
})

test('RelayKernel reputation profile caps verifier diversity at nine verifiers', (t) => {
  const now = 1800000000000
  const proofs = []
  for (let i = 1; i <= 12; i++) {
    proofs.push({
      relayPubkey: hex('aa'),
      verifierPubkey: String(i).padStart(2, '0').repeat(32),
      blockIndex: i,
      at: now,
      passed: true
    })
  }
  const profile = scoreRelayKernelReputation({ now, proofs })
  const relay = profile.relays[0]

  t.is(relay.distinctVerifiers, 12)
  t.is(relay.proofDiversityMultiplier, 1, 'diversity multiplier is capped')
  t.is(relay.proofScore, 12, 'extra verifiers do not multiply beyond one')
})

test('RelayKernel reputation profile rejects stale, failed, future, and unwitnessed evidence', (t) => {
  const now = 1800000000000
  const profile = scoreRelayKernelReputation({
    now,
    relays: [hex('aa')],
    proofs: [
      { relayPubkey: hex('aa'), verifierPubkey: hex('01'), blockIndex: 1, at: now + 1, passed: true },
      { relayPubkey: hex('aa'), verifierPubkey: hex('02'), blockIndex: 2, at: now - RELAYKERNEL_REPUTATION_WINDOW_MS - 1, passed: true },
      { relayPubkey: hex('aa'), verifierPubkey: hex('03'), blockIndex: 3, at: now, passed: false }
    ],
    bandwidthReceipts: [
      { relayPubkey: hex('aa'), bytes: 100 * 1024 * 1024, at: now, witnessCosigCount: 0 }
    ]
  })
  const relay = profile.relays[0]

  t.is(relay.score, 0)
  t.is(relay.passedProofs, 0)
  t.is(relay.witnessedBandwidthBytes, 0)
  t.is(relay.ignored.unwitnessedBandwidthBytes, 100 * 1024 * 1024)
})
