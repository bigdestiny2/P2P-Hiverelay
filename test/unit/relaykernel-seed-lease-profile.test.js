import test from 'brittle'
import { readFile } from 'fs/promises'
import {
  RELAYKERNEL_SEED_LEASE_HARD_CAPS,
  RELAYKERNEL_SEED_LEASE_PROFILE_KIND,
  buildRelayKernelSeedLeaseCaps,
  evaluateRelayKernelSeedLeaseProfile
} from 'p2p-hiverelay/core/protocol/relaykernel-seed-lease-profile.js'

const VECTOR_URL = new URL(
  '../fixtures/relaykernel-profile/relaykernel-seed-lease-profile-v1-caps-replay.json',
  import.meta.url
)

async function loadVector () {
  return JSON.parse(await readFile(VECTOR_URL, 'utf8'))
}

function hex32 (byte) {
  return byte.repeat(32)
}

function hex16 (byte) {
  return byte.repeat(16)
}

test('RelayKernel seed lease profile vector pins caps and replay behavior', async (t) => {
  const vector = await loadVector()
  const profile = evaluateRelayKernelSeedLeaseProfile(vector.input)

  t.alike(profile, vector.profile, 'seed lease profile matches fixture')
  t.is(profile.kind, RELAYKERNEL_SEED_LEASE_PROFILE_KIND)
  t.is(profile.activeLeaseCount, 3, 'accepted requests count against concurrent leases')
  t.is(profile.heartbeat[0].degraded, true, 'stale heartbeat remains serving but degraded')
  t.is(profile.heartbeat[0].reason, 'heartbeat-timeout')
  t.is(profile.requests[0].ack.leaseId, '7fa7137d9482445da841a6b5fea2129c')
  t.is(profile.requests[0].ack.actualCap, profile.capLimits.maxStorageCap)
  t.alike(profile.requests[0].appliedCaps, ['storageCap'])
  t.is(profile.requests[1].error.code, 'E_NONCE_REPLAY', 'same-batch nonce replay is rejected')
  t.is(profile.requests[2].error.code, 'E_NONCE_REPLAY', 'recent nonce history replay is rejected')
  t.is(profile.requests[3].accepted, true, 'expired nonce history no longer blocks publisher')
  t.is(profile.requests[4].error.field, 'maxConcurrentLeases')
})

test('RelayKernel seed lease caps clamp to hard limits', (t) => {
  const caps = buildRelayKernelSeedLeaseCaps({
    maxConcurrentLeases: RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxConcurrentLeases + 1,
    maxStorageCap: RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxStorageCap + 1,
    maxRetainHorizonSeconds: RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxRetainHorizonSeconds + 1,
    heartbeatIntervalSeconds: RELAYKERNEL_SEED_LEASE_HARD_CAPS.heartbeatIntervalSeconds + 1
  })

  t.is(caps.maxConcurrentLeases, RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxConcurrentLeases)
  t.is(caps.maxStorageCap, RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxStorageCap)
  t.is(caps.maxRetainHorizonSeconds, RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxRetainHorizonSeconds)
  t.is(caps.heartbeatIntervalSeconds, RELAYKERNEL_SEED_LEASE_HARD_CAPS.heartbeatIntervalSeconds)
  t.is(caps.nonceWindowSeconds, 3600)
})

test('RelayKernel seed lease profile fails closed on malformed and over-horizon requests', (t) => {
  const now = 1800000000
  const profile = evaluateRelayKernelSeedLeaseProfile({
    now,
    capLimits: { maxConcurrentLeases: 10 },
    requests: [
      { proofTier: 1 },
      {
        discoveryKey: hex32('aa'),
        publisherPubkey: hex32('bb'),
        retainUntil: now + RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxRetainHorizonSeconds + 1,
        storageCap: 1024,
        proofTier: 1,
        nonce: hex16('01')
      }
    ]
  })

  t.is(profile.requests[0].error.code, 'E_MALFORMED')
  t.is(profile.requests[0].error.reason, 'discoveryKey required')
  t.is(profile.requests[1].error.code, 'E_CAP_EXCEEDED')
  t.is(profile.requests[1].error.field, 'retainUntil')
})

test('RelayKernel seed lease profile rejects storage beyond hard cap', (t) => {
  const now = 1800000000
  const profile = evaluateRelayKernelSeedLeaseProfile({
    now,
    requests: [
      {
        discoveryKey: hex32('11'),
        publisherPubkey: hex32('22'),
        retainUntil: now + 60,
        storageCap: RELAYKERNEL_SEED_LEASE_HARD_CAPS.maxStorageCap + 1,
        proofTier: 1,
        nonce: hex16('03')
      }
    ]
  })

  t.is(profile.requests[0].accepted, false)
  t.is(profile.requests[0].error.code, 'E_CAP_EXCEEDED')
  t.is(profile.requests[0].error.field, 'storageCap')
})
