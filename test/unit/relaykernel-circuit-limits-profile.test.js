import test from 'brittle'
import { readFile } from 'fs/promises'
import {
  RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP,
  RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP,
  RELAYKERNEL_CIRCUIT_LIMITS_PROFILE_KIND,
  RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP,
  RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS,
  RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS,
  evaluateRelayKernelCircuitLimitsProfile
} from 'p2p-hiverelay/core/protocol/relaykernel-circuit-limits-profile.js'

const VECTOR_URL = new URL(
  '../fixtures/relaykernel-profile/relaykernel-circuit-limits-profile-v1-hard-caps.json',
  import.meta.url
)

async function loadVector () {
  return JSON.parse(await readFile(VECTOR_URL, 'utf8'))
}

function clone (value) {
  return JSON.parse(JSON.stringify(value))
}

test('RelayKernel circuit limits vector pins hard caps and compatibility warnings', async (t) => {
  const vector = await loadVector()
  const profile = evaluateRelayKernelCircuitLimitsProfile(vector.input)

  t.alike(profile, vector.profile, 'circuit limits profile matches fixture')
  t.is(profile.kind, RELAYKERNEL_CIRCUIT_LIMITS_PROFILE_KIND)
  t.is(profile.hardCaps.maxSessionMs, RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS)
  t.is(profile.hardCaps.maxBytes, RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP)
  t.is(profile.hardCaps.maxCircuitsPerPeer, RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP)
  t.is(profile.hardCaps.maxFrameBytes, RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP)
  t.is(profile.hardCaps.recommendedRateBytesPerSecond, RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS)
  t.is(profile.verdict.valid, true)
  t.alike(profile.verdict.warnings, [
    'using HiveRelay compatibility channel until rk-circuit is introduced'
  ])
})

test('RelayKernel circuit limits reject upward cap drift', async (t) => {
  const vector = await loadVector()
  const input = clone(vector.input)
  input.limits.maxSessionMs = RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS + 1
  input.limits.maxBytes = RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP + 1
  input.limits.maxCircuitsPerPeer = RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP + 1
  input.limits.maxFrameBytes = RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP + 1
  input.runtime.relayAccountingEnabled = false

  const profile = evaluateRelayKernelCircuitLimitsProfile(input)

  t.is(profile.verdict.valid, false)
  t.ok(profile.verdict.errors.includes('circuit byte cap exceeds 64 MiB hard cap'))
  t.ok(profile.verdict.errors.includes('per-peer circuit cap exceeds 5 hard cap'))
  t.ok(profile.verdict.errors.includes('circuit frame cap exceeds 64 KiB hard cap'))
  t.ok(profile.verdict.errors.includes('circuit session cap exceeds 10 minute hard cap'))
})

test('RelayKernel circuit limits require auth binding and bounded queues', async (t) => {
  const vector = await loadVector()
  const input = clone(vector.input)
  input.runtime.reserveAuthBindsRemoteKey = false
  input.runtime.connectAuthBindsRemoteKey = false
  delete input.limits.maxPendingConnects
  delete input.limits.maxReservePerMinute

  const profile = evaluateRelayKernelCircuitLimitsProfile(input)

  t.is(profile.verdict.valid, false)
  t.ok(profile.verdict.errors.includes('missing circuit security check: reserveAuthBindsRemoteKey'))
  t.ok(profile.verdict.errors.includes('missing circuit security check: connectAuthBindsRemoteKey'))
  t.ok(profile.verdict.errors.includes('reserve attempts are not rate limited'))
  t.ok(profile.verdict.errors.includes('pending connect queue is unbounded'))
})

test('RelayKernel circuit limits model rk-circuit and HiveMesh T1 role admission', (t) => {
  const profile = evaluateRelayKernelCircuitLimitsProfile({
    channels: ['rk-circuit', 't1-circuit'],
    limits: {
      maxSessionMs: RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS,
      maxBytes: RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP,
      maxCircuitsPerPeer: RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP,
      maxFrameBytes: RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP,
      maxPendingConnects: 10,
      maxReservePerMinute: 5,
      rateCapBytesPerSecond: RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS
    },
    runtime: {
      reserveAuthBindsRemoteKey: true,
      connectAuthBindsRemoteKey: true,
      endpointOnlyData: true,
      closeOnFrameTooLarge: true,
      closeOnByteCap: true,
      silentDropUnknownCircuit: true,
      relayAccountingEnabled: true,
      relayMaxCircuitDurationMs: RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS,
      circuitRelayCleanupMs: RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS,
      perCircuitRateCapBytesPerSecond: RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS
    },
    decisions: [
      { id: 'kernel-client', type: 'open-channel', channel: 'rk-circuit', rolePrefix: 'rkc', expectedAccepted: true },
      { id: 'kernel-relay', type: 'open-channel', channel: 'rk-circuit', rolePrefix: 'rk1', expectedAccepted: true },
      { id: 't1-relay', type: 'open-channel', channel: 't1-circuit', rolePrefix: 'rk1', expectedAccepted: true },
      { id: 't2-vault', type: 'open-channel', channel: 't1-circuit', rolePrefix: 'rk2', expectedAccepted: false },
      { id: 'rate-cap', type: 'byte-rate', bytesPerSecond: RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS + 1, expectedAccepted: false }
    ]
  })

  t.is(profile.verdict.valid, true)
  t.alike(profile.verdict.warnings, [])
  t.ok(profile.decisions.every(decision => decision.matchesExpectation))
  t.is(profile.decisions.find(decision => decision.id === 't2-vault').reason, 'E_KEY_TIER')
  t.is(profile.decisions.find(decision => decision.id === 'rate-cap').reason, 'E_CIRCUIT_LIMIT')
})
