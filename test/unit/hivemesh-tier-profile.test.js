import test from 'brittle'
import { readFile } from 'fs/promises'
import {
  BLINDSPARK_HTTP_SURFACES
} from 'p2p-hiverelay/core/protocol/relaykernel-profile.js'
import {
  HIVEMESH_TIER_KEY_PREFIX,
  HIVEMESH_TIERS,
  buildHiveMeshTierProfile,
  validateHiveMeshTierProfile
} from 'p2p-hiverelay/core/protocol/hivemesh-tier-profile.js'

const VECTOR_URL = new URL(
  '../fixtures/relaykernel-profile/hivemesh-tier-profile-v1-t2-custody-vault.json',
  import.meta.url
)

async function loadVector () {
  return JSON.parse(await readFile(VECTOR_URL, 'utf8'))
}

test('HiveMesh tier profile vector pins structural T2 blindness', async (t) => {
  const vector = await loadVector()
  const profile = buildHiveMeshTierProfile(vector.input)
  const verdict = validateHiveMeshTierProfile(profile)

  t.alike(HIVEMESH_TIERS, ['t1', 't2', 't3'])
  t.alike(HIVEMESH_TIER_KEY_PREFIX, { t1: 'rk1', t2: 'rk2', t3: 'rk3' })
  t.alike(profile, vector.profile, 'T2 profile matches fixture')
  t.alike(verdict, vector.verdict, 'T2 verdict matches fixture')
})

test('HiveMesh T1 allows Blindspark gateway surfaces', (t) => {
  const profile = buildHiveMeshTierProfile({
    tier: 't1',
    keyPrefix: 'rk1',
    capabilities: ['seed', 'circuit', 'gateway', 'prove-seeded'],
    httpGateway: true,
    publicDht: true,
    publicDirectory: true,
    storesContent: true
  })
  const verdict = validateHiveMeshTierProfile(profile)

  t.ok(verdict.valid, 'T1 seed relay profile validates')
  t.alike(profile.compatibility.blindsparkHttpGateway.surfaces, BLINDSPARK_HTTP_SURFACES)
  t.ok(profile.network.gateway, 'gateway is explicitly allowed for T1')
})

test('HiveMesh T2 rejects gateway, circuit, public DHT, and plaintext storage', (t) => {
  const profile = buildHiveMeshTierProfile({
    tier: 't2',
    keyPrefix: 'rk2',
    capabilities: ['custody-receipt', 'prove-held', 'non-serving-proof', 'gateway', 'circuit', 'public-dht'],
    httpGateway: true,
    circuit: true,
    publicDht: true,
    publicDirectory: true,
    storesContent: true,
    storesCiphertext: true,
    storesPlaintext: true
  })
  const verdict = validateHiveMeshTierProfile(profile)

  t.absent(verdict.valid, 'T2 with public serving surfaces is invalid')
  t.ok(verdict.errors.includes('forbidden capability for t2: gateway'))
  t.ok(verdict.errors.includes('forbidden capability for t2: circuit'))
  t.ok(verdict.errors.includes('forbidden capability for t2: public-dht'))
  t.ok(verdict.errors.includes('forbidden gateway for t2'))
  t.ok(verdict.errors.includes('forbidden publicDht for t2'))
  t.ok(verdict.errors.includes('forbidden storesPlaintext for t2'))
  t.ok(verdict.errors.includes('t2 must not expose Blindspark HTTP gateway surfaces'))
})

test('HiveMesh T3 rejects storage and gateway surfaces', (t) => {
  const profile = buildHiveMeshTierProfile({
    tier: 't3',
    keyPrefix: 'rk3',
    capabilities: ['tombstone-signing', 'non-serving-observation', 'bandwidth-cosign'],
    httpGateway: false,
    circuit: false,
    publicDht: false,
    storesContent: false,
    storesCiphertext: false,
    storesPlaintext: false
  })
  t.ok(validateHiveMeshTierProfile(profile).valid, 'clean T3 witness validates')

  const invalid = buildHiveMeshTierProfile({
    tier: 't3',
    keyPrefix: 'rk3',
    capabilities: ['tombstone-signing', 'non-serving-observation', 'seed', 'gateway'],
    httpGateway: true,
    storesContent: true,
    storesCiphertext: true
  })
  const verdict = validateHiveMeshTierProfile(invalid)
  t.absent(verdict.valid, 'T3 with storage/gateway is invalid')
  t.ok(verdict.errors.includes('forbidden capability for t3: seed'))
  t.ok(verdict.errors.includes('forbidden capability for t3: gateway'))
  t.ok(verdict.errors.includes('forbidden gateway for t3'))
  t.ok(verdict.errors.includes('forbidden storesContent for t3'))
  t.ok(verdict.errors.includes('forbidden storesCiphertext for t3'))
})

test('HiveMesh tier profile enforces key-prefix role separation', (t) => {
  const profile = buildHiveMeshTierProfile({
    tier: 't2',
    keyPrefix: 'rk1',
    capabilities: ['custody-receipt', 'prove-held', 'non-serving-proof'],
    storesCiphertext: true
  })
  const verdict = validateHiveMeshTierProfile(profile)

  t.absent(verdict.valid, 'wrong key prefix invalidates tier profile')
  t.ok(verdict.errors.includes('wrong key prefix for t2: expected rk2'))
})
