import test from 'brittle'
import { readFile } from 'fs/promises'
import {
  HIVEMESH_TOMBSTONE_ADJUDICATION_PROFILE_KIND,
  evaluateHiveMeshTombstoneAdjudicationProfile
} from 'p2p-hiverelay/core/protocol/hivemesh-tombstone-adjudication-profile.js'

const VECTOR_URL = new URL(
  '../fixtures/relaykernel-profile/hivemesh-tombstone-adjudication-profile-v1-false-tombstone.json',
  import.meta.url
)

async function loadVector () {
  return JSON.parse(await readFile(VECTOR_URL, 'utf8'))
}

function clone (value) {
  return JSON.parse(JSON.stringify(value))
}

function hex32 (byte) {
  return byte.repeat(32)
}

test('HiveMesh tombstone adjudication vector pins false-tombstone slashing', async (t) => {
  const vector = await loadVector()
  const profile = evaluateHiveMeshTombstoneAdjudicationProfile(vector.input)

  t.alike(profile, vector.profile, 'tombstone adjudication profile matches fixture')
  t.is(profile.kind, HIVEMESH_TOMBSTONE_ADJUDICATION_PROFILE_KIND)
  t.is(profile.tombstoneQuorum.valid, true)
  t.is(profile.tombstoneQuorum.count, 5)
  t.is(profile.contradiction.valid, true)
  t.is(profile.verdict.status, 'false-tombstone')
  t.is(profile.verdict.markRelayExpired, false)
  t.is(profile.verdict.slashWitnesses.length, 5)
})

test('HiveMesh tombstone adjudication confirms non-serving when no same-challenge contradiction exists', async (t) => {
  const vector = await loadVector()
  const input = clone(vector.input)
  input.servingEvidence = []

  const profile = evaluateHiveMeshTombstoneAdjudicationProfile(input)

  t.is(profile.tombstoneQuorum.valid, true)
  t.is(profile.contradiction.valid, false)
  t.is(profile.contradiction.reason, 'insufficient-serving-contradiction')
  t.is(profile.verdict.status, 'non-serving-confirmed')
  t.is(profile.verdict.markRelayExpired, true)
  t.alike(profile.verdict.slashWitnesses, [])
})

test('HiveMesh tombstone adjudication does not treat no-answer as non-serving without retries and grace', async (t) => {
  const vector = await loadVector()
  const input = clone(vector.input)
  input.servingEvidence = []
  input.tombstones = input.tombstones.slice(0, 5).map((entry, index) => {
    if (index === 0) return { ...entry, attempts: 1 }
    if (index === 1) return { ...entry, at: input.intent.retainUntil + 29_999 }
    return entry
  })

  const profile = evaluateHiveMeshTombstoneAdjudicationProfile(input)

  t.is(profile.tombstoneQuorum.valid, false)
  t.is(profile.tombstoneQuorum.count, 0)
  t.is(profile.verdict.status, 'insufficient-tombstone-quorum')
  t.ok(profile.tombstoneQuorum.rejected.find(row => row.reason === 'retry policy not met'))
  t.ok(profile.tombstoneQuorum.rejected.find(row => row.reason === 'observation before expiry grace'))
})

test('HiveMesh tombstone adjudication requires tombstones to bind a known non-serving proof', async (t) => {
  const vector = await loadVector()
  const input = clone(vector.input)
  input.nonServingProofs = []
  input.servingEvidence = []
  input.tombstones = input.tombstones.slice(0, 5)

  const profile = evaluateHiveMeshTombstoneAdjudicationProfile(input)

  t.is(profile.tombstoneQuorum.valid, false)
  t.is(profile.tombstoneQuorum.reason, 'no-accepted-tombstones')
  t.is(profile.verdict.status, 'insufficient-tombstone-quorum')
  t.is(profile.tombstoneQuorum.rejected.length, 5)
  t.ok(profile.tombstoneQuorum.rejected.every(row => row.reason === 'matching non-serving proof required'))
})

test('HiveMesh tombstone adjudication requires contradiction evidence to bind the tombstone challenge', async (t) => {
  const vector = await loadVector()
  const input = clone(vector.input)
  input.servingEvidence = input.servingEvidence.map(entry => ({
    ...entry,
    challengeNonce: hex32('33')
  }))

  const profile = evaluateHiveMeshTombstoneAdjudicationProfile(input)

  t.is(profile.tombstoneQuorum.valid, true)
  t.is(profile.contradiction.valid, false)
  t.is(profile.contradiction.rejected[0].reason, 'challengeNonce mismatch')
  t.is(profile.verdict.status, 'non-serving-confirmed')
  t.alike(profile.verdict.slashWitnesses, [])
})
