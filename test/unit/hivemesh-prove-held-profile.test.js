import test from 'brittle'
import { readFile } from 'fs/promises'
import {
  HIVEMESH_PROVE_HELD_COMMIT_DOMAIN,
  HIVEMESH_PROVE_HELD_PROFILE_KIND,
  evaluateHiveMeshProveHeldProfile,
  hiveMeshProveHeldCommitRoot
} from 'p2p-hiverelay/core/protocol/hivemesh-prove-held-profile.js'
import {
  validateRoleDomainMessage
} from 'p2p-hiverelay/core/protocol/role-domain-signature.js'

const VECTOR_URL = new URL(
  '../fixtures/relaykernel-profile/hivemesh-prove-held-profile-v1-commit-reveal.json',
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

function roleMessage (rolePrefix, messageType) {
  return {
    protocol: 'hivemesh',
    rolePrefix,
    channel: 't2-prove-held',
    messageType,
    messageVersion: 1,
    payloadHash: hex32('aa')
  }
}

test('HiveMesh proveHeld profile vector pins commit-reveal semantics', async (t) => {
  const vector = await loadVector()
  const profile = evaluateHiveMeshProveHeldProfile(vector.input)
  const valid = profile.sessions[0]

  t.alike(profile, vector.profile, 'proveHeld profile matches fixture')
  t.is(profile.kind, HIVEMESH_PROVE_HELD_PROFILE_KIND)
  t.is(valid.valid, true, 'hot session validates')
  t.is(valid.result.expectedCommitRoot, '55d79cd8c3a1901a61092939c7fbc3dd2de8479e42a01f6cb0c4be11db33ddfd')
  t.alike(valid.reveal.blockIndices, [2, 5], 'challenge set is canonicalized')
  t.is(valid.result.responseDeadline, 1800000015)
  t.alike(valid.result.evidenceWeight, { numerator: 1, denominator: 5 })
  t.alike(valid.domains.map(domain => domain.message.rolePrefix), ['rkv', 'rkv', 'rk2'])
  t.alike(valid.domains.map(domain => domain.message.messageType), ['commit', 'reveal', 'proof-response'])
})

test('HiveMesh proveHeld profile rejects commit mismatch, late response, and missing blocks', async (t) => {
  const vector = await loadVector()
  const profile = evaluateHiveMeshProveHeldProfile(vector.input)

  t.alike(profile.sessions.slice(1).map(session => session.error.code), [
    'E_COMMIT_MISMATCH',
    'E_RESPONSE_DEADLINE',
    'E_RESPONSE_MISMATCH'
  ])
  t.is(profile.sessions[1].expectedCommitRoot, '2d46d4f51e6a990c51726cd7976e60ab62eaf1dc8eda2c8adae332d5dce64e33')
  t.is(profile.sessions[2].responseDeadline, 1800000015)
})

test('HiveMesh proveHeld commit roots are canonical and reject duplicate challenge indices', (t) => {
  const rootA = hiveMeshProveHeldCommitRoot([5, 2], hex16('01'))
  const rootB = hiveMeshProveHeldCommitRoot([2, 5], hex16('01'))

  t.is(rootA, rootB, 'block index order does not change the committed set')
  t.is(rootA, '55d79cd8c3a1901a61092939c7fbc3dd2de8479e42a01f6cb0c4be11db33ddfd')
  t.is(HIVEMESH_PROVE_HELD_COMMIT_DOMAIN, 'hivemesh-prove-held-commit-root-v1')
  t.exception(() => hiveMeshProveHeldCommitRoot([2, 2], hex16('01')), /blockIndices must be unique/)
})

test('HiveMesh proveHeld role domains match verifier and vault responsibilities', (t) => {
  t.ok(validateRoleDomainMessage(roleMessage('rkv', 'commit')).valid, 'verifier signs commit')
  t.ok(validateRoleDomainMessage(roleMessage('rkv', 'reveal')).valid, 'verifier signs reveal')
  t.ok(validateRoleDomainMessage(roleMessage('rk2', 'proof-response')).valid, 'vault signs proof response')
  t.is(validateRoleDomainMessage(roleMessage('rk2', 'commit')).code, 'E_KEY_TIER')
  t.is(validateRoleDomainMessage(roleMessage('rkv', 'proof-response')).code, 'E_KEY_TIER')
})

test('HiveMesh proveHeld profile enforces configured reveal window', (t) => {
  const root = hiveMeshProveHeldCommitRoot([1], hex16('09'))
  const profile = evaluateHiveMeshProveHeldProfile({
    policy: { minWindowSeconds: 1, maxWindowSeconds: 5 },
    sessions: [
      {
        id: 'too-wide',
        commit: {
          discoveryKey: hex32('aa'),
          verifierPubkey: hex32('77'),
          commitRoot: root,
          windowSeconds: 6,
          deadline: 1800000030,
          committedAt: 1800000000
        },
        reveal: {
          commitRoot: root,
          blockIndices: [1],
          nonce: hex16('09'),
          verifierPubkey: hex32('77'),
          revealedAt: 1800000010
        },
        response: {
          vaultPubkey: hex32('22'),
          blockIndices: [1],
          blocks: [{
            index: 1,
            blockHash: hex32('01'),
            merklePathHash: hex32('b1'),
            sigRoot: hex32('ee')
          }],
          receivedAt: 1800000014
        }
      }
    ]
  })

  t.absent(profile.sessions[0].valid)
  t.is(profile.sessions[0].error.code, 'E_WINDOW')
})
