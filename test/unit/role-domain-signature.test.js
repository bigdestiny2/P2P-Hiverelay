import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { readFile } from 'fs/promises'
import {
  ROLE_DOMAIN_SIGNATURE_DOMAIN,
  ROLE_DOMAIN_SIGNATURE_PROFILE_KIND,
  evaluateRoleDomainSignatureProfile,
  roleDomainSignable,
  signRoleDomainMessage,
  validateRoleDomainMessage,
  verifyRoleDomainSignature
} from 'p2p-hiverelay/core/protocol/role-domain-signature.js'

const VECTOR_URL = new URL(
  '../fixtures/relaykernel-profile/role-domain-signature-profile-v1-prefix-domain.json',
  import.meta.url
)

async function loadVector () {
  return JSON.parse(await readFile(VECTOR_URL, 'utf8'))
}

function keypairFromSeed (seedHex) {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.from(seedHex, 'hex'))
  return { publicKey, secretKey }
}

test('role-domain signature profile vector pins prefixes and domains', async (t) => {
  const vector = await loadVector()
  const profile = evaluateRoleDomainSignatureProfile(vector.input)
  const seed = profile.messages.find(row => row.id === 'rkp-rk-seed')
  const tombstone = profile.messages.find(row => row.id === 'rk3-t3-tombstone')
  const forbidden = profile.messages.find(row => row.id === 'rk1-t3-tombstone-forbidden')

  t.alike(profile, vector.profile, 'role-domain profile matches fixture')
  t.is(profile.kind, ROLE_DOMAIN_SIGNATURE_PROFILE_KIND)
  t.is(profile.domain, ROLE_DOMAIN_SIGNATURE_DOMAIN)
  t.ok(seed.verify.valid, 'publisher seed signature verifies in its own domain')
  t.ok(tombstone.verify.valid, 't3 tombstone signature verifies in its own domain')
  t.not(seed.signableHex, tombstone.signableHex, 'same payload hash differs across protocol and role domains')
  t.is(forbidden.error.code, 'E_KEY_TIER', 't1 cannot sign t3 witness messages')
  t.alike(profile.replayChecks.map(row => row.code), ['E_BAD_SIGNATURE', 'E_BAD_SIGNATURE', 'E_KEY_TIER'])
})

test('role-domain signatures do not replay across allowed domains', async (t) => {
  const vector = await loadVector()
  const keyPair = keypairFromSeed(vector.input.seedHex)
  const source = vector.input.messages.find(row => row.id === 'rkp-rk-seed')
  const target = vector.input.replayChecks[0].target
  const signature = signRoleDomainMessage(source, keyPair)

  t.ok(verifyRoleDomainSignature(source, signature, keyPair.publicKey).valid, 'source domain verifies')
  const replay = verifyRoleDomainSignature(target, signature, keyPair.publicKey)
  t.absent(replay.valid, 'same key and payload hash cannot cross protocol domains')
  t.is(replay.code, 'E_BAD_SIGNATURE')
})

test('role-domain policy rejects forbidden prefixes before crypto', async (t) => {
  const vector = await loadVector()
  const keyPair = keypairFromSeed(vector.input.seedHex)
  const forbidden = vector.input.messages.find(row => row.id === 'rk1-t3-tombstone-forbidden')
  const verdict = validateRoleDomainMessage(forbidden)

  t.absent(verdict.valid, 'forbidden tier is invalid')
  t.is(verdict.code, 'E_KEY_TIER')
  t.exception(() => signRoleDomainMessage(forbidden, keyPair), /E_KEY_TIER/)

  const signature = b4a.from(vector.profile.messages.find(row => row.id === 'rk3-t3-tombstone').signature, 'hex')
  const replay = verifyRoleDomainSignature(forbidden, signature, keyPair.publicKey)
  t.absent(replay.valid, 'verification fails before checking signature bytes')
  t.is(replay.code, 'E_KEY_TIER')
})

test('role-domain signable bytes are explicit and malformed input fails closed', (t) => {
  const message = {
    protocol: 'RelayKernel',
    rolePrefix: 'RKP',
    channel: 'RK-Seed',
    messageType: 'Seed',
    messageVersion: 1,
    payloadHash: 'aa'.repeat(32)
  }
  const decoded = JSON.parse(b4a.toString(roleDomainSignable(message), 'utf8'))
  const malformed = validateRoleDomainMessage({
    protocol: 'relaykernel',
    rolePrefix: 'rkp',
    channel: 'rk-seed',
    messageType: 'seed',
    messageVersion: 300,
    payloadHash: 'aa'.repeat(32)
  })

  t.is(decoded[0], ROLE_DOMAIN_SIGNATURE_DOMAIN)
  t.alike(decoded.slice(1, 5), ['relaykernel', 'rkp', 'rk-seed', 'seed'])
  t.absent(malformed.valid)
  t.is(malformed.code, 'E_MALFORMED')
  t.is(malformed.reason, 'messageVersion must be a u8 integer')
})
