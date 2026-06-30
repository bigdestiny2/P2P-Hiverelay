import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import {
  SEED_REQUEST_REPLAY_SIGNATURE_DOMAIN,
  SEED_REQUEST_SIGNATURE_DOMAIN,
  serializeSeedRequestForDomainSigning,
  serializeSeedRequestForReplaySigning,
  serializeSeedRequestForSigning,
  serializeSeedRequestForSigningLegacy,
  verifySeedRequestSignature,
  verifySeedRequestSignatureDetails
} from 'p2p-hiverelay/core/protocol/seed-request.js'
import { buildPublisherSignedSeedOpts } from 'p2p-hiverelay/core/seed-request-builder.js'
import { HiveRelayClient } from 'p2p-hiverelay-client'

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function mockSwarm (kp) {
  const swarm = new EventEmitter()
  swarm.keyPair = kp
  swarm.connections = new Set()
  swarm.join = () => ({ destroy: () => {} })
  swarm.leave = async () => {}
  swarm.flush = async () => {}
  swarm.destroy = async () => {}
  return swarm
}

function baseMessage (kp, overrides = {}) {
  return {
    appKey: b4a.alloc(32, 0x42),
    discoveryKeys: [b4a.alloc(32, 0x24)],
    replicationFactor: 3,
    maxStorageBytes: 500 * 1024 * 1024,
    ttlSeconds: 30 * 24 * 3600,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0,
    durability: 0,
    publisherPubkey: kp.publicKey,
    publisherSignature: b4a.alloc(sodium.crypto_sign_BYTES),
    ...overrides
  }
}

function signInto (msg, payload, kp) {
  sodium.crypto_sign_detached(msg.publisherSignature, payload, kp.secretKey)
  return msg
}

function bodyFromMessage (msg) {
  return {
    appKey: b4a.toString(msg.appKey, 'hex'),
    discoveryKeys: msg.discoveryKeys.map(dk => b4a.toString(dk, 'hex')),
    replicationFactor: msg.replicationFactor,
    maxStorageBytes: msg.maxStorageBytes,
    ttlSeconds: msg.ttlSeconds,
    bountyRate: msg.bountyRate,
    revocable: msg.revocable,
    unseedFreezeMs: msg.unseedFreezeMs,
    durability: msg.durability,
    publisherPubkey: b4a.toString(msg.publisherPubkey, 'hex'),
    publisherSignature: b4a.toString(msg.publisherSignature, 'hex')
  }
}

test('seed request signature: domain-v3 preimage verifies as preferred layout', (t) => {
  const kp = keyPair()
  const msg = baseMessage(kp)
  signInto(msg, serializeSeedRequestForDomainSigning(msg), kp)

  const details = verifySeedRequestSignatureDetails(msg)
  t.is(details.ok, true)
  t.is(details.layout, 'domain-v3')
  t.is(details.domain, SEED_REQUEST_SIGNATURE_DOMAIN)
  t.is(details.legacy, false)
  t.is(verifySeedRequestSignature(msg), true)
})

test('seed request signature: replay-v1 preimage verifies as non-legacy layout', (t) => {
  const kp = keyPair()
  const msg = baseMessage(kp, {
    issuedAt: 1782753600000,
    requestNonce: b4a.alloc(16, 0x11)
  })
  signInto(msg, serializeSeedRequestForReplaySigning(msg), kp)

  const details = verifySeedRequestSignatureDetails(msg)
  t.is(details.ok, true)
  t.is(details.layout, 'replay-v1')
  t.is(details.domain, SEED_REQUEST_REPLAY_SIGNATURE_DOMAIN)
  t.is(details.legacy, false)
  t.is(verifySeedRequestSignature(msg), true)
})

test('seed request signature: legacy v2 signatures still verify', (t) => {
  const kp = keyPair()
  const msg = baseMessage(kp)
  signInto(msg, serializeSeedRequestForSigning(msg), kp)

  const details = verifySeedRequestSignatureDetails(msg)
  t.is(details.ok, true)
  t.is(details.layout, 'legacy-v2')
  t.is(details.domain, null)
  t.is(details.legacy, true)
})

test('seed request signature: legacy v1 fallback remains constrained', (t) => {
  const kp = keyPair()
  const msg = baseMessage(kp, { discoveryKeys: [], revocable: true, unseedFreezeMs: 0, durability: 0 })
  signInto(msg, serializeSeedRequestForSigningLegacy(msg), kp)

  const details = verifySeedRequestSignatureDetails(msg)
  t.is(details.ok, true)
  t.is(details.layout, 'legacy-v1')

  const archiveClaim = { ...msg, durability: 1 }
  const archiveDetails = verifySeedRequestSignatureDetails(archiveClaim)
  t.is(archiveDetails.ok, false)
  t.is(verifySeedRequestSignature(archiveClaim), false)
})

test('seed request signature: wrong domain does not verify', (t) => {
  const kp = keyPair()
  const msg = baseMessage(kp)
  const wrongDomainPayload = b4a.concat([
    b4a.from('hiverelay.seed-request.not-this-domain'),
    b4a.from([0]),
    serializeSeedRequestForSigning(msg)
  ])
  signInto(msg, wrongDomainPayload, kp)

  const details = verifySeedRequestSignatureDetails(msg)
  t.is(details.ok, false)
  t.is(details.layout, null)
})

test('seed request signature: replay envelope rejects legacy signature', (t) => {
  const kp = keyPair()
  const msg = baseMessage(kp, {
    issuedAt: 1782753600000,
    requestNonce: b4a.alloc(16, 0x22)
  })
  signInto(msg, serializeSeedRequestForSigning(msg), kp)

  const details = verifySeedRequestSignatureDetails(msg)
  t.is(details.ok, false)
  t.is(details.reason, 'replay envelope requires replay-v1 signature')
})

test('seed request builder accepts domain-separated publisher signatures', (t) => {
  const kp = keyPair()
  const msg = baseMessage(kp)
  signInto(msg, serializeSeedRequestForDomainSigning(msg), kp)

  const body = bodyFromMessage(msg)
  const result = buildPublisherSignedSeedOpts(body)
  t.is(result.ok, true)
  t.is(result.appKey, body.appKey)
  t.is(result.opts.publisherSignature, body.publisherSignature)
})

test('client seed can opt into domain-v3 signing', async (t) => {
  const kp = keyPair()
  const appKey = b4a.alloc(32, 0x55)
  const client = new HiveRelayClient({
    swarm: mockSwarm(kp),
    keyPair: kp,
    autoDiscover: false
  })
  t.teardown(() => client.destroy())

  await client.seed(appKey, {
    timeout: 1,
    retryPersistent: false,
    seedSignatureDomain: 'v3'
  })

  const entry = client.seedRequests.get(b4a.toString(appKey, 'hex'))
  t.ok(entry, 'seed request stored')
  const details = verifySeedRequestSignatureDetails(entry.request)
  t.is(details.ok, true)
  t.is(details.layout, 'domain-v3')
})
