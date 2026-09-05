import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { canonicalSeedDiscoveryHint } from '../../packages/core/core/protocol/seed-discovery-hints.js'
import { serializeSeedRequestForDomainSigning } from '../../packages/core/core/protocol/seed-request.js'
import {
  quarantineSeedRequest,
  storeLegacySeedRequest,
  verifyStoredSeedRequest
} from '../../packages/core/core/registry/seed-request-storage.js'

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function flatRequest ({ publisher = keyPair(), signed = true } = {}) {
  const appKey = b4a.alloc(32, 0x42)
  const discoveryKeys = [canonicalSeedDiscoveryHint(appKey), canonicalSeedDiscoveryHint(appKey)]
  const msg = {
    appKey,
    discoveryKeys,
    replicationFactor: 3,
    maxStorageBytes: 1024 * 1024,
    ttlSeconds: 3600,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0,
    durability: 0,
    publisherPubkey: publisher.publicKey,
    publisherSignature: b4a.alloc(64)
  }
  if (signed) {
    sodium.crypto_sign_detached(
      msg.publisherSignature,
      serializeSeedRequestForDomainSigning(msg),
      publisher.secretKey
    )
  }
  return {
    publisher,
    entry: {
      type: 'seed-request',
      timestamp: Date.now(),
      appKey: b4a.toString(appKey, 'hex'),
      discoveryKeys: discoveryKeys.map(key => b4a.toString(key, 'hex')),
      replicationFactor: msg.replicationFactor,
      maxStorageBytes: msg.maxStorageBytes,
      ttlSeconds: msg.ttlSeconds,
      bountyRate: msg.bountyRate,
      revocable: msg.revocable,
      unseedFreezeMs: msg.unseedFreezeMs,
      durability: msg.durability,
      publisherPubkey: b4a.toString(publisher.publicKey, 'hex'),
      publisherSignature: signed ? b4a.toString(msg.publisherSignature, 'hex') : null,
      signatureProfile: signed ? 'domain-v3' : null,
      issuedAt: null,
      requestNonce: null,
      contentType: 'app',
      parentKey: null,
      mountPath: null,
      geoPreference: [],
      privacyTier: 'public',
      blind: false,
      storageClass: 'persistent',
      availabilityClass: 'always-on',
      custodyIntentId: null,
      blindContentId: null,
      ciphertextRoot: null,
      commitmentRoot: null,
      contentVersion: null,
      retainUntil: null,
      shardIds: [],
      shareScheme: null,
      shareThreshold: null,
      leaseDays: null
    }
  }
}

test('stored publisher seed request preserves signed order and re-verifies provenance', (t) => {
  const { entry } = flatRequest()
  const peer = '22'.repeat(32)
  const log = '33'.repeat(32)
  const built = storeLegacySeedRequest(entry, {
    authenticatedPeerPubkey: peer,
    originLogKey: log
  })
  t.ok(built.ok)
  t.is(built.stored.kind, 'publisher-signed')
  t.alike(built.stored.request.discoveryKeys, entry.discoveryKeys, 'publisher ordering and duplicates are retained')
  t.is(built.stored.request.signatureProfile, 'domain-v3')

  const verified = verifyStoredSeedRequest(built.stored, {
    authenticatedPeerPubkey: peer,
    originLogKey: log
  })
  t.ok(verified.ok)
  t.alike(verified.entry.discoveryKeys, entry.discoveryKeys)

  t.is(verifyStoredSeedRequest({ ...built.stored, unexpected: true }, {
    authenticatedPeerPubkey: peer,
    originLogKey: log
  }).reason, 'schema-invalid', 'unknown stored fields fail closed')
  t.is(verifyStoredSeedRequest(built.stored, {
    authenticatedPeerPubkey: '44'.repeat(32),
    originLogKey: log
  }).reason, 'origin-drift')
})

test('stored seed request contains invalid signed and unsigned provenance', (t) => {
  const signed = flatRequest().entry
  signed.publisherSignature = '00'.repeat(64)
  t.is(storeLegacySeedRequest(signed, {
    authenticatedPeerPubkey: '22'.repeat(32),
    originLogKey: '33'.repeat(32)
  }).reason, 'signature-invalid')

  const unsignedFixture = flatRequest({ signed: false })
  const publisherHex = b4a.toString(unsignedFixture.publisher.publicKey, 'hex')
  const peer = storeLegacySeedRequest(unsignedFixture.entry, {
    authenticatedPeerPubkey: publisherHex,
    originLogKey: '55'.repeat(32)
  })
  t.ok(peer.ok)
  t.is(peer.stored.kind, 'authenticated-peer-legacy')

  const local = storeLegacySeedRequest(unsignedFixture.entry, {
    local: true,
    localSwarmPubkey: publisherHex,
    originLogKey: '66'.repeat(32)
  })
  t.ok(local.ok)
  t.is(local.stored.kind, 'authenticated-local-management')
  t.ok(verifyStoredSeedRequest(local.stored, {
    localSwarmPubkey: publisherHex,
    localLogKey: '66'.repeat(32)
  }).ok)
  t.is(verifyStoredSeedRequest(local.stored, {
    localSwarmPubkey: publisherHex,
    localLogKey: '77'.repeat(32)
  }).reason, 'origin-drift', 'restart identity drift cannot hydrate local management state')

  t.is(storeLegacySeedRequest(unsignedFixture.entry, {}).reason, 'missing-provenance')
})

test('stored seed request rejects distinct hints and quarantine stores only a digest', (t) => {
  const { entry } = flatRequest()
  entry.discoveryKeys.push('99'.repeat(32))
  t.is(storeLegacySeedRequest(entry, {
    authenticatedPeerPubkey: '22'.repeat(32),
    originLogKey: '33'.repeat(32)
  }).reason, 'unsupported-discovery-key-set')

  const quarantine = quarantineSeedRequest(b4a.from('rejected bytes'), 'unsupported-discovery-key-set', {
    authenticatedPeerPubkey: '22'.repeat(32),
    originLogKey: '33'.repeat(32)
  })
  t.alike(Object.keys(quarantine).sort(), [
    'kind', 'observedLogKey', 'observedPeerPubkey', 'reason', 'recordSha256', 'version'
  ])
  t.is(quarantine.recordSha256.length, 64)
  t.ok(verifyStoredSeedRequest(quarantine).quarantine)
})
