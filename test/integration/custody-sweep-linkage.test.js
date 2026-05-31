/**
 * Regression for the gap Drop hit (Ian, 2026-05-31): a relay's custody expiry
 * sweep never emitted a non-serving-proof for content seeded over the
 * seed-request channel. Two independent root causes, both fixed in v0.9.2:
 *
 *  1. Linkage. The binary seedRequestEncoding drops custody fields, so the
 *     appRegistry entry lands with custodyIntentId = null even though a signed
 *     intent for that addressKey exists in the registry (published over the
 *     custody channel). The sweep keyed attestation off entry.custodyIntentId,
 *     so it could never link the two. Now it resolves the intent by addressKey
 *     (getCustodyIntentIdByAddressKey) and backfills the entry.
 *
 *  2. Nonce. Even with a custodyIntentId, the sweep called
 *     createCustodyNonServingProof without a challengeNonce, and proof signing
 *     requires a 64-hex nonce — so every auto-attest threw "challengeNonce must
 *     be 64 hex characters". createCustodyNonServingProof now self-generates a
 *     nonce when none is supplied (same for the expiry-witness path).
 *
 * One relay handles two entries in a single sweep pass — a still-live one (gets
 * its custodyIntentId backfilled, not expired) and an expired one (resolved,
 * unseeded, and attested). Entries are registered directly via appRegistry.set
 * so the sweep is exercised deterministically without real content replication.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { randomBytes } from 'crypto'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

// A temporary-custody entry as if seeded over the seed-request channel: blind +
// atomic-handoff, but custodyIntentId omitted (the wire dropped it).
function unlinkedEntry (overrides = {}) {
  return {
    drive: { closed: false, closing: false, close: async () => {} },
    discoveryKey: randomBytes(32),
    startedAt: Date.now(),
    type: 'drive',
    blind: true,
    storageClass: 'temporary',
    availabilityClass: 'atomic-handoff',
    custodyIntentId: null,
    anchored: true,
    ...overrides
  }
}

test('custody sweep: recovers custodyIntentId by addressKey, backfills live entries, and attests expired ones', async (t) => {
  const id = randomBytes(4).toString('hex')
  const baseDir = join(tmpdir(), 'hiverelay-sweep-' + id)
  const testnet = await createTestnet(3)
  let relay = null
  await mkdir(baseDir, { recursive: true })
  t.teardown(async () => {
    if (relay) { try { await relay.stop() } catch {} }
    try { await testnet.destroy() } catch {}
    try { await rm(baseDir, { recursive: true, force: true }) } catch {}
  })

  relay = new RelayNode({
    storage: join(baseDir, 'relay'),
    bootstrapNodes: testnet.bootstrap,
    enableSeeding: true,
    enableNetworkDiscovery: false,
    enableHolesail: false,
    custodyExpiryGraceMs: 0
  })
  await relay.start()
  const attestErrors = []
  relay.on('custody-non-serving-attest-error', e => attestErrors.push(e))

  const publisher = keyPair()
  const now = Date.now()

  // ── Entry A: still LIVE (retain window open). Intent only. ──
  const liveKey = b4a.toString(randomBytes(32), 'hex')
  const liveBlind = b4a.toString(randomBytes(32), 'hex')
  const liveRetain = now + 60 * 60 * 1000
  const liveIntent = await relay.seedingRegistry.publishCustodyIntent({
    addressKey: liveKey,
    blindContentId: liveBlind,
    ciphertextRoot: b4a.toString(randomBytes(32), 'hex'),
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000,
    retainUntil: liveRetain
  }, publisher)
  relay.appRegistry.set(liveKey, unlinkedEntry({ retainUntil: liveRetain, blindContentId: liveBlind }))

  // ── Entry B: EXPIRED (retain elapsed). Full chain (committed), mirroring
  //    Drop's foundation evidence. The relay's own key signs the receipt so it
  //    is in the committed quorum. ──
  const deadKey = b4a.toString(randomBytes(32), 'hex')
  const deadBlind = b4a.toString(randomBytes(32), 'hex')
  const deadCipher = b4a.toString(randomBytes(32), 'hex')
  const deadRetain = now - 120_000
  const deadIntent = await relay.seedingRegistry.publishCustodyIntent({
    addressKey: deadKey,
    blindContentId: deadBlind,
    ciphertextRoot: deadCipher,
    contentVersion: 1,
    requiredReplicas: 1,
    deadline: now + 60_000, // receipt window open (independent of retainUntil)
    retainUntil: deadRetain // already elapsed → time-path expiry
  }, publisher)
  await relay.seedingRegistry.recordCustodyReceipt({
    intentId: deadIntent.intentId, blindContentId: deadBlind, ciphertextRoot: deadCipher, contentVersion: 1, anchored: true, retainUntil: deadRetain
  }, relay.swarm.keyPair)
  await relay.seedingRegistry.publishCustodyCommit({ intentId: deadIntent.intentId }, publisher)
  relay.appRegistry.set(deadKey, unlinkedEntry({ retainUntil: deadRetain, blindContentId: deadBlind }))

  // Both entries start unlinked; the registry can resolve both by addressKey.
  t.is(relay.appRegistry.get(liveKey).custodyIntentId || null, null, 'live entry starts unlinked')
  t.is(relay.appRegistry.get(deadKey).custodyIntentId || null, null, 'expired entry starts unlinked')
  t.is(relay.seedingRegistry.getCustodyIntentIdByAddressKey(liveKey), liveIntent.intentId, 'resolves live intent by addressKey')
  t.is(relay.seedingRegistry.getCustodyIntentIdByAddressKey(deadKey), deadIntent.intentId, 'resolves expired intent by addressKey')

  // One sweep pass handles both entries.
  const result = await relay._runCustodyExpiryPass()
  t.is(attestErrors.length, 0, 'no attest errors: ' + JSON.stringify(attestErrors))
  t.is(result.attested, 1, 'sweep signed exactly one non-serving-proof (the expired entry)')

  // Live entry: backfilled, retained.
  const liveEntry = relay.appRegistry.get(liveKey)
  t.ok(liveEntry, 'live entry retained (not unseeded)')
  t.is(liveEntry.custodyIntentId, liveIntent.intentId, 'live entry.custodyIntentId backfilled from addressKey match')

  // Expired entry: attested + unseeded.
  t.is(relay.seedingRegistry.getCustodyStatus(deadIntent.intentId).nonServingProofCount, 1,
    'non-serving-proof recorded for the expired intent')
  t.absent(relay.appRegistry.get(deadKey), 'expired entry was unseeded')
})
