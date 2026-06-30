/**
 * seed-request-builder tests.
 *
 * The builder is the shared validation + opts-assembly path used by both
 * the HTTP /api/v1/seed route and the Protomux hiverelay-publish channel's
 * 'seed' submit kind. Tests pin its contract so both transports stay in
 * lockstep.
 *
 * Signature verification uses a real Ed25519 keypair so we exercise the
 * actual verifySeedRequestSignature path, not a mock. Catches regressions
 * in the canonical-payload layout that would silently break v0.8.x
 * publishers signing against the v2 shape.
 */

import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  serializeSeedRequestForReplaySigning,
  serializeSeedRequestForSigning
} from 'p2p-hiverelay/core/protocol/seed-request.js'
import {
  buildPublisherSignedSeedOpts,
  consumePublisherSeedReplayNonce,
  extractCustodySeedOpts
} from 'p2p-hiverelay/core/seed-request-builder.js'

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

// Build a publisher-signed body exactly as a real publisher would —
// canonical-serialize, Ed25519-sign, then convert to the wire JSON shape.
function signedBody (kp, overrides = {}) {
  const fields = {
    appKey: b4a.alloc(32, 0x42),
    discoveryKeys: [],
    replicationFactor: 3,
    maxStorageBytes: 500 * 1024 * 1024,
    ttlSeconds: 30 * 24 * 3600,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0,
    durability: 0,
    publisherPubkey: kp.publicKey,
    issuedAt: overrides.issuedAt,
    requestNonce: overrides.requestNonce ? b4a.from(overrides.requestNonce, 'hex') : undefined,
    ...overrides
  }
  const payload = overrides.issuedAt !== undefined || overrides.requestNonce !== undefined
    ? serializeSeedRequestForReplaySigning(fields)
    : serializeSeedRequestForSigning(fields)
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, payload, kp.secretKey)
  const body = {
    appKey: b4a.toString(fields.appKey, 'hex'),
    discoveryKeys: fields.discoveryKeys.map(dk => b4a.toString(dk, 'hex')),
    replicationFactor: fields.replicationFactor,
    maxStorageBytes: fields.maxStorageBytes,
    ttlSeconds: fields.ttlSeconds,
    bountyRate: fields.bountyRate,
    revocable: fields.revocable,
    unseedFreezeMs: fields.unseedFreezeMs,
    durability: fields.durability,
    publisherPubkey: b4a.toString(fields.publisherPubkey, 'hex'),
    publisherSignature: b4a.toString(sig, 'hex')
  }
  if (fields.issuedAt !== undefined) body.issuedAt = fields.issuedAt
  if (fields.requestNonce !== undefined) {
    body.requestNonce = b4a.isBuffer(fields.requestNonce)
      ? b4a.toString(fields.requestNonce, 'hex')
      : fields.requestNonce
  }
  return body
}

// ─── Happy path ─────────────────────────────────────────────────────

test('builder: signed body with defaults returns ok + canonical opts', (t) => {
  const kp = keyPair()
  const body = signedBody(kp)
  const r = buildPublisherSignedSeedOpts(body)
  t.is(r.ok, true)
  t.is(r.appKey, body.appKey)
  t.is(r.opts.replicas, 3)
  t.is(r.opts.maxStorage, 500 * 1024 * 1024)
  t.is(r.opts.ttlDays, 30)
  t.is(r.opts.bountyRate, 0)
  t.is(r.opts.revocable, true)
  t.is(r.opts.unseedFreezeMs, 0)
  t.is(r.opts.durability, 0)
  t.is(r.opts.publisherPubkey, body.publisherPubkey)
  t.is(r.opts.publisherSignature, body.publisherSignature)
})

test('builder: replay-v1 signed body returns replay metadata and cache rejects duplicates', (t) => {
  const kp = keyPair()
  const now = 1782753600000
  const body = signedBody(kp, {
    issuedAt: now - 1000,
    requestNonce: '01'.repeat(16)
  })
  const r = buildPublisherSignedSeedOpts(body, { now })
  t.is(r.ok, true)
  t.is(r.opts.seedSignatureProfile, 'replay-v1')
  t.is(r.opts.issuedAt, body.issuedAt)
  t.is(r.opts.requestNonce, body.requestNonce)
  t.is(r.replay.requestNonce, body.requestNonce)

  const cache = new Map()
  t.is(consumePublisherSeedReplayNonce(r.replay, cache, { now }).ok, true)
  const duplicate = consumePublisherSeedReplayNonce(r.replay, cache, { now })
  t.is(duplicate.ok, false)
  t.is(duplicate.status, 409)
  t.ok(duplicate.error.includes('SEED_REQUEST_REPLAY'))
})

test('builder: replay fields require replay-v1 signature and fresh issuedAt', (t) => {
  const kp = keyPair()
  const now = 1782753600000
  const legacyWithReplayFields = signedBody(kp)
  legacyWithReplayFields.issuedAt = now
  legacyWithReplayFields.requestNonce = '02'.repeat(16)
  const legacy = buildPublisherSignedSeedOpts(legacyWithReplayFields, { now })
  t.is(legacy.ok, false)
  t.is(legacy.status, 403)
  t.ok(legacy.error.includes('INVALID_SIGNATURE'))

  const stale = signedBody(kp, {
    issuedAt: now - 60 * 60 * 1000 - 1,
    requestNonce: '03'.repeat(16)
  })
  const staleResult = buildPublisherSignedSeedOpts(stale, { now })
  t.is(staleResult.ok, false)
  t.is(staleResult.error, 'issuedAt is outside the replay window')

  const future = signedBody(kp, {
    issuedAt: now + 60 * 1000 + 1,
    requestNonce: '04'.repeat(16)
  })
  const futureResult = buildPublisherSignedSeedOpts(future, { now })
  t.is(futureResult.ok, false)
  t.is(futureResult.error, 'issuedAt is too far in the future')
})

test('builder: signed body with all optional metadata returns ok', (t) => {
  const kp = keyPair()
  const body = signedBody(kp)
  body.type = 'drive'
  body.storageClass = 'temporary'
  body.availabilityClass = 'atomic-handoff'
  body.privacyTier = 'p2p-only'
  body.blind = true
  body.custodyIntentId = '0'.repeat(63) + '1'
  body.blindContentId = '0'.repeat(63) + '2'
  body.ciphertextRoot = '0'.repeat(63) + '3'
  body.contentVersion = 7
  body.retainUntil = Date.now() + 60_000
  body.shardIds = [0, 1, 2]

  const r = buildPublisherSignedSeedOpts(body)
  t.is(r.ok, true)
  t.is(r.opts.type, 'drive')
  t.is(r.opts.storageClass, 'temporary')
  t.is(r.opts.availabilityClass, 'atomic-handoff')
  t.is(r.opts.privacyTier, 'p2p-only')
  t.is(r.opts.blind, true)
  t.is(r.opts.custodyIntentId, body.custodyIntentId)
  t.is(r.opts.contentVersion, 7)
  t.alike(r.opts.shardIds, [0, 1, 2])
})

// ─── Presence + format failures ─────────────────────────────────────

test('builder: missing appKey → 400', (t) => {
  const r = buildPublisherSignedSeedOpts({ publisherPubkey: 'a', publisherSignature: 'b' })
  t.is(r.ok, false)
  t.is(r.status, 400)
  t.is(r.error, 'appKey required')
})

test('builder: malformed appKey → 400', (t) => {
  const r = buildPublisherSignedSeedOpts({ appKey: 'not-hex', publisherPubkey: 'a', publisherSignature: 'b' })
  t.is(r.ok, false)
  t.is(r.status, 400)
  t.ok(r.error.includes('appKey must be 64 hex'))
})

test('builder: missing publisherPubkey → 400', (t) => {
  const r = buildPublisherSignedSeedOpts({ appKey: 'a'.repeat(64) })
  t.is(r.ok, false)
  t.is(r.error, 'publisherPubkey required')
})

test('builder: missing publisherSignature → 400', (t) => {
  const r = buildPublisherSignedSeedOpts({ appKey: 'a'.repeat(64), publisherPubkey: 'b'.repeat(64) })
  t.is(r.ok, false)
  t.is(r.error, 'publisherSignature required')
})

test('builder: signature with wrong publisher pubkey → 403 INVALID_SIGNATURE', (t) => {
  const kp1 = keyPair()
  const kp2 = keyPair()
  const body = signedBody(kp1)
  // Swap to a different pubkey while keeping kp1's signature
  body.publisherPubkey = b4a.toString(kp2.publicKey, 'hex')
  const r = buildPublisherSignedSeedOpts(body)
  t.is(r.ok, false)
  t.is(r.status, 403)
  t.ok(r.error.startsWith('INVALID_SIGNATURE'))
})

test('builder: signature over tampered field rejected', (t) => {
  const kp = keyPair()
  const body = signedBody(kp)
  body.replicationFactor = 7 // tamper after signing
  const r = buildPublisherSignedSeedOpts(body)
  t.is(r.ok, false)
  t.is(r.status, 403)
})

// ─── Numeric bounds ─────────────────────────────────────────────────

test('builder: replicationFactor out of range → 400', (t) => {
  // We don't need a valid signature here; bounds check runs before verify.
  const r = buildPublisherSignedSeedOpts({
    appKey: 'a'.repeat(64),
    publisherPubkey: 'b'.repeat(64),
    publisherSignature: 'c'.repeat(128),
    replicationFactor: 300
  })
  t.is(r.ok, false)
  t.ok(r.error.includes('[1,255]'))
})

test('builder: negative maxStorageBytes → 400', (t) => {
  const r = buildPublisherSignedSeedOpts({
    appKey: 'a'.repeat(64),
    publisherPubkey: 'b'.repeat(64),
    publisherSignature: 'c'.repeat(128),
    maxStorageBytes: -1
  })
  t.is(r.ok, false)
  t.is(r.error, 'maxStorageBytes must be non-negative')
})

// ─── discoveryKeys ──────────────────────────────────────────────────

test('builder: discoveryKeys not an array → 400', (t) => {
  const r = buildPublisherSignedSeedOpts({
    appKey: 'a'.repeat(64),
    publisherPubkey: 'b'.repeat(64),
    publisherSignature: 'c'.repeat(128),
    discoveryKeys: 'not-array'
  })
  t.is(r.ok, false)
  t.ok(r.error.includes('discoveryKeys must be an array'))
})

test('builder: too many discoveryKeys → 400', (t) => {
  const r = buildPublisherSignedSeedOpts({
    appKey: 'a'.repeat(64),
    publisherPubkey: 'b'.repeat(64),
    publisherSignature: 'c'.repeat(128),
    discoveryKeys: new Array(101).fill('d'.repeat(64))
  })
  t.is(r.ok, false)
  t.ok(r.error.includes('exceeds maximum'))
})

// ─── Optional metadata validators ───────────────────────────────────

test('builder: invalid type → 400', (t) => {
  const kp = keyPair()
  const body = signedBody(kp)
  body.type = 'not-a-real-type'
  const r = buildPublisherSignedSeedOpts(body)
  t.is(r.ok, false)
  t.ok(r.error.startsWith('type must be one of'))
})

test('builder: shardIds with negative integer → 400', (t) => {
  const kp = keyPair()
  const body = signedBody(kp)
  body.shardIds = [0, -1, 2]
  const r = buildPublisherSignedSeedOpts(body)
  t.is(r.ok, false)
  t.ok(r.error.includes('non-negative integers'))
})

test('builder: publisher-signed seed rejects unknown top-level fields', (t) => {
  const kp = keyPair()
  const body = signedBody(kp)
  body.caption = 'private docs'

  const r = buildPublisherSignedSeedOpts(body)
  t.is(r.ok, false)
  t.is(r.status, 400)
  t.is(r.error, 'unknown publisher seed field: caption')
})

test('builder: publisher-signed seed allowlists lease payment envelope', (t) => {
  const kp = keyPair()
  const body = signedBody(kp)
  body.leaseDays = 7
  body.paymentProof = { quoteId: 'quote-1' }

  const r = buildPublisherSignedSeedOpts(body)
  t.is(r.ok, true)

  const extraProof = signedBody(kp)
  extraProof.paymentProof = { quoteId: 'quote-1', memo: 'secret' }
  const extraProofResult = buildPublisherSignedSeedOpts(extraProof)
  t.is(extraProofResult.ok, false)
  t.is(extraProofResult.error, 'unknown paymentProof field: memo')

  const extraToken = signedBody(kp)
  extraToken.paymentProof = { blindToken: { secret: 's', C: 'c', note: 'secret' } }
  const extraTokenResult = buildPublisherSignedSeedOpts(extraToken)
  t.is(extraTokenResult.ok, false)
  t.is(extraTokenResult.error, 'unknown paymentProof.blindToken field: note')
})

// ─── Custody publisher mismatch ─────────────────────────────────────

test('builder: custody intent publisher mismatch → 403 CUSTODY_PUBLISHER_MISMATCH', (t) => {
  const kp = keyPair()
  const body = signedBody(kp)
  body.custodyIntentId = '0'.repeat(63) + '1'
  // Mock registry returns an intent signed by a DIFFERENT publisher
  const seedingRegistry = {
    getCustodyIntent: () => ({ publisherPubkey: 'f'.repeat(64) })
  }
  const r = buildPublisherSignedSeedOpts(body, { seedingRegistry })
  t.is(r.ok, false)
  t.is(r.status, 403)
  t.ok(r.error.startsWith('CUSTODY_PUBLISHER_MISMATCH'))
})

test('builder: custody intent publisher match → ok', (t) => {
  const kp = keyPair()
  const body = signedBody(kp)
  body.custodyIntentId = '0'.repeat(63) + '1'
  const seedingRegistry = {
    getCustodyIntent: () => ({ publisherPubkey: body.publisherPubkey })
  }
  const r = buildPublisherSignedSeedOpts(body, { seedingRegistry })
  t.is(r.ok, true)
  t.is(r.opts.custodyIntentId, body.custodyIntentId)
})

test('builder: custody intent registry error is best-effort (does not block)', (t) => {
  const kp = keyPair()
  const body = signedBody(kp)
  body.custodyIntentId = '0'.repeat(63) + '1'
  const seedingRegistry = {
    getCustodyIntent: () => { throw new Error('registry down') }
  }
  const r = buildPublisherSignedSeedOpts(body, { seedingRegistry })
  t.is(r.ok, true)
})

// ─── Body shape guards ──────────────────────────────────────────────

test('builder: null body → 400', (t) => {
  const r = buildPublisherSignedSeedOpts(null)
  t.is(r.ok, false)
  t.is(r.error, 'body required')
})

test('builder: non-object body → 400', (t) => {
  const r = buildPublisherSignedSeedOpts('garbage')
  t.is(r.ok, false)
  t.is(r.error, 'body required')
})

// ─── extractCustodySeedOpts (legacy Protomux seed path) ─────────────
//
// The binary seedRequestEncoding carries no custody fields and signs
// none, so the legacy `_onSeedRequest` handler historically dropped the
// custody binding — a custody seed accepted there landed with no
// custodyIntentId/retainUntil, so the relay could never attest a
// non-serving-proof for it. extractCustodySeedOpts pulls any well-formed
// custody linkage off an enriched message into a seedApp()-ready fragment.
// It is deliberately read-only and permissive: it does NOT re-verify the
// publisher signature (the publish channel remains the authenticated path).

test('extractCustodySeedOpts: well-formed custody fields are carried through', (t) => {
  const msg = {
    custodyIntentId: '0'.repeat(63) + '1',
    blindContentId: '0'.repeat(63) + '2',
    ciphertextRoot: '0'.repeat(63) + '3',
    contentVersion: 4,
    retainUntil: 1_700_000_000_000
  }
  const out = extractCustodySeedOpts(msg)
  t.is(out.custodyIntentId, msg.custodyIntentId)
  t.is(out.blindContentId, msg.blindContentId)
  t.is(out.ciphertextRoot, msg.ciphertextRoot)
  t.is(out.contentVersion, 4)
  t.is(out.retainUntil, 1_700_000_000_000)
})

test('extractCustodySeedOpts: hex fields are lowercased', (t) => {
  const out = extractCustodySeedOpts({ custodyIntentId: 'A'.repeat(64) })
  t.is(out.custodyIntentId, 'a'.repeat(64))
})

test('extractCustodySeedOpts: malformed / absent fields are omitted', (t) => {
  // Non-hex, wrong length, and wrong types are all dropped silently so the
  // fragment spreads to nothing — identical to the pre-fix behavior.
  const out = extractCustodySeedOpts({
    custodyIntentId: 'not-hex',
    blindContentId: 'abc', // too short
    ciphertextRoot: 123, // wrong type
    contentVersion: -1, // negative → dropped
    retainUntil: -5 // negative → dropped
  })
  t.alike(out, {})
})

test('extractCustodySeedOpts: empty object for non-object / nullish input', (t) => {
  t.alike(extractCustodySeedOpts(null), {})
  t.alike(extractCustodySeedOpts(undefined), {})
  t.alike(extractCustodySeedOpts('garbage'), {})
  t.alike(extractCustodySeedOpts({}), {})
})

test('extractCustodySeedOpts: contentVersion/retainUntil floored to integers', (t) => {
  const out = extractCustodySeedOpts({ contentVersion: 4.9, retainUntil: 100.7 })
  t.is(out.contentVersion, 4)
  t.is(out.retainUntil, 100)
})

test('extractCustodySeedOpts: contentVersion 0 and retainUntil 0 are kept', (t) => {
  // 0 is a valid floor value (>= 0 guard), not absence.
  const out = extractCustodySeedOpts({ contentVersion: 0, retainUntil: 0 })
  t.is(out.contentVersion, 0)
  t.is(out.retainUntil, 0)
})
