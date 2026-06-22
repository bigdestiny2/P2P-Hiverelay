/**
 * StorageProofService (Tier-2 relay side) — in-process tests.
 *
 * The provider runs buildStorageProof for REAL against a temp-dir Hypercore
 * wrapped in a mock node whose appRegistry returns a fake seeded entry. We then
 * verify the produced proof with verifyStorageProof, and assert the guards
 * (phantom-core, bad input, out-of-range, rate-limit) all fire.
 */
import test from 'brittle'
import Hypercore from 'hypercore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import os from 'os'
import path from 'path'
import { StorageProofService } from 'p2p-hiveservices/builtin/storage-proof-service.js'
import { verifyStorageProof } from 'p2p-hiverelay/core/protocol/proof-of-storage.js'

let _n = 0
const tmp = () => path.join(os.tmpdir(), 'hr-sp-' + process.pid + '-' + (_n++))
function relayKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}
const freshNonce = () => { const n = b4a.alloc(32); sodium.randombytes_buf(n); return n }
const hexNonce = () => b4a.toString(freshNonce(), 'hex')

async function seededCore (blocks) {
  const core = new Hypercore(tmp())
  await core.ready()
  await core.append(blocks)
  return core
}

// Mock node: appRegistry.has/get return a fake entry whose drive.core is the
// real Hypercore; keyPair is the relay's signing identity (provider start ctx).
// _shouldRedactEntry mirrors the real AppRegistry predicate so the privacy gate
// is exercised against the same logic the catalog uses.
function mockNode (core, keyPair, opts = {}) {
  const keyHex = b4a.toString(core.key, 'hex')
  const entry = opts.noDrive
    ? {}
    : { drive: { core, db: { core }, closed: false, closing: false }, blind: opts.blind === true, privacyTier: opts.privacyTier || 'public' }
  return {
    keyPair: opts.noKeyPair ? null : keyPair,
    appRegistry: {
      has: (k) => !opts.notSeeded && k === keyHex,
      get: (k) => (k === keyHex ? entry : null),
      _shouldRedactEntry: (e, o = {}) =>
        e.blind === true || (o.redactPrivate === true && String(e.privacyTier || 'public').toLowerCase() !== 'public')
    }
  }
}
async function svcFor (core, keyPair, opts = {}) {
  const svc = new StorageProofService(opts.ctor || {})
  await svc.start({ node: mockNode(core, keyPair, opts) })
  return svc
}

test('prove: valid proof verifies against the drive key', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('bb'), b4a.from('ccc')])
  const relay = relayKeyPair()
  const svc = await svcFor(core, relay)
  const nonce = freshNonce()
  const resp = await svc.prove(
    { coreKey: b4a.toString(core.key, 'hex'), index: 2, nonce: b4a.toString(nonce, 'hex') },
    { remotePubkey: 'cafe'.repeat(16) }
  )
  t.is(resp.relayPubkey, b4a.toString(relay.publicKey, 'hex'), 'signed by the relay identity')
  const verifier = new Hypercore(tmp(), core.key)
  await verifier.ready()
  const v = await verifyStorageProof({
    verifierCore: verifier,
    response: resp,
    expect: { driveKey: core.key, index: 2, nonce, relayPubkey: relay.publicKey, minLength: core.length }
  })
  t.ok(v.valid, 'proof valid'); t.is(v.reason, null)
  await verifier.close(); await core.close()
})

test('prove: NOT_SEEDED for an unknown key (phantom-core guard — never store.get)', async (t) => {
  const core = await seededCore([b4a.from('x')])
  const svc = await svcFor(core, relayKeyPair(), { notSeeded: true })
  await t.exception(svc.prove(
    { coreKey: b4a.toString(core.key, 'hex'), index: 0, nonce: hexNonce() },
    { remotePubkey: 'ab'.repeat(32) }
  ), /NOT_SEEDED/)
  await core.close()
})

test('prove: seeded entry without an open drive (placeholder) => NOT_SEEDED', async (t) => {
  const core = await seededCore([b4a.from('x')])
  const svc = await svcFor(core, relayKeyPair(), { noDrive: true })
  await t.exception(svc.prove(
    { coreKey: b4a.toString(core.key, 'hex'), index: 0, nonce: hexNonce() }, {}
  ), /NOT_SEEDED/)
  await core.close()
})

test('prove: malformed inputs rejected before any core access', async (t) => {
  const core = await seededCore([b4a.from('x')])
  const svc = await svcFor(core, relayKeyPair())
  const k = b4a.toString(core.key, 'hex')
  await t.exception(svc.prove({ coreKey: 'zz', index: 0, nonce: hexNonce() }, {}), /BAD_CORE_KEY/)
  await t.exception(svc.prove({ coreKey: k, index: -1, nonce: hexNonce() }, {}), /BAD_INDEX/)
  await t.exception(svc.prove({ coreKey: k, index: 0, nonce: 'nothex' }, {}), /BAD_NONCE/)
  await core.close()
})

test('prove: BLOCK_OUT_OF_RANGE surfaced honestly from the helper', async (t) => {
  const core = await seededCore([b4a.from('only')])
  const svc = await svcFor(core, relayKeyPair())
  await t.exception(svc.prove(
    { coreKey: b4a.toString(core.key, 'hex'), index: 99, nonce: hexNonce() }, {}
  ), /BLOCK_OUT_OF_RANGE/)
  await core.close()
})

test('prove: rate limit trips after the burst for a single caller', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('b')])
  const svc = await svcFor(core, relayKeyPair(), { ctor: { proofsPerMin: 0, proofBurst: 1 } })
  const caller = { remotePubkey: 'ff'.repeat(32) }
  const k = b4a.toString(core.key, 'hex')
  await svc.prove({ coreKey: k, index: 0, nonce: hexNonce() }, caller) // 1st ok
  await t.exception(svc.prove({ coreKey: k, index: 0, nonce: hexNonce() }, caller), /RATE_LIMITED/)
  await core.close()
})

test('prove: NO_RELAY_KEYPAIR when the node has no identity key', async (t) => {
  const core = await seededCore([b4a.from('a')])
  const svc = await svcFor(core, relayKeyPair(), { noKeyPair: true })
  await t.exception(svc.prove(
    { coreKey: b4a.toString(core.key, 'hex'), index: 0, nonce: hexNonce() }, {}
  ), /NO_RELAY_KEYPAIR/)
  await core.close()
})

test('prove: BLIND drive => NOT_SEEDED (privacy gate, indistinguishable from not-held)', async (t) => {
  const core = await seededCore([b4a.from('secret-0'), b4a.from('secret-1')])
  const svc = await svcFor(core, relayKeyPair(), { blind: true })
  await t.exception(svc.prove(
    { coreKey: b4a.toString(core.key, 'hex'), index: 0, nonce: hexNonce() },
    { remotePubkey: 'snoop'.repeat(12).slice(0, 64) }
  ), /NOT_SEEDED/, 'a blind drive must not be confirmable via a signed proof')
  await core.close()
})

test('prove: non-public privacy tier => NOT_SEEDED (redactPrivate gate)', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('b')])
  const svc = await svcFor(core, relayKeyPair(), { privacyTier: 'private' })
  await t.exception(svc.prove(
    { coreKey: b4a.toString(core.key, 'hex'), index: 0, nonce: hexNonce() }, {}
  ), /NOT_SEEDED/)
  await core.close()
})

test('prove: GLOBAL cap bounds total proof work across DISTINCT identities', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('b')])
  // Global burst 1, no refill — sybil identities can't bypass it.
  const svc = await svcFor(core, relayKeyPair(), { ctor: { globalProofBurst: 1, globalProofsPerMin: 0 } })
  const k = b4a.toString(core.key, 'hex')
  await svc.prove({ coreKey: k, index: 0, nonce: hexNonce() }, { remotePubkey: 'aa'.repeat(32) }) // 1st identity ok
  await t.exception(
    svc.prove({ coreKey: k, index: 1, nonce: hexNonce() }, { remotePubkey: 'bb'.repeat(32) }), // different identity
    /RATE_LIMITED/, 'fresh identity cannot bypass the global proof budget'
  )
  await core.close()
})

test('prove: cheap rejects (not-seeded) do NOT spend the global budget', async (t) => {
  const core = await seededCore([b4a.from('a')])
  const svc = await svcFor(core, relayKeyPair(), { ctor: { globalProofBurst: 1, globalProofsPerMin: 0 } })
  const k = b4a.toString(core.key, 'hex')
  // Flood of not-seeded requests must not drain the budget...
  for (let i = 0; i < 5; i++) {
    await t.exception(svc.prove({ coreKey: 'cc'.repeat(32), index: 0, nonce: hexNonce() }, {}), /NOT_SEEDED/)
  }
  // ...so a genuine proof still succeeds afterwards.
  const resp = await svc.prove({ coreKey: k, index: 0, nonce: hexNonce() }, { remotePubkey: 'dd'.repeat(32) })
  t.ok(resp && resp.signature, 'honest proof still served after a not-seeded flood')
  await core.close()
})

test('_buckets stays bounded under many distinct caller identities', async (t) => {
  const core = await seededCore([b4a.from('a')])
  const svc = await svcFor(core, relayKeyPair(), { ctor: { maxBuckets: 3 } })
  const k = b4a.toString(core.key, 'hex')
  for (let i = 0; i < 8; i++) {
    await svc.prove({ coreKey: k, index: 0, nonce: hexNonce() }, { remotePubkey: String(i).padStart(64, '0') })
  }
  t.ok(svc._buckets.size <= 3, 'force-eviction keeps _buckets at the cap (' + svc._buckets.size + ')')
  await svc.stop()
  t.is(svc._buckets.size, 0, 'stop() clears buckets')
  await core.close()
})
