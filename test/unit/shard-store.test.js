import test from 'brittle'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Corestore from 'corestore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { ShardStoreService, ShardEngine, shardHash, normalizeShardAddress, signShardPin, verifyShardPin, ShardPinRegistry, verifyShardProof } from '../../packages/services/builtin/shard-store/index.js'
import { createCustodyIntent, createCustodyReceipt, verifyCustodyEntry, validateCustodyTransition } from '../../packages/core/core/custody-signing.js'

async function tmpStore (t) {
  const dir = await mkdtemp(join(tmpdir(), 'shard-store-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const store = new Corestore(dir)
  t.teardown(() => store.close())
  return { store, dir }
}

const bytes = (s) => b4a.from(s, 'utf8')
// Far future so pins are "live" under the service's real-clock pin registry.
const NOW = 2000000000000

function keyPair (seed) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seed))
  return { publicKey, secretKey, hex: b4a.toString(publicKey, 'hex') }
}

const paymentPin = (hash, kp, nonce = 'a'.repeat(32)) =>
  signShardPin({ reason: 'payment', hash: normalizeShardAddress(hash), retainUntil: NOW + 3600000, nonce }, kp)
const custodyPin = (hash, kp, { custodyIntentId, shareIndex, nonce = 'b'.repeat(32) }) =>
  signShardPin({ reason: 'custody', hash: normalizeShardAddress(hash), custodyIntentId, shareIndex, retainUntil: NOW + 3600000, nonce }, kp)

test('shard-engine: put/get round-trips and is content-addressed', async (t) => {
  const { store } = await tmpStore(t)
  const engine = new ShardEngine(store)
  const data = bytes('opaque-ciphertext-blob')

  const put = await engine.put(data)
  t.is(put.deduped, false)
  t.is(put.byteLength, data.byteLength)
  t.is(put.hash, shardHash(data), 'address is blake2b-256 of ciphertext')
  t.is(put.address, 'shard:' + shardHash(data))

  const got = await engine.get(put.address)
  t.ok(b4a.equals(got.ciphertext, data), 'exact bytes returned')
  t.is(shardHash(got.ciphertext), put.hash, 'caller re-hash verifies integrity')

  // bare-hex address also works
  const got2 = await engine.get(put.hash)
  t.ok(b4a.equals(got2.ciphertext, data))
})

test('shard-engine: dedup bumps refs without re-storing', async (t) => {
  const { store } = await tmpStore(t)
  const engine = new ShardEngine(store)
  const data = bytes('same-bytes')

  const a = await engine.put(data)
  t.is(a.deduped, false)
  const b = await engine.put(data)
  t.is(b.deduped, true, 'identical bytes dedup')
  t.is(a.hash, b.hash)

  // two refs -> one unpin keeps it, second removes it
  const u1 = await engine.unpin(a.address)
  t.is(u1.refs, 1)
  t.is(u1.removed, false)
  t.ok((await engine.has(a.address)).present, 'still held after first unpin')
  const u2 = await engine.unpin(a.address)
  t.is(u2.refs, 0)
  t.is(u2.removed, true)
  await t.exception(engine.get(a.address), /NOT_HELD/)
})

test('shard-engine: rejects hash mismatch, oversize, empty, and unknown', async (t) => {
  const { store } = await tmpStore(t)
  const engine = new ShardEngine(store, { maxShardBytes: 64 })

  await t.exception(engine.put(bytes('x'), { claimedHash: 'shard:' + 'a'.repeat(64) }), /HASH_MISMATCH/)
  await t.exception(engine.put(b4a.alloc(65)), /TOO_LARGE/)
  await t.exception(engine.put(b4a.alloc(0)), /EMPTY/)
  await t.exception(engine.get('shard:' + 'b'.repeat(64)), /NOT_HELD/)
  await t.exception(engine.get('not-a-hash'), /BAD_ADDRESS/)

  // a correct claimedHash is accepted
  const data = bytes('correct')
  const ok = await engine.put(data, { claimedHash: shardHash(data) })
  t.is(ok.deduped, false)
})

test('shard-engine: content survives a reopen (persistence)', async (t) => {
  const { store, dir } = await tmpStore(t)
  const engine = new ShardEngine(store)
  const data = bytes('persist-me')
  const put = await engine.put(data)
  await engine.close()
  await store.close()

  const store2 = new Corestore(dir)
  t.teardown(() => store2.close())
  const engine2 = new ShardEngine(store2)
  const got = await engine2.get(put.address)
  t.ok(b4a.equals(got.ciphertext, data), 'shard restored from disk')
})

test('shard-engine: a tampered stored blob is caught by the caller re-hash', async (t) => {
  const { store } = await tmpStore(t)
  const engine = new ShardEngine(store)
  const data = bytes('honest-bytes')
  const put = await engine.put(data)

  // Simulate a byzantine relay returning different bytes for the same address:
  // whatever it returns, the caller's re-hash must not match the requested id.
  const got = await engine.get(put.address)
  const forged = b4a.concat([got.ciphertext, bytes('tamper')])
  t.not(shardHash(forged), put.hash, 'mutated bytes do not hash to the address')
})

test('shard-store service: payment-pinned put/get/has/unpin over the RPC surface (base64)', async (t) => {
  const { store } = await tmpStore(t)
  const pinner = keyPair(7)
  const svc = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => true })
  await svc.start({ store })
  t.teardown(() => svc.stop())

  const sealed = b4a.from('sealed-shard-3', 'utf8')
  const hash = shardHash(sealed)
  const b64 = b4a.toString(sealed, 'base64')

  const put = await svc.put({ ciphertext: b64, pin: paymentPin(hash, pinner) })
  t.is(put.ok, true)
  t.is(put.shard, 'shard:' + hash)
  t.is(put.refs, 1)

  t.is((await svc.has({ shard: put.shard })).present, true)
  const got = await svc.get({ shard: put.shard })
  t.ok(b4a.equals(b4a.from(got.ciphertext, 'base64'), sealed), 'round-trips through base64')

  // unpin requires the pinner to sign a removal; last pin gone -> GC.
  const removal = paymentPin(hash, pinner, 'f'.repeat(32))
  const un = await svc.unpin({ shard: put.shard, pinRef: put.pinRef, removal })
  t.is(un.unpinned, true)
  t.is(un.gc, true)
  await t.exception(svc.get({ shard: put.shard }), /NOT_HELD/)
})

test('shard-store service: PUT is rejected without a valid pin', async (t) => {
  const { store } = await tmpStore(t)
  const attacker = keyPair(8)
  const svc = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => true })
  await svc.start({ store })
  t.teardown(() => svc.stop())
  const sealed = b4a.from('x', 'utf8'); const hash = shardHash(sealed); const b64 = b4a.toString(sealed, 'base64')

  await t.exception(svc.put({ ciphertext: b64 }), /UNAUTHORIZED_PIN/)
  // a pin naming a DIFFERENT hash can't authorize these bytes
  await t.exception(svc.put({ ciphertext: b64, pin: paymentPin('d'.repeat(64), attacker) }), /UNAUTHORIZED_PIN/)
  // quota refused
  const noQuota = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => false })
  await noQuota.start({ store }); t.teardown(() => noQuota.stop())
  await t.exception(noQuota.put({ ciphertext: b64, pin: paymentPin(hash, attacker) }), /QUOTA_EXHAUSTED/)
})

test('shard-store service: custody pin accepted only for the relay\'s assigned share', async (t) => {
  const { store } = await tmpStore(t)
  const publisher = keyPair(9)
  const sealed = b4a.from('encrypted-share-index-3', 'utf8')
  const hash = shardHash(sealed)
  const b64 = b4a.toString(sealed, 'base64')

  // Relay's custody resolver: intent 'ci1' assigns THIS relay shareIndex 3 -> this hash.
  const resolveCustodyAssignment = async (intentId, relayPubkey) =>
    intentId === 'ci1' ? { shareIndex: 3, shard: 'shard:' + hash } : null

  const svc = new ShardStoreService({ putAuth: ['custody'], resolveCustodyAssignment })
  await svc.start({ store })
  t.teardown(() => svc.stop())

  // wrong shareIndex -> rejected
  await t.exception(svc.put({ ciphertext: b64, pin: custodyPin(hash, publisher, { custodyIntentId: 'ci1', shareIndex: 5 }) }), /UNAUTHORIZED_PIN/)
  // unknown intent -> rejected
  await t.exception(svc.put({ ciphertext: b64, pin: custodyPin(hash, publisher, { custodyIntentId: 'nope', shareIndex: 3 }) }), /UNAUTHORIZED_PIN/)
  // correct assignment -> accepted
  const ok = await svc.put({ ciphertext: b64, pin: custodyPin(hash, publisher, { custodyIntentId: 'ci1', shareIndex: 3 }) })
  t.is(ok.ok, true)
  t.is(ok.refs, 1)
})

test('shard pin registry: re-verifies signatures on load and drops tampered pins', async (t) => {
  let saved = null
  const persistence = { async load () { return saved }, async save (s) { saved = s } }
  const pinner = keyPair(11)
  const reg = new ShardPinRegistry({ persistence, clock: () => NOW })
  const good = signShardPin({ reason: 'payment', hash: 'a'.repeat(64), retainUntil: NOW + 1000, nonce: '1'.repeat(32) }, pinner)
  reg.add(good)
  await reg.flush()

  // tamper: inject a pin whose signature does not verify.
  saved.pins.push({ ...good, hash: 'b'.repeat(64) }) // sig no longer matches the mutated hash

  const reg2 = new ShardPinRegistry({ persistence, clock: () => NOW })
  await reg2.load()
  t.is(reg2.refs('a'.repeat(64)), 1, 'legit pin restored')
  t.is(reg2.refs('b'.repeat(64)), 0, 'tampered pin dropped on load')
})

test('shard pin registry: retention follows live pins and expiry', async (t) => {
  let now = NOW
  const reg = new ShardPinRegistry({ clock: () => now })
  const kp = keyPair(12)
  const hash = 'c'.repeat(64)
  reg.add(signShardPin({ reason: 'payment', hash, retainUntil: NOW + 1000, nonce: '1'.repeat(32) }, kp))
  reg.add(signShardPin({ reason: 'payment', hash, retainUntil: NOW + 5000, nonce: '2'.repeat(32) }, kp))
  t.is(reg.refs(hash), 2)
  t.is(reg.retainUntil(hash), NOW + 5000)
  now = NOW + 2000
  t.is(reg.refs(hash), 1, 'first pin expired')
  now = NOW + 6000
  t.is(reg.refs(hash), 0, 'all pins expired')
  t.alike(reg.expiredHashes(), [hash])
})

test('shard-store service: manifest advertises the content-addressed surface + pin auth', async (t) => {
  const svc = new ShardStoreService({ maxShardBytes: 1024, putAuth: ['custody', 'payment'] })
  const m = svc.manifest()
  t.is(m.name, 'shard-store')
  t.alike(m.capabilities, ['put', 'get', 'has', 'unpin', 'prove'])
  t.is(m.addressing, 'blake2b-256-ciphertext')
  t.alike(m.putAuth, ['custody', 'payment'])
  t.is(m.limits.maxShardBytes, 1024)
  t.ok(verifyShardPin(paymentPin('e'.repeat(64), keyPair(3))))
  t.absent(normalizeShardAddress('shard:xyz'))
})

test('custody shareManifest: binds shareIndex -> shard:<hash>, signed + receipt-checked (M2)', async (t) => {
  const publisher = keyPair(20)
  const relay3 = keyPair(23)
  const shardA = 'a'.repeat(64)
  const commit3 = '02' + '5'.repeat(64) // compressed secp256k1 point (66 hex)
  // Custody entries are timestamp-skew-checked against the real clock, so use
  // a real-now stamp (unlike the far-future NOW the pin registry needs).
  const ts = Date.now()
  const base = {
    version: 2,
    blindContentId: '1'.repeat(64),
    ciphertextRoot: '2'.repeat(64),
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: ts + 60000,
    retainUntil: ts + 120000,
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: 1,
    commitmentRoot: '3'.repeat(64),
    shareBundleKey: '4'.repeat(64),
    shareAssignments: [{ relayPubkey: relay3.hex, shareIndex: 3 }],
    shareManifest: [{ shareIndex: 3, shard: 'shard:' + shardA, shareCommitment: commit3 }]
  }
  const intent = createCustodyIntent(base, publisher, { timestamp: ts })
  t.is(verifyCustodyEntry(intent).valid, true, 'intent with shareManifest verifies')
  t.is(intent.shareManifest[0].shard, 'shard:' + shardA, 'shard address normalized')

  // signature covers the manifest: tampering the bound hash invalidates it
  t.is(verifyCustodyEntry({ ...intent, shareManifest: [{ shareIndex: 3, shard: 'shard:' + 'f'.repeat(64), shareCommitment: commit3 }] }).valid, false)

  // a receipt for the assigned share, echoing the manifest commitment, validates
  const receipt = createCustodyReceipt({
    version: 2,
    intentId: intent.intentId,
    blindContentId: base.blindContentId,
    ciphertextRoot: base.ciphertextRoot,
    contentVersion: 1,
    shareScheme: 'pvss-secp256k1-v1',
    commitmentRoot: base.commitmentRoot,
    retainUntil: ts + 120000,
    shareIndex: 3,
    shareCommitment: commit3,
    shareVerified: true
  }, relay3, { timestamp: ts })
  t.is(validateCustodyTransition(receipt, { intent }).valid, true, 'receipt matching the manifest binding validates')

  // a receipt whose commitment disagrees with the manifest is rejected
  const forged = createCustodyReceipt({
    version: 2,
    intentId: intent.intentId,
    blindContentId: base.blindContentId,
    ciphertextRoot: base.ciphertextRoot,
    contentVersion: 1,
    shareScheme: 'pvss-secp256k1-v1',
    commitmentRoot: base.commitmentRoot,
    retainUntil: ts + 120000,
    shareIndex: 3,
    shareCommitment: '03' + '9'.repeat(64),
    shareVerified: true
  }, relay3, { timestamp: ts })
  const bad = validateCustodyTransition(forged, { intent })
  t.is(bad.valid, false)
  t.is(bad.reason, 'shareCommitment does not match manifest binding')
})

test('shard proofs: Mode R (get+nonce) is relay-signed, content-checked, replay-guarded (M3)', async (t) => {
  const { store } = await tmpStore(t)
  const relay = keyPair(30)
  const pinner = keyPair(31)
  const svc = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => true, keyPair: relay })
  await svc.start({ store })
  t.teardown(() => svc.stop())

  const sealed = b4a.from('share-bytes-for-proof', 'utf8')
  const hash = shardHash(sealed)
  await svc.put({ ciphertext: b4a.toString(sealed, 'base64'), pin: paymentPin(hash, pinner) })

  const nonce = '1'.repeat(64)
  const got = await svc.get({ shard: 'shard:' + hash, nonce })
  t.ok(got.proof, 'get with nonce carries a Mode R proof')
  t.is(got.proof.mode, 'R')
  const bytes = b4a.from(got.ciphertext, 'base64')
  t.ok(verifyShardProof(got.proof, { hash, nonce, relayPubkey: relay.hex, bytes }), 'proof verifies against hash + relay key')

  // replay: same proof does not verify for a different challenge nonce
  t.absent(verifyShardProof(got.proof, { hash, nonce: '2'.repeat(64), relayPubkey: relay.hex, bytes }))
  // tampered bytes fail content-address check
  t.absent(verifyShardProof(got.proof, { hash, nonce, relayPubkey: relay.hex, bytes: b4a.concat([bytes, b4a.from('x')]) }))
  // a different relay key can't validate the signature
  t.absent(verifyShardProof(got.proof, { hash, nonce, relayPubkey: keyPair(99).hex, bytes }))
})

test('shard proofs: Mode A attestation only for held shards; NOT_HELD otherwise (M3)', async (t) => {
  const { store } = await tmpStore(t)
  const relay = keyPair(32)
  const pinner = keyPair(33)
  const svc = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => true, keyPair: relay })
  await svc.start({ store })
  t.teardown(() => svc.stop())

  const sealed = b4a.from('attested-share', 'utf8')
  const hash = shardHash(sealed)
  await svc.put({ ciphertext: b4a.toString(sealed, 'base64'), pin: paymentPin(hash, pinner) })

  const nonce = '3'.repeat(64)
  const res = await svc.prove({ shard: 'shard:' + hash, nonce })
  t.is(res.proof.mode, 'A')
  t.ok(verifyShardProof(res.proof, { hash, nonce, relayPubkey: relay.hex }), 'attestation verifies (no bytes needed)')
  t.absent(verifyShardProof(res.proof, { hash, nonce: '4'.repeat(64), relayPubkey: relay.hex }), 'replay-guarded')

  // proving an unheld shard is NOT_HELD (indistinguishable from unauthorized)
  await t.exception(svc.prove({ shard: 'shard:' + 'e'.repeat(64), nonce }), /NOT_HELD/)
})
