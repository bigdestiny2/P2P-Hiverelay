import test from 'brittle'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Corestore from 'corestore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { ShardStoreService, ShardEngine, shardHash, normalizeShardAddress, signShardPin, verifyShardPin, ShardPinRegistry, verifyShardProof, verifyShardTombstone, recoverShards, shardAnnounceTopic } from '../../packages/services/builtin/shard-store/index.js'
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

test('shard-store service: sweep GCs expired pins, signs non-serving tombstones (M4)', async (t) => {
  const { store } = await tmpStore(t)
  let now = NOW
  const relay = keyPair(40)
  const pinner = keyPair(41)
  const svc = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => true, keyPair: relay, clock: () => now })
  await svc.start({ store })
  t.teardown(() => svc.stop())

  const sealed = b4a.from('short-lived-share', 'utf8')
  const hash = shardHash(sealed)
  // pin with a short retention
  const shortPin = signShardPin({ reason: 'payment', hash, retainUntil: NOW + 1000, nonce: '7'.repeat(32) }, pinner)
  await svc.put({ ciphertext: b4a.toString(sealed, 'base64'), pin: shortPin })
  t.is((await svc.has({ shard: 'shard:' + hash })).present, true)

  // before expiry: sweep is a no-op
  t.is((await svc.sweep()).swept, 0)

  now = NOW + 2000 // past retainUntil
  const swept = await svc.sweep()
  t.is(swept.swept, 1, 'expired shard swept')
  t.is(swept.tombstones.length, 1)
  t.is(swept.tombstones[0].mode, 'T')
  t.ok(verifyShardTombstone(swept.tombstones[0], { hash, relayPubkey: relay.hex }), 'tombstone is relay-signed')
  t.is((await svc.has({ shard: 'shard:' + hash })).present, false, 'blob GCd')

  const stats = await svc.stats()
  t.is(stats.shards, 0)
  t.is(stats.bytes, 0)
})

test('shard recovery: k-of-n by hash with content-address verification (M4)', async (t) => {
  // three shares; threshold 2. A byzantine relay returns wrong bytes for one.
  const shares = [bytes('share-1'), bytes('share-2'), bytes('share-3')]
  const manifest = shares.map((s, i) => ({ shareIndex: i + 1, shard: 'shard:' + shardHash(s) }))

  const holders = new Map(manifest.map((m, i) => [normalizeShardAddress(m.shard), shares[i]]))
  const goodFetch = async (addr) => holders.get(normalizeShardAddress(addr)) || null

  const rec = await recoverShards({ manifest, shareThreshold: 2, fetch: goodFetch })
  t.is(rec.ok, true)
  t.is(rec.collected.length, 2, 'stops at threshold')

  // a relay that returns garbage for share 1 is caught by re-hash; recovery
  // still succeeds from the other holders.
  const byzFetch = async (addr) => {
    const h = normalizeShardAddress(addr)
    if (h === shardHash(shares[0])) return bytes('garbage')
    return holders.get(h) || null
  }
  const rec2 = await recoverShards({ manifest, shareThreshold: 2, fetch: byzFetch })
  t.is(rec2.ok, true, 'threshold met from honest holders')
  t.absent(rec2.collected.find(c => shardHash(c.bytes) !== normalizeShardAddress(c.shard)), 'every collected share content-verified')

  // announce topic is a deterministic 32-byte topic derived from the hash
  const topic = shardAnnounceTopicTest(manifest[0].shard)
  t.is(topic.length, 64)
})

function shardAnnounceTopicTest (addr) {
  return b4a.toString(shardAnnounceTopic(addr), 'hex')
}

test('shard-store service: metrics lines are aggregate (no per-hash labels) (M5)', async (t) => {
  const { store } = await tmpStore(t)
  const pinner = keyPair(50)
  const svc = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => true, keyPair: keyPair(51) })
  await svc.start({ store })
  t.teardown(() => svc.stop())

  const sealed = b4a.from('metered-share', 'utf8'); const hash = shardHash(sealed)
  await svc.put({ ciphertext: b4a.toString(sealed, 'base64'), pin: paymentPin(hash, pinner) })
  await svc.get({ shard: 'shard:' + hash })
  const lines = (await svc.metricsLines()).join('\n')
  t.ok(lines.includes('hiverelay_shards_held 1'))
  t.ok(lines.includes('hiverelay_shard_put_total 1'))
  t.ok(lines.includes('hiverelay_shard_get_total 1'))
  t.absent(lines.includes(hash), 'no per-hash labels leak')
})

test('shard-store http bridge: PUT/GET/HEAD/prove round-trip (M5)', async (t) => {
  const { store } = await tmpStore(t)
  const relay = keyPair(52)
  const pinner = keyPair(53)
  const svc = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => true, keyPair: relay })
  await svc.start({ store })
  t.teardown(() => svc.stop())

  const sealed = b4a.from('http-share-bytes', 'utf8')
  const hash = shardHash(sealed)

  // PUT
  const putRes = await httpCall(svc, 'POST', '/api/v1/shard', sealed, { 'x-shard-pin': JSON.stringify(paymentPin(hash, pinner)) })
  t.is(putRes.status, 201)
  t.is(putRes.json.shard, 'shard:' + hash)

  // HEAD present
  const headRes = await httpCall(svc, 'HEAD', '/api/v1/shard/' + hash)
  t.is(headRes.status, 200)
  t.is(headRes.headers['Content-Length'], String(sealed.byteLength))

  // GET with nonce -> octet-stream body + proof header
  const nonce = '5'.repeat(64)
  const getRes = await httpCall(svc, 'GET', '/api/v1/shard/' + hash + '?nonce=' + nonce)
  t.is(getRes.status, 200)
  t.ok(b4a.equals(getRes.body, sealed), 'raw ciphertext returned')
  const proof = JSON.parse(getRes.headers['X-Shard-Proof'])
  t.ok(verifyShardProof(proof, { hash, nonce, relayPubkey: relay.hex, bytes: getRes.body }))

  // prove
  const proveRes = await httpCall(svc, 'POST', '/api/v1/shard/' + hash + '/prove', b4a.from(JSON.stringify({ nonce })))
  t.is(proveRes.status, 200)
  t.is(proveRes.json.proof.mode, 'A')

  // unknown hash -> 404 (indistinguishable)
  const missRes = await httpCall(svc, 'HEAD', '/api/v1/shard/' + 'e'.repeat(64))
  t.is(missRes.status, 404)
})

// ─── STO-002: ref-count reconciliation + concurrent dedup/sweep ────────

test('STO-002: sweep does not delete bytes a live (unexpired) pin still references', async (t) => {
  const { store } = await tmpStore(t)
  let now = NOW
  const relay = keyPair(60)
  const pinner = keyPair(61)
  const svc = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => true, keyPair: relay, clock: () => now })
  await svc.start({ store })
  t.teardown(() => svc.stop())

  const sealed = b4a.from('shared-ciphertext-blob', 'utf8')
  const hash = shardHash(sealed)
  const b64 = b4a.toString(sealed, 'base64')

  // Two pins on the SAME bytes -> engine dedup refs = 2, two pins.
  // One expires early, one is long-lived (a live index generation).
  const shortPin = signShardPin({ reason: 'payment', hash, retainUntil: NOW + 1000, nonce: 'aa'.repeat(16) }, pinner)
  const longPin = signShardPin({ reason: 'payment', hash, retainUntil: NOW + 3600000, nonce: 'bb'.repeat(16) }, pinner)
  await svc.put({ ciphertext: b64, pin: shortPin })
  const p2 = await svc.put({ ciphertext: b64, pin: longPin })
  t.is(p2.deduped, true, 'second put deduped the identical bytes')
  t.is(p2.refs, 2, 'two live pins')
  t.is(await svc.engine.refs(hash), 2, 'engine dedup ref-count tracks both puts')

  now = NOW + 2000 // short pin expired, long pin still live
  const swept = await svc.sweep()
  t.is(swept.swept, 0, 'nothing deleted — a live pin still references the bytes')
  t.is((await svc.has({ shard: 'shard:' + hash })).present, true, 'bytes retained (no custody data loss)')
  t.is(await svc.engine.refs(hash), 1, 'one engine ref reconciled away with the expired pin')

  // Now the long pin expires too -> both sources zero -> deleted.
  now = NOW + 3600001
  const swept2 = await svc.sweep()
  t.is(swept2.swept, 1, 'last pin gone -> bytes finally reclaimed')
  t.is((await svc.has({ shard: 'shard:' + hash })).present, false, 'bytes gone once BOTH sources are zero')
})

test('STO-002: a concurrent dedup PUT racing a sweep does not lose the shard', async (t) => {
  const { store } = await tmpStore(t)
  let now = NOW
  const relay = keyPair(62)
  const pinner = keyPair(63)
  const svc = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => true, keyPair: relay, clock: () => now })
  await svc.start({ store })
  t.teardown(() => svc.stop())

  const sealed = b4a.from('race-ciphertext', 'utf8')
  const hash = shardHash(sealed)
  const b64 = b4a.toString(sealed, 'base64')

  // Seed with a single short-lived pin.
  const shortPin = signShardPin({ reason: 'payment', hash, retainUntil: NOW + 1000, nonce: 'cc'.repeat(16) }, pinner)
  await svc.put({ ciphertext: b64, pin: shortPin })

  now = NOW + 2000 // the seed pin is now expired -> sweep would GC it...
  // ...but a fresh dedup PUT (new live pin) fires concurrently. The engine's
  // per-hash lock serializes the two so the new reference is never wiped.
  const freshPin = signShardPin({ reason: 'payment', hash, retainUntil: NOW + 3600000, nonce: 'dd'.repeat(16) }, pinner)
  const [sweptRes] = await Promise.all([
    svc.sweep(),
    svc.put({ ciphertext: b64, pin: freshPin })
  ])

  // Regardless of interleaving, the shard the concurrent PUT re-referenced
  // must still be held. (sweep may report 0 or 1 depending on order, but the
  // bytes+the fresh live pin must survive.)
  t.is((await svc.has({ shard: 'shard:' + hash })).present, true, 'concurrent dedup PUT preserved the shard')
  t.is(svc.pins.refs(hash, now), 1, 'the fresh live pin survived the race')
  t.ok(sweptRes.ok)
  // And the bytes are actually retrievable (not a dangling index row).
  const got = await svc.get({ shard: 'shard:' + hash })
  t.ok(b4a.equals(b4a.from(got.ciphertext, 'base64'), sealed), 'bytes intact after the race')
})

// ─── STO-005: shard bytes accounted + disk-pressure eviction ───────────

test('STO-005: shard bytes register with StorageAccounting and update on GC', async (t) => {
  const { store } = await tmpStore(t)
  const { StorageAccounting } = await import('../../packages/core/core/relay-node/storage-accounting.js')
  const acc = new StorageAccounting({ appRegistry: { keys: () => [].values() } })
  const pinner = keyPair(64)
  const svc = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => true, keyPair: keyPair(65), storageAccounting: acc })
  await svc.start({ store })
  t.teardown(() => svc.stop())

  t.is(acc.getSummary().sourceBytes, 0, 'no shard bytes yet')
  const sealed = b4a.from('accounted-share-bytes', 'utf8')
  const hash = shardHash(sealed)
  const put = await svc.put({ ciphertext: b4a.toString(sealed, 'base64'), pin: paymentPin(hash, pinner) })
  t.is(acc.getSummary().sourceBytes, put.byteLength, 'shard bytes now visible to StorageAccounting')
  t.ok(acc.getSummary().totalBytes >= put.byteLength, 'folded into the authoritative total')

  // GC via unpin drops the bytes back out of accounting.
  const removal = paymentPin(hash, pinner, 'f'.repeat(32))
  await svc.unpin({ shard: 'shard:' + hash, pinRef: put.pinRef, removal })
  t.is(acc.getSummary().sourceBytes, 0, 'accounting reflects reclaimed bytes')
})

test('STO-005: disk-pressure eviction sheds expired shards but never a still-valid retainUntil pin', async (t) => {
  const { store } = await tmpStore(t)
  let now = NOW
  const relay = keyPair(66)
  const pinner = keyPair(67)
  const svc = new ShardStoreService({ putAuth: ['payment'], checkPaymentQuota: () => true, keyPair: relay, clock: () => now })
  await svc.start({ store })
  t.teardown(() => svc.stop())

  const expiredBytes = b4a.from('expired-under-pressure', 'utf8')
  const validBytes = b4a.from('still-valid-under-pressure', 'utf8')
  const expiredHash = shardHash(expiredBytes)
  const validHash = shardHash(validBytes)

  const expiredPin = signShardPin({ reason: 'payment', hash: expiredHash, retainUntil: NOW + 1000, nonce: '11'.repeat(16) }, pinner)
  const validPin = signShardPin({ reason: 'payment', hash: validHash, retainUntil: NOW + 3600000, nonce: '22'.repeat(16) }, pinner)
  await svc.put({ ciphertext: b4a.toString(expiredBytes, 'base64'), pin: expiredPin })
  await svc.put({ ciphertext: b4a.toString(validBytes, 'base64'), pin: validPin })

  now = NOW + 2000 // the expired pin is now past retainUntil; the valid one is not.

  // Below the hard ceiling: expired shard is evicted, the still-valid pin's
  // retainUntil floor is honored (NOT evicted) even though we are under pressure.
  const res = await svc.evictUnderPressure({ usedPct: 90, diskPressurePct: 85, hardCeilingPct: 97 })
  t.is(res.expiredEvicted, 1, 'expired shard evicted under pressure')
  t.is(res.forcedEvicted, 0, 'no still-valid pin touched below the hard ceiling')
  t.is((await svc.has({ shard: 'shard:' + expiredHash })).present, false, 'expired shard gone')
  t.is((await svc.has({ shard: 'shard:' + validHash })).present, true, 'still-valid retainUntil pin retained (floor honored)')

  // Below the pressure gate: no-op.
  const calm = await svc.evictUnderPressure({ usedPct: 50, diskPressurePct: 85 })
  t.is(calm.skipped, 'below-pressure')
  t.is((await svc.has({ shard: 'shard:' + validHash })).present, true, 'still held on a calm disk')

  // At the hard ceiling: a truly full box may claw back even the valid pin.
  const full = await svc.evictUnderPressure({ usedPct: 98, diskPressurePct: 85, hardCeilingPct: 97 })
  t.is(full.forcedEvicted, 1, 'hard ceiling sheds the lowest-priority still-valid pin')
  t.is((await svc.has({ shard: 'shard:' + validHash })).present, false, 'valid pin evicted only at the hard ceiling')
})

// Minimal HTTP req/res harness driving the shard adapter.
async function httpCall (svc, method, path, body = null, headers = {}) {
  const { EventEmitter } = await import('node:events')
  const { resolveShardRoute, handleShardHttp } = await import('../../packages/services/builtin/shard-store/http-adapter.js')
  const req = new EventEmitter()
  req.method = method
  req.headers = headers
  const res = {
    _status: null,
    _headers: {},
    _chunks: [],
    writeHead (s, h) { this._status = s; if (h) Object.assign(this._headers, h) },
    end (c) { if (c != null) this._chunks.push(b4a.isBuffer(c) ? c : b4a.from(c)); this._done = true }
  }
  const route = resolveShardRoute(method, path)
  if (!route) return { status: 404, json: null }
  const url = { searchParams: new URLSearchParams(path.split('?')[1] || '') }
  const p = handleShardHttp(svc, route, req, res, { url })
  if (body != null) { req.emit('data', b4a.isBuffer(body) ? body : b4a.from(body)) }
  req.emit('end')
  await p
  const raw = b4a.concat(res._chunks)
  const out = { status: res._status, headers: res._headers, body: raw }
  try { out.json = JSON.parse(b4a.toString(raw, 'utf8')) } catch { out.json = null }
  return out
}
