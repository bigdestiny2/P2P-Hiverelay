import test from 'brittle'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Corestore from 'corestore'
import b4a from 'b4a'
import { ShardStoreService, ShardEngine, shardHash, normalizeShardAddress } from '../../packages/services/builtin/shard-store/index.js'

async function tmpStore (t) {
  const dir = await mkdtemp(join(tmpdir(), 'shard-store-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const store = new Corestore(dir)
  t.teardown(() => store.close())
  return { store, dir }
}

const bytes = (s) => b4a.from(s, 'utf8')

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

test('shard-store service: put/get/has/unpin over the RPC surface (base64)', async (t) => {
  const { store } = await tmpStore(t)
  const svc = new ShardStoreService()
  await svc.start({ store })
  t.teardown(() => svc.stop())

  const plaintextSealedByCaller = b4a.from('sealed-shard-3', 'utf8')
  const b64 = b4a.toString(plaintextSealedByCaller, 'base64')

  const put = await svc.put({ ciphertext: b64 })
  t.is(put.ok, true)
  t.is(put.shard, 'shard:' + shardHash(plaintextSealedByCaller))

  const has = await svc.has({ shard: put.shard })
  t.is(has.present, true)
  t.is(has.byteLength, plaintextSealedByCaller.byteLength)

  const got = await svc.get({ shard: put.shard })
  t.is(got.encoding, 'base64')
  t.ok(b4a.equals(b4a.from(got.ciphertext, 'base64'), plaintextSealedByCaller), 'round-trips through base64')

  const absent = await svc.has({ shard: 'shard:' + 'c'.repeat(64) })
  t.is(absent.present, false)

  const un = await svc.unpin({ shard: put.shard })
  t.is(un.removed, true)
  await t.exception(svc.get({ shard: put.shard }), /NOT_HELD/)
})

test('shard-store service: manifest advertises the content-addressed surface', async (t) => {
  const svc = new ShardStoreService({ maxShardBytes: 1024 })
  const m = svc.manifest()
  t.is(m.name, 'shard-store')
  t.alike(m.capabilities, ['put', 'get', 'has', 'unpin'])
  t.is(m.addressing, 'blake2b-256-ciphertext')
  t.is(m.limits.maxShardBytes, 1024)
  t.ok(normalizeShardAddress('shard:' + 'a'.repeat(64)))
  t.absent(normalizeShardAddress('shard:xyz'))
})
