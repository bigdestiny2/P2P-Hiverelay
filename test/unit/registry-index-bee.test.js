// registry-index-bee: v0.8.26 regression tests for the SeedingRegistry
// Hyperbee indexed-views sidecar.
//
// The sidecar mirrors _applyEntry output to a sibling Hypercore so
// startup hydration doesn't need to replay every log block. Logs
// remain canonical; bee is a cache.

import test from 'brittle'
import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import Corestore from 'corestore'
import createTestnet from '@hyperswarm/testnet'
import Hyperswarm from 'hyperswarm'
import { SeedingRegistry } from 'p2p-hiverelay/core/registry/index.js'
import { createCustodyIntent } from 'p2p-hiverelay/core/custody-signing.js'
import b4a from 'b4a'
import sodium from 'sodium-universal'

function newKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

async function freshSetup () {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-reg-idx-'))
  const testnet = await createTestnet(2)
  return { dir, testnet }
}

async function makeRegistry (dir, testnet) {
  const store = new Corestore(dir)
  await store.ready()
  const swarm = new Hyperswarm({ bootstrap: testnet.bootstrap })
  const reg = new SeedingRegistry(store, swarm)
  await reg.start()
  return { reg, store, swarm }
}

// closeRelay shuts down a registry + swarm + store + testnet but
// DOES NOT remove the storage dir. Use rmDir at end-of-test for cleanup.
async function closeRelay ({ reg, store, swarm, testnet }) {
  try { await reg.stop() } catch (_) {}
  try { await swarm.destroy() } catch (_) {}
  try { await store.close() } catch (_) {}
  try { await testnet.destroy() } catch (_) {}
}

async function rmDir (dir) {
  try { await rm(dir, { recursive: true, force: true }) } catch (_) {}
}

test('index bee: populated by _applyEntry; survives restart via hydration', async (t) => {
  const setup = await freshSetup()
  const { dir, testnet } = setup
  const publisherKey = newKeyPair()

  // Phase 1 — publish a custody intent
  const r1 = await makeRegistry(dir, testnet)
  const intent = createCustodyIntent({
    blindContentId: b4a.toString(b4a.alloc(32, 0x11), 'hex'),
    ciphertextRoot: b4a.toString(b4a.alloc(32, 0x22), 'hex'),
    requiredReplicas: 3,
    contentVersion: 1,
    deadline: Date.now() + 60_000,
    retainUntil: Date.now() + 3_600_000
  }, publisherKey)

  await r1.reg.publishCustodyIntent(intent, publisherKey)
  // Give the fire-and-forget index-bee write a chance to land
  await r1.reg._flushIndexBee()

  t.is(r1.reg._custodyIntents.size, 1, 'phase 1 — intent in memory')
  await closeRelay({ ...r1, testnet })

  // Phase 2 — fresh registry on same corestore. The bee should hydrate
  // the intent before the log replay catches up.
  const testnet2 = await createTestnet(2)
  const r2 = await makeRegistry(dir, testnet2)
  t.is(r2.reg._custodyIntents.size, 1, 'phase 2 — intent restored from bee or log')
  const got = r2.reg.getCustodyIntent(intent.intentId)
  t.ok(got, 'intent looked up by intentId')
  t.is(got.intentId, intent.intentId)

  await closeRelay({ ...r2, testnet: testnet2 })
  await rmDir(dir)
})

test('index bee: _entryKey returns a stable composite key per type', (t) => {
  // Direct unit test of the key-derivation helper. Skips registry start.
  const reg = new SeedingRegistry({ get: () => null, ready: async () => {} }, null)

  t.is(reg._entryKey({ type: 'seed-request', appKey: 'aa' }), 'entry:seed-request:aa')
  t.is(
    reg._entryKey({ type: 'seed-accept', appKey: 'aa', relayPubkey: 'rr' }),
    'entry:seed-accept:aa:rr'
  )
  t.is(reg._entryKey({ type: 'custody-intent', intentId: 'ii' }), 'entry:custody-intent:ii')
  t.is(
    reg._entryKey({ type: 'custody-receipt', intentId: 'ii', relayPubkey: 'rr' }),
    'entry:custody-receipt:ii:rr'
  )
  t.is(
    reg._entryKey({ type: 'custody-proof', intentId: 'ii', observerPubkey: 'oo', relayPubkey: 'rr', challengeNonce: 'nn' }),
    'entry:custody-proof:ii:oo:rr:nn'
  )
  t.is(reg._entryKey({ type: 'unknown-type' }), null, 'unknown types skipped')
  t.is(reg._entryKey({ type: 'seed-request' /* no appKey */ }), null, 'missing required id returns null')
  t.is(reg._entryKey(null), null, 'null entry')
})

test('index bee: hydration is idempotent — dedup via timestamp', async (t) => {
  // Hydrating + then replaying logs MUST not produce duplicates. The
  // _applyEntry timestamp check is the safety net.
  const setup = await freshSetup()
  const { dir, testnet } = setup
  const publisherKey = newKeyPair()

  const r1 = await makeRegistry(dir, testnet)
  const intent = createCustodyIntent({
    blindContentId: b4a.toString(b4a.alloc(32, 0x33), 'hex'),
    ciphertextRoot: b4a.toString(b4a.alloc(32, 0x44), 'hex'),
    requiredReplicas: 2,
    contentVersion: 1,
    deadline: Date.now() + 60_000,
    retainUntil: Date.now() + 3_600_000
  }, publisherKey)
  await r1.reg.publishCustodyIntent(intent, publisherKey)
  await r1.reg._flushIndexBee()
  await closeRelay({ ...r1, testnet })

  // Phase 2: hydration runs FIRST, then _indexLog replays the same
  // intent block. The replay's _applyEntry sees the same timestamp
  // and doesn't double-count.
  const testnet2 = await createTestnet(2)
  const r2 = await makeRegistry(dir, testnet2)
  t.is(r2.reg._custodyIntents.size, 1, 'single intent — no duplicate from log replay')

  await closeRelay({ ...r2, testnet: testnet2 })
  await rmDir(dir)
})

test('index bee: emits hydrated event on startup', async (t) => {
  const setup = await freshSetup()
  const { dir, testnet } = setup
  const publisherKey = newKeyPair()

  // Phase 1 — seed some state
  const r1 = await makeRegistry(dir, testnet)
  await r1.reg.publishCustodyIntent(createCustodyIntent({
    blindContentId: b4a.toString(b4a.alloc(32, 0x55), 'hex'),
    ciphertextRoot: b4a.toString(b4a.alloc(32, 0x66), 'hex'),
    requiredReplicas: 3,
    contentVersion: 2,
    deadline: Date.now() + 60_000,
    retainUntil: Date.now() + 3_600_000
  }, publisherKey), publisherKey)
  await r1.reg._flushIndexBee()
  await closeRelay({ ...r1, testnet })

  // Phase 2 — fresh registry; attach a listener for the 'hydrated' event
  const testnet2 = await createTestnet(2)
  const store = new Corestore(dir)
  await store.ready()
  const swarm = new Hyperswarm({ bootstrap: testnet2.bootstrap })
  const reg = new SeedingRegistry(store, swarm)
  let hydratedEvent = null
  reg.on('hydrated', (e) => { hydratedEvent = e })
  await reg.start()

  t.ok(hydratedEvent, 'hydrated event fired during start()')
  t.is(hydratedEvent.source, 'index-bee')
  t.ok(hydratedEvent.count >= 1, 'at least one entry hydrated')

  await closeRelay({ reg, store, swarm, testnet: testnet2 })
  await rmDir(dir)
})
