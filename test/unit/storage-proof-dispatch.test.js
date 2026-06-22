/**
 * Storage-proof LIVE-PATH smoke — through the REAL Router + ServiceRegistry.
 *
 * The unit tests call StorageProofService.prove() directly; this exercises the
 * actual relay-side dispatch path a client request takes:
 *   client.callService -> ServiceProtocol (JSON over Protomux) -> router.dispatch
 *     ('storage-proof.prove', params, context) -> provider.prove -> JSON result.
 *
 * It proves the parts the direct unit tests skip: (1) registerFromRegistry binds
 * provider.prove to the route, (2) the 'public' ROUTE_ACCESS_POLICIES entry
 * actually admits an ANONYMOUS caller (no role / not authenticated), (3) the
 * proof object survives the JSON wire encoding the ServiceProtocol uses, and
 * (4) the privacy gate fires through the real dispatch path. The Protomux socket
 * layer itself is shared with poker/subscribe (already live on the fleet).
 */
import test from 'brittle'
import Hypercore from 'hypercore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import os from 'os'
import path from 'path'
import { Router } from 'p2p-hiverelay/core/router/index.js'
import { ServiceRegistry } from 'p2p-hiverelay/core/services/index.js'
import { StorageProofService } from 'p2p-hiveservices/builtin/storage-proof-service.js'
import { verifyStorageProof } from 'p2p-hiverelay/core/protocol/proof-of-storage.js'

let _n = 0
const tmp = () => path.join(os.tmpdir(), 'hr-spd-' + process.pid + '-' + (_n++))
function relayKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}
const freshNonce = () => { const n = b4a.alloc(32); sodium.randombytes_buf(n); return n }

function mockNode (core, keyPair, opts = {}) {
  const keyHex = b4a.toString(core.key, 'hex')
  const entry = { drive: { core, db: { core }, closed: false, closing: false }, blind: opts.blind === true, privacyTier: 'public' }
  return {
    keyPair,
    appRegistry: {
      has: (k) => k === keyHex,
      get: (k) => (k === keyHex ? entry : null),
      _shouldRedactEntry: (e, o = {}) => e.blind === true
    }
  }
}

async function setup (opts = {}) {
  const core = new Hypercore(tmp())
  await core.ready()
  await core.append([b4a.from('m0'), b4a.from('m1'), b4a.from('m2'), b4a.from('m3')])
  const relay = relayKeyPair()
  const registry = new ServiceRegistry()
  registry.register(new StorageProofService())
  await registry.startAll({ node: mockNode(core, relay, opts), store: null, config: {} })
  const router = new Router()
  router.registerFromRegistry(registry)
  await router.start()
  return { core, relay, router }
}

test('dispatch: ANONYMOUS caller gets a proof via the real Router (public access) + JSON wire verifies', async (t) => {
  const { core, relay, router } = await setup()
  const nonce = freshNonce()
  // Anonymous context — no role, no remotePubkey, not authenticated. If the
  // route weren't 'public', router.dispatch would throw ACCESS_DENIED here.
  const result = await router.dispatch('storage-proof.prove',
    { coreKey: b4a.toString(core.key, 'hex'), index: 2, nonce: b4a.toString(nonce, 'hex') },
    {})

  // The real transport is JSON over Protomux (services/protocol.js) — round-trip
  // the result the same way the wire does, then verify it stands on its own.
  const onWire = JSON.parse(JSON.stringify(result))
  const verifier = new Hypercore(tmp(), core.key)
  await verifier.ready()
  const v = await verifyStorageProof({
    verifierCore: verifier,
    response: onWire,
    expect: { driveKey: core.key, index: 2, nonce, relayPubkey: relay.publicKey, minLength: core.length }
  })
  t.ok(v.valid, 'proof routed through the real Router, survived JSON, and verified')
  t.is(v.reason, null)
  await verifier.close(); await core.close()
  if (typeof router.stop === 'function') await router.stop()
})

test('dispatch: privacy gate fires through the real Router (blind => NOT_SEEDED)', async (t) => {
  const { core, router } = await setup({ blind: true })
  await t.exception(
    router.dispatch('storage-proof.prove',
      { coreKey: b4a.toString(core.key, 'hex'), index: 0, nonce: b4a.toString(freshNonce(), 'hex') }, {}),
    /NOT_SEEDED/
  )
  await core.close()
  if (typeof router.stop === 'function') await router.stop()
})

test('dispatch: a bad nonce is rejected through the real Router', async (t) => {
  const { core, router } = await setup()
  await t.exception(
    router.dispatch('storage-proof.prove',
      { coreKey: b4a.toString(core.key, 'hex'), index: 0, nonce: 'not-a-hex-nonce' }, {}),
    /BAD_NONCE/
  )
  await core.close()
  if (typeof router.stop === 'function') await router.stop()
})
