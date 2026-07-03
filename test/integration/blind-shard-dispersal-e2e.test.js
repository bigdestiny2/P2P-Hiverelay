/**
 * BETA 1.0 PROOF — blind custody over the real shard store.
 *
 * A dealer PVSS-splits a secret (e.g. a public app's content key) into n shares
 * and disperses each as an opaque shard to a DISTINCT relay's real
 * ShardStoreService, authorized by a signed custody pin. Then:
 *
 *   - each relay holds exactly ONE opaque, content-addressed shard;
 *   - NO SINGLE relay (and no k-1 colluding relays) can reconstruct the secret;
 *   - ANY k relays let a reader reconstruct the exact secret at its edge.
 *
 * This exercises the actual relay authorization path (authorizeShardPin against
 * a custody assignment) + content-addressed storage + the client blind-shard
 * codec + PVSS reconstruction — end to end, no mocks of the crypto or store.
 */
import test from 'brittle'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Corestore from 'corestore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ShardStoreService, signShardPin, normalizeShardAddress
} from '../../packages/services/builtin/shard-store/index.js'
import {
  disperseSecret, recoverSecret, shardAddressOf
} from '../../packages/client/blind-shards.js'

function keyPair (seed) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seed))
  return { publicKey, secretKey, hex: b4a.toString(publicKey, 'hex') }
}

async function tmpStore (t) {
  const dir = await mkdtemp(join(tmpdir(), 'blind-shard-e2e-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const store = new Corestore(dir)
  t.teardown(() => store.close())
  return store
}

// One relay = a real ShardStoreService. Its custody resolver returns whatever
// share the dealer is assigning it right now (set just-in-time in put()), i.e.
// the relay authorizes exactly the one blob the signed manifest binds to it.
async function makeRelay (t, seed) {
  const store = await tmpStore(t)
  const kp = keyPair(seed)
  const relay = { kp, assigned: null, svc: null }
  relay.svc = new ShardStoreService({
    putAuth: ['custody'],
    resolveCustodyAssignment: async () => relay.assigned
  })
  await relay.svc.start({ store, node: { keyPair: kp } })
  t.teardown(() => relay.svc.stop())
  return relay
}

const INTENT_ID = 'a1b2'.repeat(16) // 64-hex custody intent id
const nonceFor = (i) => i.toString(16).padStart(32, '0')

// The dealer's PUT: bind the share to its assigned relay, sign a custody pin,
// and store it through the relay's REAL put() (which verifies the pin).
function dealerPut (relays, dealerKp) {
  return async (bytes, { shareIndex }) => {
    const address = shardAddressOf(bytes)
    const hash = normalizeShardAddress(address)
    const relay = relays[shareIndex - 1]
    relay.assigned = { shareIndex, shard: address }
    const pin = signShardPin({
      reason: 'custody',
      hash,
      custodyIntentId: INTENT_ID,
      shareIndex,
      retainUntil: Date.now() + 3600000,
      nonce: nonceFor(shareIndex)
    }, dealerKp)
    const res = await relay.svc.put({ ciphertext: b4a.toString(bytes, 'base64'), pin })
    return res.shard
  }
}

// A reader's fetch limited to a subset of relays (models "only these answer").
function readerFetch (relaySubset) {
  return async (address) => {
    const hash = normalizeShardAddress(address)
    for (const relay of relaySubset) {
      try {
        const has = await relay.svc.has({ hash })
        if (has && has.present) {
          const got = await relay.svc.get({ hash })
          return b4a.from(got.ciphertext, 'base64')
        }
      } catch { /* relay doesn't hold it */ }
    }
    return null
  }
}

test('blind custody E2E: 3-of-5 dispersal, no single relay reconstructs, reader rebuilds', async (t) => {
  const relays = []
  for (let i = 1; i <= 5; i++) relays.push(await makeRelay(t, i))
  const dealer = keyPair(200)

  // 1. Dealer disperses a secret across the 5 real relays.
  const dispersed = await disperseSecret({ count: 5, threshold: 3, put: dealerPut(relays, dealer) })
  t.is(dispersed.shareManifest.length, 5)

  // 2. Each relay holds exactly ONE opaque shard (placement: none has >= k).
  for (let i = 0; i < relays.length; i++) {
    let held = 0
    for (const entry of dispersed.shareManifest) {
      const has = await relays[i].svc.has({ hash: normalizeShardAddress(entry.shard) })
      if (has && has.present) held++
    }
    t.is(held, 1, 'relay ' + (i + 1) + ' holds exactly one of the five shards')
  }

  // 3. INVARIANT — a single relay cannot reconstruct.
  const one = await recoverSecret({ shareManifest: dispersed.shareManifest, threshold: 3, fetch: readerFetch([relays[0]]) })
  t.is(one.ok, false, 'one relay: not enough')
  t.is(one.collected, 1)

  // 4. INVARIANT — k-1 colluding relays still cannot reconstruct.
  const collude = await recoverSecret({ shareManifest: dispersed.shareManifest, threshold: 3, fetch: readerFetch([relays[0], relays[1]]) })
  t.is(collude.ok, false, 'two relays: still not enough')

  // 5. A reader gathering ANY k relays reconstructs the exact secret at the edge.
  const reader = await recoverSecret({
    shareManifest: dispersed.shareManifest,
    threshold: 3,
    fetch: readerFetch([relays[1], relays[3], relays[4]]) // shares 2,4,5
  })
  t.is(reader.ok, true, 'any 3 relays: reconstructs')
  t.is(reader.key, dispersed.key, 'reader recovers the dealer-private key — no relay ever held it')
  t.is(reader.secretPoint, dispersed.secretPoint)

  // 6. A reader with all relays available also works (and still stops at k).
  const full = await recoverSecret({ shareManifest: dispersed.shareManifest, threshold: 3, fetch: readerFetch(relays) })
  t.is(full.ok, true)
  t.is(full.key, dispersed.key)
})

test('relay rejects a custody pin it was not assigned', async (t) => {
  const relay = await makeRelay(t, 42)
  const dealer = keyPair(201)
  const bytes = b4a.from('an-opaque-share-blob', 'utf8')
  const address = shardAddressOf(bytes)
  const hash = normalizeShardAddress(address)

  // relay is assigned share 3 -> this hash
  relay.assigned = { shareIndex: 3, shard: address }

  // a pin claiming share 4 (not this relay's assignment) must be refused
  const wrongIndexPin = signShardPin({
    reason: 'custody',
    hash,
    custodyIntentId: INTENT_ID,
    shareIndex: 4,
    retainUntil: Date.now() + 3600000,
    nonce: nonceFor(99)
  }, dealer)
  await t.exception(
    relay.svc.put({ ciphertext: b4a.toString(bytes, 'base64'), pin: wrongIndexPin }),
    /UNAUTHORIZED_PIN/
  )

  // the correctly-assigned pin is accepted
  const okPin = signShardPin({
    reason: 'custody',
    hash,
    custodyIntentId: INTENT_ID,
    shareIndex: 3,
    retainUntil: Date.now() + 3600000,
    nonce: nonceFor(3)
  }, dealer)
  const res = await relay.svc.put({ ciphertext: b4a.toString(bytes, 'base64'), pin: okPin })
  t.is(res.shard, address)
})
