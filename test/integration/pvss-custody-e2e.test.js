/**
 * End-to-end PVSS blind-custody integration test — the REAL dealer→relay path.
 *
 * Unlike test/unit/custody-orchestration.test.js (which stubs
 * client.getCustodyStatus / _writeShareBundle / publishCustodyIntent so it
 * never touches a relay), this drives the genuine wire flow against a live
 * in-process RelayNode over its HTTP API + Hyperswarm data plane:
 *
 *   client.splitForCustody()
 *     → _pvssSplit (secret-sharing.js)
 *     → _writeShareBundle  (serves the PUBLIC bundle on a sibling hypercore)
 *     → publishCustodyIntent  (HTTP POST /api/custody/intent, Bearer auth)
 *     → _seedForCustody       (HTTP POST /seed, Bearer auth)  ← the load-bearing
 *         relay: seedApp → replicate content → _recordCustodyReceipt
 *           → _readShareBundle (replicates the bundle off the client)
 *           → verifyShareBundleForRelay (PUBLIC DLEQ verify, no decryption)
 *           → recordCustodyReceipt (anchored:true, shareVerified:true)
 *     → _awaitVerifiedReceipts (HTTP GET /api/custody/:id/status, public+redacted)
 *     → publishCustodyCommit   (HTTP POST /api/custody/:id/commit, Bearer auth)
 *   client.reconstructFromCustody()  ← recovers the dealer key from the
 *     GUARDIAN secret alone; the relay never held that key.
 *
 * This is the test that catches the two integration seams the unit suite
 * couldn't: (1) the public custody-status redaction must surface receipts[]
 * for the dealer poll, and (2) splitForCustody must actually trigger a seed so
 * a receipt is ever produced. Both were silently broken before.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import b4a from 'b4a'
import { randomBytes } from 'crypto'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { HiveRelayClient } from 'p2p-hiverelay-client'
import { keygen } from 'p2p-hiverelay-client/secret-sharing.js'

// @hyperswarm/testnet teardown race: destroying the testnet DHT while a swarm
// still has an in-flight announce/lookup query in its commit phase throws an
// uncaught "Node destroyed" / "Request destroyed" from dht-rpc — AFTER every
// assertion has already run. It is a harness artifact (nothing yanks the DHT
// out from under a live announce in production), so swallow ONLY those exact
// teardown signatures; anything else still crashes the run.
function isBenignDhtTeardown (err) {
  const s = (err && (err.message || err.code)) || ''
  return /Node destroyed|REQUEST_DESTROYED|Request destroyed|IO_SUSPENDED|Node was destroyed/i.test(String(s))
}
// Non-benign errors must still fail the run, but re-throwing inside these
// handlers risks recursion — log + exit(1) instead. (When run as part of the
// full `test:integration` glob, test/integration/zz-finalize.test.js force-
// exits 0 after all tests, so a clean run never reaches a non-zero exit here.)
process.on('uncaughtException', (err) => {
  if (isBenignDhtTeardown(err)) return
  console.error(err)
  process.exit(1)
})
process.on('unhandledRejection', (err) => {
  if (isBenignDhtTeardown(err)) return
  console.error(err)
  process.exit(1)
})

async function bringUp (t, baseDir, testnet) {
  const API_KEY = 'pvss-e2e-' + randomBytes(8).toString('hex')

  // One custody relay with the HTTP management API enabled.
  const relay = new RelayNode({
    storage: join(baseDir, 'relay'),
    bootstrapNodes: testnet.bootstrap,
    enableAPI: true,
    apiPort: 0, // ephemeral; read back via relay.api.server.address()
    apiHost: '127.0.0.1',
    apiKey: API_KEY,
    enableSeeding: true,
    enableNetworkDiscovery: false,
    enableHolesail: false,
    gatewayServeBlind: false
  })
  await relay.start()
  const relayPort = relay.api.server.address().port
  const relayUrl = 'http://127.0.0.1:' + relayPort
  const relayPubkey = b4a.toString(relay.swarm.keyPair.publicKey, 'hex')

  // Dealer client on the same testnet. autoSeed:false so we control exactly
  // when (and how) the addressKey first gets seeded.
  const client = new HiveRelayClient({
    storage: join(baseDir, 'client'),
    bootstrap: testnet.bootstrap,
    autoSeed: false,
    autoDiscover: false
  })
  await client.start()

  return { relay, client, relayUrl, relayPubkey, API_KEY }
}

test('e2e PVSS custody: clean first-seed → share-verified receipt → commit → guardian reconstruct', async (t) => {
  const id = randomBytes(4).toString('hex')
  const baseDir = join(tmpdir(), 'hiverelay-pvss-e2e-' + id)
  const testnet = await createTestnet(3)
  await mkdir(baseDir, { recursive: true })

  const { relay, client, relayUrl, relayPubkey, API_KEY } = await bringUp(t, baseDir, testnet)

  t.teardown(async () => {
    try { await client.destroy() } catch {}
    try { await relay.stop() } catch {}
    try { await testnet.destroy() } catch {}
    try { await rm(baseDir, { recursive: true, force: true }) } catch {}
  })

  // Publish a content drive but DON'T auto-seed it onto the relay — publish
  // still serves the drive on the swarm, so when splitForCustody's /seed makes
  // the relay seed it, the relay replicates it from us. This exercises the
  // clean first-seed receipt path (_seedAppInner → _recordCustodyReceipt).
  const drive = await client.publish([
    { path: '/index.html', content: '<h1>secret-bound app ' + id + '</h1>' },
    { path: '/app.js', content: 'export const build = "' + id + '"\n' }
  ], { seed: false })
  const appKey = b4a.toString(drive.key, 'hex')

  // One guardian, t = 1 of n = 1. The guardian's SECRET key never leaves the
  // dealer; the relay only ever sees the guardian's PUBLIC key (inside the
  // encrypted share it cannot open).
  const g = await keygen()

  const res = await client.splitForCustody({
    guardians: [g.publicKey],
    threshold: 1,
    relays: [{ url: relayUrl, pubkey: relayPubkey }],
    appKey,
    opts: { apiKey: API_KEY, pollIntervalMs: 500, pollTimeoutMs: 90_000 }
  })

  // ─── Dealer-side outcome ───
  t.ok(/^[0-9a-f]{64}$/.test(res.intentId), 'intentId assigned')
  t.ok(/^[0-9a-f]{64}$/.test(res.key), 'dealer key returned (64-hex)')
  t.ok(/^[0-9a-f]{64}$/.test(res.shareBundleKey), 'share bundle key returned')
  t.is(res.receipts.length, 1, 'one share-verified receipt reached quorum')
  t.is(res.receipts[0].relayPubkey, relayPubkey, 'receipt is from our relay')
  t.is(res.receipts[0].shareVerified, true, 'relay PUBLICLY verified its assigned share')
  t.is(res.receipts[0].anchored, true, 'receipt anchored')
  t.ok(res.commit && res.commit.signature, 'quorum commit signed')

  // ─── Relay-side reality: it anchored a real v2 PVSS receipt ───
  const status = relay.seedingRegistry.getCustodyStatus(res.intentId)
  t.is(status.receiptCount, 1, 'relay registry holds exactly one receipt')
  const relayReceipt = status.receipts[0]
  t.is(relayReceipt.shareVerified, true, 'stored receipt records public share verification')
  t.is(relayReceipt.version, 2, 'stored receipt is v2 (PVSS)')
  t.ok(/^0[23][0-9a-f]{64}$/.test(relayReceipt.shareCommitment), 'stored receipt carries a compressed share-commitment point')

  // ─── Blindness: the dealer key never reaches the relay ───
  // The relay holds only the OPAQUE guardian-encrypted share (in the public
  // bundle) plus the public commitments it verified against — it has neither
  // the guardian secret key nor the reconstructed secret. Proven concretely:
  // the dealer key string appears nowhere in the relay's entire custody state.
  const relayStateJson = JSON.stringify(status)
  t.absent(relayStateJson.includes(res.key), 'dealer key never appears in relay custody state')
  t.absent(relayStateJson.includes(res.secretPoint), 'secret point never appears in relay custody state')

  // ─── Recovery: the guardian secret alone reconstructs the exact key ───
  const recovered = await client.reconstructFromCustody({
    intentId: res.intentId,
    guardianSecretKeys: [g.secretKey],
    shareBundleKey: res.shareBundleKey,
    threshold: 1
  })
  t.is(recovered.key, res.key, 'guardian reconstructs the exact dealer key')
  t.is(recovered.shares, 1, 'reconstructed from one decrypted share')
})

test('e2e PVSS custody: already-seeded re-pin still anchors a share receipt', async (t) => {
  const id = randomBytes(4).toString('hex')
  const baseDir = join(tmpdir(), 'hiverelay-pvss-repin-' + id)
  const testnet = await createTestnet(3)
  await mkdir(baseDir, { recursive: true })

  const { relay, client, relayUrl, relayPubkey, API_KEY } = await bringUp(t, baseDir, testnet)

  t.teardown(async () => {
    try { await client.destroy() } catch {}
    try { await relay.stop() } catch {}
    try { await testnet.destroy() } catch {}
    try { await rm(baseDir, { recursive: true, force: true }) } catch {}
  })

  const drive = await client.publish([
    { path: '/index.html', content: '<h1>repin app ' + id + '</h1>' }
  ], { seed: false })
  const appKey = b4a.toString(drive.key, 'hex')

  // Pre-seed the addressKey PLAINLY (no custody intent). This mirrors the
  // README happy path where client.publish() auto-seeds the content before
  // splitForCustody(): by the time custody seeds, the app is already in
  // seededApps and seedApp short-circuits ({ alreadySeeded:true }). Without
  // the _recordCustodyReceiptOnRepin fix, no PVSS receipt would ever anchor on
  // this path and the split below would time out.
  await client._postSeed(relayUrl, { appKey }, { apiKey: API_KEY })

  // Give the plain seed a moment to register the entry (seedApp returns the
  // discoveryKey synchronously once the drive is created + tracked).
  await new Promise(resolve => setTimeout(resolve, 250))
  t.ok(relay.appRegistry.has(appKey), 'addressKey is already seeded before custody')

  const g = await keygen()
  const res = await client.splitForCustody({
    guardians: [g.publicKey],
    threshold: 1,
    relays: [{ url: relayUrl, pubkey: relayPubkey }],
    appKey,
    opts: { apiKey: API_KEY, pollIntervalMs: 500, pollTimeoutMs: 90_000 }
  })

  t.is(res.receipts.length, 1, 're-pin custody path still reaches quorum')
  t.is(res.receipts[0].shareVerified, true, 'share verified on the already-seeded relay')
  t.is(res.receipts[0].anchored, true, 'receipt anchored on re-pin')

  const recovered = await client.reconstructFromCustody({
    intentId: res.intentId,
    guardianSecretKeys: [g.secretKey],
    shareBundleKey: res.shareBundleKey,
    threshold: 1
  })
  t.is(recovered.key, res.key, 'guardian reconstructs the key after a re-pin custody')
})
