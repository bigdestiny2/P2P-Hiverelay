/**
 * End-to-end blind atomic custody integration test.
 *
 * Spins up 3 real RelayNode instances on a Hyperswarm testnet, runs the
 * full custody pipeline through real signing, log replication, anchoring,
 * expiry, and non-serving-proof. This is the test that catches
 * integration regressions the unit tests can't see — protocol channel
 * wiring, registry replication latency, expiry monitor side effects,
 * gateway behavior changes after retainUntil.
 *
 * Adapted from scripts/observe-testnet-seeding.js to run as a brittle
 * test in CI.
 */

import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import { createHash, randomBytes } from 'crypto'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import { hashHex } from 'p2p-hiverelay/core/custody-signing.js'

const TEST_MAX_STORAGE_BYTES = 64 * 1024 * 1024
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))

async function waitFor (label, fn, timeoutMs = 30_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const value = await fn()
    if (value) return value
    await sleep(250)
  }
  throw new Error(`${label} timed out after ${timeoutMs}ms`)
}

test('e2e blind custody: intent → quorum → commit → retired → proof → expiry → non-serving-proof', async (t) => {
  const id = randomBytes(4).toString('hex')
  const baseDir = join(tmpdir(), `hiverelay-e2e-${id}`)
  const basePort = 19400 + Math.floor(Math.random() * 500)
  const testnet = await createTestnet(3)
  const relays = []
  let publisher = null
  let sourceDrive = null
  let sourceDiscovery = null

  await mkdir(baseDir, { recursive: true })
  await mkdir(join(baseDir, 'publisher'), { recursive: true })
  for (let i = 0; i < 3; i++) await mkdir(join(baseDir, `relay-${i}`), { recursive: true })

  t.teardown(async () => {
    let firstError = null
    for (const relay of relays) {
      try { await relay.stop() } catch (err) { if (!firstError) firstError = err }
    }
    if (sourceDiscovery) {
      try { await sourceDiscovery.destroy() } catch (err) { if (!firstError) firstError = err }
    }
    if (sourceDrive) {
      try { await sourceDrive.close() } catch (err) { if (!firstError) firstError = err }
    }
    if (publisher) {
      try { await publisher.stop() } catch (err) { if (!firstError) firstError = err }
    }
    try { await testnet.destroy() } catch (err) { if (!firstError) firstError = err }
    try { await rm(baseDir, { recursive: true, force: true }) } catch (err) { if (!firstError) firstError = err }
    if (firstError) throw firstError
  })

  // ─── Bring up publisher ───
  publisher = new RelayNode({
    storage: join(baseDir, 'publisher'),
    bootstrapNodes: testnet.bootstrap,
    enableAPI: false,
    enableRelay: false,
    enableSeeding: false,
    enableServices: false,
    enableNetworkDiscovery: false,
    enableHolesail: false
  })
  await publisher.start()

  // ─── Bring up 3 custody relays ───
  for (let i = 0; i < 3; i++) {
    const relay = new RelayNode({
      storage: join(baseDir, `relay-${i}`),
      bootstrapNodes: testnet.bootstrap,
      apiPort: basePort + i,
      apiHost: '127.0.0.1',
      enableSeeding: true,
      enableNetworkDiscovery: false,
      enableHolesail: false,
      gatewayServeBlind: false,
      // Short expiry interval so the test runs fast
      custodyExpiryInterval: 5_000,
      custodyExpiryGraceMs: 0
    })
    await relay.start()
    relays.push(relay)
  }

  // ─── Encrypted ciphertext payload ───
  const ciphertext = randomBytes(2048)
  const ciphertextHash = createHash('sha256').update(ciphertext).digest('hex')

  sourceDrive = new Hyperdrive(publisher.store.session(), null)
  await sourceDrive.ready()
  await sourceDrive.put('/sealed/blob.bin', ciphertext)
  await sourceDrive.put('/sealed/manifest.json', b4a.from(JSON.stringify({
    version: 1,
    blindContentId: hashHex({ id, ciphertextHash }),
    ciphertextRoot: ciphertextHash
  }, null, 2)))

  sourceDiscovery = publisher.swarm.join(sourceDrive.discoveryKey, { server: true, client: true })
  await publisher.swarm.flush()

  const appKey = b4a.toString(sourceDrive.key, 'hex')
  const publisherKeyPair = publisher.swarm.keyPair
  const retainUntil = Date.now() + 8_000 // expires in 8 seconds
  const blindContentId = hashHex({ appKey, ciphertextHash, id })

  // ─── Step 1: Publisher publishes custody intent ───
  const intent = await relays[0].seedingRegistry.publishCustodyIntent({
    addressKey: appKey,
    blindContentId,
    ciphertextRoot: ciphertextHash,
    contentVersion: 1,
    requiredReplicas: relays.length,
    deadline: Date.now() + 60_000,
    retainUntil,
    shardPolicy: 'all'
  }, publisherKeyPair)
  t.ok(intent.signature, 'intent signed')
  t.ok(intent.intentId, 'intentId assigned')

  // ─── Step 2: Each relay seeds the drive in blind mode → auto-emits receipts ───
  for (let i = 0; i < relays.length; i++) {
    await relays[i].seedApp(appKey, {
      type: 'drive',
      privacyTier: 'p2p-only',
      blind: true,
      storageClass: 'temporary',
      availabilityClass: 'atomic-handoff',
      custodyIntentId: intent.intentId,
      blindContentId,
      ciphertextRoot: ciphertextHash,
      contentVersion: 1,
      maxStorage: TEST_MAX_STORAGE_BYTES,
      retainUntil,
      shardIds: [i]
    })
    t.is(relays[i].appRegistry.get(appKey)?.maxStorage, TEST_MAX_STORAGE_BYTES, 'storage bound persisted')
  }

  // Wait for all relays to anchor
  await waitFor('all relays anchored', () =>
    relays.every(r => r.appRegistry.get(appKey)?.anchored === true), 30_000)

  // ─── Step 3: Wait for quorum receipts to propagate via registry replication ───
  await waitFor('quorum reached on relay-0', () => {
    const status = relays[0].seedingRegistry.getCustodyStatus(intent.intentId)
    return status.receiptCount >= relays.length ? status : null
  }, 60_000)
  const quorumStatus = relays[0].seedingRegistry.getCustodyStatus(intent.intentId)
  t.is(quorumStatus.receiptCount, relays.length, 'all relays signed receipts')
  t.is(quorumStatus.quorumReached, true, 'quorum reached')

  // ─── Step 4: Publisher signs commit + source-retired ───
  await relays[0].seedingRegistry.publishCustodyCommit({ intentId: intent.intentId }, publisherKeyPair)
  await relays[0].seedingRegistry.publishSourceRetired({ intentId: intent.intentId }, publisherKeyPair)

  const committedStatus = relays[0].seedingRegistry.getCustodyStatus(intent.intentId)
  t.is(committedStatus.committed, true, 'commit visible')
  t.is(committedStatus.sourceRetired, true, 'source retired visible')

  // ─── Step 5: Observer signs custody-proof ───
  await relays[0].seedingRegistry.recordCustodyProof({
    intentId: intent.intentId,
    relayPubkey: b4a.toString(relays[0].swarm.keyPair.publicKey, 'hex'),
    challengeNonce: hashHex({ id, challenge: 'e2e' }),
    shardIds: [1],
    blockIndices: [0],
    passed: true,
    latencyMs: 1
  }, publisherKeyPair)

  const proofStatus = relays[0].seedingRegistry.getCustodyStatus(intent.intentId)
  t.is(proofStatus.proofCount, 1, 'proof recorded')
  t.is(proofStatus.passingProofs, 1, 'proof passed')

  // ─── Step 6: Wait for retainUntil to elapse + expiry monitor to fire ───
  await waitFor('all relays unseeded after expiry', () =>
    relays.every(r => !r.appRegistry.has(appKey)), 30_000)

  // ─── Step 7: Sign non-serving-proof on one relay ───
  const nonServingProof = await relays[0].createCustodyNonServingProof(intent.intentId, {
    challengeNonce: hashHex({ id, challenge: 'post-expiry-e2e' }),
    notServingReason: 'expired-unseeded'
  })
  await relays[0].seedingRegistry.recordCustodyNonServingProof(nonServingProof)

  const finalStatus = relays[0].seedingRegistry.getCustodyStatus(intent.intentId)
  // ≥ 1, not exactly 1: the v0.9.2-fixed expiry sweep auto-signs
  // non-serving-proofs on its own schedule during the run, racing the
  // manual one recorded above. Only the floor is deterministic.
  t.ok(finalStatus.nonServingProofCount >= 1, 'non-serving-proof recorded (' + finalStatus.nonServingProofCount + ' total incl. auto-sweep)')

  // ─── Step 8: Witness Tombstone — independent attestation ───
  // A separate witness key (would be a different operator in production)
  const witnessKeyPair = relays[2].swarm.keyPair // reuse relay-2's key as the witness
  const tombstone = await relays[0].seedingRegistry.recordCustodyExpiryWitness({
    intentId: intent.intentId,
    blindContentId,
    relayPubkey: b4a.toString(relays[0].swarm.keyPair.publicKey, 'hex'),
    nonServingProofHash: hashHex(nonServingProof),
    catalogPresent: false,
    gatewayServing: false,
    activeSwarmObserved: false
  }, witnessKeyPair)
  t.ok(tombstone.signature, 'witness tombstone signed')

  // ≥ 1, not exactly 1: since v0.9.2 fixed the sweep's challengeNonce, the
  // automatic cross-relay witness pass (initial fire 5s after start) also
  // produces witnesses during this test's ~15s run. Threshold-many
  // independent witnesses is the designed behavior (v0.8.20) — assert ours
  // is among them rather than pinning the count.
  const witnesses = relays[0].seedingRegistry.getCustodyExpiryWitnesses(intent.intentId)
  t.ok(witnesses.length >= 1, 'witness tombstone indexed (' + witnesses.length + ' total incl. auto-witness pass)')
  const witnessPubHex = b4a.toString(witnessKeyPair.publicKey, 'hex')
  t.ok(witnesses.some(w => w.witnessPubkey === witnessPubHex), 'manually recorded witness present')

  // ─── Step 9: Aggregate snapshot reflects everything ───
  const snap = relays[0].seedingRegistry.custodySnapshot()
  t.is(snap.intents, 1)
  t.is(snap.committed, 1)
  t.is(snap.retired, 1)
  t.is(snap.withProof, 1)
  t.is(snap.withNonServingProof, 1)
  t.is(snap.withWitnessTombstone, 1)
  t.is(snap.totalReceipts, 3)
  // Same auto-witness-pass caveat as Step 8: the total grows with however
  // many auto-witnesses fired during the run; only the floor is stable.
  t.ok(snap.totalWitnessTombstones >= 1, 'witness tombstones counted (' + snap.totalWitnessTombstones + ')')
})
