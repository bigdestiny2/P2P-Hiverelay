// WS-C: Client-side custody ORCHESTRATION — splitForCustody +
// reconstructFromCustody.
//
// splitForCustody is the publisher's single call to place a secret into blind
// custody: PVSS-split to the guardians' recipient pubkeys, publish the PUBLIC
// share bundle over the P2P data plane (a sibling hypercore), author + sign the
// v2 custody intent that names that bundle and assigns one share-index per
// relay, hand the signed intent to each relay (the HTTP control plane — SD3),
// wait for a share-verified anchored receipt from every relay, then sign +
// publish the quorum commit. requiredReplicas == n (the commit floor AND the
// shareIndex range); the reconstruction threshold t is the separate
// shareThreshold field.
//
// reconstructFromCustody is recovery: read the public bundle, let any t guardian
// secret keys decrypt their OWN shares (matched by recovering the recipient
// pubkey x·G from the key), and Lagrange-reconstruct. A custodian — who only
// ever holds ENCRYPTED shares — cannot reconstruct (blindness), and an encrypted
// share substituted for a decrypted one is rejected by reconstruct()'s DLEQ.
//
// The relay surface is stubbed: the wire format is pinned in
// client-custody.test.js and relay-side share verification in
// custody-share-bundle.test.js, so here we exercise only the client's
// composition logic. _writeShareBundle/_readShareBundle (the hypercore I/O) are
// stubbed to an in-memory map so the orchestration runs without a swarm. The
// status stub synthesizes anchored, share-verified receipts signed by the REAL
// relay keypairs, so the commit's relayQuorum + receiptRoot are meaningful.

import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { HiveRelayClient } from 'p2p-hiverelay-client'
import { keygen, reconstruct, SCHEME } from 'p2p-hiverelay-client/secret-sharing.js'
import { createCustodyReceipt, computeReceiptRoot, hashHex } from 'p2p-hiverelay-client/custody.js'
// shareCommitmentAt is the relay/verifier-side primitive; used here only to
// synthesize the X_i a real relay would anchor (the client never re-checks it).
import { shareCommitmentAt } from 'p2p-hiverelay/core/pvss.js'

const TEST_MAX_STORAGE_BYTES = 64 * 1024 * 1024

// Relays sign receipts with ed25519 identities — a SEPARATE key set from the
// secp256k1 guardian keys the shares are encrypted to.
function edKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

async function guardianKeys (n) {
  const keys = []
  for (let i = 0; i < n; i++) keys.push(await keygen())
  return keys
}

// A client whose network + bundle I/O is stubbed in-memory.
function makeClient ({ now = Date.now() } = {}) {
  const publisher = edKeyPair()
  const client = new HiveRelayClient({ keyPair: publisher })
  const state = {
    publisher,
    bundles: new Map(), // bundleKey -> public bundle
    intents: [], // { url, intent }
    seedCalls: [], // { url, body, opts }
    commits: [], // { url, intentId, commit }
    statusCalls: [], // { url, intentId }
    relaysByPubkey: new Map() // relayPubkeyHex -> ed25519 keypair
  }

  client._writeShareBundle = async (bundle) => {
    const key = hashHex('share-bundle:' + state.bundles.size + ':' + JSON.stringify(bundle))
    state.bundles.set(key, bundle)
    return key
  }
  client._readShareBundle = async (key) => state.bundles.get(key) || null
  client.publishCustodyIntent = async (url, intent) => {
    state.intents.push({ url, intent })
    return { intentId: intent.intentId }
  }
  client.publishCustodyCommit = async (url, intentId, commit) => {
    state.commits.push({ url, intentId, commit })
    return { ok: true }
  }
  client._postSeed = async (url, body, opts) => {
    state.seedCalls.push({ url, body, opts })
    return { ok: true }
  }
  // Synthesize a relay's status: one anchored, share-verified receipt per
  // assignment, signed by the real relay keypair so the commit binds real
  // signatures. The client's _awaitVerifiedReceipts dedupes across relays by
  // relayPubkey, so returning the full set from every relay is fine.
  client.getCustodyStatus = async (url, intentId) => {
    state.statusCalls.push({ url, intentId })
    const found = state.intents.find(c => c.intent.intentId === intentId)
    if (!found) return null
    const intent = found.intent
    const bundle = state.bundles.get(intent.shareBundleKey)
    const receipts = (intent.shareAssignments || []).map((a) => {
      const kp = state.relaysByPubkey.get(a.relayPubkey)
      return createCustodyReceipt({
        version: 2,
        intentId: intent.intentId,
        blindContentId: intent.blindContentId,
        ciphertextRoot: intent.ciphertextRoot,
        contentVersion: intent.contentVersion,
        retainUntil: intent.retainUntil,
        shardIds: [0],
        shareScheme: intent.shareScheme,
        commitmentRoot: intent.commitmentRoot,
        shareIndex: a.shareIndex,
        shareCommitment: shareCommitmentAt(bundle.commitments, a.shareIndex),
        shareVerified: true
      }, kp, { timestamp: now + 1000 })
    })
    return { intentId, intent, receipts }
  }

  return { client, state }
}

// n relays, n guardians, threshold t. Returns everything to drive both methods.
async function scenario ({ n = 3, threshold = 2, now = Date.now() } = {}) {
  const { client, state } = makeClient({ now })
  const guardians = await guardianKeys(n)
  const relays = Array.from({ length: n }, (_, i) => {
    const kp = edKeyPair()
    const pubkey = b4a.toString(kp.publicKey, 'hex')
    state.relaysByPubkey.set(pubkey, kp)
    return { url: 'http://relay-' + i + '.example:9100', pubkey }
  })
  const appKey = hashHex('app-drive:' + now)
  const opts = {
    maxStorage: TEST_MAX_STORAGE_BYTES,
    pollIntervalMs: 5,
    pollTimeoutMs: 4000,
    timestamp: now
  }
  return { client, state, guardians, relays, appKey, threshold, n, now, opts }
}

// ─── splitForCustody ────────────────────────────────────────────────

test('splitForCustody: composes a signed v2 intent + quorum commit', async (t) => {
  const { client, state, guardians, relays, appKey, threshold, n, opts } = await scenario()
  const res = await client.splitForCustody({
    guardians: guardians.map(g => g.publicKey),
    threshold,
    relays,
    appKey,
    opts
  })

  // Return shape.
  t.ok(/^[0-9a-f]{64}$/.test(res.intentId), 'returns an intentId')
  t.ok(/^[0-9a-f]{64}$/.test(res.shareBundleKey), 'returns the bundle key')
  t.ok(res.key, 'returns the dealer key')
  t.is(res.commitmentRoot, res.intent.commitmentRoot)
  t.is(res.receipts.length, n, 'one verified receipt per relay')

  // The signed intent went to every relay.
  t.is(state.intents.length, n, 'intent handed to each relay')
  for (let i = 0; i < n; i++) t.is(state.intents[i].url, relays[i].url, 'relay ' + i + ' url')
  const intent = state.intents[0].intent

  // v2 PVSS fields, with the load-bearing quorum semantics.
  t.is(intent.version, 2, 'v2 intent')
  t.is(intent.shareScheme, SCHEME)
  t.is(intent.shareThreshold, threshold, 'shareThreshold == reconstruction t')
  t.is(intent.requiredReplicas, n, 'requiredReplicas == n (commit floor + shareIndex range)')
  t.is(intent.addressKey, appKey, 'binds the content drive key')
  t.is(intent.shareBundleKey, res.shareBundleKey, 'names the published bundle')
  t.is(intent.commitmentRoot, state.bundles.get(res.shareBundleKey).commitmentRoot, 'commitmentRoot matches the bundle')

  t.is(state.seedCalls.length, n, 'custody seed handed to each relay')
  for (let i = 0; i < n; i++) {
    t.is(state.seedCalls[i].url, relays[i].url, 'custody seed relay ' + i + ' url')
    t.is(state.seedCalls[i].body.maxStorageBytes, TEST_MAX_STORAGE_BYTES, 'custody seed carries exact finite bound')
    t.is(state.seedCalls[i].opts.maxStorage, TEST_MAX_STORAGE_BYTES, 'private seed boundary retains exact finite bound')
  }

  // Assignment map: relays[i] -> shareIndex i+1.
  const assignments = intent.shareAssignments.map(a => ({ relayPubkey: a.relayPubkey, shareIndex: a.shareIndex }))
  t.alike(assignments, relays.map((r, i) => ({ relayPubkey: r.pubkey, shareIndex: i + 1 })), 'one share-index per relay, in order')

  // Commit binds the quorum + the chosen receipts.
  t.is(state.commits.length, n, 'commit published to each relay')
  const commit = res.commit
  t.alike(commit.relayQuorum, relays.map(r => r.pubkey).sort(), 'relayQuorum is the sorted relay set')
  t.is(commit.receiptRoot, computeReceiptRoot(res.receipts), 'receiptRoot binds the chosen receipts')
  t.is(commit.intentId, res.intentId)
})

test('splitForCustody: the published bundle carries only PUBLIC material (blind)', async (t) => {
  const { client, state, guardians, relays, appKey, threshold, n, opts } = await scenario()
  const res = await client.splitForCustody({ guardians: guardians.map(g => g.publicKey), threshold, relays, appKey, opts })

  const bundle = state.bundles.get(res.shareBundleKey)
  t.is(bundle.scheme, SCHEME)
  t.is(bundle.encryptedShares.length, n, 'one encrypted share per guardian')
  t.is(bundle.commitmentRoot, res.commitmentRoot)
  t.absent(bundle.secretPoint, 'no secret point in the bundle')
  t.absent(bundle.key, 'no dealer key in the bundle')
  // Every entry is an ENCRYPTED share (Y_i) — never a plaintext share (S_i).
  for (const s of bundle.encryptedShares) {
    t.ok(s.encryptedShare, 'has the encrypted share Y_i')
    t.absent(s.share, 'no plaintext share field on the wire')
  }
})

test('splitForCustody: validates its inputs', async (t) => {
  const { client, guardians, relays, appKey, threshold } = await scenario()
  const g = guardians.map(x => x.publicKey)
  await t.exception(client.splitForCustody({ guardians: [], threshold, relays, appKey }), /guardians\[\] required/, 'no guardians')
  await t.exception(client.splitForCustody({ guardians: g, threshold, relays: relays.slice(0, 2), appKey }), /length must equal/, 'relays != guardians')
  await t.exception(client.splitForCustody({ guardians: g, threshold: 4, relays, appKey }), /exceeds relay/, 'threshold > n')
  await t.exception(client.splitForCustody({ guardians: g, threshold, relays, appKey: 'not-hex' }), /64-hex/, 'bad appKey')
})

test('splitForCustody: rejects missing, zero, and unsafe storage bounds before side effects', async (t) => {
  const { client, state, guardians, relays, appKey, threshold } = await scenario()
  const base = {
    guardians: guardians.map(g => g.publicKey),
    threshold,
    relays,
    appKey
  }

  for (const [label, opts] of [
    ['missing', {}],
    ['zero', { maxStorage: 0 }],
    ['fractional', { maxStorage: 1.5 }],
    ['unsafe', { maxStorage: Number.MAX_SAFE_INTEGER + 1 }],
    ['string', { maxStorage: '67108864' }]
  ]) {
    await t.exception(
      client.splitForCustody({ ...base, opts }),
      /opts\.maxStorage must be a positive safe integer/,
      label + ' bound fails immediately'
    )
  }

  t.is(state.bundles.size, 0, 'invalid bounds publish no share bundle')
  t.is(state.intents.length, 0, 'invalid bounds publish no custody intent')
  t.is(state.seedCalls.length, 0, 'invalid bounds call no relay seed')
  t.is(state.statusCalls.length, 0, 'invalid bounds start no receipt polling')
  await t.exception(
    client._seedForCustody('http://relay.test', { addressKey: appKey }, {}),
    /opts\.maxStorage must be a positive safe integer/,
    'private custody seed boundary also fails closed'
  )
})

test('splitForCustody: requires a client keyPair', async (t) => {
  const client = new HiveRelayClient()
  await t.exception(
    client.splitForCustody({ guardians: [await keygen()], threshold: 1, relays: [{ url: 'http://r', pubkey: hashHex('p') }], appKey: hashHex('k') }),
    /keyPair required/,
    'splitForCustody refuses before start()'
  )
})

// ─── reconstructFromCustody ─────────────────────────────────────────

test('reconstructFromCustody: any t guardian keys recover the dealer key', async (t) => {
  const { client, guardians, relays, appKey, threshold, opts } = await scenario({ n: 3, threshold: 2 })
  const res = await client.splitForCustody({ guardians: guardians.map(g => g.publicKey), threshold, relays, appKey, opts })

  // Every 2-of-3 subset of guardian secret keys recovers the SAME key, with the
  // bundle key + threshold supplied explicitly (no relay round-trip).
  for (const idx of [[0, 1], [1, 2], [0, 2]]) {
    const out = await client.reconstructFromCustody({
      intentId: res.intentId,
      guardianSecretKeys: idx.map(i => guardians[i].secretKey),
      shareBundleKey: res.shareBundleKey,
      threshold
    })
    t.is(out.key, res.key, 'subset [' + idx.join(',') + '] recovers the dealer key')
    t.is(out.shares, threshold, 'used exactly t shares')
  }
})

test('reconstructFromCustody: resolves bundleKey + threshold from the relay intent', async (t) => {
  const { client, state, guardians, relays, appKey, threshold, opts } = await scenario()
  const res = await client.splitForCustody({ guardians: guardians.map(g => g.publicKey), threshold, relays, appKey, opts })

  // No explicit shareBundleKey/threshold: resolve them from getCustodyStatus.
  const out = await client.reconstructFromCustody({
    intentId: res.intentId,
    guardianSecretKeys: [guardians[0].secretKey, guardians[2].secretKey],
    relays
  })
  t.is(out.key, res.key, 'recovered via relay-resolved bundle key + threshold')
  t.ok(state.statusCalls.length > 0, 'queried relay status to resolve the intent')
})

test('reconstructFromCustody: fewer than t guardian keys cannot recover', async (t) => {
  const { client, guardians, relays, appKey, threshold, opts } = await scenario()
  const res = await client.splitForCustody({ guardians: guardians.map(g => g.publicKey), threshold, relays, appKey, opts })

  await t.exception(
    client.reconstructFromCustody({
      intentId: res.intentId,
      guardianSecretKeys: [guardians[0].secretKey], // 1 < t = 2
      shareBundleKey: res.shareBundleKey,
      threshold
    }),
    /1 of 2 shares/,
    'below-threshold recovery is refused'
  )
})

test('reconstructFromCustody: non-recipient keys decrypt nothing (custodians are blind)', async (t) => {
  const { client, guardians, relays, appKey, threshold, opts } = await scenario()
  const res = await client.splitForCustody({ guardians: guardians.map(g => g.publicKey), threshold, relays, appKey, opts })

  // Keys that are not any share's recipient: decryptShare's recovered x·G never
  // matches a bundle shareholder, so nothing is collected.
  const strangers = await guardianKeys(2)
  await t.exception(
    client.reconstructFromCustody({
      intentId: res.intentId,
      guardianSecretKeys: strangers.map(s => s.secretKey),
      shareBundleKey: res.shareBundleKey,
      threshold
    }),
    /0 of 2 shares/,
    'wrong keys recover nothing'
  )
})

test('blindness: the encrypted bundle alone cannot reconstruct (DLEQ-bound)', async (t) => {
  // A custodian holds only the PUBLIC bundle (encrypted shares Y_i). Feeding
  // those straight into reconstruct() — pretending Y_i are decrypted S_i — is
  // rejected: there is no path from ciphertext to secret without a guardian key.
  const { client, guardians, relays, appKey, threshold, opts } = await scenario()
  const res = await client.splitForCustody({ guardians: guardians.map(g => g.publicKey), threshold, relays, appKey, opts })
  const bundle = await client._readShareBundle(res.shareBundleKey)

  await t.exception(
    reconstruct({ shares: bundle.encryptedShares.slice(0, threshold), threshold }),
    'encrypted shares cannot stand in for decrypted ones'
  )
})
