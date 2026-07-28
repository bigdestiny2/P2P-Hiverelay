// WS-B: P2P share-bundle delivery + relay-side verification.
//
// The blind-custody invariant is that a relay holds an OPAQUE encrypted PVSS
// share it can publicly verify but never open. The publisher writes the public
// share bundle ({ commitments[], encryptedShares[] }) to a sibling hypercore and
// names that core's key in the SIGNED v2 custody intent (shareBundleKey). A
// custodying relay replicates the bundle and — with no secret key — checks the
// specific encrypted share the dealer assigned it before anchoring a receipt.
//
// Two layers are pinned here:
//   1. verifyShareBundleForRelay (pvss.js) — the pure decision: is THIS relay
//      assigned a share, does the replicated bundle match the publisher-signed
//      commitmentRoot, and does the assigned encrypted share verify? Each
//      failure has a distinct, defensive `reason`.
//   2. AppLifecycle._recordCustodyReceipt — the SD2 policy: a failed OR
//      unavailable verification must NOT anchor and must emit
//      `custody:share-verify-failed`. A success assembles a v2 receipt whose
//      PVSS fields bind to the signed intent (proven here by running the REAL
//      createCustodyReceipt + validateCustodyTransition inside a fake registry).
//
// _readShareBundle (the network I/O) is stubbed: it is best-effort, non-throwing
// glue whose only contract is "returns the parsed bundle or null", and a null
// from it is exercised as the unavailable-bundle path.

import test from 'brittle'
import b4a from 'b4a'
import Corestore from 'corestore'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import { access, mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { keygen, split } from 'p2p-hiverelay-client/secret-sharing.js'
import {
  createCustodyIntent,
  createCustodyReceipt,
  validateCustodyTransition,
  hashHex
} from 'p2p-hiverelay/core/custody-signing.js'
import { verifyShareBundleForRelay, shareCommitmentAt } from 'p2p-hiverelay/core/pvss.js'
import { AppLifecycle } from 'p2p-hiverelay/core/relay-node/app-lifecycle.js'
import { measureStorageTreeBytes } from 'p2p-hiverelay/config/storage-cap.js'
import {
  STORAGE_DRIVE_AUXILIARY_ALLOWANCE_BYTES,
  STORAGE_SHARE_BUNDLE_MAX_BYTES
} from 'p2p-hiverelay/config/storage-admission-authority.js'

// Relays sign custody entries with sodium ed25519 keys — a SEPARATE identity
// from the secp256k1 shareholder keys the shares are encrypted to.
function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

async function shareholders (n) {
  const keys = []
  for (let i = 0; i < n; i++) keys.push(await keygen())
  return keys
}

// relays[i] (an ed25519 signing identity) is assigned share i+1.
function assignmentsFor (relays) {
  return relays.map((r, i) => ({ relayPubkey: b4a.toString(r.publicKey, 'hex'), shareIndex: i + 1 }))
}

// Build a signed v2 PVSS intent + its public share bundle + n relay identities.
async function setup ({ n = 3, threshold = 2, now = Date.now() } = {}) {
  const holders = await shareholders(n)
  const res = await split({ threshold, shareholders: holders.map(k => k.publicKey) })
  const publisher = keyPair()
  const relays = Array.from({ length: n }, () => keyPair())
  const intent = createCustodyIntent({
    version: 2,
    blindContentId: hashHex('sb-blind'),
    ciphertextRoot: hashHex('sb-cipher'),
    contentVersion: 1,
    requiredReplicas: n,
    deadline: now + 60_000,
    retainUntil: now + 120_000,
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: threshold,
    commitmentRoot: res.public.commitmentRoot,
    shareBundleKey: hashHex('sb-bundle-key'),
    shareAssignments: assignmentsFor(relays)
  }, publisher, { timestamp: now })
  return { res, intent, publisher, relays, now }
}

// A fake RelayNode just rich enough for AppLifecycle._recordCustodyReceipt.
// getCustodyIntent serves the signed intent; recordCustodyReceipt runs the REAL
// signer + transition check so the v2 fields the lifecycle assembled are proven
// to produce a receipt that actually binds to the intent (not just shaped right).
function makeNode ({ keyPair: kp, intent, now }) {
  const calls = []
  const node = {
    swarm: { keyPair: kp },
    store: {},
    config: { region: 'sb-region' },
    seedingRegistry: {
      getCustodyIntent (id) {
        return intent && id === intent.intentId ? intent : null
      },
      async recordCustodyReceipt (fields, relayKeyPair) {
        const receipt = createCustodyReceipt(fields, relayKeyPair, { timestamp: now + 1000 })
        const transition = validateCustodyTransition(receipt, { intent })
        calls.push({ fields, receipt, transition })
        if (!transition.valid) throw new Error('transition-invalid:' + transition.reason)
        return receipt
      }
    }
  }
  return { node, calls }
}

function captureEvents (emitter) {
  const events = []
  for (const name of ['custody-receipt', 'custody:share-verify-failed', 'custody-receipt-error']) {
    emitter.on(name, (payload) => events.push({ name, payload }))
  }
  return events
}

function optsFor (intent) {
  return {
    blind: true,
    custodyIntentId: intent.intentId,
    blindContentId: intent.blindContentId,
    ciphertextRoot: intent.ciphertextRoot,
    contentVersion: intent.contentVersion,
    retainUntil: intent.retainUntil,
    shardIds: [0]
  }
}

// ─── verifyShareBundleForRelay (pure decision) ──────────────────────

test('verifyShareBundleForRelay: happy path returns the receipt PVSS fields', async (t) => {
  const { res, intent, relays } = await setup()
  const relayPubkey = b4a.toString(relays[0].publicKey, 'hex')
  const out = verifyShareBundleForRelay(intent, res.public, relayPubkey)
  t.ok(out.ok, 'verifies the assigned encrypted share')
  t.is(out.shareScheme, 'pvss-secp256k1-v1')
  t.is(out.commitmentRoot, intent.commitmentRoot)
  t.is(out.shareIndex, 1, 'relays[0] is assigned shareIndex 1')
  t.is(out.shareCommitment, shareCommitmentAt(res.public.commitments, 1), 'shareCommitment is X_1')
})

test('verifyShareBundleForRelay: rejects a non-PVSS or null intent', async (t) => {
  const { res, relays } = await setup()
  const relayPubkey = b4a.toString(relays[0].publicKey, 'hex')
  t.is(verifyShareBundleForRelay(null, res.public, relayPubkey).reason, 'intent-not-pvss')
  t.is(verifyShareBundleForRelay({}, res.public, relayPubkey).reason, 'intent-not-pvss')
})

test('verifyShareBundleForRelay: rejects a PVSS intent with no assignments', async (t) => {
  const { res, intent, relays } = await setup()
  const relayPubkey = b4a.toString(relays[0].publicKey, 'hex')
  const bare = { shareScheme: intent.shareScheme, commitmentRoot: intent.commitmentRoot }
  t.is(verifyShareBundleForRelay(bare, res.public, relayPubkey).reason, 'intent-missing-assignments')
})

test('verifyShareBundleForRelay: rejects a relay absent from the assignment map', async (t) => {
  const { res, intent } = await setup()
  const stranger = b4a.toString(keyPair().publicKey, 'hex')
  t.is(verifyShareBundleForRelay(intent, res.public, stranger).reason, 'relay-not-assigned')
})

test('verifyShareBundleForRelay: rejects a malformed bundle', async (t) => {
  const { res, intent, relays } = await setup()
  const relayPubkey = b4a.toString(relays[0].publicKey, 'hex')
  t.is(verifyShareBundleForRelay(intent, null, relayPubkey).reason, 'bundle-malformed', 'null bundle')
  t.is(verifyShareBundleForRelay(intent, { encryptedShares: res.public.encryptedShares }, relayPubkey).reason, 'bundle-malformed', 'missing commitments')
  t.is(verifyShareBundleForRelay(intent, { commitments: res.public.commitments }, relayPubkey).reason, 'bundle-malformed', 'missing encryptedShares')
})

test('verifyShareBundleForRelay: rejects a bundle whose commitments do not match the signed root', async (t) => {
  const { intent, relays } = await setup()
  // An independent split has a different commitment vector → a different root,
  // so a swapped-but-internally-consistent bundle cannot pass.
  const holders = await shareholders(3)
  const other = await split({ threshold: 2, shareholders: holders.map(k => k.publicKey) })
  const relayPubkey = b4a.toString(relays[0].publicKey, 'hex')
  t.is(verifyShareBundleForRelay(intent, other.public, relayPubkey).reason, 'commitmentRoot-mismatch')
})

test('verifyShareBundleForRelay: rejects when the assigned share is absent', async (t) => {
  const { res, intent, relays } = await setup()
  const relayPubkey = b4a.toString(relays[0].publicKey, 'hex')
  const bundle = { commitments: res.public.commitments, encryptedShares: res.public.encryptedShares.filter(s => s.index !== 1) }
  t.is(verifyShareBundleForRelay(intent, bundle, relayPubkey).reason, 'share-missing')
})

test('verifyShareBundleForRelay: rejects a tampered encrypted share', async (t) => {
  const { res, intent, relays } = await setup()
  const relayPubkey = b4a.toString(relays[0].publicKey, 'hex')
  const bundle = JSON.parse(JSON.stringify(res.public))
  const s1 = bundle.encryptedShares.find(s => s.index === 1)
  const s2 = bundle.encryptedShares.find(s => s.index === 2)
  s1.encryptedShare = s2.encryptedShare // breaks the DLEQ binding for index 1
  t.is(verifyShareBundleForRelay(intent, bundle, relayPubkey).reason, 'share-verify-failed')
})

// ─── AppLifecycle._recordCustodyReceipt (SD2 policy) ────────────────

test('_recordCustodyReceipt: anchors a v2 receipt when the assigned share verifies', async (t) => {
  const { res, intent, relays, now } = await setup()
  const { node, calls } = makeNode({ keyPair: relays[0], intent, now })
  const lifecycle = new AppLifecycle(node)
  lifecycle._readShareBundle = async () => res.public
  const events = captureEvents(lifecycle)

  const receipt = await lifecycle._recordCustodyReceipt(hashHex('app'), optsFor(intent))

  t.ok(receipt, 'returns an anchored receipt')
  t.is(calls.length, 1, 'recorded exactly one receipt')
  const f = calls[0].fields
  t.is(f.version, 2, 'receipt is v2')
  t.is(f.shareScheme, 'pvss-secp256k1-v1')
  t.is(f.commitmentRoot, intent.commitmentRoot)
  t.is(f.shareIndex, 1, 'relays[0] custodies share 1')
  t.is(f.shareCommitment, shareCommitmentAt(res.public.commitments, 1))
  t.is(f.shareVerified, true)
  t.ok(calls[0].transition.valid, 'assembled receipt binds to the signed intent')
  t.ok(events.find(e => e.name === 'custody-receipt'), 'emitted custody-receipt')
  t.absent(events.find(e => e.name === 'custody:share-verify-failed'), 'no failure event on success')
})

test('_recordCustodyReceipt: does not anchor when the bundle is unavailable (SD2)', async (t) => {
  const { intent, relays, now } = await setup()
  const { node, calls } = makeNode({ keyPair: relays[0], intent, now })
  const lifecycle = new AppLifecycle(node)
  lifecycle._readShareBundle = async () => null // peer never supplied block 0
  const events = captureEvents(lifecycle)

  const receipt = await lifecycle._recordCustodyReceipt(hashHex('app'), optsFor(intent))

  t.is(receipt, null, 'no receipt')
  t.is(calls.length, 0, 'never reached recordCustodyReceipt')
  const fail = events.find(e => e.name === 'custody:share-verify-failed')
  t.ok(fail, 'emitted share-verify-failed')
  t.is(fail.payload.reason, 'bundle-malformed', 'a null bundle reads as malformed')
  t.is(fail.payload.shareBundleKey, intent.shareBundleKey, 'echoes the bundle key from the signed intent')
})

test('_recordCustodyReceipt: does not anchor a tampered share (SD2)', async (t) => {
  const { res, intent, relays, now } = await setup()
  const { node, calls } = makeNode({ keyPair: relays[0], intent, now })
  const lifecycle = new AppLifecycle(node)
  const bundle = JSON.parse(JSON.stringify(res.public))
  const s1 = bundle.encryptedShares.find(s => s.index === 1)
  const s2 = bundle.encryptedShares.find(s => s.index === 2)
  s1.encryptedShare = s2.encryptedShare
  lifecycle._readShareBundle = async () => bundle
  const events = captureEvents(lifecycle)

  const receipt = await lifecycle._recordCustodyReceipt(hashHex('app'), optsFor(intent))

  t.is(receipt, null)
  t.is(calls.length, 0)
  t.is(events.find(e => e.name === 'custody:share-verify-failed').payload.reason, 'share-verify-failed')
})

test('_recordCustodyReceipt: a relay not assigned a share does not anchor', async (t) => {
  const { res, intent, now } = await setup()
  const stranger = keyPair() // ed25519 identity absent from shareAssignments
  const { node, calls } = makeNode({ keyPair: stranger, intent, now })
  const lifecycle = new AppLifecycle(node)
  lifecycle._readShareBundle = async () => res.public
  const events = captureEvents(lifecycle)

  const receipt = await lifecycle._recordCustodyReceipt(hashHex('app'), optsFor(intent))

  t.is(receipt, null)
  t.is(calls.length, 0)
  t.is(events.find(e => e.name === 'custody:share-verify-failed').payload.reason, 'relay-not-assigned')
})

test('_recordCustodyReceipt: a PVSS-hinted seed with no loaded intent fails closed', async (t) => {
  const { now } = await setup()
  const stranger = keyPair()
  const { node, calls } = makeNode({ keyPair: stranger, intent: null, now })
  const lifecycle = new AppLifecycle(node)
  let read = false
  lifecycle._readShareBundle = async () => { read = true; return null }
  const events = captureEvents(lifecycle)

  // Publisher hint says PVSS, but the signed intent is not loaded yet: decline
  // rather than anchor a plain receipt the transition check would later reject.
  const opts = {
    blind: true,
    custodyIntentId: hashHex('absent-intent'),
    blindContentId: hashHex('h-blind'),
    ciphertextRoot: hashHex('h-cipher'),
    contentVersion: 1,
    retainUntil: now + 120_000,
    shareScheme: 'pvss-secp256k1-v1'
  }
  const receipt = await lifecycle._recordCustodyReceipt(hashHex('app'), opts)

  t.is(receipt, null)
  t.is(calls.length, 0)
  t.absent(read, 'never tries to read a bundle without an authentic intent')
  t.is(events.find(e => e.name === 'custody:share-verify-failed').payload.reason, 'intent-unavailable')
})

test('_recordCustodyReceipt: a plain (non-PVSS) intent anchors a v1 receipt unchanged', async (t) => {
  const now = Date.now()
  const publisher = keyPair()
  const intent = createCustodyIntent({
    blindContentId: hashHex('p-blind'),
    ciphertextRoot: hashHex('p-cipher'),
    contentVersion: 1,
    requiredReplicas: 3,
    deadline: now + 60_000,
    retainUntil: now + 120_000
  }, publisher, { timestamp: now })
  const relay = keyPair()
  const { node, calls } = makeNode({ keyPair: relay, intent, now })
  const lifecycle = new AppLifecycle(node)
  let read = false
  lifecycle._readShareBundle = async () => { read = true; return null }
  const events = captureEvents(lifecycle)

  const receipt = await lifecycle._recordCustodyReceipt(hashHex('app'), optsFor(intent))

  t.ok(receipt, 'anchors a plain receipt')
  t.is(calls.length, 1)
  t.absent(read, 'no share-bundle read for plain custody')
  t.absent(calls[0].fields.version, 'no v2 share fields assembled')
  t.absent(calls[0].fields.shareScheme)
  t.is(receipt.version, 1, 'receipt defaults to v1')
  t.ok(events.find(e => e.name === 'custody-receipt'))
})

test('_readShareBundle: oversized signed core proof is rejected before any body range materializes', async (t) => {
  let downloads = 0
  let gets = 0
  let leaves = 0
  const core = {
    key: b4a.alloc(32, 1),
    discoveryKey: b4a.alloc(32, 2),
    length: 1,
    byteLength: STORAGE_SHARE_BUNDLE_MAX_BYTES + 1,
    async ready () {},
    async update () { return true },
    download () { downloads++; throw new Error('must not download oversized bundle') },
    async get () { gets++; return null },
    async close () {}
  }
  const node = {
    swarm: {
      join: () => ({ async flushed () {}, async destroy () { leaves++ } }),
      async leave () {},
      on () {},
      removeListener () {}
    },
    storageAdmission: {
      mutationAdmission: () => ({ allowed: true }),
      canAcknowledge: () => true,
      runMutation: run => Promise.resolve().then(run)
    }
  }
  const lifecycle = new AppLifecycle(node)
  const result = await lifecycle._readShareBundle('f'.repeat(64), {
    appKey: 'a'.repeat(64),
    timeoutMs: 100,
    createAuxStore: async () => ({
      async ready () {},
      get: () => core,
      replicate () {},
      async close () {}
    })
  })
  t.is(result, null)
  t.is(downloads, 0)
  t.is(gets, 0)
  t.is(leaves, 1)
})

test('_readShareBundle: fork swap between proof and snapshot cannot authorize a body read', async (t) => {
  let downloads = 0
  let gets = 0
  const snapshotCore = {
    fork: 1,
    length: 1,
    byteLength: 16,
    async ready () {},
    download () { downloads++; return { async done () {}, destroy () {} } },
    async get () { gets++; return b4a.from('{}') },
    async close () {}
  }
  const core = {
    key: b4a.alloc(32, 3),
    discoveryKey: b4a.alloc(32, 4),
    fork: 0,
    length: 1,
    byteLength: 16,
    async ready () {},
    async update () { return true },
    snapshot () { return snapshotCore },
    async close () {}
  }
  const node = {
    swarm: {
      join: () => ({ async flushed () {} }),
      async leave () {},
      on () {},
      removeListener () {}
    },
    storageAdmission: {
      mutationAdmission: () => ({ allowed: true }),
      canAcknowledge: () => true
    }
  }
  const lifecycle = new AppLifecycle(node)
  const result = await lifecycle._readShareBundle('e'.repeat(64), {
    appKey: 'f'.repeat(64),
    timeoutMs: 100,
    createAuxStore: async () => ({
      async ready () {},
      get: () => core,
      replicate () {},
      async close () {}
    })
  })
  t.is(result, null)
  t.is(downloads, 0, 'mismatched fork is rejected before finite range creation')
  t.is(gets, 0, 'mismatched fork is never read')
})

test('share-bundle auxiliary allowance covers a worst-case one-block Corestore slot', async (t) => {
  const storage = await mkdtemp(join(tmpdir(), 'share-bundle-footprint-'))
  t.teardown(() => rm(storage, { recursive: true, force: true }))
  const store = new Corestore(storage)
  await store.ready()
  const core = store.get({ name: 'bundle' })
  await core.ready()
  await core.append(b4a.alloc(STORAGE_SHARE_BUNDLE_MAX_BYTES))
  await core.close()
  await store.close()
  const bytes = measureStorageTreeBytes(storage)
  t.ok(bytes <= STORAGE_DRIVE_AUXILIARY_ALLOWANCE_BYTES, `${bytes} bytes fit in the per-drive auxiliary allowance`)
})

test('_readShareBundle: retries and replaced keys leave no persistent auxiliary core slot', async (t) => {
  const storage = await mkdtemp(join(tmpdir(), 'share-bundle-ephemeral-'))
  t.teardown(() => rm(storage, { recursive: true, force: true }))
  const swarm = new EventEmitter()
  swarm.join = () => ({ async flushed () {} })
  swarm.leave = async () => {}
  const appKey = 'b'.repeat(64)
  const node = {
    config: { storage },
    connections: new Map(),
    swarm,
    storageAdmission: {
      mutationAdmission: () => ({ allowed: true }),
      canAcknowledge: () => true,
      runKeyMutation: (_key, run) => Promise.resolve().then(run)
    }
  }
  const lifecycle = new AppLifecycle(node)
  for (const bundleKey of ['c'.repeat(64), 'd'.repeat(64)]) {
    t.is(await lifecycle._readShareBundle(bundleKey, { appKey, timeoutMs: 25 }), null)
    await t.exception(
      access(join(storage, '.aux-share-bundles', appKey)),
      /ENOENT/,
      'isolated slot is removed after each attempt'
    )
  }
})

test('_readShareBundle: active auxiliary fetch drains before concurrent unseed releases drive debt', async (t) => {
  const appKey = '7'.repeat(64)
  const events = []
  const tails = new Map()
  let committed = true
  let resolveProof
  let proofStarted
  const proofGate = new Promise(resolve => { resolveProof = resolve })
  const started = new Promise(resolve => { proofStarted = resolve })
  const snapshot = {
    fork: 0,
    length: 1,
    byteLength: 2,
    async ready () {},
    download () { return { async done () {}, destroy () {} } },
    async get () { return b4a.from('{}') },
    async close () { events.push('aux-snapshot-close') }
  }
  const core = {
    key: b4a.alloc(32, 5),
    discoveryKey: b4a.alloc(32, 6),
    fork: 0,
    length: 1,
    byteLength: 2,
    async ready () {},
    async update () { events.push('aux-proof-start'); proofStarted(); await proofGate; return true },
    snapshot () { return snapshot },
    async close () { events.push('aux-core-close') }
  }
  const storageAdmission = {
    mutationAdmission: () => ({ allowed: true }),
    canAcknowledge: () => committed,
    runKeyMutation (key, run) {
      const operation = (tails.get(key) || Promise.resolve()).catch(() => {}).then(run)
      const tail = operation.catch(() => {})
      tails.set(key, tail)
      tail.finally(() => { if (tails.get(key) === tail) tails.delete(key) })
      return operation
    },
    release () { events.push('authority-release'); committed = false; return true }
  }
  const entry = {
    drive: { async close () { events.push('drive-close') } },
    discoveryKey: b4a.alloc(32),
    downloadRanges: [{ destroy () { events.push('range-destroy') } }],
    downloadSnapshotCores: [{ async close () {} }, { async close () {} }]
  }
  const apps = new Map([[appKey, entry]])
  const appRegistry = {
    get: key => apps.get(key),
    has: key => apps.has(key),
    delete (key) { events.push('registry-retire'); return apps.delete(key) },
    set: (key, value) => apps.set(key, value),
    async persistDelete () { events.push('registry-delete-durable') }
  }
  const swarm = new EventEmitter()
  swarm.join = () => ({ async flushed () {} })
  swarm.leave = async () => { events.push('swarm-leave') }
  const node = { storageAdmission, appRegistry, swarm, connections: new Map() }
  const lifecycle = new AppLifecycle(node)
  const fetch = lifecycle._readShareBundle('8'.repeat(64), {
    appKey,
    timeoutMs: 1000,
    createAuxStore: async () => ({
      async ready () {},
      get: () => core,
      replicate () {},
      async close () { events.push('aux-store-close') }
    })
  })
  await started
  const unseed = lifecycle.unseedApp(appKey)
  await new Promise(resolve => setImmediate(resolve))
  t.absent(events.includes('registry-retire'), 'unseed queues behind the active auxiliary proof')
  resolveProof()
  t.alike(await fetch, {})
  await unseed
  t.ok(events.indexOf('aux-store-close') < events.indexOf('registry-retire'))
  t.ok(events.indexOf('range-destroy') < events.indexOf('authority-release'))
  t.ok(events.indexOf('drive-close') < events.indexOf('authority-release'))
})

test('_readShareBundle: acquires exactly one core session and one topic join per read', async (t) => {
  // The da70b0f restore duplicated the acquire-core + join-topic block verbatim.
  // Both copies ran, the second overwrote `core`/`discovery`, and only that
  // second pair reached teardown — so each read stranded one core session and
  // one PeerDiscovery join. The harnesses above cannot see it: they hand back
  // one shared core object and discard the join handle. Count both here.
  let sessions = 0
  let joins = 0
  let closes = 0
  let destroys = 0

  const newCore = () => ({
    key: b4a.alloc(32, 9),
    discoveryKey: b4a.alloc(32, 10),
    fork: 0,
    length: 1,
    byteLength: 16,
    async ready () {},
    async update () { return true },
    async get () { return b4a.from('{"ok":true}') },
    async close () { closes++ }
  })

  const node = {
    swarm: {
      join () { joins++; return { async flushed () {}, async destroy () { destroys++ } } },
      async leave () {},
      on () {},
      removeListener () {}
    },
    storageAdmission: {
      mutationAdmission: () => ({ allowed: true }),
      canAcknowledge: () => true
    }
  }

  const lifecycle = new AppLifecycle(node)
  const result = await lifecycle._readShareBundle('d'.repeat(64), {
    appKey: 'c'.repeat(64),
    timeoutMs: 100,
    createAuxStore: async () => ({
      async ready () {},
      get () { sessions++; return newCore() },
      replicate () {},
      async close () {}
    })
  })

  t.alike(result, { ok: true }, 'the bundle still parses')
  t.is(sessions, 1, 'one core session per read')
  t.is(joins, 1, 'one topic join per read')
  t.is(closes, 1, 'the single session is closed — no orphan left behind')
  t.is(destroys, 1, 'the single discovery is destroyed — no orphan join left behind')
})
