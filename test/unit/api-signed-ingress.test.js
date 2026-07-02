import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  authorManifestPubkeyFromPath,
  buildAuthorManifestFetchRoutePayload,
  resolveSignedIngressRoute,
  runAuthorManifestFetchAction,
  runAuthorManifestPublishAction,
  runForkProofPublishAction,
  signedIngressPersistFailureResult
} from '../../packages/core/core/relay-node/api-signed-ingress.js'
import { createSeedingManifest } from '../../packages/core/core/seeding-manifest.js'
import { signForkProof } from '../../packages/core/core/fork-proof-signing.js'

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function hex (char, length = 64) {
  return char.repeat(length)
}

function manifestFor (kp, opts = {}) {
  return createSeedingManifest({
    keyPair: kp,
    relays: [{ url: 'hyperswarm://' + hex('a'), role: 'primary' }],
    drives: [{ driveKey: hex('b'), channel: 'stable' }],
    timestamp: opts.timestamp
  })
}

class FakeManifestStore {
  constructor (opts = {}) {
    this.records = new Map()
    this.saveFails = opts.saveFails === true
    this.putCalls = 0
    this.saveCalls = 0
    this.restoreCalls = 0
  }

  get (pubkey) {
    return this.records.get(String(pubkey).toLowerCase()) || null
  }

  snapshot () {
    return { records: new Map(this.records) }
  }

  restoreSnapshot (snapshot) {
    this.restoreCalls++
    this.records = new Map(snapshot.records)
  }

  put (manifest) {
    this.putCalls++
    const key = manifest.pubkey.toLowerCase()
    const existing = this.records.get(key)
    if (existing && existing.timestamp >= manifest.timestamp) {
      return { ok: false, reason: 'stale: existing manifest is newer or equal' }
    }
    this.records.set(key, manifest)
    return { ok: true, replaced: !!existing }
  }

  async save () {
    this.saveCalls++
    if (this.saveFails) throw new Error('disk full')
  }
}

function signedForkProof (opts = {}) {
  return signForkProof({
    hypercoreKey: hex('c'),
    blockIndex: 7,
    evidence: [
      { fromRelay: 'relay-a', block: 'block-a', signature: opts.signatureA || 'sig-a' },
      { fromRelay: 'relay-b', block: 'block-b', signature: opts.signatureB || 'sig-b' }
    ]
  }, keyPair())
}

class FakeForkDetector {
  constructor (opts = {}) {
    this.records = []
    this.saveFails = opts.saveFails === true
    this.reportResult = opts.reportResult || null
    this.reportCalls = 0
    this.saveCalls = 0
    this.restoreCalls = 0
  }

  snapshot () {
    return { records: this.records.slice() }
  }

  restoreSnapshot (snapshot) {
    this.restoreCalls++
    this.records = snapshot.records.slice()
  }

  report (record) {
    this.reportCalls++
    this.records.push(record)
    if (this.reportResult) return this.reportResult
    return { ok: true, recordExists: false }
  }

  async save () {
    this.saveCalls++
    if (this.saveFails) throw new Error('fork disk full')
  }
}

test('api signed ingress: route resolver matches only exact public signed POST routes', (t) => {
  t.alike(resolveSignedIngressRoute('POST', '/api/authors/seeding.json'), {
    kind: 'author-manifest-publish'
  })
  t.alike(resolveSignedIngressRoute('POST', '/api/forks/proof'), {
    kind: 'fork-proof-publish'
  })
  t.is(resolveSignedIngressRoute('GET', '/api/authors/seeding.json'), null, 'author publish wrong method falls through')
  t.is(resolveSignedIngressRoute('POST', '/api/authors/seeding.json/extra'), null, 'author publish subpath falls through')
  t.is(resolveSignedIngressRoute('GET', '/api/forks/proof'), null, 'fork proof wrong method falls through')
  t.is(resolveSignedIngressRoute('POST', '/api/forks/proofs'), null, 'fork proof list route stays separate')
})

test('api signed ingress: author manifest fetch handles unsupported, missing, and cacheable hits', (t) => {
  const missingStore = runAuthorManifestFetchAction({
    manifestStore: null,
    pubkey: hex('1')
  })
  t.is(missingStore.status, 503)
  t.ok(missingStore.payload.error.includes('manifest store not initialized'))

  const store = new FakeManifestStore()
  const missing = runAuthorManifestFetchAction({
    manifestStore: store,
    pubkey: hex('2')
  })
  t.is(missing.status, 404)
  t.ok(missing.payload.error.includes('no seeding manifest'))

  const kp = keyPair()
  const manifest = manifestFor(kp)
  store.put(manifest)
  const hit = runAuthorManifestFetchAction({
    manifestStore: store,
    pubkey: manifest.pubkey.toUpperCase()
  })
  t.is(hit.status, 200)
  t.is(hit.payload.signature, manifest.signature)
  t.alike(hit.headers, { 'Cache-Control': 'public, max-age=30' })
})

test('api signed ingress: author manifest route helper isolates public fetch path parsing', (t) => {
  const pubkey = hex('3')
  const path = `/api/authors/${pubkey.toUpperCase()}/seeding.json`
  const store = new FakeManifestStore()
  const kp = keyPair()
  const manifest = manifestFor(kp)
  store.put(manifest)

  t.is(authorManifestPubkeyFromPath(path), pubkey.toUpperCase())
  t.is(authorManifestPubkeyFromPath('/api/authors/not-hex/seeding.json'), null)
  t.is(authorManifestPubkeyFromPath('/api/authors/' + pubkey), null)

  const hit = buildAuthorManifestFetchRoutePayload({
    manifestStore: store,
    path: `/api/authors/${manifest.pubkey}/seeding.json`
  })

  t.is(hit.status, 200)
  t.is(hit.payload.signature, manifest.signature)
  t.alike(hit.headers, { 'Cache-Control': 'public, max-age=30' })
})

test('api signed ingress: author manifest publish verifies before store mutation', async (t) => {
  const store = new FakeManifestStore()
  const empty = await runAuthorManifestPublishAction({ body: null, manifestStore: store })
  t.is(empty.status, 400)
  t.is(store.putCalls, 0)
  t.is(store.saveCalls, 0)

  const invalid = await runAuthorManifestPublishAction({
    body: { type: 'not/a-manifest' },
    manifestStore: store
  })
  t.is(invalid.status, 400)
  t.ok(invalid.payload.error.includes('invalid manifest'))
  t.is(store.putCalls, 0, 'invalid signature path never reaches put')
  t.is(store.saveCalls, 0)
})

test('api signed ingress: author manifest publish stores valid signed manifests', async (t) => {
  const store = new FakeManifestStore()
  const manifest = manifestFor(keyPair())
  const out = await runAuthorManifestPublishAction({ body: manifest, manifestStore: store })

  t.is(out.status, 200)
  t.alike(out.payload, { ok: true, pubkey: manifest.pubkey, replaced: false })
  t.is(store.putCalls, 1)
  t.is(store.saveCalls, 1)
  t.is(store.get(manifest.pubkey).signature, manifest.signature)
})

test('api signed ingress: stale author manifests return conflict without saving', async (t) => {
  const store = new FakeManifestStore()
  const kp = keyPair()
  const newer = manifestFor(kp, { timestamp: 2000 })
  const older = manifestFor(kp, { timestamp: 1000 })
  store.put(newer)
  store.saveCalls = 0

  const out = await runAuthorManifestPublishAction({ body: older, manifestStore: store })

  t.is(out.status, 409)
  t.ok(out.payload.error.includes('stale'))
  t.is(store.saveCalls, 0)
  t.is(store.get(newer.pubkey).timestamp, 2000)
})

test('api signed ingress: author manifest save failure rolls back live store', async (t) => {
  const store = new FakeManifestStore({ saveFails: true })
  const kp = keyPair()
  const older = manifestFor(kp, { timestamp: 1000 })
  const newer = manifestFor(kp, { timestamp: 2000 })
  const events = []
  store.put(older)

  const out = await runAuthorManifestPublishAction({
    body: newer,
    manifestStore: store,
    emit: (event, payload) => events.push({ event, payload })
  })

  t.is(out.ok, false)
  t.is(out.kind, 'manifest-persist')
  t.is(out.status, 500)
  t.is(out.payload.errorCode, 'persist-failed')
  t.ok(out.payload.error.startsWith('persist-failed: '), 'public payload is stable and prefixed')
  t.absent(out.payload.error.includes('disk full'), 'public payload does not leak local storage error')
  t.is(events.length, 1)
  t.is(events[0].event, 'manifest-persist-error')
  t.is(events[0].payload.message, 'disk full')
  t.is(events[0].payload.error.message, 'disk full')
  t.is(store.restoreCalls, 1)
  t.is(store.get(older.pubkey).timestamp, 1000)
})

test('api signed ingress: fork proof publish requires signed envelopes before report', async (t) => {
  const forkDetector = new FakeForkDetector()
  const empty = await runForkProofPublishAction({ body: null, forkDetector })
  t.is(empty.status, 400)
  t.is(forkDetector.reportCalls, 0)

  const unsigned = await runForkProofPublishAction({
    body: { proof: { hypercoreKey: hex('c') } },
    forkDetector
  })
  t.is(unsigned.status, 400)
  t.ok(unsigned.payload.error.includes('invalid signed proof'))
  t.is(forkDetector.reportCalls, 0)
  t.is(forkDetector.saveCalls, 0)
})

test('api signed ingress: fork proof publish reports and persists valid signed proof', async (t) => {
  const forkDetector = new FakeForkDetector()
  const signed = signedForkProof()
  const out = await runForkProofPublishAction({ body: signed, forkDetector })

  t.is(out.status, 200)
  t.alike(out.payload, {
    ok: true,
    recordExists: false,
    observer: signed.observer.pubkey
  })
  t.is(forkDetector.reportCalls, 1)
  t.is(forkDetector.saveCalls, 1)
  t.is(forkDetector.records[0].hypercoreKey, signed.proof.hypercoreKey)
  t.alike(forkDetector.records[0].evidenceA, signed.proof.evidence[0])
})

test('api signed ingress: fork detector report failures stay bad requests', async (t) => {
  const forkDetector = new FakeForkDetector({
    reportResult: { ok: false, reason: 'evidence pair has identical signatures' }
  })
  const out = await runForkProofPublishAction({
    body: signedForkProof({ signatureA: 'same', signatureB: 'same' }),
    forkDetector
  })

  t.is(out.status, 400)
  t.ok(out.payload.error.includes('evidence pair has identical signatures'))
  t.is(forkDetector.reportCalls, 1)
  t.is(forkDetector.saveCalls, 0)
})

test('api signed ingress: fork proof save failure rolls back report', async (t) => {
  const forkDetector = new FakeForkDetector({ saveFails: true })
  const events = []
  forkDetector.records.push({ hypercoreKey: hex('d') })
  const out = await runForkProofPublishAction({
    body: signedForkProof(),
    forkDetector,
    emit: (event, payload) => events.push({ event, payload })
  })

  t.is(out.ok, false)
  t.is(out.kind, 'fork-persist')
  t.is(out.status, 500)
  t.is(out.payload.errorCode, 'persist-failed')
  t.ok(out.payload.error.startsWith('persist-failed: '), 'public payload is stable and prefixed')
  t.absent(out.payload.error.includes('fork disk full'), 'public payload does not leak local storage error')
  t.is(events.length, 1)
  t.is(events[0].event, 'fork-persist-error')
  t.is(events[0].payload.message, 'fork disk full')
  t.is(events[0].payload.error.message, 'fork disk full')
  t.is(forkDetector.restoreCalls, 1)
  t.is(forkDetector.records.length, 1)
  t.is(forkDetector.records[0].hypercoreKey, hex('d'))
})

test('api signed ingress: unknown persist kinds are ignored by the failure mapper', (t) => {
  let emitted = false
  const out = signedIngressPersistFailureResult({
    kind: 'config-persist',
    error: new Error('not a signed ingress persist failure'),
    emit: () => { emitted = true }
  })

  t.is(out, null)
  t.is(emitted, false)
})
