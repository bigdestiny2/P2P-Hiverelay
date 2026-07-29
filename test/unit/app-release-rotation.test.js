import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { AppRegistry } from '../../packages/core/core/app-registry.js'
import { AppLifecycle } from '../../packages/core/core/relay-node/app-lifecycle.js'
import { hashReleaseTree, signAppRelease } from '../../packages/core/core/release-lifecycle.js'

const OLD = 'a'.repeat(64)
const NEW = 'b'.repeat(64)
const WRONG = 'c'.repeat(64)
const BUDGET = 1024 * 1024
const CONTENT = b4a.from('verified release content')
const TREE_HASH = hashReleaseTree([{ path: '/index.html', content: CONTENT }])

function keyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, 5))
  return { publicKey, secretKey }
}

function signedRelease (pair, overrides = {}) {
  return signAppRelease({
    protocolVersion: 1,
    appId: 'demo',
    version: '2.0.0',
    sequence: 2,
    generation: 2,
    driveKey: NEW,
    previousDriveKey: OLD,
    rotationReason: 'storage-budget',
    storageBudgetBytes: BUDGET,
    rollbackWindow: 3,
    rollbackDriveKeys: [OLD],
    treeHash: TREE_HASH,
    issuedAt: Date.now(),
    ...overrides
  }, pair)
}

function predecessorRelease (pair) {
  return signAppRelease({
    protocolVersion: 1,
    appId: 'demo',
    version: '1.0.0',
    sequence: 1,
    generation: 1,
    driveKey: OLD,
    previousDriveKey: null,
    rotationReason: null,
    storageBudgetBytes: BUDGET,
    rollbackWindow: 3,
    rollbackDriveKeys: [],
    treeHash: TREE_HASH,
    issuedAt: Date.now()
  }, pair)
}

function manifestDrive (release, content = CONTENT) {
  const manifest = b4a.from(JSON.stringify({
    id: 'demo',
    name: 'Demo',
    version: release.version,
    hiverelay: { release }
  }))
  return {
    async get (path) {
      if (path === '/manifest.json') return manifest
      if (path === '/index.html') return content
      return null
    },
    async * list () {
      yield { key: '/index.html' }
      yield { key: '/manifest.json' }
    }
  }
}

function harness (release, oldRelease = null) {
  const publisher = release.publisherPubkey
  const registry = new AppRegistry(null)
  registry.set(OLD, {
    type: 'app',
    appId: 'demo',
    version: '1.0.0',
    publisherPubkey: publisher,
    maxStorage: BUDGET,
    release: oldRelease
  }, { persist: false })
  registry.set(NEW, {
    type: 'app',
    appId: 'demo',
    version: '2.0.0',
    publisherPubkey: publisher,
    maxStorage: BUDGET
  }, { persist: false })
  registry.persistEntry = async () => true
  const retained = []
  const unseeded = []
  const lifecycle = new AppLifecycle({
    appRegistry: registry,
    eviction: {
      async reclaimSuperseded (opts) { retained.push(opts) }
    }
  })
  lifecycle.unseedApp = async key => { unseeded.push(key) }
  return { lifecycle, registry, retained, unseeded }
}

test('relay accepts a signed predecessor-to-successor rotation and retains its rollback key', async (t) => {
  const release = signedRelease(keyPair())
  const { lifecycle, registry, retained, unseeded } = harness(release)

  await lifecycle._indexAppManifest(NEW, manifestDrive(release))

  t.is(registry.get(NEW).release.signature, release.signature)
  t.is(registry.get(NEW).publisherPubkey, release.publisherPubkey)
  t.alike(retained, [{
    dryRun: false,
    appId: 'demo',
    publisherPubkey: release.publisherPubkey,
    retainKeys: [OLD]
  }])
  t.alike(unseeded, [], 'predecessor stays seeded inside the signed rollback window')
})

test('relay rejects a signed rotation that does not name its current predecessor', async (t) => {
  const release = signedRelease(keyPair(), {
    previousDriveKey: WRONG,
    rollbackDriveKeys: [WRONG]
  })
  const { lifecycle, registry, retained, unseeded } = harness(release)
  const rejected = []
  lifecycle.on('app-release-rejected', event => rejected.push(event))

  await lifecycle._indexAppManifest(NEW, manifestDrive(release))

  t.alike(unseeded, [NEW])
  t.is(retained.length, 0)
  t.absent(registry.get(NEW).release, 'unverified transition is never persisted as release authority')
  t.ok(rejected[0].reason.includes('current predecessor'))
})

test('same-drive signed releases advance without re-declaring the old predecessor', async (t) => {
  const pair = keyPair()
  const prior = signedRelease(pair)
  const next = signedRelease(pair, {
    version: '3.0.0',
    sequence: 3,
    driveKey: NEW,
    previousDriveKey: null,
    rotationReason: null,
    rollbackDriveKeys: [OLD],
    treeHash: TREE_HASH
  })
  const { lifecycle, registry, retained, unseeded } = harness(next)
  registry.update(NEW, { release: prior })

  await lifecycle._indexAppManifest(NEW, manifestDrive(next))

  t.is(registry.get(NEW).release.sequence, 3)
  t.alike(retained, [{
    dryRun: false,
    appId: 'demo',
    publisherPubkey: next.publisherPubkey,
    retainKeys: [OLD]
  }])
  t.alike(unseeded, [])
})

test('a rollback-protected predecessor can re-index its rotation pointer without being unseeded', async (t) => {
  const pair = keyPair()
  const prior = predecessorRelease(pair)
  const release = signedRelease(pair)
  const { lifecycle, registry, unseeded } = harness(release, prior)

  await lifecycle._indexAppManifest(NEW, manifestDrive(release))
  await lifecycle._indexAppManifest(OLD, manifestDrive(prior))

  t.alike(unseeded, [])
  t.is(registry.byAppId.get('demo'), NEW, 'new release remains the canonical lookup hint')
  t.ok(registry.has(OLD), 'rollback predecessor remains available')
})

test('signed release sequence, not semver, orders an established release chain', async (t) => {
  const pair = keyPair()
  const prior = predecessorRelease(pair)
  const release = signedRelease(pair, { version: '0.5.0' })
  const { lifecycle, registry, unseeded } = harness(release, prior)

  await lifecycle._indexAppManifest(NEW, manifestDrive(release))

  t.alike(unseeded, [])
  t.is(registry.get(NEW).release.sequence, 2)
  t.is(registry.byAppId.get('demo'), NEW)
  t.is(registry.catalog()[0].appKey, NEW)
  t.is(registry.catalogForBroadcast()[0].appKey, NEW)
})

test('relay rejects a signed manifest whose tree hash does not match the pinned drive', async (t) => {
  const release = signedRelease(keyPair())
  const { lifecycle, registry, retained, unseeded } = harness(release)

  await lifecycle._indexAppManifest(NEW, manifestDrive(release, b4a.from('tampered')))

  t.alike(unseeded, [NEW])
  t.is(retained.length, 0)
  t.absent(registry.get(NEW).release)
})

test('relay never reclaims a predecessor before signed release persistence succeeds', async (t) => {
  const release = signedRelease(keyPair())
  const { lifecycle, registry, retained, unseeded } = harness(release)
  registry.persistEntry = async () => { throw new Error('disk full') }

  await lifecycle._indexAppManifest(NEW, manifestDrive(release))

  t.is(retained.length, 0)
  t.alike(unseeded, [NEW])
})

test('verified release authority survives registry persistence and restart', async (t) => {
  const release = signedRelease(keyPair())
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-release-registry-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))

  const first = new AppRegistry(dir)
  first.set(NEW, {
    type: 'app',
    appId: 'demo',
    version: release.version,
    publisherPubkey: release.publisherPubkey,
    maxStorage: BUDGET,
    release
  })
  await first.flush()

  const restarted = new AppRegistry(dir)
  const reseed = await restarted.load()
  t.is(restarted.get(NEW).release.signature, release.signature)
  t.is(reseed[0].release.signature, release.signature)
})
