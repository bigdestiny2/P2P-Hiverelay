/**
 * Bare-runtime test suite — runs under the ACTUAL Bare runtime (not Node).
 *
 * Run with:  npm run test:bare   (→ adds ./node_modules/bare/bin, then brittle-bare)
 *
 * Unlike test/unit/bare-relay-surface.test.js — which runs under Node and so
 * exercises the `default` condition of the imports map (Node built-ins) — this
 * suite is executed by `bare`, so the `bare` condition resolves to the REAL
 * bare-events / bare-fs / bare-http1 / bare-path / bare-crypto implementations.
 *
 * It is the verification gate for any storage-stack upgrade (corestore 7 /
 * hypercore 11): nothing else in CI actually loads the Bare module graph at
 * runtime. If the Bare relay can construct and resolve policy here, the wire
 * surface is sound under Bare.
 */

import test from 'brittle'
import { isBare, runtime } from 'which-runtime'

test('bare: suite is genuinely executing under the Bare runtime', (t) => {
  t.ok(isBare, 'which-runtime reports isBare === true (not the Node fallback)')
  t.is(runtime, 'bare', 'runtime string is "bare"')
})

test('bare: BareRelay imports via the bare condition of the imports map', async (t) => {
  const { BareRelay } = await import('p2p-hiverelay/core/relay-node/bare-relay.js')
  t.ok(BareRelay, 'BareRelay class is exported under Bare')
  t.is(typeof BareRelay, 'function', 'is a constructor')
})

test('bare: external catalog adapter imports and parses without Node Buffer', async (t) => {
  const { readExternalCatalogPage } = await import('p2p-hiverelay/core/relay-node/api-catalog-read.js')
  const result = readExternalCatalogPage({
    node: {},
    url: new URL('http://bare.local/catalog.json?cursor=%7B%7D')
  })
  t.is(result.status, 400)
  t.is(result.payload.error, 'INVALID_CATALOG_CURSOR')
})

test('bare: BareRelay constructs with real bare-* modules loaded', async (t) => {
  const { BareRelay } = await import('p2p-hiverelay/core/relay-node/bare-relay.js')
  const relay = new BareRelay({ storage: '/tmp/bare-rt-smoke-' + Date.now() })
  t.ok(relay, 'instance constructed under Bare')
  t.is(relay.running, false, 'not running before start()')
  t.is(typeof relay.start, 'function', 'has start()')
  t.is(typeof relay.stop, 'function', 'has stop()')
  t.is(relay.config.acceptMode, 'open', 'Bare default accept mode is open')
  t.is(relay.config.enableSeeding, true, 'seeding enabled by default')
  t.is(relay.config.catalogSync, true, 'catalog sync enabled by default')
})

test('bare: paged catalog ownership checks initialize and stop without Node globals', async (t) => {
  const { AppCatalogDiskStageFactory } = await import('p2p-hiverelay/core/relay-node/app-catalog-paged-stage.js')
  const { createAppCatalogSnapshotIdentity } = await import('p2p-hiverelay/core/relay-node/app-catalog-paged.js')
  const { realpath, rm } = await import('bare-fs/promises')
  const root = (await realpath('/tmp')) + '/hiverelay-bare-paged-catalog-' + Date.now()
  const factory = new AppCatalogDiskStageFactory({ rootDir: root })
  try {
    await factory.ready()
    t.ok(factory._ownerUid !== null, 'root stat pins the Bare-safe owner identity')
    t.is(factory._ownedDirectoryIdentities.size, 4, 'root and owned ancestry identities are pinned')
    const peerPubkey = 'a'.repeat(64)
    const snapshot = createAppCatalogSnapshotIdentity({
      senderPubkey: peerPubkey,
      highWater: 0,
      rows: []
    })
    const metadata = {
      peerPubkey,
      snapshotId: snapshot.snapshotId,
      highWater: snapshot.highWater,
      rootDigest: snapshot.rootDigest,
      entryCount: snapshot.entryCount
    }
    const discarded = await factory.open(metadata)
    const discarding = discarded.discard()
    t.is(discarded.discard(), discarding, 'Bare stage discard shares its exact handle-drain attempt')
    await discarding
    t.is(discarded.rowsHandle, null)
    t.is(discarded.indexHandle, null)

    const stage = await factory.open(metadata)
    const committed = await stage.commit(snapshot)
    t.alike((await committed.readPage({ limit: 1 })).entries, [], 'Bare opens, verifies, reads, and closes committed files')
    await committed.release()
    await factory.stop()
    await t.exception(factory.ready(), /stopped/)
  } finally {
    await factory.stop()
    await rm(root, { recursive: true, force: true })
  }
})

test('bare: shutdown fence is synchronous and rejects new seed/unseed work', async (t) => {
  const { BareRelay } = await import('p2p-hiverelay/core/relay-node/bare-relay.js')
  const { sharedOperationFlights } = await import('p2p-hiverelay/core/shared-flight-registry.js')
  const relay = new BareRelay({ storage: '/tmp/bare-rt-fence-' + Date.now() })
  const events = []
  relay._scope = { abort () { events.push('scope') } }
  relay.appLifecycle = {
    beginShutdown () { events.push('apps') },
    seedApp () { t.fail('fenced seed reached AppLifecycle') },
    unseedApp () { t.fail('fenced unseed reached AppLifecycle') }
  }

  const fence = relay._installBareShutdownFence('bare-runtime-test')
  t.alike(events, ['scope', 'apps'])
  t.is(fence.state, 'FENCED')
  t.is(sharedOperationFlights.getStats(relay).owner.accepting, false)

  let seedError = null
  let unseedError = null
  try { relay.seedApp('a'.repeat(64)) } catch (err) { seedError = err }
  try { relay.unseedApp('a'.repeat(64)) } catch (err) { unseedError = err }
  t.is(seedError && seedError.code, 'SHUTTING_DOWN')
  t.is(unseedError && unseedError.code, 'SHUTTING_DOWN')
})

test('bare: capability doc detects the Bare runtime via which-runtime', async (t) => {
  const { buildCapabilityDoc } = await import('p2p-hiverelay/core/capability-doc.js')
  const doc = buildCapabilityDoc({})
  t.is(doc.runtime, 'bare', 'capability doc reports runtime:"bare" when executed under Bare')
  t.is(doc.schemaVersion, 1, 'capability schema version present')
})

test('bare: accept-mode resolver is deterministic under Bare', async (t) => {
  const { BareRelay } = await import('p2p-hiverelay/core/relay-node/bare-relay.js')
  const relay = new BareRelay({ storage: '/tmp/bare-rt-mode-' + Date.now() })
  const cases = [
    { acceptMode: 'open', expect: 'open' },
    { acceptMode: 'review', expect: 'review' },
    { acceptMode: 'allowlist', expect: 'allowlist' },
    { acceptMode: 'closed', expect: 'closed' }
  ]
  for (const { acceptMode, expect } of cases) {
    relay.config.acceptMode = acceptMode
    t.is(relay._resolveAcceptMode(), expect, `acceptMode ${acceptMode} resolves to ${expect}`)
  }
})

test('bare: bootstrap cache uses the shared bounded endpoint parser and LRU', async (t) => {
  const { BootstrapCache, normalizeBootstrapHost } = await import('p2p-hiverelay/core/bootstrap-cache.js')
  t.is(normalizeBootstrapHost('2001:0DB8::1').host, '2001:db8::1')
  t.is(normalizeBootstrapHost('BÜCHER.Example.').host, 'xn--bcher-kva.example')
  t.is(normalizeBootstrapHost('[::1]'), null)

  const cache = new BootstrapCache('/tmp/bare-bootstrap-cache-' + Date.now(), { maxPeers: 1 })
  cache._insert({ host: 'one.example', port: 1, lastSeen: 1 })
  cache._insert({ host: 'two.example', port: 2, lastSeen: 2 })
  t.is(cache.getStats().size, 1)
  t.is(cache.getStats().evictions, 1)
  t.is(cache._collectPeers()[0].host, 'two.example')
})

test('bare: storage accounting epoch runs without Node globals', async (t) => {
  const { runStorageAccountingEpoch } = await import('p2p-hiverelay/core/relay-node/storage-accounting-epoch.js')
  const directory = {
    dev: 1,
    ino: 1,
    blocks: 0,
    size: 0,
    isSymbolicLink: () => false,
    isDirectory: () => true,
    isFile: () => false
  }
  const file = {
    dev: 1,
    ino: 2,
    blocks: 2,
    size: 4096,
    isSymbolicLink: () => false,
    isDirectory: () => false,
    isFile: () => true
  }
  let read = false
  const result = await runStorageAccountingEpoch('/bare-root', {
    fs: {
      lstat: async path => path === '/bare-root' ? directory : file,
      opendir: async () => ({
        read: async () => {
          if (read) return null
          read = true
          return { name: 'data' }
        },
        close: async () => {}
      })
    }
  })
  t.ok(result.complete)
  t.is(result.bytes, 1024, 'allocated blocks are portable under Bare')
  t.is(result.operations.ordinary, 7)
  t.is(result.operations.cleanup, 1)
})

test('bare: a late normal directory close is never issued twice', async (t) => {
  const { StorageAccountingEpoch } = await import('p2p-hiverelay/core/relay-node/storage-accounting-epoch.js')
  const directory = {
    dev: 1,
    ino: 1,
    blocks: 0,
    size: 0,
    isSymbolicLink: () => false,
    isDirectory: () => true,
    isFile: () => false
  }
  let releaseClose
  let signalCloseStarted
  let closeStarted = 0
  let closeCalls = 0
  const closeGate = new Promise(resolve => { releaseClose = resolve })
  const closeStartedGate = new Promise(resolve => { signalCloseStarted = resolve })
  const epoch = new StorageAccountingEpoch('/bare-late-close', {
    fs: {
      async lstat () { return directory },
      async opendir () {
        return {
          async read () { return null },
          async close () {
            closeCalls++
            if (closeCalls > 1) throw new Error('Bare directory was closed twice')
            closeStarted++
            signalCloseStarted()
            await closeGate
          }
        }
      }
    }
  })

  const running = epoch.run()
  await closeStartedGate
  t.is(closeStarted, 1, 'the ordinary close owns the underlying Bare handle')
  epoch.stop()
  releaseClose()
  const result = await running

  t.is(closeCalls, 1, 'the underlying Bare handle receives one close total')
  t.is(result.operations.cleanup, 0, 'cleanup does not close the settled handle again')
  t.is(result.progress.openDirectories, 0, 'late success releases its frame')
  t.absent(result.failedDrain)
})
