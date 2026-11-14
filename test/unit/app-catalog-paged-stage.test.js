import test from 'brittle'
import b4a from 'b4a'
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, stat, symlink, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { basename, join } from 'path'
import {
  APP_CATALOG_LIMITS,
  createAppCatalogSnapshotIdentity,
  createCanonicalCatalogRow
} from '../../packages/core/core/relay-node/app-catalog-paged.js'
import { AppCatalogDiskStageFactory } from '../../packages/core/core/relay-node/app-catalog-paged-stage.js'

const PEER = 'a'.repeat(64)

function deferred () {
  let resolve
  let reject
  const promise = new Promise((_resolve, _reject) => {
    resolve = _resolve
    reject = _reject
  })
  return { promise, resolve, reject }
}

async function nextTurn () {
  await new Promise(resolve => setTimeout(resolve, 0))
}

function record (nibble, appId) {
  return {
    appKey: nibble.repeat(64),
    appId,
    type: 'app',
    parentKey: null,
    mountPath: '/',
    version: '1.0.0',
    discoveryKey: ((parseInt(nibble, 16) + 1) % 16).toString(16).repeat(64),
    blind: false,
    storageClass: 'persistent',
    availabilityClass: 'always-on',
    privacyTier: 'public',
    seededAt: 1,
    redacted: false,
    metadataVisibility: 'public',
    blindContentId: null,
    anchored: true,
    maxStorageBytes: 1_024,
    publisherPubkey: ((parseInt(nibble, 16) + 2) % 16).toString(16).repeat(64),
    durability: 1,
    revocable: false,
    retainUntil: null
  }
}

function snapshot () {
  const rows = [
    createCanonicalCatalogRow(record('1', 'alpha')),
    createCanonicalCatalogRow(record('2', 'beta'))
  ]
  return createAppCatalogSnapshotIdentity({ senderPubkey: PEER, highWater: 7, rows })
}

function metadata (value, peerPubkey = PEER) {
  return {
    peerPubkey,
    snapshotId: value.snapshotId,
    highWater: value.highWater,
    rootDigest: value.rootDigest,
    entryCount: value.entryCount
  }
}

async function stageSnapshot (factory, value, peerPubkey = PEER) {
  const stage = await factory.open(metadata(value, peerPubkey))
  for (const row of value.rows) await stage.append(row, b4a.from(JSON.stringify(row), 'utf8'))
  return stage.commit(value)
}

test('disk stage commits atomically and reopens a validated bounded catalog', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-stage-')))
  const factories = []
  t.teardown(async () => {
    await Promise.allSettled(factories.map(factory => factory.stop()))
    await rm(root, { recursive: true, force: true })
  })

  const factory = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(factory)
  await factory.ready()
  await factory.ready()
  const value = snapshot()
  const committed = await stageSnapshot(factory, value)
  const first = await committed.readPage({ limit: 1 })
  t.is(first.entries.length, 1)
  t.is(first.complete, false)
  t.ok(first.cursor)
  const second = await committed.readPage({ cursor: first.cursor, limit: 1 })
  t.alike([...first.entries, ...second.entries], value.rows)
  t.is(second.complete, true)
  t.is(second.cursor, null)
  t.is(second.entryCount, value.entryCount)

  const encodedRecordBytes = value.rows.reduce((bytes, row) => bytes + 4 + b4a.byteLength(JSON.stringify(row)), 0)
  const manifest = JSON.parse(await readFile(join(committed.path, 'manifest.json'), 'utf8'))
  t.is(manifest.encodedRecordBytes, encodedRecordBytes)
  t.is((await stat(join(committed.path, 'rows.bin'))).size, encodedRecordBytes)
  t.is((await stat(join(committed.path, 'index.bin'))).size, value.entryCount * 72)
  await committed.release()

  const restarted = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(restarted)
  await restarted.ready()
  const reopened = await restarted.openCommittedPeer(PEER)
  t.ok(reopened)
  t.is(reopened.snapshotId, value.snapshotId)
  t.alike((await reopened.readPage({ limit: 2 })).entries, value.rows)
  await reopened.release()
})

test('restart rejects non-closed pointers and mismatched manifests', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-restart-')))
  const factories = []
  t.teardown(async () => {
    await Promise.allSettled(factories.map(factory => factory.stop()))
    await rm(root, { recursive: true, force: true })
  })
  const value = snapshot()
  const factory = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(factory)
  const committed = await stageSnapshot(factory, value)
  await committed.release()
  const pointerPath = join(root, 'peers', `${PEER}.json`)
  const pointer = JSON.parse(await readFile(pointerPath, 'utf8'))

  await writeFile(pointerPath, JSON.stringify({ ...pointer, unexpected: true }))
  const unknownField = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(unknownField)
  await t.exception(unknownField.openCommittedPeer(PEER), /unknown or missing field/)

  await writeFile(pointerPath, JSON.stringify({ ...pointer, peerPubkey: 'b'.repeat(64) }))
  const wrongPeer = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(wrongPeer)
  await t.exception(wrongPeer.openCommittedPeer(PEER), /peer does not match its filename/)

  await writeFile(pointerPath, JSON.stringify(pointer))
  const manifestPath = join(committed.path, 'manifest.json')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  await writeFile(manifestPath, JSON.stringify({ ...manifest, highWater: manifest.highWater + 1 }))
  const wrongManifest = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(wrongManifest)
  await t.exception(wrongManifest.openCommittedPeer(PEER), /manifest highWater mismatch/)
})

test('restart reconciles owned crash state and fails closed on foreign entries', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-reconcile-')))
  const factories = []
  t.teardown(async () => {
    await Promise.allSettled(factories.map(factory => factory.stop()))
    await rm(root, { recursive: true, force: true })
  })
  const factory = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(factory)
  const committed = await stageSnapshot(factory, snapshot())
  await committed.release()
  const staleName = `${'b'.repeat(64)}.${'c'.repeat(64)}.${'d'.repeat(32)}`
  await mkdir(join(root, 'staging', staleName), { mode: 0o700 })
  await mkdir(join(root, 'snapshots', staleName), { mode: 0o700 })
  const temporaryPointer = `.${PEER}.${'e'.repeat(32)}.tmp`
  await writeFile(join(root, 'peers', temporaryPointer), '{}', { mode: 0o600 })

  const cleanupBarriers = []
  const restarted = new AppCatalogDiskStageFactory({
    rootDir: root,
    onDurabilityBarrier: name => cleanupBarriers.push(name)
  })
  factories.push(restarted)
  await restarted.ready()
  t.alike(await readdir(join(root, 'staging')), [])
  t.alike(await readdir(join(root, 'peers')), [`${PEER}.json`])
  t.alike(await readdir(join(root, 'snapshots')), [committed.directory])
  t.alike(cleanupBarriers, [
    'reconciled-staging-directory-synced',
    'reconciled-peers-directory-synced',
    'reconciled-snapshots-directory-synced'
  ], 'restart fsyncs every parent directory whose owned crash entry was removed')
  const reopened = await restarted.openCommittedPeer(PEER)
  t.ok(reopened)
  await reopened.release()

  await mkdir(join(root, 'staging', 'foreign-entry'), { mode: 0o700 })
  const failClosed = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(failClosed)
  await t.exception(failClosed.ready(), /unowned entry/)
})

test('retained peer catalogs evict only inactive handles at the 256-peer cap and after restart', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-retained-')))
  const factories = []
  t.teardown(async () => {
    await Promise.allSettled(factories.map(factory => factory.stop()))
    await rm(root, { recursive: true, force: true })
  })
  const factory = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(factory)
  const peers = []
  let acquiredFirst = null
  for (let i = 1; i <= APP_CATALOG_LIMITS.maxInboundPeers; i++) {
    const peer = i.toString(16).padStart(64, '0')
    const value = createAppCatalogSnapshotIdentity({ senderPubkey: peer, highWater: i, rows: [] })
    const catalog = await stageSnapshot(factory, value, peer)
    if (i === 1) acquiredFirst = catalog
    else await catalog.release()
    peers.push(peer)
  }
  t.is((await readdir(join(root, 'peers'))).length, APP_CATALOG_LIMITS.maxInboundPeers)
  t.is((await readdir(join(root, 'snapshots'))).length, APP_CATALOG_LIMITS.maxInboundPeers)

  const overflowPeer = (APP_CATALOG_LIMITS.maxInboundPeers + 1).toString(16).padStart(64, '0')
  const overflow = createAppCatalogSnapshotIdentity({
    senderPubkey: overflowPeer,
    highWater: APP_CATALOG_LIMITS.maxInboundPeers + 1,
    rows: []
  })
  const overflowCatalog = await stageSnapshot(factory, overflow, overflowPeer)
  await overflowCatalog.release()
  t.is((await readdir(join(root, 'peers'))).length, APP_CATALOG_LIMITS.maxInboundPeers)
  t.ok((await readdir(join(root, 'peers'))).includes(`${peers[0]}.json`), 'cap eviction never deletes an acquired catalog')
  t.ok(!(await readdir(join(root, 'peers'))).includes(`${peers[1]}.json`), 'the lexicographically first inactive peer is evicted')
  t.is((await acquiredFirst.readPage()).entryCount, 0, 'the acquired catalog remains readable')
  await acquiredFirst.release()

  const restarted = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(restarted)
  await restarted.ready()
  const restartPeer = (APP_CATALOG_LIMITS.maxInboundPeers + 2).toString(16).padStart(64, '0')
  const restartValue = createAppCatalogSnapshotIdentity({
    senderPubkey: restartPeer,
    highWater: APP_CATALOG_LIMITS.maxInboundPeers + 2,
    rows: []
  })
  const restartCatalog = await stageSnapshot(restarted, restartValue, restartPeer)
  await restartCatalog.release()
  t.is((await readdir(join(root, 'peers'))).length, APP_CATALOG_LIMITS.maxInboundPeers, 'restart admission drains one deterministic inactive catalog')
  let removed = 0
  for (const peer of [...peers, overflowPeer, restartPeer]) {
    if (await restarted.removeCommittedPeer(peer)) removed++
  }
  t.is(removed, APP_CATALOG_LIMITS.maxInboundPeers)
  t.alike(await readdir(join(root, 'peers')), [])
  t.alike(await readdir(join(root, 'snapshots')), [])
  const finalCatalog = await stageSnapshot(restarted, overflow, overflowPeer)
  await finalCatalog.release()
  t.is(await restarted.removeCommittedPeer(overflowPeer), true, 'controller lifecycle cleanup frees capacity deterministically')

  const emptyRestart = new AppCatalogDiskStageFactory({ rootDir: root })
  factories.push(emptyRestart)
  await emptyRestart.ready()
  t.alike(await readdir(join(root, 'peers')), [])
  t.alike(await readdir(join(root, 'snapshots')), [])
})

test('commit durability barriers precede bounded superseded-handle reclamation', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-barriers-')))
  const barriers = []
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    onDurabilityBarrier: name => barriers.push(name)
  })
  t.teardown(async () => {
    await factory.stop()
    await rm(root, { recursive: true, force: true })
  })
  const firstValue = snapshot()
  const first = await stageSnapshot(factory, firstValue)
  const secondValue = createAppCatalogSnapshotIdentity({
    senderPubkey: PEER,
    highWater: firstValue.highWater + 1,
    rows: firstValue.rows
  })
  const second = await stageSnapshot(factory, secondValue)
  t.alike((await first.readPage({ limit: 2 })).entries, firstValue.rows, 'acquired prior handle remains readable after pointer replacement')

  const thirdValue = createAppCatalogSnapshotIdentity({
    senderPubkey: PEER,
    highWater: secondValue.highWater + 1,
    rows: firstValue.rows
  })
  await t.exception(factory.open(metadata(thirdValue)), /acquired superseded snapshot/)
  t.ok((await lstat(first.path)).isDirectory(), 'one superseded directory is retained while acquired')
  await first.release()
  await t.exception(lstat(first.path), /ENOENT/)
  t.alike(barriers, [
    'staged-files-synced',
    'snapshots-directory-synced',
    'temporary-pointer-synced',
    'peers-directory-synced',
    'staged-files-synced',
    'snapshots-directory-synced',
    'temporary-pointer-synced',
    'peers-directory-synced',
    'prior-snapshot-removed',
    'snapshots-directory-resynced'
  ], 'old reclaim occurs only after the new snapshot and pointer directory barriers')
  await second.release()
  t.is(await factory.removeCommittedPeer(PEER), true)
  t.alike(barriers.slice(-2), [
    'removed-peer-directory-synced',
    'removed-snapshot-directory-synced'
  ], 'peer removal fsyncs each parent directory after deleting its owned entry')
})

test('post-commit reclaim faults are surfaced and fence later admission', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-reclaim-fault-')))
  let failReclaim = true
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    onDurabilityBarrier: name => {
      if (name === 'prior-snapshot-removed' && failReclaim) {
        failReclaim = false
        throw new Error('forced snapshot directory sync failure')
      }
    }
  })
  t.teardown(async () => {
    await factory.stop()
    await rm(root, { recursive: true, force: true })
  })
  const firstValue = snapshot()
  const first = await stageSnapshot(factory, firstValue)
  await first.release()
  const secondValue = createAppCatalogSnapshotIdentity({
    senderPubkey: PEER,
    highWater: firstValue.highWater + 1,
    rows: firstValue.rows
  })
  await t.exception(stageSnapshot(factory, secondValue), /forced snapshot directory sync failure/)
  t.is(factory.storageFault, true, 'durability fault is visible to controller status')
  await t.exception(factory.open(metadata(firstValue)), /fail-closed after a cleanup fault/)
})

test('failed pointer transaction removes its temporary pointer and owned stage', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-pointer-')))
  const barriers = []
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    beforePointerRename: () => { throw new Error('forced pointer rename failure') },
    onDurabilityBarrier: name => barriers.push(name)
  })
  t.teardown(async () => {
    await factory.stop()
    await rm(root, { recursive: true, force: true })
  })
  const value = snapshot()
  const stage = await factory.open(metadata(value))
  for (const row of value.rows) await stage.append(row, b4a.from(JSON.stringify(row), 'utf8'))
  await t.exception(stage.commit(value), /forced pointer rename failure/)
  t.alike(await readdir(join(root, 'peers')), [], 'temporary pointer is removed on rename failure')
  await stage.discard()
  t.alike(await readdir(join(root, 'snapshots')), [], 'failed owned snapshot is discardable')
  t.is(barriers.at(-1), 'discarded-stage-directory-synced', 'discard fsyncs the snapshot parent after cleanup')
})

test('factory stop drains an owned ready flight and a reserved open without publishing work', async (t) => {
  const parent = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-factory-stop-')))
  t.teardown(() => rm(parent, { recursive: true, force: true }))

  const readyRoot = join(parent, 'ready')
  const readyGate = deferred()
  const readyEntered = deferred()
  const readyFactory = new AppCatalogDiskStageFactory({ rootDir: readyRoot })
  const initialize = readyFactory._initialize.bind(readyFactory)
  readyFactory._initialize = async epoch => {
    readyEntered.resolve()
    await readyGate.promise
    return initialize(epoch)
  }
  const readyResult = readyFactory.ready().catch(err => err)
  await readyEntered.promise
  let readyStopSettled = false
  const readyStop = readyFactory.stop().then(() => { readyStopSettled = true })
  t.is(readyFactory.stop(), readyFactory._stop, 'factory stop shares one exact drain promise')
  await nextTurn()
  t.is(readyStopSettled, false, 'stop does not claim settlement while initialization is owned')
  readyGate.resolve()
  t.is((await readyResult).code, 'RESOURCE_LIMIT')
  await readyStop
  const readyTree = await readdir(parent)
  await nextTurn()
  t.alike(await readdir(parent), readyTree, 'settled stop has no later initialization mutation')
  await t.exception(readyFactory.ready(), /stopped/)

  const openRoot = join(parent, 'open')
  const openFactory = new AppCatalogDiskStageFactory({ rootDir: openRoot })
  await openFactory.ready()
  const reserve = openFactory._reservePeer.bind(openFactory)
  const reserveEntered = deferred()
  const reserveGate = deferred()
  openFactory._reservePeer = async peer => {
    await reserve(peer)
    reserveEntered.resolve()
    await reserveGate.promise
  }
  const value = snapshot()
  const opening = openFactory.open(metadata(value)).catch(err => err)
  await reserveEntered.promise
  let openStopSettled = false
  const openStop = openFactory.stop().then(() => { openStopSettled = true })
  await nextTurn()
  t.is(openStopSettled, false, 'stop drains a reserved open before discarding ownership')
  reserveGate.resolve()
  t.is((await opening).code, 'RESOURCE_LIMIT')
  await openStop
  t.alike(await readdir(join(openRoot, 'staging')), [], 'stopped open returns no stage or files')
  t.is(openFactory._active.size, 0)
  t.is(openFactory._activePeers.size, 0)
})

test('factory stop drains committed reads and late release never starts post-stop reclaim', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-read-stop-')))
  const factory = new AppCatalogDiskStageFactory({ rootDir: root })
  t.teardown(() => rm(root, { recursive: true, force: true }))

  const firstValue = snapshot()
  const first = await stageSnapshot(factory, firstValue)
  const secondValue = createAppCatalogSnapshotIdentity({
    senderPubkey: PEER,
    highWater: firstValue.highWater + 1,
    rows: firstValue.rows
  })
  const second = await stageSnapshot(factory, secondValue)
  const retainedPath = first.path
  t.ok((await lstat(retainedPath)).isDirectory())

  const readEntered = deferred()
  const readGate = deferred()
  const assertLayout = factory._assertOwnedLayout.bind(factory)
  let gateRead = true
  factory._assertOwnedLayout = async () => {
    if (gateRead) {
      gateRead = false
      readEntered.resolve()
      await readGate.promise
    }
    return assertLayout()
  }
  const reading = first.readPage({ limit: 1 }).catch(err => err)
  await readEntered.promise
  let stopped = false
  const stopping = factory.stop().then(() => { stopped = true })
  await nextTurn()
  t.is(stopped, false, 'factory stop waits for the committed read operation')
  readGate.resolve()
  t.is((await reading).code, 'RESOURCE_LIMIT')
  await stopping
  t.exception(() => first.acquire(), /stopped/)
  t.exception(() => second.readPage(), /stopped/)
  t.is(await first.release(), true)
  t.is(await second.release(), true)
  await nextTurn()
  t.ok((await lstat(retainedPath)).isDirectory(), 'late release retains superseded storage instead of mutating after stop')
})

test('provisional committed acquisition survives an actual replacement reclaim race and releases on failure', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-acquire-race-')))
  const validationEntered = deferred()
  const validationGate = deferred()
  let validationMode = 'pass'
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    beforeCommittedValidation: async () => {
      if (validationMode === 'throw') throw new Error('forced committed validation failure')
      validationEntered.resolve()
      await validationGate.promise
    }
  })
  t.teardown(async () => {
    await factory.stop()
    await rm(root, { recursive: true, force: true })
  })

  const firstValue = snapshot()
  const first = await stageSnapshot(factory, firstValue)
  const firstPath = first.path
  await first.release()
  const secondValue = createAppCatalogSnapshotIdentity({
    senderPubkey: PEER,
    highWater: firstValue.highWater + 1,
    rows: firstValue.rows
  })
  const secondStage = await factory.open(metadata(secondValue))
  for (const row of secondValue.rows) await secondStage.append(row, b4a.from(JSON.stringify(row), 'utf8'))

  const opening = factory.openCommittedPeer(PEER)
  await validationEntered.promise
  const second = await secondStage.commit(secondValue)
  t.ok((await lstat(firstPath)).isDirectory(), 'provisional lease excludes actual old-snapshot deletion')
  validationGate.resolve()
  const opened = await opening
  t.is(opened.snapshotId, secondValue.snapshotId, 'pointer is revalidated and acquisition retries current storage')
  t.alike((await opened.readPage({ limit: 2 })).entries, secondValue.rows)
  await t.exception(lstat(firstPath), /ENOENT/)
  await opened.release()
  await second.release()

  validationMode = 'throw'
  await t.exception(factory.openCommittedPeer(PEER), /forced committed validation failure/)
  t.is(await factory.removeCommittedPeer(PEER), true, 'failed provisional validation releases every lease')
})

test('owned path swaps fail closed and preserve outside sentinels without recursive deletion', async (t) => {
  const parents = []
  const factories = []
  t.teardown(async () => {
    await Promise.allSettled(factories.map(factory => factory.stop()))
    await Promise.allSettled(parents.map(path => rm(path, { recursive: true, force: true })))
  })

  const stagingParent = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-staging-swap-')))
  const stagingOutside = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-staging-outside-')))
  parents.push(stagingParent, stagingOutside)
  const stagingRoot = join(stagingParent, 'catalog')
  const stagingFactory = new AppCatalogDiskStageFactory({ rootDir: stagingRoot })
  factories.push(stagingFactory)
  const stagingValue = snapshot()
  const stagingStage = await stagingFactory.open(metadata(stagingValue))
  await writeFile(join(stagingOutside, 'sentinel'), 'staging-safe', { mode: 0o600 })
  await rename(join(stagingRoot, 'staging'), join(stagingRoot, 'staging-owned'))
  await symlink(stagingOutside, join(stagingRoot, 'staging'))
  await t.exception(stagingStage.discard(), /owned|pinned|verified|following links/)
  t.is(await readFile(join(stagingOutside, 'sentinel'), 'utf8'), 'staging-safe')

  const snapshotsParent = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-snapshots-swap-')))
  const snapshotsOutside = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-snapshots-outside-')))
  parents.push(snapshotsParent, snapshotsOutside)
  const snapshotsRoot = join(snapshotsParent, 'catalog')
  const snapshotsFactory = new AppCatalogDiskStageFactory({ rootDir: snapshotsRoot })
  factories.push(snapshotsFactory)
  const snapshotsCatalog = await stageSnapshot(snapshotsFactory, snapshot())
  await snapshotsCatalog.release()
  await writeFile(join(snapshotsOutside, 'sentinel'), 'snapshots-safe', { mode: 0o600 })
  await rename(join(snapshotsRoot, 'snapshots'), join(snapshotsRoot, 'snapshots-owned'))
  await symlink(snapshotsOutside, join(snapshotsRoot, 'snapshots'))
  await t.exception(snapshotsFactory.removeCommittedPeer(PEER), /owned|pinned|verified|following links/)
  t.is(await readFile(join(snapshotsOutside, 'sentinel'), 'utf8'), 'snapshots-safe')

  const peersParent = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-peers-swap-')))
  const peersOutside = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-peers-outside-')))
  parents.push(peersParent, peersOutside)
  const peersRoot = join(peersParent, 'catalog')
  let peersFactory = null
  peersFactory = new AppCatalogDiskStageFactory({
    rootDir: peersRoot,
    beforePointerRename: async ({ temporaryPointer }) => {
      await writeFile(join(peersOutside, 'sentinel'), 'peers-safe', { mode: 0o600 })
      await writeFile(join(peersOutside, basename(temporaryPointer)), 'outside-pointer', { mode: 0o600 })
      await rename(join(peersRoot, 'peers'), join(peersRoot, 'peers-owned'))
      await symlink(peersOutside, join(peersRoot, 'peers'))
      throw new Error('force guarded pointer cleanup')
    }
  })
  factories.push(peersFactory)
  const peersValue = snapshot()
  const peersStage = await peersFactory.open(metadata(peersValue))
  for (const row of peersValue.rows) await peersStage.append(row, b4a.from(JSON.stringify(row), 'utf8'))
  await t.exception(peersStage.commit(peersValue), /owned|pinned|verified|following links/)
  t.is(await readFile(join(peersOutside, 'sentinel'), 'utf8'), 'peers-safe')
  t.is(await readFile((await readdir(peersOutside)).map(name => join(peersOutside, name)).find(path => path.endsWith('.tmp')), 'utf8'), 'outside-pointer')
})

test('owned roots, child directories, and files require private root-derived ownership policy', async (t) => {
  const parent = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-private-')))
  t.teardown(() => rm(parent, { recursive: true, force: true }))

  const permissiveRoot = join(parent, 'permissive-root')
  await mkdir(permissiveRoot, { mode: 0o700 })
  await chmod(permissiveRoot, 0o755)
  const rootFactory = new AppCatalogDiskStageFactory({ rootDir: permissiveRoot })
  await t.exception(rootFactory.ready(), /private owner-only/)

  const root = join(parent, 'catalog')
  const factory = new AppCatalogDiskStageFactory({ rootDir: root })
  await factory.ready()
  await chmod(join(root, 'staging'), 0o750)
  const childFactory = new AppCatalogDiskStageFactory({ rootDir: root })
  await t.exception(childFactory.ready(), /private owner-only/)
  await chmod(join(root, 'staging'), 0o700)

  const catalog = await stageSnapshot(factory, snapshot())
  await catalog.release()
  const pointerPath = join(root, 'peers', `${PEER}.json`)
  await chmod(pointerPath, 0o644)
  await t.exception(factory.openCommittedPeer(PEER), /private owner-only/)
  await chmod(pointerPath, 0o600)
  await factory.stop()
})

test('direct discard waits for the stage commit mutation owner', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-stage-exclusive-')))
  const commitEntered = deferred()
  const commitGate = deferred()
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    onDurabilityBarrier: async name => {
      if (name === 'staged-files-synced') {
        commitEntered.resolve()
        await commitGate.promise
      }
    }
  })
  t.teardown(async () => {
    await factory.stop()
    await rm(root, { recursive: true, force: true })
  })
  const value = snapshot()
  const stage = await factory.open(metadata(value))
  for (const row of value.rows) await stage.append(row, b4a.from(JSON.stringify(row), 'utf8'))
  const committing = stage.commit(value)
  await commitEntered.promise
  let discarded = false
  const discarding = stage.discard().then(() => { discarded = true })
  await nextTurn()
  t.is(discarded, false, 'discard cannot delete files owned by an in-flight commit')
  commitGate.resolve()
  const catalog = await committing
  await discarding
  t.ok((await lstat(catalog.path)).isDirectory(), 'successful pointer publication remains authoritative')
  await catalog.release()
})

test('factory stop retains a failed discard owner and retries the exact unresolved cleanup', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-stop-retry-')))
  let discardFailures = 1
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    onDurabilityBarrier: name => {
      if (name === 'discarded-stage-directory-synced' && discardFailures > 0) {
        discardFailures--
        throw new Error('forced discard durability failure')
      }
    }
  })
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const stage = await factory.open(metadata(snapshot()))

  const firstStop = factory.stop()
  t.is(factory.stop(), firstStop, 'concurrent callers share the current terminal attempt')
  await t.exception(firstStop, /forced discard durability failure/)
  t.is(stage.closed, false, 'failed terminal drain is not certified closed')
  t.ok(factory._active.has(stage), 'failed stage remains an exact retry owner')
  t.ok(factory._activePeers.has(PEER), 'peer ownership is retained with failed cleanup')

  const retryStop = factory.stop()
  t.ok(retryStop !== firstStop, 'a rejected attempt is retryable without reopening ingress')
  await retryStop
  t.is(factory.stop(), retryStop, 'successful terminal authority remains exact-idempotent')
  t.is(stage.closed, true)
  t.is(factory._active.size, 0)
  t.is(factory._activePeers.size, 0)
})

test('discard preserves and retries each exact rows or index handle close', async (t) => {
  const parents = []
  t.teardown(() => Promise.allSettled(parents.map(path => rm(path, { recursive: true, force: true }))))
  for (const field of ['rowsHandle', 'indexHandle']) {
    const root = await realpath(await mkdtemp(join(tmpdir(), `hiverelay-catalog-${field}-retry-`)))
    parents.push(root)
    const factory = new AppCatalogDiskStageFactory({ rootDir: root })
    const stage = await factory.open(metadata(snapshot()))
    const handle = stage[field]
    const close = handle.close.bind(handle)
    let closeAttempts = 0
    handle.close = async () => {
      closeAttempts++
      if (closeAttempts === 1) throw new Error(`forced ${field} close failure`)
      return close()
    }

    const firstDiscard = stage.discard()
    t.is(stage.discard(), firstDiscard, `${field}: concurrent discard shares one attempt`)
    await t.exception(firstDiscard, new RegExp(`forced ${field} close failure`))
    t.is(stage[field], handle, `${field}: rejected close retains the exact handle`)
    t.is(stage.closed, false, `${field}: failed close cannot certify terminal state`)
    t.ok(factory._active.has(stage), `${field}: factory retains the cleanup owner`)

    const retryDiscard = stage.discard()
    t.ok(retryDiscard !== firstDiscard, `${field}: failed close is retried`)
    await retryDiscard
    t.is(stage[field], null, `${field}: handle is cleared only after close succeeds`)
    t.is(closeAttempts, 2, `${field}: successful handle is never double-closed`)
    await factory.stop()
  }
})

test('open index failure retains a rows handle whose close fails until stop retry succeeds', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-open-close-retry-')))
  const factory = new AppCatalogDiskStageFactory({ rootDir: root })
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const openExclusive = factory._openExclusive.bind(factory)
  let rowsCloseAttempts = 0
  factory._openExclusive = async path => {
    if (basename(path) === 'index.bin') throw new Error('forced index open failure')
    const handle = await openExclusive(path)
    if (basename(path) === 'rows.bin') {
      const close = handle.close.bind(handle)
      handle.close = async () => {
        rowsCloseAttempts++
        if (rowsCloseAttempts < 3) throw new Error('forced rows cleanup close failure')
        return close()
      }
    }
    return handle
  }

  await t.exception(factory.open(metadata(snapshot())), /forced rows cleanup close failure/)
  t.is(factory._failedOpenCleanups.size, 1, 'failed open retains its exact cleanup owner')
  t.ok(factory._activePeers.has(PEER), 'peer reservation remains owned until cleanup')
  const firstStop = factory.stop()
  t.is(factory.stop(), firstStop)
  await t.exception(firstStop, /forced rows cleanup close failure/)
  t.is(factory._failedOpenCleanups.size, 1)
  const retryStop = factory.stop()
  await retryStop
  t.is(rowsCloseAttempts, 3)
  t.is(factory._failedOpenCleanups.size, 0)
  t.is(factory._activePeers.size, 0)
  t.alike(await readdir(join(root, 'staging')), [])
})

test('commit preserves an index handle failure after closing rows and discard retries only unresolved ownership', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-commit-close-retry-')))
  const factory = new AppCatalogDiskStageFactory({ rootDir: root })
  t.teardown(async () => {
    await factory.stop()
    await rm(root, { recursive: true, force: true })
  })
  const value = snapshot()
  const stage = await factory.open(metadata(value))
  for (const row of value.rows) await stage.append(row, b4a.from(JSON.stringify(row), 'utf8'))
  const rowsHandle = stage.rowsHandle
  const indexHandle = stage.indexHandle
  const closeRows = rowsHandle.close.bind(rowsHandle)
  const closeIndex = indexHandle.close.bind(indexHandle)
  let rowsCloseAttempts = 0
  let indexCloseAttempts = 0
  rowsHandle.close = async () => {
    rowsCloseAttempts++
    return closeRows()
  }
  indexHandle.close = async () => {
    indexCloseAttempts++
    if (indexCloseAttempts === 1) throw new Error('forced commit index close failure')
    return closeIndex()
  }

  await t.exception(stage.commit(value), /forced commit index close failure/)
  t.is(stage.rowsHandle, null, 'successfully closed rows ownership is cleared immediately')
  t.is(stage.indexHandle, indexHandle, 'failed index close remains exact and retryable')
  t.is(rowsCloseAttempts, 1)
  t.is(indexCloseAttempts, 1)
  await stage.discard()
  t.is(rowsCloseAttempts, 1, 'discard never double-closes the proven rows handle')
  t.is(indexCloseAttempts, 2, 'discard retries the unresolved index handle once')
  t.is(stage.indexHandle, null)
})

test('failed last-lease reclaim remains a stop-owned retry until its durability phases settle', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-reclaim-retry-')))
  let barrierFailures = 2
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    onDurabilityBarrier: name => {
      if (name === 'prior-snapshot-removed' && barrierFailures > 0) {
        barrierFailures--
        throw new Error('forced retained reclaim failure')
      }
    }
  })
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const firstValue = snapshot()
  const first = await stageSnapshot(factory, firstValue)
  const secondValue = createAppCatalogSnapshotIdentity({
    senderPubkey: PEER,
    highWater: firstValue.highWater + 1,
    rows: firstValue.rows
  })
  const second = await stageSnapshot(factory, secondValue)

  await t.exception(first.release(), /forced retained reclaim failure/)
  t.is(factory._failedReclaims.size, 1, 'last lease hands failed disk work to a retained factory owner')
  const firstStop = factory.stop()
  t.is(factory.stop(), firstStop)
  await t.exception(firstStop, /forced retained reclaim failure/)
  t.is(factory._failedReclaims.size, 1, 'rejected stop retains the exact reclaim phase')
  const retryStop = factory.stop()
  await retryStop
  t.is(factory._failedReclaims.size, 0)
  t.is(barrierFailures, 0)
  await second.release()
})

test('failed-open cleanup retains its parent durability phase until stop retry', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-open-durable-retry-')))
  let barrierFailures = 2
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    onDurabilityBarrier: name => {
      if (name === 'failed-open-staging-directory-synced' && barrierFailures > 0) {
        barrierFailures--
        throw new Error('forced failed-open parent barrier failure')
      }
    }
  })
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const openExclusive = factory._openExclusive.bind(factory)
  factory._openExclusive = path => {
    if (basename(path) === 'index.bin') throw new Error('forced index acquisition failure')
    return openExclusive(path)
  }

  await t.exception(factory.open(metadata(snapshot())), /failed-open parent barrier failure/)
  const cleanup = [...factory._failedOpenCleanups][0]
  t.ok(cleanup.directoryRemoved, 'directory removal is checkpointed before the failed barrier')
  t.ok(cleanup.directorySynced, 'parent fsync is checkpointed before the failed barrier')
  t.is(cleanup.syncBarrierPassed, false)
  t.ok(factory._activePeers.has(PEER), 'reservation remains owned through durability failure')

  await t.exception(factory.stop(), /failed-open parent barrier failure/)
  t.is(factory._failedOpenCleanups.size, 1)
  await factory.stop()
  t.is(factory._failedOpenCleanups.size, 0)
  t.is(factory._activePeers.size, 0)
  t.is(barrierFailures, 0)
})

test('published pointer durability remains stage-owned and retryable after rename', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-published-durable-retry-')))
  let barrierFailures = 2
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    onDurabilityBarrier: name => {
      if (name === 'peers-directory-synced' && barrierFailures > 0) {
        barrierFailures--
        throw new Error('forced published pointer barrier failure')
      }
    }
  })
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const value = snapshot()
  const stage = await factory.open(metadata(value))
  for (const row of value.rows) await stage.append(row, b4a.from(JSON.stringify(row), 'utf8'))

  await t.exception(stage.commit(value), /published pointer barrier failure/)
  t.ok(stage.publishedPointer, 'renamed pointer tuple remains on the exact active stage')
  t.is(stage.closed, false)
  t.ok(factory._active.has(stage), 'factory retains the committed-but-unsettled durability owner')
  const pointer = JSON.parse(await readFile(join(root, 'peers', `${PEER}.json`), 'utf8'))
  t.ok((await lstat(join(root, 'snapshots', pointer.directory))).isDirectory(), 'published pointer never dangles')

  await t.exception(factory.stop(), /published pointer barrier failure/)
  t.ok(factory._active.has(stage), 'failed stop retains the same published stage')
  await factory.stop()
  t.is(stage.closed, true)
  t.is(factory._active.size, 0)
  t.is(barrierFailures, 0)
  t.ok((await lstat(join(root, 'snapshots', pointer.directory))).isDirectory())
})

test('stop retires a prior snapshot transferred by a published replacement', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-published-replacement-stop-')))
  let failPublishedBarrier = false
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    onDurabilityBarrier: name => {
      if (name === 'peers-directory-synced' && failPublishedBarrier) {
        failPublishedBarrier = false
        throw new Error('forced replacement pointer barrier failure')
      }
    }
  })
  t.teardown(() => rm(root, { recursive: true, force: true }))

  const firstValue = snapshot()
  const first = await stageSnapshot(factory, firstValue)
  const priorPath = first.path
  await first.release()
  const replacement = createAppCatalogSnapshotIdentity({
    senderPubkey: PEER,
    highWater: firstValue.highWater + 1,
    rows: firstValue.rows
  })
  const stage = await factory.open(metadata(replacement))
  for (const row of replacement.rows) await stage.append(row, b4a.from(JSON.stringify(row), 'utf8'))

  failPublishedBarrier = true
  await t.exception(stage.commit(replacement), /replacement pointer barrier failure/)
  t.ok((await lstat(priorPath)).isDirectory(), 'the superseded snapshot exists before stop settles the published replacement')
  t.ok(stage.priorPointer, 'the active stage retains the prior pointer before stop')
  t.is((await readdir(join(root, 'snapshots'))).length, 2)

  await factory.stop()
  await t.exception(lstat(priorPath), /ENOENT/)
  t.is((await readdir(join(root, 'snapshots'))).length, 1, 'stop retires the prior snapshot before certifying terminal state')
  t.is(stage.priorPointer, null)
  t.is(factory._failedReclaims.size, 0)
  t.is(factory._active.size, 0)
})

test('stop retains and retries a failed prior retirement transferred after discard', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'hiverelay-catalog-published-reclaim-retry-')))
  let failPublishedBarrier = false
  let failRetirementBarrier = true
  const factory = new AppCatalogDiskStageFactory({
    rootDir: root,
    onDurabilityBarrier: name => {
      if (name === 'peers-directory-synced' && failPublishedBarrier) {
        failPublishedBarrier = false
        throw new Error('forced replacement pointer barrier failure')
      }
      if (name === 'prior-snapshot-removed' && failRetirementBarrier) {
        failRetirementBarrier = false
        throw new Error('forced transferred retirement barrier failure')
      }
    }
  })
  t.teardown(() => rm(root, { recursive: true, force: true }))

  const firstValue = snapshot()
  const first = await stageSnapshot(factory, firstValue)
  const priorPath = first.path
  const priorDirectory = basename(priorPath)
  await first.release()
  const replacement = createAppCatalogSnapshotIdentity({
    senderPubkey: PEER,
    highWater: firstValue.highWater + 1,
    rows: firstValue.rows
  })
  const stage = await factory.open(metadata(replacement))
  for (const row of replacement.rows) await stage.append(row, b4a.from(JSON.stringify(row), 'utf8'))

  failPublishedBarrier = true
  await t.exception(stage.commit(replacement), /replacement pointer barrier failure/)
  t.ok((await lstat(priorPath)).isDirectory(), 'the superseded snapshot exists before stop')

  await t.exception(factory.stop(), /transferred retirement barrier failure/)
  const retained = factory._failedReclaims.get(priorDirectory)
  t.ok(retained, 'the failed retirement remains factory-owned')
  t.is(retained.pointer.directory, priorDirectory)
  t.is(retained.directoryRemoved, true, 'the completed unlink phase is checkpointed')
  t.is(stage.priorPointer, null, 'the stage transfers ownership exactly once')
  t.is(factory._active.size, 0)

  await factory.stop()
  t.is(factory._failedReclaims.size, 0)
  t.is((await readdir(join(root, 'snapshots'))).length, 1)
  await t.exception(lstat(priorPath), /ENOENT/)
})

test('peer removal checkpoints pointer and snapshot unlink durability for stop retry', async (t) => {
  const roots = []
  t.teardown(() => Promise.allSettled(roots.map(path => rm(path, { recursive: true, force: true }))))
  for (const barrier of ['removed-peer-directory-synced', 'removed-snapshot-directory-synced']) {
    const root = await realpath(await mkdtemp(join(tmpdir(), `hiverelay-catalog-peer-remove-${barrier}-`)))
    roots.push(root)
    let barrierFailures = 2
    const factory = new AppCatalogDiskStageFactory({
      rootDir: root,
      onDurabilityBarrier: name => {
        if (name === barrier && barrierFailures > 0) {
          barrierFailures--
          throw new Error(`forced ${barrier} failure`)
        }
      }
    })
    const catalog = await stageSnapshot(factory, snapshot())
    const snapshotPath = catalog.path
    await catalog.release()

    await t.exception(factory.removeCommittedPeer(PEER), new RegExp(`forced ${barrier} failure`))
    const pending = factory._failedPeerRemovals.get(PEER)
    t.ok(pending, `${barrier}: exact phase owner is retained`)
    t.is(pending.pointerRemoved, true, `${barrier}: pointer unlink is checkpointed`)
    await t.exception(lstat(join(root, 'peers', `${PEER}.json`)), /ENOENT/)
    if (barrier === 'removed-peer-directory-synced') {
      t.ok((await lstat(snapshotPath)).isDirectory(), 'snapshot remains until pointer durability settles')
    } else {
      t.is(pending.snapshotRemoved, true, 'snapshot unlink is checkpointed before its barrier')
      await t.exception(lstat(snapshotPath), /ENOENT/)
    }

    await t.exception(factory.stop(), new RegExp(`forced ${barrier} failure`))
    t.is(factory._failedPeerRemovals.get(PEER), pending, `${barrier}: stop retains the exact owner`)
    await factory.stop()
    t.is(factory._failedPeerRemovals.size, 0)
    t.is(barrierFailures, 0)
    await t.exception(lstat(snapshotPath), /ENOENT/)
  }
})

test('committed validation and page reads retain exact transient handles on close failure', async (t) => {
  const roots = []
  t.teardown(() => Promise.allSettled(roots.map(path => rm(path, { recursive: true, force: true }))))
  for (const mode of ['validation', 'read']) {
    const root = await realpath(await mkdtemp(join(tmpdir(), `hiverelay-catalog-${mode}-close-retry-`)))
    roots.push(root)
    const factory = new AppCatalogDiskStageFactory({ rootDir: root })
    const committed = await stageSnapshot(factory, snapshot())
    const openOwnedRead = factory._openOwnedRead.bind(factory)
    let closeAttempts = 0
    let wrapped = false
    factory._openOwnedRead = async (...args) => {
      const opened = await openOwnedRead(...args)
      const isTarget = basename(args[0]) === (mode === 'validation' ? 'index.bin' : 'rows.bin')
      if (isTarget && !wrapped) {
        wrapped = true
        const close = opened.handle.close.bind(opened.handle)
        opened.handle.close = async () => {
          closeAttempts++
          if (closeAttempts < 3) throw new Error(`forced ${mode} transient close failure`)
          return close()
        }
      }
      return opened
    }

    if (mode === 'validation') {
      await committed.release()
      await t.exception(factory.openCommittedPeer(PEER), /validation transient close failure/)
    } else {
      await t.exception(committed.readPage({ limit: 1 }), /read transient close failure/)
      await committed.release()
    }
    t.is(factory._failedHandleClosures.size, 1, `${mode}: exact transient handle is factory-owned`)
    await t.exception(factory.stop(), new RegExp(`${mode} transient close failure`))
    t.is(factory._failedHandleClosures.size, 1, `${mode}: failed stop retains the handle`)
    await factory.stop()
    t.is(factory._failedHandleClosures.size, 0)
    t.is(closeAttempts, 3, `${mode}: only the unresolved handle is retried`)
  }
})
