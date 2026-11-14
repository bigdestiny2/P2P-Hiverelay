import test from 'brittle'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import Hyperbee from 'hyperbee'
import createTestnet from '@hyperswarm/testnet'
import { createHash } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { RelayNode } from '../../packages/core/core/relay-node/index.js'
import { getDriveSize } from '../../packages/core/core/relay-node/cancellable-drive-update.js'

async function coreState (core) {
  const h = createHash('sha256')
  for (let i = 0; i < core.length; i++) {
    const bytes = await core.get(i, { wait: false, valueEncoding: 'binary' })
    h.update(String(bytes.length) + ':').update(bytes)
  }
  return { length: core.length, byteLength: core.byteLength, fork: core.fork, sha256: h.digest('hex') }
}
function recoveryEvent (node) {
  let timer
  const operation = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error('retained drive recovery timed out')), 15000)
    node.once('reseeded', resolve)
    node.once('reseed-error', event => reject(event.error))
  })
  return operation.finally(() => clearTimeout(timer))
}

async function storedCoreKeys (store) {
  const keys = []
  for await (const key of store.list()) keys.push(key.toString('hex'))
  return keys.sort()
}

async function testRetainedMetadata (t, maxStorage) {
  const storage = await mkdtemp(join(tmpdir(), 'hr-reseed-metadata-'))
  const testnet = await createTestnet(2, t)
  let node = null
  t.teardown(async () => { if (node) await node.stop(); await rm(storage, { recursive: true, force: true }) })
  const store = new Corestore(storage)
  await store.ready()
  const drive = new Hyperdrive(store)
  await drive.ready()
  const payload = Buffer.from('retained application content')
  await drive.put('/payload', payload)
  const appKey = drive.key.toString('hex')
  const record = {
    appKey,
    appId: 'retained-app-id',
    type: 'app',
    version: '3.2.1',
    name: 'Retained display name',
    description: 'Retained application description',
    author: 'Retained author',
    icon: '/retained-icon.svg',
    categories: ['retained-category'],
    startedAt: 1700000000000,
    publisherPubkey: 'a'.repeat(64),
    durability: 2,
    revocable: false,
    retainUntil: Date.now() + 24 * 60 * 60 * 1000,
    leaseManaged: true,
    storageClass: 'persistent',
    availabilityClass: 'always-on',
    maxStorage,
    anchored: true,
    // A legacy boolean cannot manufacture a current complete storage proof.
    unseedFreezeMs: 30000,
    futureMetadata: { preserved: 'opaque legacy metadata' }
  }
  if (maxStorage !== null) {
    const proof = await getDriveSize(drive, { requireAuthoritative: true })
    Object.assign(record, {
      anchoredAt: 1700000001000,
      anchoredLength: proof.driveVersion,
      storageProvedDriveVersion: proof.driveVersion,
      storageProvedMetaLength: proof.metaLength,
      storageProvedBlobLength: proof.blobLength,
      storageProvedTotalBytes: proof.totalBytes,
      storageProvedMetaFork: proof.metaFork,
      storageProvedBlobFork: proof.blobFork
    })
  }
  const bee = new Hyperbee(store.get({ name: 'app-registry-v1' }), { keyEncoding: 'utf-8', valueEncoding: 'json' })
  await bee.ready(); await bee.put(appKey, record)
  const expectedCore = await coreState(bee.core)
  await bee.close(); await drive.close(); await store.close()

  for (const cycle of ['first', 'cold']) {
    node = new RelayNode({ storage, maxStorageBytes: 1024 ** 3, bootstrapNodes: testnet.bootstrap, bootstrapCacheEnabled: false, enableAPI: true, apiPort: 0, apiHost: '127.0.0.1', enableRelay: false, enableSeeding: true, enableServices: false, plugins: [], enableNetworkDiscovery: false, enableHolesail: false, autoHeal: { enabled: false } })
    let eager = 0
    let persistent = 0
    let persistentOperation = null
    if (maxStorage !== null) {
      // Observe the writable recovery scheduling boundary without letting an
      // independent anchor-proof update obscure this exact boot-row assertion.
      // The unknown-bound case exercises both real replication guards below.
      node.appLifecycle._trackEagerReplicate = () => { eager++ }
      const register = node.appLifecycle._registerPersistentDownloads.bind(node.appLifecycle)
      node.appLifecycle._registerPersistentDownloads = (key, retainedDrive, tracked = false) => {
        if (!tracked) persistent++
        const operation = register(key, retainedDrive, tracked)
        if (!tracked) persistentOperation = operation
        return operation
      }
    }
    const recovered = recoveryEvent(node)
    await node.start(); await recovered
    if (persistentOperation) await persistentOperation
    const entry = node.appRegistry.get(appKey)
    for (const name of ['appId', 'version', 'name', 'description', 'author', 'icon', 'categories', 'startedAt', 'publisherPubkey', 'durability', 'revocable', 'retainUntil', 'leaseManaged', 'maxStorage']) {
      t.alike(entry[name], record[name], cycle + ': ' + name + ' preserved in the serving entry')
    }
    t.is(entry.anchored, maxStorage !== null, cycle + ': only the complete measured storage proof qualifies the anchor')
    t.is(node.appRegistry.physicalReadOnly, false, cycle + ': finite registry journal remains writable')
    t.ok(entry.drive && Buffer.isBuffer(entry.discoveryKey), cycle + ': current process owns serving handles')
    t.alike(await entry.drive.get('/payload', { wait: false }), payload, cycle + ': retained content remains readable')
    const beforeKeys = await storedCoreKeys(node.store)
    const beforeMeta = await coreState(entry.drive.core)
    const beforeBlob = await coreState(entry.drive.blobs.core)
    const response = await fetch(`http://127.0.0.1:${node.api.server.address().port}/v1/hyper/${appKey}/payload`, { signal: AbortSignal.timeout(10000) })
    if (maxStorage === null) {
      t.is(response.status, 404, cycle + ': HTTP refuses to invent a missing storage proof')
      t.alike(await response.json(), { error: 'Drive not available yet — still replicating' }, cycle + ': missing-proof response remains explicit')
    } else {
      t.is(response.status, 200, cycle + ': actual HTTP gateway serves retained content')
      t.alike(Buffer.from(await response.arrayBuffer()), payload, cycle + ': HTTP content bytes are exact')
    }
    t.alike(await storedCoreKeys(node.store), beforeKeys, cycle + ': HTTP read creates no stored core')
    t.alike(await coreState(entry.drive.core), beforeMeta, cycle + ': HTTP read leaves metadata history unchanged')
    t.alike(await coreState(entry.drive.blobs.core), beforeBlob, cycle + ': HTTP read leaves payload history unchanged')
    if (maxStorage === null) {
      t.is(node.storageAdmission.get('drive:' + appKey).state, 'unknown-recovery', cycle + ': missing old bound remains unknown')
      t.is(node.storageAdmission.reserve('core:' + 'f'.repeat(64), 1, { kind: 'core' }).reason, 'storage-commitment-unknown', cycle + ': fresh growth stays denied')
      t.absent(entry.downloadRanges?.length, cycle + ': unknown bound registers no body download ranges')
      t.absent(entry.downloadRegistration, cycle + ': unknown bound retains no pending download registration')
    } else {
      t.is(node.storageAdmission.get('drive:' + appKey).boundBytes, maxStorage, cycle + ': finite durable bound stays exact')
      t.is(eager, 1, cycle + ': writable recovery still schedules eager replication')
      t.is(persistent, 1, cycle + ': writable recovery still schedules persistent replication')
    }
    t.alike((await node.appRegistry._bee.get(appKey)).value, record, cycle + ': complete raw row including opaque fields unchanged')
    t.alike(await coreState(node.appRegistry._bee.core), expectedCore, cycle + ': registry blocks and metadata debt unchanged')
    await node.stop(); node = null
    const reopened = new Corestore(storage)
    await reopened.ready()
    const verify = new Hyperbee(reopened.get({ name: 'app-registry-v1' }), { keyEncoding: 'utf-8', valueEncoding: 'json' })
    try { await verify.ready(); t.alike((await verify.get(appKey)).value, record, cycle + ': shutdown preserves the entire durable row'); t.alike(await coreState(verify.core), expectedCore, cycle + ': shutdown appends no registry history') } finally { await verify.close(); await reopened.close() }
  }
}

test('RelayNode first/cold recovery preserves unknown-bound metadata and local bytes without authorizing HTTP or growth', async t => {
  await testRetainedMetadata(t, null)
})

test('RelayNode first/cold finite-bound recovery preserves metadata and schedules normal replication', async t => {
  await testRetainedMetadata(t, 1024 * 1024)
})
