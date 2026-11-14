import test from 'brittle'
import { execFileSync } from 'child_process'
import { createHash } from 'crypto'
import { mkdtempSync, mkdirSync, chmodSync, realpathSync, writeFileSync } from 'fs'
import { rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import Hyperdrive from 'hyperdrive'
import Hyperbee from 'hyperbee'
import createTestnet from '@hyperswarm/testnet'
import { initializeCorestoreGenerationEnvelope, corestoreGenerationOpenOptions, corestoreGenerationParticipantOptions, openCorestore } from '../../packages/core/core/persistence/storage-root-restore.js'
import { retainedReadCanonicalBytes, retainedReadRowSha256 } from '../../packages/core/core/retained-read-capability.js'
import { inspectRetainedReadCapability } from '../../packages/core/core/retained-read-inspection.js'
import { RelayNode } from '../../packages/core/core/relay-node/index.js'

const sha = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex')
function recovered (node) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('recovery timeout')), 15000)
    node.once('reseeded', () => { clearTimeout(timeout); resolve() })
    node.once('reseed-error', err => { clearTimeout(timeout); reject(err.error) })
  })
}
async function fixture (t, { inspectMissing = false } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'hr-retained-read-')))
  const storage = join(root, 'envelope'); mkdirSync(storage, { mode: 0o700 })
  const ceremony = initializeCorestoreGenerationEnvelope(storage, { participants: ['relay-node'], topLevelSidecars: ['app-registry.json', 'app-registry.json.bak', 'evicted.json', 'evicted.json.bak', 'relay-identity.json', 'seeded-cores.json', 'app-catalog-paged', 'manifests.json', 'reputation.json'] })
  const generation = corestoreGenerationOpenOptions(ceremony)
  const store = openCorestore(storage, corestoreGenerationParticipantOptions(generation, 'relay-node'))
  await store.ready()
  const drive = new Hyperdrive(store.session()); await drive.ready()
  const content = Buffer.alloc(190000)
  for (let i = 0; i < content.length; i++) content[i] = i % 251
  await drive.put('/payload.bin', content)
  await drive.put('/index.html', Buffer.from('<html><body>retained</body></html>'))
  const key = drive.key.toString('hex')
  const row = { appKey: key, type: 'app', appId: 'retained-public-fixture', privacyTier: 'public', name: 'Retained', startedAt: 1700000000000, maxStorage: null, publisherPubkey: 'a'.repeat(64), revocable: false }
  const registry = new Hyperbee(store.get({ name: 'app-registry-v1' }), { keyEncoding: 'utf-8', valueEncoding: 'json' })
  await registry.ready(); await registry.put(key, row)
  const missingKey = '1'.repeat(64)
  if (inspectMissing) await registry.put(missingKey, { ...row, appKey: missingKey })
  const inspection = await inspectRetainedReadCapability({ store, storageRoot: storage, hiverelayGeneration: generation, sourceQualificationSha256: sha(Buffer.from('synthetic qualification')), limits: { maxCoreBlocks: 1024, maxLocalBytes: 10 * 1024 * 1024 } })
  const manifest = inspection.proposal
  t.is(inspection.report.selectedDrives, 1, 'offline inspector selects the actual existing drive')
  t.is(inspection.report.registryUnchanged, true)
  if (!inspectMissing) t.is(inspection.report.registry.rawSha256, createHash('sha256').update(JSON.stringify([{ key, value: row }])).digest('hex'))
  if (inspectMissing) {
    t.alike(inspection.report.excluded, [{ appKey: missingKey, reason: 'missing-local-core', category: 'local-presence' }])
    t.is(inspection.report.activeInventoryAccountedFor, true)
    const options = { store, storageRoot: storage, hiverelayGeneration: generation, sourceQualificationSha256: sha(Buffer.from('synthetic qualification')), limits: { maxCoreBlocks: 1024, maxLocalBytes: 10 * 1024 * 1024 } }
    await t.exception(inspectRetainedReadCapability({ ...options, selectedAppKeys: [missingKey] }), /required existing core is missing/)
    await t.exception(inspectRetainedReadCapability({ ...options, limits: { maxCoreBlocks: 1, maxLocalBytes: 1024 } }), /aggregate block limit exceeded/)
  }
  t.is(inspection.report.registry.rawAfterSha256, inspection.report.registry.rawSha256)
  t.is(inspection.report.coreInventoryBefore.sha256, inspection.report.coreInventoryAfter.sha256)
  const authority = join(root, 'authority'); mkdirSync(authority, { mode: 0o700 })
  const manifestPath = join(authority, 'capability.json'); const pinPath = join(authority, 'capability.sha256')
  const bytes = retainedReadCanonicalBytes(manifest)
  writeFileSync(manifestPath, bytes, { mode: 0o444 }); writeFileSync(pinPath, sha(bytes) + '\n', { mode: 0o444 })
  const nativeRoot = process.platform === 'linux' && process.getuid() === 0
  let authorityMounted = false
  if (nativeRoot) {
    if (process.env.HIVERELAY_RETAINED_TEST_NATIVE_MOUNTS !== '1') throw new Error('Linux root retained test requires explicit disposable mount namespace')
    execFileSync('mount', ['--bind', authority, authority]); authorityMounted = true
    execFileSync('mount', ['-o', 'remount,bind,ro', authority])
    t.exception(() => chmodSync(manifestPath, 0o600), { code: 'EROFS' }, 'root cannot chmod mounted authority')
    t.exception(() => writeFileSync(join(authority, 'replacement'), 'x'), { code: 'EROFS' }, 'root cannot replace authority through parent')
  }
  const baseline = { length: registry.core.length, byteLength: registry.core.byteLength, row: retainedReadRowSha256(row) }
  await registry.close(); await drive.close(); await store.close()
  const testnet = await createTestnet(2, t)
  let node = null
  t.teardown(async () => { if (node) await node.stop(); if (authorityMounted) { execFileSync('umount', [authority]); authorityMounted = false }; chmodSync(manifestPath, 0o600); chmodSync(pinPath, 0o600); await rm(root, { recursive: true, force: true }) })
  const config = { storage, hiverelayGeneration: generation, maxStorageBytes: 1024 ** 3, bootstrapNodes: testnet.bootstrap, bootstrapCacheEnabled: false, enableAPI: true, apiPort: 0, apiHost: '127.0.0.1', enableRelay: false, enableSeeding: true, enableServices: false, plugins: [], enableNetworkDiscovery: false, enableHolesail: false, autoHeal: { enabled: false }, retainedReadCapability: { manifestPath, pinPath } }
  return { root, storage, key, content, row, manifest, config, baseline, async start () { node = new RelayNode(config); const wait = recovered(node); await node.start(); await wait; return node }, async stop () { await node.stop(); node = null } }
}

test('selected retained snapshots serve first/cold HTTP bytes and ranges without changing unknown authority', async t => {
  const f = await fixture(t)
  for (const cycle of ['first', 'cold']) {
    const node = await f.start()
    node.api._gateway.on('drive-error', event => t.comment(JSON.stringify(event)))
    const base = `http://127.0.0.1:${node.api.server.address().port}/v1/hyper/${f.key}`
    const local = node.appRegistry.get(f.key)
    t.is(local.maxStorage, null, cycle + ': bound remains unknown')
    t.is(local.anchored, false, cycle + ': no modern anchor invented')
    t.is(node.storageAdmission.canAcknowledge('drive:' + f.key), false, cycle + ': no ACK grant')
    const probe = await node.retainedReadController.acquire(f.key)
    try { t.alike(await probe.drive.get('/payload.bin'), f.content, 'direct facade bytes') } catch (error) { console.error(error.stack); throw error } finally { await probe.drive.close(); probe.release() }
    const res = await fetch(base + '/payload.bin', { signal: AbortSignal.timeout(10000) })
    t.is(res.status, 200, cycle + ': retained file available')
    t.is(res.headers.get('x-hive-read-scope'), 'retained-local-snapshot')
    t.alike(Buffer.from(await res.arrayBuffer()), f.content, cycle + ': exact signed local body')
    const range = await fetch(base + '/payload.bin', { headers: { Range: 'bytes=64000-131999' }, signal: AbortSignal.timeout(10000) })
    t.is(range.status, 206)
    t.alike(Buffer.from(await range.arrayBuffer()), f.content.subarray(64000, 132000), cycle + ': exact range across blocks')
    const head = await fetch(base + '/payload.bin', { method: 'HEAD' })
    t.is(head.status, 200); t.is(head.headers.get('content-length'), String(f.content.length)); t.is((await head.arrayBuffer()).byteLength, 0)
    const html = await fetch(base + '/')
    t.is(html.status, 200); t.is(await html.text(), '<html><body>retained</body></html>')
    const verify = await fetch(base + '/payload.bin?verify=1')
    t.is(verify.status, 501, 'retained lane explicitly refuses verify bundle'); await verify.arrayBuffer()
    const list = await fetch(base + '/absent-directory/')
    t.is(list.status, 501, 'retained lane explicitly refuses directory listing'); await list.arrayBuffer()
    t.is(node.storageAdmission.reserve('core:' + 'f'.repeat(64), 1, { kind: 'core' }).reason, 'storage-commitment-unknown')
    t.is(node.appRegistry._bee.core.length, f.baseline.length)
    t.is(node.appRegistry._bee.core.byteLength, f.baseline.byteLength)
    t.is(retainedReadRowSha256((await node.appRegistry._bee.get(f.key)).value), f.baseline.row)
    const lease = await node.retainedReadController.acquire(f.key)
    t.ok(Object.isFrozen(lease.drive)); t.alike(Object.keys(node.retainedReadController), [], 'controller hides mutable selected authority')
    for (const name of ['owner', 'metadata', 'blobReader', 'bee', 'blobs', 'core', 'store']) t.absent(lease.drive[name], 'read facade hides ' + name)
    await lease.drive.close(); lease.release()
    await f.stop()
  }
})

test('offline selection accounts for missing local cores without creating them or silently selecting them', async t => {
  await fixture(t, { inspectMissing: true })
})
