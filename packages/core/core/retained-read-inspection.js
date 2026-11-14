/** Offline proposal builder. It opens existing keys only and never enables a
 * retained capability or changes a registry row, commitment or core body. */
import { createHash } from 'crypto'
import { realpathSync, statSync } from 'fs'
import Hypercore from 'hypercore'
import Hyperdrive from 'hyperdrive'
import Hyperbee from 'hyperbee'
import { AppRegistry } from './app-registry.js'
import { corestoreGenerationStatus, corestoreGenerationPublicConfig } from './persistence/corestore-generation-envelope.js'
import { inspectRetainedReadCore, retainedReadCanonicalBytes, retainedReadRowSha256, RETAINED_READ_LIMITS } from './retained-read-capability.js'

const MAX_INVENTORY_CORES = 250000
const sha = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex')
function assert (condition, message) { if (!condition) throw new Error('RETAINED_INSPECTION: ' + message) }
async function inventory (store) {
  const keys = []
  for await (const key of store.list()) {
    assert(keys.length < MAX_INVENTORY_CORES, 'core inventory count exceeded')
    assert(Buffer.isBuffer(key) && key.length === 32, 'invalid core inventory key')
    keys.push(key.toString('hex'))
  }
  keys.sort()
  return { count: keys.length, sha256: sha(retainedReadCanonicalBytes(keys)) }
}
async function existingCore (store, discoveryKey) {
  if (!await store.getAuth(discoveryKey)) {
    const error = new Error('RETAINED_INSPECTION: required existing core is missing')
    error.code = 'RETAINED_INSPECTION_MISSING_LOCAL'
    throw error
  }
  const core = store.get({ discoveryKey, active: false, writable: false, wait: false })
  try { await core.ready(); return core } catch (error) { await core.close(); throw error }
}

export async function inspectRetainedReadCapability ({ store, storageRoot, hiverelayGeneration, sourceQualificationSha256, limits, selectedAppKeys = null } = {}) {
  assert(Number.isSafeInteger(limits?.maxCoreBlocks) && limits.maxCoreBlocks > 0 && Number.isSafeInteger(limits?.maxLocalBytes) && limits.maxLocalBytes > 0, 'explicit finite block/byte limits required')
  const status = corestoreGenerationStatus(store)
  assert(status?.ready && status.participant === 'relay-node' && status.configuredRoot === storageRoot && realpathSync(storageRoot) === storageRoot, 'exact guarded generation required')
  assert(/^sha256:[0-9a-f]{64}$/.test(sourceQualificationSha256), 'source qualification pin required')
  const generation = corestoreGenerationPublicConfig(hiverelayGeneration)
  assert(!generation.participant, 'selection uses the public generation binding')
  if (selectedAppKeys !== null) assert(Array.isArray(selectedAppKeys) && selectedAppKeys.length > 0 && selectedAppKeys.length <= RETAINED_READ_LIMITS.drives && selectedAppKeys.every((key, i) => /^[0-9a-f]{64}$/.test(key) && (i === 0 || key > selectedAppKeys[i - 1])), 'keys must be explicit, sorted and unique')
  const before = await inventory(store)
  // This read-only alias lookup is the existing Corestore7 namespace owner
  // mapping. A name-only get would silently create a missing registry.
  const registryDiscoveryKey = await store.storage.getAlias({ name: 'app-registry-v1', namespace: store.ns })
  assert(registryDiscoveryKey, 'existing app-registry alias required')
  const registryCore = await existingCore(store, registryDiscoveryKey)
  const bee = new Hyperbee(registryCore, { keyEncoding: 'utf-8', valueEncoding: 'json', extension: false, readonly: true })
  const registry = new AppRegistry(storageRoot, { store })
  registry._bee = bee
  const cores = []; const drives = []; const excluded = []; const used = new Set()
  let examinedBlocks = 0; let verifiedLocalBytes = 0; let inventoryRows
  const inspect = async core => {
    const cached = cores.find(item => item.descriptor.key === core.key.toString('hex'))
    if (cached) return cached.descriptor
    assert(examinedBlocks + core.length <= limits.maxCoreBlocks, 'aggregate block limit exceeded')
    const result = await inspectRetainedReadCore(core, { maxCoreBlocks: limits.maxCoreBlocks - examinedBlocks, maxLocalBytes: limits.maxLocalBytes - verifiedLocalBytes })
    examinedBlocks += core.length; verifiedLocalBytes += result.localBytes; cores.push(result)
    return result.descriptor
  }
  try {
    await bee.ready()
    const registryState = { key: registryCore.key.toString('hex'), length: registryCore.length, byteLength: registryCore.byteLength, fork: registryCore.fork }
    inventoryRows = await registry._readBeeInventory()
    const registryValues = inventoryRows.map(row => ({ key: row.appKey, value: row.entry }))
    const registryDigest = sha(retainedReadCanonicalBytes(registryValues))
    const rawSha256 = createHash('sha256').update(JSON.stringify(registryValues)).digest('hex')
    for (const row of inventoryRows) {
      assert(typeof row.appKey === 'string' && /^[0-9a-f]{64}$/.test(row.appKey), 'invalid registry app key')
      if (row.tombstone) continue
      if (selectedAppKeys && !selectedAppKeys.includes(row.appKey)) { excluded.push({ appKey: row.appKey, reason: 'not-operator-selected', category: 'selection' }); continue }
      const raw = row.entry
      const eligible = !raw.blind && (raw.privacyTier == null || raw.privacyTier === 'public') && (raw.maxStorage == null) && raw.storageDeleted !== true
      if (!eligible) {
        assert(!selectedAppKeys, 'explicit selected row is not public unknown-bound')
        excluded.push({ appKey: row.appKey, reason: 'not-public-unknown-bound', category: 'policy' }); continue
      }
      assert(drives.length < RETAINED_READ_LIMITS.drives, 'selected drive count exceeded')
      let meta; let blobs; let driveBee
      try {
        meta = await existingCore(store, Hypercore.discoveryKey(Buffer.from(row.appKey, 'hex')))
        if (meta.encryption || meta.length < 2 || !await meta.has(0)) {
          assert(!selectedAppKeys, 'explicit selection lacks supported local metadata')
          excluded.push({ appKey: row.appKey, reason: meta.encryption ? 'encrypted-metadata' : 'missing-local-metadata-header', category: meta.encryption ? 'policy' : 'local-presence' }); continue
        }
        const metadata = await inspect(meta)
        driveBee = new Hyperbee(meta.session({ wait: false, writable: false }), { keyEncoding: 'utf-8', valueEncoding: 'json', extension: false, readonly: true, checkout: meta.length })
        await driveBee.ready()
        // The header bytes were verified in inspect(meta); no network exists
        // in this operator phase, and missing local header fails immediately.
        const header = await driveBee.getHeader({ wait: false })
        const feed = header?.metadata?.contentFeed
        const blobKey = feed ? Buffer.from(feed).subarray(0, 32) : Hyperdrive.getContentKey(meta.manifest, meta.key)
        assert(blobKey?.length === 32, 'signed metadata must identify the blob core')
        blobs = await existingCore(store, Hypercore.discoveryKey(blobKey))
        assert(blobs.key.equals(blobKey) && !blobs.encryption, 'exact unencrypted blob owner required')
        const blobDescriptor = await inspect(blobs)
        drives.push({ appKey: row.appKey, registryRowSha256: retainedReadRowSha256(raw), driveVersion: metadata.length, metadata, blobs: blobDescriptor })
        used.add(row.appKey)
      } catch (error) {
        // Only a demonstrably absent local core may be excluded. Malformed
        // headers, corrupt bodies and invalid signatures always abort issuance.
        if (selectedAppKeys || error.code !== 'RETAINED_INSPECTION_MISSING_LOCAL') throw error
        excluded.push({ appKey: row.appKey, reason: 'missing-local-core', category: 'local-presence' })
      } finally { if (driveBee) await driveBee.close(); if (blobs) await blobs.close(); if (meta) await meta.close() }
    }
    if (selectedAppKeys) assert(selectedAppKeys.every(key => used.has(key)), 'explicit selected key absent from active inventory')
    assert(drives.length > 0, 'no eligible selected drive')
    assert(drives.length + excluded.length === inventoryRows.filter(row => !row.tombstone).length, 'active selection coverage incomplete')
    drives.sort((a, b) => a.appKey.localeCompare(b.appKey))
    const afterRows = await registry._readBeeInventory()
    const afterValues = afterRows.map(row => ({ key: row.appKey, value: row.entry }))
    const rawAfterSha256 = createHash('sha256').update(JSON.stringify(afterValues)).digest('hex')
    assert(sha(retainedReadCanonicalBytes(afterValues)) === registryDigest && rawAfterSha256 === rawSha256, 'registry changed during inspection')
    assert(registryCore.length === registryState.length && registryCore.byteLength === registryState.byteLength && registryCore.fork === registryState.fork, 'registry history changed during inspection')
    const after = await inventory(store)
    assert(before.sha256 === after.sha256 && before.count === after.count, 'core inventory changed during inspection')
    const a = statSync(storageRoot, { bigint: true }); const b = statSync(status.generationRoot, { bigint: true })
    const root = { configuredRoot: storageRoot, generationRoot: realpathSync(status.generationRoot), device: String(a.dev), inode: String(a.ino), generationDevice: String(b.dev), generationInode: String(b.ino) }
    const proposal = { schema: 'HiveRelayRetainedLocalReadCapabilityV1', purpose: 'serve-selected-local-snapshots-only', generation, root, sourceQualificationSha256, inventorySha256: registryDigest, drives }
    assert(retainedReadCanonicalBytes(proposal).length <= RETAINED_READ_LIMITS.manifestBytes, 'manifest size exceeded')
    const report = { schema: 'HiveRelayRetainedReadInspectionReportV1', passed: true, storageRoot, generation, root, sourceQualificationSha256, registry: { sha256: registryDigest, rawSha256, rawAfterSha256, rows: inventoryRows.length, active: inventoryRows.filter(row => !row.tombstone).length, tombstones: inventoryRows.filter(row => row.tombstone).length, ...registryState }, coreInventoryBefore: before, coreInventoryAfter: after, selectedDrives: drives.length, activeInventoryAccountedFor: true, excluded, cores, examinedBlocks, verifiedLocalBytes, presentBlocks: cores.reduce((n, item) => n + item.presentBlocks, 0), missingBlocks: cores.reduce((n, item) => n + item.missingBlocks, 0), registryUnchanged: true, coreInventoryUnchanged: true, runtimeAuthorizationInstalled: false }
    return { proposal, report }
  } finally { await bee.close() }
}
