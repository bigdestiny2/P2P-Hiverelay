import b4a from 'b4a'
import { createHmac, timingSafeEqual } from 'node:crypto'
import { copyFile, open, mkdir, readFile, rename, stat, unlink } from 'node:fs/promises'
import path from 'node:path'
import { blake2b256 } from '@hiverelay/blind-protocol'
import { deriveBlindVirtualBucket } from './virtual-bucket.js'

export const BLIND_STORE_GENERATION = Object.freeze({
  schema: 'hiverelay-blind-store-generation-v1',
  formatVersion: '1.2',
  legacyFormatVersion: '1.1',
  rollbackFloorFile: 'blind-store-generation-floor-v1.json'
})

export const BLIND_STORE_READER_MODE = Object.freeze({
  BLIND_ONLY: 'blind-only',
  BLIND_PLUS_LEGACY: 'blind-plus-legacy-dual-read',
  LEGACY_ONLY: 'legacy-only'
})

const MODES = new Set(Object.values(BLIND_STORE_READER_MODE))
const PLAN_DOMAIN = b4a.from('hiverelay.blind.store-generation-migration-plan.v1', 'ascii')

export function createBlindStoreMigrationPlan (inventory) {
  if (!Array.isArray(inventory)) throw new TypeError('migration inventory must be an array')
  const seen = new Set()
  const entries = inventory.map((record, index) => {
    if (record == null || !Number.isInteger(record.serviceTag) || record.serviceTag < 0 || record.serviceTag > 0xff) {
      throw new TypeError(`migration inventory[${index}].serviceTag must be a u8`)
    }
    const locator = asBytes(record.primaryLocator, `migration inventory[${index}].primaryLocator`)
    if (!Number.isInteger(record.legacyVirtualBucket) || record.legacyVirtualBucket < 0 || record.legacyVirtualBucket > 0xffff) {
      throw new TypeError(`migration inventory[${index}].legacyVirtualBucket must be a u16`)
    }
    const objectHash = asBytes(record.objectHash, `migration inventory[${index}].objectHash`, 32)
    if (!Number.isSafeInteger(record.byteLength) || record.byteLength < 0) {
      throw new TypeError(`migration inventory[${index}].byteLength must be a non-negative safe integer`)
    }
    const identity = `${record.serviceTag}:${b4a.toString(locator, 'hex')}`
    if (seen.has(identity)) throw new Error(`duplicate migration locator: ${identity}`)
    seen.add(identity)
    return {
      serviceTag: record.serviceTag,
      primaryLocatorHex: b4a.toString(locator, 'hex'),
      legacyVirtualBucket: record.legacyVirtualBucket,
      publicVirtualBucket: deriveBlindVirtualBucket(record.serviceTag, locator),
      objectHashHex: b4a.toString(objectHash, 'hex'),
      byteLength: record.byteLength
    }
  }).sort(compareEntries)

  const planBody = {
    schema: 'hiverelay-blind-store-migration-plan-v1',
    fromFormatVersion: BLIND_STORE_GENERATION.legacyFormatVersion,
    toFormatVersion: BLIND_STORE_GENERATION.formatVersion,
    copyVerifyBeforeCommit: true,
    entries
  }
  const planHash = blake2b256(b4a.concat([PLAN_DOMAIN, b4a.from(JSON.stringify(planBody), 'utf8')]))
  return Object.freeze({ ...planBody, planHashHex: b4a.toString(planHash, 'hex') })
}

export async function openBlindStoreGenerationFloor (controlDirectory, options = {}) {
  if (typeof controlDirectory !== 'string' || controlDirectory.length === 0) {
    throw new TypeError('controlDirectory must be a non-empty string')
  }
  await mkdir(controlDirectory, { recursive: true, mode: 0o700 })
  const manifestKey = asBytes(options.manifestKey, 'manifestKey', 32)
  const storeIdentity = asBytes(options.storeIdentity, 'storeIdentity')
  const markerPath = path.join(controlDirectory, BLIND_STORE_GENERATION.rollbackFloorFile)
  let firstBlindOnlyWriteAcknowledged = false
  try {
    const marker = JSON.parse(await readFile(markerPath, 'utf8'))
    if (marker.schema !== BLIND_STORE_GENERATION.schema ||
        marker.formatVersion !== BLIND_STORE_GENERATION.formatVersion ||
        typeof marker.firstBlindOnlyWriteAcknowledged !== 'boolean' ||
        marker.storeIdentityHash !== identityHash(storeIdentity) ||
        !validMac(marker, manifestKey)) {
      throw new Error('invalid blind store generation floor marker')
    }
    firstBlindOnlyWriteAcknowledged = marker.firstBlindOnlyWriteAcknowledged
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
    if (options.allowCreate !== true) throw new Error('blind store generation floor marker is missing')
    await writeMarker(false)
  }

  return {
    get firstBlindOnlyWriteAcknowledged () { return firstBlindOnlyWriteAcknowledged },
    assertReaderMode (mode) {
      if (!MODES.has(mode)) throw new TypeError(`unknown blind store reader mode: ${mode}`)
      if (firstBlindOnlyWriteAcknowledged && mode === BLIND_STORE_READER_MODE.LEGACY_ONLY) {
        throw new Error('D7 rollback floor forbids legacy-only reads after the first blind-only write')
      }
      return true
    },
    async acknowledgeBlindOnlyWrite () {
      if (firstBlindOnlyWriteAcknowledged) return false
      await writeMarker(true)
      firstBlindOnlyWriteAcknowledged = true
      return true
    }
  }

  async function writeMarker (acknowledged) {
    const body = {
      schema: BLIND_STORE_GENERATION.schema,
      formatVersion: BLIND_STORE_GENERATION.formatVersion,
      storeIdentityHash: identityHash(storeIdentity),
      firstBlindOnlyWriteAcknowledged: acknowledged
    }
    const marker = JSON.stringify({ ...body, mac: markerMac(body, manifestKey) }) + '\n'
    const temporaryPath = `${markerPath}.tmp-${process.pid}`
    const handle = await open(temporaryPath, 'wx', 0o600)
    try {
      await handle.writeFile(marker, 'utf8')
      await handle.sync()
    } finally { await handle.close() }
    try { await rename(temporaryPath, markerPath) } catch (error) {
      await unlink(temporaryPath).catch(() => {})
      throw error
    }
    const directory = await open(controlDirectory, 'r')
    try { await directory.sync() } finally { await directory.close() }
  }
}

export async function executeBlindStoreMigration (options) {
  const root = options.root
  const plan = options.plan
  const manifestKey = asBytes(options.manifestKey, 'manifestKey', 32)
  const storeIdentity = asBytes(options.storeIdentity, 'storeIdentity')
  const statePath = path.join(root, 'migration-v1.2.state.json')
  await mkdir(root, { recursive: true, mode: 0o700 })
  let state
  try {
    state = JSON.parse(await readFile(statePath, 'utf8'))
    if (!validMac(state, manifestKey) || state.planHashHex !== plan.planHashHex ||
        state.storeIdentityHash !== identityHash(storeIdentity)) throw new Error('invalid migration state')
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
    state = {
      schema: 'hiverelay-blind-store-migration-state-v1',
      planHashHex: plan.planHashHex,
      storeIdentityHash: identityHash(storeIdentity),
      phase: 'inventory'
    }
    await persist()
  }
  await boundary('inventory')
  if (state.phase === 'inventory') {
    for (const entry of options.files) {
      await mkdir(path.dirname(entry.targetPath), { recursive: true, mode: 0o700 })
      try { await copyFile(entry.legacyPath, entry.targetPath, 1) } catch (error) {
        if (error.code !== 'EEXIST') throw error
      }
    }
    state.phase = 'copy'; await persist()
  }
  await boundary('copy')
  if (state.phase === 'copy') {
    for (const entry of options.files) {
      const bytes = await readFile(entry.targetPath)
      const metadata = await stat(entry.legacyPath)
      if (metadata.size !== entry.byteLength || bytes.byteLength !== entry.byteLength ||
          b4a.toString(blake2b256(bytes), 'hex') !== entry.objectHashHex) throw new Error('migration hash verification failed')
    }
    state.phase = 'hash-verify'; await persist()
  }
  await boundary('hash-verify')
  if (state.phase === 'hash-verify') { state.phase = 'commit'; await persist() }
  await boundary('commit')
  if (state.phase === 'commit') { state.phase = 'finalize'; await persist() }
  await boundary('finalize')
  return Object.freeze({ phase: state.phase, legacySourcesPreserved: true, planHashHex: plan.planHashHex })

  async function boundary (phase) { if (options.faultInjector) await options.faultInjector(phase) }
  async function persist () {
    const body = { ...state }; delete body.mac
    const bytes = JSON.stringify({ ...body, mac: markerMac(body, manifestKey) }) + '\n'
    const temporary = `${statePath}.tmp-${process.pid}`
    const handle = await open(temporary, 'w', 0o600)
    try { await handle.writeFile(bytes); await handle.sync() } finally { await handle.close() }
    await rename(temporary, statePath)
    const directory = await open(root, 'r'); try { await directory.sync() } finally { await directory.close() }
  }
}

function identityHash (value) { return b4a.toString(blake2b256(value), 'hex') }
function markerMac (body, key) { return createHmac('sha256', key).update(JSON.stringify(body)).digest('hex') }
function validMac (value, key) {
  if (!value || typeof value.mac !== 'string' || !/^[0-9a-f]{64}$/.test(value.mac)) return false
  const body = { ...value }; delete body.mac
  return timingSafeEqual(b4a.from(value.mac, 'hex'), b4a.from(markerMac(body, key), 'hex'))
}

function asBytes (value, label, length = null) {
  if (!b4a.isBuffer(value) && !(value instanceof Uint8Array)) throw new TypeError(`${label} must be bytes`)
  const bytes = b4a.from(value)
  if (length != null && bytes.byteLength !== length) throw new TypeError(`${label} must be ${length} bytes`)
  return bytes
}

function compareEntries (left, right) {
  return left.serviceTag - right.serviceTag || left.primaryLocatorHex.localeCompare(right.primaryLocatorHex)
}
