import b4a from 'b4a'
import { open, mkdir, readFile, rename, unlink } from 'node:fs/promises'
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

export async function openBlindStoreGenerationFloor (controlDirectory) {
  if (typeof controlDirectory !== 'string' || controlDirectory.length === 0) {
    throw new TypeError('controlDirectory must be a non-empty string')
  }
  await mkdir(controlDirectory, { recursive: true, mode: 0o700 })
  const markerPath = path.join(controlDirectory, BLIND_STORE_GENERATION.rollbackFloorFile)
  let firstBlindOnlyWriteAcknowledged = false
  try {
    const marker = JSON.parse(await readFile(markerPath, 'utf8'))
    if (marker.schema !== BLIND_STORE_GENERATION.schema ||
        marker.formatVersion !== BLIND_STORE_GENERATION.formatVersion ||
        marker.firstBlindOnlyWriteAcknowledged !== true) {
      throw new Error('invalid blind store generation floor marker')
    }
    firstBlindOnlyWriteAcknowledged = true
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
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
      const marker = JSON.stringify({
        schema: BLIND_STORE_GENERATION.schema,
        formatVersion: BLIND_STORE_GENERATION.formatVersion,
        firstBlindOnlyWriteAcknowledged: true
      }) + '\n'
      const temporaryPath = `${markerPath}.tmp-${process.pid}`
      const handle = await open(temporaryPath, 'wx', 0o600)
      try {
        await handle.writeFile(marker, 'utf8')
        await handle.sync()
      } finally {
        await handle.close()
      }
      try {
        await rename(temporaryPath, markerPath)
      } catch (error) {
        await unlink(temporaryPath).catch(() => {})
        throw error
      }
      const directory = await open(controlDirectory, 'r')
      try { await directory.sync() } finally { await directory.close() }
      firstBlindOnlyWriteAcknowledged = true
      return true
    }
  }
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
