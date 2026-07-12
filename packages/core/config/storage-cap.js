import { lstatSync, readdirSync, realpathSync, statfsSync, statSync } from 'fs'
import { join } from 'path'

export const LEGACY_DEFAULT_MAX_STORAGE_BYTES = 50 * 1024 * 1024 * 1024
export const STORAGE_RESERVE_MIN_BYTES = 2 * 1024 * 1024 * 1024
export const STORAGE_RESERVE_MAX_BYTES = 20 * 1024 * 1024 * 1024
export const STORAGE_RESERVE_FRACTION = 0.10

// Symbols survive object spread (RelayNode's config normalization) while JSON
// and Object.entries ignore them. This lets provenance travel with the runtime
// config without becoming a public config field or being confused with an
// operator-authored value.
export const STORAGE_CAP_PROVENANCE = Symbol.for('p2p-hiverelay.storage-cap-provenance.v1')

function finiteNonNegativeInteger (value) {
  const n = Number(value)
  return Number.isSafeInteger(n) && n >= 0 ? n : null
}

function setProvenance (config, provenance) {
  if (!config || typeof config !== 'object') return config
  Object.defineProperty(config, STORAGE_CAP_PROVENANCE, {
    configurable: true,
    enumerable: true,
    writable: true,
    value: Object.freeze({ schemaVersion: 1, ...provenance })
  })
  return config
}

export function getStorageCapProvenance (config) {
  const value = config && config[STORAGE_CAP_PROVENANCE]
  return value && typeof value === 'object' ? value : null
}

export function markStorageCapExplicit (config, source = 'operator') {
  const requestedBytes = finiteNonNegativeInteger(config && config.maxStorageBytes)
  const existing = getStorageCapProvenance(config)
  return setProvenance(config, {
    ...(existing || {}),
    explicit: true,
    source,
    requestedBytes,
    effectiveBytes: requestedBytes,
    status: existing?.status || 'unresolved'
  })
}

export function markStorageCapDefault (config) {
  return setProvenance(config, {
    explicit: false,
    source: 'default',
    requestedBytes: LEGACY_DEFAULT_MAX_STORAGE_BYTES,
    effectiveBytes: finiteNonNegativeInteger(config && config.maxStorageBytes),
    status: 'unresolved'
  })
}

export function copyStorageCapProvenance (source, target) {
  const provenance = getStorageCapProvenance(source)
  if (provenance) setProvenance(target, provenance)
  return target
}

/**
 * Physical reserve kept outside HiveRelay's new-adoption budget.
 *
 * The reserve is 10% of the measured filesystem, with a 2 GiB floor so small
 * hosts retain useful OS/database headroom and a 20 GiB ceiling so large
 * volumes are not needlessly stranded. It is an admission reserve, not an
 * eviction target: already-held data remains available for recovery and
 * operator management even when the reserve is crossed.
 */
export function storageReserveBytes (totalBytes) {
  const total = finiteNonNegativeInteger(totalBytes)
  if (total === null || total === 0) return 0
  return Math.min(
    total,
    STORAGE_RESERVE_MAX_BYTES,
    Math.max(STORAGE_RESERVE_MIN_BYTES, Math.floor(total * STORAGE_RESERVE_FRACTION))
  )
}

function allocatedBytes (stat) {
  const blocks = finiteNonNegativeInteger(stat && stat.blocks)
  if (blocks !== null) {
    const bytes = blocks * 512
    if (Number.isSafeInteger(bytes)) return bytes
  }
  const size = finiteNonNegativeInteger(stat && stat.size)
  return size === null ? 0 : size
}

/**
 * Measure allocated bytes already held inside the exact storage tree. This is
 * intentionally synchronous because cap resolution happens once before the
 * relay accepts traffic. Symlinks are counted but never followed, and visited
 * directories are de-duplicated by device/inode.
 */
export function measureStorageTreeBytes (storagePath, opts = {}) {
  const lstat = opts.lstat || lstatSync
  const readdir = opts.readdir || readdirSync
  const pending = [storagePath]
  const visitedDirectories = new Set()
  let total = 0

  while (pending.length > 0) {
    const path = pending.pop()
    const entry = lstat(path)
    total += allocatedBytes(entry)
    if (!Number.isSafeInteger(total)) throw new Error('storage usage exceeds safe integer range')
    if (!entry.isDirectory()) continue

    const identity = String(entry.dev) + ':' + String(entry.ino)
    if (visitedDirectories.has(identity)) continue
    visitedDirectories.add(identity)

    for (const name of readdir(path)) pending.push(join(path, name))
  }

  return total
}

function unresolved (config, provenance, reason, storagePath) {
  // Only an unset/default cap is replaced with zero. An explicit designation
  // remains byte-for-byte intact, but its unresolved physical proof makes the
  // runtime admission gate fail closed.
  if (!provenance.explicit) config.maxStorageBytes = 0
  setProvenance(config, {
    ...provenance,
    effectiveBytes: finiteNonNegativeInteger(config.maxStorageBytes),
    status: 'unresolved',
    reason,
    storagePath: storagePath == null ? null : String(storagePath),
    availableBytes: 0,
    reserveBytes: 0,
    currentStorageBytes: 0
  })
  return config
}

/**
 * Resolve and attest the storage cap against the exact storage directory.
 *
 * Missing paths are never replaced by their nearest existing ancestor: that
 * could measure `/` while an operator intended a not-yet-mounted `/data`
 * volume. The caller must create the intended directory/mount first. Optional
 * `config.storageFilesystem` ({ realpath, device }) pins an expected backing
 * filesystem for deployments that need a stronger mount assertion.
 *
 * Explicit caps are never rewritten. For an unset cap the effective logical
 * cap is min(legacy 50 GiB, already-held HiveRelay bytes + currently available
 * bytes minus the reserve). A separate runtime admission gate keeps enforcing
 * the reserve as free space changes.
 */
export function resolveStorageCap (config, opts = {}) {
  if (!config || typeof config !== 'object') throw new TypeError('config is required')

  const storagePath = opts.storagePath || config.storage
  const existing = getStorageCapProvenance(config)
  const provenance = existing || {
    schemaVersion: 1,
    explicit: Object.prototype.hasOwnProperty.call(config, 'maxStorageBytes'),
    source: 'operator',
    requestedBytes: finiteNonNegativeInteger(config.maxStorageBytes),
    effectiveBytes: finiteNonNegativeInteger(config.maxStorageBytes),
    status: 'unresolved'
  }

  if (!storagePath || typeof storagePath !== 'string') {
    return unresolved(config, provenance, 'storage-path-missing', storagePath)
  }

  const stat = opts.stat || statSync
  const realpath = opts.realpath || realpathSync
  const statfs = opts.statfs || statfsSync
  const measureStorageBytes = opts.measureStorageBytes || measureStorageTreeBytes

  let pathStat
  let resolvedPath
  let filesystem
  try {
    // stat() follows a symlink, which is intentional: statfs must measure the
    // filesystem that will actually receive Corestore writes.
    pathStat = stat(storagePath)
    if (!pathStat || typeof pathStat.isDirectory !== 'function' || !pathStat.isDirectory()) {
      return unresolved(config, provenance, 'storage-path-not-directory', storagePath)
    }
    resolvedPath = realpath(storagePath)
    const resolvedStat = stat(resolvedPath)
    if (!resolvedStat || typeof resolvedStat.isDirectory !== 'function' || !resolvedStat.isDirectory()) {
      return unresolved(config, provenance, 'storage-realpath-not-directory', storagePath)
    }
    if (String(pathStat.dev) !== String(resolvedStat.dev)) {
      return unresolved(config, provenance, 'storage-filesystem-changed-during-proof', storagePath)
    }
    filesystem = statfs(resolvedPath)
    pathStat = resolvedStat
  } catch (err) {
    const code = err && typeof err.code === 'string' ? err.code.toLowerCase() : 'unavailable'
    return unresolved(config, provenance, `storage-filesystem-${code}`, storagePath)
  }

  const blockSize = finiteNonNegativeInteger(filesystem && filesystem.bsize)
  const blocks = finiteNonNegativeInteger(filesystem && filesystem.blocks)
  const availableBlocks = finiteNonNegativeInteger(filesystem && filesystem.bavail)
  if (!blockSize || blocks === null || availableBlocks === null) {
    return unresolved(config, provenance, 'storage-filesystem-invalid-statfs', storagePath)
  }

  const totalBytes = blocks * blockSize
  const availableBytes = availableBlocks * blockSize
  if (!Number.isSafeInteger(totalBytes) || totalBytes <= 0 ||
      !Number.isSafeInteger(availableBytes) || availableBytes < 0 || availableBytes > totalBytes) {
    return unresolved(config, provenance, 'storage-filesystem-invalid-capacity', storagePath)
  }

  const expected = opts.expectedFilesystem || config.storageFilesystem
  const device = String(pathStat.dev)
  if (expected && typeof expected === 'object') {
    if (expected.realpath != null && String(expected.realpath) !== String(resolvedPath)) {
      return unresolved(config, provenance, 'storage-filesystem-realpath-mismatch', storagePath)
    }
    if (expected.device != null && String(expected.device) !== device) {
      return unresolved(config, provenance, 'storage-filesystem-device-mismatch', storagePath)
    }
  }

  const reserveBytes = storageReserveBytes(totalBytes)
  const physicalBudgetBytes = Math.max(0, availableBytes - reserveBytes)
  let currentStorageBytes
  try {
    currentStorageBytes = finiteNonNegativeInteger(measureStorageBytes(resolvedPath))
  } catch (err) {
    const code = err && typeof err.code === 'string' ? err.code.toLowerCase() : 'unavailable'
    return unresolved(config, provenance, `storage-usage-${code}`, storagePath)
  }
  if (currentStorageBytes === null) {
    return unresolved(config, provenance, 'storage-usage-invalid', storagePath)
  }

  if (!provenance.explicit) {
    // Add already-held HiveRelay bytes to the new-adoption budget. Without
    // this term a restart would repeatedly ratchet the logical cap downward as
    // free space falls, even though the existing bytes were already counted.
    config.maxStorageBytes = Math.min(
      LEGACY_DEFAULT_MAX_STORAGE_BYTES,
      currentStorageBytes + physicalBudgetBytes
    )
  }

  setProvenance(config, {
    ...provenance,
    requestedBytes: provenance.explicit
      ? finiteNonNegativeInteger(provenance.requestedBytes ?? config.maxStorageBytes)
      : LEGACY_DEFAULT_MAX_STORAGE_BYTES,
    effectiveBytes: finiteNonNegativeInteger(config.maxStorageBytes),
    status: 'resolved',
    reason: null,
    storagePath,
    realpath: resolvedPath,
    device,
    totalBytes,
    availableBytes,
    reserveBytes,
    physicalBudgetBytes,
    currentStorageBytes
  })
  return config
}

/**
 * Compute whether a new pin/adoption may begin. Existing data and management
 * operations do not call this gate, so an over-cap node can still boot, serve,
 * inspect and unseed content. No eviction is enabled or triggered here.
 */
export function evaluateStorageAdmission (config, opts = {}) {
  const usedBytes = finiteNonNegativeInteger(opts.usedBytes) || 0
  const additionalBytes = finiteNonNegativeInteger(opts.additionalBytes) || 0
  const capBytes = finiteNonNegativeInteger(config && config.maxStorageBytes) || 0
  const provenance = getStorageCapProvenance(config)

  if (provenance && provenance.status !== 'resolved') {
    return {
      allowed: false,
      reason: 'storage-filesystem-unresolved',
      capBytes,
      usedBytes,
      availableBytes: 0,
      additionalBytes
    }
  }

  const logicalAvailable = Math.max(0, capBytes - usedBytes)
  let physicalAvailable = Infinity
  let reserveBytes = 0

  const disk = opts.diskInfo && typeof opts.diskInfo === 'object' ? opts.diskInfo : null
  if (disk && Number.isSafeInteger(Number(disk.freeBytes)) && Number(disk.freeBytes) >= 0 &&
      Number.isSafeInteger(Number(disk.totalBytes)) && Number(disk.totalBytes) > 0) {
    reserveBytes = storageReserveBytes(Number(disk.totalBytes))
    physicalAvailable = Math.max(0, Number(disk.freeBytes) - reserveBytes)
  } else if (provenance && Number.isSafeInteger(provenance.availableBytes)) {
    reserveBytes = Number.isSafeInteger(provenance.reserveBytes) ? provenance.reserveBytes : 0
    physicalAvailable = Math.max(0, provenance.availableBytes - reserveBytes)
  }

  const availableBytes = Math.max(0, Math.min(logicalAvailable, physicalAvailable))
  let reason = null
  if (usedBytes >= capBytes) reason = 'storage-cap-reached'
  else if (physicalAvailable <= 0) reason = 'storage-reserve-reached'
  else if (additionalBytes > availableBytes) reason = 'insufficient-storage'

  return {
    allowed: reason === null && availableBytes > 0,
    reason,
    capBytes,
    usedBytes,
    logicalAvailableBytes: logicalAvailable,
    physicalAvailableBytes: Number.isFinite(physicalAvailable) ? physicalAvailable : null,
    availableBytes,
    reserveBytes,
    additionalBytes
  }
}
