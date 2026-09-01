/**
 * corestore 7 storage-root migration guard.
 *
 * hypercore-storage 3 (corestore 7) runs a one-time `tmpFixStorage` the first
 * time it opens a pre-7 storage root: every top-level entry that isn't
 * corestore's own (cores/, primary-key, …) is moved into the new db/
 * subdirectory so the RocksDB migration owns the layout. That relocation is
 * SYNCHRONOUS inside `new Corestore(dir)` (verified against
 * hypercore-storage/index.js).
 *
 * The relay keeps its own state files in the same root — app-registry.json,
 * federation.json, identity.key, services.json, the client's
 * app-drives/forks/pending-seeds JSON, … — and they get swept into db/ too,
 * invisible to every component that reads them from the root (an upgrading
 * relay would boot with an "empty" registry and forget what it seeds).
 *
 * openCorestore() is a drop-in replacement for `new Corestore(dir)` at
 * state-bearing roots: snapshot the root's top-level entries BEFORE the
 * open (only a marker-less, pre-7 root can be migrated), then move back
 * whatever the migration relocated into db/. Files that survive at the root
 * are never touched, and db/ itself is left strictly to corestore.
 */

import Corestore from 'corestore'
import { existsSync, readdirSync, renameSync } from 'fs'
import { join } from 'path'
import {
  guardCorestoreGenerationReady,
  prepareCorestoreGenerationOpen
} from './corestore-generation-envelope.js'

export {
  CORESTORE_GENERATION_CAPABILITIES,
  CORESTORE_GENERATION_ENVELOPE,
  CORESTORE_GENERATION_MIGRATION_BINDING,
  CorestoreGenerationError,
  assertPatchedHypercoreStorageMigration,
  corestoreGenerationOpenOptions,
  corestoreGenerationHealth,
  corestoreGenerationParticipantOptions,
  corestoreGenerationPublicConfig,
  corestoreGenerationStatus,
  createContentAddressedCorestoreBackup,
  importLegacyCorestoreCopyIntoEnvelope,
  initializeCorestoreGenerationEnvelope,
  inventoryCorestoreGenerationTree,
  rebindRestoredCorestoreDevice,
  restoreContentAddressedCorestoreBackup
} from './corestore-generation-envelope.js'

// Entries hypercore-storage manages itself at the storage root — never ours.
const CORESTORE_OWNED = new Set(['CORESTORE', 'primary-key', 'cores', 'db'])

export function openCorestore (storage, opts) {
  let prepared = null
  let corestoreOptions = opts
  if (opts && typeof opts === 'object' && Object.prototype.hasOwnProperty.call(opts, 'hiverelayGeneration')) {
    corestoreOptions = { ...opts }
    const generationOptions = corestoreOptions.hiverelayGeneration
    delete corestoreOptions.hiverelayGeneration
    if (generationOptions != null) {
      if (corestoreOptions.allowBackup === true) {
        throw new TypeError('allowBackup is forbidden for a generation-envelope writer')
      }
      if (corestoreOptions.readOnly === true) {
        throw new TypeError('readOnly generation-envelope verification requires the offline verification API')
      }
      prepared = prepareCorestoreGenerationOpen(storage, generationOptions)
      storage = prepared.storage
    }
  }

  let before = null
  try {
    // Only a pre-7 root (no CORESTORE marker yet) can be migrated on open.
    // The explicit generation importer has already separated Corestore-owned
    // bytes from relay sidecars, so its nested root never uses this legacy
    // relocation compatibility shim.
    if (!prepared && typeof storage === 'string' && !existsSync(join(storage, 'CORESTORE'))) {
      before = readdirSync(storage)
    }
  } catch {
    before = null // brand-new or unreadable root — nothing to protect
  }

  const store = new Corestore(storage, corestoreOptions)

  if (before) {
    for (const name of before) {
      if (CORESTORE_OWNED.has(name)) continue
      if (existsSync(join(storage, name))) continue // survived at the root
      try {
        renameSync(join(storage, 'db', name), join(storage, name))
      } catch {
        // tmpFixStorage only moves, never deletes — a miss here means the
        // entry vanished some other way; nothing to restore.
      }
    }
  }

  return prepared ? guardCorestoreGenerationReady(store, prepared) : store
}
