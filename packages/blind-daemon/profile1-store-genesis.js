import fs from 'node:fs/promises'
import { constants as FS_CONSTANTS } from 'node:fs'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  blindControlStateSnapshotV1,
  blindStoreManifestV1,
  controlSnapshotHash,
  decodeCanonical,
  encodeCanonical
} from '@hiverelay/blind-protocol'
import {
  renameFileNoReplace,
  renameFileNoReplacePlatformSupported
} from '@hiverelay/blind-peercred'
import { verifyBlindCellInboxCoreEmptyGenesisSnapshotSemanticVerifier } from './cell-inbox-core-control-snapshot.js'
import { BlindLocalCheckpointStore } from './local-checkpoint-store.js'
import { TwoSlotManifestStore } from './manifest-store.js'
import { BlindRecoveryValidationCoordinator } from './recovery-validation-authority.js'
import {
  acquireBlindStoreSessionTransactionLease,
  BlindStoreSession
} from './store-session.js'
import { BlindTransactionStore } from './transaction-store.js'

const ZERO32 = b4a.alloc(32)
const INTENT_MAGIC = b4a.from('HRBGI001', 'ascii')
const INTENT_VERSION = 1
const INTENT_BYTES = 8 + 2 + 32 + 32
const INTENT_FILE = 'genesis-intent.v1'
const INTENT_TEMP = /^\.genesis-intent\.v1\.([0-9a-f]{32})\.tmp$/
const GENESIS_ARTIFACT_TEMP = /^\.(checkpoint|snapshot)-([0-9a-f]{64})\.v1\.([0-9a-f]{32})\.tmp$/
const MAX_INTENT_TEMPS = 16
const COMMITMENT_DOMAIN = b4a.from('hiverelay.blind.profile1-genesis-intent.v1', 'ascii')
const INTENT_MAC_DOMAIN = b4a.from('hiverelay.blind.profile1-genesis-intent-mac.v1', 'ascii')
const TRANSACTION_ID_DOMAIN = b4a.from('hiverelay.blind.profile1-genesis-transaction-id.v1', 'ascii')
const MAX_U64 = (1n << 64n) - 1n

const EXPECTED_BINDING_FIELDS = Object.freeze([
  'relayPublicKey',
  'storeId',
  'durabilityProfileId',
  'durabilityContinuityHash',
  'durabilityProfileHash',
  'formatMajor',
  'formatMinor',
  'storeFormatHash',
  'specHash',
  'abiHash',
  'mapGeneration',
  'bucketMapHash',
  'writerEpoch',
  'writerFenceTokenHash'
])

export const BLIND_PROFILE1_STORE_GENESIS_STATUS = Object.freeze({
  mechanicalCrashResumableGenesisImplemented: true,
  mechanicalRevision1CheckpointImplemented: true,
  mechanicalTwoSlotManifestInitializationImplemented: true,
  mechanicalValidatedRecoveryHandoffImplemented: true,
  emptyGenesisPublicationSemanticAuthorityImplemented: true,
  generalSnapshotPublicationAuthorized: false,
  profileId: 1,
  productionReady: false,
  remainingBlockers: Object.freeze([
    'FINAL_STORE_FORMAT_AUTHORITY_UNPUBLISHED',
    'TWO_SLOT_MANIFEST_RUNTIME_INTEGRATION_UNASSEMBLED',
    'ALL_FAMILY_SHADOW_SEMANTIC_AUTHORITY_UNIMPLEMENTED',
    'CELL_INBOX_CORE_WAL_STATE_MACHINE_AND_ENGINE_RESTORE_UNIMPLEMENTED',
    'CHECKPOINT_GARBAGE_COLLECTION_UNIMPLEMENTED',
    'WAL_PRUNING_UNIMPLEMENTED',
    'PROFILE2_EXTERNAL_JOURNAL_WITNESS_UNIMPLEMENTED'
  ])
})

export class BlindProfile1StoreGenesisError extends Error {
  constructor (message, code = 'BLIND_PROFILE1_GENESIS_INVALID') {
    super(message)
    this.name = 'BlindProfile1StoreGenesisError'
    this.code = code
  }
}

function canonicalRoot (value) {
  if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value) || path.normalize(value) !== value) {
    throw new TypeError('profile-1 genesis root must be a canonical absolute path')
  }
  return value
}

function bytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (length != null && value.byteLength !== length) throw new TypeError(`${field} must be exactly ${length} bytes`)
  if (nonzero && value.every(byte => byte === 0)) throw new TypeError(`${field} must be nonzero`)
  return value
}

function integer (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field} is not an unsigned integer`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) throw new TypeError(`${field} is outside u64`)
  return value
}

function u16bytes (value) {
  const output = b4a.alloc(2)
  output.writeUInt16BE(value)
  return output
}

function u32bytes (value) {
  const output = b4a.alloc(4)
  output.writeUInt32BE(value)
  return output
}

function u64bytes (value) {
  value = u64(value, 'length')
  const output = b4a.alloc(8)
  output.writeBigUInt64BE(value)
  return output
}

function hashParts (domain, value, key = null) {
  const input = b4a.concat([domain, u64bytes(BigInt(value.byteLength)), value])
  const output = b4a.alloc(32)
  if (key == null) sodium.crypto_generichash(output, input)
  else sodium.crypto_generichash(output, input, key)
  return output
}

function isZero32 (value) {
  return b4a.equals(bytes(value, 32, 'zero field'), ZERO32)
}

function canonicalManifestTemplate (input) {
  let manifest
  try {
    manifest = decodeCanonical(
      blindStoreManifestV1,
      encodeCanonical(blindStoreManifestV1, input),
      { copyBytes: true }
    )
  } catch (error) {
    throw new BlindProfile1StoreGenesisError(`manifest template is not canonical: ${error.message}`)
  }
  if (manifest.durabilityProfileId !== 1 || manifest.manifestRevision !== 0n ||
      manifest.previousManifestHash != null || manifest.mapGeneration === 0n || manifest.writerEpoch === 0n) {
    throw new BlindProfile1StoreGenesisError(
      'genesis requires profile 1, manifest revision 0, no predecessor, and nonzero map/writer generations'
    )
  }
  for (const field of [
    'externalJournalId',
    'externalWitnessPublicKey',
    'restoreEvidenceFeedId',
    'lastAckWalHash',
    'externalCheckpointHash',
    'migrationCursorHash'
  ]) {
    if (!isZero32(manifest[field])) {
      throw new BlindProfile1StoreGenesisError(`profile-1 genesis requires ${field} to be zero`)
    }
  }
  if (manifest.externalLeaseRevision !== 0n || manifest.lastAckWalSequence !== 0n ||
      manifest.externalCheckpointRevision !== 0n || manifest.migrationState !== 0 ||
      manifest.sourceFormatMajor !== 0 || manifest.targetFormatMajor !== 0) {
    throw new BlindProfile1StoreGenesisError('profile-1 genesis contains nonzero external or migration state')
  }
  return Object.freeze(manifest)
}

function manifestIntentTemplate (manifest) {
  return encodeCanonical(blindStoreManifestV1, {
    ...manifest,
    previousManifestHash: null,
    manifestRevision: 0n
  })
}

function normalizedGenesisRecord (value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('genesisRecord must be an object')
  }
  return Object.freeze({
    type: integer(value.type, 1, 255, 'genesisRecord.type'),
    virtualBucket: integer(value.virtualBucket, 0, 0xffff, 'genesisRecord.virtualBucket'),
    payload: b4a.from(bytes(value.payload, null, 'genesisRecord.payload'))
  })
}

function intentCommitment (manifest, record) {
  const recordBytes = b4a.concat([
    b4a.from([record.type]),
    u16bytes(record.virtualBucket),
    u32bytes(record.payload.byteLength),
    record.payload
  ])
  return hashParts(COMMITMENT_DOMAIN, b4a.concat([manifestIntentTemplate(manifest), recordBytes]))
}

function intentBytes (commitment, manifestKey) {
  const prefix = b4a.concat([INTENT_MAGIC, u16bytes(INTENT_VERSION), commitment])
  return b4a.concat([prefix, hashParts(INTENT_MAC_DOMAIN, prefix, manifestKey)], INTENT_BYTES)
}

function expectedBindings (manifest) {
  return Object.freeze(Object.fromEntries(EXPECTED_BINDING_FIELDS.map(field => [
    field,
    manifest[field] && typeof manifest[field].byteLength === 'number'
      ? b4a.from(manifest[field])
      : manifest[field]
  ])))
}

function copyEntries (entries) {
  if (!Array.isArray(entries) || entries.length !== 3) {
    throw new TypeError('genesisSnapshotEntries must contain exactly three canonical empty global fragments')
  }
  return Object.freeze(entries.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new TypeError(`genesisSnapshotEntries[${index}] must be an object`)
    }
    return Object.freeze({
      entryKind: integer(entry.entryKind, 1, 8, `genesisSnapshotEntries[${index}].entryKind`),
      key: b4a.from(bytes(entry.key, null, `genesisSnapshotEntries[${index}].key`)),
      value: b4a.from(bytes(entry.value, null, `genesisSnapshotEntries[${index}].value`))
    })
  }))
}

function sameGenesisFrame (frame, record, transactionId) {
  return frame.sequence === 1n && frame.type === record.type && frame.virtualBucket === record.virtualBucket &&
    b4a.equals(frame.transactionId, transactionId) && b4a.equals(frame.payload, record.payload)
}

function checkpointValue (manifest, snapshotBytes, walAnchor) {
  return {
    magic: b4a.from('HRBCKP01', 'ascii'),
    checkpointVersion: 1,
    relayPublicKey: b4a.from(manifest.relayPublicKey),
    storeId: b4a.from(manifest.storeId),
    durabilityProfileId: manifest.durabilityProfileId,
    durabilityContinuityHash: b4a.from(manifest.durabilityContinuityHash),
    durabilityProfileHash: b4a.from(manifest.durabilityProfileHash),
    formatMajor: manifest.formatMajor,
    formatMinor: manifest.formatMinor,
    storeFormatHash: b4a.from(manifest.storeFormatHash),
    specHash: b4a.from(manifest.specHash),
    abiHash: b4a.from(manifest.abiHash),
    mapGeneration: manifest.mapGeneration,
    bucketMapHash: b4a.from(manifest.bucketMapHash),
    writerEpoch: manifest.writerEpoch,
    writerFenceTokenHash: b4a.from(manifest.writerFenceTokenHash),
    checkpointRevision: 1n,
    previousCheckpointHash: null,
    coveredWalSequence: walAnchor.sequence,
    coveredWalHash: b4a.from(walAnchor.hash),
    epochFloor: manifest.epochFloor,
    descriptorSequenceFloor: manifest.descriptorSequenceFloor,
    descriptorHashFloor: b4a.from(manifest.descriptorHashFloor),
    snapshotByteLength: BigInt(snapshotBytes.byteLength),
    snapshotHash: controlSnapshotHash(snapshotBytes)
  }
}

async function syncDirectory (directory) {
  const handle = await fs.open(directory, FS_CONSTANTS.O_RDONLY)
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

function privateFile (stat) {
  return stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    (typeof process.getuid !== 'function' || stat.uid === process.getuid()) &&
    (stat.mode & 0o600) === 0o600 && (stat.mode & 0o077) === 0
}

async function readStablePrivateFile (target, expectedBytes) {
  const linked = await fs.lstat(target)
  if (!privateFile(linked) || linked.size !== expectedBytes) {
    throw new BlindProfile1StoreGenesisError('genesis intent is not a private exact-length regular file')
  }
  const handle = await fs.open(target, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
  try {
    const opened = await handle.stat()
    if (!privateFile(opened) || opened.dev !== linked.dev || opened.ino !== linked.ino || opened.size !== expectedBytes) {
      throw new BlindProfile1StoreGenesisError('genesis intent path and opened inode disagree')
    }
    const value = await handle.readFile()
    const after = await handle.stat()
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
        after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
      throw new BlindProfile1StoreGenesisError('genesis intent changed while it was read')
    }
    return value
  } finally {
    await handle.close()
  }
}

function runtimeObject (transactionStore, session, recoveryAuthority) {
  let closed = false
  let closePromise = null
  const runtime = Object.freeze({
    transactionStore,
    recoveryAuthority: Object.freeze({
      checkpointSequence: recoveryAuthority.checkpointSequence,
      walHeadSequence: recoveryAuthority.walHeadSequence,
      tornTailBytes: recoveryAuthority.tornTailBytes
    }),
    status: BLIND_PROFILE1_STORE_GENESIS_STATUS,
    close () {
      if (closePromise) return closePromise
      closed = true
      closePromise = (async () => {
        let failure = null
        try {
          await transactionStore.close()
        } catch (error) {
          failure = error
        }
        try {
          await session.close()
        } catch (error) {
          failure = failure || error
        }
        if (failure) throw failure
      })()
      return closePromise
    },
    get closed () { return closed }
  })
  return runtime
}

export class BlindProfile1StoreGenesisCoordinator {
  constructor (options = {}) {
    if (!renameFileNoReplacePlatformSupported()) {
      throw new BlindProfile1StoreGenesisError(
        'profile-1 genesis requires atomic rename-no-replace',
        'BLIND_RENAME_NOREPLACE_UNSUPPORTED'
      )
    }
    this.root = canonicalRoot(options.root)
    this.controlDirectory = path.join(this.root, 'control')
    this.intentPath = path.join(this.controlDirectory, INTENT_FILE)
    this.manifestKey = b4a.from(bytes(options.manifestKey, 32, 'manifestKey', true))
    this.manifestTemplate = canonicalManifestTemplate(options.manifestTemplate)
    this.bindings = expectedBindings(this.manifestTemplate)
    this.genesisRecord = normalizedGenesisRecord(options.genesisRecord)
    this.genesisSnapshotEntries = copyEntries(options.genesisSnapshotEntries)
    this.snapshotSemanticVerifier = verifyBlindCellInboxCoreEmptyGenesisSnapshotSemanticVerifier(
      options.snapshotSemanticVerifier
    )
    this.commitment = intentCommitment(this.manifestTemplate, this.genesisRecord)
    this.expectedIntentBytes = intentBytes(this.commitment, this.manifestKey)
    this.genesisTransactionId = hashParts(TRANSACTION_ID_DOMAIN, this.commitment)
    this.maximumSnapshotBytes = integer(
      options.maximumSnapshotBytes == null ? 256 * 1024 * 1024 : options.maximumSnapshotBytes,
      1024,
      0x7fffffff,
      'maximumSnapshotBytes'
    )
    this.maximumEntries = integer(
      options.maximumEntries == null ? 0x1000000 : options.maximumEntries,
      3,
      0x1000000,
      'maximumEntries'
    )
    if (options.faultInjector != null && typeof options.faultInjector !== 'function') {
      throw new TypeError('faultInjector must be a function')
    }
    this.faultInjector = options.faultInjector || null
    this.opened = false
  }

  async _fault (point, context = {}) {
    if (this.faultInjector) await this.faultInjector(point, Object.freeze({ root: this.root, ...context }))
  }

  _transactionOptions (extra = {}) {
    return {
      root: this.root,
      mapGeneration: this.manifestTemplate.mapGeneration,
      ownerFenceTokenHash: this.manifestTemplate.writerFenceTokenHash,
      durabilityContinuityHash: this.manifestTemplate.durabilityContinuityHash,
      faultInjector: this.faultInjector,
      ...extra
    }
  }

  async _intentTemps () {
    let names
    try {
      names = (await fs.readdir(this.controlDirectory)).filter(name => INTENT_TEMP.test(name))
    } catch (error) {
      if (error && error.code === 'ENOENT') return []
      throw error
    }
    if (names.length > MAX_INTENT_TEMPS) {
      throw new BlindProfile1StoreGenesisError('genesis intent temporary-file bound exceeded')
    }
    for (const name of names) {
      const stat = await fs.lstat(path.join(this.controlDirectory, name))
      if (!privateFile(stat)) throw new BlindProfile1StoreGenesisError('genesis intent temporary is not private')
    }
    return names
  }

  async _verifyIntent () {
    const observed = await readStablePrivateFile(this.intentPath, INTENT_BYTES)
    if (!b4a.equals(observed, this.expectedIntentBytes)) {
      throw new BlindProfile1StoreGenesisError(
        'genesis intent MAC or exact launch commitment does not match this startup'
      )
    }
    return true
  }

  async _installIntent () {
    const temps = await this._intentTemps()
    for (const name of temps) await fs.unlink(path.join(this.controlDirectory, name))
    if (temps.length > 0) await syncDirectory(this.controlDirectory)
    try {
      await this._verifyIntent()
      return false
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error
    }
    const temporary = path.join(
      this.controlDirectory,
      `.genesis-intent.v1.${randomBytes(16).toString('hex')}.tmp`
    )
    let handle
    let installed = false
    try {
      handle = await fs.open(
        temporary,
        FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW,
        0o600
      )
      await handle.writeFile(this.expectedIntentBytes)
      await this._fault('genesis-intent:after-temp-write')
      await handle.sync()
      await this._fault('genesis-intent:after-temp-sync')
      installed = renameFileNoReplace(temporary, this.intentPath)
      await this._fault('genesis-intent:after-no-replace-rename', { installed })
      await syncDirectory(this.controlDirectory)
      await this._fault('genesis-intent:after-directory-sync', { installed })
      if (!installed) await fs.unlink(temporary)
      await this._verifyIntent()
      return installed
    } finally {
      if (handle) await handle.close().catch(() => {})
    }
  }

  _snapshotBytes (walAnchor) {
    return encodeCanonical(blindControlStateSnapshotV1, {
      version: 1,
      relayPublicKey: b4a.from(this.manifestTemplate.relayPublicKey),
      storeId: b4a.from(this.manifestTemplate.storeId),
      durabilityContinuityHash: b4a.from(this.manifestTemplate.durabilityContinuityHash),
      walSequence: walAnchor.sequence,
      walHash: b4a.from(walAnchor.hash),
      entries: this.genesisSnapshotEntries
    })
  }

  async _removeIntent () {
    await this._verifyIntent()
    await fs.unlink(this.intentPath)
    await this._fault('genesis-intent:after-unlink')
    for (const name of await this._intentTemps()) await fs.unlink(path.join(this.controlDirectory, name))
    await syncDirectory(this.controlDirectory)
    await this._fault('genesis-intent:after-unlink-directory-sync')
  }

  async _cleanupGenesisArtifactTemps (checkpointHash, snapshotHash) {
    const expected = Object.freeze({
      checkpoint: b4a.toString(checkpointHash, 'hex'),
      snapshot: b4a.toString(snapshotHash, 'hex')
    })
    let removed = 0
    for (const name of await fs.readdir(this.controlDirectory)) {
      const match = GENESIS_ARTIFACT_TEMP.exec(name)
      if (!match) continue
      if (match[2] !== expected[match[1]]) {
        throw new BlindProfile1StoreGenesisError(
          'genesis found a checkpoint/snapshot temporary outside its exact intent-bound hashes'
        )
      }
      const target = path.join(this.controlDirectory, name)
      if (!privateFile(await fs.lstat(target))) {
        throw new BlindProfile1StoreGenesisError('genesis checkpoint/snapshot temporary is not private')
      }
      await fs.unlink(target)
      removed++
      await this._fault('profile1-genesis:after-artifact-temp-unlink', { name, removed })
    }
    if (removed > 0) {
      await syncDirectory(this.controlDirectory)
      await this._fault('profile1-genesis:after-artifact-temp-directory-sync', { removed })
    }
  }

  async _publishGenesis () {
    const session = new BlindStoreSession({
      root: this.root,
      allowPristineBootstrap: true,
      faultInjector: this.faultInjector
    })
    let transactionStore = null
    let manifestStore = null
    let checkpointStore = null
    try {
      await session.open()
      await this._fault('profile1-genesis:after-store-session-open')
      let intentExists = true
      try {
        await this._verifyIntent()
      } catch (error) {
        if (!error || error.code !== 'ENOENT') throw error
        intentExists = false
      }
      if (!intentExists) await this._installIntent()
      await this._verifyIntent()

      const recovered = []
      transactionStore = new BlindTransactionStore(this._transactionOptions({
        storeSessionContext: session.lockContext()
      }))
      await transactionStore.open(async frame => { recovered.push(frame) })
      if (transactionStore.walSequence === 0n) {
        const appended = await transactionStore.append({
          ...this.genesisRecord,
          transactionId: this.genesisTransactionId
        })
        if (!sameGenesisFrame(appended, this.genesisRecord, this.genesisTransactionId)) {
          throw new BlindProfile1StoreGenesisError('newly appended genesis WAL frame differs from its intent')
        }
      } else if (transactionStore.walSequence !== 1n || recovered.length !== 1 ||
          !sameGenesisFrame(recovered[0], this.genesisRecord, this.genesisTransactionId)) {
        throw new BlindProfile1StoreGenesisError(
          'resumed genesis WAL is not exactly the one intent-bound sequence-1 frame'
        )
      }
      await this._fault('profile1-genesis:after-wal-genesis')

      manifestStore = new TwoSlotManifestStore({
        controlDirectory: this.controlDirectory,
        manifestKey: this.manifestKey,
        expectedBindings: this.bindings,
        faultInjector: this.faultInjector
      })
      await manifestStore.open()
      checkpointStore = new BlindLocalCheckpointStore({
        controlDirectory: this.controlDirectory,
        expectedBindings: this.bindings,
        snapshotSemanticVerifier: this.snapshotSemanticVerifier,
        maximumSnapshotBytes: this.maximumSnapshotBytes,
        maximumEntries: this.maximumEntries,
        faultInjector: this.faultInjector
      })
      await checkpointStore.open()
      let installedGenesis = null
      await transactionStore.withWalBarrier(async (walBarrierAuthority, verifiedWalAnchor) => {
        if (verifiedWalAnchor.sequence !== 1n) {
          throw new BlindProfile1StoreGenesisError('genesis WAL barrier is not sequence 1')
        }
        const snapshotBytes = this._snapshotBytes(verifiedWalAnchor)
        const checkpoint = checkpointValue(this.manifestTemplate, snapshotBytes, verifiedWalAnchor)
        const installed = await checkpointStore.initializeGenesis({
          walBarrierAuthority,
          verifiedWalAnchor,
          checkpoint,
          snapshotBytes
        })
        const manifest = decodeCanonical(blindStoreManifestV1, encodeCanonical(blindStoreManifestV1, {
          ...this.manifestTemplate,
          checkpointWalSequence: verifiedWalAnchor.sequence,
          checkpointHash: installed.headerHash,
          previousManifestHash: null,
          manifestRevision: 0n
        }), { copyBytes: true })
        const manifestSnapshot = await manifestStore.initialize(manifest)
        const validated = await checkpointStore.validateManifestCheckpoint({
          manifestSnapshot,
          walBarrierAuthority,
          verifiedWalAnchor
        })
        if (validated.header.checkpointRevision !== 1n || validated.walAnchor.sequence !== 1n) {
          throw new BlindProfile1StoreGenesisError('genesis checkpoint validation returned an unexpected anchor')
        }
        installedGenesis = Object.freeze({
          checkpointHash: b4a.from(installed.headerHash),
          snapshotHash: b4a.from(installed.header.snapshotHash)
        })
      })
      await this._fault('profile1-genesis:after-store-validation')
      if (!installedGenesis) throw new BlindProfile1StoreGenesisError('genesis validation produced no installed authority')
      await this._cleanupGenesisArtifactTemps(
        installedGenesis.checkpointHash,
        installedGenesis.snapshotHash
      )
      await this._removeIntent()
    } finally {
      if (checkpointStore) await checkpointStore.close().catch(() => {})
      if (manifestStore) await manifestStore.close().catch(() => {})
      if (transactionStore) await transactionStore.close().catch(() => {})
      await session.close().catch(() => {})
    }
  }

  async _recover (applyShadowFrame, applyRecoveredFrame) {
    const session = new BlindStoreSession({ root: this.root })
    let lease = null
    let manifestStore = null
    let checkpointStore = null
    let recoveryCoordinator = null
    let transactionStore = null
    let handedOff = false
    try {
      await session.open()
      lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), this.root)
      manifestStore = new TwoSlotManifestStore({
        controlDirectory: this.controlDirectory,
        manifestKey: this.manifestKey,
        expectedBindings: this.bindings
      })
      await manifestStore.open({ validationOnly: true })
      checkpointStore = new BlindLocalCheckpointStore({
        controlDirectory: this.controlDirectory,
        expectedBindings: this.bindings,
        snapshotSemanticVerifier: this.snapshotSemanticVerifier,
        maximumSnapshotBytes: this.maximumSnapshotBytes,
        maximumEntries: this.maximumEntries
      })
      await checkpointStore.open({ validationOnly: true })
      recoveryCoordinator = new BlindRecoveryValidationCoordinator({
        root: this.root,
        manifestStore,
        checkpointStore,
        maximumWalBytes: 1024 * 1024 * 1024,
        maximumWalFrames: 1000000,
        maximumWalPayloadBytes: 1024 * 1024
      })
      const recoveryAuthority = await recoveryCoordinator.validate({ lease, applyShadowFrame })
      transactionStore = new BlindTransactionStore(this._transactionOptions({
        recoveryHandoff: {
          lease,
          validationResult: recoveryAuthority,
          validate: async context => context.validationResult
        }
      }))
      await transactionStore.open(applyRecoveredFrame)
      handedOff = true
      lease = null
      await recoveryCoordinator.close()
      await checkpointStore.close()
      await manifestStore.close()
      return runtimeObject(transactionStore, session, recoveryAuthority)
    } catch (error) {
      if (transactionStore) await transactionStore.close().catch(() => {})
      if (recoveryCoordinator) await recoveryCoordinator.close().catch(() => {})
      if (checkpointStore) await checkpointStore.close().catch(() => {})
      if (manifestStore) await manifestStore.close().catch(() => {})
      if (lease) lease.release()
      await session.close().catch(() => {})
      throw error
    } finally {
      if (handedOff) {
        recoveryCoordinator = null
        checkpointStore = null
        manifestStore = null
      }
    }
  }

  async open (options = {}) {
    if (this.opened) throw new Error('profile-1 store genesis coordinator is one-shot')
    if (typeof options.applyShadowFrame !== 'function' || typeof options.applyRecoveredFrame !== 'function') {
      throw new TypeError('applyShadowFrame and applyRecoveredFrame must be awaited callbacks')
    }
    this.opened = true
    let intentExists = false
    let manifestExists = false
    try {
      await fs.lstat(this.intentPath)
      intentExists = true
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error
    }
    for (const slot of ['manifest-a.v1', 'manifest-b.v1']) {
      try {
        await fs.lstat(path.join(this.controlDirectory, slot))
        manifestExists = true
      } catch (error) {
        if (!error || error.code !== 'ENOENT') throw error
      }
    }
    if (intentExists || !manifestExists) await this._publishGenesis()
    return this._recover(options.applyShadowFrame, options.applyRecoveredFrame)
  }
}

export const BLIND_PROFILE1_GENESIS_LAYOUT = Object.freeze({
  intentFile: INTENT_FILE,
  intentTemporaryPattern: INTENT_TEMP.source,
  intentBytes: INTENT_BYTES,
  maximumIntentTemporaryFiles: MAX_INTENT_TEMPS,
  commitmentDomain: b4a.toString(COMMITMENT_DOMAIN, 'ascii'),
  macDomain: b4a.toString(INTENT_MAC_DOMAIN, 'ascii'),
  transactionIdDomain: b4a.toString(TRANSACTION_ID_DOMAIN, 'ascii')
})
