import {
  chmodSync,
  closeSync,
  constants as FS_CONSTANTS,
  existsSync,
  fsyncSync,
  fstatSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
  unlinkSync,
  writeSync
} from 'fs'
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto'
import { basename, dirname, isAbsolute, join, normalize, relative, resolve, sep } from 'path'
import DeviceFile from 'device-file'
import FDLock from 'fd-lock'

export const CORESTORE_GENERATION_ENVELOPE = Object.freeze({
  schema: 'hiverelay-corestore-generation-envelope-v1',
  triggerSchema: 'hiverelay-corestore-generation-trigger-v1',
  activationSchema: 'hiverelay-corestore-generation-activation-v1',
  importIntentSchema: 'hiverelay-corestore-legacy-import-intent-v1',
  importReceiptSchema: 'hiverelay-corestore-legacy-import-receipt-v1',
  restoreIntentSchema: 'hiverelay-corestore-device-restore-intent-v1',
  restoreReceiptSchema: 'hiverelay-corestore-device-restore-receipt-v1',
  mode: 'hc11-envelope-v1',
  generation: 'hc11-v1',
  authorityDirectory: '.hiverelay-generation',
  generationDirectory: 'generations',
  generationRoot: 'generations/hc11-v1',
  activationCoreName: 'hiverelay.corestore-generation.activation.v1',
  oldWriterPoisonDirectories: Object.freeze(['CORESTORE', 'primary-key']),
  triggerFile: 'hc11-trigger.v1.json',
  importIntentFile: 'legacy-import-intent.v1.json',
  importReceiptFile: 'legacy-import-receipt.v1.json',
  restoreIntentPrefix: 'device-restore-intent.',
  restoreReceiptPrefix: 'device-restore-receipt.'
})

export const CORESTORE_GENERATION_MIGRATION_BINDING = Object.freeze({
  toolingCommit: 'aa2f58ccc8f424eb1ed527c9a88de214b78d9d4a',
  profileId: 'hiverelay-d7b-cutover',
  profileSha256: 'sha256:f1d578f20a2529ce1280c2883df88ed1fcd9ab35ef1da240d3cb90430e894a41',
  profileAcceptedSourceCommit: '1cebfaad0eaccb9d58571238f5c865ac88b3dfc4',
  implementationBaseCommit: 'd40bd5dfbedad36886407a8f495c858103b2fb7a',
  accountingAmendmentSha256: 'sha256:88503728c096d068c18e3d76f88a788e64cbd7620115c458f359442d426b7af5',
  hypercoreStorageVersion: '3.2.0',
  hypercoreStoragePatchGitBlob: 'e14a5d1be3e0029ae84a5b71fee6aec717e99177',
  hypercoreStoragePatchSha256: 'sha256:fbcd793cfb4fd3334b04bfd9163a728064eef2500361cb83ef84e95d13b46b53',
  patchedMigrationSourceSha256: 'sha256:04153bfa8de76c0dc2a802936cbbeea6c22f20a1a79035cd65ed1957cc8ff2d5'
})

export const CORESTORE_GENERATION_CAPABILITIES = Object.freeze({
  triggerKind: 'hc11-only-write',
  importedCs6AndHc11ReaderImplemented: true,
  freshHc11ReaderImplemented: true,
  writesLegacyGeneration: false,
  oldWriterFenceScope: 'configured-envelope-path-only',
  oldD40Cs7Fence: 'reserved-directory-at-configured-envelope-CORESTORE',
  oldV024Cs6Fence: 'reserved-directory-at-configured-envelope-primary-key',
  directInnerPathFenceImplemented: false,
  blindCumulativeDualReadImplemented: false,
  blindMustRemainDisabledForThisProfile: true,
  pearMigrateRecordByteCompatible: false,
  pearMigrateAdapterRequired: true,
  pearMigrateAdapterImplemented: true,
  arbitraryPathByteCopyBootableWithoutRebind: false,
  signedAuthenticatedDeviceRebindImplemented: true,
  inventoryRequiresOwnerReadableTraversableDirectories: true,
  packedNpmPatchApplicationGuaranteed: true,
  liveFleetBackupProofIncluded: false
})

const AUTHORITY_KEY_FILE = 'authority-key.v1'
const INSTALLATION_ID_FILE = 'installation-id.v1'
const ENVELOPE_FILE = 'envelope.v1.json'
const TEMPORARY = /^\.(?:generation-envelope|hc11-trigger|legacy-import-(?:intent|receipt)|device-restore-(?:intent|receipt))\.[0-9a-f]{32}\.tmp$/
const COPY_TEMPORARY = /^\..+\.hiverelay-copy-[0-9a-f]{32}\.tmp$/
const RESTORE_INTENT = /^device-restore-intent\.([0-9]{16})\.v1\.json$/
const RESTORE_RECEIPT = /^device-restore-receipt\.([0-9]{16})\.v1\.json$/
const HEX_32 = /^[0-9a-f]{64}$/
const DIGEST = /^sha256:[0-9a-f]{64}$/
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const STATUS = new WeakMap()
const DEFAULT_MAX_ENTRIES = 250_000
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024 * 1024
const DEFAULT_MAX_DEPTH = 256
const LEGACY_CORESTORE_OWNED = Object.freeze(['cores', 'primary-key'])
const ENVELOPE_RESERVED = new Set([
  CORESTORE_GENERATION_ENVELOPE.authorityDirectory,
  CORESTORE_GENERATION_ENVELOPE.generationDirectory,
  ...CORESTORE_GENERATION_ENVELOPE.oldWriterPoisonDirectories
])
const AUTHORITY_ENTRIES = new Set([
  AUTHORITY_KEY_FILE,
  INSTALLATION_ID_FILE,
  ENVELOPE_FILE,
  CORESTORE_GENERATION_ENVELOPE.triggerFile,
  CORESTORE_GENERATION_ENVELOPE.importIntentFile,
  CORESTORE_GENERATION_ENVELOPE.importReceiptFile
])

export class CorestoreGenerationError extends Error {
  constructor (message, code = 'CORESTORE_GENERATION_INVALID') {
    super(message)
    this.name = 'CorestoreGenerationError'
    this.code = code
  }
}

// Offline operator ceremony. Production startup must only consume externally
// pinned receipt fields; it must never call this function and trust the result.
export function initializeCorestoreGenerationEnvelope (configuredRoot, rawOptions = {}) {
  const root = canonicalAbsolute(configuredRoot, 'generation envelope root')
  const rootState = privateDirectory(root, 'generation envelope root')
  if (rootState.realpath !== root) fail('generation envelope root must not traverse a symbolic link')
  const ceremony = normalizeCeremonyOptions(rawOptions)
  const names = readdirSync(root).sort(compareCodeUnits)

  if (names.length !== 0) {
    if (!ceremony.expectedInstallationId || !ceremony.expectedAuthorityKeySha256 ||
        !ceremony.expectedManifestSha256) {
      fail('a non-empty envelope can only be re-ratified with externally pinned installation, authority, and manifest digests',
        'CORESTORE_GENERATION_BINDING_REQUIRED')
    }
    if (!sameStrings(names, [...ENVELOPE_RESERVED].sort(compareCodeUnits))) {
      fail('generation ceremony accepts only an empty root or the exact reserved fresh-envelope layout',
        'CORESTORE_GENERATION_OFFLINE_IMPORT_REQUIRED')
    }
    const binding = readEnvelopeBinding(root, {
      ...ceremony,
      participant: ceremony.participants[0]
    }, { freshOnly: true })
    assertExactArray(binding.manifest.participants, ceremony.participants, 'generation participant manifest')
    assertExactArray(binding.manifest.topLevelSidecars, ceremony.topLevelSidecars, 'generation sidecar manifest')
    return publicEnvelopeReceipt(binding)
  }

  const paths = envelopePaths(root)
  mkdirPrivate(paths.authority)
  mkdirPrivate(paths.generations)
  mkdirPrivate(paths.generationRoot)
  for (const poison of paths.poison) mkdirPrivate(poison)
  const authorityKey = randomBytes(32)
  const installationId = randomBytes(32)
  writeExclusiveSynced(paths.authorityKey, authorityKey)
  writeExclusiveSynced(paths.installationId, installationId)
  const body = envelopeBody({
    installationId: installationId.toString('hex'),
    authorityKeySha256: digest(authorityKey),
    participants: ceremony.participants,
    topLevelSidecars: ceremony.topLevelSidecars
  })
  installOrValidateSigned(paths.envelope, body, authorityKey, 'generation-envelope')
  syncDirectory(paths.authority)
  syncDirectory(paths.generations)
  syncDirectory(root)
  const binding = readEnvelopeBinding(root, {
    mode: CORESTORE_GENERATION_ENVELOPE.mode,
    expectedInstallationId: body.installationId,
    expectedAuthorityKeySha256: body.authorityKeySha256,
    expectedManifestSha256: digest(canonicalBytes(body)),
    participant: ceremony.participants[0],
    faultInjector: null
  }, { freshOnly: true })
  injectSync(ceremony.faultInjector, 'corestore-generation:ceremony-complete', Object.freeze({ root }))
  return publicEnvelopeReceipt(binding)
}

export function corestoreGenerationOpenOptions (ceremony, overrides = {}) {
  if (!ceremony || ceremony.schema !== CORESTORE_GENERATION_ENVELOPE.schema) {
    throw new TypeError('offline generation ceremony receipt is required')
  }
  if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) {
    throw new TypeError('generation open-option overrides must be an object')
  }
  const unknown = Object.keys(overrides).filter(key => key !== 'participant' && key !== 'faultInjector')
  if (unknown.length) throw new TypeError(`generation open-option overrides contain unknown fields: ${unknown.join(', ')}`)
  return Object.freeze({
    mode: CORESTORE_GENERATION_ENVELOPE.mode,
    expectedInstallationId: ceremony.installationId,
    expectedAuthorityKeySha256: ceremony.authorityKeySha256,
    expectedManifestSha256: ceremony.manifestSha256,
    ...overrides
  })
}

export function corestoreGenerationPublicConfig (binding) {
  if (binding == null) return null
  if (!binding || typeof binding !== 'object' || Array.isArray(binding)) {
    throw new TypeError('hiverelayGeneration must be an object')
  }
  if (binding.mode !== CORESTORE_GENERATION_ENVELOPE.mode) {
    throw new TypeError(`generation mode must be ${CORESTORE_GENERATION_ENVELOPE.mode}`)
  }
  if (typeof binding.expectedInstallationId !== 'string' || !HEX_32.test(binding.expectedInstallationId)) {
    throw new TypeError('expectedInstallationId must be 32-byte lowercase hex')
  }
  for (const field of ['expectedAuthorityKeySha256', 'expectedManifestSha256']) {
    if (typeof binding[field] !== 'string' || !DIGEST.test(binding[field])) {
      throw new TypeError(`${field} must be a sha256 digest`)
    }
  }
  const normalized = {
    mode: binding.mode,
    expectedInstallationId: binding.expectedInstallationId,
    expectedAuthorityKeySha256: binding.expectedAuthorityKeySha256,
    expectedManifestSha256: binding.expectedManifestSha256
  }
  if (binding.participant != null) normalized.participant = safeName(binding.participant, 'generation participant')
  return Object.freeze(normalized)
}

export function corestoreGenerationParticipantOptions (binding, participant) {
  if (binding == null) return undefined
  if (!binding || typeof binding !== 'object' || Array.isArray(binding)) {
    throw new TypeError('hiverelayGeneration must be an object')
  }
  const allowed = new Set([
    'mode',
    'expectedInstallationId',
    'expectedAuthorityKeySha256',
    'expectedManifestSha256',
    'participant'
  ])
  const unknown = Object.keys(binding).filter(key => !allowed.has(key))
  if (unknown.length) throw new TypeError(`hiverelayGeneration contains unknown fields: ${unknown.join(', ')}`)
  binding = corestoreGenerationPublicConfig(binding)
  participant = safeName(participant, 'generation participant')
  if (binding.participant != null && binding.participant !== participant) {
    throw new TypeError(`generation participant is fixed to ${participant} for this runtime path`)
  }
  return Object.freeze({
    hiverelayGeneration: Object.freeze({ ...binding, participant })
  })
}

export function prepareCorestoreGenerationOpen (configuredRoot, rawOptions = {}) {
  const options = normalizeOpenOptions(rawOptions)
  const binding = readEnvelopeBinding(configuredRoot, options)
  const importState = readImportState(binding)
  if (importState.intent && !importState.receipt) {
    fail('legacy import is incomplete; resume and verify the offline import before opening Corestore',
      'CORESTORE_GENERATION_IMPORT_INCOMPLETE')
  }
  const restoreState = readDeviceRestoreState(binding, options)
  if (restoreState.intent && !restoreState.receipt) {
    fail('device restore is incomplete; resume the externally authorized rebind before production startup',
      'CORESTORE_GENERATION_RESTORE_INCOMPLETE')
  }
  if (importState.receipt) assertPatchedHypercoreStorageMigration()
  return Object.freeze({
    storage: binding.paths.generationRoot,
    binding,
    options,
    importReceipt: importState.receipt,
    restoreReceipt: restoreState.receipt,
    restoreReceiptSha256: restoreState.receiptSha256
  })
}

export function guardCorestoreGenerationReady (store, prepared) {
  if (!store || typeof store.ready !== 'function' || !prepared || !prepared.binding) {
    throw new TypeError('Corestore and prepared generation binding are required')
  }
  const originalReady = store.ready.bind(store)
  let readyPromise = null
  store.ready = function generationGuardedReady () {
    if (readyPromise) return readyPromise
    readyPromise = (async () => {
      await originalReady()
      await inject(prepared.options, 'corestore-generation:after-inner-ready', prepared.binding)
      const sentinel = await ensureActivationSentinel(store, prepared)
      await inject(prepared.options, 'corestore-generation:after-activation-sentinel-sync', sentinel)
      const receipt = await ensureHc11Trigger(prepared, sentinel)
      await inject(prepared.options, 'corestore-generation:before-ready-acknowledgement', receipt)
      STATUS.set(store, Object.freeze({
        ready: true,
        receipt,
        receiptSha256: digest(canonicalBytes(receipt)),
        configuredRoot: prepared.binding.root,
        generationRoot: prepared.binding.paths.generationRoot,
        participant: prepared.options.participant,
        capabilities: CORESTORE_GENERATION_CAPABILITIES
      }))
      return store
    })()
    return readyPromise
  }
  STATUS.set(store, Object.freeze({
    ready: false,
    configuredRoot: prepared.binding.root,
    generationRoot: prepared.binding.paths.generationRoot,
    participant: prepared.options.participant,
    capabilities: CORESTORE_GENERATION_CAPABILITIES
  }))
  return store
}

export function corestoreGenerationStatus (store) {
  return STATUS.get(store) || null
}

export function corestoreGenerationHealth (binding, store) {
  const status = store ? corestoreGenerationStatus(store) : null
  if (binding == null) {
    return Object.freeze({ configured: false, ready: false, generation: null, participant: null })
  }
  corestoreGenerationPublicConfig(binding)
  return Object.freeze({
    configured: true,
    ready: status?.ready === true,
    generation: CORESTORE_GENERATION_ENVELOPE.generation,
    participant: status?.participant || null,
    triggerKind: status?.receipt?.kind || null,
    triggerRecordSha256: status?.receipt?.triggerRecordSha256 || null,
    deviceRestoreReceiptSha256: status?.receipt?.deviceRestoreReceiptSha256 || null,
    blindCumulativeDualReadImplemented: false
  })
}

export function importLegacyCorestoreCopyIntoEnvelope ({ sourceRoot, envelopeRoot, ceremony, limits, faultInjector } = {}) {
  if (faultInjector != null && typeof faultInjector !== 'function') throw new TypeError('faultInjector must be a function')
  const source = canonicalAbsolute(sourceRoot, 'legacy copy root')
  const root = canonicalAbsolute(envelopeRoot, 'generation envelope root')
  assertDisjoint(source, root)
  assertLegacyImportSourcePreflight(source)
  const options = normalizeOpenOptions(corestoreGenerationOpenOptions(ceremony, {
    participant: ceremony?.participants?.[0]
  }))
  const binding = readEnvelopeBinding(root, options)
  assertPatchedHypercoreStorageMigration()
  const priorImport = readImportState(binding)
  if (existsSync(binding.paths.trigger)) {
    fail('legacy import cannot run after the HC11 activation trigger')
  }
  validateImportTargetState(binding, priorImport)
  const normalizedLimits = treeLimits(limits)
  const sourceNames = readdirSync(source).sort(compareCodeUnits)
  for (const ownedName of LEGACY_CORESTORE_OWNED) {
    if (!sourceNames.includes(ownedName)) {
      fail(`legacy CS6 copy is missing required ${ownedName}`, 'CORESTORE_GENERATION_LEGACY_LAYOUT_INVALID')
    }
  }
  const allowed = new Set([...LEGACY_CORESTORE_OWNED, ...binding.manifest.topLevelSidecars])
  const unknown = sourceNames.filter(name => !allowed.has(name))
  if (unknown.length) {
    fail(`legacy copy contains unclassified top-level entries: ${unknown.join(', ')}`,
      'CORESTORE_GENERATION_LEGACY_LAYOUT_INVALID')
  }
  const before = inventoryTree(source, normalizedLimits)
  const owned = projectInventory(before, new Set(LEGACY_CORESTORE_OWNED))
  const sidecars = projectInventory(before, new Set(binding.manifest.topLevelSidecars))
  const intentBody = {
    schema: CORESTORE_GENERATION_ENVELOPE.importIntentSchema,
    installationId: binding.installationId,
    sourceContentSha256: before.contentSha256,
    sourceEntries: before.entries.length,
    sourceBytes: before.totalBytes.toString(),
    cs6OwnedContentSha256: owned.contentSha256,
    relaySidecarContentSha256: sidecars.contentSha256,
    targetGeneration: CORESTORE_GENERATION_ENVELOPE.generation,
    method: 'exact-reviewed-offline-copy',
    migrationTooling: CORESTORE_GENERATION_MIGRATION_BINDING
  }
  installOrValidateSigned(binding.paths.importIntent, intentBody, binding.authorityKey, 'legacy-import-intent')
  injectSync(faultInjector, 'corestore-generation:after-import-intent-sync', Object.freeze({
    sourceContentSha256: before.contentSha256
  }))
  copyProjectedInventory(source, binding.paths.generationRoot, owned, faultInjector)
  injectSync(faultInjector, 'corestore-generation:after-import-corestore-copy-sync', Object.freeze({
    cs6OwnedContentSha256: owned.contentSha256
  }))
  copyProjectedInventory(source, binding.root, sidecars, faultInjector)
  const after = inventoryTree(source, normalizedLimits)
  if (!sameInventory(before, after, true)) fail('legacy source copy changed during offline import', 'CORESTORE_GENERATION_SOURCE_CHANGED')
  const importedOwned = projectInventory(inventoryTree(binding.paths.generationRoot, normalizedLimits),
    new Set(LEGACY_CORESTORE_OWNED))
  const importedSidecars = projectInventory(inventoryTree(binding.root, normalizedLimits),
    new Set(binding.manifest.topLevelSidecars))
  if (!sameInventory(owned, importedOwned, false) || !sameInventory(sidecars, importedSidecars, false)) {
    fail('imported generation does not exactly match the preserved legacy copy', 'CORESTORE_GENERATION_IMPORT_MISMATCH')
  }
  const receiptBody = {
    schema: CORESTORE_GENERATION_ENVELOPE.importReceiptSchema,
    installationId: binding.installationId,
    sourceContentSha256: before.contentSha256,
    importedCs6OwnedContentSha256: importedOwned.contentSha256,
    importedRelaySidecarContentSha256: importedSidecars.contentSha256,
    sourceEntries: before.entries.length,
    sourceBytes: before.totalBytes.toString(),
    targetGeneration: CORESTORE_GENERATION_ENVELOPE.generation,
    method: 'exact-reviewed-offline-copy',
    sourceUnchanged: true,
    exactCopyVerified: true,
    migrationTooling: CORESTORE_GENERATION_MIGRATION_BINDING
  }
  injectSync(faultInjector, 'corestore-generation:before-import-receipt-sync', Object.freeze({
    sourceContentSha256: before.contentSha256
  }))
  installOrValidateSigned(binding.paths.importReceipt, receiptBody, binding.authorityKey, 'legacy-import-receipt')
  syncDirectory(binding.paths.authority)
  return Object.freeze({ ...receiptBody, receiptSha256: signedFileDigest(binding.paths.importReceipt), liveFleetProof: false })
}

export function inventoryCorestoreGenerationTree (root, limits) {
  return publicInventory(inventoryTree(canonicalAbsolute(root, 'storage inventory root'), treeLimits(limits)))
}

export function createContentAddressedCorestoreBackup ({ sourceRoot, backupBase, limits, faultInjector } = {}) {
  if (faultInjector != null && typeof faultInjector !== 'function') throw new TypeError('faultInjector must be a function')
  const source = canonicalAbsolute(sourceRoot, 'backup source root')
  const base = canonicalAbsolute(backupBase, 'backup base root')
  assertDisjoint(source, base)
  privateDirectory(base, 'backup base root')
  const normalizedLimits = treeLimits(limits)
  const before = inventoryTree(source, normalizedLimits)
  const target = join(base, `sha256-${before.contentSha256.slice(7)}`)
  if (!existsSync(target)) mkdirPrivate(target)
  else privateDirectory(target, 'content-addressed backup root')
  copyInventoryResume(source, target, before, normalizedLimits, faultInjector)
  const after = inventoryTree(source, normalizedLimits)
  const backup = inventoryTree(target, normalizedLimits)
  if (!sameInventory(before, after, true) || !sameInventory(before, backup, false)) {
    fail('content-addressed backup did not preserve an exact stable source copy', 'CORESTORE_GENERATION_BACKUP_MISMATCH')
  }
  return Object.freeze({
    schema: 'hiverelay-corestore-content-addressed-backup-v1',
    contentSha256: before.contentSha256,
    entries: before.entries.length,
    totalBytes: before.totalBytes,
    backupRoot: target,
    sourceUnchanged: true,
    exactCopyVerified: true,
    liveFleetProof: false
  })
}

export function restoreContentAddressedCorestoreBackup ({
  backupRoot,
  restoreRoot,
  expectedContentSha256,
  limits,
  faultInjector
} = {}) {
  if (faultInjector != null && typeof faultInjector !== 'function') throw new TypeError('faultInjector must be a function')
  const source = canonicalAbsolute(backupRoot, 'content-addressed backup root')
  const target = canonicalAbsolute(restoreRoot, 'isolated restore root')
  assertDisjoint(source, target)
  privateDirectory(target, 'isolated restore root')
  if (typeof expectedContentSha256 !== 'string' || !DIGEST.test(expectedContentSha256)) {
    throw new TypeError('expectedContentSha256 must be a sha256 digest')
  }
  if (basename(source) !== `sha256-${expectedContentSha256.slice(7)}`) fail('backup path does not match its content address')
  const normalizedLimits = treeLimits(limits)
  const before = inventoryTree(source, normalizedLimits)
  if (before.contentSha256 !== expectedContentSha256) fail('backup contents do not match the expected content address')
  copyInventoryResume(source, target, before, normalizedLimits, faultInjector)
  const after = inventoryTree(source, normalizedLimits)
  const restored = inventoryTree(target, normalizedLimits)
  if (!sameInventory(before, after, true) || !sameInventory(before, restored, false)) {
    fail('isolated restore did not reproduce the exact backup', 'CORESTORE_GENERATION_RESTORE_MISMATCH')
  }
  return Object.freeze({
    schema: 'hiverelay-corestore-isolated-restore-v1',
    contentSha256: restored.contentSha256,
    entries: restored.entries.length,
    totalBytes: restored.totalBytes,
    backupUnchanged: true,
    exactRestoreVerified: true,
    liveFleetProof: false
  })
}

export async function rebindRestoredCorestoreDevice ({
  restoreRoot,
  ceremony,
  participant,
  expectedContentSha256,
  limits,
  faultInjector
} = {}) {
  if (typeof expectedContentSha256 !== 'string' || !DIGEST.test(expectedContentSha256)) {
    throw new TypeError('expectedContentSha256 must be a sha256 digest')
  }
  if (faultInjector != null && typeof faultInjector !== 'function') throw new TypeError('faultInjector must be a function')
  const options = normalizeOpenOptions(corestoreGenerationOpenOptions(ceremony, { participant }))
  const binding = readEnvelopeBinding(canonicalAbsolute(restoreRoot, 'restored envelope root'), options)
  const outerDescriptor = openSync(binding.paths.authority, FS_CONSTANTS.O_RDONLY)
  let outerLock
  try {
    outerLock = new FDLock(outerDescriptor, { wait: true })
    await outerLock.ready()
  } catch (error) {
    if (outerLock) await outerLock.close().catch(() => {})
    else closeSync(outerDescriptor)
    throw error
  }
  try {
    return await rebindRestoredCorestoreDeviceLocked({
      binding,
      options,
      expectedContentSha256,
      limits,
      faultInjector
    })
  } finally {
    await outerLock.close().catch(() => {})
  }
}

async function rebindRestoredCorestoreDeviceLocked ({
  binding,
  options,
  expectedContentSha256,
  limits,
  faultInjector
}) {
  const trigger = readRequiredSigned(binding.paths.trigger, binding.authorityKey, 'HC11 generation trigger')
  validateTriggerIdentity(trigger, binding, options)
  const normalizedLimits = treeLimits(limits)
  let state = readDeviceRestoreState(binding, options)

  // An exact rerun against an already closed sequence is idempotent. A backup
  // taken after that sequence has a different content address and therefore
  // starts the next chained record instead.
  if (!state.incomplete && state.receipt && state.intent.expectedContentSha256 === expectedContentSha256) {
    assertRestoreImmutablePayload(state.intent, immutableRestorePayloadInventory(binding, normalizedLimits))
    return publicRestoreReceipt(state.receipt, state.receiptPath)
  }

  let intent = state.incomplete ? state.intent : null
  let intentPath = state.incomplete ? state.intentPath : null
  let receiptPath = state.incomplete ? state.receiptPath : null
  if (intent) {
    if (intent.expectedContentSha256 !== expectedContentSha256) {
      fail('incomplete device restore intent does not match the externally selected backup')
    }
  } else {
    const restored = inventoryTree(binding.root, normalizedLimits)
    if (restored.contentSha256 !== expectedContentSha256) {
      fail('restored envelope does not match the externally selected content-addressed backup')
    }
    const preFingerprint = generationFingerprint(binding.paths.generationRoot, binding.installationId,
      trigger.activationSentinel)
    const acceptedFingerprint = state.receipt
      ? state.receipt.restoredGenerationFingerprintSha256
      : trigger.generationFingerprintSha256
    if (preFingerprint.fingerprintSha256 !== acceptedFingerprint) {
      fail('restored generation fingerprint is not the trigger or latest chained restore state')
    }
    const marker = join(binding.paths.generationRoot, 'CORESTORE')
    if (await DeviceFile.validate(marker, { id: null })) {
      fail('device restore ceremony requires a copied marker that is invalid on this device')
    }
    const immutable = immutableRestorePayloadInventory(binding, normalizedLimits)
    const sequence = state.nextSequence
    const previousRestoreReceiptSha256 = state.receiptSha256
    intentPath = restoreJournalPath(binding, 'intent', sequence)
    receiptPath = restoreJournalPath(binding, 'receipt', sequence)
    intent = {
      schema: CORESTORE_GENERATION_ENVELOPE.restoreIntentSchema,
      installationId: binding.installationId,
      sequence,
      previousRestoreReceiptSha256,
      expectedContentSha256,
      immutablePayloadSha256: immutable.contentSha256,
      immutablePayloadEntries: immutable.entries.length,
      immutablePayloadBytes: immutable.totalBytes.toString(),
      triggerRecordSha256: signedFileDigest(binding.paths.trigger),
      originalGenerationFingerprintSha256: trigger.generationFingerprintSha256,
      preRebindGenerationFingerprintSha256: preFingerprint.fingerprintSha256,
      preRebindCorestoreMarkerSha256: preFingerprint.corestoreMarkerSha256,
      databaseIdentitySha256: trigger.databaseIdentitySha256,
      method: 'signed-offline-device-marker-rebind'
    }
    installOrValidateSigned(intentPath, intent, binding.authorityKey, 'device-restore-intent')
    injectSync(faultInjector, 'corestore-generation:after-restore-intent-sync', Object.freeze(intent))
    state = readDeviceRestoreState(binding, options)
  }

  const immutableBeforeMarker = immutableRestorePayloadInventory(binding, normalizedLimits)
  assertRestoreImmutablePayload(intent, immutableBeforeMarker)

  const marker = join(binding.paths.generationRoot, 'CORESTORE')
  let markerValid = existsSync(marker) && await DeviceFile.validate(marker, { id: null })
  let device = null
  try {
    if (!markerValid) {
      if (existsSync(marker)) unlinkSync(marker)
      syncDirectory(binding.paths.generationRoot)
      injectSync(faultInjector, 'corestore-generation:after-old-device-marker-remove', Object.freeze({
        preRebindCorestoreMarkerSha256: intent.preRebindCorestoreMarkerSha256
      }))
      device = new DeviceFile(marker, { lock: true, data: { id: null } })
      await device.ready()
      fsyncRegularFile(marker, 'restored Corestore marker')
      syncDirectory(binding.paths.generationRoot)
      markerValid = await DeviceFile.validate(marker, { id: null })
      if (!markerValid) fail('new Corestore device marker did not validate on the restore device')
    } else {
      device = new DeviceFile(marker, { create: false, lock: true, data: { id: null } })
      await device.ready()
    }

    const sentinel = trigger.activationSentinel
    const fingerprint = generationFingerprint(binding.paths.generationRoot, binding.installationId, sentinel)
    if (fingerprint.databaseIdentitySha256 !== intent.databaseIdentitySha256) {
      fail('device rebind changed the restored Corestore database identity')
    }
    const immutableBeforeReceipt = immutableRestorePayloadInventory(binding, normalizedLimits)
    assertRestoreImmutablePayload(intent, immutableBeforeReceipt)
    injectSync(faultInjector, 'corestore-generation:after-new-device-marker-sync', Object.freeze({
      sequence: intent.sequence,
      restoredCorestoreMarkerSha256: fingerprint.corestoreMarkerSha256
    }))
    await injectRestore(faultInjector, 'corestore-generation:before-device-restore-receipt', Object.freeze({
      sequence: intent.sequence,
      restoredCorestoreMarkerSha256: fingerprint.corestoreMarkerSha256
    }))
    const receiptBody = {
      schema: CORESTORE_GENERATION_ENVELOPE.restoreReceiptSchema,
      installationId: binding.installationId,
      sequence: intent.sequence,
      previousRestoreReceiptSha256: intent.previousRestoreReceiptSha256,
      intentRecordSha256: signedFileDigest(intentPath),
      expectedContentSha256: intent.expectedContentSha256,
      immutablePayloadSha256: intent.immutablePayloadSha256,
      triggerRecordSha256: signedFileDigest(binding.paths.trigger),
      originalGenerationFingerprintSha256: trigger.generationFingerprintSha256,
      preRebindGenerationFingerprintSha256: intent.preRebindGenerationFingerprintSha256,
      preRebindCorestoreMarkerSha256: intent.preRebindCorestoreMarkerSha256,
      restoredGenerationFingerprintSha256: fingerprint.fingerprintSha256,
      originalCorestoreMarkerSha256: trigger.corestoreMarkerSha256,
      restoredCorestoreMarkerSha256: fingerprint.corestoreMarkerSha256,
      databaseIdentitySha256: fingerprint.databaseIdentitySha256,
      activationSentinel: sentinel,
      method: 'signed-offline-device-marker-rebind',
      oldWriterFencePreserved: true,
      exactBackupVerifiedBeforeMutation: true,
      immutablePayloadVerifiedBeforeReceipt: true,
      deviceMarkerExplicitlyFsynced: true,
      deviceMarkerLockHeldThroughReceipt: true
    }
    installOrValidateSigned(receiptPath, receiptBody, binding.authorityKey, 'device-restore-receipt')
    syncDirectory(binding.paths.authority)
    return publicRestoreReceipt(receiptBody, receiptPath)
  } finally {
    if (device) await device.close().catch(() => {})
  }
}

export function assertPatchedHypercoreStorageMigration () {
  let file
  try {
    const resolved = import.meta.resolve('hypercore-storage/migrations/0/index.js')
    if (!resolved.startsWith('file://')) throw new Error('installed migration did not resolve to a file')
    file = decodeURIComponent(new URL(resolved).pathname)
  } catch {
    fail('the installed hypercore-storage migration source is unavailable; npm-only package installs must explicitly apply the tracked patch',
      'CORESTORE_GENERATION_MIGRATION_PATCH_MISSING')
  }
  const actual = digest(readRegularFile(file, 'installed hypercore-storage migration source'))
  if (actual !== CORESTORE_GENERATION_MIGRATION_BINDING.patchedMigrationSourceSha256) {
    fail('the installed hypercore-storage 3.2.0 migration is not the exact tracked patched source',
      'CORESTORE_GENERATION_MIGRATION_PATCH_MISSING')
  }
  return Object.freeze({
    version: CORESTORE_GENERATION_MIGRATION_BINDING.hypercoreStorageVersion,
    installedSource: file,
    installedSourceSha256: actual,
    patchSha256: CORESTORE_GENERATION_MIGRATION_BINDING.hypercoreStoragePatchSha256
  })
}

function validateImportTargetState (binding, priorImport) {
  const generationNames = readdirSync(binding.paths.generationRoot).sort(compareCodeUnits)
  const unexpectedGeneration = generationNames.filter(name => !LEGACY_CORESTORE_OWNED.includes(name))
  if (unexpectedGeneration.length) {
    fail(`legacy import target contains undeclared entries: ${unexpectedGeneration.join(', ')}`,
      'CORESTORE_GENERATION_IMPORT_MISMATCH')
  }
  const presentSidecars = binding.manifest.topLevelSidecars.filter(name => existsSync(join(binding.root, name)))
  if (!priorImport.intent && (generationNames.length || presentSidecars.length)) {
    fail('legacy import target is populated without a signed import intent',
      'CORESTORE_GENERATION_IMPORT_MISMATCH')
  }
}

async function ensureActivationSentinel (store, prepared) {
  const { binding, options } = prepared
  verifyEnvelopeLayout(binding, options)
  const body = activationBody(binding, options)
  const bytes = canonicalBytes(body)
  const core = store.get({ name: CORESTORE_GENERATION_ENVELOPE.activationCoreName })
  await core.ready()
  if (core.length === 0) await core.append(bytes)
  if (core.length !== 1) fail('HC11 activation sentinel has an invalid length')
  const actual = await core.get(0)
  if (!Buffer.from(actual).equals(bytes)) fail('HC11 activation sentinel does not match this installation authority')
  const evidence = activationEvidence(core, bytes, options.participant)
  await core.close()
  return evidence
}

function activationBody (binding, options) {
  return {
    schema: CORESTORE_GENERATION_ENVELOPE.activationSchema,
    installationId: binding.installationId,
    manifestSha256: binding.manifestSha256,
    generation: CORESTORE_GENERATION_ENVELOPE.generation,
    participant: options.participant,
    migrationTooling: CORESTORE_GENERATION_MIGRATION_BINDING
  }
}

function activationEvidence (core, bytes, participant) {
  return Object.freeze({
    schema: CORESTORE_GENERATION_ENVELOPE.activationSchema,
    key: Buffer.from(core.key).toString('hex'),
    length: core.length,
    fork: core.fork,
    blockSha256: digest(bytes),
    participant
  })
}

function validateTriggerIdentity (trigger, binding, options) {
  if (trigger.schema !== CORESTORE_GENERATION_ENVELOPE.triggerSchema ||
      trigger.installationId !== binding.installationId ||
      trigger.manifestSha256 !== binding.manifestSha256 ||
      trigger.kind !== 'hc11-only-write' || trigger.result !== 'acknowledged' ||
      trigger.participant !== options.participant || trigger.sequence !== 1) {
    fail('HC11 generation trigger does not match the restored installation')
  }
}

function validateRestoreReceipt (receipt, binding, trigger, intent, intentPath) {
  if (receipt.schema !== CORESTORE_GENERATION_ENVELOPE.restoreReceiptSchema ||
      receipt.installationId !== binding.installationId ||
      receipt.sequence !== intent.sequence ||
      receipt.previousRestoreReceiptSha256 !== intent.previousRestoreReceiptSha256 ||
      receipt.intentRecordSha256 !== signedFileDigest(intentPath) ||
      receipt.expectedContentSha256 !== intent.expectedContentSha256 ||
      receipt.immutablePayloadSha256 !== intent.immutablePayloadSha256 ||
      receipt.triggerRecordSha256 !== signedFileDigest(binding.paths.trigger) ||
      receipt.originalGenerationFingerprintSha256 !== trigger.generationFingerprintSha256 ||
      receipt.preRebindGenerationFingerprintSha256 !== intent.preRebindGenerationFingerprintSha256 ||
      receipt.preRebindCorestoreMarkerSha256 !== intent.preRebindCorestoreMarkerSha256 ||
      receipt.originalCorestoreMarkerSha256 !== trigger.corestoreMarkerSha256 ||
      receipt.databaseIdentitySha256 !== trigger.databaseIdentitySha256 ||
      typeof receipt.restoredGenerationFingerprintSha256 !== 'string' || !DIGEST.test(receipt.restoredGenerationFingerprintSha256) ||
      typeof receipt.restoredCorestoreMarkerSha256 !== 'string' || !DIGEST.test(receipt.restoredCorestoreMarkerSha256) ||
      !canonicalBytes(receipt.activationSentinel).equals(canonicalBytes(trigger.activationSentinel)) ||
      receipt.method !== 'signed-offline-device-marker-rebind' ||
      receipt.oldWriterFencePreserved !== true || receipt.exactBackupVerifiedBeforeMutation !== true ||
      receipt.immutablePayloadVerifiedBeforeReceipt !== true || receipt.deviceMarkerExplicitlyFsynced !== true ||
      receipt.deviceMarkerLockHeldThroughReceipt !== true) {
    fail('device restore receipt does not close the signed restore intent')
  }
}

function publicRestoreReceipt (receipt, receiptPath) {
  return Object.freeze({
    ...receipt,
    receiptSha256: signedFileDigest(receiptPath),
    operationalWriterRestoreImplemented: true,
    arbitraryDirectCopyBootable: false,
    liveFleetProof: false
  })
}

async function ensureHc11Trigger (prepared, sentinel) {
  const { binding, options, importReceipt, restoreReceipt, restoreReceiptSha256 } = prepared
  verifyEnvelopeLayout(binding, options)
  const fingerprint = generationFingerprint(binding.paths.generationRoot, binding.installationId, sentinel)
  const importedLegacy = importReceipt != null
  const body = {
    schema: CORESTORE_GENERATION_ENVELOPE.triggerSchema,
    installationId: binding.installationId,
    manifestSha256: binding.manifestSha256,
    sequence: 1,
    kind: 'hc11-only-write',
    result: 'acknowledged',
    participant: options.participant,
    generation: CORESTORE_GENERATION_ENVELOPE.generation,
    generationFingerprintSha256: fingerprint.fingerprintSha256,
    corestoreMarkerSha256: fingerprint.corestoreMarkerSha256,
    databaseIdentitySha256: fingerprint.databaseIdentitySha256,
    activationSentinel: sentinel,
    importedLegacyContentSha256: importedLegacy ? importReceipt.sourceContentSha256 : null,
    verifiedReaderState: importedLegacy ? 'imported-cs6-plus-hc11' : 'fresh-hc11-only',
    pearMigrateCandidateWriterMode: importedLegacy ? 'dual-read' : null,
    oldWriterFence: {
      scope: 'configured-envelope-path-only',
      d40Cs7: 'reserved-directory-at-envelope-CORESTORE',
      v024Cs6: 'reserved-directory-at-envelope-primary-key',
      directInnerPathFenced: false
    },
    blindCumulativeDualReadImplemented: false,
    migrationTooling: CORESTORE_GENERATION_MIGRATION_BINDING
  }
  const signed = signedValue(body, binding.authorityKey)
  const bytes = canonicalBytes(signed)
  const existing = readOptionalSigned(binding.paths.trigger, binding.authorityKey, 'HC11 generation trigger')
  if (existing) {
    if (restoreReceipt) {
      const originalBody = {
        ...body,
        generationFingerprintSha256: restoreReceipt.originalGenerationFingerprintSha256,
        corestoreMarkerSha256: restoreReceipt.originalCorestoreMarkerSha256
      }
      assertExactBody(existing, originalBody, 'pre-restore HC11 generation trigger')
      if (fingerprint.fingerprintSha256 !== restoreReceipt.restoredGenerationFingerprintSha256 ||
          fingerprint.corestoreMarkerSha256 !== restoreReceipt.restoredCorestoreMarkerSha256 ||
          !canonicalBytes(sentinel).equals(canonicalBytes(restoreReceipt.activationSentinel))) {
        fail('restored generation does not match its signed device rebind receipt')
      }
    } else {
      assertExactBody(existing, body, 'HC11 generation trigger')
    }
  } else {
    const temporary = temporaryPath(binding.paths.authority, 'hc11-trigger')
    writeExclusiveSynced(temporary, bytes)
    await inject(options, 'corestore-generation:after-trigger-temp-sync', Object.freeze({
      generationFingerprintSha256: fingerprint.fingerprintSha256
    }))
    try {
      linkSync(temporary, binding.paths.trigger)
      syncDirectory(binding.paths.authority)
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error
      const raced = readRequiredSigned(binding.paths.trigger, binding.authorityKey, 'HC11 generation trigger')
      assertExactBody(raced, body, 'HC11 generation trigger')
    } finally {
      unlinkTemporary(temporary)
      syncDirectory(binding.paths.authority)
    }
    await inject(options, 'corestore-generation:after-trigger-link', Object.freeze({
      generationFingerprintSha256: fingerprint.fingerprintSha256
    }))
  }
  verifyEnvelopeLayout(binding, options)
  return Object.freeze({
    schema: 'hiverelay-corestore-generation-trigger-receipt-v1',
    installationId: binding.installationId,
    manifestSha256: binding.manifestSha256,
    sequence: 1,
    kind: 'hc11-only-write',
    result: 'acknowledged',
    participant: options.participant,
    generationFingerprintSha256: fingerprint.fingerprintSha256,
    activationSentinel: sentinel,
    triggerRecordSha256: signedFileDigest(binding.paths.trigger),
    deviceRestoreReceiptSha256: restoreReceipt == null ? null : restoreReceiptSha256,
    importedLegacyContentSha256: importedLegacy ? importReceipt.sourceContentSha256 : null,
    verifiedReaderState: importedLegacy ? 'imported-cs6-plus-hc11' : 'fresh-hc11-only',
    pearMigrateCandidateWriterMode: importedLegacy ? 'dual-read' : null,
    migrationRecordCompatible: false,
    migrationRecordAdapterRequired: true,
    blindCumulativeDualReadImplemented: false,
    migrationTooling: CORESTORE_GENERATION_MIGRATION_BINDING
  })
}

function readEnvelopeBinding (configuredRoot, options, { freshOnly = false } = {}) {
  const root = canonicalAbsolute(configuredRoot, 'generation envelope root')
  privateDirectory(root, 'generation envelope root')
  const paths = envelopePaths(root)
  if (!existsSync(paths.authority)) {
    const names = readdirSync(root)
    const oldRoot = names.some(name => ['CORESTORE', 'primary-key', 'cores', 'db'].includes(name))
    fail(oldRoot
      ? 'top-level CS6/CS7 roots are never reorganized in place; use a reviewed offline copy and fresh generation envelope'
      : 'generation envelope ceremony is missing',
    oldRoot ? 'CORESTORE_GENERATION_OFFLINE_IMPORT_REQUIRED' : 'CORESTORE_GENERATION_MISSING')
  }
  privateDirectory(paths.authority, 'generation authority directory')
  privateDirectory(paths.generations, 'generation directory')
  privateDirectory(paths.generationRoot, 'HC11 generation root')
  verifyPoison(paths)
  assertAuthorityNames(paths.authority)
  const authorityKey = readPrivateFile(paths.authorityKey, 'generation authority key', 32)
  const installationId = readPrivateFile(paths.installationId, 'generation installation id', 32)
  const authorityKeySha256 = digest(authorityKey)
  const installationIdHex = installationId.toString('hex')
  if (installationIdHex !== options.expectedInstallationId ||
      authorityKeySha256 !== options.expectedAuthorityKeySha256) {
    fail('generation envelope does not match the externally configured installation authority',
      'CORESTORE_GENERATION_BINDING_MISMATCH')
  }
  const manifest = readRequiredSigned(paths.envelope, authorityKey, 'generation envelope')
  if (!Array.isArray(manifest.participants) || !Array.isArray(manifest.topLevelSidecars)) {
    fail('generation envelope has no complete participant and sidecar manifest')
  }
  const expected = envelopeBody({
    installationId: installationIdHex,
    authorityKeySha256,
    participants: normalizedNames(manifest.participants, 'manifest participants', 32),
    topLevelSidecars: normalizeSidecars(manifest.topLevelSidecars)
  })
  assertExactBody(manifest, expected, 'generation envelope')
  const manifestSha256 = digest(canonicalBytes(manifest))
  if (manifestSha256 !== options.expectedManifestSha256) {
    fail('generation envelope manifest does not match the external release configuration',
      'CORESTORE_GENERATION_BINDING_MISMATCH')
  }
  if (!manifest.participants.includes(options.participant)) {
    fail(`generation participant ${options.participant} is absent from the signed manifest`,
      'CORESTORE_GENERATION_PARTICIPANT_MISSING')
  }
  const binding = Object.freeze({
    root,
    paths,
    authorityKey,
    installationId: installationIdHex,
    authorityKeySha256,
    manifestSha256,
    manifest
  })
  verifyEnvelopeLayout(binding, options, { freshOnly })
  return binding
}

function envelopeBody ({ installationId, authorityKeySha256, participants, topLevelSidecars }) {
  return {
    schema: CORESTORE_GENERATION_ENVELOPE.schema,
    mode: CORESTORE_GENERATION_ENVELOPE.mode,
    generation: CORESTORE_GENERATION_ENVELOPE.generation,
    generationRoot: CORESTORE_GENERATION_ENVELOPE.generationRoot,
    installationId,
    authorityKeySha256,
    participants,
    topLevelSidecars,
    poisonDirectories: [...CORESTORE_GENERATION_ENVELOPE.oldWriterPoisonDirectories],
    migrationTooling: CORESTORE_GENERATION_MIGRATION_BINDING
  }
}

function readImportState (binding) {
  const intent = readOptionalSigned(binding.paths.importIntent, binding.authorityKey, 'legacy import intent')
  const receipt = readOptionalSigned(binding.paths.importReceipt, binding.authorityKey, 'legacy import receipt')
  if (receipt && !intent) fail('legacy import receipt has no signed intent')
  if (intent && (intent.schema !== CORESTORE_GENERATION_ENVELOPE.importIntentSchema ||
      intent.installationId !== binding.installationId || intent.method !== 'exact-reviewed-offline-copy' ||
      intent.targetGeneration !== CORESTORE_GENERATION_ENVELOPE.generation)) {
    fail('legacy import intent is invalid')
  }
  if (receipt && (receipt.schema !== CORESTORE_GENERATION_ENVELOPE.importReceiptSchema ||
      receipt.installationId !== binding.installationId ||
      receipt.sourceContentSha256 !== intent.sourceContentSha256 ||
      receipt.exactCopyVerified !== true || receipt.sourceUnchanged !== true)) {
    fail('legacy import receipt does not close its exact signed intent')
  }
  return { intent, receipt }
}

function readDeviceRestoreState (binding, options) {
  const records = restoreJournalRecords(binding)
  if (records.length === 0) {
    return {
      intent: null,
      receipt: null,
      intentPath: null,
      receiptPath: null,
      receiptSha256: null,
      incomplete: false,
      nextSequence: 1
    }
  }
  const trigger = readRequiredSigned(binding.paths.trigger, binding.authorityKey, 'HC11 generation trigger')
  validateTriggerIdentity(trigger, binding, options)

  let previousReceiptSha256 = null
  let previousReceipt = null
  let latest = null
  for (let index = 0; index < records.length; index++) {
    const record = records[index]
    const sequence = index + 1
    if (record.sequence !== sequence || !record.intentPath) {
      fail('device restore journal must be a contiguous sequence of signed intents')
    }
    const intent = readRequiredSigned(record.intentPath, binding.authorityKey,
      `device restore intent ${sequence}`)
    if (intent.schema !== CORESTORE_GENERATION_ENVELOPE.restoreIntentSchema ||
        intent.installationId !== binding.installationId || intent.sequence !== sequence ||
        intent.previousRestoreReceiptSha256 !== previousReceiptSha256 ||
        intent.triggerRecordSha256 !== signedFileDigest(binding.paths.trigger) ||
        typeof intent.expectedContentSha256 !== 'string' || !DIGEST.test(intent.expectedContentSha256) ||
        typeof intent.immutablePayloadSha256 !== 'string' || !DIGEST.test(intent.immutablePayloadSha256) ||
        !Number.isSafeInteger(intent.immutablePayloadEntries) || intent.immutablePayloadEntries < 0 ||
        typeof intent.immutablePayloadBytes !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(intent.immutablePayloadBytes) ||
        intent.originalGenerationFingerprintSha256 !== trigger.generationFingerprintSha256 ||
        intent.preRebindGenerationFingerprintSha256 !== (previousReceipt
          ? previousReceipt.restoredGenerationFingerprintSha256
          : trigger.generationFingerprintSha256) ||
        intent.preRebindCorestoreMarkerSha256 !== (previousReceipt
          ? previousReceipt.restoredCorestoreMarkerSha256
          : trigger.corestoreMarkerSha256) ||
        intent.databaseIdentitySha256 !== trigger.databaseIdentitySha256 ||
        intent.method !== 'signed-offline-device-marker-rebind') {
      fail(`device restore intent ${sequence} is invalid`)
    }
    if (!record.receiptPath) {
      if (index !== records.length - 1) fail('only the final device restore journal record may be incomplete')
      latest = { ...record, intent, receipt: null, receiptSha256: null }
      continue
    }
    const receipt = readRequiredSigned(record.receiptPath, binding.authorityKey,
      `device restore receipt ${sequence}`)
    validateRestoreReceipt(receipt, binding, trigger, intent, record.intentPath)
    const receiptSha256 = signedFileDigest(record.receiptPath)
    previousReceiptSha256 = receiptSha256
    previousReceipt = receipt
    latest = { ...record, intent, receipt, receiptSha256 }
  }

  if (latest.receipt) {
    const fingerprint = generationFingerprint(binding.paths.generationRoot, binding.installationId,
      latest.receipt.activationSentinel)
    if (fingerprint.fingerprintSha256 !== latest.receipt.restoredGenerationFingerprintSha256 ||
        fingerprint.corestoreMarkerSha256 !== latest.receipt.restoredCorestoreMarkerSha256) {
      fail('restored generation does not match its latest signed device rebind receipt')
    }
  }
  return {
    intent: latest.intent,
    receipt: latest.receipt,
    intentPath: latest.intentPath,
    receiptPath: latest.receiptPath || restoreJournalPath(binding, 'receipt', latest.sequence),
    receiptSha256: latest.receiptSha256,
    incomplete: latest.receipt == null,
    nextSequence: latest.receipt == null ? latest.sequence : latest.sequence + 1
  }
}

function generationFingerprint (generationRoot, installationId, sentinel) {
  const corestoreMarkerSha256 = digest(readRegularFile(join(generationRoot, 'CORESTORE'), 'nested Corestore marker'))
  const databaseIdentitySha256 = digest(readRegularFile(join(generationRoot, 'db', 'IDENTITY'), 'nested database identity'))
  const fingerprintSha256 = digest(Buffer.concat([
    Buffer.from('hiverelay.corestore-generation-fingerprint.v1\0', 'ascii'),
    Buffer.from(installationId, 'hex'),
    Buffer.from(corestoreMarkerSha256.slice(7), 'hex'),
    Buffer.from(databaseIdentitySha256.slice(7), 'hex'),
    Buffer.from(sentinel.blockSha256.slice(7), 'hex'),
    Buffer.from(sentinel.key, 'hex')
  ]))
  return { fingerprintSha256, corestoreMarkerSha256, databaseIdentitySha256 }
}

function normalizeCeremonyOptions (value) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('generation ceremony options must be an object')
  }
  const participants = normalizedNames(value.participants, 'participants', 32)
  const topLevelSidecars = normalizeSidecars(value.topLevelSidecars || [])
  if (value.faultInjector != null && typeof value.faultInjector !== 'function') {
    throw new TypeError('generation faultInjector must be a function')
  }
  for (const [field, pattern] of [
    ['expectedInstallationId', HEX_32],
    ['expectedAuthorityKeySha256', DIGEST],
    ['expectedManifestSha256', DIGEST]
  ]) {
    if (value[field] != null && (typeof value[field] !== 'string' || !pattern.test(value[field]))) {
      throw new TypeError(`${field} is invalid`)
    }
  }
  return Object.freeze({
    participants,
    topLevelSidecars,
    expectedInstallationId: value.expectedInstallationId || null,
    expectedAuthorityKeySha256: value.expectedAuthorityKeySha256 || null,
    expectedManifestSha256: value.expectedManifestSha256 || null,
    faultInjector: value.faultInjector || null
  })
}

function normalizeSidecars (value) {
  if (!Array.isArray(value) || value.length > 128) throw new TypeError('topLevelSidecars must contain 0..128 entries')
  const names = value.map(name => safeName(name, 'topLevelSidecars')).sort(compareCodeUnits)
  if (new Set(names).size !== names.length) throw new TypeError('topLevelSidecars entries must be unique')
  for (const name of names) {
    if (ENVELOPE_RESERVED.has(name) || LEGACY_CORESTORE_OWNED.includes(name)) {
      throw new TypeError(`topLevelSidecars contains reserved entry ${name}`)
    }
  }
  return Object.freeze(names)
}

function normalizeOpenOptions (value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('hiverelayGeneration must be an object')
  const allowed = new Set([
    'mode',
    'expectedInstallationId',
    'expectedAuthorityKeySha256',
    'expectedManifestSha256',
    'participant',
    'faultInjector'
  ])
  const unknown = Object.keys(value).filter(key => !allowed.has(key))
  if (unknown.length) throw new TypeError(`hiverelayGeneration contains unknown fields: ${unknown.join(', ')}`)
  if (value.mode !== CORESTORE_GENERATION_ENVELOPE.mode) {
    throw new TypeError(`generation mode must be ${CORESTORE_GENERATION_ENVELOPE.mode}`)
  }
  if (typeof value.expectedInstallationId !== 'string' || !HEX_32.test(value.expectedInstallationId)) {
    throw new TypeError('expectedInstallationId must be 32-byte lowercase hex')
  }
  for (const field of ['expectedAuthorityKeySha256', 'expectedManifestSha256']) {
    if (typeof value[field] !== 'string' || !DIGEST.test(value[field])) throw new TypeError(`${field} must be a sha256 digest`)
  }
  const participant = safeName(value.participant, 'generation participant')
  if (value.faultInjector != null && typeof value.faultInjector !== 'function') {
    throw new TypeError('generation faultInjector must be a function')
  }
  return Object.freeze({
    mode: value.mode,
    expectedInstallationId: value.expectedInstallationId,
    expectedAuthorityKeySha256: value.expectedAuthorityKeySha256,
    expectedManifestSha256: value.expectedManifestSha256,
    participant,
    faultInjector: value.faultInjector || null
  })
}

function normalizedNames (value, label, max) {
  if (!Array.isArray(value) || value.length < 1 || value.length > max) {
    throw new TypeError(`${label} must contain 1..${max} entries`)
  }
  const names = value.map(name => safeName(name, label)).sort(compareCodeUnits)
  if (new Set(names).size !== names.length) throw new TypeError(`${label} entries must be unique`)
  return Object.freeze(names)
}

function safeName (name, label) {
  if (typeof name !== 'string' || !SAFE_NAME.test(name) || name === '.' || name === '..') {
    throw new TypeError(`${label} entries must be safe top-level names`)
  }
  return name
}

function publicEnvelopeReceipt (binding) {
  return Object.freeze({
    schema: CORESTORE_GENERATION_ENVELOPE.schema,
    mode: CORESTORE_GENERATION_ENVELOPE.mode,
    installationId: binding.installationId,
    authorityKeySha256: binding.authorityKeySha256,
    manifestSha256: binding.manifestSha256,
    participants: Object.freeze([...binding.manifest.participants]),
    topLevelSidecars: Object.freeze([...binding.manifest.topLevelSidecars]),
    generation: CORESTORE_GENERATION_ENVELOPE.generation,
    generationRoot: CORESTORE_GENERATION_ENVELOPE.generationRoot,
    oldWriterFenceScope: CORESTORE_GENERATION_CAPABILITIES.oldWriterFenceScope,
    migrationTooling: CORESTORE_GENERATION_MIGRATION_BINDING
  })
}

function envelopePaths (root) {
  const authority = join(root, CORESTORE_GENERATION_ENVELOPE.authorityDirectory)
  const generations = join(root, CORESTORE_GENERATION_ENVELOPE.generationDirectory)
  return Object.freeze({
    authority,
    generations,
    generationRoot: join(root, ...CORESTORE_GENERATION_ENVELOPE.generationRoot.split('/')),
    poison: CORESTORE_GENERATION_ENVELOPE.oldWriterPoisonDirectories.map(name => join(root, name)),
    authorityKey: join(authority, AUTHORITY_KEY_FILE),
    installationId: join(authority, INSTALLATION_ID_FILE),
    envelope: join(authority, ENVELOPE_FILE),
    trigger: join(authority, CORESTORE_GENERATION_ENVELOPE.triggerFile),
    importIntent: join(authority, CORESTORE_GENERATION_ENVELOPE.importIntentFile),
    importReceipt: join(authority, CORESTORE_GENERATION_ENVELOPE.importReceiptFile)
  })
}

function restoreJournalPath (binding, kind, sequence) {
  if ((kind !== 'intent' && kind !== 'receipt') || !Number.isSafeInteger(sequence) ||
      sequence < 1) {
    fail('device restore journal sequence is invalid')
  }
  const prefix = kind === 'intent'
    ? CORESTORE_GENERATION_ENVELOPE.restoreIntentPrefix
    : CORESTORE_GENERATION_ENVELOPE.restoreReceiptPrefix
  return join(binding.paths.authority, `${prefix}${String(sequence).padStart(16, '0')}.v1.json`)
}

function restoreJournalRecords (binding) {
  const records = new Map()
  for (const name of readdirSync(binding.paths.authority)) {
    const intent = RESTORE_INTENT.exec(name)
    const receipt = RESTORE_RECEIPT.exec(name)
    if (!intent && !receipt) continue
    const sequence = Number((intent || receipt)[1])
    if (!Number.isSafeInteger(sequence) || sequence < 1) fail('device restore journal filename is invalid')
    let record = records.get(sequence)
    if (!record) {
      record = { sequence, intentPath: null, receiptPath: null }
      records.set(sequence, record)
    }
    if (intent) record.intentPath = join(binding.paths.authority, name)
    else record.receiptPath = join(binding.paths.authority, name)
  }
  return [...records.values()].sort((left, right) => left.sequence - right.sequence)
}

function verifyEnvelopeLayout (binding, options, { freshOnly = false } = {}) {
  verifyPoison(binding.paths)
  const allowedRoot = new Set([...ENVELOPE_RESERVED, ...binding.manifest.topLevelSidecars])
  const names = readdirSync(binding.root).sort(compareCodeUnits)
  const unknown = names.filter(name => !allowedRoot.has(name))
  if (unknown.length) fail(`generation envelope contains undeclared top-level entries: ${unknown.join(', ')}`)
  const generationNames = readdirSync(binding.paths.generations).sort(compareCodeUnits)
  if (!sameStrings(generationNames, [CORESTORE_GENERATION_ENVELOPE.generation])) {
    fail('generation directory contains an undeclared generation')
  }
  if (freshOnly) {
    const expected = [...ENVELOPE_RESERVED].sort(compareCodeUnits)
    if (!sameStrings(names, expected) || readdirSync(binding.paths.generationRoot).length !== 0) {
      fail('fresh generation envelope contains state outside the exact reserved layout')
    }
  }
  if (!binding.manifest.participants.includes(options.participant)) {
    fail(`generation participant ${options.participant} is absent from the signed manifest`)
  }
}

function verifyPoison (paths) {
  for (const poison of paths.poison) privateDirectory(poison, `old-writer poison directory ${basename(poison)}`)
}

function assertAuthorityNames (authority) {
  const names = readdirSync(authority)
  const unknown = names.filter(name => !AUTHORITY_ENTRIES.has(name) &&
    !RESTORE_INTENT.test(name) && !RESTORE_RECEIPT.test(name) && !TEMPORARY.test(name))
  if (unknown.length) fail(`generation authority contains unknown entries: ${unknown.sort(compareCodeUnits).join(', ')}`)
  for (const name of names) {
    if (!TEMPORARY.test(name)) continue
    const stat = lstatSync(join(authority, name))
    const uid = currentUid()
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink < 1 || stat.nlink > 2 || (stat.mode & 0o777) !== 0o600 ||
        (uid != null && stat.uid !== uid)) {
      fail(`generation authority contains unsafe tolerated temporary ${name}`)
    }
  }
}

function temporaryPath (directory, label) {
  return join(directory, `.${label}.${randomBytes(16).toString('hex')}.tmp`)
}

function installOrValidateSigned (file, body, key, label) {
  const signed = signedValue(body, key)
  if (existsSync(file)) {
    assertExactBody(readRequiredSigned(file, key, label), body, label)
    return
  }
  const temporary = temporaryPath(dirname(file), label)
  writeExclusiveSynced(temporary, canonicalBytes(signed))
  try {
    linkSync(temporary, file)
    syncDirectory(dirname(file))
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error
    assertExactBody(readRequiredSigned(file, key, label), body, label)
  } finally {
    unlinkTemporary(temporary)
  }
}

function unlinkTemporary (file) {
  try { unlinkSync(file) } catch (error) { if (error?.code !== 'ENOENT') throw error }
}

function signedValue (body, key) {
  return { ...body, mac: createHmac('sha256', key).update(canonicalBytes(body)).digest('hex') }
}

function readOptionalSigned (file, key, label) {
  if (!existsSync(file)) return null
  return readRequiredSigned(file, key, label)
}

function readRequiredSigned (file, key, label) {
  let raw
  let value
  try {
    raw = readRegularFile(file, label)
    value = JSON.parse(raw.toString('utf8'))
  } catch {
    fail(`${label} is not valid JSON`)
  }
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      typeof value.mac !== 'string' || !HEX_32.test(value.mac)) fail(`${label} has no valid MAC`)
  const body = { ...value }
  delete body.mac
  const expected = createHmac('sha256', key).update(canonicalBytes(body)).digest()
  const actual = Buffer.from(value.mac, 'hex')
  if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) fail(`${label} MAC is invalid`)
  if (!raw.equals(canonicalBytes({ ...body, mac: value.mac }))) {
    fail(`${label} is not the unique canonical signed encoding`)
  }
  return body
}

function assertExactBody (actual, expected, label) {
  if (!canonicalBytes(actual).equals(canonicalBytes(expected))) fail(`${label} does not match its expected authority`)
}

function assertExactArray (actual, expected, label) {
  if (!Array.isArray(actual) || !sameStrings(actual, expected)) fail(`${label} does not match its expected authority`)
}

function canonicalBytes (value) {
  return Buffer.from(JSON.stringify(stableValue(value)) + '\n', 'utf8')
}

function stableValue (value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value == null || typeof value !== 'object') return value
  return Object.fromEntries(Object.keys(value).sort(compareCodeUnits).map(key => [key, stableValue(value[key])]))
}

function digest (value) { return `sha256:${createHash('sha256').update(value).digest('hex')}` }

function signedFileDigest (file) { return digest(readRegularFile(file, basename(file))) }

function canonicalAbsolute (value, label) {
  if (typeof value !== 'string' || value.includes('\0') || !isAbsolute(value) || normalize(value) !== value) {
    throw new TypeError(`${label} must be a canonical absolute path`)
  }
  return value
}

function privateDirectory (directory, label) {
  let stat
  try { stat = lstatSync(directory) } catch (error) {
    if (error?.code === 'ENOENT') fail(`${label} is missing`)
    throw error
  }
  const uid = currentUid()
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 ||
      (uid != null && stat.uid !== uid)) {
    fail(`${label} must be a daemon-owned private regular directory`)
  }
  const real = realpathSync(directory)
  if (real !== directory) fail(`${label} must be canonical and must not traverse a symbolic link`)
  return { stat, realpath: real }
}

function assertLegacyImportSourcePreflight (directory) {
  const stat = lstatSync(directory)
  const uid = currentUid()
  if (!stat.isDirectory() || stat.isSymbolicLink() || (uid != null && stat.uid !== uid)) {
    fail('legacy copy root must be an operator-owned regular directory before offline import',
      'CORESTORE_GENERATION_LEGACY_PREFLIGHT_REQUIRED')
  }
  if ((stat.mode & 0o777) !== 0o700) {
    fail('legacy copy root is not private; verify offline ownership, then chmod 0700 before inventory/import',
      'CORESTORE_GENERATION_LEGACY_PREFLIGHT_REQUIRED')
  }
  const real = realpathSync(directory)
  if (real !== directory) {
    fail('legacy copy root must be canonical and must not traverse a symbolic link',
      'CORESTORE_GENERATION_LEGACY_PREFLIGHT_REQUIRED')
  }
}

function mkdirPrivate (directory) {
  try { mkdirSync(directory, { mode: 0o700 }) } catch (error) { if (error?.code !== 'EEXIST') throw error }
  privateDirectory(directory, basename(directory))
}

function readPrivateFile (file, label, exactBytes) {
  const stat = lstatSync(file)
  const uid = currentUid()
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 ||
      (stat.mode & 0o600) !== 0o600 || (uid != null && stat.uid !== uid) ||
      stat.size !== exactBytes) fail(`${label} must be a private single-link ${exactBytes}-byte file`)
  return readRegularFile(file, label)
}

function readRegularFile (file, label) {
  const before = lstatSync(file)
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) fail(`${label} must be a single-link regular file`)
  const descriptor = openSync(file, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW || 0))
  try {
    const opened = fstatSync(descriptor)
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) fail(`${label} changed while opening`)
    const value = Buffer.allocUnsafe(opened.size)
    let offset = 0
    while (offset < value.byteLength) {
      const length = readSync(descriptor, value, offset, value.byteLength - offset, offset)
      if (length === 0) fail(`${label} ended before its pinned size`)
      offset += length
    }
    const after = fstatSync(descriptor)
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
      fail(`${label} changed while reading`)
    }
    return value
  } finally {
    closeSync(descriptor)
  }
}

function fsyncRegularFile (file, label) {
  const before = lstatSync(file)
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) {
    fail(`${label} must be a single-link regular file`)
  }
  const descriptor = openSync(file, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW || 0))
  try {
    const opened = fstatSync(descriptor)
    if (opened.dev !== before.dev || opened.ino !== before.ino) fail(`${label} changed while opening`)
    fsyncSync(descriptor)
  } finally {
    closeSync(descriptor)
  }
}

function writeExclusiveSynced (file, value) {
  const descriptor = openSync(file, FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL |
    (FS_CONSTANTS.O_NOFOLLOW || 0), 0o600)
  try {
    const bytes = Buffer.from(value)
    let offset = 0
    while (offset < bytes.byteLength) offset += writeSync(descriptor, bytes, offset, bytes.byteLength - offset)
    fsyncSync(descriptor)
  } finally {
    closeSync(descriptor)
  }
}

function syncDirectory (directory) {
  // A Corestore close can finish asynchronously while a restore begins. On
  // Node 22.23 that stale close may race a newly reused descriptor and surface
  // as EBADF. Reopen once so the durability barrier is still performed on a
  // live directory descriptor; any persistent failure remains fail-closed.
  for (let attempt = 0; attempt < 2; attempt++) {
    const descriptor = openSync(directory, FS_CONSTANTS.O_RDONLY)
    let syncError = null
    let closeError = null
    try {
      fsyncSync(descriptor)
    } catch (error) {
      syncError = error
    } finally {
      try {
        closeSync(descriptor)
      } catch (error) {
        closeError = error
      }
    }
    const error = syncError || closeError
    if (error) {
      if (error?.code !== 'EBADF' || attempt === 1) throw error
      continue
    }
    return
  }
}

function currentUid () {
  const runtimeProcess = globalThis.process
  return runtimeProcess && typeof runtimeProcess.getuid === 'function' ? runtimeProcess.getuid() : null
}

function fail (message, code) { throw new CorestoreGenerationError(message, code) }

function compareCodeUnits (left, right) { return left < right ? -1 : left > right ? 1 : 0 }

function sameStrings (left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

function assertDisjoint (left, right) {
  const l = resolve(left)
  const r = resolve(right)
  const lr = relative(l, r)
  const rl = relative(r, l)
  if (l === r || (!lr.startsWith(`..${sep}`) && lr !== '..' && !isAbsolute(lr)) ||
      (!rl.startsWith(`..${sep}`) && rl !== '..' && !isAbsolute(rl))) {
    throw new TypeError('storage roots must be disjoint and non-nested')
  }
}

function treeLimits (limits = {}) {
  if (limits == null || typeof limits !== 'object' || Array.isArray(limits)) throw new TypeError('inventory limits must be an object')
  return Object.freeze({
    maxEntries: positiveLimit(limits.maxEntries, DEFAULT_MAX_ENTRIES, 'maxEntries'),
    maxBytes: positiveLimit(limits.maxBytes, DEFAULT_MAX_BYTES, 'maxBytes'),
    maxDepth: positiveLimit(limits.maxDepth, DEFAULT_MAX_DEPTH, 'maxDepth')
  })
}

function positiveLimit (value, fallback, label) {
  value = value == null ? fallback : value
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} must be a positive safe integer`)
  return value
}

function inventoryTree (root, limits) {
  const rootState = privateDirectory(root, 'storage inventory root')
  const entries = []
  const states = []
  let totalBytes = 0n
  walk(root, '', 0)
  entries.sort((left, right) => compareCodeUnits(left.path, right.path))
  states.sort((left, right) => compareCodeUnits(left.path, right.path))
  return inventoryValue(root, rootState, entries, states, totalBytes)

  function walk (directory, relativeDirectory, depth) {
    if (depth > limits.maxDepth) fail('storage inventory exceeds its maximum depth', 'CORESTORE_GENERATION_INVENTORY_LIMIT')
    for (const name of readdirSync(directory).sort(compareCodeUnits)) {
      const target = join(directory, name)
      const relativePath = relativeDirectory ? `${relativeDirectory}/${name}` : name
      const stat = lstatSync(target)
      if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) {
        fail(`storage inventory rejects non-regular entry ${relativePath}`, 'CORESTORE_GENERATION_INVENTORY_UNSAFE')
      }
      if (stat.isFile() && stat.nlink !== 1) {
        fail(`storage inventory rejects multi-link file ${relativePath}`, 'CORESTORE_GENERATION_INVENTORY_UNSAFE')
      }
      if (entries.length + 1 > limits.maxEntries) fail('storage inventory exceeds its entry bound', 'CORESTORE_GENERATION_INVENTORY_LIMIT')
      const mode = stat.mode & 0o777
      if (stat.isDirectory()) {
        if ((mode & 0o500) !== 0o500) {
          fail(`storage inventory requires owner read and execute permission on directory ${relativePath}`,
            'CORESTORE_GENERATION_DIRECTORY_MODE_UNSUPPORTED')
        }
        entries.push({ path: relativePath, kind: 'directory', mode })
        states.push(entryState(relativePath, stat))
        walk(target, relativePath, depth + 1)
      } else {
        totalBytes += BigInt(stat.size)
        if (totalBytes > BigInt(limits.maxBytes)) fail('storage inventory exceeds its byte bound', 'CORESTORE_GENERATION_INVENTORY_LIMIT')
        const sha256 = hashRegularFile(target, `storage entry ${relativePath}`)
        entries.push({ path: relativePath, kind: 'file', mode, size: stat.size, sha256 })
        states.push(entryState(relativePath, stat))
      }
    }
  }
}

function inventoryValue (root, rootState, entries, states, totalBytes) {
  const contentSha256 = digest(canonicalBytes({
    schema: 'hiverelay-storage-tree-content-v1',
    entries,
    totalBytes: totalBytes.toString()
  }))
  return { root, rootState, entries, states, totalBytes, contentSha256 }
}

function publicInventory (inventory) {
  return Object.freeze({
    schema: 'hiverelay-storage-tree-inventory-v1',
    contentSha256: inventory.contentSha256,
    entries: Object.freeze(inventory.entries.map(entry => Object.freeze({ ...entry }))),
    totalBytes: inventory.totalBytes,
    deterministicOrder: 'unicode-code-unit'
  })
}

function projectInventory (inventory, topNames) {
  return filterInventory(inventory, entry => topNames.has(entry.path.split('/')[0]))
}

function filterInventory (inventory, include) {
  const entries = inventory.entries.filter(include)
  const included = new Set(entries.map(entry => entry.path))
  const states = inventory.states.filter(entry => included.has(entry.path))
  const totalBytes = entries.reduce((sum, entry) => sum + BigInt(entry.kind === 'file' ? entry.size : 0), 0n)
  return inventoryValue(inventory.root, inventory.rootState, entries, states, totalBytes)
}

function immutableRestorePayloadInventory (binding, limits) {
  const markerPath = `${CORESTORE_GENERATION_ENVELOPE.generationRoot}/CORESTORE`
  const authorityPrefix = `${CORESTORE_GENERATION_ENVELOPE.authorityDirectory}/`
  return filterInventory(inventoryTree(binding.root, limits), entry => {
    if (entry.path === markerPath) return false
    if (!entry.path.startsWith(authorityPrefix)) return true
    const name = entry.path.slice(authorityPrefix.length)
    return !RESTORE_INTENT.test(name) && !RESTORE_RECEIPT.test(name)
  })
}

function assertRestoreImmutablePayload (intent, inventory) {
  if (inventory.contentSha256 !== intent.immutablePayloadSha256 ||
      inventory.entries.length !== intent.immutablePayloadEntries ||
      inventory.totalBytes.toString() !== intent.immutablePayloadBytes) {
    fail('restored payload changed after the signed restore intent',
      'CORESTORE_GENERATION_RESTORE_PAYLOAD_CHANGED')
  }
}

function entryState (path, stat) {
  return {
    path,
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    nlink: stat.nlink,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs
  }
}

function sameInventory (left, right, compareStates) {
  if (left.contentSha256 !== right.contentSha256 || left.totalBytes !== right.totalBytes ||
      !canonicalBytes(left.entries).equals(canonicalBytes(right.entries))) return false
  return !compareStates || canonicalBytes(left.states).equals(canonicalBytes(right.states))
}

function copyProjectedInventory (source, destination, inventory, faultInjector) {
  privateDirectory(destination, 'generation import target')
  cleanupCopyTemporaries(destination)
  for (const entry of inventory.entries.filter(entry => entry.kind === 'directory')) {
    const target = join(destination, ...entry.path.split('/'))
    if (!existsSync(target)) {
      mkdirSync(target, { mode: 0o700 })
      syncDirectory(dirname(target))
    }
    const stat = lstatSync(target)
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`import target ${entry.path} is not a directory`)
    // Keep the owner able to populate a source directory whose final mode is
    // read-only. Exact source modes are restored only after every child has
    // been atomically installed.
    chmodSync(target, 0o700)
  }
  for (const entry of inventory.entries.filter(entry => entry.kind === 'file')) {
    const target = join(destination, ...entry.path.split('/'))
    if (existsSync(target)) {
      const existing = inventoryEntry(target, entry.path)
      if (!canonicalBytes(existing).equals(canonicalBytes(entry))) {
        fail(`generation import contains mismatched entry ${entry.path}`, 'CORESTORE_GENERATION_IMPORT_MISMATCH')
      }
      continue
    }
    copyFileSynced(join(source, ...entry.path.split('/')), target, entry, faultInjector)
  }
  for (const entry of [...inventory.entries].filter(entry => entry.kind === 'directory').reverse()) {
    finalizeCopiedDirectory(join(destination, ...entry.path.split('/')), entry.mode)
  }
  syncDirectory(destination)
}

function finalizeCopiedDirectory (directory, mode) {
  const descriptor = openSync(directory, FS_CONSTANTS.O_RDONLY)
  try {
    fsyncSync(descriptor)
    chmodSync(directory, mode)
    fsyncSync(descriptor)
  } finally {
    closeSync(descriptor)
  }
  syncDirectory(dirname(directory))
}

function copyInventoryResume (source, destination, inventory, limits, faultInjector) {
  privateDirectory(destination, 'copy destination root')
  cleanupCopyTemporaries(destination)
  const existing = inventoryTree(destination, limits)
  const expected = new Map(inventory.entries.map(entry => [entry.path, entry]))
  for (const entry of existing.entries) {
    const wanted = expected.get(entry.path)
    const resumableDirectory = wanted?.kind === 'directory' && entry.kind === 'directory' &&
      (entry.mode === 0o700 || entry.mode === wanted.mode)
    if (!wanted || (!resumableDirectory && !canonicalBytes(wanted).equals(canonicalBytes(entry)))) {
      fail(`copy destination contains unexpected or mismatched entry ${entry.path}`,
        'CORESTORE_GENERATION_COPY_MISMATCH')
    }
  }
  copyProjectedInventory(source, destination, inventory, faultInjector)
}

function cleanupCopyTemporaries (root) {
  walk(root)

  function walk (directory) {
    let changed = false
    for (const name of readdirSync(directory)) {
      const target = join(directory, name)
      const stat = lstatSync(target)
      if (COPY_TEMPORARY.test(name)) {
        if (!stat.isFile() || stat.isSymbolicLink()) fail('invalid copy temporary entry')
        unlinkSync(target)
        changed = true
        continue
      }
      if (stat.isDirectory() && !stat.isSymbolicLink()) walk(target)
    }
    if (changed) syncDirectory(directory)
  }
}

function inventoryEntry (file, path) {
  const stat = lstatSync(file)
  if (stat.isDirectory() && !stat.isSymbolicLink()) return { path, kind: 'directory', mode: stat.mode & 0o777 }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail(`copy target ${path} is unsafe`)
  return { path, kind: 'file', mode: stat.mode & 0o777, size: stat.size, sha256: hashRegularFile(file, `copy target ${path}`) }
}

function hashRegularFile (file, label) {
  const before = lstatSync(file)
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) fail(`${label} must be a single-link regular file`)
  const descriptor = openSync(file, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW || 0))
  const hash = createHash('sha256')
  const buffer = Buffer.allocUnsafe(64 * 1024)
  let total = 0
  try {
    const opened = fstatSync(descriptor)
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) fail(`${label} changed while opening`)
    while (true) {
      const length = readSync(descriptor, buffer, 0, buffer.byteLength, null)
      if (length === 0) break
      hash.update(buffer.subarray(0, length))
      total += length
    }
    const after = fstatSync(descriptor)
    if (total !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs ||
        after.ctimeMs !== opened.ctimeMs) fail(`${label} changed while hashing`)
  } finally {
    closeSync(descriptor)
  }
  return `sha256:${hash.digest('hex')}`
}

function copyFileSynced (source, destination, expected, faultInjector) {
  const temporary = join(dirname(destination),
    `.${basename(destination)}.hiverelay-copy-${randomBytes(16).toString('hex')}.tmp`)
  const sourceDescriptor = openSync(source, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW || 0))
  const destinationDescriptor = openSync(temporary,
    FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | (FS_CONSTANTS.O_NOFOLLOW || 0),
    expected.mode)
  const hash = createHash('sha256')
  let total = 0
  const buffer = Buffer.allocUnsafe(64 * 1024)
  try {
    while (true) {
      const length = readSync(sourceDescriptor, buffer, 0, buffer.byteLength, null)
      if (length === 0) break
      hash.update(buffer.subarray(0, length))
      let offset = 0
      while (offset < length) offset += writeSync(destinationDescriptor, buffer, offset, length - offset)
      total += length
      injectSync(faultInjector, 'corestore-generation:after-copy-file-chunk', Object.freeze({
        path: expected.path,
        bytesCopied: total
      }))
    }
    chmodSync(temporary, expected.mode)
    fsyncSync(destinationDescriptor)
  } finally {
    closeSync(destinationDescriptor)
    closeSync(sourceDescriptor)
  }
  if (total !== expected.size || `sha256:${hash.digest('hex')}` !== expected.sha256) {
    fail(`source entry ${expected.path} changed while it was copied`, 'CORESTORE_GENERATION_SOURCE_CHANGED')
  }
  injectSync(faultInjector, 'corestore-generation:after-copy-file-temp-sync', Object.freeze({ path: expected.path }))
  try {
    linkSync(temporary, destination)
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error
    const existing = inventoryEntry(destination, expected.path)
    if (!canonicalBytes(existing).equals(canonicalBytes(expected))) {
      fail(`copy destination contains mismatched entry ${expected.path}`, 'CORESTORE_GENERATION_COPY_MISMATCH')
    }
  }
  syncDirectory(dirname(destination))
  injectSync(faultInjector, 'corestore-generation:after-copy-file-link', Object.freeze({ path: expected.path }))
  unlinkTemporary(temporary)
  syncDirectory(dirname(destination))
}

function injectSync (injector, point, context) {
  if (injector) injector(point, context)
}

async function injectRestore (injector, point, context) {
  if (injector) await injector(point, context)
}

async function inject (options, point, context) {
  if (options.faultInjector) await options.faultInjector(point, Object.freeze(context))
}
