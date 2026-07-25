import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import { PRIVATE_IPC_V4_STATUS } from '@hiverelay/blind-ipc'
import {
  blake2b256,
  blindServiceDescriptorV1,
  encodeCanonical,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import {
  createBlindCellControlSnapshotSemanticAuthority,
  createBlindCellControlSnapshotSemanticVerifier,
  streamBlindCellControlSnapshotEntries
} from './cell-control-snapshot.js'
import {
  createBlindInboxControlSnapshotSemanticAuthority,
  createBlindInboxControlSnapshotSemanticVerifier,
  streamBlindInboxControlSnapshotEntries
} from './inbox-control-snapshot.js'
import {
  createBlindCellInboxControlSnapshotSemanticAuthority,
  createBlindCellInboxControlSnapshotSemanticVerifier
} from './cell-inbox-control-snapshot.js'
import {
  createBlindCoreControlSnapshotSemanticAuthority,
  createBlindCoreControlSnapshotSemanticVerifier,
  streamBlindCoreControlSnapshotEntries
} from './core-control-snapshot.js'
import {
  createBlindCellInboxCoreControlSnapshotSemanticAuthority,
  createBlindCellInboxCoreEmptyGenesisSnapshotSemanticVerifier
} from './cell-inbox-core-control-snapshot.js'
import { TwoSlotManifestStore } from './manifest-store.js'
import { BlindProfile1StoreGenesisCoordinator } from './profile1-store-genesis.js'

// Bounded vNext direct-HTTPS public-test profile assembly.
//
// This module is the composition surface for the LIMITED_PUBLIC_TEST_V1
// release profile (profile ID 1, operation mask 0x0001ffff — the baseline 17
// DESCRIBE/CELL/INBOX/CORE operations). It GENUINELY assembles the production
// runtime exclusions by wiring the already-accepted modules into the daemon
// entrypoint: the CELL/INBOX/CORE public execution line (assembled inside
// assembleProductionBlindDaemon), the sealed admission redemption adapter, and
// the accepted bounded one-hop FORWARD relay (forward-https-runtime-vnext.js).
//
// Discipline honoured here:
//  - No release-gate override, no BLIND_RUNTIME_TEST_SEAM paths, no hand-written
//    driver. The production release gate stays strict; this module makes each
//    exclusion TRUE-assembled rather than filtering it away.
//  - FORWARD descriptor/readiness/advertised operation bits stay ZERO per the
//    run's forward-activation rule. The accepted FORWARD module already never
//    publishes a bit; this assembly does not change that.
//  - Sealed node-scoped material is consumed only through the existing
//    config/env surface (bootstrap-config.js, production-runtime.js config and
//    the forward env below). No new secret flow is invented.
//
// This module deliberately imports nothing from production-runtime.js so the
// release gate (which lives there) can depend on this module without a cycle.

export const LIMITED_PUBLIC_TEST_V1_PROFILE = 'LIMITED_PUBLIC_TEST_V1'

// The baseline-17 public-test operation mask (release profile ID 1). FORWARD
// bits (18-21) and CORE.OPEN_REPLICATION (bit 17) are reserved and stay zero.
export const LIMITED_PUBLIC_TEST_V1_OPERATION_BITS = 0x0001ffff

export function isVnextPublicTestProfile (profile) {
  return profile === LIMITED_PUBLIC_TEST_V1_PROFILE
}

// The vNext public-test profile enables the complete CELL/INBOX/CORE public
// execution line. FORWARD is a separate bounded one-hop class assembled beside
// it; it never contributes descriptor/readiness bits.
export const VNEXT_PUBLIC_TEST_RUNTIME_FLAGS = Object.freeze({
  enableCellRuntime: true,
  enableInboxRuntime: true,
  enableCoreRuntime: true
})

function configFailure (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function optionalPath (environment, name) {
  const value = environment[name]
  if (value == null || value === '') return null
  if (typeof value !== 'string' || value.includes('\0') || value.length > 4096) {
    configFailure('BLIND_VNEXT_FORWARD_CONFIG_INVALID', `${name} must be one canonical path`)
  }
  return value
}

function optionalHash (environment, name) {
  const raw = environment[name]
  if (raw == null || raw === '') return null
  if (typeof raw !== 'string' || !/^[0-9a-fA-F]{64}$/.test(raw)) {
    configFailure('BLIND_VNEXT_FORWARD_CONFIG_INVALID', `${name} must be an exact 32-byte hash in hex`)
  }
  const value = b4a.from(raw, 'hex')
  if (value.every(byte => byte === 0)) {
    configFailure('BLIND_VNEXT_FORWARD_CONFIG_INVALID', `${name} must be nonzero`)
  }
  return value
}

// Parse and validate the bounded one-hop FORWARD class configuration from the
// signed launch env surface. Returns null when FORWARD is not configured at
// all (the caller then treats FORWARD_PUBLIC_EXECUTION and the profile-2
// external journal witness as not yet assembled). When any FORWARD material is
// present the complete set is required, so a half-configured FORWARD class
// fails closed instead of assembling a partial relay.
export function loadVnextForwardConfig (environment = process.env) {
  const root = optionalPath(environment, 'HIVERELAY_BLIND_FORWARD_STORE_ROOT')
  const manifestKeyFile = optionalPath(environment, 'HIVERELAY_BLIND_FORWARD_MANIFEST_KEY_FILE')
  const atRestKeyFile = optionalPath(environment, 'HIVERELAY_BLIND_FORWARD_ATREST_KEY_FILE')
  const sourceStoreId = optionalHash(environment, 'HIVERELAY_BLIND_FORWARD_SOURCE_STORE_ID')
  const targetStoreId = optionalHash(environment, 'HIVERELAY_BLIND_FORWARD_TARGET_STORE_ID')
  const sourceContinuityHash = optionalHash(environment, 'HIVERELAY_BLIND_FORWARD_SOURCE_CONTINUITY_HASH')
  const targetContinuityHash = optionalHash(environment, 'HIVERELAY_BLIND_FORWARD_TARGET_CONTINUITY_HASH')
  const sourceSocketPath = optionalPath(environment, 'HIVERELAY_BLIND_FORWARD_SOURCE_SOCKET')
  const targetSocketPath = optionalPath(environment, 'HIVERELAY_BLIND_FORWARD_TARGET_SOCKET')

  const present = [root, manifestKeyFile, atRestKeyFile, sourceStoreId, targetStoreId,
    sourceContinuityHash, targetContinuityHash]
  const anyPresent = present.some(value => value != null) || sourceSocketPath != null ||
    targetSocketPath != null
  if (!anyPresent) return null
  if (present.some(value => value == null)) {
    configFailure('BLIND_VNEXT_FORWARD_CONFIG_INVALID',
      'the bounded FORWARD class requires the complete storage identity set when any of it is configured')
  }
  return Object.freeze({
    storage: Object.freeze({
      root,
      manifestKeyFile,
      atRestKeyFile,
      sourceStoreId,
      targetStoreId,
      sourceDurabilityContinuityHash: sourceContinuityHash,
      targetDurabilityContinuityHash: targetContinuityHash
    }),
    sourceSocketPath,
    targetSocketPath,
    // The WIRE v3 ABI and private IPC v4 format hashes are pinned generated
    // authorities, imported (never hardcoded) so a contract drift fails closed.
    wireV3AbiHash: b4a.from(PRIVATE_IPC_V4_STATUS.importedWireV3AbiHash, 'hex'),
    privateIpcV4Hash: b4a.from(PRIVATE_IPC_V4_STATUS.privateIpcFormatHash, 'hex')
  })
}

// ---------------------------------------------------------------------------
// Store-genesis ceremony (vNext serving-path floor material).
//
// runVnextStoreGenesisCeremony seals the node-scoped store-genesis material
// the production serving path consumes: it DRIVES the accepted
// BlindProfile1StoreGenesisCoordinator pipeline (transactionStore WAL genesis
// -> withWalBarrier -> BlindLocalCheckpointStore.initializeGenesis ->
// TwoSlotManifestStore.initialize) against a blind store root and returns the
// sealed manifest floor facts. The pipeline is idempotent: once the two-slot
// manifest exists and the genesis intent is removed, re-running the ceremony
// on the same root skips publication and returns through validated recovery,
// so the sealed bytes stay byte-identical.
//
// Derivation rule for the caller-supplied consistency tokens: bucketMapHash
// and partitionKey are bound through manifest -> checkpoint as opaque tokens;
// the storage engine never independently validates bucketMapHash against a
// live bucket map (verified in the accepted storage paths), so the caller
// derives both deterministically from the sealed identity, e.g.
//   bucketMapHash = blake2b256('hiverelay.blind.bucket-map.v1'    | storeId | u64be(mapGeneration))
//   partitionKey  = blake2b256('hiverelay.blind.partition-key.v1' | storeId | manifestKey)
// so that re-running the ceremony is byte-identical and idempotent.
//
// Secret hygiene: the ceremony makes no secret copies of its own — manifestKey
// and partitionKey are passed through to the driven stores, which copy them
// internally; the verification TwoSlotManifestStore zeroes its internal key
// copy on close. Caller-owned secret buffers stay caller-owned and are never
// logged here.

const STORE_GENESIS_MAX_U64 = (1n << 64n) - 1n

// The exact binding field set the genesis coordinator pins into the sealed
// manifest (mirrors profile1-store-genesis.js expectedBindings); the
// post-ceremony verification load re-verifies the same bindings.
const STORE_GENESIS_MANIFEST_BINDING_FIELDS = Object.freeze([
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

function genesisFailure (message) {
  configFailure('BLIND_VNEXT_STORE_GENESIS_INVALID', message)
}

function genesisRoot (value) {
  if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value) ||
      path.normalize(value) !== value) {
    genesisFailure('storeRoot must be one canonical absolute path')
  }
  return value
}

function genesisBytes32 (value, field) {
  if (!value || typeof value.byteLength !== 'number') genesisFailure(`${field} must be bytes`)
  const normalized = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (normalized.byteLength !== 32) genesisFailure(`${field} must be exactly 32 bytes`)
  if (normalized.every(byte => byte === 0)) genesisFailure(`${field} must be nonzero`)
  return normalized
}

function genesisU64 (value, field, nonzero) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) genesisFailure(`${field} is not an unsigned integer`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > STORE_GENESIS_MAX_U64 ||
      (nonzero && value === 0n)) {
    genesisFailure(`${field} is outside its u64 bound`)
  }
  return value
}

function genesisInteger (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    genesisFailure(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

// Validates the decoded current descriptor (chain head / successor) against
// its canonical bytes and returns the descriptor hash floor pinned into the
// manifest. Fails closed before any filesystem mutation.
function genesisDescriptorFloor (descriptor, descriptorCanonicalBytes) {
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)) {
    genesisFailure('descriptor must be the decoded current service descriptor')
  }
  if (!descriptorCanonicalBytes || typeof descriptorCanonicalBytes.byteLength !== 'number' ||
      descriptorCanonicalBytes.byteLength === 0) {
    genesisFailure('descriptorCanonicalBytes must be nonempty bytes')
  }
  const durability = descriptor.durability
  const build = descriptor.build
  if (!durability || typeof durability !== 'object' || Array.isArray(durability) ||
      !build || typeof build !== 'object' || Array.isArray(build)) {
    genesisFailure('descriptor must carry its durability and build profiles')
  }
  if (durability.profileId !== 1) {
    genesisFailure('store genesis seals durability profile 1 descriptors only')
  }
  for (const [field, value] of [
    ['descriptor.storeId', descriptor.storeId],
    ['descriptor.relayPublicKey', descriptor.relayPublicKey],
    ['descriptor.durabilityContinuityHash', descriptor.durabilityContinuityHash],
    ['descriptor.durabilityProfileHash', descriptor.durabilityProfileHash],
    ['descriptor.durability.storeFormatHash', durability.storeFormatHash],
    ['descriptor.build.specHash', build.specHash],
    ['descriptor.build.abiHash', build.abiHash]
  ]) {
    if (!value || typeof value.byteLength !== 'number' || value.byteLength !== 32) {
      genesisFailure(`${field} must be exactly 32 bytes`)
    }
  }
  for (const [field, value] of [
    ['descriptor.durability.storeFormatMajor', durability.storeFormatMajor],
    ['descriptor.durability.storeFormatMinor', durability.storeFormatMinor],
    ['descriptor.issuedEpoch', descriptor.issuedEpoch]
  ]) {
    if (!Number.isSafeInteger(value) || value < 0) genesisFailure(`${field} must be an unsigned integer`)
  }
  genesisU64(descriptor.descriptorSequence, 'descriptor.descriptorSequence', false)
  let encoded = null
  try {
    encoded = encodeCanonical(blindServiceDescriptorV1, descriptor)
  } catch (error) {
    genesisFailure(`descriptor is not canonically encodable: ${error.message}`)
  }
  if (!b4a.equals(encoded, descriptorCanonicalBytes)) {
    genesisFailure('descriptor does not match its canonical bytes')
  }
  return serviceDescriptorHash(descriptorCanonicalBytes)
}

// The blindStoreManifestV1 template the pipeline canonicalizes: profile 1,
// manifest revision 0, no predecessor, nonzero map/writer generations, zero
// external/migration state. The codec mandates a NONZERO checkpointHash and
// MAC, so the template carries deterministic nonzero placeholders derived
// from the descriptor hash floor; neither survives the pipeline —
// initializeGenesis installs the real checkpoint anchor (WAL sequence 1 and
// the installed checkpoint header hash replace both anchor fields) and
// TwoSlotManifestStore.initialize re-seals the MAC under the launch key, so
// re-running the ceremony stays byte-identical.
function genesisPlaceholderHash (domain, descriptorHashFloor) {
  return blake2b256(b4a.concat([b4a.from(domain, 'ascii'), descriptorHashFloor]))
}

function genesisManifestTemplate (options) {
  const { descriptor, descriptorHashFloor, bucketMapHash, mapGeneration, ownerFenceTokenHash } = options
  const zero = b4a.alloc(32)
  return {
    magic: b4a.from('HRBLIND1', 'ascii'),
    manifestVersion: 1,
    storeId: b4a.from(descriptor.storeId),
    relayPublicKey: b4a.from(descriptor.relayPublicKey),
    durabilityProfileId: descriptor.durability.profileId,
    durabilityContinuityHash: b4a.from(descriptor.durabilityContinuityHash),
    durabilityProfileHash: b4a.from(descriptor.durabilityProfileHash),
    formatMajor: descriptor.durability.storeFormatMajor,
    formatMinor: descriptor.durability.storeFormatMinor,
    storeFormatHash: b4a.from(descriptor.durability.storeFormatHash),
    specHash: b4a.from(descriptor.build.specHash),
    abiHash: b4a.from(descriptor.build.abiHash),
    mapGeneration,
    bucketMapHash: b4a.from(bucketMapHash),
    checkpointWalSequence: 0n,
    checkpointHash: genesisPlaceholderHash(
      'hiverelay.blind.store-genesis-checkpoint-placeholder.v1', descriptorHashFloor),
    epochFloor: descriptor.issuedEpoch,
    writerEpoch: 1n,
    writerFenceTokenHash: b4a.from(ownerFenceTokenHash),
    externalLeaseRevision: 0n,
    externalJournalId: zero,
    externalWitnessPublicKey: zero,
    restoreEvidenceFeedId: zero,
    lastAckWalSequence: 0n,
    lastAckWalHash: zero,
    externalCheckpointRevision: 0n,
    externalCheckpointHash: zero,
    descriptorSequenceFloor: descriptor.descriptorSequence,
    descriptorHashFloor,
    migrationState: 0,
    sourceFormatMajor: 0,
    targetFormatMajor: 0,
    migrationCursorHash: zero,
    previousManifestHash: null,
    manifestRevision: 0n,
    mac: genesisPlaceholderHash(
      'hiverelay.blind.store-genesis-mac-placeholder.v1', descriptorHashFloor)
  }
}

function emptyGenesisCellState (manifest) {
  return {
    relayPublicKey: b4a.from(manifest.relayPublicKey),
    spends: new Map(),
    commitments: new Map(),
    requestResults: new Map(),
    cells: new Map(),
    accounting: {
      storedBytes: 0,
      stagingBytes: 0,
      controlBytes: 0,
      tombstoneBytes: 0,
      reservedCells: 0,
      stagingByProfile: new Map()
    },
    epochFloor: manifest.epochFloor,
    clockUnsafe: false,
    readOnlyReason: null,
    integrityEvidence: []
  }
}

function emptyGenesisInboxState (manifest) {
  return {
    relayPublicKey: b4a.from(manifest.relayPublicKey),
    spends: new Map(),
    commitments: new Map(),
    requestResults: new Map(),
    inboxes: new Map(),
    frames: new Map(),
    retryPins: new Map(),
    accounting: {
      storedFrameBytes: 0,
      stagingFrameBytes: 0,
      controlBytes: 0,
      tombstoneBytes: 0,
      frameIndexBytes: 0,
      reservedFrames: 0,
      stagingByProfile: new Map()
    },
    epochFloor: manifest.epochFloor,
    clockUnsafe: false,
    readOnlyReason: null,
    integrityEvidence: []
  }
}

function emptyGenesisCoreState (manifest) {
  return {
    relayPublicKey: b4a.from(manifest.relayPublicKey),
    storeId: b4a.from(manifest.storeId),
    durabilityContinuityHash: b4a.from(manifest.durabilityContinuityHash),
    recordsByLogical: new Map(),
    recordsBySpend: new Map(),
    controlChannels: new Map(),
    epochFloor: manifest.epochFloor,
    clockUnsafe: false,
    readOnlyReason: null
  }
}

function compareGenesisSnapshotEntries (left, right) {
  return left.entryKind - right.entryKind || b4a.compare(left.key, right.key)
}

// Streams the empty cell/inbox/core states through the six control-snapshot
// semantic authority/verifier factories into the sorted canonical empty
// global fragments, and brands the empty-genesis publication verifier the
// coordinator requires.
async function emptyGenesisSnapshotAuthority (partitionKey, manifest) {
  const cell = createBlindCellControlSnapshotSemanticAuthority({ partitionKey })
  const inbox = createBlindInboxControlSnapshotSemanticAuthority({ partitionKey })
  const core = createBlindCoreControlSnapshotSemanticAuthority({ partitionKey })
  const cellInbox = createBlindCellInboxControlSnapshotSemanticAuthority({
    partitionKey,
    cellVerifier: createBlindCellControlSnapshotSemanticVerifier(cell),
    inboxVerifier: createBlindInboxControlSnapshotSemanticVerifier(inbox)
  })
  const combined = createBlindCellInboxCoreControlSnapshotSemanticAuthority({
    partitionKey,
    cellInboxVerifier: createBlindCellInboxControlSnapshotSemanticVerifier(cellInbox),
    coreVerifier: createBlindCoreControlSnapshotSemanticVerifier(core)
  })
  const entries = []
  for await (const entry of streamBlindCellControlSnapshotEntries(cell, emptyGenesisCellState(manifest))) entries.push(entry)
  for await (const entry of streamBlindInboxControlSnapshotEntries(inbox, emptyGenesisInboxState(manifest))) entries.push(entry)
  for await (const entry of streamBlindCoreControlSnapshotEntries(core, emptyGenesisCoreState(manifest))) entries.push(entry)
  entries.sort(compareGenesisSnapshotEntries)
  return {
    entries,
    verifier: createBlindCellInboxCoreEmptyGenesisSnapshotSemanticVerifier(combined)
  }
}

function genesisManifestBindings (manifest) {
  return Object.freeze(Object.fromEntries(STORE_GENESIS_MANIFEST_BINDING_FIELDS.map(field => {
    const value = manifest[field]
    return [field, value && typeof value.byteLength === 'number' ? b4a.from(value) : value]
  })))
}

function u64beBytes (value) {
  const bytes = b4a.alloc(8)
  bytes.writeBigUInt64BE(value, 0)
  return bytes
}

// The deterministic bucket-map consistency token. The ceremony seals it into
// the manifest; the serving path re-derives the identical value to load and
// enforce the manifest floor. This is the single shared derivation so the two
// can never diverge (see the derivation rule above).
export function deriveVnextBucketMapHash (storeId, mapGeneration) {
  return blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.bucket-map.v1', 'ascii'),
    b4a.from(storeId),
    u64beBytes(mapGeneration)
  ]))
}

// The exact expectedBindings the production serving path uses to open the
// sealed two-slot manifest and enforce its descriptor floor. Built through the
// same genesisManifestTemplate + genesisManifestBindings the ceremony seals, so
// the bindings match the sealed manifest byte-for-byte. The descriptorHashFloor
// is the chain head's serviceDescriptorHash (the serving path's activated head).
export function vnextStoreGenesisExpectedBindings (descriptor, descriptorHashFloor, mapGeneration, ownerFenceTokenHash) {
  const bucketMapHash = deriveVnextBucketMapHash(descriptor.storeId, mapGeneration)
  const template = genesisManifestTemplate({
    descriptor,
    descriptorHashFloor,
    bucketMapHash,
    mapGeneration,
    ownerFenceTokenHash
  })
  return genesisManifestBindings(template)
}

async function ensureGenesisStoreRoot (storeRoot) {
  let stat = null
  try {
    stat = await fs.lstat(storeRoot)
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error
  }
  if (stat == null) {
    await fs.mkdir(storeRoot, { recursive: true, mode: 0o700 })
    stat = await fs.lstat(storeRoot)
  }
  if (!stat.isDirectory() || stat.isSymbolicLink() ||
      (typeof process.getuid === 'function' && stat.uid !== process.getuid()) ||
      (stat.mode & 0o700) !== 0o700 || (stat.mode & 0o077) !== 0) {
    genesisFailure('storeRoot is not a private daemon-owned directory')
  }
}

// Runs the store-genesis ceremony against options.storeRoot and returns a
// frozen result exposing the sealed manifest floor
// (descriptorSequenceFloor/descriptorHashFloor), the manifest revision and
// hash, the checkpoint anchor (checkpointWalSequence) and anchor hash
// (checkpointHash), the validated recovery sequences, and the two-slot
// manifest file paths under <storeRoot>/control.
export async function runVnextStoreGenesisCeremony (options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    genesisFailure('store genesis ceremony options must be one object')
  }
  const storeRoot = genesisRoot(options.storeRoot)
  const descriptorHashFloor = genesisDescriptorFloor(options.descriptor, options.descriptorCanonicalBytes)
  const manifestKey = genesisBytes32(options.manifestKey, 'manifestKey')
  const ownerFenceTokenHash = genesisBytes32(options.ownerFenceTokenHash, 'ownerFenceTokenHash')
  const partitionKey = genesisBytes32(options.partitionKey, 'partitionKey')
  const bucketMapHash = genesisBytes32(options.bucketMapHash, 'bucketMapHash')
  const mapGeneration = genesisU64(options.mapGeneration, 'mapGeneration', true)
  const maximumSnapshotBytes = genesisInteger(
    options.maximumSnapshotBytes == null ? 256 * 1024 * 1024 : options.maximumSnapshotBytes,
    1024, 0x7fffffff, 'maximumSnapshotBytes')
  const maximumEntries = genesisInteger(
    options.maximumEntries == null ? 0x1000000 : options.maximumEntries,
    3, 0x1000000, 'maximumEntries')
  if (options.faultInjector != null && typeof options.faultInjector !== 'function') {
    genesisFailure('faultInjector must be a function')
  }

  const descriptor = options.descriptor
  const manifestTemplate = genesisManifestTemplate({
    descriptor,
    descriptorHashFloor,
    bucketMapHash,
    mapGeneration,
    ownerFenceTokenHash
  })
  const snapshot = await emptyGenesisSnapshotAuthority(partitionKey, manifestTemplate)
  await ensureGenesisStoreRoot(storeRoot)
  const controlDirectory = path.join(storeRoot, 'control')

  const coordinator = new BlindProfile1StoreGenesisCoordinator({
    root: storeRoot,
    manifestKey,
    partitionKey,
    manifestTemplate,
    genesisRecord: {
      type: 9,
      virtualBucket: 0,
      payload: b4a.from('profile-1-floor-genesis-v1', 'utf8')
    },
    genesisSnapshotEntries: snapshot.entries,
    snapshotSemanticVerifier: snapshot.verifier,
    maximumSnapshotBytes,
    maximumEntries,
    faultInjector: options.faultInjector || null
  })
  const recoveredWalSequences = []
  const shadowWalSequences = []
  let runtime = null
  let recoveryAuthority = null
  try {
    runtime = await coordinator.open({
      applyShadowFrame: async frame => { shadowWalSequences.push(frame.sequence) },
      applyRecoveredFrame: async frame => { recoveredWalSequences.push(frame.sequence) }
    })
    recoveryAuthority = runtime.recoveryAuthority
  } finally {
    if (runtime) await runtime.close()
  }

  // Independent post-ceremony proof: the sealed two-slot manifest must
  // MAC-verify under the same launch key and exact bindings the pipeline
  // pinned. The store zeroes its internal key copy on close.
  const manifestStore = new TwoSlotManifestStore({
    controlDirectory,
    manifestKey,
    expectedBindings: genesisManifestBindings(manifestTemplate)
  })
  await manifestStore.open({ validationOnly: true })
  let sealed = null
  try {
    sealed = await manifestStore.load()
  } finally {
    await manifestStore.close()
  }
  const manifest = sealed.manifest
  return Object.freeze({
    storeRoot,
    controlDirectory,
    manifestRevision: sealed.revision,
    manifestHash: b4a.from(sealed.hash),
    checkpointSequence: recoveryAuthority.checkpointSequence,
    checkpointWalSequence: manifest.checkpointWalSequence,
    checkpointHash: b4a.from(manifest.checkpointHash),
    walHeadSequence: recoveryAuthority.walHeadSequence,
    descriptorSequenceFloor: manifest.descriptorSequenceFloor,
    descriptorHashFloor: b4a.from(manifest.descriptorHashFloor),
    recoveredWalSequences: Object.freeze(recoveredWalSequences.slice()),
    shadowWalSequences: Object.freeze(shadowWalSequences.slice()),
    manifestPaths: Object.freeze({
      a: path.join(controlDirectory, 'manifest-a.v1'),
      b: path.join(controlDirectory, 'manifest-b.v1')
    })
  })
}
