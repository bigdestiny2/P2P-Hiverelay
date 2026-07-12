import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import {
  blindServiceDescriptorV1,
  blindStoreManifestV1,
  decodeCanonical,
  encodeCanonical
} from '@hiverelay/blind-protocol'
import {
  createBlindCellControlSnapshotSemanticAuthority,
  createBlindCellControlSnapshotSemanticVerifier,
  streamBlindCellControlSnapshotEntries
} from '../cell-control-snapshot.js'
import {
  createBlindInboxControlSnapshotSemanticAuthority,
  createBlindInboxControlSnapshotSemanticVerifier,
  streamBlindInboxControlSnapshotEntries
} from '../inbox-control-snapshot.js'
import {
  createBlindCellInboxControlSnapshotSemanticAuthority,
  createBlindCellInboxControlSnapshotSemanticVerifier
} from '../cell-inbox-control-snapshot.js'
import {
  createBlindCoreControlSnapshotSemanticAuthority,
  createBlindCoreControlSnapshotSemanticVerifier,
  streamBlindCoreControlSnapshotEntries
} from '../core-control-snapshot.js'
import {
  createBlindCellInboxCoreControlSnapshotSemanticAuthority,
  createBlindCellInboxCoreControlSnapshotSemanticVerifier,
  createBlindCellInboxCoreEmptyGenesisSnapshotSemanticVerifier
} from '../cell-inbox-core-control-snapshot.js'
import {
  BLIND_PROFILE1_STORE_GENESIS_STATUS,
  BlindProfile1StoreGenesisCoordinator
} from '../profile1-store-genesis.js'
import { classifyBlindStoreRoot, BLIND_STORE_ROOT_CLASSIFICATION } from '../store-session.js'
import { descriptorValue, manifestBytes } from './coordinator-fixtures.js'

const PARTITION_KEY = b4a.alloc(32, 0x71)
const MANIFEST_KEY = b4a.alloc(32, 0x91)

function bytes (fill) {
  return b4a.alloc(32, fill)
}

function emptyCellState (manifest) {
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

function emptyInboxState (manifest) {
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

function emptyCoreState (manifest) {
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

function compareEntries (left, right) {
  return left.entryKind - right.entryKind || b4a.compare(left.key, right.key)
}

async function snapshotAuthority (manifest) {
  const cell = createBlindCellControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY })
  const inbox = createBlindInboxControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY })
  const core = createBlindCoreControlSnapshotSemanticAuthority({ partitionKey: PARTITION_KEY })
  const cellInbox = createBlindCellInboxControlSnapshotSemanticAuthority({
    partitionKey: PARTITION_KEY,
    cellVerifier: createBlindCellControlSnapshotSemanticVerifier(cell),
    inboxVerifier: createBlindInboxControlSnapshotSemanticVerifier(inbox)
  })
  const combined = createBlindCellInboxCoreControlSnapshotSemanticAuthority({
    partitionKey: PARTITION_KEY,
    cellInboxVerifier: createBlindCellInboxControlSnapshotSemanticVerifier(cellInbox),
    coreVerifier: createBlindCoreControlSnapshotSemanticVerifier(core)
  })
  const entries = []
  for await (const entry of streamBlindCellControlSnapshotEntries(cell, emptyCellState(manifest))) entries.push(entry)
  for await (const entry of streamBlindInboxControlSnapshotEntries(inbox, emptyInboxState(manifest))) entries.push(entry)
  for await (const entry of streamBlindCoreControlSnapshotEntries(core, emptyCoreState(manifest))) entries.push(entry)
  entries.sort(compareEntries)
  return {
    entries,
    recoveryVerifier: createBlindCellInboxCoreControlSnapshotSemanticVerifier(combined),
    verifier: createBlindCellInboxCoreEmptyGenesisSnapshotSemanticVerifier(combined)
  }
}

async function newRoot (t) {
  const created = await fs.mkdtemp(path.join(os.tmpdir(), 'hiverelay-profile1-genesis-'))
  const root = await fs.realpath(created)
  await fs.chmod(root, 0o700)
  t.teardown(() => fs.rm(root, { recursive: true, force: true }))
  return root
}

async function fixture (t, options = {}) {
  const root = options.root || await newRoot(t)
  const descriptor = descriptorValue()
  const descriptorCanonical = encodeCanonical(blindServiceDescriptorV1, descriptor)
  const manifest = decodeCanonical(blindStoreManifestV1, manifestBytes({
    descriptor,
    canonicalBytes: descriptorCanonical,
    checkpointWalSequence: 0n,
    checkpointHash: b4a.alloc(32),
    mac: b4a.alloc(32)
  }), { copyBytes: true })
  const snapshot = await snapshotAuthority(manifest)
  return {
    root,
    manifest,
    snapshot,
    coordinator (overrides = {}) {
      return new BlindProfile1StoreGenesisCoordinator({
        root,
        manifestKey: overrides.manifestKey || MANIFEST_KEY,
        partitionKey: PARTITION_KEY,
        manifestTemplate: manifest,
        genesisRecord: {
          type: 9,
          virtualBucket: 0,
          payload: b4a.from('profile-1-floor-genesis-v1')
        },
        genesisSnapshotEntries: snapshot.entries,
        snapshotSemanticVerifier: snapshot.verifier,
        maximumSnapshotBytes: 1024 * 1024,
        maximumEntries: 1024,
        faultInjector: overrides.faultInjector
      })
    }
  }
}

async function openRuntime (state, coordinator = state.coordinator(), observations = {}) {
  observations.shadow = observations.shadow || []
  observations.recovered = observations.recovered || []
  return coordinator.open({
    applyShadowFrame: async frame => { observations.shadow.push(frame.sequence) },
    applyRecoveredFrame: async frame => { observations.recovered.push(frame.sequence) }
  })
}

test('profile-1 genesis publishes revision 1, removes intent, and always returns through validated recovery', async t => {
  const state = await fixture(t)
  const observed = {}
  const runtime = await openRuntime(state, state.coordinator(), observed)
  t.alike(observed.shadow, [])
  t.alike(observed.recovered, [1n])
  t.is(runtime.recoveryAuthority.checkpointSequence, 1n)
  t.is(runtime.recoveryAuthority.walHeadSequence, 1n)
  t.is(runtime.recoveryAuthority.tornTailBytes, 0)
  t.is((await classifyBlindStoreRoot(state.root)).kind, BLIND_STORE_ROOT_CLASSIFICATION.CURRENT_MANIFESTED)
  const controlNames = (await fs.readdir(path.join(state.root, 'control'))).sort()
  t.ok(controlNames.includes('manifest-a.v1'))
  t.ok(controlNames.includes('manifest-b.v1'))
  t.absent(controlNames.includes('genesis-intent.v1'))
  t.is(BLIND_PROFILE1_STORE_GENESIS_STATUS.productionReady, false)
  t.is(BLIND_PROFILE1_STORE_GENESIS_STATUS.emptyGenesisPublicationSemanticAuthorityImplemented, true)
  t.ok(BLIND_PROFILE1_STORE_GENESIS_STATUS.remainingBlockers.includes(
    'FINAL_STORE_FORMAT_AUTHORITY_UNPUBLISHED'))
  t.ok(BLIND_PROFILE1_STORE_GENESIS_STATUS.remainingBlockers.includes(
    'TWO_SLOT_MANIFEST_RUNTIME_INTEGRATION_UNASSEMBLED'))
  t.ok(BLIND_PROFILE1_STORE_GENESIS_STATUS.remainingBlockers.includes(
    'CELL_INBOX_CORE_WAL_STATE_MACHINE_AND_ENGINE_RESTORE_UNIMPLEMENTED'))
  await runtime.close()

  const reopened = {}
  const second = await openRuntime(state, state.coordinator(), reopened)
  t.alike(reopened.shadow, [])
  t.alike(reopened.recovered, [1n])
  await second.close()
})

test('profile-1 genesis requires its narrow empty-state semantic authority and exactly three globals', async t => {
  const state = await fixture(t)
  await t.exception.all(() => new BlindProfile1StoreGenesisCoordinator({
    root: state.root,
    manifestKey: MANIFEST_KEY,
    partitionKey: PARTITION_KEY,
    manifestTemplate: state.manifest,
    genesisRecord: { type: 9, virtualBucket: 0, payload: b4a.from('profile-1-floor-genesis-v1') },
    genesisSnapshotEntries: state.snapshot.entries,
    snapshotSemanticVerifier: state.snapshot.recoveryVerifier
  }), /branded empty-genesis/)

  const extra = [...state.snapshot.entries, {
    entryKind: state.snapshot.entries[0].entryKind,
    key: b4a.concat([state.snapshot.entries[0].key, b4a.from([0])]),
    value: state.snapshot.entries[0].value
  }]
  await t.exception.all(() => new BlindProfile1StoreGenesisCoordinator({
    root: state.root,
    manifestKey: MANIFEST_KEY,
    partitionKey: PARTITION_KEY,
    manifestTemplate: state.manifest,
    genesisRecord: { type: 9, virtualBucket: 0, payload: b4a.from('profile-1-floor-genesis-v1') },
    genesisSnapshotEntries: extra,
    snapshotSemanticVerifier: state.snapshot.verifier
  }), /exactly three canonical empty global fragments/)

  const substituted = state.snapshot.entries.map((entry, index) => ({
    ...entry,
    key: index === 0 ? b4a.from([entry.key[0], 2]) : entry.key
  }))
  const substitutedCoordinator = new BlindProfile1StoreGenesisCoordinator({
    root: state.root,
    manifestKey: MANIFEST_KEY,
    partitionKey: PARTITION_KEY,
    manifestTemplate: state.manifest,
    genesisRecord: { type: 9, virtualBucket: 0, payload: b4a.from('profile-1-floor-genesis-v1') },
    genesisSnapshotEntries: substituted,
    snapshotSemanticVerifier: state.snapshot.verifier,
    maximumSnapshotBytes: 1024 * 1024,
    maximumEntries: 1024
  })
  await t.exception(openRuntime(state, substitutedCoordinator), /non-global or noncanonical family fragment/)
})

const CRASH_POINTS = Object.freeze([
  'store-session:after-classification',
  'store-session:after-pristine-recheck',
  'store-session:after-control-mkdir',
  'store-session:after-lock-create',
  'store-session:after-lock-file-sync',
  'store-session:after-control-directory-sync',
  'store-session:after-root-directory-sync',
  'profile1-genesis:after-store-session-open',
  'genesis-intent:after-temp-write',
  'genesis-intent:after-temp-sync',
  'genesis-intent:after-no-replace-rename',
  'genesis-intent:after-directory-sync',
  'store:blob:after-directory-create',
  'store:blob:after-parent-directory-sync',
  'store:staging:after-directory-create',
  'store:staging:after-parent-directory-sync',
  'wal:after-file-open',
  'wal:after-open-file-sync',
  'wal:after-open-directory-sync',
  'wal:after-write',
  'wal:after-sync',
  'profile1-genesis:after-wal-genesis',
  'checkpoint:snapshot:after-temp-write',
  'checkpoint:snapshot:after-temp-sync',
  'checkpoint:snapshot:after-no-replace-rename',
  'checkpoint:snapshot:after-install-directory-sync',
  'checkpoint:snapshot:after-reopen-verify',
  'checkpoint:checkpoint:after-temp-write',
  'checkpoint:checkpoint:after-temp-sync',
  'checkpoint:checkpoint:after-no-replace-rename',
  'checkpoint:checkpoint:after-install-directory-sync',
  'checkpoint:checkpoint:after-reopen-verify',
  'manifest:after-temp-write',
  'manifest:after-temp-sync',
  'manifest:after-rename',
  'manifest:after-directory-sync',
  'manifest:after-first-install',
  'manifest:after-second-install',
  'profile1-genesis:after-store-validation',
  'genesis-intent:after-unlink',
  'genesis-intent:after-unlink-directory-sync'
])

test('every genesis write, fsync, rename, and publication boundary resumes to one exact store', async t => {
  t.plan(CRASH_POINTS.length * 4)
  for (const crashPoint of CRASH_POINTS) {
    const state = await fixture(t)
    let reached = false
    const crashing = state.coordinator({
      faultInjector: async point => {
        if (!reached && point === crashPoint) {
          reached = true
          throw new Error(`simulated crash at ${point}`)
        }
      }
    })
    await t.exception(openRuntime(state, crashing), new RegExp(`simulated crash at ${crashPoint.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`))
    t.ok(reached, `${crashPoint} was exercised`)
    const observed = {}
    const recovered = await openRuntime(state, state.coordinator(), observed)
    t.alike(observed.recovered, [1n], `${crashPoint} recovered exactly one genesis frame`)
    t.is((await classifyBlindStoreRoot(state.root)).kind,
      BLIND_STORE_ROOT_CLASSIFICATION.CURRENT_MANIFESTED,
      `${crashPoint} ended manifested`)
    await recovered.close()
  }
})

test('authenticated genesis cleans only its own orphan artifact temporaries and that cleanup is resumable', async t => {
  for (const cleanupPoint of [
    'profile1-genesis:after-artifact-temp-unlink',
    'profile1-genesis:after-artifact-temp-directory-sync'
  ]) {
    const state = await fixture(t)
    let staged = false
    await t.exception(openRuntime(state, state.coordinator({
      faultInjector: async point => {
        if (!staged && point === 'checkpoint:snapshot:after-temp-sync') {
          staged = true
          throw new Error('leave authenticated genesis snapshot temporary')
        }
      }
    })), /leave authenticated genesis snapshot temporary/)
    let cleanupReached = false
    await t.exception(openRuntime(state, state.coordinator({
      faultInjector: async point => {
        if (!cleanupReached && point === cleanupPoint) {
          cleanupReached = true
          throw new Error(`stop at ${cleanupPoint}`)
        }
      }
    })), new RegExp(`stop at ${cleanupPoint}`))
    t.ok(cleanupReached)
    const runtime = await openRuntime(state)
    const controlNames = await fs.readdir(path.join(state.root, 'control'))
    t.absent(controlNames.some(name => /^\.(checkpoint|snapshot)-/.test(name)))
    await runtime.close()
  }
})

test('authenticated intent rejects a different manifest key and partial WAL without an intent is ambiguous', async t => {
  const state = await fixture(t)
  let crashed = false
  await t.exception(openRuntime(state, state.coordinator({
    faultInjector: async point => {
      if (!crashed && point === 'genesis-intent:after-directory-sync') {
        crashed = true
        throw new Error('stop after durable intent')
      }
    }
  })), /stop after durable intent/)
  await t.exception(openRuntime(state, state.coordinator({ manifestKey: bytes(0x92) })), /intent MAC|commitment/)

  const other = await fixture(t)
  const control = path.join(other.root, 'control')
  await fs.mkdir(control, { mode: 0o700 })
  await fs.writeFile(path.join(control, 'writer.lock.v1'), b4a.alloc(0), { mode: 0o600 })
  await fs.writeFile(path.join(control, 'wal.v2'), b4a.from('unbound-wal'), { mode: 0o600 })
  t.is((await classifyBlindStoreRoot(other.root)).kind, BLIND_STORE_ROOT_CLASSIFICATION.LEGACY_AMBIGUOUS)
  await t.exception(openRuntime(other, other.coordinator()), /legacy or ambiguous/)
})
