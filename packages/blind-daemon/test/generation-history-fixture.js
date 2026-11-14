import fs from 'node:fs/promises'
import path from 'node:path'
import { generateKeyPairSync, sign } from 'node:crypto'
import b4a from 'b4a'
import {
  allocationCommitment,
  blake2b256,
  cellPutRequestCommitment,
  cellStorageSlot,
  encodeCanonical,
  relayResultBindingV1
} from '@hiverelay/blind-protocol'
import { BlindCellStorageEngine } from '../storage-engine.js'
import { prepareBlindGenerationStartup } from '../generation-startup.js'
import { createBlindGenerationWriterAcknowledgment, BLIND_STORE_READER_MODE } from '../storage-generation-v12.js'
import { BlindStoreSession, acquireBlindStoreSessionTransactionLease } from '../store-session.js'

const EPOCH_MILLIS = 21600000n
const RELAY_PUBLIC_KEY = b4a.alloc(32, 0x71)
const PARTITION_KEY = b4a.alloc(32, 0x81)
const FENCE_HASH = b4a.alloc(32, 0x91)
const CONTINUITY = b4a.alloc(32, 0x94)
const STORE_ID = b4a.alloc(32, 0x95)
const DURABILITY_PROFILE_HASH = b4a.alloc(32, 0x96)
const SEGMENT_MAX_BYTES = 64 * 1024

function clock (epoch = 1000) {
  return {
    epoch,
    offsetMillis: 0n,
    now () { return BigInt(this.epoch) * EPOCH_MILLIS + this.offsetMillis }
  }
}

function options (root, time, overrides = {}) {
  return {
    root,
    relayPublicKey: RELAY_PUBLIC_KEY,
    storeId: STORE_ID,
    durabilityProfileHash: DURABILITY_PROFILE_HASH,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: CONTINUITY,
    durabilityProfileId: 1,
    initialEpochFloor: 1000,
    nowUnixMillis: () => time.now(),
    autoClock: false,
    walSegmentMaxBytes: SEGMENT_MAX_BYTES,
    ...overrides
  }
}

function rawEd25519KeyPair () {
  const pair = generateKeyPairSync('ed25519')
  const der = pair.publicKey.export({ format: 'der', type: 'spki' })
  return { privateKey: pair.privateKey, publicKey: b4a.from(der.subarray(der.byteLength - 32)) }
}

function managementKeys () {
  return {
    create: rawEd25519KeyPair(),
    renew: rawEd25519KeyPair(),
    drop: rawEd25519KeyPair()
  }
}

function profile1ResultBindingBytes (overrides = {}) {
  return encodeCanonical(relayResultBindingV1, {
    version: 1,
    relayPublicKey: RELAY_PUBLIC_KEY,
    storeId: STORE_ID,
    descriptorSequence: 1n,
    descriptorHash: b4a.alloc(32, 0x97),
    durabilityProfileId: 1,
    durabilityContinuityHash: CONTINUITY,
    durabilityProfileHash: DURABILITY_PROFILE_HASH,
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: b4a.alloc(32),
    externalCommitWitness: null,
    ...overrides
  })
}

function putFixture (fixture = {}) {
  const keys = fixture.keys || managementKeys()
  const allocationEpoch = fixture.allocationEpoch == null ? 1000 : fixture.allocationEpoch
  const sizeClass = fixture.sizeClass == null ? 1 : fixture.sizeClass
  const leaseClass = fixture.leaseClass == null ? 1 : fixture.leaseClass
  const cellBlob = fixture.cellBlob || b4a.alloc(4096, fixture.blobByte == null ? 0xa1 : fixture.blobByte)
  const declaredBlobHash = fixture.declaredBlobHash || blake2b256(cellBlob)
  const storageSlot = cellStorageSlot({ allocationEpoch, createPublicKey: keys.create.publicKey })
  const allocation = allocationCommitment({
    relayPublicKey: RELAY_PUBLIC_KEY,
    storageSlot,
    allocationEpoch,
    sizeClass,
    leaseClass,
    declaredCellBlobHash: declaredBlobHash,
    createPublicKey: keys.create.publicKey,
    renewPublicKey: keys.renew.publicKey,
    dropPublicKey: keys.drop.publicKey
  })
  const clientNonce = fixture.clientNonce || b4a.alloc(32, fixture.nonceByte == null ? 0xb1 : fixture.nonceByte)
  const requestCommitment = cellPutRequestCommitment({ allocationCommitment: allocation, clientNonce })
  const request = {
    version: 1,
    storageSlot,
    allocationEpoch,
    sizeClass,
    leaseClass,
    clientNonce,
    createPublicKey: keys.create.publicKey,
    renewPublicKey: keys.renew.publicKey,
    dropPublicKey: keys.drop.publicKey,
    declaredBlobHash,
    createSignature: sign(null, allocation, keys.create.privateKey)
  }
  return {
    keys,
    cellBlob,
    request,
    preparedAdmission: {
      spendTag: fixture.spendTag || b4a.alloc(32, fixture.spendByte == null ? 0xc1 : fixture.spendByte),
      requestCommitment,
      profileId: fixture.profileId == null ? 1 : fixture.profileId,
      schemeId: 1,
      parameterHash: b4a.alloc(32, 0xc7),
      costClass: { resourceClass: sizeClass, leaseClass, costUnits: 1n },
      walCommitRecord: b4a.alloc(32, 0xc8)
    },
    source: fixture.source == null ? cellBlob : fixture.source
  }
}

async function atomicPut (engine, fixture) {
  return engine.commitAtomicCellPut({
    authority: await engine.stageAtomicCellPut({
      request: fixture.request,
      source: fixture.cellBlob,
      admissionProfileId: fixture.preparedAdmission.profileId,
      resultBinding: profile1ResultBindingBytes()
    }),
    preparedAdmission: fixture.preparedAdmission,
    preCommitFence: () => true
  })
}

async function sealedSegmentNames (root) {
  const names = await fs.readdir(path.join(root, 'control'))
  return names.filter(name => name.startsWith('wal-')).sort()
}

export { clock, options, putFixture, atomicPut, profile1ResultBindingBytes, sealedSegmentNames, BlindCellStorageEngine }

export const MANIFEST_KEY = b4a.alloc(32, 0xd1)
export const INSTALLATION_ID = b4a.from('generation-history-functional-fixture')

export function startupOptions (root, time, extra = {}) {
  return {
    stores: [{ role: 'cell', root, engineOptions: options(root, time) }],
    manifestKey: MANIFEST_KEY,
    installationIdentity: INSTALLATION_ID,
    readerMode: BLIND_STORE_READER_MODE.BLIND_ONLY,
    ...extra
  }
}

export async function openHistory (root, time, extra = {}) {
  const startup = await prepareBlindGenerationStartup(startupOptions(root, time, extra))
  const engine = new BlindCellStorageEngine(options(root, time, {
    generationStartupHandoff: startup.handoffs.get('cell'),
    onBlindWriteAcknowledged: createBlindGenerationWriterAcknowledgment(() => startup.floor, 'cell'),
    faultInjector: extra.faultInjector
  }))
  try {
    await engine.open()
    return { engine, startup, async close () { await engine.close(); await startup.close() } }
  } catch (error) {
    await engine.close()
    await startup.close()
    throw error
  }
}

export async function retireCells (engine, time) {
  time.epoch = 1040
  await engine.confirmClock(time.epoch)
  await engine.gc()
  time.epoch = 2502
  await engine.confirmClock(time.epoch)
  return engine.compact()
}

export async function generationBytes (root) {
  const control = path.join(root, 'control')
  return Promise.all((await fs.readdir(control)).filter(name => name.startsWith('blind-store-generation-')).sort().map(async name => ({ name, bytes: await fs.readFile(path.join(control, name)) })))
}

export async function inspectEngineHistory (Engine, engineOptions) {
  const session = new BlindStoreSession({ root: engineOptions.root, validationOnly: true, allowUnmanifestedWal: true })
  await session.open()
  const lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), engineOptions.root)
  try { return (await Engine.inspectGeneration(engineOptions, { lease })).hasIrreversibleState } finally { lease.release(); await session.close() }
}
