import b4a from 'b4a'
import test from 'brittle'
import sodium from 'sodium-universal'
import {
  CORE_SESSION_CLASS,
  FAMILY,
  RESULT_SIGNATURE_DOMAIN_ID,
  blindCoreControlGlobalSnapshotV1,
  blindCoreOpenReplicationRetrySnapshotV1,
  coreOpenReplicationRequestCommitment,
  coreOpenReplicationResultV1,
  decodeCanonical,
  encodeCanonical,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import {
  BLIND_CORE_CONTROL_SNAPSHOT_STATUS,
  createBlindCoreControlSnapshotSemanticAuthority,
  createBlindCoreControlSnapshotSemanticVerifier,
  reconstructBlindCoreControlSnapshot,
  streamBlindCoreControlSnapshotEntries,
  verifyBlindCoreControlSnapshotSemanticResult,
  verifyBlindCoreControlSnapshotSemanticVerifier
} from '../core-control-snapshot.js'
import { coreOpenReplicationLogicalRetryKey } from '../core-stream.js'

const SEED = b4a.alloc(sodium.crypto_sign_SEEDBYTES, 0x91)
const RELAY_PUBLIC_KEY = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
const RELAY_SECRET_KEY = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
sodium.crypto_sign_seed_keypair(RELAY_PUBLIC_KEY, RELAY_SECRET_KEY, SEED)

function bytes (fill, length = 32) {
  return b4a.alloc(length, fill)
}

const STORE_ID = bytes(0x02)
const CONTINUITY = bytes(0x03)

function signResult (value) {
  const unsignedValue = { ...value, signature: bytes(0, 64) }
  const encoded = encodeCanonical(coreOpenReplicationResultV1, unsignedValue)
  const unsigned = encoded.subarray(0, encoded.byteLength - 64)
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature,
    resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.CORE_OPEN_RESULT, unsigned), RELAY_SECRET_KEY)
  return { ...unsignedValue, signature }
}

function record (seed, state, overrides = {}) {
  const sessionClass = overrides.sessionClass || 1
  const wireProfileHash = overrides.wireProfileHash || bytes(0x10 + seed)
  const clientNonce = overrides.clientNonce || bytes(0x20 + seed)
  const parentSessionId = overrides.parentSessionId || bytes(0x30 + seed, 16)
  const controlChannelId = overrides.controlChannelId || BigInt(40 + seed)
  const parentChannelBinding = overrides.parentChannelBinding || bytes(0x40 + seed)
  const streamId = overrides.streamId || BigInt(50 + seed)
  const limits = CORE_SESSION_CLASS[sessionClass]
  const openedAtEpoch = overrides.openedAtEpoch == null ? 100 : overrides.openedAtEpoch
  const requestCommitment = coreOpenReplicationRequestCommitment({
    relayPublicKey: RELAY_PUBLIC_KEY,
    wireProfileHash,
    sessionClass,
    controlChannelId,
    parentChannelBinding,
    clientNonce
  })
  const logicalRetryKey = coreOpenReplicationLogicalRetryKey(RELAY_PUBLIC_KEY, {
    wireProfileHash,
    sessionClass,
    clientNonce
  })
  const common = {
    family: FAMILY.CORE,
    operation: 'OPEN_REPLICATION',
    state,
    logicalRetryKey,
    spendTag: overrides.spendTag || bytes(0x50 + seed, 16),
    requestCommitment,
    wireProfileHash,
    sessionClass,
    clientNonce,
    parentSessionId,
    controlChannelId,
    parentChannelBinding,
    streamId,
    maxSessionBytes: BigInt(limits.maxSessionBytes),
    idleMillis: limits.idleMillis,
    lifetimeMillis: limits.lifetimeMillis,
    openedAtEpoch,
    terminalReason: state === 'TERMINAL' ? (overrides.terminalReason || 'clean-fin') : null
  }
  const result = signResult({
    version: 1,
    relayBinding: {
      version: 1,
      relayPublicKey: RELAY_PUBLIC_KEY,
      storeId: STORE_ID,
      descriptorSequence: 7n,
      descriptorHash: bytes(0x61),
      durabilityProfileId: 1,
      durabilityContinuityHash: CONTINUITY,
      durabilityProfileHash: bytes(0x62),
      restoreEvidenceHeadSequence: 0n,
      restoreEvidenceHeadHash: bytes(0),
      externalCommitWitness: null
    },
    wireProfileHash,
    sessionClass,
    controlChannelId,
    parentChannelBinding,
    streamId,
    maxSessionBytes: BigInt(limits.maxSessionBytes),
    idleMillis: limits.idleMillis,
    lifetimeMillis: limits.lifetimeMillis,
    openedAtEpoch,
    requestNonce: clientNonce,
    requestCommitment,
    signature: bytes(0, 64)
  })
  common.result = overrides.withoutResult === true ? null : result
  return common
}

function fixture (reverse = false) {
  const records = [
    record(1, 'RESERVED'),
    record(2, 'LIVE'),
    record(3, 'TERMINAL'),
    record(4, 'TERMINAL', { withoutResult: true, terminalReason: 'core-open-failed' })
  ]
  if (reverse) records.reverse()
  const recordsByLogical = new Map(records.map(value => [b4a.toString(value.logicalRetryKey, 'hex'), value]))
  const recordsBySpend = new Map(records.map(value => [b4a.toString(value.spendTag, 'hex'), value]))
  const controlChannels = new Map(records.map(value => [
    `${b4a.toString(value.parentSessionId, 'hex')}:${value.controlChannelId}`,
    value
  ]))
  return {
    relayPublicKey: RELAY_PUBLIC_KEY,
    storeId: STORE_ID,
    durabilityContinuityHash: CONTINUITY,
    recordsByLogical,
    recordsBySpend,
    controlChannels,
    epochFloor: 100,
    clockUnsafe: false,
    readOnlyReason: null
  }
}

function headers () {
  const header = {
    relayPublicKey: RELAY_PUBLIC_KEY,
    storeId: STORE_ID,
    durabilityContinuityHash: CONTINUITY,
    walSequence: 7n,
    walHash: bytes(0x04)
  }
  return {
    header,
    checkpointHeader: {
      relayPublicKey: header.relayPublicKey,
      storeId: header.storeId,
      durabilityContinuityHash: header.durabilityContinuityHash,
      coveredWalSequence: header.walSequence,
      coveredWalHash: header.walHash,
      epochFloor: 100
    }
  }
}

function authority (overrides = {}) {
  return createBlindCoreControlSnapshotSemanticAuthority(overrides)
}

async function entriesFor (semanticAuthority, state) {
  const output = []
  for await (const entry of streamBlindCoreControlSnapshotEntries(semanticAuthority, state)) {
    output.push({ entryKind: entry.entryKind, key: b4a.from(entry.key), value: b4a.from(entry.value) })
  }
  return output
}

async function reconstruct (semanticAuthority, entries) {
  return reconstructBlindCoreControlSnapshot(semanticAuthority, {
    ...headers(),
    declaredEntryCount: entries.length,
    entries
  })
}

function copyEntries (entries) {
  return entries.map(entry => ({
    entryKind: entry.entryKind,
    key: b4a.from(entry.key),
    value: b4a.from(entry.value)
  }))
}

function signedRetryIndexes (entries) {
  return entries
    .map((entry, index) => ({
      index,
      value: entry.entryKind === 5
        ? decodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, entry.value, { copyBytes: true })
        : null
    }))
    .filter(item => item.value && item.value.resultBytes != null)
}

test('Core recovery snapshots deterministically retain reserved/live/terminal retry barriers', async t => {
  const semanticAuthority = authority()
  const entries = await entriesFor(semanticAuthority, fixture())
  t.alike(await entriesFor(semanticAuthority, fixture(true)), entries)
  const verifier = createBlindCoreControlSnapshotSemanticVerifier(semanticAuthority)
  t.is(verifyBlindCoreControlSnapshotSemanticVerifier(verifier), verifier)
  const result = await verifier({ ...headers(), declaredEntryCount: entries.length, entries })
  t.is(verifyBlindCoreControlSnapshotSemanticResult(result, {
    ...headers().header,
    entryCount: 5
  }), result)
  t.is(result.coreOpenReplicationRetryComplete, true)
  t.is(result.coreComplete, false)
  t.is(result.publicationAuthorized, false)
  t.is(result.productionComplete, false)
  const recovered = result.coreState
  t.is(recovered.recordsByLogical.size, 4)
  t.is(recovered.recordsBySpend.size, 4)
  t.is(recovered.controlChannels.size, 4)
  t.alike([...recovered.recordsByLogical.values()].map(value => value.state).sort(),
    ['LIVE', 'RESERVED', 'TERMINAL', 'TERMINAL'])
  t.is([...recovered.recordsByLogical.values()].filter(value => value.result == null).length, 1)
  t.is(BLIND_CORE_CONTROL_SNAPSHOT_STATUS.coreMirrorBodyStorageImplemented, false)
  t.is(BLIND_CORE_CONTROL_SNAPSHOT_STATUS.coreReplicationEngineRestoreImplemented, false)
})

test('Core semantic authority/result state and tuple are branded and immutable', async t => {
  t.ok(createBlindCoreControlSnapshotSemanticAuthority())
  const semanticAuthority = authority()
  const entries = await entriesFor(semanticAuthority, fixture())
  const result = await reconstruct(semanticAuthority, entries)
  const original = result.coreState
  result.relayPublicKey.fill(0)
  result.coreState.recordsByLogical.clear()
  original.recordsBySpend.clear()
  verifyBlindCoreControlSnapshotSemanticResult(result, headers().header)
  t.alike(result.relayPublicKey, RELAY_PUBLIC_KEY)
  t.is(result.coreState.recordsByLogical.size, 4)
  t.is(result.coreState.recordsBySpend.size, 4)
  await t.exception.all(() => verifyBlindCoreControlSnapshotSemanticVerifier(async () => {}), /branded Core/)
  await t.exception.all(() => verifyBlindCoreControlSnapshotSemanticResult({ ...result }), /branded Core/)
})

test('Core reconstruction rejects unknown, duplicate, incomplete, substituted, and miscounted entries', async t => {
  const semanticAuthority = authority()
  const entries = await entriesFor(semanticAuthority, fixture())

  const unknown = copyEntries(entries)
  unknown[0].key[1] = 0xff
  await t.exception(reconstruct(semanticAuthority, unknown), /unknown Core control snapshot entry/)

  const duplicate = [entries[0], entries[0], ...entries.slice(1)]
  await t.exception(reconstruct(semanticAuthority, duplicate), /strictly sorted and duplicate-free/)

  const incomplete = entries.filter(entry => entry.entryKind !== 6)
  await t.exception(reconstruct(semanticAuthority, incomplete), /incomplete without its global record/)

  const substitutedKey = copyEntries(entries)
  substitutedKey[0].key[substitutedKey[0].key.byteLength - 1] ^= 1
  await t.exception(reconstruct(semanticAuthority, substitutedKey), /key does not match logicalRetryKey/)

  const collidingSpend = copyEntries(entries)
  const first = decodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, collidingSpend[0].value, { copyBytes: true })
  const second = decodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, collidingSpend[1].value, { copyBytes: true })
  second.spendTag = first.spendTag
  collidingSpend[1].value = encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, second)
  await t.exception(reconstruct(semanticAuthority, collidingSpend), /repeats an admission spend tag/)

  const wrongCount = copyEntries(entries)
  const globalIndex = wrongCount.findIndex(entry => entry.entryKind === 6)
  const global = decodeCanonical(blindCoreControlGlobalSnapshotV1, wrongCount[globalIndex].value, { copyBytes: true })
  global.liveCount++
  wrongCount[globalIndex].value = encodeCanonical(blindCoreControlGlobalSnapshotV1, global)
  await t.exception(reconstruct(semanticAuthority, wrongCount), /liveCount does not match/)
})

test('Core reconstruction rejects result, request, partition, epoch, and checkpoint substitution', async t => {
  const semanticAuthority = authority()
  const entries = await entriesFor(semanticAuthority, fixture())

  const wrongResult = copyEntries(entries)
  const signedIndexes = signedRetryIndexes(wrongResult)
  const first = signedIndexes[0].value
  const second = signedIndexes[1].value
  second.resultBytes = first.resultBytes
  wrongResult[signedIndexes[1].index].value = encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, second)
  await t.exception(reconstruct(semanticAuthority, wrongResult), /signed result does not match/)

  const badSignature = copyEntries(entries)
  const signedIndex = signedRetryIndexes(badSignature)[0]
  const signed = signedIndex.value
  const signedResult = decodeCanonical(coreOpenReplicationResultV1, signed.resultBytes, { copyBytes: true })
  signedResult.signature[0] ^= 1
  signed.resultBytes = encodeCanonical(coreOpenReplicationResultV1, signedResult)
  badSignature[signedIndex.index].value = encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, signed)
  await t.exception(reconstruct(semanticAuthority, badSignature), /signature is invalid/)

  const wrongRequest = copyEntries(entries)
  const request = decodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, wrongRequest[0].value, { copyBytes: true })
  request.requestCommitment[0] ^= 1
  wrongRequest[0].value = encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, request)
  await t.exception(reconstruct(semanticAuthority, wrongRequest), /request commitment does not match/)

  const wrongBucket = copyEntries(entries)
  const bucket = decodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, wrongBucket[0].value, { copyBytes: true })
  bucket.recordVirtualBucket ^= 1
  wrongBucket[0].value = encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, bucket)
  await t.exception(reconstruct(semanticAuthority, wrongBucket), /virtual bucket does not match/)

  const future = copyEntries(entries)
  const futureIndex = signedRetryIndexes(future)[0]
  const futureValue = futureIndex.value
  const futureResult = decodeCanonical(coreOpenReplicationResultV1, futureValue.resultBytes, { copyBytes: true })
  futureValue.openedAtEpoch = 101
  futureResult.openedAtEpoch = 101
  futureValue.resultBytes = encodeCanonical(coreOpenReplicationResultV1, futureResult)
  future[futureIndex.index].value = encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, futureValue)
  await t.exception(reconstruct(semanticAuthority, future), /openedAtEpoch exceeds/)

  await t.exception(reconstructBlindCoreControlSnapshot(semanticAuthority, {
    header: headers().header,
    checkpointHeader: { ...headers().checkpointHeader, coveredWalHash: bytes(0x99) },
    declaredEntryCount: entries.length,
    entries
  }), /tuple does not match/)
})

test('Core candidate generation rejects divergent indexes and unsupported/incomplete lifecycle state', async t => {
  const semanticAuthority = authority()

  const wrongSpend = fixture()
  wrongSpend.recordsBySpend.delete(wrongSpend.recordsBySpend.keys().next().value)
  await t.exception(entriesFor(semanticAuthority, wrongSpend), /spendIndexCount does not match/)

  const wrongChannel = fixture()
  wrongChannel.controlChannels.set('forged:1', wrongChannel.recordsByLogical.values().next().value)
  await t.exception(entriesFor(semanticAuthority, wrongChannel), /channelIndexCount does not match/)

  const missingTerminalReason = fixture()
  const terminal = [...missingTerminalReason.recordsByLogical.values()].find(value => value.state === 'TERMINAL')
  terminal.terminalReason = null
  await t.exception(entriesFor(semanticAuthority, missingTerminalReason), /requires a terminal reason/)

  const liveWithoutResult = fixture()
  const live = [...liveWithoutResult.recordsByLogical.values()].find(value => value.state === 'LIVE')
  live.result = null
  await t.exception(entriesFor(semanticAuthority, liveWithoutResult), /require their signed result/)

  const recoveryGap = fixture()
  recoveryGap.readOnlyReason = 'RECOVERY_GAP_READ_ONLY'
  await t.exception(entriesFor(semanticAuthority, recoveryGap), /no integrity-evidence schema/)

  const tooSmall = authority({ maximumCandidateEntries: 4 })
  await t.exception(entriesFor(tooSmall, fixture()), /configured entry bound/)
})
