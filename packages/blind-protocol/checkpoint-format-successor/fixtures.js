// Deterministic structural fixtures. Hashes/signatures are synthetic; no store authority.
import b4a from 'b4a'
import { readFileSync } from 'node:fs'
import * as primitive from '../codec.js'
import * as internal from '../client-internal-schemas.js'
import * as wire from '../schemas.js'
import { coreMirrorRequestCommitment, coreServeRequestCommitment, coreOpenReplicationRequestCommitment } from '../hashes.js'
import { CORE_SESSION_CLASS } from '../registry.js'
import { formatHash, coreBucket, openLogicalKey, canonicalJSON, snapshotHash, MAX_SEQUENCE } from './codec.js'

export const H = n => b4a.alloc(32, n)
export const wal = n => ({ sequence: BigInt(n), hash: H(Number(BigInt(n) % 250n) + 1) })
export const clone = v => JSON.parse(canonicalJSON(v), (k, x) => x && x.$u64 !== undefined ? BigInt(x.$u64) : x && x.$bytes !== undefined ? b4a.from(x.$bytes, 'hex') : x)
export function populatedFamily (id) {
  const data = JSON.parse(readFileSync(new URL('./populated-family-fixtures.json', import.meta.url), 'utf8'), (k, x) => x && x.$u64 !== undefined ? BigInt(x.$u64) : x && x.$bytes !== undefined ? b4a.from(x.$bytes, 'hex') : x)
  const f = data.fixtures.find(f => f.id === id)
  if (!f) throw new Error('unknown populated family fixture')
  const s = base(f.role)
  Object.assign(s.identity, f.identity); Object.assign(s.floors, f.floors)
  s.history.irreversible = 1; s.history.firstTriggerHash = H(13)
  s[f.role === 1 ? 'cell' : 'inbox'] = f.rows
  return s
}
export function base (role) {
  return { magic: b4a.from('HRBCS002'), formatMajor: 2, formatMinor: 0, formatHash: formatHash(), identity: { installationId: H(1), rootId: H(role + 1), role, relayPublicKey: H(5), storeId: H(6), durabilityContinuityHash: H(7) }, coveredWal: wal(300001), writer: { mapGeneration: 1n, writerEpoch: 1n, fenceHash: H(8) }, floors: { epoch: 10, descriptorSequence: 1n, descriptorHash: H(9), clockUnsafe: 0, recoveryGap: 0 }, history: { irreversible: 0, authoritySequence: 1n, authorityRecordHash: H(10), firstTriggerHash: null }, revision: 1n, previousSnapshotHash: null, compactionWalHighWater: 0n, retainFromSequence: 1n, cell: null, inbox: null, core: null }
}
function global (role) {
  const codec = internal[role === 1 ? 'blindCellControlGlobalSnapshotV1' : 'blindInboxControlGlobalSnapshotV1']
  const value = Object.fromEntries(codec.schemaFields.map(name => [name, ['version', 'epochFloor', 'clockUnsafe', 'recoveryGap', 'profileStagingCount', 'integrityEvidenceCount'].includes(name) ? 0 : 0n]))
  Object.assign(value, { version: 1, epochFloor: 10, controlRecordAccountingBytes: 512, tombstoneRecordAccountingBytes: 512 })
  if (role === 2) Object.assign(value, { frameIndexAccountingBytes: 256, retryRecordAccountingBytes: 256 })
  return { kind: 6, subtype: 1, key: b4a.alloc(0), value: primitive.encodeCanonical(codec, value) }
}
export const family = role => ({ ...base(role), [role === 1 ? 'cell' : 'inbox']: [global(role)] })
export const emptyCore = () => ({ admissions: [], mirrors: [], generations: [], floors: [], proofs: [], opens: [], counts: { admissions: 0, mirrors: 0, generations: 0, floors: 0, proofs: 0, opens: 0, activeCores: 0, liveProofPins: 0, liveCorpusBytes: 0n, controlBytes: 0n, proofPinBytes: 0n, tombstoneBytes: 0n } })
export function binding (snapshot) {
  return { version: 1, relayPublicKey: snapshot.identity.relayPublicKey, storeId: snapshot.identity.storeId, descriptorSequence: 1n, descriptorHash: H(9), durabilityProfileId: 1, durabilityContinuityHash: H(7), durabilityProfileHash: H(11), restoreEvidenceHeadSequence: 0n, restoreEvidenceHeadHash: b4a.alloc(32), externalCommitWitness: null }
}
const admissionWire = () => ({ profileId: 1, schemeId: 1, parameterHash: H(12), token: b4a.from([1]) })
export function admission (operation, tag, commitment, resourceClass = 1, leaseClass = 0) {
  return { operation, value: { version: 1, spendTag: H(tag), requestCommitment: commitment, profileId: 1, schemeId: 1, parameterHash: H(12), resourceClass, leaseClass, costUnits: 1n, walCommitRecord: b4a.from([1]) } }
}
export function paidOpen (lifecycleState = 3) {
  const s = { ...base(3), core: emptyCore() }
  s.history.irreversible = 1; s.history.firstTriggerHash = H(13)
  const o = { version: 1, lifecycleState, logicalRetryKey: H(14), spendTag: H(20), requestCommitment: H(15), wireProfileHash: H(16), sessionClass: 1, clientNonce: H(17), parentSessionId: H(18), controlChannelId: 1n, parentChannelBinding: H(19), streamId: 2n, maxSessionBytes: BigInt(CORE_SESSION_CLASS[1].maxSessionBytes), idleMillis: CORE_SESSION_CLASS[1].idleMillis, lifetimeMillis: CORE_SESSION_CLASS[1].lifetimeMillis, openedAtEpoch: 10, recordVirtualBucket: 0, resultBytes: null, terminalReason: lifecycleState === 3 ? b4a.from('recovery-terminal') : null }
  o.logicalRetryKey = openLogicalKey(s.identity.relayPublicKey, o); o.recordVirtualBucket = coreBucket(o.logicalRetryKey)
  o.requestCommitment = coreOpenReplicationRequestCommitment({ ...o, relayPublicKey: s.identity.relayPublicKey })
  if (lifecycleState !== 3) o.resultBytes = primitive.encodeCanonical(wire.coreOpenReplicationResultV1, { version: 1, relayBinding: binding(s), wireProfileHash: o.wireProfileHash, sessionClass: o.sessionClass, controlChannelId: o.controlChannelId, parentChannelBinding: o.parentChannelBinding, streamId: o.streamId, maxSessionBytes: o.maxSessionBytes, idleMillis: o.idleMillis, lifetimeMillis: o.lifetimeMillis, openedAtEpoch: o.openedAtEpoch, requestNonce: o.clientNonce, requestCommitment: o.requestCommitment, signature: b4a.alloc(64, 1) })
  s.core.admissions.push(admission(3, 20, o.requestCommitment)); s.core.opens.push({ value: o, lifecycleWal: wal(8) })
  Object.assign(s.core.counts, { admissions: 1, opens: 1, controlBytes: 512n })
  return s
}
export function coreWithProof (expired = false) {
  const s = { ...base(3), core: emptyCore() }; const c = s.core
  s.history.irreversible = 1; s.history.firstTriggerHash = H(13)
  const request = { version: 1, corePublicKey: H(30), fork: 0n, length: 2n, signedHeadHash: H(31), leaseClass: 1, clientNonce: H(32), admission: admissionWire() }
  const requestCommitment = coreMirrorRequestCommitment({ ...request, relayPublicKey: s.identity.relayPublicKey })
  const result = { version: 1, relayBinding: binding(s), corePublicKey: request.corePublicKey, fork: 0n, length: 2n, signedHeadHash: request.signedHeadHash, observedAtEpoch: 1, leaseEpoch: 5, result: 1, requestNonce: request.clientNonce, requestCommitment, signature: b4a.alloc(64, 2) }
  c.admissions.push(admission(1, 20, requestCommitment, 1, 1))
  c.mirrors.push({ spendTag: H(20), request, result, acceptedAtEpoch: 1, acceptanceWal: wal(2), acceptanceBasis: null, targetLeaseEpoch: 5, candidateRevision: 0n, virtualBucket: coreBucket(request.corePublicKey), lifecycleWal: wal(3), state: 3, retryCount: 0, retryReason: null, terminalReason: null })
  const key = { corePublicKey: request.corePublicKey, revision: 0n }
  c.generations.push({ key, mirrorSpendTag: H(20), activationWal: wal(3), activationBasis: null, fork: 0n, length: 2n, signedHeadHash: request.signedHeadHash, leaseEpoch: 5, activatedAtEpoch: 1, corpus: { virtualBucket: coreBucket(request.corePublicKey), objectId: H(33), byteLength: 100, hash: H(34) } })
  c.floors.push({ key, active: 0, expiredAtEpoch: 5, expiryWal: wal(5) })
  const proofRequest = { version: 1, corePublicKey: request.corePublicKey, fork: 0n, length: 2n, signedHeadHash: request.signedHeadHash, blockIndices: [0n], clientNonce: H(35), admission: admissionWire() }
  const proofCommitment = coreServeRequestCommitment({ ...proofRequest, relayPublicKey: s.identity.relayPublicKey })
  const ack = { ...result, result: 2, requestNonce: proofRequest.clientNonce, requestCommitment: proofCommitment }
  c.admissions.push(admission(2, 21, proofCommitment))
  c.proofs.push({ spendTag: H(21), request: proofRequest, acknowledgement: ack, source: key, pinWal: wal(4), expiryWal: expired ? wal(6) : null, proofByteLength: 100, proofHash: H(36), pinnedAtUnixMillis: 1000n, expiresAtUnixMillis: 901000n, expiredAtUnixMillis: expired ? 901000n : null })
  Object.assign(c.counts, { admissions: 2, mirrors: 1, generations: 1, floors: 1, proofs: 1, liveProofPins: expired ? 0 : 1, liveCorpusBytes: expired ? 0n : 100n, controlBytes: 512n, proofPinBytes: expired ? 0n : 1024n, tombstoneBytes: expired ? 256n : 0n })
  return s
}
export function successor (previous) {
  const next = clone(previous); next.revision++; next.previousSnapshotHash = snapshotHash(previous); next.coveredWal = wal(previous.coveredWal.sequence + 1n)
  return next
}
export function positives () {
  const cell = family(1); const retired = clone(cell); retired.history.irreversible = 1; retired.history.firstTriggerHash = H(13); retired.compactionWalHighWater = 300000n; retired.retainFromSequence = 300001n
  const core = { ...base(3), core: emptyCore() }
  const high = successor(retired); high.coveredWal = wal(MAX_SEQUENCE)
  const blind = [1, 2, 3].map(role => ({ role, rootId: H(role + 1), storeId: H(6), durabilityContinuityHash: H(7), formatHash: formatHash(), wal: wal(300001), checkpointHash: H(40 + role), snapshotHash: H(50 + role), irreversible: role === 3 ? 1 : 0 }))
  const hc11 = { rootId: H(60), envelopeManifestHash: H(61), databaseIdentityHash: H(62), activationKey: H(63), length: 1n, fork: 0n, activationBlockHash: H(64), triggerReceiptHash: H(65) }
  const participants = { magic: b4a.from('HRBPA001'), installationId: H(1), revision: 1n, previousAuthorityHash: null, firstTriggerHash: H(13), blind, hc11 }
  const coverage = { identity: retired.identity, writer: retired.writer, formatHash: formatHash(), wal: retired.coveredWal, snapshotHash: snapshotHash(retired), checkpointHash: H(41), manifestHash: H(42), manifestRevision: 1n, historyRecordHash: H(10), retainFromSequence: 300001n }
  return [
    ...['cell-populated', 'inbox-populated-retry', 'inbox-expired-append'].map(id => [id, 'Snapshot', populatedFamily(id)]),
    ...lifecycleSuccessors().map(([id, previous, next]) => [id, 'Snapshot', next]),
    ['mirror-accepted', 'Snapshot', mirrorLifecycle(1)], ['mirror-retry-pending', 'Snapshot', mirrorLifecycle(2)], ['mirror-terminal', 'Snapshot', mirrorLifecycle(4)], ['core-historical-active-generations', 'Snapshot', historicalActivation()], ['cell-pristine', 'Snapshot', cell], ['inbox-pristine', 'Snapshot', family(2)], ['core-pristine', 'Snapshot', core], ['cell-retired-history', 'Snapshot', retired], ['core-paid-open-reserved', 'Snapshot', paidOpen(1)], ['core-paid-open-live', 'Snapshot', paidOpen(2)], ['core-paid-open-terminal', 'Snapshot', paidOpen(3)], ['core-expired-floor-live-proof', 'Snapshot', coreWithProof()], ['core-retained-expired-proof', 'Snapshot', coreWithProof(true)], ['u64-high-checkpoint', 'Snapshot', high], ['typed-four-participants', 'Participants', participants], ['coverage-description', 'CoverageBinding', coverage], ['bounded-large-head-empty-suffix', 'ReplayBinding', { coverage, head: coverage.wal, observedFrames: 0, observedBytes: 0n, maximumFrames: 1, maximumBytes: 1024n }]
  ]
}

export function lifecycleSuccessors () {
  const accepted = mirrorLifecycle(1)
  const pending = successor(accepted)
  Object.assign(pending.core.mirrors[0], { state: 2, retryCount: 1, retryReason: 1, lifecycleWal: pending.coveredWal })
  const retried = successor(pending)
  Object.assign(retried.core.mirrors[0], { retryCount: 2, retryReason: 2, lifecycleWal: retried.coveredWal })
  const terminal = successor(retried)
  Object.assign(terminal.core.mirrors[0], { state: 4, terminalReason: 1, lifecycleWal: terminal.coveredWal })
  const active = successor(retried); const generation = clone(coreWithProof().core.generations[0])
  Object.assign(active.core.mirrors[0], { state: 3, lifecycleWal: active.coveredWal })
  generation.activationWal = active.coveredWal
  active.core.generations = [generation]
  active.core.floors = [{ key: generation.key, active: 1, expiredAtEpoch: null, expiryWal: null }]
  Object.assign(active.core.counts, { generations: 1, floors: 1, activeCores: 1, liveCorpusBytes: 100n })
  const expired = successor(active)
  Object.assign(expired.core.floors[0], { active: 0, expiredAtEpoch: 5, expiryWal: expired.coveredWal })
  Object.assign(expired.core.counts, { activeCores: 0, liveCorpusBytes: 0n })
  const advanced = successor(expired); advanced.coveredWal = wal(expired.coveredWal.sequence + 2n)
  const newer = historicalActivation().core
  const mirror = clone(newer.mirrors[1]); mirror.acceptanceWal = wal(expired.coveredWal.sequence + 1n); mirror.lifecycleWal = advanced.coveredWal; mirror.acceptanceBasis.originWal = generation.activationWal
  const nextGeneration = clone(newer.generations[1]); nextGeneration.activationWal = advanced.coveredWal
  advanced.core.admissions.push(clone(newer.admissions[2])); advanced.core.mirrors.push(mirror); advanced.core.generations.push(nextGeneration)
  advanced.core.floors = [{ key: nextGeneration.key, active: 1, expiredAtEpoch: null, expiryWal: null }]
  Object.assign(advanced.core.counts, { admissions: 2, mirrors: 2, generations: 2, activeCores: 1, liveCorpusBytes: 100n, controlBytes: 1024n })
  return [['mirror-accepted-to-pending', accepted, pending], ['mirror-pending-retry-increment', pending, retried], ['mirror-pending-to-terminal', retried, terminal], ['mirror-pending-to-active', retried, active], ['floor-active-to-expired', active, expired], ['floor-expired-to-new-activation', expired, advanced]]
}

export function mirrorLifecycle (state) {
  const s = coreWithProof(); const c = s.core
  c.admissions.pop(); c.generations = []; c.floors = []; c.proofs = []
  Object.assign(c.mirrors[0], { state, lifecycleWal: wal(state === 1 ? 2 : 3), retryCount: state === 2 ? 1 : 0, retryReason: state === 2 ? 1 : null, terminalReason: state === 4 ? 1 : null })
  Object.assign(c.counts, { admissions: 1, generations: 0, floors: 0, proofs: 0, liveProofPins: 0, liveCorpusBytes: 0n, proofPinBytes: 0n })
  return s
}
export function historicalActivation () {
  const s = coreWithProof(true); const c = s.core; const old = c.generations[0]
  const request = { ...clone(c.mirrors[0].request), length: 3n, signedHeadHash: H(38), clientNonce: H(37) }
  const commitment = coreMirrorRequestCommitment({ ...request, relayPublicKey: s.identity.relayPublicKey })
  const result = { ...clone(c.mirrors[0].result), length: 3n, signedHeadHash: H(38), requestNonce: H(37), requestCommitment: commitment, observedAtEpoch: 10, leaseEpoch: 14 }
  c.admissions.push(admission(1, 22, commitment, 1, 1))
  c.mirrors.push({ ...clone(c.mirrors[0]), spendTag: H(22), request, result, acceptedAtEpoch: 10, acceptanceWal: wal(7), lifecycleWal: wal(8), candidateRevision: 1n, targetLeaseEpoch: 14, acceptanceBasis: { fork: 0n, length: 2n, signedHeadHash: H(31), leaseEpoch: 5, stateRevision: 0n, originWal: wal(3) } })
  const key = { corePublicKey: H(30), revision: 1n }
  c.generations.push({ ...clone(old), key, mirrorSpendTag: H(22), activationWal: wal(8), activationBasis: old.key, length: 3n, signedHeadHash: H(38), leaseEpoch: 14, activatedAtEpoch: 10, corpus: { ...clone(old.corpus), objectId: H(39) } })
  c.floors = [{ key, active: 1, expiredAtEpoch: null, expiryWal: null }]
  Object.assign(c.counts, { admissions: 3, mirrors: 2, generations: 2, activeCores: 1, liveCorpusBytes: 100n, controlBytes: 1024n })
  return s
}
