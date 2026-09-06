import b4a from 'b4a'
import * as primitive from '../codec.js'
import * as internal from '../client-internal-schemas.js'
import * as wire from '../schemas.js'
import { blake2b256, hashStoreFormat, coreMirrorRequestCommitment, coreServeRequestCommitment, coreOpenReplicationRequestCommitment } from '../hashes.js'
import { definitions, limits, rules, rowCodecs, predecessorPins, validatorSha256, rowKeys, semanticSourcePins } from './catalog.js'

import { LEASE_CLASS_EPOCHS } from '../registry.js'

export { definitions, limits, rules, rowCodecs, predecessorPins, validatorSha256, rowKeys, semanticSourcePins }
const MAX_U64 = (1n << 64n) - 1n
const same = (a, b) => b4a.equals(a, b)
const hex = value => b4a.toString(value, 'hex')
const positive = (value, name) => { if (value === 0n || value === 0) fail(`${name} must be positive`) }
function fail (message) { throw Object.assign(new Error(message), { code: 'CHECKPOINT_FORMAT_INVALID' }) }

export function canonicalJSON (value) {
  if (typeof value === 'bigint') return JSON.stringify({ $u64: value.toString() })
  if (ArrayBuffer.isView(value)) return JSON.stringify({ $bytes: hex(value) })
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`
  if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJSON(value[k])}`).join(',')}}`
  return JSON.stringify(value)
}

const authorityBytes = b4a.from(canonicalJSON({ schema: 'hiverelay.checkpoint-format-authority.v2', formatMajor: 2, formatMinor: 0, definitions, limits, rules, rowCodecs, predecessorPins, validatorSha256, rowKeys, semanticSourcePins }) + '\n')
export const formatHash = () => b4a.from(hashStoreFormat(authorityBytes))

export const artifactBytes = () => b4a.from(authorityBytes)

const types = new Map()
function checked (base, check) {
  return {
    preencode (s, v) { check(v); base.preencode(s, v) },
    encode (s, v) { base.encode(s, v) },
    decode (s) { const v = base.decode(s); check(v); return v }
  }
}
function compile (type) {
  if (typeof type === 'string') {
    if (type === 'u8') return primitive.u8
    if (type === 'u16') return primitive.u16be
    if (type === 'u32') return primitive.u32be
    if (type === 'u64') return checked(primitive.u64be, v => { if (typeof v !== 'bigint') fail('u64 requires bigint') })
    if (type === 'bool') return primitive.ranged(primitive.u8, 0, 1, 'boolean')
    if (type === 'hash') return checked(primitive.fixedBytes(32), v => { if (!v || !ArrayBuffer.isView(v) || v.byteLength !== 32 || v.every(b => b === 0)) fail('hash must be nonzero bytes32') })
    if (types.has(type)) return types.get(type)
    if (!definitions[type]) fail('unknown closed schema')
    const fields = definitions[type]
    const codec = primitive.struct(fields.map(([name, child]) => [name, compile(child)]), {
      name: type,
      validate: value => {
        if (Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).length !== fields.length || fields.some(([name]) => !Object.hasOwn(value, name))) fail(`${type} requires exact fields`)
        validate(type, value)
      }
    })
    types.set(type, codec)
    return codec
  }
  if (type.array) return primitive.arrayOf(compile(type.array), 0, type.max)
  if (type.optional) return primitive.optional(compile(type.optional))
  if (type.bytes) return primitive.boundedBytes(...type.bytes)
  if (type.enum) return checked(primitive.u8, v => { if (!type.enum.includes(v)) fail('unknown enum value') })
  if (type.ascii) return primitive.constantBytes(b4a.from(type.ascii))
  if (type.constant != null) return primitive.constant(compile(type.width), type.constant)
  if (type.legacy) {
    const base = internal[type.legacy] || wire[type.legacy]
    if (!base) fail('unknown frozen codec')
    return checked(base, value => {
      const bytes = primitive.encodeCanonical(base, value)
      const decoded = primitive.decodeCanonical(base, bytes, { copyBytes: true })
      if (canonicalJSON(value) !== canonicalJSON(decoded)) fail(`noncanonical object for ${type.legacy}`)
    })
  }
  fail('unknown grammar type')
}

function sorted (rows, key, label) {
  const keys = rows.map(key)
  for (let i = 1; i < keys.length; i++) if (keys[i - 1] >= keys[i]) fail(`${label} must be strictly sorted and unique`)
}
const generationKey = key => `${hex(key.corePublicKey)}:${key.revision.toString(16).padStart(16, '0')}`
const bodyKey = body => `${body.virtualBucket}:${hex(body.objectId)}`

function validate (name, v) {
  if (name === 'Wal') positive(v.sequence, 'WAL sequence')
  if (name === 'Writer') { positive(v.mapGeneration, 'map generation'); positive(v.writerEpoch, 'writer epoch') }
  if (name === 'History') {
    positive(v.authoritySequence, 'authority sequence')
    if (v.irreversible && v.firstTriggerHash === null) fail('irreversible checkpoint requires existing first trigger')
  }
  if (name === 'Floors') positive(v.descriptorSequence, 'descriptor sequence')
  if (name === 'Body' && (v.byteLength < 1 || v.byteLength > 64 * 1024 * 1024)) fail('corpus byte length outside bound')
  if (name === 'Admission') positive(v.value.costUnits, 'paid cost')
  if (name === 'Mirror') {
    if ((v.state === 4) !== (v.terminalReason !== null) || (v.retryCount === 0) !== (v.retryReason === null) || (v.state === 2 && v.retryCount === 0)) fail('mirror lifecycle fields disagree')
    if (v.candidateRevision !== (v.acceptanceBasis ? v.acceptanceBasis.stateRevision + 1n : 0n) || (v.acceptanceBasis && v.acceptanceBasis.originWal.sequence >= v.acceptanceWal.sequence)) fail('mirror acceptance basis/revision mismatch')
    if (v.lifecycleWal.sequence < v.acceptanceWal.sequence || (v.lifecycleWal.sequence === v.acceptanceWal.sequence && !same(v.lifecycleWal.hash, v.acceptanceWal.hash))) fail('mirror lifecycle precedes acceptance')
    if (v.targetLeaseEpoch <= v.acceptedAtEpoch) fail('mirror lease is not advancing')
  }
  if (name === 'Generation') {
    if (v.key.revision !== (v.activationBasis ? v.activationBasis.revision + 1n : 0n) || (v.activationBasis && !same(v.key.corePublicKey, v.activationBasis.corePublicKey))) fail('activation revision/basis mismatch')
    positive(v.length, 'core length')
    if (v.leaseEpoch <= v.activatedAtEpoch) fail('activation exceeds lease')
  }
  if (name === 'Proof') {
    if ((v.expiredAtUnixMillis === null) !== (v.expiryWal === null) || (v.expiryWal && v.expiryWal.sequence <= v.pinWal.sequence)) fail('proof expiry evidence mismatch')
    if (v.proofByteLength < 1 || v.proofByteLength > 4194048 || (v.expiresAtUnixMillis <= v.pinnedAtUnixMillis || v.expiresAtUnixMillis - v.pinnedAtUnixMillis > 900000n) || (v.expiredAtUnixMillis !== null && v.expiredAtUnixMillis < v.expiresAtUnixMillis)) fail('proof bounds/lifecycle invalid')
  }
  if (name === 'CoreState') validateCore(v)
  if (name === 'Snapshot') validateSnapshot(v)
  if (name === 'Hc11Evidence' && (v.length !== 1n || v.fork !== 0n)) fail('HC11 v1 activation evidence requires unforked one-block sentinel')
  if (name === 'Participants') {
    positive(v.revision, 'participant revision')
    if ((v.revision === 1n) !== (v.previousAuthorityHash === null)) fail('authority predecessor presence invalid')
    if (v.blind.length === 0 && v.hc11 === null) fail('installation requires participants')
    sorted(v.blind, x => x.role, 'participant roles')
    const roots = v.blind.map(x => hex(x.rootId)); if (v.hc11) roots.push(hex(v.hc11.rootId))
    if (new Set(roots).size !== roots.length) fail('participant roots collide')
    if ((v.hc11 || v.blind.some(x => x.irreversible)) && v.firstTriggerHash === null) fail('irreversible participant lacks first trigger')
  }
  if (name === 'CoverageBinding') { positive(v.manifestRevision, 'manifest revision'); positive(v.retainFromSequence, 'retention floor'); if (!same(v.formatHash, formatHash()) || v.retainFromSequence > v.wal.sequence) fail('invalid coverage format/retention') }
  if (name === 'ReplayBinding') {
    if (v.maximumFrames < 1 || v.maximumFrames > limits.maximumRetainedWalFrames || v.maximumBytes < 1n || v.maximumBytes > BigInt(limits.maximumRetainedWalBytes) || v.observedFrames > v.maximumFrames || v.observedBytes > v.maximumBytes || v.head.sequence < v.coverage.wal.sequence || (v.head.sequence === v.coverage.wal.sequence && !same(v.head.hash, v.coverage.wal.hash))) fail('replay coverage or observed-work bounds invalid')
  }
}

function validateCore (v) {
  sorted(v.admissions, x => hex(x.value.spendTag), 'admissions')
  sorted(v.mirrors, x => hex(x.spendTag), 'mirrors')
  sorted(v.generations, x => generationKey(x.key), 'generations')
  sorted(v.floors, x => hex(x.key.corePublicKey), 'floors')
  sorted(v.proofs, x => hex(x.spendTag), 'proofs')
  sorted(v.opens, x => hex(x.value.logicalRetryKey), 'opens')
  const admissions = new Map(v.admissions.map(x => [hex(x.value.spendTag), x]))
  const mirrors = new Map(v.mirrors.map(x => [hex(x.spendTag), x]))
  const generations = new Map(v.generations.map(x => [generationKey(x.key), x]))
  const consumed = new Set()
  const liveBodies = new Map()
  const claim = (tag, operation, commitment) => {
    const key = hex(tag); const a = admissions.get(key)
    if (!a || a.operation !== operation || consumed.has(key) || !same(a.value.requestCommitment, commitment)) fail('paid row/admission ownership mismatch')
    consumed.add(key); return a.value
  }
  const live = g => {
    const key = bodyKey(g.corpus); const previous = liveBodies.get(key)
    if (previous && canonicalJSON(previous) !== canonicalJSON(g.corpus)) fail('body reference identity conflict')
    liveBodies.set(key, g.corpus)
  }
  for (const m of v.mirrors) {
    const a = claim(m.spendTag, 1, m.result.requestCommitment)
    if (a.leaseClass !== m.request.leaseClass || a.resourceClass < 1 || a.resourceClass > 45 || m.result.result !== 1 || m.result.leaseEpoch !== m.targetLeaseEpoch) fail('mirror admission/result mismatch')
    for (const field of ['corePublicKey', 'signedHeadHash']) if (!same(m.request[field], m.result[field])) fail('mirror result head mismatch')
    const basis = m.acceptanceBasis
    const length = !basis || m.request.fork > basis.fork || m.targetLeaseEpoch > basis.leaseEpoch ? m.request.length : m.request.length - basis.length
    let units = (length + 1048575n) / 1048576n; let expectedClass = 1
    while (units > 1n && expectedClass <= 45) { units >>= 1n; expectedClass++ }
    if (length < 1n || expectedClass > 45 || a.resourceClass !== expectedClass || m.targetLeaseEpoch < m.acceptedAtEpoch + LEASE_CLASS_EPOCHS[m.request.leaseClass] || (basis && (m.targetLeaseEpoch < basis.leaseEpoch || m.request.fork < basis.fork || (m.request.fork === basis.fork && (m.request.length < basis.length || (m.request.length === basis.length && !same(m.request.signedHeadHash, basis.signedHeadHash))))))) fail('mirror accepted basis/resource class invalid')
    if (m.request.fork !== m.result.fork || m.request.length !== m.result.length || !same(m.request.clientNonce, m.result.requestNonce)) fail('mirror result request mismatch')
  }
  const activatedMirrors = new Set(v.generations.map(g => hex(g.mirrorSpendTag)))
  if (activatedMirrors.size !== v.generations.length) fail('mirror activated more than once')
  for (const g of v.generations) {
    const m = mirrors.get(hex(g.mirrorSpendTag))
    if (!m || m.state !== 3 || !same(m.request.corePublicKey, g.key.corePublicKey) || m.request.fork !== g.fork || m.request.length !== g.length || !same(m.request.signedHeadHash, g.signedHeadHash) || m.targetLeaseEpoch !== g.leaseEpoch || g.activationWal.sequence <= m.acceptanceWal.sequence || canonicalJSON(g.activationWal) !== canonicalJSON(m.lifecycleWal)) fail('activation has no matching historically ACTIVE mirror')
  }
  for (const g of v.generations) if (g.activationBasis) { const prior = generations.get(generationKey(g.activationBasis)); if (!prior || prior.activationWal.sequence >= g.activationWal.sequence) fail('activation predecessor missing or regressed') }
  for (const m of v.mirrors) if (m.state === 3 && !activatedMirrors.has(hex(m.spendTag))) fail('ACTIVE mirror lacks activation evidence')
  const latest = new Map()
  for (const g of v.generations) latest.set(hex(g.key.corePublicKey), g.key)
  if (latest.size !== v.floors.length || v.floors.some(f => generationKey(latest.get(hex(f.key.corePublicKey)) || f.key) !== generationKey(f.key))) fail('durable latest floor missing or regressed')
  for (const f of v.floors) {
    const g = generations.get(generationKey(f.key)); if (!g) fail('floor lacks generation')
    if (f.active) { if (f.expiredAtEpoch !== null || f.expiryWal !== null) fail('active floor has expiry'); live(g) } else if (f.expiredAtEpoch === null || f.expiryWal === null || f.expiredAtEpoch < g.leaseEpoch || f.expiryWal.sequence <= g.activationWal.sequence) fail('inactive floor lacks valid expiry evidence')
  }
  for (const p of v.proofs) {
    const a = claim(p.spendTag, 2, p.acknowledgement.requestCommitment)
    const g = generations.get(generationKey(p.source))
    if (!g || a.leaseClass !== 0 || a.resourceClass < 1 || a.resourceClass > 6 || p.acknowledgement.result !== 2 || !same(p.request.corePublicKey, g.key.corePublicKey) || p.request.fork !== g.fork || p.request.length !== g.length || !same(p.request.signedHeadHash, g.signedHeadHash)) fail('proof admission/source mismatch')
    const resultBytes = 1 + primitive.encodeCanonical(wire.blindCoreAckV1, p.acknowledgement).byteLength + (p.proofByteLength <= 252 ? 1 : p.proofByteLength <= 65535 ? 3 : 5) + p.proofByteLength
    const expectedBand = [4096, 16384, 65536, 262144, 1048576, 4194304].findIndex(max => resultBytes <= max) + 1
    if (expectedBand === 0 || a.resourceClass !== expectedBand) fail('proof complete-result admission band mismatch')
    if (p.pinWal.sequence <= g.activationWal.sequence || p.acknowledgement.leaseEpoch !== g.leaseEpoch || p.request.fork !== p.acknowledgement.fork || p.request.length !== p.acknowledgement.length || !same(p.request.corePublicKey, p.acknowledgement.corePublicKey) || !same(p.request.signedHeadHash, p.acknowledgement.signedHeadHash) || !same(p.request.clientNonce, p.acknowledgement.requestNonce)) fail('proof acknowledgement/source binding mismatch')
    if (p.expiredAtUnixMillis === null) live(g)
  }
  const openKeys = ['streamId', 'requestCommitment'].map(field => v.opens.map(o => canonicalJSON(o.value[field])))
  openKeys.push(v.opens.map(o => `${hex(o.value.parentSessionId)}:${o.value.controlChannelId}`))
  if (openKeys.some(keys => new Set(keys).size !== keys.length)) fail('OPEN derived index collision')
  for (const o of v.opens) {
    const a = claim(o.value.spendTag, 3, o.value.requestCommitment)
    if (a.leaseClass !== 0 || a.resourceClass !== o.value.sessionClass) fail('OPEN admission mismatch')
  }
  if (consumed.size !== admissions.size) fail('admission lacks complete paid operation state')
  for (const field of ['admissions', 'mirrors', 'generations', 'floors', 'proofs', 'opens']) if (v.counts[field] !== v[field].length) fail(`${field} count mismatch`)
  if (v.counts.activeCores !== v.floors.filter(f => f.active).length || v.counts.liveProofPins !== v.proofs.filter(p => p.expiredAtUnixMillis === null).length || v.counts.liveCorpusBytes !== [...liveBodies.values()].reduce((n, b) => n + BigInt(b.byteLength), 0n)) fail('core live ownership accounting mismatch')
  if (v.counts.controlBytes !== 512n * BigInt(v.mirrors.length + v.opens.length) || v.counts.proofPinBytes !== 1024n * BigInt(v.counts.liveProofPins) || v.counts.tombstoneBytes !== 256n * BigInt(v.proofs.length - v.counts.liveProofPins)) fail('core control accounting mismatch')
}

// The existing CELL/INBOX canonical entries are reused, not rewritten.

function validateSnapshot (v) {
  if (!same(v.formatHash, formatHash())) fail('unknown successor format hash')
  positive(v.revision, 'snapshot revision'); positive(v.retainFromSequence, 'retention floor')
  if ((v.revision === 1n) !== (v.previousSnapshotHash === null) || v.compactionWalHighWater > v.coveredWal.sequence || v.retainFromSequence > v.coveredWal.sequence) fail('snapshot predecessor or compaction coverage mismatch')
  const role = v.identity.role
  if ((role === 1) !== (v.cell !== null) || (role === 2) !== (v.inbox !== null) || (role === 3) !== (v.core !== null)) fail('role payload mismatch')
  if (role === 3) {
    if (v.core.admissions.length && !v.history.irreversible) fail('paid CORE state has false history')
    for (const g of v.core.generations) if (g.activationWal.sequence > v.coveredWal.sequence || g.activatedAtEpoch > v.floors.epoch) fail('generation exceeds checkpoint')
    const resultBinding = result => {
      for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash']) if (!same(result.relayBinding[field], v.identity[field])) fail('CORE result identity mismatch')
      if (result.relayBinding.descriptorSequence > v.floors.descriptorSequence || (result.relayBinding.descriptorSequence === v.floors.descriptorSequence && !same(result.relayBinding.descriptorHash, v.floors.descriptorHash))) fail('CORE result descriptor floor mismatch')
    }
    for (const m of v.core.mirrors) {
      resultBinding(m.result)
      if (m.result.observedAtEpoch !== m.acceptedAtEpoch) fail('mirror observation/acceptance mismatch')
      if (m.acceptanceWal.sequence > v.coveredWal.sequence || m.lifecycleWal.sequence > v.coveredWal.sequence || m.acceptedAtEpoch > v.floors.epoch || m.virtualBucket !== coreBucket(m.request.corePublicKey)) fail('mirror capture bounds/bucket mismatch')
      if (!same(coreMirrorRequestCommitment({ ...m.request, relayPublicKey: v.identity.relayPublicKey }), m.result.requestCommitment)) fail('mirror request commitment mismatch')
    }
    for (const p of v.core.proofs) {
      resultBinding(p.acknowledgement)
      if (p.pinWal.sequence > v.coveredWal.sequence || (p.expiryWal && p.expiryWal.sequence > v.coveredWal.sequence) || !same(coreServeRequestCommitment({ ...p.request, relayPublicKey: v.identity.relayPublicKey }), p.acknowledgement.requestCommitment)) fail('proof capture/request binding mismatch')
    }
    for (const g of v.core.generations) if (g.corpus.virtualBucket !== coreBucket(g.key.corePublicKey)) fail('corpus bucket mismatch')
    for (const f of v.core.floors) if (f.expiryWal && (f.expiryWal.sequence > v.coveredWal.sequence || f.expiredAtEpoch > v.floors.epoch)) fail('floor expiry exceeds checkpoint')
    for (const { value: o, lifecycleWal } of v.core.opens) {
      if (lifecycleWal.sequence > v.coveredWal.sequence || o.openedAtEpoch > v.floors.epoch || !same(openLogicalKey(v.identity.relayPublicKey, o), o.logicalRetryKey) || o.recordVirtualBucket !== coreBucket(o.logicalRetryKey) || !same(coreOpenReplicationRequestCommitment({ ...o, relayPublicKey: v.identity.relayPublicKey }), o.requestCommitment)) fail('OPEN identity/request/capture mismatch')
      if (o.resultBytes) {
        const result = primitive.decodeCanonical(wire.coreOpenReplicationResultV1, o.resultBytes, { copyBytes: true })
        resultBinding(result)
        for (const field of ['wireProfileHash', 'parentChannelBinding', 'requestCommitment']) if (!same(o[field], result[field])) fail('OPEN signed result mismatch')
        for (const field of ['sessionClass', 'controlChannelId', 'streamId', 'maxSessionBytes', 'idleMillis', 'lifetimeMillis', 'openedAtEpoch']) if (o[field] !== result[field]) fail('OPEN result tuple mismatch')
        if (!same(o.clientNonce, result.requestNonce)) fail('OPEN result nonce mismatch')
      }
    }
    return
  }
  const rows = role === 1 ? v.cell : v.inbox
  sorted(rows, x => `${x.kind.toString(16).padStart(2, '0')}${x.subtype.toString(16).padStart(2, '0')}${hex(x.key)}`, 'family rows')
  let global = null
  for (const row of rows) {
    const id = `${row.kind}:${row.subtype}`
    const codecName = rowCodecs[role][id]
    const codec = internal[codecName] || wire[codecName]
    if (!codec) fail('unknown family entry kind/subtype')
    if (row.kind === 2 || id === '6:2') fail('checkpoint capture must drain provisional/reserved state')
    const value = primitive.decodeCanonical(codec, row.value, { copyBytes: true })
    const expectedKey = b4a.concat(rowKeys[role][id].map(field => { const [key, type] = field.split(':'); return type ? primitive.encodeCanonical(type === 'u64' ? primitive.u64be : primitive.u16be, value[key]) : value[key] }))
    if (!same(expectedKey, row.key)) fail('family key/value identity mismatch')
    if (!same(primitive.encodeCanonical(codec, value), row.value)) fail('family entry is not canonical')
    if (id === '6:1') { if (row.key.byteLength || global) fail('invalid global key'); global = value }
  }
  if (global && (global.profileStagingCount !== 0 || (role === 1 ? global.stagingBytes !== 0n || global.reservedCells !== 0n : global.stagingFrameBytes !== 0n || global.reservedFrames !== 0n))) fail('global state must drain transient work')
  if (!global || global.epochFloor !== v.floors.epoch || global.clockUnsafe !== v.floors.clockUnsafe || global.recoveryGap !== v.floors.recoveryGap) fail('family global/floor binding mismatch')
  if (rows.some(r => (role === 1 && (r.kind === 3 || (r.kind === 1 && [1, 2, 5].includes(r.subtype)))) || (role === 2 && (r.kind === 4 || (r.kind === 1 && [1, 4].includes(r.subtype))))) && !v.history.irreversible) fail('paid family state has false history')
}

export function coreBucket (locator) {
  const hash = blake2b256(b4a.concat([b4a.from('hiverelay.blind.virtual-bucket.v1'), b4a.from([4]), primitive.encodeCanonical(primitive.u64be, BigInt(locator.byteLength)), locator]))
  return hash[0] * 256 + hash[1]
}
export function openLogicalKey (relayPublicKey, value) {
  return blake2b256(b4a.concat([b4a.from('hiverelay.blind.core-open-retry.v1'), relayPublicKey, value.wireProfileHash, b4a.from([value.sessionClass]), value.clientNonce]))
}

export function encode (name, value) {
  const codec = compile(name)
  const size = { start: 0, end: 0 }
  codec.preencode(size, value)
  if (size.end > limits.maximumSnapshotBytes) fail('encoded record exceeds total byte budget')
  return primitive.encodeCanonical(codec, value)
}
export function decode (name, bytes) {
  if (!ArrayBuffer.isView(bytes) || bytes.byteLength > limits.maximumSnapshotBytes) fail('encoded record exceeds total byte budget')
  return primitive.decodeCanonical(compile(name), bytes, { copyBytes: true })
}
export function snapshotHash (snapshot) {
  const data = encode('Snapshot', snapshot)
  return blake2b256(b4a.concat([b4a.from('hiverelay.blind.checkpoint-snapshot.v2'), primitive.encodeCanonical(primitive.u64be, BigInt(data.byteLength)), data]))
}
export function assertSnapshotSuccessor (previous, next) {
  encode('Snapshot', previous); encode('Snapshot', next)
  if (canonicalJSON(previous.identity) !== canonicalJSON(next.identity) || next.revision !== previous.revision + 1n || !same(snapshotHash(previous), next.previousSnapshotHash) || next.coveredWal.sequence <= previous.coveredWal.sequence) fail('snapshot successor lineage mismatch')
  if (next.history.irreversible < previous.history.irreversible || next.history.authoritySequence < previous.history.authoritySequence || (previous.history.firstTriggerHash !== null && !same(previous.history.firstTriggerHash, next.history.firstTriggerHash))) fail('history regressed')
  if (next.history.authoritySequence === previous.history.authoritySequence && !same(next.history.authorityRecordHash, previous.history.authorityRecordHash)) fail('authority sequence fork')
  if (next.floors.epoch < previous.floors.epoch || next.floors.descriptorSequence < previous.floors.descriptorSequence || (next.floors.descriptorSequence === previous.floors.descriptorSequence && !same(next.floors.descriptorHash, previous.floors.descriptorHash)) || next.compactionWalHighWater < previous.compactionWalHighWater) fail('checkpoint floor regressed or forked')
  if (next.writer.mapGeneration < previous.writer.mapGeneration || next.writer.writerEpoch < previous.writer.writerEpoch || (next.writer.writerEpoch === previous.writer.writerEpoch && !same(next.writer.fenceHash, previous.writer.fenceHash)) || next.retainFromSequence < previous.retainFromSequence) fail('writer or retention floor regressed/forked')
  if (previous.core) {
    // One canonical identity index per retained group. No per-record history scans.
    const retained = new Map(next.core.admissions.map(a => [hex(a.value.spendTag), canonicalJSON(a)]))
    const mirrors = new Map(next.core.mirrors.map(m => [hex(m.spendTag), m]))
    const generations = new Map(next.core.generations.map(g => [generationKey(g.key), g]))
    const floors = new Map(next.core.floors.map(f => [hex(f.key.corePublicKey), f]))
    const proofs = new Map(next.core.proofs.map(p => [hex(p.spendTag), p]))
    const opens = new Map(next.core.opens.map(o => [hex(o.value.logicalRetryKey), o]))
    for (const a of previous.core.admissions) if (retained.get(hex(a.value.spendTag)) !== canonicalJSON(a)) fail('CORE paid admission retired without a retention contract')
    const acceptance = m => {
      const { state, retryCount, retryReason, terminalReason, lifecycleWal, ...immutable } = m
      return canonicalJSON(immutable)
    }
    for (const m of previous.core.mirrors) {
      const n = mirrors.get(hex(m.spendTag))
      if (!n || acceptance(m) !== acceptance(n)) fail('CORE MIRROR acceptance evidence changed/retired')
      if (canonicalJSON(m) === canonicalJSON(n)) continue
      if (m.state === 3 || m.state === 4 || n.state < m.state || n.retryCount < m.retryCount || (n.retryCount === m.retryCount && n.retryReason !== m.retryReason) || (n.state === 2 && n.retryCount === m.retryCount) || n.state === 1 || n.lifecycleWal.sequence <= previous.coveredWal.sequence) fail('CORE MIRROR lifecycle regressed or final evidence changed')
    }
    for (const g of previous.core.generations) if (canonicalJSON(generations.get(generationKey(g.key))) !== canonicalJSON(g)) fail('CORE historical generation changed/retired')
    for (const f of previous.core.floors) {
      const n = floors.get(hex(f.key.corePublicKey))
      if (!n || n.key.revision < f.key.revision) fail('CORE durable floor regressed/retired')
      if (n.key.revision === f.key.revision) {
        if (canonicalJSON(n) === canonicalJSON(f)) continue
        if (!f.active || n.active || n.expiryWal.sequence <= previous.coveredWal.sequence) fail('CORE floor expiry changed or generation reactivated')
      } else {
        const g = generations.get(generationKey(n.key))
        if (g.activationWal.sequence <= previous.coveredWal.sequence || (f.expiryWal && g.activationWal.sequence <= f.expiryWal.sequence)) fail('CORE floor advance lacks later activation')
      }
    }
    for (const p of previous.core.proofs) {
      const n = proofs.get(hex(p.spendTag))
      if (!n || canonicalJSON({ ...p, expiryWal: null, expiredAtUnixMillis: null }) !== canonicalJSON({ ...n, expiryWal: null, expiredAtUnixMillis: null }) || (p.expiredAtUnixMillis !== null && canonicalJSON(n) !== canonicalJSON(p))) fail('CORE proof evidence changed/retired')
    }
    for (const o of previous.core.opens) {
      const n = opens.get(hex(o.value.logicalRetryKey))
      if (!n || n.value.lifecycleState < o.value.lifecycleState || (o.value.lifecycleState === 3 && canonicalJSON(o) !== canonicalJSON(n))) fail('CORE OPEN lifecycle regressed/retired')
    }
  }
  return true // A data-level relationship, never a verified-WAL or lease capability.
}
export const MAX_SEQUENCE = MAX_U64

export function participantHash (value) {
  const bytes = encode('Participants', value)
  return blake2b256(b4a.concat([b4a.from('hiverelay.blind.participant-authority.v1'), primitive.encodeCanonical(primitive.u64be, BigInt(bytes.byteLength)), bytes]))
}
export function assertParticipantsSuccessor (previous, next) {
  encode('Participants', previous); encode('Participants', next)
  if (!same(previous.installationId, next.installationId) || next.revision !== previous.revision + 1n || !same(participantHash(previous), next.previousAuthorityHash) || (previous.firstTriggerHash && !same(previous.firstTriggerHash, next.firstTriggerHash))) fail('installation lineage/first trigger mismatch')
  for (const p of previous.blind) {
    const n = next.blind.find(n => n.role === p.role)
    if (!n || ['rootId', 'storeId', 'durabilityContinuityHash', 'formatHash'].some(k => !same(p[k], n[k])) || n.irreversible < p.irreversible || n.wal.sequence < p.wal.sequence || (n.wal.sequence === p.wal.sequence && canonicalJSON(n) !== canonicalJSON(p))) fail('blind participant removed/regressed/forked')
  }
  if (previous.hc11 && canonicalJSON(previous.hc11) !== canonicalJSON(next.hc11)) fail('HC11 activation evidence changed/removed')
  return true
}
export function compatibility ({ major, minor, hash, reader, genesisAvailable }) {
  if (reader !== 'candidate-codec' && reader !== 'frozen-runtime') return 'REFUSE_UNKNOWN_READER'
  if (major === 2 && minor === 0 && hash && same(hash, formatHash())) return reader === 'candidate-codec' ? 'DECODE_ONLY_NO_RUNTIME_AUTHORITY' : 'REFUSE_UNSUPPORTED_FORMAT'
  if (major === 1 && minor === 2) return genesisAvailable ? 'REQUIRE_FROZEN_AUTHORITY_AND_FULL_WAL_READER' : 'REFUSE_PRUNED_PREDECESSOR'
  return 'REFUSE_UNKNOWN_FORMAT'
}
