import b4a from 'b4a'
import { blindCoreOpenReplicationRetrySnapshotV1, encodeCanonical } from '@hiverelay/blind-protocol'
import { BlindWalIntegrityError } from './transaction-store.js'

// This collector receives only transitions already checked by the real CORE
// reducer. It runs on the read-only shadow, never on the live storage engine.
// Its output is descriptive state, not checkpoint publication authority.
export function copyCoreCaptureValue (value) {
  if (value === null || typeof value !== 'object') return value
  if (ArrayBuffer.isView(value)) return b4a.from(value)
  if (Array.isArray(value)) return value.map(copyCoreCaptureValue)
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, copyCoreCaptureValue(item)]))
}

const hex = value => b4a.toString(value, 'hex')
const generationKey = value => `${hex(value.corePublicKey)}:${value.revision}`
const wal = frame => ({ sequence: frame.sequence, hash: b4a.from(frame.walHash) })
const keyOf = value => ({ corePublicKey: b4a.from(value.corePublicKey), revision: value.stateRevision })
const fail = message => { throw new BlindWalIntegrityError(`CORE full-WAL capture: ${message}`) }

export class CoreWalCaptureCollector {
  constructor (maximumRows) {
    this.maximumRows = maximumRows
    for (const kind of ['admissions', 'mirrors', 'generations', 'floors', 'proofs', 'opens']) this[kind] = new Map()
  }

  put (kind, key, value) {
    const rows = this[kind]
    if (!rows.has(key) && rows.size >= this.maximumRows) fail(`${kind} exceeds its retained-row bound`)
    rows.set(key, copyCoreCaptureValue(value))
  }

  admit (operation, admission) {
    const key = hex(admission.spendTag)
    if (this.admissions.has(key)) fail('paid admission repeated')
    this.put('admissions', key, { operation, value: admission })
  }

  mirrorAccepted (frame, admission, record, result, pending, current) {
    let acceptanceBasis = null
    if (pending) {
      const prior = this.mirrors.get(hex(pending.spendTag))
      if (!prior) fail('pending acceptance basis missing')
      acceptanceBasis = {
        fork: prior.request.fork,
        length: prior.request.length,
        signedHeadHash: prior.request.signedHeadHash,
        leaseEpoch: prior.targetLeaseEpoch,
        stateRevision: prior.candidateRevision,
        originWal: prior.acceptanceWal
      }
    } else if (current) {
      const prior = this.generations.get(generationKey(keyOf(current)))
      if (!prior) fail('activated acceptance basis missing')
      acceptanceBasis = {
        fork: prior.fork,
        length: prior.length,
        signedHeadHash: prior.signedHeadHash,
        leaseEpoch: prior.leaseEpoch,
        stateRevision: prior.key.revision,
        originWal: prior.activationWal
      }
    }
    this.admit(1, admission)
    this.put('mirrors', hex(admission.spendTag), {
      spendTag: admission.spendTag,
      request: record.request,
      result,
      acceptedAtEpoch: record.acceptedAtEpoch,
      acceptanceWal: wal(frame),
      acceptanceBasis,
      targetLeaseEpoch: record.targetLeaseEpoch,
      candidateRevision: record.candidateRevision,
      virtualBucket: record.virtualBucket,
      lifecycleWal: wal(frame),
      state: 1,
      retryCount: 0,
      retryReason: null,
      terminalReason: null
    })
  }

  mirrorActivated (frame, spendTag, record, previousFloor) {
    const mirror = this.mirrors.get(hex(spendTag))
    if (!mirror || (mirror.state !== 1 && mirror.state !== 2)) fail('activation lacks pending evidence')
    const key = keyOf(record)
    this.put('generations', generationKey(key), {
      key,
      mirrorSpendTag: spendTag,
      activationWal: wal(frame),
      activationBasis: previousFloor ? keyOf(previousFloor) : null,
      fork: record.fork,
      length: record.length,
      signedHeadHash: record.signedHeadHash,
      leaseEpoch: record.leaseEpoch,
      activatedAtEpoch: record.activatedAtEpoch,
      corpus: record.corpus
    })
    this.put('floors', hex(record.corePublicKey), { key, active: true, expiredAtEpoch: null, expiryWal: null })
    mirror.state = 3
    mirror.lifecycleWal = wal(frame)
  }

  mirrorTransition (frame, spendTag, state, record) {
    const row = this.mirrors.get(hex(spendTag))
    if (!row) fail('mirror lifecycle lacks acceptance')
    row.state = state
    row.lifecycleWal = wal(frame)
    row.retryCount = record.retryCount
    row.retryReason = record.retryReason ?? null
    row.terminalReason = record.terminalReason ?? null
  }

  proofPinned (frame, admission, pin, acknowledgement, source) {
    const key = keyOf(source)
    if (!this.generations.has(generationKey(key))) fail('proof source generation missing')
    this.admit(2, admission)
    this.put('proofs', hex(admission.spendTag), {
      spendTag: admission.spendTag,
      request: pin.request,
      acknowledgement,
      source: key,
      pinWal: wal(frame),
      expiryWal: null,
      proofByteLength: pin.proofByteLength,
      proofHash: pin.proofHash,
      pinnedAtUnixMillis: pin.pinnedAtUnixMillis,
      expiresAtUnixMillis: pin.expiresAtUnixMillis,
      expiredAtUnixMillis: null
    })
  }

  proofExpired (frame, value) {
    const row = this.proofs.get(hex(value.spendTag))
    if (!row || row.expiryWal !== null) fail('expiry lacks live retained proof')
    // The predecessor reducer did not enforce this timestamp predicate. Keep
    // normal legacy replay unchanged, but never manufacture an eligible time.
    if (value.expiredAtUnixMillis < row.expiresAtUnixMillis) fail('original proof expiry precedes its deadline')
    row.expiredAtUnixMillis = value.expiredAtUnixMillis
    row.expiryWal = wal(frame)
  }

  coreExpired (frame, value) {
    const row = this.floors.get(hex(value.corePublicKey))
    if (!row || row.key.revision !== value.stateRevision || !row.active) fail('expiry lacks active floor')
    row.active = false
    row.expiredAtEpoch = value.expiredAtEpoch
    row.expiryWal = wal(frame)
  }

  openState (frame, admission, snapshot) {
    const key = hex(snapshot.logicalRetryKey)
    const prior = this.opens.get(key)
    if (prior) {
      const retained = this.admissions.get(hex(admission.spendTag))
      // Compare the complete canonical admission, including its original
      // commit material. A new lifecycle must not rewrite the paid operation.
      if (!retained || retained.operation !== 3 || !sameValue(retained.value, admission)) fail('OPEN admission changed')
      const mutable = new Set(['lifecycleState', 'resultBytes', 'terminalReason'])
      for (const field of Object.keys(snapshot)) {
        if (!mutable.has(field) && !sameValue(prior.value[field], snapshot[field])) fail(`OPEN ${field} changed`)
      }
      if (prior.value.resultBytes !== null && snapshot.resultBytes !== null &&
          !b4a.equals(prior.value.resultBytes, snapshot.resultBytes)) fail('OPEN signed result changed')
    } else {
      this.admit(3, admission)
    }
    // Encoding enforces the frozen field grammar; the actual reducer checked
    // the retained result signature before this shadow-only hook ran.
    encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, snapshot)
    this.put('opens', key, { value: snapshot, lifecycleWal: wal(frame) })
  }

  finish (engine) {
    const rows = kind => [...this[kind]].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, row]) => row)
    const core = Object.fromEntries(['admissions', 'mirrors', 'generations', 'floors', 'proofs', 'opens'].map(kind => [kind, rows(kind)]))
    core.generations.sort((a, b) => b4a.compare(a.key.corePublicKey, b.key.corePublicKey) || (a.key.revision < b.key.revision ? -1 : a.key.revision > b.key.revision ? 1 : 0))
    const a = engine.accounting
    if (this.admissions.size !== engine.spends.size || this.mirrors.size !== engine.mirrorAttempts.size ||
        this.floors.size !== engine.coreFloors.size || this.opens.size !== engine.openRecords.size ||
        this.proofs.size !== a.proofPins + a.proofSpendTombstones) fail('retained groups disagree with replayed accounting')
    core.counts = {
      admissions: core.admissions.length,
      mirrors: core.mirrors.length,
      generations: core.generations.length,
      floors: core.floors.length,
      proofs: core.proofs.length,
      opens: core.opens.length,
      activeCores: a.activeCores,
      liveProofPins: a.proofPins,
      liveCorpusBytes: BigInt(a.corpusBytes),
      controlBytes: BigInt(a.controlBytes),
      proofPinBytes: BigInt(a.proofPinBytes),
      tombstoneBytes: BigInt(a.tombstoneBytes)
    }
    return copyCoreCaptureValue(core)
  }
}

function sameValue (a, b) {
  if (a === b) return true
  if (a === null || b === null || typeof a !== typeof b) return false
  if (ArrayBuffer.isView(a) || ArrayBuffer.isView(b)) return ArrayBuffer.isView(a) && ArrayBuffer.isView(b) && b4a.equals(a, b)
  if (typeof a !== 'object') return false
  const keys = Object.keys(a)
  return keys.length === Object.keys(b).length && keys.every(key => Object.hasOwn(b, key) && sameValue(a[key], b[key]))
}
