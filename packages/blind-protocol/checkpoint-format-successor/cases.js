import b4a from 'b4a'
import { positives, clone, H, family, paidOpen, coreWithProof, successor } from './fixtures.js'
import { encode, participantHash } from './codec.js'

export function negatives () {
  const cases = []
  const value = (id, make, mutate, pattern) => { const input = clone(make()); mutate(input); cases.push({ id, mode: 'encode', type: 'Snapshot', input, pattern }) }
  const cell = () => family(1)
  value('missing-history', cell, s => { delete s.history }, 'object')
  value('unknown-field', cell, s => { s.unreviewed = 1 }, 'exact fields')
  value('unknown-major', cell, s => { s.formatMajor = 3 }, 'must be 2')
  value('unknown-minor', cell, s => { s.formatMinor = 1 }, 'must be 0')
  value('unknown-hash', cell, s => { s.formatHash = H(99) }, 'unknown successor')
  value('role-payload-fork', cell, s => { s.identity.role = 2 }, 'role payload')
  value('zero-root', cell, s => { s.identity.rootId = b4a.alloc(32) }, 'nonzero')
  value('descriptor-zero', cell, s => { s.floors.descriptorSequence = 0n }, 'positive')
  value('global-floor-fork', cell, s => { s.floors.epoch++ }, 'global/floor')
  value('missing-global', cell, s => { s.cell = [] }, 'global/floor')
  value('duplicate-row', cell, s => { s.cell.push(clone(s.cell[0])) }, 'sorted and unique')
  value('global-key', cell, s => { s.cell[0].key = H(1) }, 'key/value identity')
  value('unknown-row', cell, s => { s.cell[0].subtype = 9 }, 'unknown family')
  value('provisional-row', cell, s => { s.cell[0].kind = 2 }, 'drain')
  value('malformed-row-bytes', cell, s => { s.cell[0].value = b4a.from([1]) }, 'truncated')
  value('compaction-beyond-anchor', cell, s => { s.compactionWalHighWater = s.coveredWal.sequence + 1n }, 'coverage mismatch')
  value('retention-beyond-anchor', cell, s => { s.retainFromSequence = s.coveredWal.sequence + 1n }, 'coverage mismatch')
  value('u64-overflow', cell, s => { s.coveredWal.sequence = 1n << 64n }, 'outside u64')
  value('u64-number', cell, s => { s.coveredWal.sequence = 300001 }, 'requires bigint')
  value('paid-open-false-history', paidOpen, s => { s.history.irreversible = 0 }, 'false history')
  value('paid-open-missing-trigger', paidOpen, s => { s.history.firstTriggerHash = null }, 'first trigger')
  value('paid-open-missing-admission', paidOpen, s => { s.core.admissions = []; s.core.counts.admissions = 0 }, 'ownership')
  value('paid-open-zero-cost', paidOpen, s => { s.core.admissions[0].value.costUnits = 0n }, 'positive')
  value('paid-open-unknown-admission-field', paidOpen, s => { s.core.admissions[0].value.extra = 1 }, 'noncanonical object')
  value('paid-open-class-fork', paidOpen, s => { s.core.admissions[0].value.resourceClass = 2 }, 'OPEN admission')
  value('paid-open-logical-fork', paidOpen, s => { s.core.opens[0].value.logicalRetryKey = H(80) }, 'OPEN identity')
  value('paid-open-result-identity-fork', () => paidOpen(1), s => { s.identity.storeId = H(80) }, 'result identity')
  value('paid-open-incomplete-counts', paidOpen, s => { s.core.counts.opens = 0 }, 'count mismatch')
  value('proof-missing-original-admission', coreWithProof, s => { s.core.admissions.pop() }, 'ownership')
  value('proof-missing-source', coreWithProof, s => { s.core.proofs[0].source.revision = 9n }, 'source mismatch')
  value('proof-expiry-before-pin', coreWithProof, s => { s.core.proofs[0].expiresAtUnixMillis = 1n }, 'bounds/lifecycle')
  value('proof-wrong-band', coreWithProof, s => { s.core.admissions[1].value.resourceClass = 2 }, 'admission band')
  value('expired-proof-counted-live', () => coreWithProof(true), s => { s.core.counts.liveProofPins = 1 }, 'accounting')
  value('inactive-floor-without-expiry', coreWithProof, s => { s.core.floors[0].expiryWal = null }, 'expiry evidence')
  value('missing-durable-floor', coreWithProof, s => { s.core.floors = []; s.core.counts.floors = 0 }, 'latest floor')
  value('missing-activation', coreWithProof, s => { s.core.generations = [] }, 'activation evidence')
  value('candidate-not-activation-revision', coreWithProof, s => { s.core.mirrors[0].candidateRevision = 1n }, 'basis/revision')
  value('wrong-corpus-bucket', coreWithProof, s => { s.core.generations[0].corpus.virtualBucket ^= 1 }, 'bucket mismatch')
  value('activation-beyond-anchor', coreWithProof, s => { s.coveredWal.sequence = 2n }, 'checkpoint')
  const relation = (id, mutate, pattern, make = paidOpen) => {
    const previous = make(); const input = successor(previous); mutate(input, previous)
    cases.push({ id, mode: 'snapshot-successor', previous, input, pattern })
  }
  relation('regressed-history', s => { s.history.irreversible = 0 }, 'false history|history regressed')
  relation('retired-history-cleared', s => { s.history.irreversible = 0 }, 'history regressed', () => { const s = cell(); s.history.irreversible = 1; s.history.firstTriggerHash = H(13); return s })
  relation('first-trigger-replaced', s => { s.history.firstTriggerHash = H(80) }, 'history regressed')
  relation('history-record-fork', s => { s.history.authorityRecordHash = H(80) }, 'authority sequence fork')
  relation('foreign-installation', s => { s.identity.installationId = H(80) }, 'lineage mismatch')
  relation('foreign-role-root', s => { s.identity.rootId = H(80) }, 'lineage mismatch')
  relation('previous-snapshot-fork', s => { s.previousSnapshotHash = H(80) }, 'lineage mismatch')
  relation('wal-regression', s => { s.coveredWal.sequence = 300000n }, 'lineage mismatch')
  relation('descriptor-fork', s => { s.floors.descriptorHash = H(80) }, 'forked')
  relation('writer-fork', s => { s.writer.fenceHash = H(80) }, 'writer')
  relation('core-admissions-retired', s => { s.core.admissions = []; s.core.opens = []; Object.assign(s.core.counts, { admissions: 0, opens: 0, controlBytes: 0n }) }, 'retired')
  const participants = positives().find(([id]) => id === 'typed-four-participants')[2]
  const participant = (id, mutate, pattern) => { const input = clone(participants); mutate(input); cases.push({ id, mode: 'encode', type: 'Participants', input, pattern }) }
  participant('hc11-is-not-blind-wal', s => { s.hc11.wal = s.blind[0].wal }, 'exact fields')
  participant('hc11-invalid-activation-length', s => { s.hc11.length = 2n }, 'one-block')
  participant('hc11-invalid-fork', s => { s.hc11.fork = 1n }, 'one-block')
  participant('participants-root-collision', s => { s.hc11.rootId = s.blind[0].rootId }, 'collide')
  participant('participants-role-duplicate', s => { s.blind[1].role = 1 }, 'sorted and unique')
  participant('participants-trigger-missing', s => { s.firstTriggerHash = null }, 'first trigger')
  const next = clone(participants); next.revision++; next.previousAuthorityHash = participantHash(participants); next.hc11 = null
  cases.push({ id: 'hc11-participant-removed', mode: 'participants-successor', previous: participants, input: next, pattern: 'changed/removed' })
  const replay = positives().find(([id]) => id === 'bounded-large-head-empty-suffix')[2]
  for (const [id, mutate] of [['suffix-frame-budget', x => { x.observedFrames = 2 }], ['suffix-byte-budget', x => { x.observedBytes = 1025n }], ['suffix-anchor-fork', x => { x.head.hash = H(80) }]]) {
    const input = clone(replay); input.head = clone(input.head); mutate(input); cases.push({ id, mode: 'encode', type: 'ReplayBinding', input, pattern: 'bounds invalid' })
  }
  const bytes = encode('Snapshot', cell())
  cases.push({ id: 'trailing-bytes', mode: 'decode', type: 'Snapshot', input: b4a.concat([bytes, b4a.from([0])]), pattern: 'trailing' })
  cases.push({ id: 'truncated-snapshot', mode: 'decode', type: 'Snapshot', input: bytes.subarray(0, bytes.length - 1), pattern: 'truncated' })
  const overlong = encode('Participants', participants); const at = 82 // fixed header, present first trigger, before blind array
  // Derive the array marker location from fixed field widths, not a scan for a byte value.
  overlong[at] = 0xfd
  cases.push({ id: 'noncanonical-count', mode: 'decode', type: 'Participants', input: b4a.concat([overlong.subarray(0, at + 1), b4a.from([3, 0]), overlong.subarray(at + 1)]), pattern: 'non-canonical' })
  return cases
}
