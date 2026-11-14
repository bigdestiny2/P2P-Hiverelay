// Bounded ordinary retained-history regression, not a deployment-capacity claim.
import assert from 'node:assert/strict'
import { performance } from 'node:perf_hooks'
import { coreMirrorRequestCommitment, coreServeRequestCommitment, coreOpenReplicationRequestCommitment } from '../hashes.js'
import { encode, assertSnapshotSuccessor, coreBucket, openLogicalKey } from './codec.js'
import { coreWithProof, paidOpen, base, emptyCore, clone, wal, H, successor } from './fixtures.js'

function key (domain, n) { const bytes = Buffer.alloc(32, domain); bytes.writeUInt32BE(n, 28); return bytes }
function retainedHistory (count) {
  const s = { ...base(3), core: emptyCore() }; const c = s.core
  s.history.irreversible = 1; s.history.firstTriggerHash = H(13)
  const template = coreWithProof(true).core; const open = paidOpen().core
  for (let i = 0; i < count; i++) {
    const m = clone(template.mirrors[0]); const g = clone(template.generations[0]); const p = clone(template.proofs[0])
    const a = clone(template.admissions[0]); const proofAdmission = clone(template.admissions[1])
    m.spendTag = key(20, i); m.request.length = BigInt(i + 1); m.request.clientNonce = key(32, i); m.request.signedHeadHash = key(31, i)
    m.result.length = m.request.length; m.result.signedHeadHash = m.request.signedHeadHash; m.result.requestNonce = m.request.clientNonce
    m.result.requestCommitment = coreMirrorRequestCommitment({ ...m.request, relayPublicKey: s.identity.relayPublicKey })
    m.acceptanceWal = wal(4 * i + 1); m.lifecycleWal = wal(4 * i + 2); m.candidateRevision = BigInt(i)
    if (i) { const prior = c.generations[i - 1]; m.acceptanceBasis = { fork: prior.fork, length: prior.length, signedHeadHash: prior.signedHeadHash, leaseEpoch: prior.leaseEpoch, stateRevision: prior.key.revision, originWal: prior.activationWal } }
    g.key.revision = BigInt(i); g.mirrorSpendTag = m.spendTag; g.length = m.request.length; g.signedHeadHash = m.request.signedHeadHash
    g.activationWal = m.lifecycleWal; g.activationBasis = i ? c.generations[i - 1].key : null; g.corpus.objectId = key(33, i)
    a.value.spendTag = m.spendTag; a.value.requestCommitment = m.result.requestCommitment
    p.spendTag = key(21, i); p.source = g.key; p.pinWal = wal(4 * i + 3); p.expiryWal = wal(4 * i + 4)
    p.request.length = g.length; p.request.signedHeadHash = g.signedHeadHash; p.request.clientNonce = key(35, i)
    Object.assign(p.acknowledgement, { length: g.length, signedHeadHash: g.signedHeadHash, requestNonce: p.request.clientNonce, requestCommitment: coreServeRequestCommitment({ ...p.request, relayPublicKey: s.identity.relayPublicKey }) })
    proofAdmission.value.spendTag = p.spendTag; proofAdmission.value.requestCommitment = p.acknowledgement.requestCommitment
    const o = clone(open.opens[0]); const oa = clone(open.admissions[0])
    Object.assign(o.value, { spendTag: key(22, i), streamId: BigInt(i + 1), controlChannelId: BigInt(i + 1), clientNonce: key(17, i) })
    o.value.logicalRetryKey = openLogicalKey(s.identity.relayPublicKey, o.value); o.value.recordVirtualBucket = coreBucket(o.value.logicalRetryKey)
    o.value.requestCommitment = coreOpenReplicationRequestCommitment({ ...o.value, relayPublicKey: s.identity.relayPublicKey })
    oa.value.spendTag = o.value.spendTag; oa.value.requestCommitment = o.value.requestCommitment
    c.admissions.push(a, proofAdmission, oa); c.mirrors.push(m); c.generations.push(g); c.proofs.push(p); c.opens.push(o)
  }
  c.admissions.sort((a, b) => Buffer.compare(a.value.spendTag, b.value.spendTag)); c.opens.sort((a, b) => Buffer.compare(a.value.logicalRetryKey, b.value.logicalRetryKey))
  c.floors = [{ key: c.generations[count - 1].key, active: 1, expiredAtEpoch: null, expiryWal: null }]
  Object.assign(c.counts, { admissions: 3 * count, mirrors: count, generations: count, floors: 1, proofs: count, opens: count, activeCores: 1, liveCorpusBytes: 100n, controlBytes: 1024n * BigInt(count), tombstoneBytes: 256n * BigInt(count) })
  return s
}

const observations = []
for (const count of [128, 512, 2048]) {
  const previous = retainedHistory(count); const next = successor(previous)
  // These arrays must be joined by canonical key indexes. A return to per-record
  // some/find searches fails deterministically even on a fast machine.
  for (const s of [previous, next]) {
    for (const group of ['generations', 'proofs', 'opens']) {
      for (const method of ['some', 'find']) Object.defineProperty(s.core[group], method, { value () { throw new Error(`unindexed ${group}.${method} history search`) } })
    }
  }
  const start = performance.now(); const bytes = encode('Snapshot', previous).byteLength
  assert.equal(assertSnapshotSuccessor(previous, next), true)
  observations.push({ retainedPerGroup: count, groups: previous.core.counts, encodedBytes: bytes, encodeAndSuccessorMillis: Number((performance.now() - start).toFixed(3)), unindexedHistorySearches: 0 })
}
console.log(JSON.stringify({ pass: true, runtime: process.version, platform: process.platform, arch: process.arch, observations, scope: 'finite synthetic valid retained histories; fixed 2048-group ceiling for this ordinary regression, not production capacity or a store benchmark' }, (k, v) => typeof v === 'bigint' ? v.toString() : v))
