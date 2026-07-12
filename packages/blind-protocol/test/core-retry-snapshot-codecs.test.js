import b4a from 'b4a'
import test from 'brittle'
import {
  CORE_SESSION_CLASS,
  blindCoreControlGlobalSnapshotV1,
  blindCoreOpenReplicationRetrySnapshotV1,
  decodeCanonical,
  encodeCanonical
} from '../index.js'

function bytes (length, fill) {
  return b4a.alloc(length, fill)
}

function terminalRecord (overrides = {}) {
  const limits = CORE_SESSION_CLASS[1]
  return {
    version: 1,
    lifecycleState: 3,
    logicalRetryKey: bytes(32, 1),
    spendTag: bytes(16, 2),
    requestCommitment: bytes(32, 3),
    wireProfileHash: bytes(32, 4),
    sessionClass: 1,
    clientNonce: bytes(32, 5),
    parentSessionId: bytes(16, 6),
    controlChannelId: 7n,
    parentChannelBinding: bytes(32, 8),
    streamId: 9n,
    maxSessionBytes: BigInt(limits.maxSessionBytes),
    idleMillis: limits.idleMillis,
    lifetimeMillis: limits.lifetimeMillis,
    openedAtEpoch: 10,
    recordVirtualBucket: 11,
    resultBytes: null,
    terminalReason: b4a.from('core-open-failed', 'ascii'),
    ...overrides
  }
}

test('Core retry snapshot codecs freeze lifecycle/result presence and exact class limits', t => {
  const value = terminalRecord()
  const encoded = encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, value)
  t.alike(decodeCanonical(blindCoreOpenReplicationRetrySnapshotV1, encoded, { copyBytes: true }), value)
  t.exception(() => encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1,
    terminalRecord({ lifecycleState: 2 })), /terminalReason presence/)
  t.exception(() => encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1,
    terminalRecord({ lifecycleState: 2, terminalReason: null })), /require their signed result/)
  t.exception(() => encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1,
    terminalRecord({ maxSessionBytes: 1n })), /limits do not match/)
  t.exception(() => encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1,
    terminalRecord({ terminalReason: b4a.from('bad\nreason') })), /printable ASCII/)
  t.exception(() => encodeCanonical(blindCoreOpenReplicationRetrySnapshotV1,
    terminalRecord({ parentSessionId: bytes(16, 0) })), /parentSessionId must be nonzero/)
})

test('Core retry global snapshot canonically carries exact state/index accounting', t => {
  const value = {
    version: 1,
    epochFloor: 100,
    clockUnsafe: 1,
    recordCount: 3n,
    reservedCount: 1n,
    liveCount: 1n,
    terminalCount: 1n,
    spendIndexCount: 3n,
    logicalIndexCount: 3n,
    channelIndexCount: 3n,
    resultCount: 2n,
    snapshotRecordBytes: 1024n
  }
  const encoded = encodeCanonical(blindCoreControlGlobalSnapshotV1, value)
  t.alike(decodeCanonical(blindCoreControlGlobalSnapshotV1, encoded), value)
  t.exception(() => encodeCanonical(blindCoreControlGlobalSnapshotV1, {
    ...value,
    clockUnsafe: 2
  }), /boolean/)
})
