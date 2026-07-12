import test from 'brittle'
import b4a from 'b4a'
import {
  CELL_RECEIPT_RESULT,
  INBOX_APPEND_AUTH_MODE,
  INBOX_MANAGE_OPERATION,
  INBOX_RECEIPT_RESULT,
  batchGetEntriesCommitment,
  batchGetResultV1,
  batchGetV1,
  blindReceiptV1,
  blake2b256,
  cellStorageSlot,
  decodeCanonical,
  dropCellV1,
  encodeCanonical,
  getCellResultV1,
  getCellV1,
  inboxAppendAckV1,
  inboxAppendV1,
  inboxCreateV1,
  inboxManageV1,
  inboxPhysicalTopic,
  inboxReadEntriesCommitment,
  inboxReadResultV1,
  inboxReadV1,
  inboxReceiptV1,
  inboxWatchV1,
  proveCellResultV1,
  proveCellV1,
  putCellV1,
  renewCellV1
} from '../index.js'

const KiB = 1024
const bytes = (length, value) => b4a.alloc(length, value)

function relayBinding (seed) {
  return {
    version: 1,
    relayPublicKey: bytes(32, seed),
    storeId: bytes(32, seed + 1),
    descriptorSequence: 1n,
    descriptorHash: bytes(32, seed + 2),
    durabilityProfileId: 1,
    durabilityContinuityHash: bytes(32, seed + 3),
    durabilityProfileHash: bytes(32, seed + 4),
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: bytes(32, 0),
    externalCommitWitness: null
  }
}

function admission (value = 0xa0) {
  return {
    profileId: 7,
    schemeId: 9,
    parameterHash: bytes(32, value),
    token: bytes(3, value + 1)
  }
}

function putCell (overrides = {}) {
  const allocationEpoch = 0x01020304
  const createPublicKey = bytes(32, 0x11)
  const cellBlob = bytes(4 * KiB, 0x51)
  return {
    version: 1,
    storageSlot: cellStorageSlot({ allocationEpoch, createPublicKey }),
    allocationEpoch,
    sizeClass: 1,
    leaseClass: 2,
    clientNonce: bytes(32, 0x12),
    createPublicKey,
    renewPublicKey: bytes(32, 0x13),
    dropPublicKey: bytes(32, 0x14),
    declaredBlobHash: blake2b256(cellBlob),
    createSignature: bytes(64, 0x15),
    admission: admission(),
    cellBlob,
    ...overrides
  }
}

function cellReceipt (overrides = {}) {
  return {
    version: 1,
    protocol: b4a.from('hiverelay-blind-cell-v1', 'ascii'),
    relayBinding: relayBinding(0x21),
    slotCommitment: bytes(32, 0x22),
    cellBlobHash: bytes(32, 0x23),
    allocationCommitment: bytes(32, 0x24),
    requestCommitment: bytes(32, 0x25),
    sizeClass: 1,
    allocationEpoch: 10,
    leaseClass: 2,
    leaseEpoch: 11,
    stateRevision: 12n,
    receiptEpoch: 13,
    requestNonce: bytes(32, 0x26),
    result: CELL_RECEIPT_RESULT.STORED,
    signature: bytes(64, 0x27),
    ...overrides
  }
}

function inboxCreate (overrides = {}) {
  const allocationEpoch = 0x05060708
  const createPublicKey = bytes(32, 0x31)
  return {
    version: 1,
    allocationEpoch,
    physicalTopic: inboxPhysicalTopic({ allocationEpoch, createPublicKey }),
    frameClassBits: 0x07,
    appendAuthMode: INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED,
    createPublicKey,
    appendPublicKey: bytes(32, 0x32),
    renewPublicKey: bytes(32, 0x33),
    closePublicKey: bytes(32, 0x34),
    retentionClass: 2,
    leaseClass: 3,
    clientNonce: bytes(32, 0x35),
    createSignature: bytes(64, 0x36),
    admission: admission(0xb0),
    ...overrides
  }
}

test('CELL codecs freeze exact class bytes and self-certifying PUT fields', t => {
  const put = putCell()
  const encoded = encodeCanonical(putCellV1, put)
  t.is(encoded.byteLength, 4399)
  const decoded = decodeCanonical(putCellV1, encoded)
  t.is(decoded.sizeClass, 1)
  t.alike(decoded.storageSlot, put.storageSlot)
  t.alike(decoded.cellBlob, put.cellBlob)

  t.exception(() => encodeCanonical(putCellV1, putCell({ cellBlob: bytes(4 * KiB - 1, 0x51) })), /exactly 4096 bytes/)
  t.exception(() => encodeCanonical(putCellV1, putCell({ storageSlot: bytes(32, 0xff) })), /not self-certifying/)
  t.exception(() => encodeCanonical(putCellV1, putCell({ declaredBlobHash: bytes(32, 0xff) })), /does not match cellBlob/)
  t.exception(() => encodeCanonical(putCellV1, putCell({ sizeClass: 0 })), /outside 1..5/)

  const largest = putCell({
    sizeClass: 5,
    cellBlob: bytes(1024 * KiB, 0x52),
    declaredBlobHash: blake2b256(bytes(1024 * KiB, 0x52))
  })
  t.is(encodeCanonical(putCellV1, largest).byteLength, 1024 * KiB + 303)
})

test('CELL management, reads and receipt relationships fail closed', t => {
  const slot = bytes(32, 0x41)
  const renew = {
    version: 1,
    storageSlot: slot,
    expectedRevision: 4n,
    expectedLeaseEpoch: 5,
    leaseClass: 1,
    clientNonce: bytes(32, 0x42),
    admission: admission(),
    signature: bytes(64, 0x43)
  }
  t.is(decodeCanonical(renewCellV1, encodeCanonical(renewCellV1, renew)).expectedRevision, 4n)
  t.exception(() => encodeCanonical(renewCellV1, { ...renew, leaseClass: 0 }), /outside 1..4/)

  const drop = {
    version: 1,
    storageSlot: slot,
    expectedRevision: 6n,
    expectedLeaseEpoch: 7,
    clientNonce: bytes(32, 0x44),
    signature: bytes(64, 0x45)
  }
  t.is(decodeCanonical(dropCellV1, encodeCanonical(dropCellV1, drop)).expectedLeaseEpoch, 7)

  for (const codec of [getCellV1, proveCellV1]) {
    const value = { version: 1, storageSlot: slot, clientNonce: bytes(32, 0x46), admission: null }
    t.is(encodeCanonical(codec, value).byteLength, 66)
    t.is(decodeCanonical(codec, encodeCanonical(codec, { ...value, admission: admission() })).admission.profileId, 7)
  }

  const receipt = cellReceipt()
  const encodedReceipt = encodeCanonical(blindReceiptV1, receipt)
  t.alike(decodeCanonical(blindReceiptV1, encodedReceipt).protocol, receipt.protocol)
  t.exception(() => encodeCanonical(blindReceiptV1, { ...receipt, protocol: b4a.from('wrong', 'ascii') }), /fixed value/)
  t.exception(() => encodeCanonical(blindReceiptV1, { ...receipt, leaseClass: 0 }), /requires a lease/)
  t.is(encodeCanonical(blindReceiptV1, cellReceipt({
    result: CELL_RECEIPT_RESULT.DROPPED,
    leaseClass: 0
  })).byteLength, encodedReceipt.byteLength)
  t.exception(() => encodeCanonical(blindReceiptV1, cellReceipt({
    result: CELL_RECEIPT_RESULT.DROPPED,
    leaseClass: 1
  })), /lease NONE/)
})

test('CELL result unions preserve request order and commit exact canonical entries', t => {
  const blob = bytes(4 * KiB, 0x61)
  const getResult = { version: 1, sizeClass: 1, cellBlob: blob }
  const encodedGet = encodeCanonical(getCellResultV1, getResult)
  t.is(encodedGet.byteLength, 4098)
  t.alike(decodeCanonical(getCellResultV1, encodedGet).cellBlob, blob)
  const badClass = b4a.from(encodedGet)
  badClass[1] = 0
  t.exception(() => decodeCanonical(getCellResultV1, badClass), /outside 1..5/)

  const receipt = cellReceipt({
    cellBlobHash: blake2b256(blob),
    result: CELL_RECEIPT_RESULT.SERVED
  })
  const proof = { version: 1, receipt, sizeClass: 1, cellBlob: blob }
  t.is(decodeCanonical(proveCellResultV1, encodeCanonical(proveCellResultV1, proof)).sizeClass, 1)
  t.exception(() => encodeCanonical(proveCellResultV1, {
    ...proof,
    receipt: cellReceipt({ cellBlobHash: blake2b256(blob), result: CELL_RECEIPT_RESULT.STORED })
  }), /must be SERVED/)
  t.exception(() => encodeCanonical(proveCellResultV1, { ...proof, cellBlob: bytes(4 * KiB, 0x62) }), /receipt hash/)
  t.exception(() => encodeCanonical(proveCellResultV1, { ...proof, sizeClass: 2 }), /exactly 16384 bytes/)

  const slots = [bytes(32, 0x01), bytes(32, 0x02)]
  const request = { version: 1, clientNonce: bytes(32, 0x63), slots, admission: null }
  t.alike(decodeCanonical(batchGetV1, encodeCanonical(batchGetV1, request)).slots, slots)
  t.exception(() => encodeCanonical(batchGetV1, { ...request, slots: [slots[0], slots[0]] }), /duplicate/)
  t.exception(() => encodeCanonical(batchGetV1, { ...request, slots: [] }), /outside 1..64/)

  const entries = [{ status: 0 }, { status: 1, sizeClass: 1, cellBlob: blob }]
  const result = {
    version: 1,
    relayBinding: relayBinding(0x64),
    requestNonce: request.clientNonce,
    requestCommitment: bytes(32, 0x65),
    entries,
    entriesCommitment: batchGetEntriesCommitment(entries),
    signature: bytes(64, 0x66)
  }
  const encoded = encodeCanonical(batchGetResultV1, result)
  const decoded = decodeCanonical(batchGetResultV1, encoded)
  t.is(decoded.entries[0].status, 0)
  t.is(decoded.entries[1].status, 1)
  t.alike(decoded.entries[1].cellBlob, blob)
  t.exception(() => encodeCanonical(batchGetResultV1, { ...result, entriesCommitment: bytes(32, 0) }), /does not match entries/)
  t.exception(() => encodeCanonical(batchGetResultV1, { ...result, entries: [] }), /outside 1..64/)
  const largestBlob = bytes(64 * KiB, 0x67)
  const oversizedEntries = Array.from({ length: 64 }, () => ({
    status: 1,
    sizeClass: 3,
    cellBlob: largestBlob
  }))
  t.exception(() => encodeCanonical(batchGetResultV1, {
    ...result,
    entries: oversizedEntries,
    entriesCommitment: batchGetEntriesCommitment(oversizedEntries)
  }), /exceeds its operation cap/)
  const badTag = b4a.from(encoded)
  badTag[277] = 2
  t.exception(() => decodeCanonical(batchGetResultV1, badTag), /status must be 0 or 1/)
})

test('INBOX create and management codecs enforce authorization shape', t => {
  const create = inboxCreate()
  const encoded = encodeCanonical(inboxCreateV1, create)
  t.alike(decodeCanonical(inboxCreateV1, encoded).physicalTopic, create.physicalTopic)
  t.exception(() => encodeCanonical(inboxCreateV1, inboxCreate({ physicalTopic: bytes(32, 0) })), /not self-certifying/)
  t.exception(() => encodeCanonical(inboxCreateV1, inboxCreate({ frameClassBits: 0x10 })), /advertised inbox classes/)
  t.exception(() => encodeCanonical(inboxCreateV1, inboxCreate({ appendPublicKey: null })), /does not match appendAuthMode/)

  const open = inboxCreate({
    appendAuthMode: INBOX_APPEND_AUTH_MODE.OPEN_CAPABILITY,
    appendPublicKey: null
  })
  t.is(decodeCanonical(inboxCreateV1, encodeCanonical(inboxCreateV1, open)).appendPublicKey, null)

  const manage = {
    version: 1,
    operation: INBOX_MANAGE_OPERATION.RENEW,
    physicalTopic: create.physicalTopic,
    expectedRevision: 7n,
    expectedLeaseEpoch: 8,
    leaseClass: 2,
    clientNonce: bytes(32, 0x71),
    signature: bytes(64, 0x72),
    admission: admission()
  }
  t.is(decodeCanonical(inboxManageV1, encodeCanonical(inboxManageV1, manage)).operation, INBOX_MANAGE_OPERATION.RENEW)
  t.exception(() => encodeCanonical(inboxManageV1, { ...manage, admission: null }), /renew requires lease and admission/)
  const close = { ...manage, operation: INBOX_MANAGE_OPERATION.CLOSE, leaseClass: 0, admission: null }
  t.is(decodeCanonical(inboxManageV1, encodeCanonical(inboxManageV1, close)).leaseClass, 0)
  t.exception(() => encodeCanonical(inboxManageV1, { ...close, leaseClass: 1 }), /close requires lease NONE/)
})

test('INBOX append/read/watch codecs enforce exact frames and cursor bounds', t => {
  const physicalTopic = bytes(32, 0x81)
  const frame = bytes(4 * KiB, 0x82)
  const append = {
    version: 1,
    physicalTopic,
    frameClass: 1,
    frameHash: blake2b256(frame),
    clientNonce: bytes(32, 0x83),
    appendSignature: bytes(64, 0x84),
    admission: admission(),
    frame
  }
  const encoded = encodeCanonical(inboxAppendV1, append)
  t.alike(decodeCanonical(inboxAppendV1, encoded).frame, frame)
  t.exception(() => encodeCanonical(inboxAppendV1, { ...append, frame: frame.subarray(1) }), /exactly 4096 bytes/)
  t.exception(() => encodeCanonical(inboxAppendV1, { ...append, frameHash: bytes(32, 0) }), /does not match frame/)

  const read = {
    version: 1,
    physicalTopic,
    cursor: bytes(128, 0x85),
    limit: 64,
    clientNonce: bytes(32, 0x86),
    admission: null
  }
  t.is(decodeCanonical(inboxReadV1, encodeCanonical(inboxReadV1, read)).cursor.byteLength, 128)
  t.exception(() => encodeCanonical(inboxReadV1, { ...read, cursor: bytes(129, 0) }), /outside 0..128/)
  t.exception(() => encodeCanonical(inboxReadV1, { ...read, limit: 65 }), /outside 1..64/)

  const watch = {
    version: 1,
    physicalTopic,
    afterRevision: 9n,
    limit: 1,
    maxWaitMillis: 30000,
    clientNonce: bytes(32, 0x87),
    admission: admission()
  }
  t.is(decodeCanonical(inboxWatchV1, encodeCanonical(inboxWatchV1, watch)).maxWaitMillis, 30000)
  t.exception(() => encodeCanonical(inboxWatchV1, { ...watch, maxWaitMillis: 0 }), /outside 1..30000/)
  t.exception(() => encodeCanonical(inboxWatchV1, { ...watch, maxWaitMillis: 30001 }), /outside 1..30000/)
})

test('INBOX signed results freeze result tags, ordering and commitments', t => {
  const receipt = {
    version: 1,
    relayBinding: relayBinding(0x91),
    topicCommitment: bytes(32, 0x92),
    stateRevision: 10n,
    leaseClass: 2,
    leaseEpoch: 11,
    requestNonce: bytes(32, 0x93),
    requestCommitment: bytes(32, 0x94),
    result: INBOX_RECEIPT_RESULT.CREATED,
    signature: bytes(64, 0x95)
  }
  t.is(decodeCanonical(inboxReceiptV1, encodeCanonical(inboxReceiptV1, receipt)).result, 1)
  t.exception(() => encodeCanonical(inboxReceiptV1, { ...receipt, leaseClass: 0 }), /requires a lease/)
  t.is(encodeCanonical(inboxReceiptV1, {
    ...receipt,
    result: INBOX_RECEIPT_RESULT.CLOSED,
    leaseClass: 0
  }).byteLength, encodeCanonical(inboxReceiptV1, receipt).byteLength)

  const ack = {
    version: 1,
    relayBinding: relayBinding(0x96),
    topicCommitment: bytes(32, 0x97),
    frameHash: bytes(32, 0x98),
    appendRevision: 12n,
    storedAtEpoch: 13,
    expiresAtEpoch: 14,
    requestNonce: bytes(32, 0x99),
    requestCommitment: bytes(32, 0x9a),
    result: 1,
    signature: bytes(64, 0x9b)
  }
  t.is(decodeCanonical(inboxAppendAckV1, encodeCanonical(inboxAppendAckV1, ack)).result, 1)
  t.exception(() => encodeCanonical(inboxAppendAckV1, { ...ack, result: 2 }), /must be 1/)
  t.exception(() => encodeCanonical(inboxAppendAckV1, { ...ack, expiresAtEpoch: 13 }), /must be after/)

  const frameA = bytes(4 * KiB, 0xa1)
  const frameB = bytes(4 * KiB, 0xa2)
  const entries = [
    { appendRevision: 2n, frameHash: blake2b256(frameA), frameClass: 1, frame: frameA },
    { appendRevision: 3n, frameHash: blake2b256(frameB), frameClass: 1, frame: frameB }
  ]
  const result = {
    version: 1,
    relayBinding: relayBinding(0xa3),
    requestNonce: bytes(32, 0xa4),
    requestCommitment: bytes(32, 0xa5),
    snapshotRevision: 3n,
    entries,
    entriesCommitment: inboxReadEntriesCommitment(entries),
    nextCursor: bytes(128, 0xa6),
    signature: bytes(64, 0xa7)
  }
  const encoded = encodeCanonical(inboxReadResultV1, result)
  t.is(decodeCanonical(inboxReadResultV1, encoded).entries[1].appendRevision, 3n)
  t.exception(() => encodeCanonical(inboxReadResultV1, {
    ...result,
    entries: [entries[1], entries[0]],
    entriesCommitment: inboxReadEntriesCommitment([entries[1], entries[0]])
  }), /strictly increasing/)
  t.exception(() => encodeCanonical(inboxReadResultV1, {
    ...result,
    snapshotRevision: 2n
  }), /exceeds snapshotRevision/)
  t.exception(() => encodeCanonical(inboxReadResultV1, { ...result, entriesCommitment: bytes(32, 0) }), /does not match entries/)
  t.exception(() => encodeCanonical(inboxReadResultV1, { ...result, nextCursor: bytes(129, 0) }), /outside 0..128/)
  const largestFrame = bytes(64 * KiB, 0xa8)
  const oversizedEntries = Array.from({ length: 64 }, (_, index) => ({
    appendRevision: BigInt(index + 1),
    frameHash: blake2b256(largestFrame),
    frameClass: 3,
    frame: largestFrame
  }))
  t.exception(() => encodeCanonical(inboxReadResultV1, {
    ...result,
    snapshotRevision: 64n,
    entries: oversizedEntries,
    entriesCommitment: inboxReadEntriesCommitment(oversizedEntries),
    nextCursor: null
  }), /exceeds its operation cap/)
  const badFrame = { ...entries[0], frameHash: bytes(32, 0) }
  t.exception(() => inboxReadEntriesCommitment([badFrame]), /does not match frame/)

  const empty = { ...result, entries: [], entriesCommitment: inboxReadEntriesCommitment([]), nextCursor: null }
  t.is(decodeCanonical(inboxReadResultV1, encodeCanonical(inboxReadResultV1, empty)).entries.length, 0)
})
