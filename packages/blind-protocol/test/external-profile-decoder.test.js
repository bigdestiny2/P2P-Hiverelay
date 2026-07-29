import test from 'brittle'
import b4a from 'b4a'
import * as externalDecoderAuthority from '../external-profile-decoder.js'
import {
  blindCoreReadCapV1,
  readCellCapV1
} from '../client-composition-external-codecs.js'
import { encodeCanonical } from '../codec.js'
import {
  blindCoreAckV1,
  blindReceiptV1,
  inboxAppendAckV1,
  inboxReceiptV1
} from '../schemas.js'

const { decodeBlindExternalProfileValueV1 } = externalDecoderAuthority
const bytes = (length, value) => b4a.alloc(length, value)

function throwsBadEncoding (t, operation, message) {
  try {
    operation()
    t.fail(message)
  } catch (error) {
    t.is(error.code, 'BAD_ENCODING', message)
  }
}

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

function fixtureBytes () {
  const coreAck = {
    version: 1,
    relayBinding: relayBinding(0x11),
    corePublicKey: bytes(32, 0x16),
    fork: 2n,
    length: 16n,
    signedHeadHash: bytes(32, 0x17),
    observedAtEpoch: 100,
    leaseEpoch: 104,
    result: 2,
    requestNonce: bytes(32, 0x18),
    requestCommitment: bytes(32, 0x19),
    signature: bytes(64, 0x1a)
  }
  const coreReadCap = {
    version: 1,
    corePublicKey: bytes(32, 0x21),
    blockEncryptionKey: bytes(32, 0x22),
    witnessedFork: 3n,
    witnessedLength: 9n,
    witnessedSignedHead: bytes(8, 0x23)
  }
  const cellReceipt = {
    version: 1,
    protocol: b4a.from('hiverelay-blind-cell-v1', 'ascii'),
    relayBinding: relayBinding(0x31),
    slotCommitment: bytes(32, 0x36),
    cellBlobHash: bytes(32, 0x37),
    allocationCommitment: bytes(32, 0x38),
    requestCommitment: bytes(32, 0x39),
    sizeClass: 1,
    allocationEpoch: 10,
    leaseClass: 2,
    leaseEpoch: 11,
    stateRevision: 12n,
    receiptEpoch: 13,
    requestNonce: bytes(32, 0x3a),
    result: 1,
    signature: bytes(64, 0x3b)
  }
  const appendAck = {
    version: 1,
    relayBinding: relayBinding(0x41),
    topicCommitment: bytes(32, 0x46),
    frameHash: bytes(32, 0x47),
    appendRevision: 12n,
    storedAtEpoch: 13,
    expiresAtEpoch: 14,
    requestNonce: bytes(32, 0x48),
    requestCommitment: bytes(32, 0x49),
    result: 1,
    signature: bytes(64, 0x4a)
  }
  const inboxReceipt = {
    version: 1,
    relayBinding: relayBinding(0x51),
    topicCommitment: bytes(32, 0x56),
    stateRevision: 10n,
    leaseClass: 2,
    leaseEpoch: 11,
    requestNonce: bytes(32, 0x57),
    requestCommitment: bytes(32, 0x58),
    result: 1,
    signature: bytes(64, 0x59)
  }
  const readCellCap = {
    version: 1,
    relayPublicKey: bytes(32, 0x61),
    storageSlot: bytes(32, 0x62),
    cellKey: bytes(32, 0x63),
    sizeClass: 1,
    expectedCellBlobHash: bytes(32, 0x64)
  }
  return new Map([
    ['BlindCoreAckV1', encodeCanonical(blindCoreAckV1, coreAck)],
    ['BlindCoreReadCapV1', encodeCanonical(blindCoreReadCapV1, coreReadCap)],
    ['BlindReceiptV1', encodeCanonical(blindReceiptV1, cellReceipt)],
    ['InboxAppendAckV1', encodeCanonical(inboxAppendAckV1, appendAck)],
    ['InboxReceiptV1', encodeCanonical(inboxReceiptV1, inboxReceipt)],
    ['ReadCellCapV1', encodeCanonical(readCellCapV1, readCellCap)]
  ])
}

test('external-profile decoder exposes one closed six-type executable authority', t => {
  t.alike(Object.keys(externalDecoderAuthority), ['decodeBlindExternalProfileValueV1'])
  const fixtures = fixtureBytes()
  t.alike([...fixtures.keys()], [
    'BlindCoreAckV1',
    'BlindCoreReadCapV1',
    'BlindReceiptV1',
    'InboxAppendAckV1',
    'InboxReceiptV1',
    'ReadCellCapV1'
  ])
  for (const [name, encoded] of fixtures) {
    const decoded = decodeBlindExternalProfileValueV1(name, encoded)
    t.ok(Object.isFrozen(decoded), `${name} result container is frozen`)
    if (decoded.relayBinding != null) {
      t.ok(Object.isFrozen(decoded.relayBinding), `${name} nested result container is frozen`)
    }
  }

  for (const name of [
    '', 'BlindHealthResultV1', 'WriteCellCapV1', 'CellBlobV1',
    'BlindStoreManifestV1', '__proto__'
  ]) {
    throwsBadEncoding(t, () => decodeBlindExternalProfileValueV1(
      name, fixtures.get('ReadCellCapV1')), `unknown ${name || '<empty>'} is rejected`)
  }
  throwsBadEncoding(t, () => decodeBlindExternalProfileValueV1(
    { name: 'ReadCellCapV1', codec: readCellCapV1 }, fixtures.get('ReadCellCapV1')),
  'raw schema injection is rejected')
  throwsBadEncoding(t, () => decodeBlindExternalProfileValueV1(
    'ReadCellCapV1', fixtures.get('ReadCellCapV1'), () => true),
  'callback injection is rejected')

  const originalMapGet = Map.prototype.get
  const canonicalReadCap = fixtures.get('ReadCellCapV1')
  let mapSelectionCalls = 0
  try {
    Reflect.set(Map.prototype, 'get', function () {
      mapSelectionCalls++
      return { codec: readCellCapV1, minimum: 0, maximum: Number.MAX_SAFE_INTEGER }
    })
    t.is(decodeBlindExternalProfileValueV1(
      'ReadCellCapV1', canonicalReadCap).sizeClass, 1,
    'global Map prototype mutation cannot replace the closed selector')
  } finally {
    Reflect.set(Map.prototype, 'get', originalMapGet)
  }
  t.is(mapSelectionCalls, 0, 'closed selection does not dispatch through a mutable registry primitive')
})

test('external-profile decoder rejects truncation, trailing, oversize, noncanonical and wrong-type bytes', t => {
  const fixtures = fixtureBytes()
  const maximums = new Map([
    ['BlindCoreAckV1', 16384],
    ['BlindCoreReadCapV1', 8192],
    ['BlindReceiptV1', 16384],
    ['InboxAppendAckV1', 16384],
    ['InboxReceiptV1', 16384],
    ['ReadCellCapV1', 131]
  ])
  for (const [name, encoded] of fixtures) {
    throwsBadEncoding(t, () => decodeBlindExternalProfileValueV1(
      name, encoded.subarray(0, encoded.byteLength - 1)), `${name} truncation is rejected`)
    throwsBadEncoding(t, () => decodeBlindExternalProfileValueV1(
      name, b4a.concat([encoded, b4a.from([0])])), `${name} trailing byte is rejected`)
    throwsBadEncoding(t, () => decodeBlindExternalProfileValueV1(
      name, bytes(maximums.get(name) + 1, 1)), `${name} oversize input is rejected before decode`)
  }

  const coreCap = fixtures.get('BlindCoreReadCapV1')
  const compactLengthOffset = 1 + 32 + 32 + 8 + 8
  t.is(coreCap[compactLengthOffset], 8, 'fixture uses the canonical single-byte compact length')
  const noncanonical = b4a.concat([
    coreCap.subarray(0, compactLengthOffset),
    b4a.from([0xfd, 8, 0]),
    coreCap.subarray(compactLengthOffset + 1)
  ])
  throwsBadEncoding(t, () => decodeBlindExternalProfileValueV1(
    'BlindCoreReadCapV1', noncanonical), 'overlong compact length is rejected')

  for (const [actualName, encoded] of fixtures) {
    for (const expectedName of fixtures.keys()) {
      if (actualName === expectedName) continue
      throwsBadEncoding(t, () => decodeBlindExternalProfileValueV1(
        expectedName, encoded), `${actualName} bytes cannot decode as ${expectedName}`)
    }
  }
})

test('external-profile decoded values have no input or cross-call byte aliases', t => {
  const fixtures = fixtureBytes()
  const source = fixtures.get('BlindReceiptV1')
  const input = b4a.from(source)
  const decoded = decodeBlindExternalProfileValueV1('BlindReceiptV1', input)
  const relayKey = b4a.from(decoded.relayBinding.relayPublicKey)
  input.fill(0)
  t.ok(b4a.equals(decoded.relayBinding.relayPublicKey, relayKey),
    'mutating the caller input cannot mutate the decoded result')

  decoded.relayBinding.relayPublicKey.fill(0)
  const second = decodeBlindExternalProfileValueV1('BlindReceiptV1', source)
  t.ok(b4a.equals(second.relayBinding.relayPublicKey, relayKey),
    'mutating one returned byte copy cannot poison the authority or another call')

  const cap = fixtures.get('ReadCellCapV1')
  const offset = 7
  const view = new Uint8Array(cap.buffer, cap.byteOffset + offset, cap.byteLength - offset)
  const padded = b4a.alloc(cap.byteLength + offset, 0xee)
  padded.set(cap, offset)
  const dataView = new DataView(padded.buffer, padded.byteOffset + offset, cap.byteLength)
  t.is(decodeBlindExternalProfileValueV1('ReadCellCapV1', dataView).sizeClass, 1,
    'an offset ArrayBuffer view is copied and decoded exactly')
  t.is(view.byteLength, cap.byteLength - offset, 'fixture subview remains independent')

  if (typeof SharedArrayBuffer !== 'undefined') {
    const shared = new Uint8Array(new SharedArrayBuffer(cap.byteLength))
    shared.set(cap)
    throwsBadEncoding(t, () => decodeBlindExternalProfileValueV1(
      'ReadCellCapV1', shared), 'shared-memory input is rejected')
  }
})
