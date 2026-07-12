import {
  boundedBytes,
  constant,
  fixedBytes,
  optional,
  ranged,
  struct,
  u8,
  u64be
} from './codec.js'
import { protocolError } from './errors.js'

const bytes32 = fixedBytes(32)
const version1 = constant(u8, 1, 'version')

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function nonzero (value, field) {
  for (const byte of value) {
    if (byte !== 0) return
  }
  fail(`${field} must be nonzero`)
}

// These two codecs are a deliberately narrow executable leaf shared by the
// final client-composition authority and the browser external-profile decoder.
// Keep the remaining client-only schemas out of the public browser graph.
export const readCellCapV1 = struct([
  ['version', version1],
  ['relayPublicKey', bytes32],
  ['storageSlot', bytes32],
  ['cellKey', bytes32],
  ['sizeClass', ranged(u8, 1, 5, 'sizeClass')],
  ['expectedCellBlobHash', optional(bytes32, 'expectedCellBlobHash')]
], {
  name: 'ReadCellCapV1',
  validate (value) {
    for (const field of ['relayPublicKey', 'storageSlot', 'cellKey']) nonzero(value[field], field)
    if (value.expectedCellBlobHash != null) nonzero(value.expectedCellBlobHash, 'expectedCellBlobHash')
  }
})

export const blindCoreReadCapV1 = struct([
  ['version', version1],
  ['corePublicKey', bytes32],
  ['blockEncryptionKey', bytes32],
  ['witnessedFork', u64be],
  ['witnessedLength', u64be],
  ['witnessedSignedHead', boundedBytes(1, 4096, 'witnessedSignedHead')]
], {
  name: 'BlindCoreReadCapV1',
  validate (value) {
    nonzero(value.corePublicKey, 'corePublicKey')
    nonzero(value.blockEncryptionKey, 'blockEncryptionKey')
  }
})
