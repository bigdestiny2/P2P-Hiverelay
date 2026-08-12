import b4a from 'b4a'
import {
  CELL_SIZE_CLASS,
  FAMILY,
  OPERATION
} from '../../blind-protocol/wire-runtime-authority.js'
import { cellGetRequestCommitment } from '../../blind-protocol/hashes.js'
import { getCellResultV1 } from '../../blind-protocol/schemas.js'
import { asBytes } from '../../blind-client/bytes.js'
import { openCell } from '../../blind-client/cells.js'
import { fail } from '../../blind-client/errors.js'
import {
  decodeCanonicalCopy,
  sameBytes
} from '../../blind-client/signed.js'
import { verifiedEndpointContext } from '../../blind-client/verified-endpoint.js'

const VERIFIED_CELL_GET_RESULT = Symbol('VerifiedCellGetResult')
const resultInternals = new WeakMap()

class VerifiedCellGetResult {
  constructor (token, fields) {
    if (token !== VERIFIED_CELL_GET_RESULT) {
      throw new TypeError('VerifiedCellGetResult is not directly constructible')
    }
    resultInternals.set(this, fields)
    Object.freeze(this)
  }
}

export function verifyCellGetResult (options) {
  if (!options || typeof options !== 'object') {
    fail('BAD_CLIENT_INPUT', 'CELL.GET result verification options are required')
  }
  const context = verifiedEndpointContext(options.endpoint)
  if (context.familyId !== FAMILY.CELL || context.operationId !== OPERATION.CELL.GET) {
    fail('BAD_CLIENT_INPUT', 'qualified endpoint is not CELL.GET')
  }
  const request = options.request
  if (!request || typeof request !== 'object') {
    fail('BAD_CLIENT_INPUT', 'CELL.GET request is required')
  }
  const storageSlot = b4a.from(asBytes(request.storageSlot, 'CELL.GET request storageSlot', 32))
  const clientNonce = b4a.from(asBytes(request.clientNonce, 'CELL.GET request clientNonce', 32))
  const requestCommitment = b4a.from(asBytes(options.requestCommitment, 'requestCommitment', 32))
  const recomputed = cellGetRequestCommitment({
    relayPublicKey: context.relayPublicKey,
    storageSlot,
    clientNonce
  })
  if (!sameBytes(requestCommitment, recomputed)) {
    fail('BAD_CLIENT_INPUT', 'requestCommitment does not match the canonical CELL.GET request')
  }
  const decoded = decodeCanonicalCopy(getCellResultV1, options.resultBytes, 'CELL.GET result')
  return new VerifiedCellGetResult(VERIFIED_CELL_GET_RESULT, {
    bytes: decoded.bytes,
    value: decoded.value,
    context,
    storageSlot
  })
}

export async function openVerifiedCellGetResult (options) {
  if (!options || typeof options !== 'object') {
    fail('BAD_CLIENT_INPUT', 'verified CELL.GET result options are required')
  }
  const internal = resultInternals.get(options.verifiedResult)
  if (!internal) {
    fail('BAD_CLIENT_INPUT', 'a package-owned verified CELL.GET result is required')
  }
  const readCap = options.readCap
  if (!readCap || typeof readCap !== 'object' || readCap.version !== 1) {
    fail('BAD_CLIENT_INPUT', 'frozen readCap version 1 is required')
  }
  const relayPublicKey = b4a.from(asBytes(readCap.relayPublicKey, 'readCap relayPublicKey', 32))
  const storageSlot = b4a.from(asBytes(readCap.storageSlot, 'readCap storageSlot', 32))
  const cellKey = b4a.from(asBytes(readCap.cellKey, 'readCap cellKey', 32))
  try {
    const sizeClass = readCap.sizeClass
    const expectedCellBlobBytes = CELL_SIZE_CLASS[sizeClass]
    if (!Number.isInteger(sizeClass) || expectedCellBlobBytes == null) {
      fail('BAD_CLIENT_INPUT', 'readCap sizeClass is outside the frozen cell classes')
    }
    const expectedCellBlobHash = b4a.from(asBytes(
      readCap.expectedCellBlobHash, 'readCap expectedCellBlobHash', 32))
    if (!sameBytes(relayPublicKey, internal.context.relayPublicKey)) {
      fail('BAD_CLIENT_INPUT', 'readCap relayPublicKey does not match the verified CELL.GET endpoint')
    }
    if (!sameBytes(storageSlot, internal.storageSlot)) {
      fail('BAD_CLIENT_INPUT', 'readCap storageSlot does not match the verified CELL.GET request')
    }
    if (internal.value.sizeClass !== sizeClass) {
      fail('RELAY_PROTOCOL_VIOLATION', 'CELL.GET result sizeClass does not match the read capability')
    }
    const cellBlob = b4a.from(asBytes(
      internal.value.cellBlob, 'CELL.GET result cellBlob', expectedCellBlobBytes))
    return await openCell({
      runtime: options.runtime,
      storageSlot,
      cellKey,
      sizeClass,
      expectedCellBlobHash,
      cellBlob
    })
  } finally {
    cellKey.fill(0)
  }
}
