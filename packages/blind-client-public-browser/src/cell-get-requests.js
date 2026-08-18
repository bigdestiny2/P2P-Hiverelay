import b4a from 'b4a'
import {
  CELL_SIZE_CLASS,
  FAMILY,
  OPERATION,
  operationProfile
} from '../../blind-protocol/wire-runtime-authority.js'
import { cellGetRequestCommitment } from '../../blind-protocol/hashes.js'
import { getCellV1 } from '../../blind-protocol/schemas.js'
import { encodeCanonical } from '../../blind-protocol/codec.js'
import { asBytes, randomBytes } from '../../blind-client/bytes.js'
import { fail } from '../../blind-client/errors.js'
import { resolveAdmission } from '../../blind-client/provider.js'

function nonce (runtime, value) {
  return value == null
    ? randomBytes(runtime, 32, 'client nonce')
    : b4a.from(asBytes(value, 'clientNonce', 32))
}

export async function createGetCellRequest (options) {
  if (!options || typeof options !== 'object' || !options.readCap) {
    fail('BAD_CLIENT_INPUT', 'readCap is required')
  }
  const runtime = options.runtime
  const relayPublicKey = asBytes(options.readCap.relayPublicKey, 'relayPublicKey', 32)
  const storageSlot = asBytes(options.readCap.storageSlot, 'storageSlot', 32)
  const cellBytes = CELL_SIZE_CLASS[options.readCap.sizeClass]
  if (cellBytes == null) {
    fail('BAD_CLIENT_INPUT', 'readCap sizeClass is outside the frozen cell classes')
  }
  const clientNonce = nonce(runtime, options.clientNonce)
  const requestCommitment = cellGetRequestCommitment({
    relayPublicKey,
    storageSlot,
    clientNonce
  })
  const admission = await resolveAdmission(options, {
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestCommitment,
    relayPublicKey
  }, false, 'CELL.GET admission provider is invalid')
  const request = { version: 1, storageSlot, clientNonce, admission }
  const profile = operationProfile(FAMILY.CELL, OPERATION.CELL.GET)
  if (!profile) fail('BAD_CLIENT_INPUT', 'CELL.GET has no frozen operation profile')
  return Object.freeze({
    request,
    requestBytes: encodeCanonical(getCellV1, request),
    requestCommitment,
    wire: Object.freeze({
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.GET,
      expectedResultBodyBytes: 2 + cellBytes
    })
  })
}
