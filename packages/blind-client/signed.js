import b4a from 'b4a'
import sodium from './crypto.js'
import { decodeCanonical, encodeCanonical } from '@hiverelay/blind-protocol/codec'
import {
  auxiliarySignaturePayload,
  resultSignaturePayload
} from '@hiverelay/blind-protocol/hashes'
import { fail } from './errors.js'

export function sameBytes (left, right) {
  return left != null && right != null && left.byteLength === right.byteLength && b4a.equals(left, right)
}

export function decodeCanonicalCopy (encoding, input, label) {
  let bytes
  let value
  try {
    bytes = b4a.from(input)
    value = decodeCanonical(encoding, bytes, { copyBytes: true })
    if (!b4a.equals(encodeCanonical(encoding, value), bytes)) throw new Error('canonical round-trip changed bytes')
  } catch (error) {
    fail('RELAY_PROTOCOL_VIOLATION', `${label} is not canonical`, { cause: error })
  }
  return { bytes, value }
}

export function verifyResultSignedValue (encoding, value, domainId, publicKey, label, trailingSignatureBytes = 64) {
  return verifySignedValue(encoding, value, domainId, publicKey, label,
    trailingSignatureBytes, resultSignaturePayload, value.signature)
}

export function verifyAuxiliarySignedValue (encoding, value, domainId, publicKey, label,
  trailingSignatureBytes = 64, signature = value.signature) {
  return verifySignedValue(encoding, value, domainId, publicKey, label,
    trailingSignatureBytes, auxiliarySignaturePayload, signature)
}

function verifySignedValue (encoding, value, domainId, publicKey, label,
  trailingSignatureBytes, payloadFactory, signature) {
  const complete = encodeCanonical(encoding, value)
  if (!Number.isSafeInteger(trailingSignatureBytes) || trailingSignatureBytes < 64 || complete.byteLength <= trailingSignatureBytes) {
    fail('RELAY_PROTOCOL_VIOLATION', `${label} has an invalid signature boundary`)
  }
  if (trailingSignatureBytes !== 64 || signature == null || signature.byteLength !== 64) {
    fail('RELAY_PROTOCOL_VIOLATION', `${label} has no canonical final signature`)
  }
  const unsigned = complete.subarray(0, complete.byteLength - trailingSignatureBytes)
  let payload
  try {
    payload = payloadFactory(domainId, unsigned)
  } catch (error) {
    fail('RELAY_PROTOCOL_VIOLATION', `${label} uses an unknown signature domain`, { cause: error })
  }
  if (!sodium.crypto_sign_verify_detached(signature, payload, publicKey)) {
    fail('RELAY_PROTOCOL_VIOLATION', `${label} signature is invalid`)
  }
  return unsigned
}

export function verifyDetached (publicKey, message, signature, label) {
  if (!sodium.crypto_sign_verify_detached(signature, message, publicKey)) {
    fail('RELAY_PROTOCOL_VIOLATION', `${label} signature is invalid`)
  }
}
