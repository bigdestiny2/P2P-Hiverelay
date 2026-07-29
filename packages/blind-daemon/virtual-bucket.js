import b4a from 'b4a'
import { blake2b256 } from '@hiverelay/blind-protocol'

const DOMAIN = b4a.from('hiverelay.blind.virtual-bucket.v1', 'ascii')

function locatorBytes (value) {
  if (!b4a.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new TypeError('primaryLocator must be bytes')
  }
  if (value.byteLength === 0) throw new TypeError('primaryLocator must not be empty')
  return b4a.from(value)
}

export function deriveBlindVirtualBucket (serviceTag, primaryLocator) {
  if (!Number.isInteger(serviceTag) || serviceTag < 1 || serviceTag > 0xff) {
    throw new TypeError('serviceTag must be an unsigned nonzero byte')
  }
  const locator = locatorBytes(primaryLocator)
  const length = b4a.alloc(8)
  length.writeBigUInt64BE(BigInt(locator.byteLength))
  const digest = blake2b256(b4a.concat([DOMAIN, b4a.from([serviceTag]), length, locator]))
  return digest[0] * 0x100 + digest[1]
}

export const BLIND_VIRTUAL_BUCKET_DERIVATION = Object.freeze({
  version: 1,
  bucketCount: 65536,
  domain: 'hiverelay.blind.virtual-bucket.v1',
  algorithm: 'BLAKE2b-256',
  secret: false
})
