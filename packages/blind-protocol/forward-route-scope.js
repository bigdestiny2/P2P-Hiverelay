import b4a from 'b4a'
import { protocolError } from './errors.js'
import { blake2b256 } from './hashes.js'
import {
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  DOMAIN_PURPOSE,
  DOMAIN_RECIPE,
  domainRegistryEntry
} from './registry.js'

const MAX_U64 = (1n << 64n) - 1n

export const FORWARD_ROUTE_SCOPE_MAX_RELAY_COUNT = 4
export const FORWARD_ROUTE_SCOPE_GENESIS_DOMAIN = 'hiverelay.blind.forward-scope-genesis.v1'
export const FORWARD_ROUTE_SCOPE_HOP_DOMAIN = 'hiverelay.blind.forward-scope-hop.v1'

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function bytes (value, length, field) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  const output = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (output.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  return output
}

function unsigned (value, length, maximum, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail(`${field} is outside its unsigned range`)
  const output = b4a.alloc(length)
  for (let index = length - 1; index >= 0; index--) {
    output[index] = value & 0xff
    value = Math.floor(value / 0x100)
  }
  return output
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} is outside u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail(`${field} is outside u64`)
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

export function forwardRouteScopeGenesisHash (value) {
  if (!value || typeof value !== 'object') fail('route-scope genesis input must be an object')
  return blake2b256(b4a.concat([
    b4a.from(FORWARD_ROUTE_SCOPE_GENESIS_DOMAIN, 'ascii'),
    bytes(value.rootRouteId, 16, 'rootRouteId'),
    bytes(value.rootCircuitNonce, 32, 'rootCircuitNonce'),
    bytes(value.rootRequestCommitment, 32, 'rootRequestCommitment'),
    unsigned(value.maxRelayCount, 1, FORWARD_ROUTE_SCOPE_MAX_RELAY_COUNT, 'maxRelayCount'),
    unsigned(value.expiresEpoch, 4, 0xffffffff, 'expiresEpoch')
  ]))
}

export function forwardRouteScopeHopHash (value) {
  if (!value || typeof value !== 'object') fail('route-scope hop hash input must be an object')
  return blake2b256(b4a.concat([
    b4a.from(FORWARD_ROUTE_SCOPE_HOP_DOMAIN, 'ascii'),
    bytes(value.previousScopeHash, 32, 'previousScopeHash'),
    unsigned(value.hopIndex, 1, FORWARD_ROUTE_SCOPE_MAX_RELAY_COUNT - 1, 'hopIndex'),
    bytes(value.relayPublicKey, 32, 'relayPublicKey'),
    u64(value.descriptorSequence, 'descriptorSequence'),
    bytes(value.descriptorHash, 32, 'descriptorHash')
  ]))
}

export function forwardRouteScopeSignaturePayload (scopeHash) {
  scopeHash = bytes(scopeHash, 32, 'scopeHash')
  const domainId = AUXILIARY_SIGNATURE_DOMAIN_ID.FORWARD_ROUTE_SCOPE
  const domain = domainRegistryEntry(domainId)
  if (!domain || domain.purpose !== DOMAIN_PURPOSE.AUXILIARY_SIGNATURE ||
      domain.recipeId !== DOMAIN_RECIPE.ED25519_DOMAIN_LEN64_PAYLOAD) {
    fail('forward route-scope signature domain is absent from the draft registry')
  }
  return b4a.concat([
    b4a.from(domain.exactAsciiBytes, 'ascii'),
    u64(scopeHash.byteLength, 'scopeHash length'),
    scopeHash
  ])
}
