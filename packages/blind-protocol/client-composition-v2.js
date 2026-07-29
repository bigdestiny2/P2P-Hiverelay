import b4a from 'b4a'
import c from 'compact-encoding'
import { protocolError } from './errors.js'

export const CLIENT_COMPOSITION_V2_PROTOCOL = Object.freeze({ authorityVersion: 2, formatMajor: 2, formatMinor: 0 })

export const CLIENT_COMPOSITION_SCHEMA_V2 = Object.freeze({
  ForwardHttpsVerifiedEndpointV2: 7,
  ForwardHttpsSessionV2: 8
})

export const CLIENT_COMPOSITION_V2_SCHEMA_DECLARATIONS = Object.freeze([
  Object.freeze({
    schemaId: 7,
    schemaName: 'ForwardHttpsVerifiedEndpointV2',
    fields: Object.freeze([
      'version:u8=2', 'releaseProfileId:u8=2', 'routeKind:u8=7',
      'wireV2AbiHash:fixed32[nonzero]', 'verifiedEndpointHandleHash:fixed32[nonzero;opaque-exact-FORWARD-operation]',
      'targetCatalogEntryId:fixed32[nonzero]', 'targetRelayPublicKey:fixed32[nonzero]',
      'targetDescriptorSequence:u64be[nonzero]', 'targetDescriptorHash:fixed32[nonzero]',
      'signedDescriptorHash:fixed32[nonzero]', 'signedHealthHash:fixed32[nonzero]',
      'descriptorFresh:true', 'signedHealthFresh:true', 'credentialFreeHttps:true',
      'cookies:false', 'authorization:false', 'referrer:false', 'redirect:false',
      'exactRequestBytes:65536', 'exactResultBytes:65536',
      'continuityBackend:INDEXEDDB_PERSISTENT', 'no-url-host-ip-dial-fields'
    ])
  }),
  Object.freeze({
    schemaId: 8,
    schemaName: 'ForwardHttpsSessionV2',
    fields: Object.freeze([
      'version:u8=2', 'verifiedEndpoint:ForwardHttpsVerifiedEndpointV2',
      'sessionId:fixed32[nonzero]', 'parentCapabilityHash:fixed32[nonzero]',
      'nextSequence:u64be', 'outstandingCount:u8[0..1]',
      'exact-retry:idempotent', 'changed-same-sequence:terminal',
      'signed-result-verification:required', 'readback-verification:required',
      'forwardReadinessOperationBits:0'
    ])
  })
])

function fail (message) {
  protocolError('BAD_CLIENT_COMPOSITION_V2', message)
}

function bytes (value, field) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (value.byteLength !== 32) fail(`${field} must be exactly 32 bytes`)
  for (const byte of value) if (byte !== 0) return b4a.from(value)
  fail(`${field} must be nonzero`)
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value <= 0n || value > ((1n << 64n) - 1n)) fail(`${field} must be a nonzero u64`)
  return value
}

export function assertForwardHttpsVerifiedEndpointV2 (value, expectedWireV2AbiHash = null) {
  if (!value || typeof value !== 'object') fail('verified endpoint must be an object')
  for (const forbidden of ['url', 'host', 'hostname', 'ip', 'ipAddress', 'dialAddress', 'credentials']) {
    if (forbidden in value) fail(`verified endpoint ${forbidden} is forbidden`)
  }
  if (value.version !== 2 || value.releaseProfileId !== 2 || value.routeKind !== 7) fail('verified endpoint fixed profile is invalid')
  const output = {
    version: 2,
    releaseProfileId: 2,
    routeKind: 7,
    wireV2AbiHash: bytes(value.wireV2AbiHash, 'wireV2AbiHash'),
    verifiedEndpointHandleHash: bytes(value.verifiedEndpointHandleHash, 'verifiedEndpointHandleHash'),
    targetCatalogEntryId: bytes(value.targetCatalogEntryId, 'targetCatalogEntryId'),
    targetRelayPublicKey: bytes(value.targetRelayPublicKey, 'targetRelayPublicKey'),
    targetDescriptorSequence: u64(value.targetDescriptorSequence, 'targetDescriptorSequence'),
    targetDescriptorHash: bytes(value.targetDescriptorHash, 'targetDescriptorHash'),
    signedDescriptorHash: bytes(value.signedDescriptorHash, 'signedDescriptorHash'),
    signedHealthHash: bytes(value.signedHealthHash, 'signedHealthHash'),
    descriptorFresh: value.descriptorFresh,
    signedHealthFresh: value.signedHealthFresh,
    credentialFreeHttps: value.credentialFreeHttps,
    cookies: value.cookies,
    authorization: value.authorization,
    referrer: value.referrer,
    redirect: value.redirect,
    exactRequestBytes: value.exactRequestBytes,
    exactResultBytes: value.exactResultBytes,
    continuityBackend: value.continuityBackend
  }
  if (expectedWireV2AbiHash != null && !b4a.equals(output.wireV2AbiHash, bytes(expectedWireV2AbiHash, 'expectedWireV2AbiHash'))) {
    fail('verified endpoint WIRE v2 ABI hash does not match')
  }
  if (output.descriptorFresh !== true || output.signedHealthFresh !== true || output.credentialFreeHttps !== true ||
      output.cookies !== false || output.authorization !== false || output.referrer !== false || output.redirect !== false ||
      output.exactRequestBytes !== 65_536 || output.exactResultBytes !== 65_536 ||
      output.continuityBackend !== 'INDEXEDDB_PERSISTENT') {
    fail('verified endpoint trust or privacy policy is incomplete')
  }
  return Object.freeze(output)
}

function list (encoding) {
  return {
    preencode (state, values) {
      c.uint.preencode(state, values.length)
      for (const value of values) encoding.preencode(state, value)
    },
    encode (state, values) {
      c.uint.encode(state, values.length)
      for (const value of values) encoding.encode(state, value)
    },
    decode (state) {
      const length = c.uint.decode(state)
      const values = []
      for (let i = 0; i < length; i++) values.push(encoding.decode(state))
      return values
    }
  }
}

const schemaEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.schemaId)
    c.string.preencode(state, value.schemaName)
    c.buffer.preencode(state, value.canonicalDeclarationBytes)
  },
  encode (state, value) {
    c.uint.encode(state, value.schemaId)
    c.string.encode(state, value.schemaName)
    c.buffer.encode(state, value.canonicalDeclarationBytes)
  },
  decode (state) {
    return {
      schemaId: c.uint.decode(state),
      schemaName: c.string.decode(state),
      canonicalDeclarationBytes: b4a.from(c.buffer.decode(state))
    }
  }
}

const schemasEncoding = list(schemaEncoding)

export const clientCompositionV2Encoding = {
  preencode (state, value) {
    c.string.preencode(state, value.magic)
    c.uint.preencode(state, value.authorityVersion)
    c.uint.preencode(state, value.formatMajor)
    c.uint.preencode(state, value.formatMinor)
    c.buffer.preencode(state, value.baseCompositionV1FormatHash)
    c.buffer.preencode(state, value.wireV2AbiHash)
    c.uint.preencode(state, value.baseSchemaCount)
    schemasEncoding.preencode(state, value.additionalSchemas)
    c.uint.preencode(state, value.forwardReadinessOperationBits)
  },
  encode (state, value) {
    c.string.encode(state, value.magic)
    c.uint.encode(state, value.authorityVersion)
    c.uint.encode(state, value.formatMajor)
    c.uint.encode(state, value.formatMinor)
    c.buffer.encode(state, value.baseCompositionV1FormatHash)
    c.buffer.encode(state, value.wireV2AbiHash)
    c.uint.encode(state, value.baseSchemaCount)
    schemasEncoding.encode(state, value.additionalSchemas)
    c.uint.encode(state, value.forwardReadinessOperationBits)
  },
  decode (state) {
    return {
      magic: c.string.decode(state),
      authorityVersion: c.uint.decode(state),
      formatMajor: c.uint.decode(state),
      formatMinor: c.uint.decode(state),
      baseCompositionV1FormatHash: b4a.from(c.buffer.decode(state)),
      wireV2AbiHash: b4a.from(c.buffer.decode(state)),
      baseSchemaCount: c.uint.decode(state),
      additionalSchemas: schemasEncoding.decode(state),
      forwardReadinessOperationBits: c.uint.decode(state)
    }
  }
}

export function createClientCompositionV2Value (baseCompositionV1FormatHash, wireV2AbiHash) {
  return {
    magic: 'hiverelay-blind-client-composition-v2',
    ...CLIENT_COMPOSITION_V2_PROTOCOL,
    baseCompositionV1FormatHash: bytes(baseCompositionV1FormatHash, 'baseCompositionV1FormatHash'),
    wireV2AbiHash: bytes(wireV2AbiHash, 'wireV2AbiHash'),
    baseSchemaCount: 6,
    additionalSchemas: CLIENT_COMPOSITION_V2_SCHEMA_DECLARATIONS.map(schema => ({
      schemaId: schema.schemaId,
      schemaName: schema.schemaName,
      canonicalDeclarationBytes: b4a.from(JSON.stringify({ name: schema.schemaName, fields: schema.fields }))
    })),
    forwardReadinessOperationBits: 0
  }
}

export function encodeClientCompositionV2 (value) {
  const state = { start: 0, end: 0, buffer: null }
  clientCompositionV2Encoding.preencode(state, value)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  clientCompositionV2Encoding.encode(state, value)
  if (state.start !== state.end) fail('composition v2 encoder length mismatch')
  return state.buffer
}

export function decodeClientCompositionV2 (input) {
  const state = { start: 0, end: input.byteLength, buffer: input }
  const value = clientCompositionV2Encoding.decode(state)
  if (state.start !== state.end || !b4a.equals(encodeClientCompositionV2(value), input)) fail('composition v2 authority is not canonical')
  if (value.magic !== 'hiverelay-blind-client-composition-v2' || value.authorityVersion !== 2 ||
      value.formatMajor !== 2 || value.formatMinor !== 0 || value.baseSchemaCount !== 6 ||
      value.additionalSchemas.length !== 2 || value.additionalSchemas[0].schemaId !== 7 ||
      value.additionalSchemas[1].schemaId !== 8 || value.forwardReadinessOperationBits !== 0) {
    fail('composition v2 fixed allocation is invalid')
  }
  return value
}

export function encodeClientCompositionV2SchemaCatalog (schemas = CLIENT_COMPOSITION_V2_SCHEMA_DECLARATIONS) {
  const values = schemas.map(schema => ({
    schemaId: schema.schemaId,
    schemaName: schema.schemaName,
    canonicalDeclarationBytes: schema.canonicalDeclarationBytes == null
      ? b4a.from(JSON.stringify({ name: schema.schemaName, fields: schema.fields }))
      : b4a.from(schema.canonicalDeclarationBytes)
  }))
  const state = { start: 0, end: 0, buffer: null }
  schemasEncoding.preencode(state, values)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  schemasEncoding.encode(state, values)
  return state.buffer
}

export function decodeClientCompositionV2SchemaCatalog (input) {
  const state = { start: 0, end: input.byteLength, buffer: input }
  const schemas = schemasEncoding.decode(state)
  if (state.start !== state.end || !b4a.equals(encodeClientCompositionV2SchemaCatalog(schemas), input)) {
    fail('composition v2 schema catalog is not canonical')
  }
  if (schemas.length !== 2 || schemas[0].schemaId !== 7 || schemas[1].schemaId !== 8) {
    fail('composition v2 schema catalog allocation is invalid')
  }
  return schemas
}
