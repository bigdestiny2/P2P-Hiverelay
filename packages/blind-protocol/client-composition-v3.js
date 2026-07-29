import b4a from 'b4a'
import c from 'compact-encoding'
import { decodeCanonical } from './codec.js'
import { protocolError } from './errors.js'
import {
  FORWARD_HTTPS_REQUEST_KIND_V1,
  FORWARD_HTTPS_REQUEST_ROLE_V1,
  FORWARD_HTTPS_RESULT_ROLE_V1,
  blindForwardHttpsOriginForwardTurnRequestV1,
  blindForwardHttpsOriginForwardTurnResultV1,
  forwardHttpsCapabilityPrefixHashV1,
  forwardHttpsOriginRequestCommitmentV1,
  forwardHttpsParentCapabilityPrefixHashV1,
  forwardHttpsStableSessionIdV1,
  forwardHttpsTargetResultChainHashV1,
  verifyForwardHttpsParentCapabilitySignatureV1,
  verifyForwardHttpsResultSignatureV1
} from './wire-v3.js'

const MAX_U64 = (1n << 64n) - 1n

export const CLIENT_COMPOSITION_V3_PROTOCOL = Object.freeze({ authorityVersion: 3, formatMajor: 3, formatMinor: 0 })

export const CLIENT_COMPOSITION_SCHEMA_V3 = Object.freeze({
  ForwardHttpsVerifiedEndpointV3: 9,
  ForwardHttpsSessionV3: 10
})

export const FORWARD_HTTPS_OUTSTANDING_STATE_V3 = Object.freeze({
  NONE: 0,
  PERSISTED_BEFORE_FETCH: 1,
  AWAITING_DEFINITIVE_TARGET: 2
})

export const CLIENT_COMPOSITION_V3_SCHEMA_DECLARATIONS = Object.freeze([
  Object.freeze({
    schemaId: 9,
    schemaName: 'ForwardHttpsVerifiedEndpointV3',
    fields: Object.freeze([
      'version:u8=3', 'releaseProfileId:u8=2', 'routeKind:u8=7', 'wireV3AbiHash:fixed32[nonzero]',
      'verifiedEndpointHandleHash:fixed32[nonzero;opaque-exact-FORWARD-operation]',
      'sourceRelayPublicKey:fixed32[nonzero]', 'sourceDescriptorSequence:u64be[nonzero]', 'sourceDescriptorHash:fixed32[nonzero]',
      'targetCatalogEntryId:fixed32[nonzero]', 'targetRelayPublicKey:fixed32[nonzero;different-source]',
      'targetDescriptorSequence:u64be[nonzero]', 'targetDescriptorHash:fixed32[nonzero]',
      'signedDescriptorHash:fixed32[nonzero]', 'signedHealthHash:fixed32[nonzero]',
      'descriptorFresh:true', 'signedHealthFresh:true', 'credentialFreeHttps:true',
      'cookies:false', 'authorization:false', 'referrer:false', 'redirect:false',
      'exactRequestBytes:65536', 'exactResultBytes:65536', 'continuityBackend:INDEXEDDB_PERSISTENT',
      'no-url-host-ip-dial-or-credential-fields'
    ])
  }),
  Object.freeze({
    schemaId: 10,
    schemaName: 'ForwardHttpsSessionV3',
    fields: Object.freeze([
      'version:u8=3', 'verifiedEndpoint:ForwardHttpsVerifiedEndpointV3',
      'stableSessionId:fixed32[nonzero]', 'capabilityPrefixHash:fixed32[nonzero]', 'clientSessionNonce:fixed32[nonzero]',
      'nextSequence:u64be', 'previousTargetResultHash:fixed32[zero-iff-nextSequence-zero]',
      'terminal:u8[0|1]', 'outstandingState:u8[NONE=0|PERSISTED_BEFORE_FETCH=1|AWAITING_DEFINITIVE_TARGET=2]',
      'outstandingOriginRequestCommitment:fixed32[zero-iff-NONE]',
      'outstandingOriginRequest:bytes[zero-iff-NONE|exact65536-otherwise]',
      'lastDefinitiveTargetResult:bytes[zero-iff-nextSequence-zero|exact65536-otherwise]',
      'indexeddb-transactional-persistence-required', 'source-results-never-advance', 'forwardReadinessOperationBits:0'
    ])
  })
])

function fail (message) {
  protocolError('BAD_CLIENT_COMPOSITION_V3', message)
}

function bytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  value = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (value.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  if (nonzero && isZero(value)) fail(`${field} must be nonzero`)
  return b4a.from(value)
}

function variableBytes (value, field) {
  if (value == null) return b4a.alloc(0)
  if (typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  return b4a.from(value)
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function u64 (value, field, nonzero = false) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64 || (nonzero && value === 0n)) fail(`${field} is outside u64`)
  return value
}

function exactObjectKeys (value, expected, field) {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${field} has an unknown or missing field`)
  }
}

const VERIFIED_ENDPOINT_FIELDS_V3 = Object.freeze([
  'version', 'releaseProfileId', 'routeKind', 'wireV3AbiHash', 'verifiedEndpointHandleHash',
  'sourceRelayPublicKey', 'sourceDescriptorSequence', 'sourceDescriptorHash', 'targetCatalogEntryId',
  'targetRelayPublicKey', 'targetDescriptorSequence', 'targetDescriptorHash', 'signedDescriptorHash',
  'signedHealthHash', 'descriptorFresh', 'signedHealthFresh', 'credentialFreeHttps', 'cookies',
  'authorization', 'referrer', 'redirect', 'exactRequestBytes', 'exactResultBytes', 'continuityBackend'
])

const SESSION_FIELDS_V3 = Object.freeze([
  'version', 'verifiedEndpoint', 'stableSessionId', 'capabilityPrefixHash', 'clientSessionNonce',
  'nextSequence', 'previousTargetResultHash', 'terminal', 'outstandingState',
  'outstandingOriginRequestCommitment', 'outstandingOriginRequest', 'lastDefinitiveTargetResult'
])

function assertCapabilityMatchesEndpoint (capability, endpoint) {
  for (const field of ['sourceRelayPublicKey', 'sourceDescriptorHash', 'targetRelayPublicKey', 'targetDescriptorHash', 'targetCatalogEntryId']) {
    if (!b4a.equals(capability[field], endpoint[field])) fail(`session capability ${field} does not match the verified endpoint`)
  }
  if (capability.sourceDescriptorSequence !== endpoint.sourceDescriptorSequence ||
      capability.targetDescriptorSequence !== endpoint.targetDescriptorSequence) {
    fail('session capability descriptor sequence does not match the verified endpoint')
  }
}

export function assertForwardHttpsVerifiedEndpointV3 (value, expectedWireV3AbiHash = null) {
  if (!value || typeof value !== 'object') fail('verified endpoint must be an object')
  for (const forbidden of [
    'url', 'host', 'hostname', 'ip', 'ipAddress', 'dialAddress', 'credentials', 'username', 'password', 'authorizationHeader'
  ]) {
    if (forbidden in value) fail(`verified endpoint ${forbidden} is forbidden`)
  }
  exactObjectKeys(value, VERIFIED_ENDPOINT_FIELDS_V3, 'verified endpoint')
  if (value.version !== 3 || value.releaseProfileId !== 2 || value.routeKind !== 7) fail('verified endpoint fixed profile is invalid')
  const output = {
    version: 3,
    releaseProfileId: 2,
    routeKind: 7,
    wireV3AbiHash: bytes(value.wireV3AbiHash, 32, 'wireV3AbiHash', true),
    verifiedEndpointHandleHash: bytes(value.verifiedEndpointHandleHash, 32, 'verifiedEndpointHandleHash', true),
    sourceRelayPublicKey: bytes(value.sourceRelayPublicKey, 32, 'sourceRelayPublicKey', true),
    sourceDescriptorSequence: u64(value.sourceDescriptorSequence, 'sourceDescriptorSequence', true),
    sourceDescriptorHash: bytes(value.sourceDescriptorHash, 32, 'sourceDescriptorHash', true),
    targetCatalogEntryId: bytes(value.targetCatalogEntryId, 32, 'targetCatalogEntryId', true),
    targetRelayPublicKey: bytes(value.targetRelayPublicKey, 32, 'targetRelayPublicKey', true),
    targetDescriptorSequence: u64(value.targetDescriptorSequence, 'targetDescriptorSequence', true),
    targetDescriptorHash: bytes(value.targetDescriptorHash, 32, 'targetDescriptorHash', true),
    signedDescriptorHash: bytes(value.signedDescriptorHash, 32, 'signedDescriptorHash', true),
    signedHealthHash: bytes(value.signedHealthHash, 32, 'signedHealthHash', true),
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
  if (b4a.equals(output.sourceRelayPublicKey, output.targetRelayPublicKey)) fail('source and target relay public keys must differ')
  if (expectedWireV3AbiHash != null && !b4a.equals(output.wireV3AbiHash, bytes(expectedWireV3AbiHash, 32, 'expectedWireV3AbiHash', true))) {
    fail('verified endpoint WIRE v3 ABI hash does not match')
  }
  if (output.descriptorFresh !== true || output.signedHealthFresh !== true || output.credentialFreeHttps !== true ||
      output.cookies !== false || output.authorization !== false || output.referrer !== false || output.redirect !== false ||
      output.exactRequestBytes !== 65_536 || output.exactResultBytes !== 65_536 ||
      output.continuityBackend !== 'INDEXEDDB_PERSISTENT') {
    fail('verified endpoint trust, privacy, size, or continuity policy is incomplete')
  }
  return Object.freeze(output)
}

export function assertForwardHttpsSessionV3 (value, expectedWireV3AbiHash = null) {
  if (!value || typeof value !== 'object' || value.version !== 3) fail('session fixed header is invalid')
  exactObjectKeys(value, SESSION_FIELDS_V3, 'session')
  const verifiedEndpoint = assertForwardHttpsVerifiedEndpointV3(value.verifiedEndpoint, expectedWireV3AbiHash)
  const stableSessionId = bytes(value.stableSessionId, 32, 'stableSessionId', true)
  const capabilityPrefixHash = bytes(value.capabilityPrefixHash, 32, 'capabilityPrefixHash', true)
  const clientSessionNonce = bytes(value.clientSessionNonce, 32, 'clientSessionNonce', true)
  const nextSequence = u64(value.nextSequence, 'nextSequence')
  const previousTargetResultHash = bytes(value.previousTargetResultHash, 32, 'previousTargetResultHash')
  if ((nextSequence === 0n) !== isZero(previousTargetResultHash)) fail('previous target result hash must be zero iff nextSequence is zero')
  if (value.terminal !== 0 && value.terminal !== 1) fail('terminal must be 0 or 1')
  if (![0, 1, 2].includes(value.outstandingState)) fail('outstandingState is outside the closed registry')
  const commitment = bytes(value.outstandingOriginRequestCommitment, 32, 'outstandingOriginRequestCommitment')
  const request = variableBytes(value.outstandingOriginRequest, 'outstandingOriginRequest')
  if (value.outstandingState === FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE) {
    if (!isZero(commitment) || request.byteLength !== 0) fail('NONE outstanding state requires zero commitment and zero request bytes')
  } else if (isZero(commitment) || request.byteLength !== 65_536) {
    fail('persisted outstanding state requires a nonzero commitment and exact 65536-byte request')
  } else {
    const decoded = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, request, { copyBytes: true })
    if (decoded.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE ||
        decoded.sequence !== nextSequence ||
        !b4a.equals(decoded.stableSessionId, stableSessionId) ||
        !b4a.equals(decoded.clientSessionNonce, clientSessionNonce) ||
        !b4a.equals(decoded.previousTargetResultHash, previousTargetResultHash) ||
        !b4a.equals(forwardHttpsOriginRequestCommitmentV1(request), commitment) ||
        !b4a.equals(forwardHttpsCapabilityPrefixHashV1(request), capabilityPrefixHash) ||
        !b4a.equals(forwardHttpsStableSessionIdV1(decoded.parentCapability, clientSessionNonce), stableSessionId)) {
      fail('outstanding origin request does not bind the exact session state')
    }
    assertCapabilityMatchesEndpoint(decoded.parentCapability, verifiedEndpoint)
    if ((nextSequence === 0n) !== (decoded.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.OPEN)) {
      fail('only the sequence-zero request may be OPEN')
    }
  }
  const lastResult = variableBytes(value.lastDefinitiveTargetResult, 'lastDefinitiveTargetResult')
  if (nextSequence === 0n ? lastResult.byteLength !== 0 : lastResult.byteLength !== 65_536) {
    fail('last definitive target result size does not match nextSequence')
  }
  if (nextSequence !== 0n) {
    const decoded = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, lastResult, { copyBytes: true })
    if (decoded.resultRole !== FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT ||
        decoded.sequence !== nextSequence - 1n ||
        !b4a.equals(decoded.stableSessionId, stableSessionId) ||
        !b4a.equals(forwardHttpsStableSessionIdV1(decoded.finalizedParentCapability, clientSessionNonce), stableSessionId) ||
        !b4a.equals(forwardHttpsParentCapabilityPrefixHashV1(decoded.finalizedParentCapability), capabilityPrefixHash) ||
        !b4a.equals(forwardHttpsTargetResultChainHashV1(lastResult), previousTargetResultHash) ||
        !b4a.equals(decoded.signerPublicKey, verifiedEndpoint.targetRelayPublicKey) ||
        decoded.signerDescriptorSequence !== verifiedEndpoint.targetDescriptorSequence ||
        !b4a.equals(decoded.signerDescriptorHash, verifiedEndpoint.targetDescriptorHash) ||
        !verifyForwardHttpsParentCapabilitySignatureV1(decoded.finalizedParentCapability) ||
        !verifyForwardHttpsResultSignatureV1(lastResult)) {
      fail('last definitive target result does not bind the exact session chain and target authority')
    }
    assertCapabilityMatchesEndpoint(decoded.finalizedParentCapability, verifiedEndpoint)
    if (decoded.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.CLOSE && value.terminal !== 1) {
      fail('a definitive CLOSE request requires terminal state')
    }
  }
  if (value.terminal === 1 && value.outstandingState !== FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE) {
    fail('terminal session cannot retain a live outstanding request')
  }
  return Object.freeze({
    version: 3,
    verifiedEndpoint,
    stableSessionId,
    capabilityPrefixHash,
    clientSessionNonce,
    nextSequence,
    previousTargetResultHash,
    terminal: value.terminal,
    outstandingState: value.outstandingState,
    outstandingOriginRequestCommitment: commitment,
    outstandingOriginRequest: request,
    lastDefinitiveTargetResult: lastResult
  })
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
const declarationBytes = schema => b4a.from(JSON.stringify({ name: schema.schemaName, fields: schema.fields }), 'utf8')

export const clientCompositionV3Encoding = {
  preencode (state, value) {
    c.string.preencode(state, value.magic)
    c.uint.preencode(state, value.authorityVersion)
    c.uint.preencode(state, value.formatMajor)
    c.uint.preencode(state, value.formatMinor)
    c.buffer.preencode(state, value.baseClientCompositionV2FormatHash)
    c.buffer.preencode(state, value.wireV3AbiHash)
    c.uint.preencode(state, value.baseSchemaCount)
    schemasEncoding.preencode(state, value.additionalSchemas)
    c.uint.preencode(state, value.forwardReadinessOperationBits)
  },
  encode (state, value) {
    c.string.encode(state, value.magic)
    c.uint.encode(state, value.authorityVersion)
    c.uint.encode(state, value.formatMajor)
    c.uint.encode(state, value.formatMinor)
    c.buffer.encode(state, value.baseClientCompositionV2FormatHash)
    c.buffer.encode(state, value.wireV3AbiHash)
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
      baseClientCompositionV2FormatHash: b4a.from(c.buffer.decode(state)),
      wireV3AbiHash: b4a.from(c.buffer.decode(state)),
      baseSchemaCount: c.uint.decode(state),
      additionalSchemas: schemasEncoding.decode(state),
      forwardReadinessOperationBits: c.uint.decode(state)
    }
  }
}

export function createClientCompositionV3Value (baseClientCompositionV2FormatHash, wireV3AbiHash) {
  return {
    magic: 'hiverelay-blind-client-composition-v3',
    ...CLIENT_COMPOSITION_V3_PROTOCOL,
    baseClientCompositionV2FormatHash: bytes(baseClientCompositionV2FormatHash, 32, 'baseClientCompositionV2FormatHash', true),
    wireV3AbiHash: bytes(wireV3AbiHash, 32, 'wireV3AbiHash', true),
    baseSchemaCount: 8,
    additionalSchemas: CLIENT_COMPOSITION_V3_SCHEMA_DECLARATIONS.map(schema => ({
      schemaId: schema.schemaId,
      schemaName: schema.schemaName,
      canonicalDeclarationBytes: declarationBytes(schema)
    })),
    forwardReadinessOperationBits: 0
  }
}

export function encodeClientCompositionV3 (value) {
  const state = { start: 0, end: 0, buffer: null }
  clientCompositionV3Encoding.preencode(state, value)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  clientCompositionV3Encoding.encode(state, value)
  if (state.start !== state.end) fail('composition v3 encoder length mismatch')
  return state.buffer
}

export function decodeClientCompositionV3 (input) {
  input = b4a.from(input)
  const state = { start: 0, end: input.byteLength, buffer: input }
  const value = clientCompositionV3Encoding.decode(state)
  if (state.start !== state.end || !b4a.equals(encodeClientCompositionV3(value), input)) fail('composition v3 authority is not canonical')
  if (value.magic !== 'hiverelay-blind-client-composition-v3' || value.authorityVersion !== 3 ||
      value.formatMajor !== 3 || value.formatMinor !== 0 || value.baseSchemaCount !== 8 ||
      value.baseClientCompositionV2FormatHash.byteLength !== 32 || value.wireV3AbiHash.byteLength !== 32 ||
      value.additionalSchemas.length !== 2 || value.forwardReadinessOperationBits !== 0 ||
      value.additionalSchemas.some((schema, index) => schema.schemaId !== index + 9 ||
        !b4a.equals(schema.canonicalDeclarationBytes, declarationBytes(CLIENT_COMPOSITION_V3_SCHEMA_DECLARATIONS[index])))) {
    fail('composition v3 fixed allocation or declarations are invalid')
  }
  return value
}

export function encodeClientCompositionV3SchemaCatalog (schemas = CLIENT_COMPOSITION_V3_SCHEMA_DECLARATIONS) {
  const values = schemas.map(schema => ({
    schemaId: schema.schemaId,
    schemaName: schema.schemaName,
    canonicalDeclarationBytes: schema.canonicalDeclarationBytes == null
      ? declarationBytes(schema)
      : b4a.from(schema.canonicalDeclarationBytes)
  }))
  const state = { start: 0, end: 0, buffer: null }
  schemasEncoding.preencode(state, values)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  schemasEncoding.encode(state, values)
  return state.buffer
}

export function decodeClientCompositionV3SchemaCatalog (input) {
  input = b4a.from(input)
  const state = { start: 0, end: input.byteLength, buffer: input }
  const schemas = schemasEncoding.decode(state)
  if (state.start !== state.end || !b4a.equals(encodeClientCompositionV3SchemaCatalog(schemas), input) ||
      schemas.length !== 2 || schemas.some((schema, index) => schema.schemaId !== index + 9 ||
        !b4a.equals(schema.canonicalDeclarationBytes, declarationBytes(CLIENT_COMPOSITION_V3_SCHEMA_DECLARATIONS[index])))) {
    fail('composition v3 schema catalog is not canonical')
  }
  return schemas
}
