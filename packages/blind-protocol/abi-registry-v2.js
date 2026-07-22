import b4a from 'b4a'
import c from 'compact-encoding'
import { protocolError } from './errors.js'
import {
  FORWARD_HTTPS_DOMAIN_V2,
  FORWARD_HTTPS_TRANSPORT_VARIANTS_V2,
  RELEASE_PROFILE_V2,
  WIRE_V2_PROTOCOL,
  WIRE_V2_SCHEMA_DECLARATIONS
} from './wire-v2.js'

function fail (message) {
  protocolError('BAD_WIRE_V2_ABI', message)
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

const profileEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.profileId)
    c.string.preencode(state, value.canonicalName)
    c.uint.preencode(state, value.operationBits)
    c.uint.preencode(state, value.isDefault ? 1 : 0)
  },
  encode (state, value) {
    c.uint.encode(state, value.profileId)
    c.string.encode(state, value.canonicalName)
    c.uint.encode(state, value.operationBits)
    c.uint.encode(state, value.isDefault ? 1 : 0)
  },
  decode (state) {
    return {
      profileId: c.uint.decode(state),
      canonicalName: c.string.decode(state),
      operationBits: c.uint.decode(state),
      isDefault: c.uint.decode(state) === 1
    }
  }
}

const variantEncoding = {
  preencode (state, value) {
    c.string.preencode(state, value.family)
    c.string.preencode(state, value.operation)
    c.uint.preencode(state, value.turnKind)
    c.uint.preencode(state, value.routeKind)
    c.uint.preencode(state, value.releaseProfileId)
    c.uint.preencode(state, value.requestSchemaId)
    c.uint.preencode(state, value.resultSchemaId)
    c.uint.preencode(state, value.requestBytes)
    c.uint.preencode(state, value.resultBytes)
  },
  encode (state, value) {
    c.string.encode(state, value.family)
    c.string.encode(state, value.operation)
    c.uint.encode(state, value.turnKind)
    c.uint.encode(state, value.routeKind)
    c.uint.encode(state, value.releaseProfileId)
    c.uint.encode(state, value.requestSchemaId)
    c.uint.encode(state, value.resultSchemaId)
    c.uint.encode(state, value.requestBytes)
    c.uint.encode(state, value.resultBytes)
  },
  decode (state) {
    return {
      family: c.string.decode(state),
      operation: c.string.decode(state),
      turnKind: c.uint.decode(state),
      routeKind: c.uint.decode(state),
      releaseProfileId: c.uint.decode(state),
      requestSchemaId: c.uint.decode(state),
      resultSchemaId: c.uint.decode(state),
      requestBytes: c.uint.decode(state),
      resultBytes: c.uint.decode(state)
    }
  }
}

const domainEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.domainId)
    c.string.preencode(state, value.purpose)
    c.string.preencode(state, value.name)
    c.string.preencode(state, value.exactAsciiBytes)
  },
  encode (state, value) {
    c.uint.encode(state, value.domainId)
    c.string.encode(state, value.purpose)
    c.string.encode(state, value.name)
    c.string.encode(state, value.exactAsciiBytes)
  },
  decode (state) {
    return {
      domainId: c.uint.decode(state),
      purpose: c.string.decode(state),
      name: c.string.decode(state),
      exactAsciiBytes: c.string.decode(state)
    }
  }
}

const schemasEncoding = list(schemaEncoding)
const profilesEncoding = list(profileEncoding)
const variantsEncoding = list(variantEncoding)
const domainsEncoding = list(domainEncoding)

export const wireAbiV2Encoding = {
  preencode (state, value) {
    c.string.preencode(state, value.magic)
    c.uint.preencode(state, value.formatVersion)
    c.string.preencode(state, value.protocolFamily)
    c.uint.preencode(state, value.protocolMajor)
    c.uint.preencode(state, value.protocolMinor)
    c.buffer.preencode(state, value.baseAbiHash)
    c.uint.preencode(state, value.baseSchemaCount)
    schemasEncoding.preencode(state, value.additionalSchemas)
    profilesEncoding.preencode(state, value.releaseProfiles)
    variantsEncoding.preencode(state, value.transportVariants)
    domainsEncoding.preencode(state, value.additionalDomains)
    c.uint.preencode(state, value.forwardReadinessOperationBits)
  },
  encode (state, value) {
    c.string.encode(state, value.magic)
    c.uint.encode(state, value.formatVersion)
    c.string.encode(state, value.protocolFamily)
    c.uint.encode(state, value.protocolMajor)
    c.uint.encode(state, value.protocolMinor)
    c.buffer.encode(state, value.baseAbiHash)
    c.uint.encode(state, value.baseSchemaCount)
    schemasEncoding.encode(state, value.additionalSchemas)
    profilesEncoding.encode(state, value.releaseProfiles)
    variantsEncoding.encode(state, value.transportVariants)
    domainsEncoding.encode(state, value.additionalDomains)
    c.uint.encode(state, value.forwardReadinessOperationBits)
  },
  decode (state) {
    return {
      magic: c.string.decode(state),
      formatVersion: c.uint.decode(state),
      protocolFamily: c.string.decode(state),
      protocolMajor: c.uint.decode(state),
      protocolMinor: c.uint.decode(state),
      baseAbiHash: b4a.from(c.buffer.decode(state)),
      baseSchemaCount: c.uint.decode(state),
      additionalSchemas: schemasEncoding.decode(state),
      releaseProfiles: profilesEncoding.decode(state),
      transportVariants: variantsEncoding.decode(state),
      additionalDomains: domainsEncoding.decode(state),
      forwardReadinessOperationBits: c.uint.decode(state)
    }
  }
}

function declarationBytes (schema) {
  return b4a.from(JSON.stringify({ name: schema.schemaName, fields: schema.fields }), 'utf8')
}

export function createWireAbiV2Value (baseAbiHash) {
  if (!baseAbiHash || baseAbiHash.byteLength !== 32) fail('baseAbiHash must be exactly 32 bytes')
  return {
    magic: 'hiverelay-blind-wire-abi-v2',
    formatVersion: WIRE_V2_PROTOCOL.abiFormatVersion,
    protocolFamily: 'hiverelay-blind-wire',
    protocolMajor: WIRE_V2_PROTOCOL.major,
    protocolMinor: WIRE_V2_PROTOCOL.minor,
    baseAbiHash: b4a.from(baseAbiHash),
    baseSchemaCount: 73,
    additionalSchemas: WIRE_V2_SCHEMA_DECLARATIONS.map(schema => ({
      schemaId: schema.schemaId,
      schemaName: schema.schemaName,
      canonicalDeclarationBytes: declarationBytes(schema)
    })),
    releaseProfiles: Object.entries(RELEASE_PROFILE_V2).map(([canonicalName, profile]) => ({
      profileId: profile.id,
      canonicalName,
      operationBits: profile.operationBits,
      isDefault: profile.isDefault
    })),
    transportVariants: FORWARD_HTTPS_TRANSPORT_VARIANTS_V2.map(value => ({ ...value })),
    additionalDomains: [
      { ...FORWARD_HTTPS_DOMAIN_V2.REQUEST, purpose: 'REQUEST_COMMITMENT' },
      { ...FORWARD_HTTPS_DOMAIN_V2.RESULT, purpose: 'RESULT_SIGNATURE' },
      { ...FORWARD_HTTPS_DOMAIN_V2.PARENT_CAPABILITY, purpose: 'AUXILIARY_SIGNATURE' }
    ],
    forwardReadinessOperationBits: 0
  }
}

export function encodeWireAbiV2 (value) {
  const state = { start: 0, end: 0, buffer: null }
  wireAbiV2Encoding.preencode(state, value)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  wireAbiV2Encoding.encode(state, value)
  if (state.start !== state.end) fail('ABI encoder did not fill its allocation')
  return state.buffer
}

export function decodeWireAbiV2 (input) {
  const state = { start: 0, end: input.byteLength, buffer: input }
  const value = wireAbiV2Encoding.decode(state)
  if (state.start !== state.end) fail('trailing bytes after WIRE v2 ABI')
  const canonical = encodeWireAbiV2(value)
  if (!b4a.equals(canonical, input)) fail('WIRE v2 ABI is not canonical')
  if (value.magic !== 'hiverelay-blind-wire-abi-v2' || value.formatVersion !== 2 ||
      value.protocolMajor !== 1 || value.protocolMinor !== 1 || value.baseSchemaCount !== 73) {
    fail('WIRE v2 ABI fixed header is invalid')
  }
  if (value.additionalSchemas.length !== 2 || value.additionalSchemas[0].schemaId !== 74 ||
      value.additionalSchemas[1].schemaId !== 75 || value.forwardReadinessOperationBits !== 0) {
    fail('WIRE v2 ABI additive allocation or readiness is invalid')
  }
  return value
}
