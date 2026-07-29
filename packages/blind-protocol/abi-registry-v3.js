import b4a from 'b4a'
import c from 'compact-encoding'
import { protocolError } from './errors.js'
import { RELEASE_PROFILE_V2 } from './wire-v2.js'
import {
  FORWARD_HTTPS_DOMAIN_V3,
  FORWARD_HTTPS_SUCCESSOR_TRANSPORT_VARIANTS_V3,
  WIRE_V3_HASH_DOMAIN_PURPOSE,
  WIRE_V3_HASH_RECIPES,
  WIRE_V3_PROTOCOL,
  WIRE_V3_SCHEMA_DECLARATIONS
} from './wire-v3.js'

function fail (message) {
  protocolError('BAD_WIRE_V3_ABI', message)
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

const uintList = list(c.uint)

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
    const value = {
      profileId: c.uint.decode(state),
      canonicalName: c.string.decode(state),
      operationBits: c.uint.decode(state),
      isDefault: c.uint.decode(state)
    }
    if (value.isDefault !== 0 && value.isDefault !== 1) fail('profile isDefault is outside 0..1')
    value.isDefault = value.isDefault === 1
    return value
  }
}

const variantEncoding = {
  preencode (state, value) {
    c.string.preencode(state, value.family)
    c.string.preencode(state, value.operation)
    c.uint.preencode(state, value.requestKind)
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
    c.uint.encode(state, value.requestKind)
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
      requestKind: c.uint.decode(state),
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
    c.uint.preencode(state, value.purposeId)
    c.uint.preencode(state, value.recipeId)
    c.string.preencode(state, value.purpose)
    c.string.preencode(state, value.name)
    c.string.preencode(state, value.exactAsciiBytes)
  },
  encode (state, value) {
    c.uint.encode(state, value.domainId)
    c.uint.encode(state, value.purposeId)
    c.uint.encode(state, value.recipeId)
    c.string.encode(state, value.purpose)
    c.string.encode(state, value.name)
    c.string.encode(state, value.exactAsciiBytes)
  },
  decode (state) {
    return {
      domainId: c.uint.decode(state),
      purposeId: c.uint.decode(state),
      recipeId: c.uint.decode(state),
      purpose: c.string.decode(state),
      name: c.string.decode(state),
      exactAsciiBytes: c.string.decode(state)
    }
  }
}

const hashRecipeEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.recipeId)
    c.string.preencode(state, value.name)
    c.string.preencode(state, value.canonicalPreimage)
  },
  encode (state, value) {
    c.uint.encode(state, value.recipeId)
    c.string.encode(state, value.name)
    c.string.encode(state, value.canonicalPreimage)
  },
  decode (state) {
    return {
      recipeId: c.uint.decode(state),
      name: c.string.decode(state),
      canonicalPreimage: c.string.decode(state)
    }
  }
}

const schemasEncoding = list(schemaEncoding)
const profilesEncoding = list(profileEncoding)
const variantsEncoding = list(variantEncoding)
const domainsEncoding = list(domainEncoding)
const hashRecipesEncoding = list(hashRecipeEncoding)

export const wireAbiV3Encoding = {
  preencode (state, value) {
    c.string.preencode(state, value.magic)
    c.uint.preencode(state, value.formatVersion)
    c.string.preencode(state, value.protocolFamily)
    c.uint.preencode(state, value.protocolMajor)
    c.uint.preencode(state, value.protocolMinor)
    c.buffer.preencode(state, value.baseWireV2AbiHash)
    c.uint.preencode(state, value.baseSchemaCount)
    uintList.preencode(state, value.compatibilityOnlySchemaIds)
    schemasEncoding.preencode(state, value.additionalSchemas)
    profilesEncoding.preencode(state, value.releaseProfiles)
    variantsEncoding.preencode(state, value.successorTransportVariants)
    domainsEncoding.preencode(state, value.additionalDomains)
    c.uint.preencode(state, value.hashDomainPurposeId)
    hashRecipesEncoding.preencode(state, value.hashRecipes)
    c.uint.preencode(state, value.forwardReadinessOperationBits)
  },
  encode (state, value) {
    c.string.encode(state, value.magic)
    c.uint.encode(state, value.formatVersion)
    c.string.encode(state, value.protocolFamily)
    c.uint.encode(state, value.protocolMajor)
    c.uint.encode(state, value.protocolMinor)
    c.buffer.encode(state, value.baseWireV2AbiHash)
    c.uint.encode(state, value.baseSchemaCount)
    uintList.encode(state, value.compatibilityOnlySchemaIds)
    schemasEncoding.encode(state, value.additionalSchemas)
    profilesEncoding.encode(state, value.releaseProfiles)
    variantsEncoding.encode(state, value.successorTransportVariants)
    domainsEncoding.encode(state, value.additionalDomains)
    c.uint.encode(state, value.hashDomainPurposeId)
    hashRecipesEncoding.encode(state, value.hashRecipes)
    c.uint.encode(state, value.forwardReadinessOperationBits)
  },
  decode (state) {
    return {
      magic: c.string.decode(state),
      formatVersion: c.uint.decode(state),
      protocolFamily: c.string.decode(state),
      protocolMajor: c.uint.decode(state),
      protocolMinor: c.uint.decode(state),
      baseWireV2AbiHash: b4a.from(c.buffer.decode(state)),
      baseSchemaCount: c.uint.decode(state),
      compatibilityOnlySchemaIds: uintList.decode(state),
      additionalSchemas: schemasEncoding.decode(state),
      releaseProfiles: profilesEncoding.decode(state),
      successorTransportVariants: variantsEncoding.decode(state),
      additionalDomains: domainsEncoding.decode(state),
      hashDomainPurposeId: c.uint.decode(state),
      hashRecipes: hashRecipesEncoding.decode(state),
      forwardReadinessOperationBits: c.uint.decode(state)
    }
  }
}

const declarationBytes = schema => b4a.from(JSON.stringify({ name: schema.schemaName, fields: schema.fields }), 'utf8')

export function createWireAbiV3Value (baseWireV2AbiHash) {
  if (!baseWireV2AbiHash || baseWireV2AbiHash.byteLength !== 32) fail('baseWireV2AbiHash must be exactly 32 bytes')
  return {
    magic: 'hiverelay-blind-wire-abi-v3',
    formatVersion: WIRE_V3_PROTOCOL.abiFormatVersion,
    protocolFamily: 'hiverelay-blind-wire',
    protocolMajor: WIRE_V3_PROTOCOL.major,
    protocolMinor: WIRE_V3_PROTOCOL.minor,
    baseWireV2AbiHash: b4a.from(baseWireV2AbiHash),
    baseSchemaCount: 75,
    compatibilityOnlySchemaIds: [74, 75],
    additionalSchemas: WIRE_V3_SCHEMA_DECLARATIONS.map(schema => ({
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
    successorTransportVariants: FORWARD_HTTPS_SUCCESSOR_TRANSPORT_VARIANTS_V3.map(value => ({ ...value })),
    additionalDomains: Object.values(FORWARD_HTTPS_DOMAIN_V3).map(value => ({ ...value })),
    hashDomainPurposeId: WIRE_V3_HASH_DOMAIN_PURPOSE.purposeId,
    hashRecipes: WIRE_V3_HASH_RECIPES.map(value => ({ ...value })),
    forwardReadinessOperationBits: 0
  }
}

export function encodeWireAbiV3 (value) {
  const state = { start: 0, end: 0, buffer: null }
  wireAbiV3Encoding.preencode(state, value)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  wireAbiV3Encoding.encode(state, value)
  if (state.start !== state.end) fail('WIRE v3 ABI encoder did not fill its allocation')
  return state.buffer
}

function exactIds (values, expected, field) {
  if (values.length !== expected.length || values.some((value, index) => value !== expected[index])) fail(`${field} fixed order is invalid`)
}

export function decodeWireAbiV3 (input) {
  const state = { start: 0, end: input.byteLength, buffer: input }
  const value = wireAbiV3Encoding.decode(state)
  if (state.start !== state.end) fail('trailing bytes after WIRE v3 ABI')
  if (!b4a.equals(encodeWireAbiV3(value), input)) fail('WIRE v3 ABI is not canonical')
  if (value.magic !== 'hiverelay-blind-wire-abi-v3' || value.formatVersion !== 3 ||
      value.protocolFamily !== 'hiverelay-blind-wire' || value.protocolMajor !== 1 || value.protocolMinor !== 2 ||
      value.baseWireV2AbiHash.byteLength !== 32 || value.baseSchemaCount !== 75 ||
      value.hashDomainPurposeId !== 4 || value.forwardReadinessOperationBits !== 0) {
    fail('WIRE v3 ABI fixed header is invalid')
  }
  exactIds(value.compatibilityOnlySchemaIds, [74, 75], 'compatibility-only schema IDs')
  exactIds(value.additionalSchemas.map(schema => schema.schemaId), [76, 77], 'additional schema IDs')
  const profiles = value.releaseProfiles
  if (profiles.length !== 2 || profiles[0].profileId !== 1 || profiles[0].canonicalName !== 'LIMITED_PUBLIC_TEST_V1' ||
      profiles[0].operationBits !== 131071 || profiles[0].isDefault !== true || profiles[1].profileId !== 2 ||
      profiles[1].canonicalName !== 'LIMITED_PUBLIC_TEST_FORWARD_ONE_HOP_V1' || profiles[1].operationBits !== 4063231 ||
      profiles[1].isDefault !== false) {
    fail('releaseProfiles fixed logical rows or order are invalid')
  }
  exactIds(value.successorTransportVariants.map(variant => variant.requestKind), [1, 2, 3, 4], 'successor transport variants')
  exactIds(value.additionalDomains.map(domain => domain.domainId), [18, 113, 114, 115, 215, 216, 217, 218, 219], 'additional domains')
  exactIds(value.hashRecipes.map(recipe => recipe.recipeId), [3, 4], 'hash recipes')
  for (const domain of value.additionalDomains.slice(5)) {
    if (domain.purposeId !== 4 || domain.purpose !== 'HASH_DOMAIN' || (domain.recipeId !== 3 && domain.recipeId !== 4)) {
      fail('WIRE v3 HASH domain semantics are invalid')
    }
  }
  return value
}
