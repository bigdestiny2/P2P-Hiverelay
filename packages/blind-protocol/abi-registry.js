import b4a from 'b4a'
import c from 'compact-encoding'
import {
  ADMISSION_COST_RULES,
  ADMISSION_CONFORMANCE_CLASS,
  ADMISSION_MODE,
  AGE_BAND,
  ALL_OPERATION_BITS,
  ABI_STATUS,
  CELL_SIZE_CLASS,
  CELL_RECEIPT_RESULT,
  CLOCK_UNSAFE_OPERATION_BITS,
  CONTROL_CHANNEL_ID_TYPE,
  CORE_SESSION_CLASS,
  CORE_ACK_RESULT,
  COST_CLASS_RULE_ID,
  DRAINING_OPERATION_BITS,
  DISPATCH_LIMITS,
  DURABILITY_PROFILE_ID,
  DURABILITY_RPO_BAND,
  DURABILITY_RTO_BAND,
  DOMAIN_PURPOSE,
  DOMAIN_RECIPE,
  DOMAIN_REGISTRY,
  ENDPOINT_ROLE,
  ENDPOINT_LIMITS,
  ERROR_CODE,
  ERROR_PROFILE_ID,
  ERROR_PROFILE_ROWS,
  ERROR_RETRY_AFTER_MODE,
  FAMILY,
  FAMILY_ROUTES,
  FORWARD_CLOSE_KIND,
  FORWARD_CIRCUIT_CLASS,
  FRAME_KIND,
  IMPLEMENTED_SCHEMAS,
  INBOX_APPEND_AUTH_MODE,
  INBOX_APPEND_RESULT,
  INBOX_FRAME_CLASS,
  INBOX_MANAGE_OPERATION,
  INBOX_RECEIPT_RESULT,
  LEASE_CLASS_EPOCHS,
  OPERATION,
  OPERATION_CAP_ROWS,
  OPERATION_PROFILE_ROWS,
  OHTTP_TRANSPORT_ERROR_CODE,
  OHTTP_TRANSPORT_ERROR_ROWS,
  OHTTP_DELIVERY_BOUNDARY,
  OHTTP_RETRY_ACTION,
  OPERATION_COUNT,
  OUTER_CLASS,
  PROTOCOL,
  PRIVACY_PROFILE,
  PUBLIC_PROFILE_LIMITS,
  REQUEST_COMMITMENT_DOMAIN_ID,
  REDUNDANCY_CLASS,
  RESULT_SIGNATURE_DOMAIN_ID,
  SCHEMA_CATEGORY,
  STREAM_TRANSITION,
  STREAM_WIRE_CLASS,
  STORE_LIFECYCLE_STATE,
  TRANSPORT_EXPORTER_ID,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  HEALTH_CLOCK_STATE,
  HEALTH_INTEGRITY_STATE,
  HEALTH_REBALANCE_STATE,
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  assertReleaseReady,
  draftSchemaId,
  schemaCategory
} from './registry.js'
import {
  admissionCostRuleV1,
  domainRegistryEntryV1,
  errorProfileEntryV1,
  operationProfileV1
} from './schemas.js'

function encodeWith (encoding, value) {
  const state = { start: 0, end: 0, buffer: null }
  encoding.preencode(state, value)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  encoding.encode(state, value)
  return state.buffer
}

function listEncoding (itemEncoding) {
  return {
    preencode (state, values) {
      c.uint.preencode(state, values.length)
      for (const value of values) itemEncoding.preencode(state, value)
    },
    encode (state, values) {
      c.uint.encode(state, values.length)
      for (const value of values) itemEncoding.encode(state, value)
    }
  }
}

const nameIdEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.id)
    c.string.preencode(state, value.name)
  },
  encode (state, value) {
    c.uint.encode(state, value.id)
    c.string.encode(state, value.name)
  }
}

const classEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.id)
    c.uint.preencode(state, value.value)
  },
  encode (state, value) {
    c.uint.encode(state, value.id)
    c.uint.encode(state, value.value)
  }
}

const namedValueEncoding = {
  preencode (state, value) {
    c.string.preencode(state, value.name)
    c.uint.preencode(state, value.value)
  },
  encode (state, value) {
    c.string.encode(state, value.name)
    c.uint.encode(state, value.value)
  }
}

const forwardCircuitClassEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.id)
    c.uint.preencode(state, value.grantedInitialWindow)
    c.uint.preencode(state, value.maxCircuitBytes)
    c.uint.preencode(state, value.idleMillis)
    c.uint.preencode(state, value.lifetimeMillis)
  },
  encode (state, value) {
    c.uint.encode(state, value.id)
    c.uint.encode(state, value.grantedInitialWindow)
    c.uint.encode(state, value.maxCircuitBytes)
    c.uint.encode(state, value.idleMillis)
    c.uint.encode(state, value.lifetimeMillis)
  }
}

const coreSessionClassEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.id)
    c.uint.preencode(state, value.maxSessionBytes)
    c.uint.preencode(state, value.idleMillis)
    c.uint.preencode(state, value.lifetimeMillis)
  },
  encode (state, value) {
    c.uint.encode(state, value.id)
    c.uint.encode(state, value.maxSessionBytes)
    c.uint.encode(state, value.idleMillis)
    c.uint.encode(state, value.lifetimeMillis)
  }
}

const operationCapEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.familyId)
    c.uint.preencode(state, value.operationId)
    c.uint.preencode(state, value.requestSchemaId)
    c.uint.preencode(state, value.resultSchemaId)
    c.uint.preencode(state, value.maxRequestBodyBytes)
    c.uint.preencode(state, value.maxResultBodyBytes)
  },
  encode (state, value) {
    c.uint.encode(state, value.familyId)
    c.uint.encode(state, value.operationId)
    c.uint.encode(state, value.requestSchemaId)
    c.uint.encode(state, value.resultSchemaId)
    c.uint.encode(state, value.maxRequestBodyBytes)
    c.uint.encode(state, value.maxResultBodyBytes)
  }
}

const operationBitEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.familyId)
    c.uint.preencode(state, value.operationId)
    c.uint.preencode(state, value.ordinal)
    c.uint.preencode(state, value.bit)
  },
  encode (state, value) {
    c.uint.encode(state, value.familyId)
    c.uint.encode(state, value.operationId)
    c.uint.encode(state, value.ordinal)
    c.uint.encode(state, value.bit)
  }
}

const ohttpTransportErrorProfileEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.code)
    c.uint.preencode(state, value.protectedStatus)
    c.uint.preencode(state, value.deliveryBoundary)
    c.uint.preencode(state, value.retryAction)
  },
  encode (state, value) {
    c.uint.encode(state, value.code)
    c.uint.encode(state, value.protectedStatus)
    c.uint.encode(state, value.deliveryBoundary)
    c.uint.encode(state, value.retryAction)
  }
}

const familyEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.id)
    c.string.preencode(state, value.name)
    c.string.preencode(state, value.route)
    listEncoding(nameIdEncoding).preencode(state, value.operations)
  },
  encode (state, value) {
    c.uint.encode(state, value.id)
    c.string.encode(state, value.name)
    c.string.encode(state, value.route)
    listEncoding(nameIdEncoding).encode(state, value.operations)
  }
}

const schemaEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.category)
    c.uint.preencode(state, value.categoryLocalSchemaId)
    c.string.preencode(state, value.name)
    c.buffer.preencode(state, value.canonicalSchemaBytes)
  },
  encode (state, value) {
    c.uint.encode(state, value.category)
    c.uint.encode(state, value.categoryLocalSchemaId)
    c.string.encode(state, value.name)
    c.buffer.encode(state, value.canonicalSchemaBytes)
  }
}

const wireAbiV1Encoding = {
  preencode (state, value) {
    c.string.preencode(state, value.magic)
    c.uint.preencode(state, value.formatVersion)
    c.string.preencode(state, value.protocolFamily)
    c.uint.preencode(state, value.protocolMajor)
    c.uint.preencode(state, value.protocolMinor)
    c.string.preencode(state, value.mediaType)
    listEncoding(familyEncoding).preencode(state, value.families)
    listEncoding(nameIdEncoding).preencode(state, value.schemaCategories)
    listEncoding(nameIdEncoding).preencode(state, value.frameKinds)
    listEncoding(nameIdEncoding).preencode(state, value.admissionModes)
    listEncoding(nameIdEncoding).preencode(state, value.streamTransitions)
    listEncoding(nameIdEncoding).preencode(state, value.transportSupportBits)
    listEncoding(nameIdEncoding).preencode(state, value.endpointRoles)
    listEncoding(nameIdEncoding).preencode(state, value.privacyProfiles)
    listEncoding(nameIdEncoding).preencode(state, value.domainPurposes)
    listEncoding(nameIdEncoding).preencode(state, value.domainRecipes)
    listEncoding(nameIdEncoding).preencode(state, value.costClassRuleKinds)
    listEncoding(nameIdEncoding).preencode(state, value.errorCodes)
    listEncoding(nameIdEncoding).preencode(state, value.errorProfileIds)
    listEncoding(nameIdEncoding).preencode(state, value.errorRetryAfterModes)
    listEncoding(nameIdEncoding).preencode(state, value.ohttpTransportErrorCodes)
    listEncoding(nameIdEncoding).preencode(state, value.ohttpDeliveryBoundaries)
    listEncoding(nameIdEncoding).preencode(state, value.ohttpRetryActions)
    listEncoding(nameIdEncoding).preencode(state, value.transportIds)
    listEncoding(nameIdEncoding).preencode(state, value.transportExporterIds)
    listEncoding(nameIdEncoding).preencode(state, value.controlChannelIdTypes)
    listEncoding(nameIdEncoding).preencode(state, value.durabilityProfileIds)
    listEncoding(nameIdEncoding).preencode(state, value.durabilityRpoBands)
    listEncoding(nameIdEncoding).preencode(state, value.durabilityRtoBands)
    listEncoding(nameIdEncoding).preencode(state, value.redundancyClasses)
    listEncoding(nameIdEncoding).preencode(state, value.ageBands)
    listEncoding(nameIdEncoding).preencode(state, value.cellReceiptResults)
    listEncoding(nameIdEncoding).preencode(state, value.inboxManageOperations)
    listEncoding(nameIdEncoding).preencode(state, value.inboxAppendAuthModes)
    listEncoding(nameIdEncoding).preencode(state, value.inboxReceiptResults)
    listEncoding(nameIdEncoding).preencode(state, value.inboxAppendResults)
    listEncoding(nameIdEncoding).preencode(state, value.admissionConformanceClasses)
    listEncoding(nameIdEncoding).preencode(state, value.coreAckResults)
    listEncoding(nameIdEncoding).preencode(state, value.forwardCloseKinds)
    listEncoding(nameIdEncoding).preencode(state, value.storeLifecycleStates)
    listEncoding(nameIdEncoding).preencode(state, value.healthClockStates)
    listEncoding(nameIdEncoding).preencode(state, value.healthIntegrityStates)
    listEncoding(nameIdEncoding).preencode(state, value.healthRebalanceStates)
    listEncoding(classEncoding).preencode(state, value.cellClasses)
    listEncoding(classEncoding).preencode(state, value.inboxClasses)
    listEncoding(classEncoding).preencode(state, value.outerClasses)
    listEncoding(classEncoding).preencode(state, value.streamClasses)
    listEncoding(classEncoding).preencode(state, value.leaseClasses)
    listEncoding(namedValueEncoding).preencode(state, value.dispatchLimits)
    listEncoding(namedValueEncoding).preencode(state, value.endpointLimits)
    listEncoding(namedValueEncoding).preencode(state, value.publicProfileLimits)
    listEncoding(namedValueEncoding).preencode(state, value.operationRegistryValues)
    listEncoding(forwardCircuitClassEncoding).preencode(state, value.forwardCircuitClasses)
    listEncoding(coreSessionClassEncoding).preencode(state, value.coreSessionClasses)
    listEncoding(domainRegistryEntryV1).preencode(state, value.domainRegistry)
    listEncoding(errorProfileEntryV1).preencode(state, value.errorProfiles)
    listEncoding(ohttpTransportErrorProfileEncoding).preencode(state, value.ohttpTransportErrorProfiles)
    listEncoding(admissionCostRuleV1).preencode(state, value.admissionCostRules)
    listEncoding(operationProfileV1).preencode(state, value.operationProfiles)
    listEncoding(operationCapEncoding).preencode(state, value.operationCaps)
    listEncoding(operationBitEncoding).preencode(state, value.operationBits)
    listEncoding(schemaEncoding).preencode(state, value.implementedSchemas)
    listEncoding(c.string).preencode(state, value.requiredSchemaNames)
    listEncoding(c.string).preencode(state, value.missingSchemaNames)
  },
  encode (state, value) {
    c.string.encode(state, value.magic)
    c.uint.encode(state, value.formatVersion)
    c.string.encode(state, value.protocolFamily)
    c.uint.encode(state, value.protocolMajor)
    c.uint.encode(state, value.protocolMinor)
    c.string.encode(state, value.mediaType)
    listEncoding(familyEncoding).encode(state, value.families)
    listEncoding(nameIdEncoding).encode(state, value.schemaCategories)
    listEncoding(nameIdEncoding).encode(state, value.frameKinds)
    listEncoding(nameIdEncoding).encode(state, value.admissionModes)
    listEncoding(nameIdEncoding).encode(state, value.streamTransitions)
    listEncoding(nameIdEncoding).encode(state, value.transportSupportBits)
    listEncoding(nameIdEncoding).encode(state, value.endpointRoles)
    listEncoding(nameIdEncoding).encode(state, value.privacyProfiles)
    listEncoding(nameIdEncoding).encode(state, value.domainPurposes)
    listEncoding(nameIdEncoding).encode(state, value.domainRecipes)
    listEncoding(nameIdEncoding).encode(state, value.costClassRuleKinds)
    listEncoding(nameIdEncoding).encode(state, value.errorCodes)
    listEncoding(nameIdEncoding).encode(state, value.errorProfileIds)
    listEncoding(nameIdEncoding).encode(state, value.errorRetryAfterModes)
    listEncoding(nameIdEncoding).encode(state, value.ohttpTransportErrorCodes)
    listEncoding(nameIdEncoding).encode(state, value.ohttpDeliveryBoundaries)
    listEncoding(nameIdEncoding).encode(state, value.ohttpRetryActions)
    listEncoding(nameIdEncoding).encode(state, value.transportIds)
    listEncoding(nameIdEncoding).encode(state, value.transportExporterIds)
    listEncoding(nameIdEncoding).encode(state, value.controlChannelIdTypes)
    listEncoding(nameIdEncoding).encode(state, value.durabilityProfileIds)
    listEncoding(nameIdEncoding).encode(state, value.durabilityRpoBands)
    listEncoding(nameIdEncoding).encode(state, value.durabilityRtoBands)
    listEncoding(nameIdEncoding).encode(state, value.redundancyClasses)
    listEncoding(nameIdEncoding).encode(state, value.ageBands)
    listEncoding(nameIdEncoding).encode(state, value.cellReceiptResults)
    listEncoding(nameIdEncoding).encode(state, value.inboxManageOperations)
    listEncoding(nameIdEncoding).encode(state, value.inboxAppendAuthModes)
    listEncoding(nameIdEncoding).encode(state, value.inboxReceiptResults)
    listEncoding(nameIdEncoding).encode(state, value.inboxAppendResults)
    listEncoding(nameIdEncoding).encode(state, value.admissionConformanceClasses)
    listEncoding(nameIdEncoding).encode(state, value.coreAckResults)
    listEncoding(nameIdEncoding).encode(state, value.forwardCloseKinds)
    listEncoding(nameIdEncoding).encode(state, value.storeLifecycleStates)
    listEncoding(nameIdEncoding).encode(state, value.healthClockStates)
    listEncoding(nameIdEncoding).encode(state, value.healthIntegrityStates)
    listEncoding(nameIdEncoding).encode(state, value.healthRebalanceStates)
    listEncoding(classEncoding).encode(state, value.cellClasses)
    listEncoding(classEncoding).encode(state, value.inboxClasses)
    listEncoding(classEncoding).encode(state, value.outerClasses)
    listEncoding(classEncoding).encode(state, value.streamClasses)
    listEncoding(classEncoding).encode(state, value.leaseClasses)
    listEncoding(namedValueEncoding).encode(state, value.dispatchLimits)
    listEncoding(namedValueEncoding).encode(state, value.endpointLimits)
    listEncoding(namedValueEncoding).encode(state, value.publicProfileLimits)
    listEncoding(namedValueEncoding).encode(state, value.operationRegistryValues)
    listEncoding(forwardCircuitClassEncoding).encode(state, value.forwardCircuitClasses)
    listEncoding(coreSessionClassEncoding).encode(state, value.coreSessionClasses)
    listEncoding(domainRegistryEntryV1).encode(state, value.domainRegistry)
    listEncoding(errorProfileEntryV1).encode(state, value.errorProfiles)
    listEncoding(ohttpTransportErrorProfileEncoding).encode(state, value.ohttpTransportErrorProfiles)
    listEncoding(admissionCostRuleV1).encode(state, value.admissionCostRules)
    listEncoding(operationProfileV1).encode(state, value.operationProfiles)
    listEncoding(operationCapEncoding).encode(state, value.operationCaps)
    listEncoding(operationBitEncoding).encode(state, value.operationBits)
    listEncoding(schemaEncoding).encode(state, value.implementedSchemas)
    listEncoding(c.string).encode(state, value.requiredSchemaNames)
    listEncoding(c.string).encode(state, value.missingSchemaNames)
  }
}

function sortedNameIds (object) {
  return Object.entries(object)
    .map(([name, id]) => ({ name, id }))
    .sort((a, b) => a.id - b.id || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
}

function sortedClasses (object) {
  return Object.entries(object)
    .map(([id, value]) => ({ id: Number(id), value }))
    .sort((a, b) => a.id - b.id)
}

function sortedNamedValues (object) {
  return Object.entries(object)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)
}

function sortedTupleClasses (object) {
  return Object.entries(object)
    .map(([id, value]) => ({ id: Number(id), ...value }))
    .sort((a, b) => a.id - b.id)
}

function assertClosedRegistries () {
  const requiredDomainIds = [
    ...Object.values(REQUEST_COMMITMENT_DOMAIN_ID),
    ...Object.values(RESULT_SIGNATURE_DOMAIN_ID),
    ...Object.values(AUXILIARY_SIGNATURE_DOMAIN_ID)
  ]
  if (DOMAIN_REGISTRY.length !== requiredDomainIds.length) {
    throw new Error('domain registry is missing or has unknown rows')
  }
  const seenDomainBytes = new Set()
  for (let index = 0; index < DOMAIN_REGISTRY.length; index++) {
    const entry = DOMAIN_REGISTRY[index]
    const expectedId = requiredDomainIds[index]
    const expectedPurpose = index < 16
      ? DOMAIN_PURPOSE.REQUEST_COMMITMENT
      : index < 27 ? DOMAIN_PURPOSE.RESULT_SIGNATURE : DOMAIN_PURPOSE.AUXILIARY_SIGNATURE
    const expectedRecipe = expectedPurpose === DOMAIN_PURPOSE.REQUEST_COMMITMENT
      ? DOMAIN_RECIPE.OPERATION_DEFINED_COMMITMENT_PREIMAGE
      : DOMAIN_RECIPE.ED25519_DOMAIN_LEN64_PAYLOAD
    if (entry.domainId !== expectedId || entry.purpose !== expectedPurpose || entry.recipeId !== expectedRecipe) {
      throw new Error('domain registry has an unknown ID or wrong purpose/recipe')
    }
    if (!/^[\x20-\x7e]{1,96}$/.test(entry.exactAsciiBytes) || seenDomainBytes.has(entry.exactAsciiBytes)) {
      throw new Error('domain registry has duplicate or non-canonical ASCII bytes')
    }
    seenDomainBytes.add(entry.exactAsciiBytes)
  }

  const retryableCodes = new Set([9, 16, 17, 18])
  if (ERROR_PROFILE_ROWS.length !== 20) throw new Error('error profile 1 must have exactly 20 rows')
  for (let index = 0; index < ERROR_PROFILE_ROWS.length; index++) {
    const entry = ERROR_PROFILE_ROWS[index]
    const code = index + 1
    if (entry.errorProfileId !== ERROR_PROFILE_ID.CANONICAL_V1 || entry.code !== code ||
        entry.directCorrelatedStatus !== 200 || entry.protectedInnerStatus !== 200 ||
        entry.retryable !== (retryableCodes.has(code) ? 1 : 0) ||
        entry.retryAfterMode !== (code === 18 ? 1 : 0)) {
      throw new Error('error profile 1 has an unknown, missing, duplicate, or inconsistent row')
    }
  }

  if (OHTTP_TRANSPORT_ERROR_ROWS.length !== 3) throw new Error('OHTTP transport error mapping must have exactly three rows')
  const expectedTransportRows = [
    [1, 400, OHTTP_DELIVERY_BOUNDARY.BEFORE_VALID_DISPATCH, OHTTP_RETRY_ACTION.NONE],
    [2, 503, OHTTP_DELIVERY_BOUNDARY.BEFORE_TARGET_HANDOFF, OHTTP_RETRY_ACTION.FRESH_HPKE_SAME_DESTINATION_POLICY],
    [3, 504, OHTTP_DELIVERY_BOUNDARY.MAY_HAVE_REACHED_TARGET, OHTTP_RETRY_ACTION.RECONCILE_WITHOUT_AUTOMATIC_RETRY]
  ]
  for (let index = 0; index < expectedTransportRows.length; index++) {
    const row = OHTTP_TRANSPORT_ERROR_ROWS[index]
    const expected = expectedTransportRows[index]
    if (row.code !== expected[0] || row.protectedStatus !== expected[1] ||
        row.deliveryBoundary !== expected[2] || row.retryAction !== expected[3]) {
      throw new Error('OHTTP transport error mapping has an unknown or misplaced row')
    }
  }

  if (OPERATION_CAP_ROWS.length !== OPERATION_PROFILE_ROWS.length || OPERATION_CAP_ROWS.some((row, index) => {
    const profile = OPERATION_PROFILE_ROWS[index]
    return row.familyId !== profile.familyId || row.operationId !== profile.operationId ||
      row.requestSchemaId !== profile.requestSchemaId || row.resultSchemaId !== profile.resultSchemaId ||
      row.maxRequestBodyBytes !== profile.maxRequestBodyBytes || row.maxResultBodyBytes !== profile.maxResultBodyBytes
  })) throw new Error('operation cap registry is not the exact projection of operation profiles')
}

export function wireAbiRegistryValue (schemaCatalogEntries = null) {
  assertClosedRegistries()
  const families = Object.entries(FAMILY)
    .map(([name, id]) => ({
      name,
      id,
      route: FAMILY_ROUTES[id],
      operations: sortedNameIds(OPERATION[name])
    }))
    .sort((a, b) => a.id - b.id)

  const catalogByName = schemaCatalogEntries == null
    ? null
    : new Map(schemaCatalogEntries.map(entry => [b4a.toString(entry.schemaName, 'ascii'), entry]))
  const wireSchemas = IMPLEMENTED_SCHEMAS
    .filter(schema => schemaCategory(schema.name) === SCHEMA_CATEGORY.WIRE)
    .map(schema => {
      const catalog = catalogByName && catalogByName.get(schema.name)
      if (catalog) {
        return {
          category: catalog.category,
          categoryLocalSchemaId: catalog.categoryLocalSchemaId,
          name: schema.name,
          canonicalSchemaBytes: catalog.canonicalSchemaBytes
        }
      }
      // Diagnostic package callers can inspect/encode the registry without the
      // stable-master source file. Authority generation always supplies the
      // compiled master catalog and therefore never uses this fallback.
      return {
        category: SCHEMA_CATEGORY.WIRE,
        categoryLocalSchemaId: draftSchemaId(schema.name),
        name: schema.name,
        canonicalSchemaBytes: b4a.from(JSON.stringify(schema.fields), 'utf8')
      }
    })
    .sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)
  if (catalogByName && (wireSchemas.some(schema => schema.category !== SCHEMA_CATEGORY.WIRE) ||
      wireSchemas.some(schema => schema.categoryLocalSchemaId === 0) ||
      wireSchemas.length !== ABI_STATUS.wireRequiredSchemaNames.length)) {
    throw new Error('compiled master catalog does not contain the complete WIRE schema set')
  }

  return {
    magic: 'hiverelay-blind-abi-v1',
    formatVersion: 1,
    protocolFamily: PROTOCOL.family,
    protocolMajor: PROTOCOL.major,
    protocolMinor: PROTOCOL.minor,
    mediaType: PROTOCOL.mediaType,
    families,
    schemaCategories: sortedNameIds(SCHEMA_CATEGORY),
    frameKinds: sortedNameIds(FRAME_KIND),
    admissionModes: sortedNameIds(ADMISSION_MODE),
    streamTransitions: sortedNameIds(STREAM_TRANSITION),
    transportSupportBits: sortedNameIds(TRANSPORT_SUPPORT),
    endpointRoles: sortedNameIds(ENDPOINT_ROLE),
    privacyProfiles: sortedNameIds(PRIVACY_PROFILE),
    domainPurposes: sortedNameIds(DOMAIN_PURPOSE),
    domainRecipes: sortedNameIds(DOMAIN_RECIPE),
    costClassRuleKinds: sortedNameIds(COST_CLASS_RULE_ID),
    errorCodes: sortedNameIds(ERROR_CODE),
    errorProfileIds: sortedNameIds(ERROR_PROFILE_ID),
    errorRetryAfterModes: sortedNameIds(ERROR_RETRY_AFTER_MODE),
    ohttpTransportErrorCodes: sortedNameIds(OHTTP_TRANSPORT_ERROR_CODE),
    ohttpDeliveryBoundaries: sortedNameIds(OHTTP_DELIVERY_BOUNDARY),
    ohttpRetryActions: sortedNameIds(OHTTP_RETRY_ACTION),
    transportIds: sortedNameIds(TRANSPORT_ID),
    transportExporterIds: sortedNameIds(TRANSPORT_EXPORTER_ID),
    controlChannelIdTypes: sortedNameIds(CONTROL_CHANNEL_ID_TYPE),
    durabilityProfileIds: sortedNameIds(DURABILITY_PROFILE_ID),
    durabilityRpoBands: sortedNameIds(DURABILITY_RPO_BAND),
    durabilityRtoBands: sortedNameIds(DURABILITY_RTO_BAND),
    redundancyClasses: sortedNameIds(REDUNDANCY_CLASS),
    ageBands: sortedNameIds(AGE_BAND),
    cellReceiptResults: sortedNameIds(CELL_RECEIPT_RESULT),
    inboxManageOperations: sortedNameIds(INBOX_MANAGE_OPERATION),
    inboxAppendAuthModes: sortedNameIds(INBOX_APPEND_AUTH_MODE),
    inboxReceiptResults: sortedNameIds(INBOX_RECEIPT_RESULT),
    inboxAppendResults: sortedNameIds(INBOX_APPEND_RESULT),
    admissionConformanceClasses: sortedNameIds(ADMISSION_CONFORMANCE_CLASS),
    coreAckResults: sortedNameIds(CORE_ACK_RESULT),
    forwardCloseKinds: sortedNameIds(FORWARD_CLOSE_KIND),
    storeLifecycleStates: sortedNameIds(STORE_LIFECYCLE_STATE),
    healthClockStates: sortedNameIds(HEALTH_CLOCK_STATE),
    healthIntegrityStates: sortedNameIds(HEALTH_INTEGRITY_STATE),
    healthRebalanceStates: sortedNameIds(HEALTH_REBALANCE_STATE),
    cellClasses: sortedClasses(CELL_SIZE_CLASS),
    inboxClasses: sortedClasses(INBOX_FRAME_CLASS),
    outerClasses: sortedClasses(OUTER_CLASS),
    streamClasses: sortedClasses(STREAM_WIRE_CLASS),
    leaseClasses: sortedClasses(LEASE_CLASS_EPOCHS),
    dispatchLimits: sortedNamedValues(DISPATCH_LIMITS),
    endpointLimits: sortedNamedValues(ENDPOINT_LIMITS),
    publicProfileLimits: sortedNamedValues(PUBLIC_PROFILE_LIMITS),
    operationRegistryValues: sortedNamedValues({
      ALL_OPERATION_BITS,
      CLOCK_UNSAFE_OPERATION_BITS,
      DRAINING_OPERATION_BITS,
      OPERATION_COUNT
    }),
    forwardCircuitClasses: sortedTupleClasses(FORWARD_CIRCUIT_CLASS),
    coreSessionClasses: sortedTupleClasses(CORE_SESSION_CLASS),
    domainRegistry: DOMAIN_REGISTRY.map(entry => ({
      ...entry,
      exactAsciiBytes: b4a.from(entry.exactAsciiBytes, 'ascii')
    })),
    errorProfiles: ERROR_PROFILE_ROWS,
    ohttpTransportErrorProfiles: OHTTP_TRANSPORT_ERROR_ROWS,
    admissionCostRules: ADMISSION_COST_RULES,
    operationProfiles: OPERATION_PROFILE_ROWS,
    operationCaps: OPERATION_CAP_ROWS,
    operationBits: OPERATION_PROFILE_ROWS.map((row, ordinal) => ({
      familyId: row.familyId,
      operationId: row.operationId,
      ordinal,
      bit: 2 ** ordinal
    })),
    implementedSchemas: wireSchemas,
    requiredSchemaNames: [...ABI_STATUS.wireRequiredSchemaNames].sort(),
    missingSchemaNames: [...ABI_STATUS.wireMissingSchemaNames].sort()
  }
}

export function encodeWireAbiRegistry (schemaCatalogEntries = null) {
  // A candidate registry may intentionally describe not-yet-frozen rows so it
  // can be reviewed and exercised before authority regeneration.  Never let
  // the final-authority encoder turn that candidate into publishable bytes.
  // This also produces the governing release blocker instead of an incidental
  // validation error against the older frozen runtime registry.
  assertReleaseReady()
  return encodeWith(wireAbiV1Encoding, wireAbiRegistryValue(schemaCatalogEntries))
}

// Transitional API aliases share the final-authority gate. A review candidate
// may expose unfrozen rows through the value API, but neither encoder emits
// bytes until the candidate is release-ready; after freezing both names remain
// byte-identical. The aliases may be removed only in a later package major.
export const draftAbiRegistryValue = wireAbiRegistryValue
export const encodeDraftAbiRegistry = encodeWireAbiRegistry
export const draftRegistryEncoding = wireAbiV1Encoding

export { wireAbiV1Encoding }
