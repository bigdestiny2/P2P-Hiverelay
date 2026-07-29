import {
  CELL_SIZE_CLASS,
  DISPATCH_LIMITS,
  FAMILY,
  INBOX_FRAME_CLASS,
  OPERATION,
  OUTER_CLASS
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { fail } from './errors.js'
import { selectedOperationProfile } from './selected-operation-profile.js'

export const WORKLOAD = Object.freeze({
  RECORDS: 'records',
  RENDEZVOUS: 'rendezvous',
  HISTORY: 'history',
  LIVE: 'live',
  SEMANTIC: 'semantic'
})

export const PRIMITIVE = Object.freeze({
  CELL: 'cell',
  INBOX: 'inbox',
  CORE: 'core',
  P2P_DIRECT: 'p2p-direct',
  LOCAL_COMPUTE: 'local-compute',
  EXTERNAL: 'external'
})

export const RUNTIME = Object.freeze({
  BROWSER: 'browser',
  NATIVE: 'native',
  TOR_BROWSER: 'tor-browser'
})

export const PRIVACY_PRESET = Object.freeze({
  FAST: 'fast',
  PRIVATE: 'private',
  HIGH_PRIVACY: 'high-privacy',
  CUSTOM: 'custom'
})

export const TRANSPORT_REQUIREMENT = Object.freeze({
  DIRECT: 'direct',
  SOURCE_SEPARATED: 'source-separated',
  TOR: 'tor'
})

export const TRANSPORT_PROFILE = Object.freeze({
  DIRECT: 'direct-blind-v1',
  OHTTP: 'split-web-ohttp-v1',
  SPLIT_NATIVE: 'split-native-protomux-v1',
  TOR_NATIVE: 'tor-native-full-v1',
  TOR_BROWSER: 'tor-browser-full-v1',
  P2P_DIRECT: 'p2p-direct',
  EXTERNAL_DIRECT: 'external-direct-declared',
  EXTERNAL_SOURCE_SEPARATED: 'external-source-separated-declared',
  EXTERNAL_TOR: 'external-tor-declared'
})

export const DOWNGRADE_POLICY = Object.freeze({
  DENY: 'deny',
  PROMPT: 'prompt'
})

export const PLAN_STATUS = Object.freeze({
  DRAFT: 'draft',
  QUEUEABLE: 'queueable',
  BLOCKED: 'blocked'
})

export const EVIDENCE_REQUIREMENT = Object.freeze({
  SIGNED_TRANSPORT_PROFILE: 'signed-transport-profile',
  VERIFIED_ENDPOINT: 'verified-endpoint',
  FRESH_SIGNED_HEALTH: 'fresh-signed-health',
  ADAPTER_CONFORMANCE: 'adapter-conformance',
  CLASS_SHAPING_CAPTURE: 'class-shaping-capture',
  STREAM_SHAPING_CAPTURE: 'stream-shaping-capture',
  APPLICATION_IDENTITY_BOUNDARY: 'application-identity-boundary',
  INBOX_ANONYMOUS_REPLY_PROFILE: 'inbox-anonymous-reply-profile',
  UNIVERSAL_READ_BUCKET_PROFILE: 'universal-read-bucket-profile',
  P2P_SESSION_PREPARATION: 'p2p-session-preparation',
  ROLE_SEPARATION_CAPTURE: 'role-separation-capture',
  NO_DIRECT_RACE_CAPTURE: 'no-direct-race-capture',
  NO_CLEARNET_CAPTURE: 'no-clearnet-capture',
  BROWSER_OPAQUE_ORIGIN_CAPTURE: 'browser-opaque-origin-capture',
  EXTERNAL_ENDPOINT_EVIDENCE: 'external-endpoint-evidence',
  EXTERNAL_CONNECTOR_CONFORMANCE: 'external-connector-conformance',
  DISCLOSURE_AUTHORIZATION: 'disclosure-authorization'
})

const METADATA_SHAPING = Object.freeze(['none', 'padded', 'bucketed-experimental'])
const IDENTITY_EXPOSURE = Object.freeze(['stable', 'session', 'anonymous-reply'])
const READ_INTEREST = Object.freeze(['observable', 'bucketed-experimental'])
const OUTER_ENVELOPE_HEADER_BYTES = 6
const CELL_GET_RESULT_BODY_OVERHEAD_BYTES = 2
const CELL_BLOB_OVERHEAD_BYTES = 1 + 12 + 16 + 4
const CELL_PUT_PROFILE = selectedOperationProfile(FAMILY.CELL, OPERATION.CELL.PUT)
const OUTER_CLASS_BYTES = Object.freeze(Object.values(OUTER_CLASS).sort((left, right) => left - right))
// Exact maximum canonical request structure, including maximum admission bytes.
// These are guarded against real canonical encodings by the policy test suite.
const CELL_PUT_REQUEST_BODY_OVERHEAD_BYTES = 4398
const CELL_GET_REQUEST_BODY_MAX_BYTES = 4201

function maximumCellContentBytes (sizeClass) {
  if (!Number.isInteger(sizeClass) || CELL_SIZE_CLASS[sizeClass] == null) {
    fail('BAD_CLIENT_INPUT', 'sizeClass is outside the frozen cell classes')
  }
  return CELL_SIZE_CLASS[sizeClass] - CELL_BLOB_OVERHEAD_BYTES
}

const PRESETS = Object.freeze({
  [PRIVACY_PRESET.FAST]: Object.freeze({
    preset: PRIVACY_PRESET.FAST,
    transport: TRANSPORT_REQUIREMENT.DIRECT,
    metadataShaping: 'padded',
    identityExposure: 'session',
    readInterest: 'observable',
    downgradePolicy: DOWNGRADE_POLICY.DENY,
    backgroundPreferred: false
  }),
  [PRIVACY_PRESET.PRIVATE]: Object.freeze({
    preset: PRIVACY_PRESET.PRIVATE,
    transport: TRANSPORT_REQUIREMENT.SOURCE_SEPARATED,
    metadataShaping: 'padded',
    identityExposure: 'session',
    readInterest: 'observable',
    downgradePolicy: DOWNGRADE_POLICY.PROMPT,
    backgroundPreferred: false
  }),
  [PRIVACY_PRESET.HIGH_PRIVACY]: Object.freeze({
    preset: PRIVACY_PRESET.HIGH_PRIVACY,
    transport: TRANSPORT_REQUIREMENT.TOR,
    metadataShaping: 'padded',
    identityExposure: 'session',
    readInterest: 'observable',
    downgradePolicy: DOWNGRADE_POLICY.DENY,
    backgroundPreferred: true
  })
})

const CUSTOM_FIELDS = Object.freeze([
  'transport',
  'metadataShaping',
  'identityExposure',
  'readInterest',
  'downgradePolicy',
  'backgroundPreferred'
])
const CUSTOM_OPTION_FIELDS = Object.freeze([...CUSTOM_FIELDS, 'base'])

export const privacy = Object.freeze({
  fast: options => createPrivacyIntent(PRIVACY_PRESET.FAST, options),
  private: options => createPrivacyIntent(PRIVACY_PRESET.PRIVATE, options),
  highPrivacy: options => createPrivacyIntent(PRIVACY_PRESET.HIGH_PRIVACY, options),
  custom: options => createPrivacyIntent(PRIVACY_PRESET.CUSTOM, options)
})

export function createPrivacyIntent (preset = PRIVACY_PRESET.PRIVATE, options = {}) {
  if (options == null) options = {}
  if (!isPlainObject(options)) fail('BAD_CLIENT_INPUT', 'privacy options must be an object')
  const fixed = typeof preset === 'string' && hasOwn(PRESETS, preset) ? PRESETS[preset] : null
  if (fixed) {
    if (Object.keys(options).length !== 0) {
      fail('PRESET_IMMUTABLE', `${preset} is an immutable preset; use custom privacy constraints instead`)
    }
    return fixed
  }
  if (preset !== PRIVACY_PRESET.CUSTOM) fail('BAD_CLIENT_INPUT', `unknown privacy preset ${String(preset)}`)
  const keys = Object.keys(options)
  for (const key of keys) {
    if (!CUSTOM_OPTION_FIELDS.includes(key)) fail('BAD_CLIENT_INPUT', `unknown custom privacy field ${key}`)
  }
  const baseName = options.base
  if (baseName != null && (typeof baseName !== 'string' || !hasOwn(PRESETS, baseName))) {
    fail('BAD_CLIENT_INPUT', 'custom privacy base is invalid')
  }
  const resolved = baseName == null ? {} : { ...PRESETS[baseName] }
  delete resolved.preset
  for (const field of CUSTOM_FIELDS) {
    if (options[field] != null) resolved[field] = options[field]
  }
  if (CUSTOM_FIELDS.some(field => resolved[field] == null)) {
    fail('BAD_CLIENT_INPUT', 'custom privacy must provide every closed constraint axis or inherit it from a fixed base')
  }
  const value = { preset, base: baseName || null, ...resolved }
  validatePrivacyAxes(value)
  return Object.freeze(value)
}

export function draftWorkloadPlan (options) {
  if (!isPlainObject(options)) fail('BAD_CLIENT_INPUT', 'workload planning options are required')
  assertOnlyFields(Object.keys(options), [
    'workload',
    'runtime',
    'privacy',
    'inventory',
    'availability',
    'durability',
    'costBudget',
    'externalDisclosure',
    'downgradeAuthorization',
    'disclosureAuthorization'
  ], 'workload planning options')
  if (options.downgradeAuthorization != null) {
    fail('BAD_CLIENT_INPUT', 'the pure draft planner cannot consume downgrade authorization; qualification must remain consent-pending')
  }
  if (options.disclosureAuthorization != null) {
    fail('BAD_CLIENT_INPUT', 'the pure draft planner cannot consume disclosure authorization; connector qualification must bind it later')
  }
  const workload = normalizeWorkload(options.workload)
  const runtime = options.runtime
  if (!Object.values(RUNTIME).includes(runtime)) fail('BAD_CLIENT_INPUT', 'runtime is invalid')
  if (options.inventory != null && options.availability != null) {
    fail('BAD_CLIENT_INPUT', 'provide inventory, not both inventory and the compatibility availability alias')
  }
  const inventory = normalizeInventory(options.inventory != null ? options.inventory : options.availability)
  const intent = normalizePrivacy(options.privacy)
  const budget = normalizeCostBudget(options.costBudget)
  const primitiveChoice = choosePrimitive(workload, runtime, inventory)
  if (primitiveChoice.code) {
    return blocked(workload, runtime, primitiveChoice.primitive, intent, primitiveChoice.code, primitiveChoice.reason)
  }
  const primitive = primitiveChoice.primitive
  if (workload.kind !== WORKLOAD.SEMANTIC && options.externalDisclosure != null) {
    return blocked(workload, runtime, primitive, intent, 'WORKLOAD_DISCLOSURE_CONFLICT',
      'external-service disclosure applies only to semantic workloads')
  }
  if (workload.kind === WORKLOAD.SEMANTIC && primitive === PRIMITIVE.LOCAL_COMPUTE &&
      options.externalDisclosure != null) {
    return blocked(workload, runtime, primitive, intent, 'WORKLOAD_DISCLOSURE_CONFLICT',
      'local semantic execution must not carry an external-service disclosure')
  }
  if (workload.kind === WORKLOAD.SEMANTIC && primitive === PRIMITIVE.EXTERNAL) {
    const disclosureError = validateExternalDisclosure(options.externalDisclosure)
    if (disclosureError) {
      return blocked(workload, runtime, primitive, intent, disclosureError.code, disclosureError.reason)
    }
  }
  const durabilityResolution = normalizeDurability(options.durability, primitive)
  if (durabilityResolution.code) {
    return blocked(workload, runtime, primitive, intent, durabilityResolution.code, durabilityResolution.reason)
  }
  const durability = durabilityResolution.value
  let cell = null
  let inbox = null
  if (primitive === PRIMITIVE.CELL) {
    cell = planCell(workload, durability)
    if (cell.requiresChunkManifest) {
      return blocked(workload, runtime, primitive, intent, 'CHUNK_MANIFEST_REQUIRED',
        'the object exceeds the largest Cell payload; the application must supply a signed chunk manifest', {
          durability,
          costBudget: budget,
          chunking: cell
        })
    }
  }
  if (primitive === PRIMITIVE.INBOX) {
    inbox = planInbox(workload)
    if (inbox.exceedsMaximumFrame) {
      return blocked(workload, runtime, primitive, intent, 'RENDEZVOUS_FRAME_TOO_LARGE',
        'the opaque rendezvous payload exceeds the largest universal Inbox frame', {
          durability,
          costBudget: budget,
          inbox
        })
    }
  }

  const axisResolution = resolveNonTransportAxes(intent, primitive)
  if (axisResolution.blockers.length > 0) {
    return blocked(workload, runtime, primitive, intent, 'PRIVACY_AXIS_UNSUPPORTED',
      `unsupported privacy axes: ${axisResolution.blockers.join(', ')}`, { privacyResolution: axisResolution.axes })
  }

  if (budget != null && primitive !== PRIMITIVE.CELL) {
    return blocked(workload, runtime, primitive, intent, 'COST_EVIDENCE_UNAVAILABLE',
      `the ${primitive} adapter has not supplied a qualified cost model for the requested hard ceiling`, {
        durability,
        costBudget: budget,
        privacyResolution: axisResolution.axes
      })
  }
  if (cell != null && budget != null && cell.blindEnvelope == null) {
    return blocked(workload, runtime, primitive, intent, 'COST_EVIDENCE_UNAVAILABLE',
      'an exact Cell size basis is required before enforcing a blind-envelope amplification ceiling', {
        durability,
        costBudget: budget,
        cell,
        privacyResolution: axisResolution.axes
      })
  }
  if (cell != null && budget != null &&
      cell.blindEnvelope.usefulByteAmplification > budget.maxBlindEnvelopeAmplification) {
    return blocked(workload, runtime, primitive, intent, 'COST_BUDGET_EXCEEDED',
      `v1 blind-envelope amplification ${cell.blindEnvelope.usefulByteAmplification} exceeds the configured ceiling`, {
        estimate: cell.blindEnvelope,
        suggestion: cell.batchRecommended ? 'batch-small-records' : 'use-core-or-chunked-p2p',
        durability,
        costBudget: budget,
        privacyResolution: axisResolution.axes
      })
  }

  if (workload.kind === WORKLOAD.SEMANTIC) {
    return planSemantic({ workload, runtime, primitive, intent, inventory, axisResolution, disclosure: options.externalDisclosure })
  }
  if (workload.kind === WORKLOAD.LIVE) {
    return planLive({ workload, runtime, primitive, intent, inventory, axisResolution })
  }

  const transport = resolveTransport({
    workload,
    runtime,
    primitive,
    intent,
    inventory
  })
  const intendedTransportProfile = transport.profile || intendedProfile(runtime, intent.transport)
  if (intendedTransportProfile == null) {
    return blocked(workload, runtime, primitive, intent, 'TRANSPORT_UNSUPPORTED',
      'the requested transport has no candidate profile in this runtime', {
        durability,
        costBudget: budget,
        cell,
        inbox,
        privacyResolution: axisResolution.axes
      })
  }
  const privacyResolution = deepFreeze({
    ...axisResolution.axes,
    transport: axisRecord(intent.transport, intendedTransportProfile, 'qualification-required',
      transportRequiredEvidence(intendedTransportProfile, runtime),
      assumptions(intendedTransportProfile), transportClaim(intendedTransportProfile))
  })
  const planDetails = {
    wireOperation: wireOperationFor(primitive, workload.operation),
    privacyResolution,
    intendedTransportProfile,
    execution: intent.backgroundPreferred ? 'background-preferred' : 'interactive-capable',
    durability,
    costBudget: budget,
    claims: claimsFor(primitive, intendedTransportProfile, runtime),
    assumptions: assumptions(intendedTransportProfile),
    warnings: warningsFor(intent, intendedTransportProfile),
    cell,
    inbox
  }
  if (primitive === PRIMITIVE.CORE && inventory.core !== true) {
    return queueable(workload, runtime, primitive, intent, 'QUEUEABLE_CORE_STREAM_UNAVAILABLE',
      'Blind Core needs an available native stream adapter', planDetails)
  }
  if (!transport.profile) {
    const extra = { ...planDetails, ...transport }
    delete extra.status
    delete extra.code
    delete extra.reason
    return transport.status === PLAN_STATUS.QUEUEABLE
      ? queueable(workload, runtime, primitive, intent, transport.code, transport.reason, extra)
      : blocked(workload, runtime, primitive, intent, transport.code, transport.reason, extra)
  }
  if (primitive === PRIMITIVE.CORE && transport.profile === TRANSPORT_PROFILE.OHTTP) {
    return blocked(workload, runtime, primitive, intent, 'TRANSPORT_UNSUPPORTED',
      'Blind Core cannot open replication over OHTTP', planDetails)
  }

  const plan = {
    status: PLAN_STATUS.DRAFT,
    code: 'QUALIFICATION_REQUIRED',
    executable: false,
    workload: workload.kind,
    primitive,
    runtime,
    operation: workload.operation,
    requestedPrivacy: intent,
    ...planDetails,
    downgraded: false,
    downgradeAuthorized: false,
    readiness: 'a qualified endpoint, exact operation, profile hash, adapter evidence and fresh health must still be pinned'
  }

  return deepFreeze(plan)
}

export const planWorkload = draftWorkloadPlan
export const draftWorkload = draftWorkloadPlan

export function estimateCellWireV1 (options) {
  if (!isPlainObject(options)) fail('BAD_CLIENT_INPUT', 'cell envelope estimate options are required')
  assertOnlyFields(Object.keys(options), ['operation', 'sizeClass', 'usefulBytes', 'replicas'], 'cell envelope estimate')
  const sizeClass = options.sizeClass
  const cellBytes = CELL_SIZE_CLASS[sizeClass]
  if (cellBytes == null) fail('BAD_CLIENT_INPUT', 'sizeClass is outside the frozen cell classes')
  const operation = String(options.operation || '').toUpperCase()
  if (operation !== 'PUT' && operation !== 'GET') fail('BAD_CLIENT_INPUT', 'operation must be PUT or GET')
  const replicaCount = options.replicas == null ? 1 : options.replicas
  if (!Number.isSafeInteger(replicaCount) || replicaCount < 1 || replicaCount > 16) {
    fail('BAD_CLIENT_INPUT', 'replicas must be within 1..16')
  }
  const usefulBytes = options.usefulBytes == null ? maximumCellContentBytes(sizeClass) : options.usefulBytes
  if (!Number.isSafeInteger(usefulBytes) || usefulBytes < 1 || usefulBytes > maximumCellContentBytes(sizeClass)) {
    fail('BAD_CLIENT_INPUT', 'usefulBytes must fit the selected Cell content capacity')
  }
  const requestBodyBytes = operation === 'PUT'
    ? cellBytes + CELL_PUT_REQUEST_BODY_OVERHEAD_BYTES
    : CELL_GET_REQUEST_BODY_MAX_BYTES
  const resultBodyBytes = operation === 'PUT'
    ? CELL_PUT_PROFILE.maxResultBodyBytes
    : cellBytes + CELL_GET_RESULT_BODY_OVERHEAD_BYTES
  const innerBytes = DISPATCH_LIMITS.PREFIX_BYTES + DISPATCH_LIMITS.HEADER_BYTES +
    Math.max(requestBodyBytes, resultBodyBytes)
  const outerBytesPerDirection = smallestOuterClassBytes(OUTER_ENVELOPE_HEADER_BYTES + innerBytes)
  const roundTripBytesPerDestination = outerBytesPerDirection * 2
  const totalOuterBytes = roundTripBytesPerDestination * replicaCount
  return Object.freeze({
    protocol: 'hiverelay-blind-v1-symmetric-outer',
    accountingBoundary: 'frozen blind outer envelopes only; transport wrappers, handshakes, retries and IP framing excluded',
    operation,
    sizeClass,
    cellBytes,
    usefulBytes,
    exact: true,
    requestOuterBytes: outerBytesPerDirection,
    responseOuterBytes: outerBytesPerDirection,
    roundTripBytesPerDestination,
    destinationCount: replicaCount,
    totalOuterBytes,
    usefulByteAmplification: totalOuterBytes / usefulBytes
  })
}

function normalizeWorkload (value) {
  if (typeof value === 'string') value = { kind: value }
  if (!isPlainObject(value) || !Object.values(WORKLOAD).includes(value.kind)) {
    fail('BAD_CLIENT_INPUT', 'workload kind is invalid')
  }
  assertOnlyFields(Object.keys(value), ['kind', 'byteLength', 'operation', 'execution', 'primitive'], 'workload')
  const byteLength = value.byteLength == null ? null : value.byteLength
  if (byteLength != null && (!Number.isSafeInteger(byteLength) || byteLength < 1)) {
    fail('BAD_CLIENT_INPUT', 'workload byteLength must be a positive safe integer when supplied')
  }
  let defaultOperation = 'put'
  let allowedOperations = ['put', 'get']
  if (value.kind === WORKLOAD.RENDEZVOUS) {
    defaultOperation = 'append'
    allowedOperations = ['create', 'append', 'read', 'watch', 'renew', 'close']
  } else if (value.kind === WORKLOAD.LIVE) {
    defaultOperation = 'session'
    allowedOperations = ['session']
  } else if (value.kind === WORKLOAD.SEMANTIC) {
    defaultOperation = 'execute'
    allowedOperations = ['execute']
  }
  const operation = value.operation == null ? defaultOperation : String(value.operation).toLowerCase()
  if (!allowedOperations.includes(operation)) {
    fail('BAD_CLIENT_INPUT', `${value.kind} workload operation is invalid`)
  }
  if (value.kind !== WORKLOAD.SEMANTIC && value.execution != null) {
    fail('BAD_CLIENT_INPUT', 'execution applies only to semantic workloads')
  }
  if (value.execution != null && value.execution !== 'local' && value.execution !== 'external') {
    fail('BAD_CLIENT_INPUT', 'semantic execution must be local or external')
  }
  let execution = value.execution
  if (value.kind === WORKLOAD.SEMANTIC && execution == null) {
    execution = value.primitive === PRIMITIVE.EXTERNAL ? 'external' : 'local'
  }
  return Object.freeze({ ...value, byteLength, operation, execution })
}

function normalizePrivacy (value) {
  if (value == null) return privacy.private()
  if (typeof value === 'string') return createPrivacyIntent(value)
  if (!isPlainObject(value)) fail('BAD_CLIENT_INPUT', 'privacy intent is invalid')
  const preset = value.preset || PRIVACY_PRESET.CUSTOM
  const fixed = typeof preset === 'string' && hasOwn(PRESETS, preset) ? PRESETS[preset] : null
  if (fixed) {
    const keys = Object.keys(value)
    if (keys.length !== Object.keys(fixed).length || keys.some(key => fixed[key] !== value[key])) {
      fail('PRESET_IMMUTABLE', `${preset} is an immutable preset; use custom privacy constraints instead`)
    }
    return fixed
  }
  const custom = { ...value }
  delete custom.preset
  return createPrivacyIntent(preset, custom)
}

function validatePrivacyAxes (value) {
  if (!Object.values(TRANSPORT_REQUIREMENT).includes(value.transport)) {
    fail('BAD_CLIENT_INPUT', 'privacy transport requirement is invalid')
  }
  if (!METADATA_SHAPING.includes(value.metadataShaping)) fail('BAD_CLIENT_INPUT', 'metadataShaping is invalid')
  if (!IDENTITY_EXPOSURE.includes(value.identityExposure)) fail('BAD_CLIENT_INPUT', 'identityExposure is invalid')
  if (!READ_INTEREST.includes(value.readInterest)) fail('BAD_CLIENT_INPUT', 'readInterest is invalid')
  if (!Object.values(DOWNGRADE_POLICY).includes(value.downgradePolicy)) fail('BAD_CLIENT_INPUT', 'downgradePolicy is invalid')
  if (typeof value.backgroundPreferred !== 'boolean') fail('BAD_CLIENT_INPUT', 'backgroundPreferred must be boolean')
}

function resolveNonTransportAxes (intent, primitive) {
  let axes
  if (primitive === PRIMITIVE.LOCAL_COMPUTE) {
    axes = {
      metadataShaping: axisRecord(intent.metadataShaping, null, 'not-applicable', [], [],
        'local compute selects no network metadata-shaping path'),
      identityExposure: axisRecord(intent.identityExposure, null, 'not-applicable', [], [],
        'local compute exposes no identity to a network service'),
      readInterest: axisRecord(intent.readInterest, null, 'not-applicable', [], [],
        'local compute has no storage read-interest observer'),
      transport: axisRecord(intent.transport, null, 'not-applicable', [], [],
        'local compute selects no network transport')
    }
  } else if (primitive === PRIMITIVE.EXTERNAL) {
    axes = {
      metadataShaping: axisRecord(intent.metadataShaping, null, 'connector-qualification-required',
        [EVIDENCE_REQUIREMENT.EXTERNAL_CONNECTOR_CONFORMANCE], [],
        'the external connector must prove its metadata-shaping behavior'),
      identityExposure: axisRecord(intent.identityExposure, null, 'connector-qualification-required',
        [EVIDENCE_REQUIREMENT.EXTERNAL_CONNECTOR_CONFORMANCE, EVIDENCE_REQUIREMENT.DISCLOSURE_AUTHORIZATION], [],
        'the external connector and application must prove the disclosed identity boundary'),
      readInterest: axisRecord(intent.readInterest, null, 'connector-qualification-required',
        [EVIDENCE_REQUIREMENT.DISCLOSURE_AUTHORIZATION], [],
        'the external service can interpret request interest unless its connector proves otherwise')
    }
  } else if (primitive === PRIMITIVE.P2P_DIRECT) {
    axes = {
      metadataShaping: intent.metadataShaping === 'bucketed-experimental'
        ? axisRecord(intent.metadataShaping, null, 'unsupported',
          [EVIDENCE_REQUIREMENT.UNIVERSAL_READ_BUCKET_PROFILE], [],
          'the direct P2P profile has no qualified bucketed metadata-shaping mode')
        : axisRecord(intent.metadataShaping, null, 'adapter-qualification-required',
          [EVIDENCE_REQUIREMENT.P2P_SESSION_PREPARATION, EVIDENCE_REQUIREMENT.ADAPTER_CONFORMANCE], [],
          'the prepared P2P adapter must prove any padding or shaping behavior'),
      identityExposure: intent.identityExposure === 'anonymous-reply'
        ? axisRecord(intent.identityExposure, null, 'unsupported',
          [EVIDENCE_REQUIREMENT.APPLICATION_IDENTITY_BOUNDARY], [],
          'peer-authenticated live sessions do not provide anonymous-reply identity exposure')
        : axisRecord(intent.identityExposure, null, 'adapter-qualification-required',
          [EVIDENCE_REQUIREMENT.P2P_SESSION_PREPARATION, EVIDENCE_REQUIREMENT.APPLICATION_IDENTITY_BOUNDARY], [],
          'peer authentication and application identity scope must be proven during session preparation'),
      readInterest: axisRecord(intent.readInterest, null, 'not-applicable', [], [],
        'a live P2P session has no storage-locator read-interest axis')
    }
  } else {
    const paddingPlan = primitive === PRIMITIVE.CORE ? 'stream-shaping-adapter-defined' : 'fixed-class-padding'
    const anonymousReplySupported = primitive === PRIMITIVE.INBOX
    axes = {
      metadataShaping: intent.metadataShaping === 'bucketed-experimental'
        ? axisRecord(intent.metadataShaping, null, 'unsupported',
          [EVIDENCE_REQUIREMENT.UNIVERSAL_READ_BUCKET_PROFILE], [],
          'universal read buckets/PIR are not implemented')
        : axisRecord(intent.metadataShaping, paddingPlan, 'qualification-required',
          [primitive === PRIMITIVE.CORE
            ? EVIDENCE_REQUIREMENT.STREAM_SHAPING_CAPTURE
            : EVIDENCE_REQUIREMENT.CLASS_SHAPING_CAPTURE,
          EVIDENCE_REQUIREMENT.ADAPTER_CONFORMANCE], [],
          'the selected adapter must prove the planned class-shaping behavior'),
      identityExposure: intent.identityExposure === 'anonymous-reply' && !anonymousReplySupported
        ? axisRecord(intent.identityExposure, null, 'unsupported',
          [EVIDENCE_REQUIREMENT.INBOX_ANONYMOUS_REPLY_PROFILE], [],
          'anonymous-reply exposure is available only through a separately prepared Inbox capability profile')
        : axisRecord(intent.identityExposure,
          intent.identityExposure === 'anonymous-reply' ? 'capability-scoped-reply' : intent.identityExposure,
          'application-policy-required',
          intent.identityExposure === 'anonymous-reply'
            ? [EVIDENCE_REQUIREMENT.INBOX_ANONYMOUS_REPLY_PROFILE, EVIDENCE_REQUIREMENT.APPLICATION_IDENTITY_BOUNDARY]
            : [EVIDENCE_REQUIREMENT.APPLICATION_IDENTITY_BOUNDARY], [],
          'the application adapter must prove that no stronger identity enters relay-visible state'),
      readInterest: intent.readInterest === 'observable'
        ? axisRecord(intent.readInterest, 'observable', 'known-visible', [], [],
          'requested locators and access timing remain visible to storage')
        : axisRecord(intent.readInterest, null, 'unsupported',
          [EVIDENCE_REQUIREMENT.UNIVERSAL_READ_BUCKET_PROFILE], [],
          'bucketed read interest needs a separately qualified universal bucket/PIR profile')
    }
  }
  const blockers = Object.entries(axes).filter(([, resolution]) => resolution.state === 'unsupported').map(([name]) => name)
  return { axes: deepFreeze(axes), blockers }
}

function normalizeInventory (value = {}) {
  if (!isPlainObject(value)) fail('BAD_CLIENT_INPUT', 'deployment inventory must be an object')
  const fields = Object.keys(value)
  assertOnlyFields(fields, [
    'direct',
    'ohttp',
    'splitNative',
    'torNative',
    'torBrowser',
    'core',
    'p2p',
    'external'
  ], 'deployment inventory')
  for (const field of fields) {
    if (typeof value[field] !== 'boolean') fail('BAD_CLIENT_INPUT', `deployment inventory ${field} must be boolean`)
  }
  return Object.freeze({ ...value })
}

function normalizeDurability (value = {}, primitive) {
  if (value == null) value = {}
  if (!isPlainObject(value)) fail('BAD_CLIENT_INPUT', 'durability must be an object')
  const fields = Object.keys(value)
  if (primitive === PRIMITIVE.CELL) {
    assertOnlyFields(fields, [
      'replicaTarget',
      'acknowledgementTarget',
      'readbackTarget',
      'fetchTarget',
      'independentOperatorGroups'
    ], 'Cell durability')
    const result = {
      model: 'cell-replicas-v1',
      replicaTarget: numberOr(value.replicaTarget, 3, 'replicaTarget'),
      acknowledgementTarget: numberOr(value.acknowledgementTarget, 2, 'acknowledgementTarget'),
      readbackTarget: numberOr(value.readbackTarget, 2, 'readbackTarget'),
      fetchTarget: numberOr(value.fetchTarget, 1, 'fetchTarget'),
      independentOperatorGroups: numberOr(value.independentOperatorGroups, 2, 'independentOperatorGroups')
    }
    if (result.acknowledgementTarget > result.replicaTarget || result.readbackTarget > result.replicaTarget ||
        result.fetchTarget > result.replicaTarget) {
      fail('BAD_CLIENT_INPUT', 'Cell durability evidence targets cannot exceed replicaTarget')
    }
    if (result.independentOperatorGroups > result.readbackTarget) {
      fail('BAD_CLIENT_INPUT', 'Cell independentOperatorGroups cannot exceed readbackTarget')
    }
    return { value: Object.freeze(result) }
  }
  if (primitive === PRIMITIVE.INBOX) {
    assertOnlyFields(fields, [
      'stripeCountLog2',
      'replicaTargetPerStripe',
      'appendAcknowledgementTargetPerStripe',
      'readbackTargetPerStripe',
      'independentOperatorGroups'
    ], 'Inbox durability')
    const result = {
      model: 'inbox-replicas-and-stripes-v1',
      stripeCountLog2: numberBetweenOr(value.stripeCountLog2, 3, 0, 6, 'stripeCountLog2'),
      replicaTargetPerStripe: numberOr(value.replicaTargetPerStripe, 3, 'replicaTargetPerStripe'),
      appendAcknowledgementTargetPerStripe: numberOr(value.appendAcknowledgementTargetPerStripe, 2, 'appendAcknowledgementTargetPerStripe'),
      readbackTargetPerStripe: numberOr(value.readbackTargetPerStripe, 2, 'readbackTargetPerStripe'),
      independentOperatorGroups: numberOr(value.independentOperatorGroups, 2, 'independentOperatorGroups')
    }
    result.stripeCount = 2 ** result.stripeCountLog2
    if (result.appendAcknowledgementTargetPerStripe > result.replicaTargetPerStripe ||
        result.readbackTargetPerStripe > result.replicaTargetPerStripe) {
      fail('BAD_CLIENT_INPUT', 'Inbox durability evidence targets cannot exceed replicaTargetPerStripe')
    }
    if (result.independentOperatorGroups > result.readbackTargetPerStripe) {
      fail('BAD_CLIENT_INPUT', 'Inbox independentOperatorGroups cannot exceed readbackTargetPerStripe')
    }
    return { value: Object.freeze(result) }
  }
  if (primitive === PRIMITIVE.CORE) {
    assertOnlyFields(fields, ['mirrorTarget', 'proofTarget', 'recentlyServedTarget', 'independentOperatorGroups'], 'Core durability')
    const result = {
      model: 'core-mirrors-v1',
      mirrorTarget: numberOr(value.mirrorTarget, 3, 'mirrorTarget'),
      proofTarget: numberOr(value.proofTarget, 1, 'proofTarget'),
      recentlyServedTarget: numberOr(value.recentlyServedTarget, 2, 'recentlyServedTarget'),
      independentOperatorGroups: numberOr(value.independentOperatorGroups, 2, 'independentOperatorGroups')
    }
    if (result.proofTarget > result.mirrorTarget || result.recentlyServedTarget > result.mirrorTarget) {
      fail('BAD_CLIENT_INPUT', 'Core durability evidence targets cannot exceed mirrorTarget')
    }
    if (result.independentOperatorGroups > result.recentlyServedTarget) {
      fail('BAD_CLIENT_INPUT', 'Core independentOperatorGroups cannot exceed recentlyServedTarget')
    }
    return { value: Object.freeze(result) }
  }
  if (fields.length > 0) {
    return {
      code: 'WORKLOAD_DURABILITY_CONFLICT',
      reason: `${primitive} does not provide Blind Cell, Inbox, or Core durability; compose a separate durable workload`
    }
  }
  return { value: null }
}

function numberOr (value, fallback, field) {
  return numberBetweenOr(value, fallback, 1, 16, field)
}

function numberBetweenOr (value, fallback, minimum, maximum, field) {
  const result = value == null ? fallback : value
  if (!Number.isSafeInteger(result) || result < minimum || result > maximum) {
    fail('BAD_CLIENT_INPUT', `durability ${field} is outside ${minimum}..${maximum}`)
  }
  return result
}

function assertOnlyFields (actual, allowed, label) {
  const unknown = actual.filter(field => !allowed.includes(field))
  if (unknown.length > 0) fail('BAD_CLIENT_INPUT', `${label} has unknown fields: ${unknown.join(', ')}`)
}

function choosePrimitive (workload, runtime, inventory) {
  let primitive = workload.primitive
  if (primitive != null && !Object.values(PRIMITIVE).includes(primitive)) {
    fail('BAD_CLIENT_INPUT', 'workload primitive override is invalid')
  }
  if (primitive == null) {
    if (workload.kind === WORKLOAD.RECORDS) primitive = PRIMITIVE.CELL
    else if (workload.kind === WORKLOAD.RENDEZVOUS) primitive = PRIMITIVE.INBOX
    else if (workload.kind === WORKLOAD.HISTORY) {
      primitive = runtime === RUNTIME.NATIVE ? PRIMITIVE.CORE : PRIMITIVE.CELL
    } else if (workload.kind === WORKLOAD.LIVE) primitive = PRIMITIVE.P2P_DIRECT
    else primitive = workload.execution === 'local' ? PRIMITIVE.LOCAL_COMPUTE : PRIMITIVE.EXTERNAL
  }
  const allowed = {
    [WORKLOAD.RECORDS]: [PRIMITIVE.CELL],
    [WORKLOAD.RENDEZVOUS]: [PRIMITIVE.INBOX],
    [WORKLOAD.HISTORY]: runtime === RUNTIME.NATIVE ? [PRIMITIVE.CELL, PRIMITIVE.CORE] : [PRIMITIVE.CELL],
    [WORKLOAD.LIVE]: [PRIMITIVE.P2P_DIRECT],
    [WORKLOAD.SEMANTIC]: [PRIMITIVE.LOCAL_COMPUTE, PRIMITIVE.EXTERNAL]
  }
  if (!allowed[workload.kind].includes(primitive)) {
    return {
      primitive,
      code: 'WORKLOAD_PRIMITIVE_UNSUPPORTED',
      reason: `${primitive} cannot represent the ${workload.kind} workload in the ${runtime} runtime`
    }
  }
  if (workload.kind === WORKLOAD.SEMANTIC) {
    const expected = workload.execution === 'local' ? PRIMITIVE.LOCAL_COMPUTE : PRIMITIVE.EXTERNAL
    if (primitive !== expected) {
      return {
        primitive,
        code: 'WORKLOAD_PRIMITIVE_CONFLICT',
        reason: `${workload.execution} semantic execution requires the ${expected} primitive`
      }
    }
  }
  return { primitive }
}

function intendedProfile (runtime, requirement) {
  if (requirement === TRANSPORT_REQUIREMENT.DIRECT) return TRANSPORT_PROFILE.DIRECT
  if (requirement === TRANSPORT_REQUIREMENT.SOURCE_SEPARATED) {
    if (runtime === RUNTIME.BROWSER) return TRANSPORT_PROFILE.OHTTP
    if (runtime === RUNTIME.NATIVE) return TRANSPORT_PROFILE.SPLIT_NATIVE
    if (runtime === RUNTIME.TOR_BROWSER) return TRANSPORT_PROFILE.TOR_BROWSER
  }
  if (requirement === TRANSPORT_REQUIREMENT.TOR) {
    if (runtime === RUNTIME.NATIVE) return TRANSPORT_PROFILE.TOR_NATIVE
    if (runtime === RUNTIME.TOR_BROWSER) return TRANSPORT_PROFILE.TOR_BROWSER
  }
  return null
}

function wireOperationFor (primitive, applicationOperation) {
  let familyName
  let operationName
  if (primitive === PRIMITIVE.CELL) {
    familyName = 'CELL'
    operationName = applicationOperation.toUpperCase()
  } else if (primitive === PRIMITIVE.INBOX) {
    familyName = 'INBOX'
    operationName = applicationOperation.toUpperCase()
  } else if (primitive === PRIMITIVE.CORE) {
    familyName = 'CORE'
    operationName = applicationOperation === 'put' ? 'MIRROR' : 'OPEN_REPLICATION'
  } else {
    return null
  }
  const operationId = OPERATION[familyName][operationName]
  if (operationId == null) fail('BAD_CLIENT_INPUT', `${primitive} has no wire operation for ${applicationOperation}`)
  return Object.freeze({
    family: familyName,
    familyId: FAMILY[familyName],
    operation: operationName,
    operationId
  })
}

function resolveTransport (context) {
  const { runtime, intent, inventory } = context
  let profile = null
  let reason = null
  if (intent.transport === TRANSPORT_REQUIREMENT.DIRECT) {
    if (inventory.direct === true) profile = TRANSPORT_PROFILE.DIRECT
    else reason = 'direct transport is unavailable'
  } else if (intent.transport === TRANSPORT_REQUIREMENT.SOURCE_SEPARATED) {
    if (runtime === RUNTIME.BROWSER && inventory.ohttp === true) profile = TRANSPORT_PROFILE.OHTTP
    else if (runtime === RUNTIME.NATIVE && inventory.splitNative === true) profile = TRANSPORT_PROFILE.SPLIT_NATIVE
    else if (runtime === RUNTIME.TOR_BROWSER && inventory.torBrowser === true) profile = TRANSPORT_PROFILE.TOR_BROWSER
    else reason = 'the runtime has no available source-separated transport'
  } else if (runtime === RUNTIME.NATIVE && inventory.torNative === true) profile = TRANSPORT_PROFILE.TOR_NATIVE
  else if (runtime === RUNTIME.TOR_BROWSER && inventory.torBrowser === true) profile = TRANSPORT_PROFILE.TOR_BROWSER
  else reason = 'the runtime has no available full Tor transport'

  if (profile) return { profile, downgraded: false }
  if (intent.downgradePolicy === DOWNGRADE_POLICY.PROMPT && inventory.direct === true) {
    return {
      profile: null,
      status: PLAN_STATUS.QUEUEABLE,
      code: 'DOWNGRADE_CONSENT_REQUIRED',
      reason,
      consentRequired: true,
      suggestedTransportProfile: TRANSPORT_PROFILE.DIRECT
    }
  }
  return {
    profile: null,
    status: PLAN_STATUS.QUEUEABLE,
    code: 'QUEUEABLE_PRIVACY_PATH_UNAVAILABLE',
    reason,
    consentRequired: false
  }
}

function planLive (context) {
  const { workload, runtime, primitive, intent, inventory, axisResolution } = context
  const profile = TRANSPORT_PROFILE.P2P_DIRECT
  const details = {
    wireOperation: null,
    privacyResolution: deepFreeze({
      ...axisResolution.axes,
      transport: axisRecord(intent.transport, profile, 'session-preparation-required',
        transportRequiredEvidence(profile, runtime),
        ['peer reachability and direct-path metadata exposure'], transportClaim(profile))
    }),
    intendedTransportProfile: profile,
    execution: 'interactive',
    durability: null,
    costBudget: null,
    claims: claimsFor(primitive, profile, runtime),
    assumptions: ['peer reachability and direct-path metadata exposure'],
    warnings: ['pair with Cells or Blind Core when offline durability is required']
  }
  if (intent.transport !== TRANSPORT_REQUIREMENT.DIRECT) {
    return blocked(workload, runtime, primitive, intent, 'WORKLOAD_PRIVACY_CONFLICT',
      'live P2P is a low-latency direct path; use an asynchronous Cell/Core path for stronger transport privacy', details)
  }
  if (inventory.p2p !== true) {
    return queueable(workload, runtime, primitive, intent, 'P2P_PATH_UNAVAILABLE',
      'no direct P2P path is currently present in the deployment inventory', details)
  }
  return deepFreeze({
    status: PLAN_STATUS.DRAFT,
    code: 'P2P_SESSION_PREPARATION_REQUIRED',
    executable: false,
    workload: workload.kind,
    primitive,
    runtime,
    operation: workload.operation,
    requestedPrivacy: intent,
    ...details,
    downgraded: false,
    downgradeAuthorized: false,
    readiness: 'ICE/NAT traversal, peer authentication and the exact session path must still be prepared'
  })
}

function planSemantic (context) {
  const { workload, runtime, primitive, intent, inventory, axisResolution, disclosure } = context
  if (primitive === PRIMITIVE.LOCAL_COMPUTE) {
    if (disclosure != null) {
      return blocked(workload, runtime, primitive, intent, 'WORKLOAD_DISCLOSURE_CONFLICT',
        'local semantic execution must not carry an external-service disclosure', {
          privacyResolution: axisResolution.axes
        })
    }
    return deepFreeze({
      status: PLAN_STATUS.DRAFT,
      code: 'LOCAL_COMPUTE_APP_OWNED',
      executable: false,
      workload: workload.kind,
      primitive,
      runtime,
      operation: workload.operation,
      requestedPrivacy: intent,
      privacyResolution: axisResolution.axes,
      intendedTransportProfile: null,
      wireOperation: null,
      execution: 'local-application-code',
      durability: null,
      costBudget: null,
      claims: claimsFor(primitive, null, runtime),
      assumptions: ['the application controls the local execution environment'],
      warnings: [],
      downgraded: false,
      downgradeAuthorized: false,
      readiness: 'local semantic execution is application-owned and never sent to the blind substrate'
    })
  }
  const disclosureError = validateExternalDisclosure(disclosure)
  if (disclosureError) {
    return blocked(workload, runtime, primitive, intent, disclosureError.code,
      disclosureError.reason, { privacyResolution: axisResolution.axes })
  }
  if (disclosure.networkTransport !== intent.transport) {
    return blocked(workload, runtime, primitive, intent, 'PRIVACY_AXIS_UNSUPPORTED',
      'the disclosed external network transport does not satisfy the requested privacy transport', {
        privacyResolution: axisResolution.axes
      })
  }
  const profile = externalTransportProfile(disclosure.networkTransport)
  const disclosureMetadata = externalDisclosureMetadata(disclosure)
  const claims = deepFreeze({
    ...claimsFor(primitive, profile, runtime),
    semanticDisclosure: {
      claimCeiling: 'explicitly non-blind semantic service',
      operatorSees: disclosureMetadata.operatorSees,
      authority: disclosureMetadata.authority,
      retention: disclosureMetadata.retention
    }
  })
  const details = {
    wireOperation: null,
    privacyResolution: deepFreeze({
      ...axisResolution.axes,
      transport: axisRecord(intent.transport, profile, 'connector-qualification-required',
        transportRequiredEvidence(profile, runtime),
        assumptions(profile), transportClaim(profile))
    }),
    intendedTransportProfile: profile,
    semanticBoundary: 'explicitly-non-blind',
    execution: 'external-service',
    durability: null,
    costBudget: null,
    claims,
    assumptions: ['the named service can interpret the disclosed semantic input', ...assumptions(profile)],
    warnings: ['this operation is outside the blind substrate trust boundary'],
    externalDisclosure: disclosureMetadata,
    consentRequired: true,
    consentStatus: 'qualification-required'
  }
  if (inventory.external !== true) {
    return queueable(workload, runtime, primitive, intent, 'EXTERNAL_SERVICE_UNAVAILABLE',
      'the declared semantic service is not currently present in the deployment inventory', details)
  }
  if (!externalTransportAvailable(profile, runtime, inventory)) {
    return queueable(workload, runtime, primitive, intent, 'QUEUEABLE_PRIVACY_PATH_UNAVAILABLE',
      'the declared semantic service lacks the requested network-privacy path in the deployment inventory', details)
  }
  return deepFreeze({
    status: PLAN_STATUS.DRAFT,
    code: 'EXTERNAL_CONNECTOR_QUALIFICATION_REQUIRED',
    executable: false,
    workload: workload.kind,
    primitive,
    runtime,
    operation: workload.operation,
    requestedPrivacy: intent,
    ...details,
    downgraded: false,
    downgradeAuthorized: false,
    readiness: 'the named connector must revalidate endpoint evidence, consent scope and network transport before execution'
  })
}

function externalTransportAvailable (profile, runtime, inventory) {
  if (profile === TRANSPORT_PROFILE.EXTERNAL_DIRECT) return inventory.direct === true
  if (profile === TRANSPORT_PROFILE.EXTERNAL_SOURCE_SEPARATED) {
    if (runtime === RUNTIME.BROWSER) return inventory.ohttp === true
    if (runtime === RUNTIME.NATIVE) return inventory.splitNative === true
    return inventory.torBrowser === true
  }
  if (profile === TRANSPORT_PROFILE.EXTERNAL_TOR) {
    if (runtime === RUNTIME.NATIVE) return inventory.torNative === true
    if (runtime === RUNTIME.TOR_BROWSER) return inventory.torBrowser === true
  }
  return false
}

function validateExternalDisclosure (value) {
  const disclosure = reason => ({ code: 'SEMANTIC_SERVICE_DISCLOSURE_REQUIRED', reason })
  if (!isPlainObject(value)) return disclosure('semantic work must provide a complete external disclosure')
  assertOnlyFields(Object.keys(value), [
    'serviceId',
    'purpose',
    'operatorSees',
    'authority',
    'retention',
    'endpointEvidence',
    'networkTransport'
  ], 'external disclosure')
  if (typeof value.serviceId !== 'string' || value.serviceId.length === 0) return disclosure('external disclosure requires serviceId')
  if (typeof value.purpose !== 'string' || value.purpose.length === 0) return disclosure('external disclosure requires purpose')
  if (!Array.isArray(value.operatorSees) || value.operatorSees.length === 0 ||
      value.operatorSees.some(item => typeof item !== 'string' || item.length === 0)) return disclosure('external disclosure requires operatorSees')
  if (value.authority !== 'advisory' && value.authority !== 'authoritative') return disclosure('external disclosure authority is invalid')
  if (typeof value.retention !== 'string' || value.retention.length === 0) return disclosure('external disclosure requires retention')
  if (!validEndpointEvidence(value.endpointEvidence)) {
    return disclosure('external disclosure endpointEvidence must be a content-addressed sha256 or blake2b256 digest')
  }
  if (!Object.values(TRANSPORT_REQUIREMENT).includes(value.networkTransport)) {
    return disclosure('external disclosure requires a closed networkTransport')
  }
  return null
}

function validEndpointEvidence (value) {
  return typeof value === 'string' && /^(sha256|blake2b256):[0-9a-f]{64}$/i.test(value)
}

function externalDisclosureMetadata (value) {
  return deepFreeze({
    serviceId: value.serviceId,
    purpose: value.purpose,
    operatorSees: [...new Set(value.operatorSees)].sort(),
    authority: value.authority,
    retention: value.retention,
    networkTransport: value.networkTransport,
    endpointEvidenceMetadata: endpointEvidenceMetadata(value.endpointEvidence)
  })
}

function endpointEvidenceMetadata (value) {
  const separator = value.indexOf(':')
  return { kind: value.slice(0, separator).toLowerCase(), digest: value.toLowerCase() }
}

function externalTransportProfile (requirement) {
  if (requirement === TRANSPORT_REQUIREMENT.DIRECT) return TRANSPORT_PROFILE.EXTERNAL_DIRECT
  if (requirement === TRANSPORT_REQUIREMENT.SOURCE_SEPARATED) return TRANSPORT_PROFILE.EXTERNAL_SOURCE_SEPARATED
  return TRANSPORT_PROFILE.EXTERNAL_TOR
}

function planCell (workload, durability) {
  const destinationCountBasis = workload.operation === 'get' ? 'fetchTarget' : 'replicaTarget'
  if (workload.byteLength == null) {
    return Object.freeze({
      requiresChunkManifest: false,
      estimateStatus: 'size-basis-required',
      sizeClass: null,
      maximumCellPayloadBytes: maximumCellContentBytes(Math.max(...Object.keys(CELL_SIZE_CLASS).map(Number))),
      batchRecommended: null,
      destinationCountBasis,
      blindEnvelope: null
    })
  }
  const usefulBytes = Math.max(1, workload.byteLength)
  let sizeClass = null
  for (const id of Object.keys(CELL_SIZE_CLASS).map(Number).sort((a, b) => a - b)) {
    if (usefulBytes <= maximumCellContentBytes(id)) {
      sizeClass = id
      break
    }
  }
  if (sizeClass == null) {
    const maximumPayloadBytes = maximumCellContentBytes(Math.max(...Object.keys(CELL_SIZE_CLASS).map(Number)))
    return Object.freeze({
      requiresChunkManifest: true,
      maximumCellPayloadBytes: maximumPayloadBytes,
      minimumChunkCount: Math.ceil(usefulBytes / maximumPayloadBytes)
    })
  }
  const blindEnvelope = estimateCellWireV1({
    operation: workload.operation,
    sizeClass,
    usefulBytes,
    replicas: workload.operation === 'get' ? durability.fetchTarget : durability.replicaTarget
  })
  return Object.freeze({
    requiresChunkManifest: false,
    sizeClass,
    cellBytes: CELL_SIZE_CLASS[sizeClass],
    maximumCellPayloadBytes: maximumCellContentBytes(sizeClass),
    batchRecommended: sizeClass === 1 && usefulBytes < 2048,
    estimateStatus: 'exact-minimum-fitting-v1-envelope',
    destinationCountBasis,
    blindEnvelope
  })
}

function planInbox (workload) {
  const frameClasses = Object.entries(INBOX_FRAME_CLASS)
    .map(([id, bytes]) => ({ id: Number(id), bytes }))
    .sort((left, right) => left.bytes - right.bytes)
  const maximumFrameBytes = frameClasses[frameClasses.length - 1].bytes
  if (workload.byteLength == null) {
    return Object.freeze({
      exceedsMaximumFrame: false,
      estimateStatus: 'size-basis-required',
      frameClass: null,
      frameBytes: null,
      maximumFrameBytes
    })
  }
  const selected = frameClasses.find(candidate => workload.byteLength <= candidate.bytes)
  if (selected == null) {
    return Object.freeze({
      exceedsMaximumFrame: true,
      estimateStatus: 'over-maximum-universal-frame',
      usefulBytes: workload.byteLength,
      maximumFrameBytes
    })
  }
  return Object.freeze({
    exceedsMaximumFrame: false,
    estimateStatus: 'minimum-fitting-universal-frame',
    frameClass: selected.id,
    frameBytes: selected.bytes,
    usefulBytes: workload.byteLength,
    paddingAllowanceBytes: selected.bytes - workload.byteLength,
    maximumFrameBytes,
    accountingBoundary: 'opaque Inbox frame only; application framing and encryption must fit inside the selected class'
  })
}

function normalizeCostBudget (value) {
  if (value == null) return null
  if (!isPlainObject(value)) fail('BAD_CLIENT_INPUT', 'costBudget must be an object')
  const fields = Object.keys(value)
  if (value.maxWireAmplification != null) {
    fail('BAD_CLIENT_INPUT', 'maxWireAmplification is ambiguous; use maxBlindEnvelopeAmplification or an adapter fleet budget')
  }
  assertOnlyFields(fields, ['maxBlindEnvelopeAmplification'], 'costBudget')
  if (!Number.isFinite(value.maxBlindEnvelopeAmplification) || value.maxBlindEnvelopeAmplification <= 0) {
    fail('BAD_CLIENT_INPUT', 'maxBlindEnvelopeAmplification must be a positive finite number')
  }
  return Object.freeze({ maxBlindEnvelopeAmplification: value.maxBlindEnvelopeAmplification })
}

function smallestOuterClassBytes (requiredBytes) {
  for (const bytes of OUTER_CLASS_BYTES) {
    if (requiredBytes <= bytes) return bytes
  }
  fail('BAD_CLIENT_INPUT', 'operation exceeds every public v1 outer class')
}

function blocked (workload, runtime, primitive, intent, code, reason, extra = {}) {
  return deepFreeze({
    status: PLAN_STATUS.BLOCKED,
    code,
    reason,
    executable: false,
    workload: workload.kind,
    primitive,
    runtime,
    operation: workload.operation,
    requestedPrivacy: intent,
    downgraded: false,
    downgradeAuthorized: false,
    consentRequired: extra.consentRequired === true,
    ...extra
  })
}

function queueable (workload, runtime, primitive, intent, code, reason, extra = {}) {
  const journalableMutation = ['put', 'create', 'append', 'renew', 'close'].includes(workload.operation)
  return deepFreeze({
    status: PLAN_STATUS.QUEUEABLE,
    code,
    reason,
    executable: false,
    workload: workload.kind,
    primitive,
    runtime,
    operation: workload.operation,
    requestedPrivacy: intent,
    prospectiveQueue: {
      state: 'not-journaled',
      action: journalableMutation ? 'journal-mutation-intent' : 'wait-for-path',
      intentCanBeJournaled: journalableMutation,
      localVisible: false
    },
    downgraded: false,
    downgradeAuthorized: false,
    consentRequired: false,
    ...extra
  })
}

function axisRecord (requested, planned, state, requiredEvidence, axisAssumptions, claimCeiling) {
  return deepFreeze({
    requested,
    planned,
    state,
    requiredEvidence: [...requiredEvidence],
    assumptions: [...axisAssumptions],
    claimCeiling
  })
}

function transportRequiredEvidence (profile, runtime) {
  if (profile === TRANSPORT_PROFILE.P2P_DIRECT) {
    return [
      EVIDENCE_REQUIREMENT.P2P_SESSION_PREPARATION,
      EVIDENCE_REQUIREMENT.ADAPTER_CONFORMANCE
    ]
  }
  if (profile === TRANSPORT_PROFILE.EXTERNAL_DIRECT ||
      profile === TRANSPORT_PROFILE.EXTERNAL_SOURCE_SEPARATED ||
      profile === TRANSPORT_PROFILE.EXTERNAL_TOR) {
    const required = [
      EVIDENCE_REQUIREMENT.EXTERNAL_ENDPOINT_EVIDENCE,
      EVIDENCE_REQUIREMENT.EXTERNAL_CONNECTOR_CONFORMANCE,
      EVIDENCE_REQUIREMENT.DISCLOSURE_AUTHORIZATION
    ]
    if (profile === TRANSPORT_PROFILE.EXTERNAL_SOURCE_SEPARATED) {
      required.push(EVIDENCE_REQUIREMENT.ROLE_SEPARATION_CAPTURE)
      required.push(EVIDENCE_REQUIREMENT.NO_DIRECT_RACE_CAPTURE)
    }
    if (profile === TRANSPORT_PROFILE.EXTERNAL_TOR) {
      required.push(EVIDENCE_REQUIREMENT.NO_CLEARNET_CAPTURE)
    }
    if ((profile === TRANSPORT_PROFILE.EXTERNAL_SOURCE_SEPARATED ||
        profile === TRANSPORT_PROFILE.EXTERNAL_TOR) &&
        (runtime === RUNTIME.BROWSER || runtime === RUNTIME.TOR_BROWSER)) {
      required.push(EVIDENCE_REQUIREMENT.BROWSER_OPAQUE_ORIGIN_CAPTURE)
    }
    return required
  }
  const required = [
    EVIDENCE_REQUIREMENT.SIGNED_TRANSPORT_PROFILE,
    EVIDENCE_REQUIREMENT.VERIFIED_ENDPOINT,
    EVIDENCE_REQUIREMENT.FRESH_SIGNED_HEALTH,
    EVIDENCE_REQUIREMENT.ADAPTER_CONFORMANCE
  ]
  if (profile === TRANSPORT_PROFILE.OHTTP || profile === TRANSPORT_PROFILE.SPLIT_NATIVE) {
    required.push(EVIDENCE_REQUIREMENT.ROLE_SEPARATION_CAPTURE)
    required.push(EVIDENCE_REQUIREMENT.NO_DIRECT_RACE_CAPTURE)
  }
  if (profile === TRANSPORT_PROFILE.OHTTP) {
    required.push(EVIDENCE_REQUIREMENT.BROWSER_OPAQUE_ORIGIN_CAPTURE)
  }
  if (profile === TRANSPORT_PROFILE.TOR_NATIVE || profile === TRANSPORT_PROFILE.TOR_BROWSER) {
    required.push(EVIDENCE_REQUIREMENT.NO_CLEARNET_CAPTURE)
  }
  if (profile === TRANSPORT_PROFILE.TOR_BROWSER) {
    required.push(EVIDENCE_REQUIREMENT.BROWSER_OPAQUE_ORIGIN_CAPTURE)
  }
  return required
}

function transportClaim (profile) {
  if (profile === TRANSPORT_PROFILE.DIRECT) return 'source and access path visible to adjacent storage'
  if (profile === TRANSPORT_PROFILE.OHTTP || profile === TRANSPORT_PROFILE.SPLIT_NATIVE) {
    return 'source-separated only under adjacent-role non-collusion; timing and volume may correlate'
  }
  if (profile === TRANSPORT_PROFILE.TOR_NATIVE || profile === TRANSPORT_PROFILE.TOR_BROWSER) {
    return 'source/location separation under the Tor threat model; no global-observer claim'
  }
  if (profile === TRANSPORT_PROFILE.P2P_DIRECT) return 'direct peer path metadata is exposed to the network path'
  if (profile === TRANSPORT_PROFILE.EXTERNAL_DIRECT) return 'direct external connector; source and semantic request metadata are visible to the service path'
  if (profile === TRANSPORT_PROFILE.EXTERNAL_SOURCE_SEPARATED) {
    return 'external source-separated connector only under adjacent-role non-collusion; the service still sees disclosed semantics'
  }
  if (profile === TRANSPORT_PROFILE.EXTERNAL_TOR) {
    return 'external Tor connector under the Tor threat model; the service still sees disclosed semantics'
  }
  if (profile != null) return 'declared connector path; qualification remains service-specific'
  return 'no network transport selected'
}

function claimsFor (primitive, profile, runtime) {
  const representation = {
    [PRIMITIVE.CELL]: 'opaque immutable Cell; unlinkable replicas require fresh slots, keys, nonces and ciphertext',
    [PRIMITIVE.INBOX]: 'opaque bounded rendezvous; not authority, completeness or durable history',
    [PRIMITIVE.CORE]: 'encrypted append stream with stable transport-key linkability',
    [PRIMITIVE.P2P_DIRECT]: 'peer-authenticated live session; no storage durability by itself',
    [PRIMITIVE.LOCAL_COMPUTE]: 'local application trust boundary',
    [PRIMITIVE.EXTERNAL]: 'explicitly non-blind semantic service'
  }[primitive]
  const durability = {
    [PRIMITIVE.CELL]: 'no remote durability until replica receipts and exact readbacks are verified',
    [PRIMITIVE.INBOX]: 'bounded stripe/replica evidence only; never durable-history completeness',
    [PRIMITIVE.CORE]: 'no mirror durability until signed heads and challenged readback evidence are verified',
    [PRIMITIVE.P2P_DIRECT]: 'no offline or storage durability',
    [PRIMITIVE.LOCAL_COMPUTE]: 'application-defined local persistence only',
    [PRIMITIVE.EXTERNAL]: 'provider-specific retention; never Blind Cell/Inbox/Core durability'
  }[primitive]
  const readInterest = {
    [PRIMITIVE.CELL]: { status: 'known-visible', ceiling: 'requested Cell locators and access timing remain visible to storage' },
    [PRIMITIVE.INBOX]: { status: 'known-visible', ceiling: 'requested Inbox topics and access timing remain visible to storage' },
    [PRIMITIVE.CORE]: { status: 'known-visible', ceiling: 'requested Core keys and replication timing remain visible to blind peers' },
    [PRIMITIVE.P2P_DIRECT]: { status: 'not-applicable', ceiling: 'the storage-locator read-interest axis does not apply to a live peer session' },
    [PRIMITIVE.LOCAL_COMPUTE]: { status: 'not-applicable', ceiling: 'local compute has no network read-interest observer' },
    [PRIMITIVE.EXTERNAL]: { status: 'provider-visible', ceiling: 'the semantic provider can interpret request interest and result selection' }
  }[primitive]
  const browserOriginRequired = (runtime === RUNTIME.BROWSER || runtime === RUNTIME.TOR_BROWSER) &&
    (profile === TRANSPORT_PROFILE.OHTTP ||
      profile === TRANSPORT_PROFILE.TOR_BROWSER ||
      profile === TRANSPORT_PROFILE.EXTERNAL_SOURCE_SEPARATED ||
      profile === TRANSPORT_PROFILE.EXTERNAL_TOR)
  return deepFreeze({
    representation: { status: 'design-ceiling', ceiling: representation },
    transport: { status: profile == null ? 'not-applicable' : 'qualification-required', ceiling: transportClaim(profile) },
    readInterest,
    durability: { status: 'unverified-until-evidence', ceiling: durability },
    browserOriginGate: {
      status: browserOriginRequired ? 'qualification-required' : 'not-applicable',
      ceiling: browserOriginRequired
        ? 'browser source separation does not prove opaque application origin or Fetch Metadata until the capture gate passes'
        : null
    }
  })
}

function assumptions (profile) {
  if (profile === TRANSPORT_PROFILE.OHTTP || profile === TRANSPORT_PROFILE.SPLIT_NATIVE ||
      profile === TRANSPORT_PROFILE.EXTERNAL_SOURCE_SEPARATED) {
    return ['entry and storage roles do not collude', 'traffic timing and volume may correlate']
  }
  if (profile === TRANSPORT_PROFILE.TOR_NATIVE || profile === TRANSPORT_PROFILE.TOR_BROWSER ||
      profile === TRANSPORT_PROFILE.EXTERNAL_TOR) {
    return ['Tor threat model', 'no clearnet fallback', 'timing and volume remain observable']
  }
  return ['deployment inventory is planning input, not qualification evidence']
}

function warningsFor (intent, profile) {
  const warnings = []
  if (intent.readInterest === 'observable') warnings.push('requested locators and access timing remain visible to storage')
  if (intent.metadataShaping === 'padded') warnings.push('padding hides exact lengths only within universal classes')
  if (profile === TRANSPORT_PROFILE.TOR_BROWSER) warnings.push('browser Origin/Fetch Metadata claims require the separate opaque-origin gate')
  return warnings
}

function deepFreeze (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value) || ArrayBuffer.isView(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function isPlainObject (value) {
  if (value == null || typeof value !== 'object' || Array.isArray(value) || ArrayBuffer.isView(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function hasOwn (object, key) {
  return Object.prototype.hasOwnProperty.call(object, key)
}
