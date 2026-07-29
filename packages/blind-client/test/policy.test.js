import test from 'brittle'
import { maximumCellContentBytes } from '../cells.js'
import {
  DOWNGRADE_POLICY,
  EVIDENCE_REQUIREMENT,
  PLAN_STATUS,
  PRIMITIVE,
  RUNTIME,
  TRANSPORT_PROFILE,
  WORKLOAD,
  createPrivacyIntent,
  draftWorkloadPlan,
  estimateCellWireV1,
  privacy
} from '../policy.js'

const completeDisclosure = Object.freeze({
  serviceId: 'search-provider',
  purpose: 'full-text search',
  operatorSees: ['timing', 'query', 'query'],
  authority: 'advisory',
  retention: 'provider policy',
  endpointEvidence: `sha256:${'0'.repeat(64)}`,
  networkTransport: 'source-separated'
})

test('pure policy planning routes workloads but never manufactures executable evidence', t => {
  const inventory = { direct: true, ohttp: true, splitNative: true, torNative: true, core: true, p2p: true, external: true }
  const records = draftWorkloadPlan({ workload: WORKLOAD.RECORDS, runtime: RUNTIME.BROWSER, privacy: privacy.fast(), inventory })
  const inbox = draftWorkloadPlan({ workload: WORKLOAD.RENDEZVOUS, runtime: RUNTIME.BROWSER, privacy: privacy.private(), inventory })
  const history = draftWorkloadPlan({ workload: WORKLOAD.HISTORY, runtime: RUNTIME.NATIVE, privacy: privacy.private(), inventory })
  const live = draftWorkloadPlan({ workload: WORKLOAD.LIVE, runtime: RUNTIME.NATIVE, privacy: privacy.fast(), inventory })
  const semantic = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'external' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    inventory,
    externalDisclosure: completeDisclosure
  })

  for (const plan of [records, inbox, history, live, semantic]) {
    t.is(plan.status, PLAN_STATUS.DRAFT)
    t.is(plan.executable, false)
    for (const axis of Object.values(plan.privacyResolution)) {
      if (axis.state.endsWith('-required')) t.ok(axis.requiredEvidence.length > 0)
    }
  }
  t.is(records.primitive, PRIMITIVE.CELL)
  t.is(records.intendedTransportProfile, TRANSPORT_PROFILE.DIRECT)
  t.is(inbox.primitive, PRIMITIVE.INBOX)
  t.is(inbox.intendedTransportProfile, TRANSPORT_PROFILE.OHTTP)
  t.ok(inbox.privacyResolution.transport.requiredEvidence.includes(
    EVIDENCE_REQUIREMENT.BROWSER_OPAQUE_ORIGIN_CAPTURE
  ))
  t.is(inbox.claims.browserOriginGate.status, 'qualification-required')
  t.is(history.primitive, PRIMITIVE.CORE)
  t.is(history.intendedTransportProfile, TRANSPORT_PROFILE.SPLIT_NATIVE)
  t.is(history.wireOperation.operation, 'MIRROR')
  t.is(history.wireOperation.operationId, 1)
  t.is(history.claims.representation.ceiling, 'encrypted append stream with stable transport-key linkability')
  t.is(live.primitive, PRIMITIVE.P2P_DIRECT)
  t.is(semantic.primitive, PRIMITIVE.EXTERNAL)
  t.is(semantic.semanticBoundary, 'explicitly-non-blind')
  t.is(semantic.claims.semanticDisclosure.claimCeiling, 'explicitly non-blind semantic service')
  t.alike(semantic.claims.semanticDisclosure.operatorSees, ['query', 'timing'])
  t.ok(semantic.privacyResolution.transport.requiredEvidence.includes(
    EVIDENCE_REQUIREMENT.ROLE_SEPARATION_CAPTURE
  ))
  t.ok(semantic.privacyResolution.transport.requiredEvidence.includes(
    EVIDENCE_REQUIREMENT.NO_DIRECT_RACE_CAPTURE
  ))
  t.ok(semantic.privacyResolution.transport.requiredEvidence.includes(
    EVIDENCE_REQUIREMENT.BROWSER_OPAQUE_ORIGIN_CAPTURE
  ))
  t.is(semantic.claims.browserOriginGate.status, 'qualification-required')

  const torDisclosure = {
    ...completeDisclosure,
    networkTransport: 'tor'
  }
  const highPrivacyExternal = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'external' },
    runtime: RUNTIME.NATIVE,
    privacy: privacy.highPrivacy(),
    inventory,
    externalDisclosure: torDisclosure
  })
  t.is(highPrivacyExternal.status, PLAN_STATUS.DRAFT)
  t.ok(highPrivacyExternal.privacyResolution.transport.requiredEvidence.includes(
    EVIDENCE_REQUIREMENT.NO_CLEARNET_CAPTURE
  ))
  t.is(highPrivacyExternal.claims.browserOriginGate.status, 'not-applicable')
})

test('ordinary browser history changes representation to Cells without changing privacy', t => {
  const plan = draftWorkloadPlan({
    workload: { kind: WORKLOAD.HISTORY, byteLength: 2048 },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    inventory: { ohttp: true, core: false }
  })
  t.is(plan.status, PLAN_STATUS.DRAFT)
  t.is(plan.primitive, PRIMITIVE.CELL)
  t.is(plan.intendedTransportProfile, TRANSPORT_PROFILE.OHTTP)
  t.is(plan.downgraded, false)
})

test('private downgrade remains consent-pending in the pure draft planner', t => {
  const options = {
    workload: WORKLOAD.RECORDS,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    inventory: { direct: true, ohttp: false }
  }
  const pending = draftWorkloadPlan(options)
  t.is(pending.status, PLAN_STATUS.QUEUEABLE)
  t.is(pending.code, 'DOWNGRADE_CONSENT_REQUIRED')
  t.is(pending.consentRequired, true)
  t.is(pending.suggestedTransportProfile, TRANSPORT_PROFILE.DIRECT)
  t.is(pending.prospectiveQueue.state, 'not-journaled')
  t.is(pending.prospectiveQueue.action, 'journal-mutation-intent')
  t.exception(() => draftWorkloadPlan({
    ...options,
    downgradeAuthorization: { consentId: 'caller-asserted' }
  }), /cannot consume downgrade authorization/)
  t.exception(() => draftWorkloadPlan({
    ...options,
    disclosureAuthorization: { consentId: 'caller-asserted' }
  }), /cannot consume disclosure authorization/)
})

test('queueable results are prospective and operation-aware', t => {
  const mutation = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, operation: 'put' },
    runtime: RUNTIME.NATIVE,
    privacy: privacy.highPrivacy(),
    inventory: { direct: true, torNative: false }
  })
  t.is(mutation.status, PLAN_STATUS.QUEUEABLE)
  t.is(mutation.code, 'QUEUEABLE_PRIVACY_PATH_UNAVAILABLE')
  t.absent(mutation.localState)
  t.is(mutation.prospectiveQueue.state, 'not-journaled')
  t.is(mutation.prospectiveQueue.action, 'journal-mutation-intent')
  t.is(mutation.prospectiveQueue.intentCanBeJournaled, true)
  t.is(mutation.prospectiveQueue.localVisible, false)
  t.is(mutation.intendedTransportProfile, TRANSPORT_PROFILE.TOR_NATIVE)
  t.is(mutation.privacyResolution.transport.state, 'qualification-required')
  t.is(mutation.cell.estimateStatus, 'size-basis-required')
  t.ok(mutation.claims.transport)

  const read = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, operation: 'get' },
    runtime: RUNTIME.NATIVE,
    privacy: privacy.highPrivacy(),
    inventory: { torNative: false }
  })
  t.is(read.status, PLAN_STATUS.QUEUEABLE)
  t.is(read.prospectiveQueue.action, 'wait-for-path')
  t.is(read.prospectiveQueue.intentCanBeJournaled, false)
  t.is(read.operation, 'get')
})

test('fixed presets are immutable and axes are prospective per primitive', t => {
  t.exception(() => privacy.highPrivacy({ transport: 'direct' }), /immutable preset/)
  t.exception(() => draftWorkloadPlan({
    workload: WORKLOAD.RECORDS,
    runtime: RUNTIME.NATIVE,
    privacy: {
      ...privacy.highPrivacy(),
      transport: 'direct'
    },
    inventory: { direct: true }
  }), /immutable preset/)

  const unsupported = draftWorkloadPlan({
    workload: WORKLOAD.RENDEZVOUS,
    runtime: RUNTIME.NATIVE,
    privacy: privacy.custom({
      transport: 'source-separated',
      metadataShaping: 'bucketed-experimental',
      identityExposure: 'anonymous-reply',
      readInterest: 'bucketed-experimental',
      downgradePolicy: DOWNGRADE_POLICY.DENY,
      backgroundPreferred: true
    }),
    inventory: { splitNative: true }
  })
  t.is(unsupported.status, PLAN_STATUS.BLOCKED)
  t.is(unsupported.code, 'PRIVACY_AXIS_UNSUPPORTED')
  t.is(unsupported.privacyResolution.metadataShaping.state, 'unsupported')
  t.is(unsupported.privacyResolution.identityExposure.state, 'application-policy-required')
  t.is(unsupported.privacyResolution.readInterest.state, 'unsupported')

  const supported = draftWorkloadPlan({
    workload: WORKLOAD.RENDEZVOUS,
    runtime: RUNTIME.NATIVE,
    privacy: privacy.custom({
      transport: 'source-separated',
      metadataShaping: 'padded',
      identityExposure: 'session',
      readInterest: 'observable',
      downgradePolicy: DOWNGRADE_POLICY.DENY,
      backgroundPreferred: true
    }),
    inventory: { splitNative: true }
  })
  t.is(supported.status, PLAN_STATUS.DRAFT)
  t.is(supported.intendedTransportProfile, TRANSPORT_PROFILE.SPLIT_NATIVE)
  t.is(supported.privacyResolution.metadataShaping.state, 'qualification-required')
  t.is(supported.privacyResolution.identityExposure.state, 'application-policy-required')
  t.is(supported.privacyResolution.readInterest.state, 'known-visible')

  const local = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'local' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.custom({
      transport: 'tor',
      metadataShaping: 'bucketed-experimental',
      identityExposure: 'anonymous-reply',
      readInterest: 'bucketed-experimental',
      downgradePolicy: DOWNGRADE_POLICY.DENY,
      backgroundPreferred: false
    })
  })
  t.is(local.status, PLAN_STATUS.DRAFT)
  for (const axis of Object.values(local.privacyResolution)) {
    t.is(axis.state, 'not-applicable')
    t.is(Object.prototype.hasOwnProperty.call(axis, 'actual'), false)
  }

  const live = draftWorkloadPlan({
    workload: WORKLOAD.LIVE,
    runtime: RUNTIME.NATIVE,
    privacy: privacy.fast(),
    inventory: { p2p: true }
  })
  t.is(live.privacyResolution.metadataShaping.state, 'adapter-qualification-required')
  t.is(live.privacyResolution.identityExposure.state, 'adapter-qualification-required')
  t.is(live.privacyResolution.readInterest.state, 'not-applicable')
  t.is(Object.prototype.hasOwnProperty.call(live.privacyResolution.metadataShaping, 'actual'), false)

  const core = draftWorkloadPlan({
    workload: WORKLOAD.HISTORY,
    runtime: RUNTIME.NATIVE,
    privacy: privacy.private(),
    inventory: { core: true, splitNative: true }
  })
  t.is(core.privacyResolution.metadataShaping.planned, 'stream-shaping-adapter-defined')
  t.is(core.privacyResolution.metadataShaping.state, 'qualification-required')
  t.is(Object.prototype.hasOwnProperty.call(core.privacyResolution.transport, 'actual'), false)

  const based = privacy.custom({ base: 'private', backgroundPreferred: true })
  t.is(based.preset, 'custom')
  t.is(based.base, 'private')
  t.is(based.transport, 'source-separated')
  t.is(based.backgroundPreferred, true)
})

test('semantic execution defaults local and external disclosure remains consent-pending', t => {
  const local = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'local' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private()
  })
  t.is(local.status, PLAN_STATUS.DRAFT)
  t.is(local.primitive, PRIMITIVE.LOCAL_COMPUTE)
  t.is(local.intendedTransportProfile, null)
  t.is(local.claims.readInterest.status, 'not-applicable')

  const localByDefault = draftWorkloadPlan({
    workload: WORKLOAD.SEMANTIC,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private()
  })
  t.is(localByDefault.status, PLAN_STATUS.DRAFT)
  t.is(localByDefault.primitive, PRIMITIVE.LOCAL_COMPUTE)

  const missing = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'external' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    inventory: { external: true, ohttp: true },
    externalDisclosure: { serviceId: 'search-provider', operatorSees: ['query'] }
  })
  t.is(missing.status, PLAN_STATUS.BLOCKED)
  t.is(missing.code, 'SEMANTIC_SERVICE_DISCLOSURE_REQUIRED')

  const mismatch = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'external' },
    runtime: RUNTIME.NATIVE,
    privacy: privacy.highPrivacy(),
    inventory: { external: true, ohttp: true },
    externalDisclosure: completeDisclosure
  })
  t.is(mismatch.status, PLAN_STATUS.BLOCKED)
  t.is(mismatch.code, 'PRIVACY_AXIS_UNSUPPORTED')

  const external = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'external' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    inventory: { external: true, ohttp: true },
    externalDisclosure: completeDisclosure
  })
  t.is(external.status, PLAN_STATUS.DRAFT)
  t.is(external.code, 'EXTERNAL_CONNECTOR_QUALIFICATION_REQUIRED')
  t.is(external.intendedTransportProfile, TRANSPORT_PROFILE.EXTERNAL_SOURCE_SEPARATED)
  t.absent(external.externalDisclosure.endpointEvidence)
  t.is(external.externalDisclosure.endpointEvidenceMetadata.kind, 'sha256')
  t.is(external.externalDisclosure.endpointEvidenceMetadata.digest, completeDisclosure.endpointEvidence)
  t.alike(external.externalDisclosure.operatorSees, ['query', 'timing'])
  t.absent(external.externalDisclosure.consentDeclaration)
  t.is(external.consentRequired, true)
  t.is(external.consentStatus, 'qualification-required')
  t.is(external.claims.semanticDisclosure.authority, completeDisclosure.authority)
  t.is(external.claims.semanticDisclosure.retention, completeDisclosure.retention)
  t.exception.all(() => {
    external.externalDisclosure.endpointEvidenceMetadata.digest = 'sha256:changed'
  }, /read only|Cannot assign/)

  const invalidEvidence = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'external' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    inventory: { external: true },
    externalDisclosure: { ...completeDisclosure, endpointEvidence: new Map() }
  })
  t.is(invalidEvidence.status, PLAN_STATUS.BLOCKED)
  t.is(invalidEvidence.code, 'SEMANTIC_SERVICE_DISCLOSURE_REQUIRED')

  t.exception(() => draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'external' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    inventory: { external: true },
    externalDisclosure: { ...completeDisclosure, userConsent: { consentId: 'caller-shaped', grantedAt: 1 } }
  }), /unknown fields/)

  const missingOffline = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'external' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    inventory: { external: false },
    externalDisclosure: { serviceId: 'search-provider' }
  })
  t.is(missingOffline.code, 'SEMANTIC_SERVICE_DISCLOSURE_REQUIRED')

  const unavailable = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'external' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    inventory: { external: false, ohttp: false },
    externalDisclosure: completeDisclosure
  })
  t.is(unavailable.status, PLAN_STATUS.QUEUEABLE)
  t.is(unavailable.code, 'EXTERNAL_SERVICE_UNAVAILABLE')
  t.is(unavailable.prospectiveQueue.action, 'wait-for-path')
  t.alike(unavailable.externalDisclosure.operatorSees, ['query', 'timing'])
  t.ok(unavailable.privacyResolution.transport.requiredEvidence.length > 0)
  t.ok(unavailable.claims.semanticDisclosure)
})

test('live traffic exposes its direct-path conflict and preparation boundary', t => {
  const blocked = draftWorkloadPlan({
    workload: WORKLOAD.LIVE,
    runtime: RUNTIME.NATIVE,
    privacy: privacy.highPrivacy(),
    inventory: { p2p: true, torNative: true }
  })
  t.is(blocked.status, PLAN_STATUS.BLOCKED)
  t.is(blocked.code, 'WORKLOAD_PRIVACY_CONFLICT')

  const draft = draftWorkloadPlan({
    workload: WORKLOAD.LIVE,
    runtime: RUNTIME.NATIVE,
    privacy: privacy.fast(),
    inventory: { p2p: true }
  })
  t.is(draft.status, PLAN_STATUS.DRAFT)
  t.is(draft.code, 'P2P_SESSION_PREPARATION_REQUIRED')

  const unavailable = draftWorkloadPlan({
    workload: WORKLOAD.LIVE,
    runtime: RUNTIME.NATIVE,
    privacy: privacy.fast(),
    inventory: { p2p: false }
  })
  t.is(unavailable.status, PLAN_STATUS.QUEUEABLE)
  t.is(unavailable.code, 'P2P_PATH_UNAVAILABLE')
  t.is(unavailable.prospectiveQueue.action, 'wait-for-path')
  t.is(unavailable.intendedTransportProfile, TRANSPORT_PROFILE.P2P_DIRECT)
})

test('primitive overrides use a closed workload and runtime matrix', t => {
  const externalRecord = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, primitive: PRIMITIVE.EXTERNAL },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true, external: true }
  })
  t.is(externalRecord.status, PLAN_STATUS.BLOCKED)
  t.is(externalRecord.code, 'WORKLOAD_PRIMITIVE_UNSUPPORTED')

  const browserCore = draftWorkloadPlan({
    workload: { kind: WORKLOAD.HISTORY, primitive: PRIMITIVE.CORE },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true, core: true }
  })
  t.is(browserCore.status, PLAN_STATUS.BLOCKED)
  t.is(browserCore.code, 'WORKLOAD_PRIMITIVE_UNSUPPORTED')

  const localAsExternal = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'local', primitive: PRIMITIVE.EXTERNAL },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    inventory: { external: true },
    externalDisclosure: completeDisclosure
  })
  t.is(localAsExternal.status, PLAN_STATUS.BLOCKED)
  t.is(localAsExternal.code, 'WORKLOAD_PRIMITIVE_CONFLICT')

  const externalAsLocal = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'external', primitive: PRIMITIVE.LOCAL_COMPUTE },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private()
  })
  t.is(externalAsLocal.status, PLAN_STATUS.BLOCKED)
  t.is(externalAsLocal.code, 'WORKLOAD_PRIMITIVE_CONFLICT')

  const localWithDisclosure = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'local' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    externalDisclosure: completeDisclosure
  })
  t.is(localWithDisclosure.status, PLAN_STATUS.BLOCKED)
  t.is(localWithDisclosure.code, 'WORKLOAD_DISCLOSURE_CONFLICT')
})

test('durability policies are primitive-specific and physically valid', t => {
  const inbox = draftWorkloadPlan({
    workload: WORKLOAD.RENDEZVOUS,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true }
  })
  t.is(inbox.durability.stripeCountLog2, 3)
  t.is(inbox.durability.stripeCount, 8)
  t.is(inbox.durability.replicaTargetPerStripe, 3)
  t.is(inbox.durability.appendAcknowledgementTargetPerStripe, 2)
  t.is(inbox.durability.readbackTargetPerStripe, 2)
  t.is(inbox.durability.independentOperatorGroups, 2)
  t.is(inbox.inbox.estimateStatus, 'size-basis-required')

  for (const [byteLength, frameClass, frameBytes] of [
    [1, 1, 4096],
    [4096, 1, 4096],
    [4097, 2, 16384],
    [16385, 3, 65536],
    [65536, 3, 65536]
  ]) {
    const sized = draftWorkloadPlan({
      workload: { kind: WORKLOAD.RENDEZVOUS, operation: 'append', byteLength },
      runtime: RUNTIME.BROWSER,
      privacy: privacy.fast(),
      inventory: { direct: true }
    })
    t.is(sized.status, PLAN_STATUS.DRAFT)
    t.is(sized.inbox.frameClass, frameClass)
    t.is(sized.inbox.frameBytes, frameBytes)
    t.is(sized.wireOperation.operation, 'APPEND')
  }

  const oversizedInbox = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RENDEZVOUS, operation: 'append', byteLength: 65537 },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: false }
  })
  t.is(oversizedInbox.status, PLAN_STATUS.BLOCKED)
  t.is(oversizedInbox.code, 'RENDEZVOUS_FRAME_TOO_LARGE')
  t.is(oversizedInbox.inbox.maximumFrameBytes, 65536)

  for (let stripeCountLog2 = 0; stripeCountLog2 <= 6; stripeCountLog2++) {
    const plan = draftWorkloadPlan({
      workload: WORKLOAD.RENDEZVOUS,
      runtime: RUNTIME.BROWSER,
      privacy: privacy.fast(),
      inventory: { direct: true },
      durability: { stripeCountLog2 }
    })
    t.is(plan.durability.stripeCount, 2 ** stripeCountLog2)
  }

  t.exception(() => draftWorkloadPlan({
    workload: WORKLOAD.RENDEZVOUS,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true },
    durability: { stripeTarget: 3 }
  }), /unknown fields/)
  t.exception(() => draftWorkloadPlan({
    workload: WORKLOAD.RENDEZVOUS,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true },
    durability: { replicaTargetPerStripe: 2, appendAcknowledgementTargetPerStripe: 3 }
  }), /cannot exceed replicaTargetPerStripe/)
  t.exception(() => draftWorkloadPlan({
    workload: WORKLOAD.RENDEZVOUS,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true },
    durability: { readbackTargetPerStripe: 1, independentOperatorGroups: 2 }
  }), /cannot exceed readbackTargetPerStripe/)

  const cell = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, byteLength: 1024 },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true }
  })
  t.is(cell.durability.fetchTarget, 1)
  t.is(cell.durability.independentOperatorGroups, 2)
  t.exception(() => draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, byteLength: 1024 },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true },
    durability: { readbackTarget: 1, independentOperatorGroups: 2 }
  }), /cannot exceed readbackTarget/)

  const live = draftWorkloadPlan({
    workload: WORKLOAD.LIVE,
    runtime: RUNTIME.NATIVE,
    privacy: privacy.fast(),
    inventory: { p2p: true },
    durability: { replicaTarget: 3 }
  })
  t.is(live.status, PLAN_STATUS.BLOCKED)
  t.is(live.code, 'WORKLOAD_DURABILITY_CONFLICT')
})

test('v1 estimator exposes exact blind-envelope amplification for every Cell class', t => {
  const rows = [
    { sizeClass: 1, put: 65536, get: 16384 },
    { sizeClass: 2, put: 65536, get: 65536 },
    { sizeClass: 3, put: 262144, get: 262144 },
    { sizeClass: 4, put: 1048576, get: 1048576 },
    { sizeClass: 5, put: 8388608, get: 8388608 }
  ]
  for (const row of rows) {
    const put = estimateCellWireV1({ operation: 'PUT', sizeClass: row.sizeClass, usefulBytes: 1, replicas: 3 })
    const get = estimateCellWireV1({ operation: 'GET', sizeClass: row.sizeClass, usefulBytes: 1 })
    t.is(put.requestOuterBytes, row.put)
    t.is(put.responseOuterBytes, row.put)
    t.is(get.requestOuterBytes, row.get)
    t.is(get.responseOuterBytes, row.get)
    t.is(put.totalOuterBytes, row.put * 2 * 3)
    t.is(get.totalOuterBytes, row.get * 2)
  }
  const smallPut = estimateCellWireV1({ operation: 'PUT', sizeClass: 1, usefulBytes: 1024, replicas: 3 })
  t.is(smallPut.totalOuterBytes, 393216)
  t.is(smallPut.usefulByteAmplification, 384)
  const maximumContent = estimateCellWireV1({ operation: 'PUT', sizeClass: 1 })
  t.is(maximumContent.usefulBytes, maximumCellContentBytes(1))
  t.exception(() => estimateCellWireV1({
    operation: 'PUT',
    sizeClass: 1,
    usefulBytes: 1,
    transportBytes: 1
  }), /unknown fields/)
})

test('Cell representation blockers are invariant under transport availability', t => {
  const plan = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, byteLength: 2 * 1024 * 1024 },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: false },
    costBudget: { maxBlindEnvelopeAmplification: 100 }
  })
  t.is(plan.status, PLAN_STATUS.BLOCKED)
  t.is(plan.code, 'CHUNK_MANIFEST_REQUIRED')
  t.ok(plan.chunking.minimumChunkCount > 1)
})

test('placement and exact Cell cost bases never depend on temporary availability', t => {
  const availableRecord = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, byteLength: 2048 },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true }
  })
  const unavailableRecord = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, byteLength: 2048 },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: false }
  })
  t.is(availableRecord.status, PLAN_STATUS.DRAFT)
  t.is(unavailableRecord.status, PLAN_STATUS.QUEUEABLE)
  for (const field of [
    'primitive',
    'wireOperation',
    'cell',
    'durability',
    'costBudget',
    'intendedTransportProfile',
    'privacyResolution',
    'claims',
    'assumptions',
    'warnings'
  ]) t.alike(unavailableRecord[field], availableRecord[field])

  const history = draftWorkloadPlan({
    workload: WORKLOAD.HISTORY,
    runtime: RUNTIME.NATIVE,
    privacy: privacy.fast(),
    inventory: { direct: true, core: false }
  })
  t.is(history.primitive, PRIMITIVE.CORE)
  t.is(history.status, PLAN_STATUS.QUEUEABLE)
  t.is(history.code, 'QUEUEABLE_CORE_STREAM_UNAVAILABLE')
  t.is(history.intendedTransportProfile, TRANSPORT_PROFILE.DIRECT)
  t.is(history.privacyResolution.transport.state, 'qualification-required')
  t.is(history.wireOperation.operation, 'MIRROR')

  const historyRead = draftWorkloadPlan({
    workload: { kind: WORKLOAD.HISTORY, operation: 'get' },
    runtime: RUNTIME.NATIVE,
    privacy: privacy.private(),
    inventory: { core: true, splitNative: true }
  })
  t.is(historyRead.status, PLAN_STATUS.DRAFT)
  t.is(historyRead.operation, 'get')
  t.is(historyRead.wireOperation.operation, 'OPEN_REPLICATION')
  t.is(historyRead.wireOperation.operationId, 3)

  const unknownSize = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, operation: 'get' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true }
  })
  t.is(unknownSize.status, PLAN_STATUS.DRAFT)
  t.is(unknownSize.cell.estimateStatus, 'size-basis-required')
  t.is(unknownSize.cell.blindEnvelope, null)

  const exactRead = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, operation: 'get', byteLength: 1024 },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true },
    durability: { replicaTarget: 5, readbackTarget: 2, fetchTarget: 1, independentOperatorGroups: 2 }
  })
  t.is(exactRead.cell.destinationCountBasis, 'fetchTarget')
  t.is(exactRead.cell.blindEnvelope.destinationCount, 1)

  const noCostBasis = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, operation: 'get' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: false },
    costBudget: { maxBlindEnvelopeAmplification: 1000 }
  })
  t.is(noCostBasis.status, PLAN_STATUS.BLOCKED)
  t.is(noCostBasis.code, 'COST_EVIDENCE_UNAVAILABLE')
})

test('cost budgets name the exact accounting boundary', t => {
  const blocked = draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, byteLength: 1024 },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true },
    costBudget: { maxBlindEnvelopeAmplification: 100 }
  })
  t.is(blocked.status, PLAN_STATUS.BLOCKED)
  t.is(blocked.code, 'COST_BUDGET_EXCEEDED')
  t.is(blocked.suggestion, 'batch-small-records')
  t.ok(blocked.estimate.accountingBoundary.includes('transport wrappers'))

  t.exception(() => draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, byteLength: 1024 },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: false },
    costBudget: { maxWireAmplification: 100 }
  }), /ambiguous/)

  const live = draftWorkloadPlan({
    workload: WORKLOAD.LIVE,
    runtime: RUNTIME.NATIVE,
    privacy: privacy.fast(),
    inventory: { p2p: true },
    costBudget: { maxBlindEnvelopeAmplification: 10 }
  })
  t.is(live.status, PLAN_STATUS.BLOCKED)
  t.is(live.code, 'COST_EVIDENCE_UNAVAILABLE')

  const external = draftWorkloadPlan({
    workload: { kind: WORKLOAD.SEMANTIC, execution: 'external' },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.private(),
    inventory: { external: true },
    externalDisclosure: completeDisclosure,
    costBudget: { maxBlindEnvelopeAmplification: 10 }
  })
  t.is(external.status, PLAN_STATUS.BLOCKED)
  t.is(external.code, 'COST_EVIDENCE_UNAVAILABLE')

  t.exception(() => draftWorkloadPlan({
    workload: WORKLOAD.RECORDS,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: {},
    costBudget: { maxBlindEnvelopeAmplification: 10, maxForegroundBytes: 1 }
  }), /unknown fields/)
})

test('planner inputs are closed plain-data schemas', t => {
  const objectPrototypeWasFrozen = Object.isFrozen(Object.prototype)
  for (const inheritedName of ['__proto__', 'constructor', 'toString']) {
    t.exception(() => createPrivacyIntent(inheritedName), /unknown privacy preset/)
    t.exception(() => privacy.custom({ base: inheritedName }), /custom privacy base is invalid/)
    t.exception(() => draftWorkloadPlan({
      workload: WORKLOAD.SEMANTIC,
      runtime: RUNTIME.BROWSER,
      privacy: inheritedName
    }), /unknown privacy preset/)
  }
  t.is(Object.isFrozen(Object.prototype), objectPrototypeWasFrozen)
  t.exception(() => draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, byteLength: 0 },
    runtime: RUNTIME.BROWSER
  }), /positive safe integer/)
  t.exception(() => draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, byteLenght: 2 * 1024 * 1024 },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true }
  }), /unknown fields/)
  t.exception(() => draftWorkloadPlan({
    workload: WORKLOAD.RECORDS,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { driect: true }
  }), /unknown fields/)
  t.exception(() => draftWorkloadPlan({
    workload: WORKLOAD.RECORDS,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: 'yes' }
  }), /must be boolean/)
  t.exception(() => draftWorkloadPlan({
    workload: WORKLOAD.RECORDS,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: false
  }), /inventory must be an object/)
  t.exception(() => draftWorkloadPlan({
    workload: WORKLOAD.RECORDS,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true },
    costBuget: { maxBlindEnvelopeAmplification: 10 }
  }), /unknown fields/)
  t.exception(() => draftWorkloadPlan({
    workload: { kind: WORKLOAD.RECORDS, primitive: PRIMITIVE.P2P_DIRECT },
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    costBudget: { maxWireAmplification: 10 }
  }), /ambiguous/)
  const misplacedDisclosure = draftWorkloadPlan({
    workload: WORKLOAD.RECORDS,
    runtime: RUNTIME.BROWSER,
    privacy: privacy.fast(),
    inventory: { direct: true },
    externalDisclosure: completeDisclosure
  })
  t.is(misplacedDisclosure.status, PLAN_STATUS.BLOCKED)
  t.is(misplacedDisclosure.code, 'WORKLOAD_DISCLOSURE_CONFLICT')
  t.exception(() => draftWorkloadPlan(Object.assign(Object.create({ inherited: true }), {
    workload: WORKLOAD.RECORDS,
    runtime: RUNTIME.BROWSER
  })), /options are required/)
})
