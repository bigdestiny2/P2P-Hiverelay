import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  createCustodyIntent,
  verifyCustodyEntry
} from '../custody-signing.js'
import {
  SEED_PROTOCOL_HANDSHAKE_MAX_BYTES,
  SEED_PROTOCOL_VERSION,
  evaluateSeedProtocolHandshake
} from './seed-request.js'
import {
  buildCapabilityDoc,
  capabilityDocSignablePayload,
  verifyCapabilityDoc
} from '../capability-doc.js'
import {
  accountingReceiptSignable,
  verifyAccountingReceipt
} from './accounting-receipt.js'
import {
  RETRIEVABILITY_PROOF_DOMAIN,
  RETRIEVABILITY_PROOF_SIGNATURE_PROFILE,
  retrievabilityProofSignable,
  storageProofSignable
} from './proof-of-storage.js'
import {
  buildRelayKernelProfile,
  validateRelayKernelProfile
} from './relaykernel-profile.js'
import {
  buildHiveMeshTierProfile,
  validateHiveMeshTierProfile
} from './hivemesh-tier-profile.js'
import {
  buildWitnessQuorumPolicy,
  evaluateWitnessQuorum,
  validateWitnessQuorumPolicy
} from './witness-quorum-policy.js'
import {
  scoreRelayKernelReputation
} from './relaykernel-reputation-profile.js'
import {
  evaluateRelayKernelSeedLeaseProfile
} from './relaykernel-seed-lease-profile.js'
import {
  evaluateRoleDomainSignatureProfile
} from './role-domain-signature.js'
import {
  buildRelayKernelMetaProfile,
  validateRelayKernelMetaProfile
} from './relaykernel-meta-profile.js'
import {
  evaluateHiveMeshProveHeldProfile
} from './hivemesh-prove-held-profile.js'
import {
  scoreHiveMeshTierReputation
} from './hivemesh-tier-reputation-profile.js'
import {
  evaluateHiveMeshTombstoneAdjudicationProfile
} from './hivemesh-tombstone-adjudication-profile.js'
import {
  evaluateRelayKernelCircuitLimitsProfile
} from './relaykernel-circuit-limits-profile.js'
import {
  relayReserveEncoding,
  seedAcceptEncoding,
  seedDenyEncoding,
  seedRequestEncoding,
  unseedRequestEncoding
} from './messages.js'
import {
  circuitCloseEncoding,
  circuitConnectEncoding,
  circuitDataEncoding,
  circuitReadyEncoding,
  circuitStatusEncoding
} from './relay-circuit.js'

export function verifyProfileVector (vector) {
  const errors = []
  const warnings = []
  if (!vector || typeof vector !== 'object') {
    return { valid: false, name: null, errors: ['vector object required'], warnings }
  }

  const name = typeof vector.name === 'string' ? vector.name : null
  try {
    if (!name) errors.push('vector name required')
    else if (name === 'accounting-receipt-v1-os-grounded') verifyAccountingVector(vector, errors)
    else if (name === 'retrievability-proof-signable-v1') verifyRetrievabilityVector(vector, errors)
    else if (name === 'relaykernel-profile-v1-minimal-compat') verifyRelayKernelVector(vector, errors)
    else if (name === 'hivemesh-tier-profile-v1-t2-custody-vault') verifyHiveMeshVector(vector, errors)
    else if (name === 'witness-quorum-policy-v1-5-of-7-diverse') verifyWitnessQuorumVector(vector, errors)
    else if (name === 'custody-allowlist-v2-strict') verifyCustodyAllowlistVector(vector, errors)
    else if (name === 'relaykernel-reputation-profile-v1-no-self-attestation') verifyReputationVector(vector, errors)
    else if (name === 'relaykernel-seed-lease-profile-v1-caps-replay') verifySeedLeaseVector(vector, errors)
    else if (name === 'role-domain-signature-profile-v1-prefix-domain') verifyRoleDomainVector(vector, errors)
    else if (name === 'relaykernel-meta-profile-v1-opt-in-directory') verifyRelayKernelMetaVector(vector, errors)
    else if (name === 'relaykernel-meta-profile-v1-reserved-namespace-reject') verifyRelayKernelMetaVector(vector, errors)
    else if (name === 'hivemesh-prove-held-profile-v1-commit-reveal') verifyHiveMeshProveHeldVector(vector, errors)
    else if (name === 'hivemesh-tier-reputation-profile-v1-no-global-score') verifyHiveMeshTierReputationVector(vector, errors)
    else if (name === 'hivemesh-tombstone-adjudication-profile-v1-false-tombstone') verifyHiveMeshTombstoneAdjudicationVector(vector, errors)
    else if (name === 'relaykernel-circuit-limits-profile-v1-hard-caps') verifyRelayKernelCircuitLimitsVector(vector, errors)
    else if (name === 'capability-doc-signature-v1') verifyCapabilityDocVector(vector, errors)
    else if (name === 'seed-protocol-binary-v1') verifySeedProtocolBinaryVector(vector, errors)
    else if (name === 'seed-protocol-handshake-v1') verifySeedProtocolHandshakeVector(vector, errors)
    else if (name === 'circuit-protocol-binary-v1') verifyCircuitProtocolBinaryVector(vector, errors)
    else errors.push('unsupported vector: ' + name)
  } catch (err) {
    errors.push('vector verification error: ' + (err && err.message ? err.message : String(err)))
  }

  return { valid: errors.length === 0, name, errors, warnings }
}

export function verifyProfileVectors (vectors) {
  const results = Array.isArray(vectors) ? vectors.map(verifyProfileVector) : []
  return {
    valid: results.length > 0 && results.every(result => result.valid),
    count: results.length,
    passed: results.filter(result => result.valid).length,
    failed: results.filter(result => !result.valid).length,
    results
  }
}

function verifyAccountingVector (vector, errors) {
  const verdict = verifyAccountingReceipt(vector.receipt)
  if (!verdict.valid) errors.push('accounting receipt failed verification: ' + verdict.reason)
  if (vector.receipt?.relayPubkey !== vector.relayPubkey) errors.push('accounting relayPubkey mismatch')
  compareHex(
    'accounting signableHex',
    b4a.toString(accountingReceiptSignable(vector.receipt), 'hex'),
    vector.signableHex,
    errors
  )
}

function verifyRetrievabilityVector (vector, errors) {
  if (vector.domain !== RETRIEVABILITY_PROOF_DOMAIN) errors.push('retrievability domain mismatch')
  if (vector.signatureProfile !== RETRIEVABILITY_PROOF_SIGNATURE_PROFILE) {
    errors.push('retrievability signatureProfile mismatch')
  }

  const keyPair = keyPairFromSeed(vector.seedHex)
  compareHex('retrievability relayPubkey', b4a.toString(keyPair.publicKey, 'hex'), vector.relayPubkey, errors)

  const coreKey = b4a.from(String(vector.coreKey || ''), 'hex')
  const nonce = b4a.from(String(vector.nonce || ''), 'hex')
  const blockValue = b4a.from(String(vector.blockValueHex || ''), 'hex')
  const { signable, blockHash } = retrievabilityProofSignable(coreKey, vector.index, nonce, blockValue)
  const legacy = storageProofSignable(coreKey, vector.index, nonce, blockValue)

  compareHex('retrievability blockHash', b4a.toString(blockHash, 'hex'), vector.blockHash, errors)
  compareHex('retrievability signableHex', b4a.toString(signable, 'hex'), vector.signableHex, errors)

  const sig = b4a.from(String(vector.signature || ''), 'hex')
  const profileOk = sig.byteLength === sodium.crypto_sign_BYTES &&
    sodium.crypto_sign_verify_detached(sig, signable, keyPair.publicKey)
  if (!profileOk) errors.push('retrievability signature failed verification')

  const legacyOk = sig.byteLength === sodium.crypto_sign_BYTES &&
    sodium.crypto_sign_verify_detached(sig, legacy.signable, keyPair.publicKey)
  if (legacyOk) errors.push('retrievability signature replays as legacy proof bytes')
}

function verifyRelayKernelVector (vector, errors) {
  const profile = buildRelayKernelProfile(vector.input)
  const verdict = validateRelayKernelProfile(profile)
  compareJson('relaykernel profile', profile, vector.profile, errors)
  compareJson('relaykernel verdict', verdict, vector.verdict, errors)
}

function verifyHiveMeshVector (vector, errors) {
  const profile = buildHiveMeshTierProfile(vector.input)
  const verdict = validateHiveMeshTierProfile(profile)
  compareJson('hivemesh profile', profile, vector.profile, errors)
  compareJson('hivemesh verdict', verdict, vector.verdict, errors)
}

function verifyWitnessQuorumVector (vector, errors) {
  const policy = buildWitnessQuorumPolicy(vector.input)
  const verdict = validateWitnessQuorumPolicy(policy)
  const entries = policy.witnesses.slice(0, vector.quorum?.required || 0).map(witness => ({
    intentId: policy.intentId,
    relayPubkey: policy.subjectRelayPubkey,
    witnessPubkey: witness.witnessPubkey,
    catalogPresent: false,
    gatewayServing: false,
    activeSwarmObserved: false
  }))
  const quorum = evaluateWitnessQuorum(policy, entries)
  compareJson('witness verdict', verdict, vector.verdict, errors)
  compareJson('witness quorum', quorum, vector.quorum, errors)
}

function verifyCustodyAllowlistVector (vector, errors) {
  const keyPair = keyPairFromSeed(vector.publisherSeedHex)
  compareHex('custody publisherPubkey', b4a.toString(keyPair.publicKey, 'hex'), vector.publisherPubkey, errors)

  const intent = createCustodyIntent(vector.input, keyPair, {
    timestamp: vector.input?.timestamp,
    now: vector.now
  })
  compareJson('custody allowlist intent', intent, vector.validIntent, errors)
  compareJson(
    'custody allowlist valid verdict',
    verifyCustodyEntry(vector.validIntent, { now: vector.now }),
    vector.validVerdict,
    errors
  )

  const topLevel = {
    ...vector.validIntent,
    caption: 'plaintext should not ride along'
  }
  compareJson(
    'custody allowlist top-level rejection',
    verifyCustodyEntry(topLevel, { now: vector.now }),
    vector.rejections.topLevelCaption,
    errors
  )

  const topLevelSecret = {
    ...vector.validIntent,
    dataKey: 'plaintext should not ride along'
  }
  compareJson(
    'custody allowlist secret-field rejection',
    verifyCustodyEntry(topLevelSecret, { now: vector.now }),
    vector.rejections.topLevelDataKey,
    errors
  )

  const nested = {
    ...vector.validIntent,
    shareAssignments: vector.validIntent.shareAssignments.map((assignment, index) => index === 0
      ? { ...assignment, caption: 'plaintext should not ride along' }
      : assignment)
  }
  compareJson(
    'custody allowlist nested rejection',
    verifyCustodyEntry(nested, { now: vector.now }),
    vector.rejections.nestedAssignmentCaption,
    errors
  )
}

function verifyReputationVector (vector, errors) {
  const profile = scoreRelayKernelReputation(vector.input)
  compareJson('relaykernel reputation profile', profile, vector.profile, errors)
}

function verifySeedLeaseVector (vector, errors) {
  const profile = evaluateRelayKernelSeedLeaseProfile(vector.input)
  compareJson('relaykernel seed lease profile', profile, vector.profile, errors)
}

function verifyRoleDomainVector (vector, errors) {
  const profile = evaluateRoleDomainSignatureProfile(vector.input)
  compareJson('role domain signature profile', profile, vector.profile, errors)
}

function verifyRelayKernelMetaVector (vector, errors) {
  const profile = buildRelayKernelMetaProfile(vector.input)
  const verdict = validateRelayKernelMetaProfile(profile)
  compareJson('relaykernel meta profile', profile, vector.profile, errors)
  compareJson('relaykernel meta verdict', verdict, vector.verdict, errors)
}

function verifyHiveMeshProveHeldVector (vector, errors) {
  const profile = evaluateHiveMeshProveHeldProfile(vector.input)
  compareJson('hivemesh proveHeld profile', profile, vector.profile, errors)
}

function verifyHiveMeshTierReputationVector (vector, errors) {
  const profile = scoreHiveMeshTierReputation(vector.input)
  compareJson('hivemesh tier reputation profile', profile, vector.profile, errors)
}

function verifyHiveMeshTombstoneAdjudicationVector (vector, errors) {
  const profile = evaluateHiveMeshTombstoneAdjudicationProfile(vector.input)
  compareJson('hivemesh tombstone adjudication profile', profile, vector.profile, errors)
}

function verifyRelayKernelCircuitLimitsVector (vector, errors) {
  const profile = evaluateRelayKernelCircuitLimitsProfile(vector.input)
  compareJson('relaykernel circuit limits profile', profile, vector.profile, errors)
}

function verifyCapabilityDocVector (vector, errors) {
  const keyPair = keyPairFromSeed(vector.seedHex)
  compareHex('capability doc pubkey', b4a.toString(keyPair.publicKey, 'hex'), vector.pubkey, errors)
  const doc = buildCapabilityDoc({
    relay: capabilityVectorRelay(vector.input, keyPair),
    runtime: vector.input?.runtime,
    version: vector.input?.version,
    software: vector.input?.software,
    name: vector.input?.name,
    description: vector.input?.description,
    gatewayUrl: vector.input?.gatewayUrl,
    indexRoom: vector.input?.indexRoom,
    attestedAt: vector.input?.attestedAt
  })
  compareJson('capability doc', doc, vector.doc, errors)
  const signable = capabilityDocSignablePayload(doc)
  if (vector.signableHex) {
    compareHex(
      'capability doc signableHex',
      b4a.toString(signable, 'hex'),
      vector.signableHex,
      errors
    )
  }
  if (vector.signableHash) {
    const digest = b4a.alloc(32)
    sodium.crypto_generichash(digest, signable)
    compareHex(
      'capability doc signableHash',
      b4a.toString(digest, 'hex'),
      vector.signableHash,
      errors
    )
  }
  compareJson('capability doc verdict', verifyCapabilityDoc(doc), vector.verdict, errors)
  for (const check of Array.isArray(vector.freshness) ? vector.freshness : []) {
    compareJson(
      'capability doc freshness ' + (check.id || '(unnamed)'),
      verifyCapabilityDoc(doc, check.opts || {}),
      check.verdict,
      errors
    )
  }

  const tampered = JSON.parse(JSON.stringify(doc))
  tampered.protocol_profile.signature_domains.seed_request.preferred = 'legacy-v2'
  const tamperedVerdict = verifyCapabilityDoc(tampered)
  if (tamperedVerdict.valid || tamperedVerdict.reason !== vector.tamper?.expectedReason) {
    errors.push('capability doc tamper verdict mismatch')
  }
}

function verifySeedProtocolBinaryVector (vector, errors) {
  if (vector.kind !== 'protocol-binary-conformance') errors.push('seed protocol kind mismatch')
  if (vector.protocol !== 'hiverelay-seed') errors.push('seed protocol name mismatch')
  if (vector.version !== 1) errors.push('seed protocol version mismatch')

  for (const item of Array.isArray(vector.messages) ? vector.messages : []) {
    const encoding = seedProtocolEncoding(item.type)
    if (!encoding) {
      errors.push('unsupported seed protocol message type: ' + item.type)
      continue
    }
    const value = seedProtocolValueFromJson(item.type, item.value)
    compareHex(
      seedProtocolLabel(item, 'frameHex'),
      encodeProtocolFrameHex(encoding, value),
      item.frameHex,
      errors
    )
    compareJson(
      seedProtocolLabel(item, 'decoded'),
      wireJsonFromValue(decodeProtocolFrame(encoding, item.frameHex)),
      item.value,
      errors
    )
  }

  for (const item of Array.isArray(vector.malformed) ? vector.malformed : []) {
    const encoding = seedProtocolEncoding(item.type)
    if (!encoding) {
      errors.push('unsupported malformed seed protocol message type: ' + item.type)
      continue
    }
    const decoded = decodeProtocolFrame(encoding, item.frameHex)
    if (!decoded || decoded.error !== item.expectedError) {
      errors.push(seedProtocolLabel(item, 'error') + ' mismatch')
    }
  }

  for (const item of Array.isArray(vector.encodeFailures) ? vector.encodeFailures : []) {
    const encoding = seedProtocolEncoding(item.type)
    if (!encoding) {
      errors.push('unsupported encode-failure seed protocol message type: ' + item.type)
      continue
    }
    const state = { start: 0, end: 0, buffer: null }
    let thrown = null
    try {
      encoding.preencode(state, seedProtocolValueFromJson(item.type, item.value))
    } catch (err) {
      thrown = err
    }
    const message = thrown && thrown.message ? thrown.message : ''
    if (!message.includes(item.expectedError)) {
      errors.push(seedProtocolLabel(item, 'encode failure') + ' mismatch')
    }
    if (state.end !== 0) {
      errors.push(seedProtocolLabel(item, 'encode failure state') + ' grew state.end')
    }
  }
}

function verifySeedProtocolHandshakeVector (vector, errors) {
  if (vector.kind !== 'protocol-version-negotiation') errors.push('seed handshake kind mismatch')
  if (vector.protocol !== 'hiverelay-seed') errors.push('seed handshake protocol mismatch')
  compareJson('seed handshake local version', SEED_PROTOCOL_VERSION, vector.localVersion, errors)
  if (vector.maxHandshakeBytes !== SEED_PROTOCOL_HANDSHAKE_MAX_BYTES) {
    errors.push('seed handshake max bytes mismatch')
  }

  for (const item of Array.isArray(vector.cases) ? vector.cases : []) {
    const handshake = seedProtocolHandshakeFromVector(item)
    const verdict = evaluateSeedProtocolHandshake(handshake, {
      localVersion: vector.localVersion
    })
    compareJson(seedProtocolHandshakeLabel(item), verdict, item.verdict, errors)
  }
}

function verifyCircuitProtocolBinaryVector (vector, errors) {
  if (vector.kind !== 'protocol-binary-conformance') errors.push('circuit protocol kind mismatch')
  if (vector.protocol !== 'hiverelay-circuit') errors.push('circuit protocol name mismatch')
  if (vector.version !== 1) errors.push('circuit protocol version mismatch')

  for (const item of Array.isArray(vector.messages) ? vector.messages : []) {
    const encoding = circuitProtocolEncoding(item.type)
    if (!encoding) {
      errors.push('unsupported circuit protocol message type: ' + item.type)
      continue
    }
    const value = circuitProtocolValueFromJson(item.type, item.value)
    compareHex(
      circuitProtocolLabel(item, 'frameHex'),
      encodeProtocolFrameHex(encoding, value),
      item.frameHex,
      errors
    )
    compareJson(
      circuitProtocolLabel(item, 'decoded'),
      wireJsonFromValue(decodeProtocolFrameSafe(encoding, item.frameHex)),
      item.value,
      errors
    )
  }

  for (const item of Array.isArray(vector.malformed) ? vector.malformed : []) {
    const encoding = circuitProtocolEncoding(item.type)
    if (!encoding) {
      errors.push('unsupported malformed circuit protocol message type: ' + item.type)
      continue
    }
    const decoded = decodeProtocolFrameSafe(encoding, item.frameHex)
    if (!decoded || decoded.error !== item.expectedError) {
      errors.push(circuitProtocolLabel(item, 'error') + ' mismatch')
    }
  }

  for (const item of Array.isArray(vector.encodeFailures) ? vector.encodeFailures : []) {
    const encoding = circuitProtocolEncoding(item.type)
    if (!encoding) {
      errors.push('unsupported encode-failure circuit protocol message type: ' + item.type)
      continue
    }
    const state = { start: 0, end: 0, buffer: null }
    let thrown = null
    try {
      encoding.preencode(state, circuitProtocolValueFromJson(item.type, item.value))
    } catch (err) {
      thrown = err
    }
    const message = thrown && thrown.message ? thrown.message : ''
    if (!message.includes(item.expectedError)) {
      errors.push(circuitProtocolLabel(item, 'encode failure') + ' mismatch')
    }
    if (state.end !== 0) {
      errors.push(circuitProtocolLabel(item, 'encode failure state') + ' grew state.end')
    }
  }
}

function keyPairFromSeed (seedHex) {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.from(String(seedHex || ''), 'hex'))
  return { publicKey, secretKey }
}

function capabilityVectorRelay (input = {}, keyPair) {
  const relay = {
    mode: input.mode || null,
    config: input.config || {},
    swarm: { keyPair }
  }
  if (input.appRegistry) {
    const entries = Array.isArray(input.appRegistry.catalog) ? input.appRegistry.catalog : []
    relay.appRegistry = { catalog: () => entries }
  }
  if (input.federation) {
    const snapshot = input.federation.snapshot || {}
    relay.federation = { snapshot: () => snapshot }
  }
  if (input.serviceRegistry) {
    const catalog = Array.isArray(input.serviceRegistry.catalog) ? input.serviceRegistry.catalog : []
    relay.serviceRegistry = { catalog: () => catalog }
  }
  if (input.paymentManager) relay.paymentManager = { paymentProvider: {} }
  if (input.signedDirectory) relay._signedDirectory = { getStats: () => input.signedDirectory.stats || {} }
  if (input.publishProtocol) relay._publishProtocol = {}
  if (input.accountingReceipts) relay.createAccountingReceipt = () => {}
  if (input.relayCore) {
    relay.relay = {
      maxCircuitDuration: input.relayCore.maxCircuitDuration,
      maxCircuitBytes: input.relayCore.maxCircuitBytes,
      maxCircuitsPerPeer: input.relayCore.maxCircuitsPerPeer,
      maxCircuitRateBytesPerSecond: input.relayCore.maxCircuitRateBytesPerSecond
    }
    if (input.relayCore.recordCircuitBytes) relay.relay.recordCircuitBytes = () => true
  }
  if (input.circuitRelay) {
    relay._circuitRelay = {
      maxCircuitDuration: input.circuitRelay.maxCircuitDuration,
      maxCircuitBytes: input.circuitRelay.maxCircuitBytes,
      maxCircuitsPerPeer: input.circuitRelay.maxCircuitsPerPeer,
      maxCircuitRateBytesPerSecond: input.circuitRelay.maxCircuitRateBytesPerSecond,
      maxDataMsgBytes: input.circuitRelay.maxDataMsgBytes,
      _maxPendingConnects: input.circuitRelay.maxPendingConnects,
      _maxReservesPerMin: input.circuitRelay.maxReservesPerMin
    }
  }
  return relay
}

function compareHex (label, actual, expected, errors) {
  if (actual !== expected) errors.push(label + ' mismatch')
}

function compareJson (label, actual, expected, errors) {
  if (stableStringify(actual) !== stableStringify(expected)) errors.push(label + ' mismatch')
}

function stableStringify (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']'
  const keys = Object.keys(value).sort()
  return '{' + keys.map(key => JSON.stringify(key) + ':' + stableStringify(value[key])).join(',') + '}'
}

function seedProtocolEncoding (type) {
  if (type === 'seed-request') return seedRequestEncoding
  if (type === 'seed-accept') return seedAcceptEncoding
  if (type === 'seed-deny') return seedDenyEncoding
  if (type === 'unseed-request') return unseedRequestEncoding
  return null
}

function encodeProtocolFrameHex (encoding, value) {
  const state = { start: 0, end: 0, buffer: null }
  encoding.preencode(state, value)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  encoding.encode(state, value)
  return b4a.toString(state.buffer, 'hex')
}

function decodeProtocolFrame (encoding, frameHex) {
  const buffer = b4a.from(String(frameHex || ''), 'hex')
  return encoding.decode({ buffer, start: 0, end: buffer.length })
}

function decodeProtocolFrameSafe (encoding, frameHex) {
  try {
    return decodeProtocolFrame(encoding, frameHex)
  } catch (err) {
    return { error: err && err.message ? err.message : String(err) }
  }
}

function seedProtocolValueFromJson (type, value = {}) {
  const msg = { ...value, appKey: hexBuffer(value.appKey) }
  if (type === 'seed-request') {
    msg.discoveryKeys = Array.isArray(value.discoveryKeys)
      ? value.discoveryKeys.map(hexBuffer)
      : []
    msg.publisherPubkey = hexBuffer(value.publisherPubkey)
    msg.publisherSignature = hexBuffer(value.publisherSignature)
  } else if (type === 'seed-accept') {
    msg.relayPubkey = hexBuffer(value.relayPubkey)
    msg.relaySignature = hexBuffer(value.relaySignature)
  } else if (type === 'seed-deny') {
    msg.relayPubkey = hexBuffer(value.relayPubkey)
    msg.relaySignature = hexBuffer(value.relaySignature)
  } else if (type === 'unseed-request') {
    msg.publisherPubkey = hexBuffer(value.publisherPubkey)
    msg.publisherSignature = hexBuffer(value.publisherSignature)
  }
  return msg
}

function circuitProtocolEncoding (type) {
  if (type === 'reserve') return relayReserveEncoding
  if (type === 'connect') return circuitConnectEncoding
  if (type === 'status') return circuitStatusEncoding
  if (type === 'data') return circuitDataEncoding
  if (type === 'ready') return circuitReadyEncoding
  if (type === 'close') return circuitCloseEncoding
  return null
}

function circuitProtocolValueFromJson (type, value = {}) {
  const msg = { ...value }
  if (type === 'reserve') {
    msg.peerPubkey = hexBuffer(value.peerPubkey)
  } else if (type === 'connect') {
    msg.targetPubkey = hexBuffer(value.targetPubkey)
    msg.sourcePubkey = hexBuffer(value.sourcePubkey)
  } else if (type === 'data') {
    msg.circuitId = hexBuffer(value.circuitId)
    msg.data = hexBuffer(value.data)
  } else if (type === 'ready') {
    msg.circuitId = hexBuffer(value.circuitId)
    msg.remotePubkey = hexBuffer(value.remotePubkey)
  } else if (type === 'close') {
    msg.circuitId = hexBuffer(value.circuitId)
  }
  return msg
}

function hexBuffer (hex) {
  return b4a.from(String(hex || ''), 'hex')
}

function wireJsonFromValue (value) {
  if (b4a.isBuffer(value)) return b4a.toString(value, 'hex')
  if (Array.isArray(value)) return value.map(wireJsonFromValue)
  if (!value || typeof value !== 'object') return value
  const out = {}
  for (const [key, child] of Object.entries(value)) out[key] = wireJsonFromValue(child)
  return out
}

function seedProtocolHandshakeFromVector (item) {
  if (!item || item.handshake === null) return null
  if (typeof item.handshakeText === 'string') return b4a.from(item.handshakeText)
  if (typeof item.handshakeHex === 'string') return b4a.from(item.handshakeHex, 'hex')
  if (Number.isSafeInteger(item.handshakeFillBytes)) {
    const fill = Number.isSafeInteger(item.handshakeFillByte) ? item.handshakeFillByte : 0
    return b4a.alloc(item.handshakeFillBytes, fill)
  }
  if (item.handshakeJson !== undefined) return b4a.from(JSON.stringify(item.handshakeJson))
  return null
}

function seedProtocolHandshakeLabel (item) {
  return 'seed protocol handshake ' + (item.id || '(unnamed)')
}

function seedProtocolLabel (item, field) {
  return 'seed protocol ' + (item.id || item.type || '(unnamed)') + ' ' + field
}

function circuitProtocolLabel (item, field) {
  return 'circuit protocol ' + (item.id || item.type || '(unnamed)') + ' ' + field
}
