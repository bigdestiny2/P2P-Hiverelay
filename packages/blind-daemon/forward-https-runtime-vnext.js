// Direct-HTTPS one-hop FORWARD daemon runtime, reconstructed on the accepted
// storage base (12adf204) per the runtime relock activation. The module
// consumes only the accepted storage layer exports (replay journal v4,
// source/target stores v3, storage authority v3) and the frozen WIRE v3 /
// private IPC v4 contracts. The unary DESCRIBE/CELL/INBOX/CORE surface is
// composed through the accepted production assembly; this module adds the
// bounded one-hop turn relay on top. Readiness, descriptor and advertised
// operation bits stay zero: this module never publishes a descriptor bit.

import fs from 'node:fs/promises'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { socketPeerCredentials } from '@hiverelay/blind-peercred'
import {
  ERROR_CODE,
  FORWARD_HTTPS_REQUEST_KIND_V1,
  FORWARD_HTTPS_REQUEST_ROLE_V1,
  FORWARD_HTTPS_RESPONSE_KIND_V1,
  FORWARD_HTTPS_RESULT_ROLE_V1,
  FORWARD_HTTPS_V3_LIMITS,
  ForwardHttpsOriginSessionContractV1,
  ForwardHttpsTransportBudgetV1,
  assertForwardHttpsCatalogTargetV1,
  assertForwardHttpsForwardedRequestAuthorityV1,
  blindForwardHttpsOriginForwardTurnRequestV1,
  blindForwardHttpsOriginForwardTurnResultV1,
  createForwardHttpsForwardedRequestV1,
  decodeCanonical,
  encodeCanonical,
  forwardHttpsForwardedRequestCommitmentV1,
  forwardHttpsOriginRequestCommitmentV1,
  forwardHttpsParentCapabilitySignaturePayloadV1,
  forwardHttpsResultSignaturePayloadV1,
  forwardOpenRequestCommitment
} from '@hiverelay/blind-protocol'
import {
  LOCAL_FORWARD_HTTPS_DIRECTION_V4,
  PRIVATE_IPC_V4_LIMITS,
  LocalForwardHttpsTargetClaimModelV4,
  LocalForwardHttpsTranscriptAccumulatorV4,
  decodeLocalForwardHttpsSourceOriginTranscriptV4,
  decodeLocalForwardHttpsTargetIngressTranscriptV4,
  encodeLocalForwardHttpsTurnV4
} from '@hiverelay/blind-ipc'
import {
  FORWARD_HTTPS_REPLAY_ROLE_V4,
  consumeForwardHttpsReplayV4,
  reserveForwardHttpsReplayV4
} from './forward-https-replay-journal-v4.js'
import {
  consumeForwardHttpsStorageReplayV3,
  sourceForwardHttpsStorageAuthorityV3,
  targetForwardHttpsStorageAuthorityV3
} from './forward-https-storage-authority-v3.js'
import {
  FORWARD_HTTPS_SOURCE_WAL_TYPE,
  forwardHttpsSourceTurnStateV3,
  persistForwardHttpsSourceResultV3,
  prepareForwardHttpsSourceTurnV3
} from './forward-https-source-store-v3.js'
import {
  FORWARD_HTTPS_TARGET_WAL_TYPE,
  acceptForwardedHttpsTargetTurnV3,
  forwardHttpsTargetTurnStateV3,
  runNextForwardHttpsTargetProcessorWorkV3
} from './forward-https-target-store-v3.js'

const REQUEST_BYTES = FORWARD_HTTPS_V3_LIMITS.EXACT_REQUEST_BYTES
const RESULT_BYTES = FORWARD_HTTPS_V3_LIMITS.EXACT_RESULT_BYTES
const ORIGIN_AUTHORITY_BYTES = PRIVATE_IPC_V4_LIMITS.ORIGIN_AUTHORITY_BYTES
const SOURCE_ORIGIN_TRANSCRIPT_BYTES = PRIVATE_IPC_V4_LIMITS.SOURCE_ORIGIN_TRANSCRIPT_BYTES
const TARGET_INGRESS_TRANSCRIPT_BYTES = PRIVATE_IPC_V4_LIMITS.TARGET_INGRESS_TRANSCRIPT_BYTES
const RESULT_TRANSCRIPT_BYTES = PRIVATE_IPC_V4_LIMITS.RESULT_TRANSCRIPT_BYTES
const MAX_DEADLINE_MILLIS = PRIVATE_IPC_V4_LIMITS.MAX_DEADLINE_MILLIS

export const FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE = Object.freeze({
  INVALID: 'BLIND_FORWARD_RUNTIME_VNEXT_INVALID',
  AUTHORITY_MISMATCH: 'BLIND_FORWARD_RUNTIME_VNEXT_AUTHORITY_MISMATCH',
  DESCRIPTOR_MISMATCH: 'BLIND_FORWARD_RUNTIME_VNEXT_DESCRIPTOR_MISMATCH',
  CATALOGUE_MISMATCH: 'BLIND_FORWARD_RUNTIME_VNEXT_CATALOGUE_MISMATCH',
  CAPABILITY_WINDOW: 'BLIND_FORWARD_RUNTIME_VNEXT_CAPABILITY_WINDOW',
  REPLAY_TERMINAL: 'BLIND_FORWARD_RUNTIME_VNEXT_REPLAY_TERMINAL',
  TARGET_UNAVAILABLE: 'BLIND_FORWARD_RUNTIME_VNEXT_TARGET_UNAVAILABLE',
  RESULT_INVALID: 'BLIND_FORWARD_RUNTIME_VNEXT_RESULT_INVALID',
  STORAGE: 'BLIND_FORWARD_RUNTIME_VNEXT_STORAGE',
  PEERCRED: 'BLIND_FORWARD_RUNTIME_VNEXT_PEERCRED',
  DIAL_FIELD: 'BLIND_FORWARD_RUNTIME_VNEXT_DIAL_FIELD'
})

export class ForwardHttpsRuntimeVnextError extends Error {
  constructor (message, code = FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.INVALID) {
    super(message)
    this.name = 'ForwardHttpsRuntimeVnextError'
    this.code = code
  }
}

function fail (message, code = FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.INVALID) {
  throw new ForwardHttpsRuntimeVnextError(message, code)
}

function exactBytes (value, length, field, nonzero = false) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  value = b4a.from(value)
  if (value.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  if (nonzero) {
    let found = false
    for (const byte of value) if (byte !== 0) { found = true; break }
    if (!found) fail(`${field} must be nonzero`)
  }
  return value
}

function same (left, right) {
  return left.byteLength === right.byteLength && b4a.equals(left, right)
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} is outside u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n) fail(`${field} is outside u64`)
  return value
}

const FORBIDDEN_DIAL_FIELDS = Object.freeze([
  'url', 'host', 'hostname', 'ip', 'ipAddress', 'address', 'dialAddress',
  'credentials', 'authorization', 'username', 'password'
])

function assertNoDialFields (value, field) {
  if (!value || typeof value !== 'object') fail(`${field} must be an object`)
  for (const forbidden of FORBIDDEN_DIAL_FIELDS) {
    if (forbidden in value) {
      fail(`${field}.${forbidden} is forbidden`, FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.DIAL_FIELD)
    }
  }
  return value
}

function defaultMonotonicMillis () {
  return Number(process.hrtime.bigint() / 1_000_000n)
}

function defaultEpochSeconds () {
  return Math.floor(Date.now() / 1000)
}

function signDetached (secretKey, payload) {
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, payload, secretKey)
  return signature
}

// The error taxonomy mirrored onto signed source results: terminal classes
// (replay/session terminal, binding, descriptor, catalogue, dial-field and
// budget violations) are signed RETRY_TERMINAL and never advance the chain;
// every other pre-forward failure is a retryable INTERNAL.
const TERMINAL_ERROR_CODES = new Set([
  FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.AUTHORITY_MISMATCH,
  FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.DESCRIPTOR_MISMATCH,
  FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.CATALOGUE_MISMATCH,
  FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.CAPABILITY_WINDOW,
  FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.REPLAY_TERMINAL,
  FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.DIAL_FIELD,
  'TERMINAL_FORWARD_HTTPS_SESSION',
  'FORWARD_HTTPS_BUDGET_EXHAUSTED'
])

function assertAuthorityBinding (authority, expected, endpointId, monotonicMillis) {
  if (!same(exactBytes(authority.wireV3AbiHash, 32, 'authority.wireV3AbiHash', true), expected.wireV3AbiHash) ||
      !same(exactBytes(authority.signedLaunchTopologyHash, 32, 'authority.signedLaunchTopologyHash', true), expected.signedLaunchTopologyHash)) {
    fail('local authority does not bind the frozen contract or launch topology hashes',
      FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.AUTHORITY_MISMATCH)
  }
  if (authority.endpointId !== endpointId) {
    fail('local authority endpoint is not the configured public endpoint',
      FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.AUTHORITY_MISMATCH)
  }
  const accepted = u64(authority.acceptedMonotonicMillis, 'acceptedMonotonicMillis')
  const deadline = u64(authority.absoluteDeadlineMonotonicMillis, 'absoluteDeadlineMonotonicMillis')
  const now = BigInt(monotonicMillis())
  if (deadline <= accepted || deadline - accepted > BigInt(MAX_DEADLINE_MILLIS) || now < accepted || now > deadline) {
    fail('local authority exchange is outside its bounded deadline', FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.AUTHORITY_MISMATCH)
  }
  return true
}

function assertCapabilityWindow (capability, nowEpoch) {
  if (!Number.isSafeInteger(nowEpoch) || nowEpoch < capability.issuedAtEpoch || nowEpoch >= capability.expiresAtEpoch) {
    fail('parent capability is not inside its exact epoch window', FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.CAPABILITY_WINDOW)
  }
  return true
}

function assertDescriptorBinding (capability, descriptorSnapshot, field) {
  if (field === 'source') {
    if (!same(capability.sourceRelayPublicKey, descriptorSnapshot.descriptor.relayPublicKey) ||
        u64(capability.sourceDescriptorSequence, 'sourceDescriptorSequence') !== descriptorSnapshot.descriptorSequence ||
        !same(capability.sourceDescriptorHash, descriptorSnapshot.hash)) {
      fail('capability source descriptor does not match the current signed descriptor',
        FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.DESCRIPTOR_MISMATCH)
    }
    return true
  }
  fail('descriptor binding field is unknown')
}

function assertResolvedDescriptor (resolved, relayPublicKey, sequence, hash, field) {
  assertNoDialFields(resolved, field)
  if (!same(exactBytes(resolved.relayPublicKey, 32, `${field}.relayPublicKey`, true), relayPublicKey) ||
      u64(resolved.descriptorSequence, `${field}.descriptorSequence`) !== u64(sequence, `${field}.descriptorSequence`) ||
      !same(exactBytes(resolved.descriptorHash, 32, `${field}.descriptorHash`, true), hash)) {
    fail(`${field} does not exactly match the capability`, FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.DESCRIPTOR_MISMATCH)
  }
  return true
}

function encodeResultTurn (input) {
  return encodeLocalForwardHttpsTurnV4({
    version: 4,
    direction: LOCAL_FORWARD_HTTPS_DIRECTION_V4.RESULT,
    wireRole: input.resultRole,
    flags: 0,
    wireV3AbiHash: input.wireV3AbiHash,
    localExchangeId: input.exchangeId,
    originRequestCommitment: input.originRequestCommitment,
    stableSessionId: input.stableSessionId,
    sequence: input.sequence,
    body: input.resultBytes
  })
}

// Sign one exact ID77 body: encode with a zero signature, sign the exact role
// domain payload, re-encode with the signature and prove the decode round-trip.
function signResultBody (unsignedValue, secretKey) {
  const zeroed = { ...unsignedValue, resultSignature: b4a.alloc(64) }
  const unsignedBytes = encodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, zeroed)
  const signature = signDetached(secretKey, forwardHttpsResultSignaturePayloadV1(unsignedBytes))
  const signedBytes = encodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, { ...zeroed, resultSignature: signature })
  decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, signedBytes, { copyBytes: true })
  return signedBytes
}

// ---------------------------------------------------------------------------
// Source runtime: accepts one source-origin IPC v4 transcript per exchange,
// verifies exporter/capability/descriptors/catalogue/nonce/expiry/class and
// budget before any target contact, drives the durable source store, and
// returns one signed result turn.
// ---------------------------------------------------------------------------

export class ForwardHttpsSourceRuntimeVnext {
  constructor (options = {}) {
    this.storageAuthority = options.storageAuthority || null
    this.descriptorState = options.descriptorState || null
    this.relayPublicKey = exactBytes(options.relayPublicKey, 32, 'relayPublicKey', true)
    this.secretKey = exactBytes(options.secretKey, 64, 'secretKey', true)
    this.wireV3AbiHash = exactBytes(options.wireV3AbiHash, 32, 'wireV3AbiHash', true)
    this.signedLaunchTopologyHash = exactBytes(options.signedLaunchTopologyHash, 32, 'signedLaunchTopologyHash', true)
    this.endpointId = options.endpointId
    this.resolveTargetDescriptor = options.resolveTargetDescriptor
    this.resolveCatalogEntry = options.resolveCatalogEntry
    this.dialTarget = options.dialTarget
    this.nowEpoch = options.nowEpoch || defaultEpochSeconds
    this.monotonicMillis = options.monotonicMillis || defaultMonotonicMillis
    this.budgetBytes = options.budgetBytes == null ? FORWARD_HTTPS_V3_LIMITS.TRANSPORT_BUDGET_BYTES : options.budgetBytes
    this.sessions = new Map()
    this.locks = new Map()
    this.closed = false
    if (!this.storageAuthority || !this.descriptorState) throw new TypeError('storageAuthority and descriptorState are required')
    if (!Number.isInteger(this.endpointId) || this.endpointId < 1 || this.endpointId > 255) throw new TypeError('endpointId is outside 1..255')
    for (const field of ['resolveTargetDescriptor', 'resolveCatalogEntry', 'dialTarget']) {
      if (typeof this[field] !== 'function') throw new TypeError(`${field} is required`)
    }
    if (!Number.isSafeInteger(this.budgetBytes) || this.budgetBytes < FORWARD_HTTPS_V3_LIMITS.TRANSPORT_EXCHANGE_BYTES ||
        this.budgetBytes > FORWARD_HTTPS_V3_LIMITS.TRANSPORT_BUDGET_BYTES) {
      throw new TypeError('budgetBytes is outside the exact transport budget bound')
    }
    this.sourceStore = sourceForwardHttpsStorageAuthorityV3(this.storageAuthority)
    this.replayJournal = this.sourceStore.replayJournalAuthority
  }

  close () {
    this.closed = true
    this.secretKey.fill(0)
  }

  _session (stableSessionId) {
    const key = b4a.toString(stableSessionId, 'hex')
    let entry = this.sessions.get(key)
    if (!entry) {
      entry = {
        contract: new ForwardHttpsOriginSessionContractV1(stableSessionId, {
          budget: new ForwardHttpsTransportBudgetV1(this.budgetBytes)
        })
      }
      this.sessions.set(key, entry)
    }
    return { key, entry }
  }

  async _locked (key, operation) {
    const previous = this.locks.get(key) || Promise.resolve()
    let release
    const current = new Promise(resolve => { release = resolve })
    this.locks.set(key, previous.then(() => current))
    await previous
    try {
      return await operation()
    } finally {
      release()
      if (this.locks.get(key) === current) this.locks.delete(key)
    }
  }

  // Verify every pre-contact authority the activation names: exporter binding,
  // capability window and fixed bounds, source and target descriptors, the
  // catalogue pin, nonce and class. Nothing is dialed before this returns.
  async _verifyPreContact (authority, origin, originBytes) {
    exactBytes(authority.tlsExporterBindingHash, 32, 'authority.tlsExporterBindingHash', true)
    exactBytes(authority.edgeProcessNonce, 32, 'authority.edgeProcessNonce', true)
    exactBytes(authority.localChannelNonce, 32, 'authority.localChannelNonce', true)
    const capability = origin.parentCapability
    if (!same(capability.sourceRelayPublicKey, this.relayPublicKey)) {
      fail('capability source relay is not this daemon', FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.DESCRIPTOR_MISMATCH)
    }
    assertCapabilityWindow(capability, this.nowEpoch())
    const snapshot = this.descriptorState.requireCurrent()
    assertDescriptorBinding(capability, snapshot, 'source')
    const [targetDescriptor, catalogEntry] = await Promise.all([
      this.resolveTargetDescriptor(b4a.from(capability.targetRelayPublicKey)),
      this.resolveCatalogEntry(b4a.from(capability.targetCatalogEntryId))
    ])
    assertResolvedDescriptor(targetDescriptor, capability.targetRelayPublicKey,
      capability.targetDescriptorSequence, capability.targetDescriptorHash, 'targetDescriptor')
    assertNoDialFields(catalogEntry, 'catalogEntry')
    try {
      assertForwardHttpsCatalogTargetV1(capability, catalogEntry)
    } catch {
      fail('catalogue entry does not exactly pin the capability target',
        FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.CATALOGUE_MISMATCH)
    }
    return { snapshot, targetDescriptor, catalogEntry }
  }

  _mintForwarded (origin, originBytes, tlsExporterBindingHash) {
    const template = { ...origin.parentCapability, tlsExporterBindingHash: b4a.from(tlsExporterBindingHash), signature: b4a.alloc(64) }
    const signature = signDetached(this.secretKey, forwardHttpsParentCapabilitySignaturePayloadV1(template))
    const finalized = { ...template, signature }
    const forwardedBytes = createForwardHttpsForwardedRequestV1(originBytes, finalized, tlsExporterBindingHash, this.secretKey)
    return { finalized, forwardedBytes }
  }

  _sourceResult (input) {
    const signedBytes = signResultBody({
      version: 1,
      routeKind: 7,
      releaseProfileId: 2,
      resultRole: input.resultRole,
      requestKind: input.request.requestKind,
      responseKind: input.responseKind,
      flags: 0,
      stableSessionId: input.request.stableSessionId,
      sequence: input.request.sequence,
      previousTargetResultHash: input.request.previousTargetResultHash,
      originRequestCommitment: forwardHttpsOriginRequestCommitmentV1(input.originBytes),
      forwardedRequestCommitment: forwardHttpsForwardedRequestCommitmentV1(input.forwardedBytes),
      finalizedParentCapability: input.finalized,
      turnTlsExporterBindingHash: input.finalized.tlsExporterBindingHash,
      sourceTransformSignature: input.forwarded.sourceTransformSignature,
      signerPublicKey: this.relayPublicKey,
      signerDescriptorSequence: input.snapshot.descriptorSequence,
      signerDescriptorHash: b4a.from(input.snapshot.hash),
      inner: input.inner == null ? null : input.inner
    }, this.secretKey)
    return signedBytes
  }

  _preForwardError (input, error) {
    const terminal = error && (error instanceof ForwardHttpsRuntimeVnextError
      ? TERMINAL_ERROR_CODES.has(error.code)
      : TERMINAL_ERROR_CODES.has(error && error.code))
    return this._sourceResult({
      ...input,
      resultRole: FORWARD_HTTPS_RESULT_ROLE_V1.SOURCE_PRE_FORWARD_ERROR,
      responseKind: FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR,
      inner: {
        version: 1,
        code: terminal ? ERROR_CODE.RETRY_TERMINAL : ERROR_CODE.INTERNAL,
        retryable: terminal ? 0 : 1,
        retryAfterEpoch: null
      }
    })
  }

  _ambiguous (input) {
    return this._sourceResult({
      ...input,
      resultRole: FORWARD_HTTPS_RESULT_ROLE_V1.SOURCE_POST_FORWARD_AMBIGUOUS,
      responseKind: FORWARD_HTTPS_RESPONSE_KIND_V1.AMBIGUOUS,
      inner: null
    })
  }

  async _persistPrepare (origin, originBytes) {
    const stableSessionId = origin.stableSessionId
    try {
      await prepareForwardHttpsSourceTurnV3(this.sourceStore, { stableSessionId, body: originBytes })
    } catch (error) {
      // A recovered slot (daemon restart between prepare and result) takes the
      // exact TRANSPORT_RESERVED retry frame instead of a fresh PREPARE.
      if (error && error.code === 'FORWARD_HTTPS_STORAGE_AUTHORITY_V3_SEQUENCE_INVALID' &&
          forwardHttpsSourceTurnStateV3(this.sourceStore, stableSessionId).slotState === 'ALLOCATED') {
        await persistForwardHttpsSourceResultV3(this.sourceStore, {
          walType: FORWARD_HTTPS_SOURCE_WAL_TYPE.TRANSPORT_RESERVED,
          stableSessionId,
          body: originBytes
        })
        return
      }
      throw error
    }
  }

  async handleOriginTranscript (transcriptBytes, context = {}) {
    if (this.closed) fail('source runtime is closed')
    const record = exactBytes(transcriptBytes, SOURCE_ORIGIN_TRANSCRIPT_BYTES, 'source-origin transcript')
    const { authority, turn } = decodeLocalForwardHttpsSourceOriginTranscriptV4(record, { eof: true })
    assertAuthorityBinding(authority, this, this.endpointId, this.monotonicMillis)
    const replayRecord = b4a.from(record.subarray(0, ORIGIN_AUTHORITY_BYTES))
    // Durable replay burn: reserve the exact authority tuple before any store
    // mutation; the consumed capability is verified exactly once after the
    // definitive store effect lands.
    const reservation = await reserveForwardHttpsReplayV4(this.replayJournal, { record: replayRecord })
    const origin = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, turn.body, { copyBytes: true })
    if (origin.requestRole !== FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE) {
      fail('source runtime accepts ORIGIN_TEMPLATE requests only', FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.AUTHORITY_MISMATCH)
    }
    const { key, entry } = this._session(origin.stableSessionId)
    return this._locked(key, async () => {
      let preContact
      try {
        preContact = await this._verifyPreContact(authority, origin, turn.body)
      } catch (error) {
        // Verification failures before any session admission still answer with
        // a signed non-definitive result bound to a freshly minted transform,
        // so the caller learns the exact terminal/retryable class.
        const { finalized, forwardedBytes } = this._mintForwarded(origin, turn.body, authority.tlsExporterBindingHash)
        const forwarded = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, forwardedBytes, { copyBytes: true })
        const resultBytes = this._preForwardError({
          request: origin,
          originBytes: turn.body,
          forwardedBytes,
          forwarded,
          finalized,
          snapshot: this.descriptorState.requireCurrent()
        }, error)
        await consumeForwardHttpsReplayV4(this.replayJournal, reservation, { record: replayRecord })
          .then(consumed => consumeForwardHttpsStorageReplayV3(this.storageAuthority, {
            consumed,
            role: FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN,
            record: replayRecord
          }))
        return encodeResultTurn({
          resultRole: FORWARD_HTTPS_RESULT_ROLE_V1.SOURCE_PRE_FORWARD_ERROR,
          wireV3AbiHash: this.wireV3AbiHash,
          exchangeId: authority.localExchangeId,
          originRequestCommitment: authority.originRequestCommitment,
          stableSessionId: authority.stableSessionId,
          sequence: authority.sequence,
          resultBytes
        })
      }
      const { snapshot } = preContact
      const admission = entry.contract.acceptOrigin(turn.body, { nowEpoch: this.nowEpoch() })
      if (admission.disposition === 'CACHED_TARGET_RESULT') {
        await consumeForwardHttpsReplayV4(this.replayJournal, reservation, { record: replayRecord })
          .then(consumed => consumeForwardHttpsStorageReplayV3(this.storageAuthority, {
            consumed,
            role: FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN,
            record: replayRecord
          }))
        const cached = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, admission.resultBytes, { copyBytes: true })
        return encodeResultTurn({
          resultRole: cached.resultRole,
          wireV3AbiHash: this.wireV3AbiHash,
          exchangeId: authority.localExchangeId,
          originRequestCommitment: authority.originRequestCommitment,
          stableSessionId: authority.stableSessionId,
          sequence: authority.sequence,
          resultBytes: admission.resultBytes
        })
      }
      const { finalized, forwardedBytes } = this._mintForwarded(origin, turn.body, authority.tlsExporterBindingHash)
      const forwarded = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, forwardedBytes, { copyBytes: true })
      const resultInput = { request: origin, originBytes: turn.body, forwardedBytes, forwarded, finalized, snapshot }
      try {
        if (admission.disposition === 'ACCEPTED') {
          await this._persistPrepare(origin, turn.body)
        }
        entry.contract.recordForwarded(forwardedBytes)
      } catch (error) {
        const resultBytes = this._preForwardError(resultInput, error)
        await consumeForwardHttpsReplayV4(this.replayJournal, reservation, { record: replayRecord })
          .then(consumed => consumeForwardHttpsStorageReplayV3(this.storageAuthority, {
            consumed,
            role: FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN,
            record: replayRecord
          }))
        return encodeResultTurn({
          resultRole: FORWARD_HTTPS_RESULT_ROLE_V1.SOURCE_PRE_FORWARD_ERROR,
          wireV3AbiHash: this.wireV3AbiHash,
          exchangeId: authority.localExchangeId,
          originRequestCommitment: authority.originRequestCommitment,
          stableSessionId: authority.stableSessionId,
          sequence: authority.sequence,
          resultBytes
        })
      }
      let resultBytes
      try {
        resultBytes = exactBytes(await this.dialTarget(Object.freeze({
          forwardedBytes: b4a.from(forwardedBytes),
          catalogEntry: preContact.catalogEntry,
          targetDescriptor: preContact.targetDescriptor,
          signal: context.signal
        })), RESULT_BYTES, 'target result')
        const completion = entry.contract.complete(resultBytes)
        if (completion.disposition !== 'DEFINITIVE_TARGET_RESULT') resultBytes = null
      } catch {
        resultBytes = null
      }
      if (resultBytes == null) {
        // The target was contacted (or its answer failed provenance): the turn
        // outcome is unknown, so the source signs a post-forward AMBIGUOUS.
        resultBytes = this._ambiguous(resultInput)
        const resultRole = FORWARD_HTTPS_RESULT_ROLE_V1.SOURCE_POST_FORWARD_AMBIGUOUS
        await consumeForwardHttpsReplayV4(this.replayJournal, reservation, { record: replayRecord })
          .then(consumed => consumeForwardHttpsStorageReplayV3(this.storageAuthority, {
            consumed,
            role: FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN,
            record: replayRecord
          }))
        return encodeResultTurn({
          resultRole,
          wireV3AbiHash: this.wireV3AbiHash,
          exchangeId: authority.localExchangeId,
          originRequestCommitment: authority.originRequestCommitment,
          stableSessionId: authority.stableSessionId,
          sequence: authority.sequence,
          resultBytes
        })
      }
      await persistForwardHttpsSourceResultV3(this.sourceStore, {
        walType: FORWARD_HTTPS_SOURCE_WAL_TYPE.RESULT_PERSISTED,
        stableSessionId: origin.stableSessionId,
        body: resultBytes
      })
      await consumeForwardHttpsReplayV4(this.replayJournal, reservation, { record: replayRecord })
        .then(consumed => consumeForwardHttpsStorageReplayV3(this.storageAuthority, {
          consumed,
          role: FORWARD_HTTPS_REPLAY_ROLE_V4.SOURCE_ORIGIN,
          record: replayRecord
        }))
      const definitive = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, resultBytes, { copyBytes: true })
      return encodeResultTurn({
        resultRole: definitive.resultRole,
        wireV3AbiHash: this.wireV3AbiHash,
        exchangeId: authority.localExchangeId,
        originRequestCommitment: authority.originRequestCommitment,
        stableSessionId: authority.stableSessionId,
        sequence: authority.sequence,
        resultBytes
      })
    })
  }
}

// ---------------------------------------------------------------------------
// Target runtime: accepts one target-ingress IPC v4 transcript per exchange
// from its own peercred-authenticated edge. The target edge is a bounded byte
// relay; this runtime verifies the forwarded request authority, capability,
// catalogue, expiry and budget before any responder work, drives the durable
// target store, signs the exact ID77 result and returns one result turn.
// ---------------------------------------------------------------------------

export class ForwardHttpsTargetRuntimeVnext {
  constructor (options = {}) {
    this.storageAuthority = options.storageAuthority || null
    this.descriptorState = options.descriptorState || null
    this.relayPublicKey = exactBytes(options.relayPublicKey, 32, 'relayPublicKey', true)
    this.secretKey = exactBytes(options.secretKey, 64, 'secretKey', true)
    this.wireV3AbiHash = exactBytes(options.wireV3AbiHash, 32, 'wireV3AbiHash', true)
    this.signedLaunchTopologyHash = exactBytes(options.signedLaunchTopologyHash, 32, 'signedLaunchTopologyHash', true)
    this.endpointId = options.endpointId
    this.resolveCatalogEntry = options.resolveCatalogEntry
    this.responder = options.responder
    this.nowEpoch = options.nowEpoch || defaultEpochSeconds
    this.monotonicMillis = options.monotonicMillis || defaultMonotonicMillis
    this.claims = new Map()
    this.locks = new Map()
    this.closed = false
    if (!this.storageAuthority || !this.descriptorState) throw new TypeError('storageAuthority and descriptorState are required')
    if (!Number.isInteger(this.endpointId) || this.endpointId < 1 || this.endpointId > 255) throw new TypeError('endpointId is outside 1..255')
    if (typeof this.resolveCatalogEntry !== 'function') throw new TypeError('resolveCatalogEntry is required')
    if (!this.responder || typeof this.responder.respond !== 'function') throw new TypeError('responder.respond is required')
    this.targetStore = targetForwardHttpsStorageAuthorityV3(this.storageAuthority)
    this.replayJournal = this.targetStore.replayJournalAuthority
  }

  close () {
    this.closed = true
    this.secretKey.fill(0)
  }

  _claim (stableSessionId) {
    const key = b4a.toString(stableSessionId, 'hex')
    let entry = this.claims.get(key)
    if (!entry) {
      entry = { model: new LocalForwardHttpsTargetClaimModelV4() }
      this.claims.set(key, entry)
    }
    return { key, entry }
  }

  async _locked (key, operation) {
    const previous = this.locks.get(key) || Promise.resolve()
    let release
    const current = new Promise(resolve => { release = resolve })
    this.locks.set(key, previous.then(() => current))
    await previous
    try {
      return await operation()
    } finally {
      release()
      if (this.locks.get(key) === current) this.locks.delete(key)
    }
  }

  _errorResult (forwarded, ingress, code, retryable) {
    const snapshot = this.descriptorState.requireCurrent()
    return signResultBody({
      version: 1,
      routeKind: 7,
      releaseProfileId: 2,
      resultRole: FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT,
      requestKind: forwarded.request.requestKind,
      responseKind: FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR,
      flags: 0,
      stableSessionId: forwarded.request.stableSessionId,
      sequence: forwarded.request.sequence,
      previousTargetResultHash: forwarded.request.previousTargetResultHash,
      originRequestCommitment: forwarded.request.originRequestCommitment,
      forwardedRequestCommitment: forwardHttpsForwardedRequestCommitmentV1(ingress.body),
      finalizedParentCapability: forwarded.request.parentCapability,
      turnTlsExporterBindingHash: forwarded.request.turnTlsExporterBindingHash,
      sourceTransformSignature: forwarded.request.sourceTransformSignature,
      signerPublicKey: this.relayPublicKey,
      signerDescriptorSequence: snapshot.descriptorSequence,
      signerDescriptorHash: b4a.from(snapshot.hash),
      inner: { version: 1, code, retryable: retryable ? 1 : 0, retryAfterEpoch: null }
    }, this.secretKey)
  }

  _successResult (forwarded, ingress, answer) {
    const snapshot = this.descriptorState.requireCurrent()
    return signResultBody({
      version: 1,
      routeKind: 7,
      releaseProfileId: 2,
      resultRole: FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT,
      requestKind: forwarded.request.requestKind,
      responseKind: answer.responseKind,
      flags: 0,
      stableSessionId: forwarded.request.stableSessionId,
      sequence: forwarded.request.sequence,
      previousTargetResultHash: forwarded.request.previousTargetResultHash,
      originRequestCommitment: forwarded.request.originRequestCommitment,
      forwardedRequestCommitment: forwardHttpsForwardedRequestCommitmentV1(ingress.body),
      finalizedParentCapability: forwarded.request.parentCapability,
      turnTlsExporterBindingHash: forwarded.request.turnTlsExporterBindingHash,
      sourceTransformSignature: forwarded.request.sourceTransformSignature,
      signerPublicKey: this.relayPublicKey,
      signerDescriptorSequence: snapshot.descriptorSequence,
      signerDescriptorHash: b4a.from(snapshot.hash),
      inner: answer.inner == null ? null : answer.inner
    }, this.secretKey)
  }

  async _verifyIngress (ingress, forwarded) {
    exactBytes(ingress.targetTlsExporterBindingHash, 32, 'ingress.targetTlsExporterBindingHash', true)
    const capability = forwarded.request.parentCapability
    if (!same(capability.targetRelayPublicKey, this.relayPublicKey)) {
      fail('forwarded capability target relay is not this daemon', FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.DESCRIPTOR_MISMATCH)
    }
    assertCapabilityWindow(capability, this.nowEpoch())
    const snapshot = this.descriptorState.requireCurrent()
    if (u64(capability.targetDescriptorSequence, 'targetDescriptorSequence') !== snapshot.descriptorSequence ||
        !same(capability.targetDescriptorHash, snapshot.hash)) {
      fail('forwarded capability target descriptor does not match the current signed descriptor',
        FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.DESCRIPTOR_MISMATCH)
    }
    const catalogEntry = await this.resolveCatalogEntry(b4a.from(capability.targetCatalogEntryId))
    assertNoDialFields(catalogEntry, 'catalogEntry')
    try {
      assertForwardHttpsCatalogTargetV1(capability, catalogEntry)
    } catch {
      fail('catalogue entry does not exactly pin the capability target',
        FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.CATALOGUE_MISMATCH)
    }
    return { snapshot, catalogEntry }
  }

  async handleTargetIngressTranscript (transcriptBytes, context = {}) {
    if (this.closed) fail('target runtime is closed')
    const record = exactBytes(transcriptBytes, TARGET_INGRESS_TRANSCRIPT_BYTES, 'target-ingress transcript')
    const ingress = decodeLocalForwardHttpsTargetIngressTranscriptV4(record, { eof: true })
    assertAuthorityBinding(ingress, this, this.endpointId, this.monotonicMillis)
    const replayRecord = b4a.from(record)
    const reservation = await reserveForwardHttpsReplayV4(this.replayJournal, { record: replayRecord })
    const burn = async () => {
      const consumed = await consumeForwardHttpsReplayV4(this.replayJournal, reservation, { record: replayRecord })
      consumeForwardHttpsStorageReplayV3(this.storageAuthority, {
        consumed,
        role: FORWARD_HTTPS_REPLAY_ROLE_V4.TARGET_INGRESS,
        record: replayRecord
      })
    }
    let forwarded
    try {
      forwarded = assertForwardHttpsForwardedRequestAuthorityV1(ingress.body)
    } catch (error) {
      fail(`forwarded request authority is invalid: ${error.message}`, FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.AUTHORITY_MISMATCH)
    }
    const { key, entry } = this._claim(forwarded.request.stableSessionId)
    return this._locked(key, async () => {
      try {
        await this._verifyIngress(ingress, forwarded)
      } catch (error) {
        const resultBytes = this._errorResult(forwarded, ingress, ERROR_CODE.RETRY_TERMINAL, false)
        await burn()
        return encodeResultTurn({
          resultRole: FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT,
          wireV3AbiHash: this.wireV3AbiHash,
          exchangeId: ingress.targetLocalExchangeId,
          originRequestCommitment: forwarded.request.originRequestCommitment,
          stableSessionId: forwarded.request.stableSessionId,
          sequence: forwarded.request.sequence,
          resultBytes
        })
      }
      let claim
      try {
        claim = entry.model.claim(ingress.body)
      } catch (error) {
        const resultBytes = this._errorResult(forwarded, ingress, ERROR_CODE.RETRY_TERMINAL, false)
        await burn()
        return encodeResultTurn({
          resultRole: FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT,
          wireV3AbiHash: this.wireV3AbiHash,
          exchangeId: ingress.targetLocalExchangeId,
          originRequestCommitment: forwarded.request.originRequestCommitment,
          stableSessionId: forwarded.request.stableSessionId,
          sequence: forwarded.request.sequence,
          resultBytes
        })
      }
      if (claim.disposition === 'EXACT_RETRY' && claim.resultBytes) {
        await burn()
        return encodeResultTurn({
          resultRole: FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT,
          wireV3AbiHash: this.wireV3AbiHash,
          exchangeId: ingress.targetLocalExchangeId,
          originRequestCommitment: forwarded.request.originRequestCommitment,
          stableSessionId: forwarded.request.stableSessionId,
          sequence: forwarded.request.sequence,
          resultBytes: claim.resultBytes
        })
      }
      const stableSessionId = forwarded.request.stableSessionId
      const turnState = forwardHttpsTargetTurnStateV3(this.targetStore, stableSessionId)
      if (!turnState.present) {
        await acceptForwardedHttpsTargetTurnV3(this.targetStore, { stableSessionId, body: ingress.body })
      } else {
        // Exact durable retry on a recovered or live session: the two-frame
        // crypto reservation (113 prefix + 112 final) binds the same exact
        // forwarded commitment and applies exactly once.
        await acceptForwardedHttpsTargetTurnV3(this.targetStore, {
          walType: FORWARD_HTTPS_TARGET_WAL_TYPE.TRANSPORT_RESERVED,
          stableSessionId,
          body: forwardHttpsForwardedRequestCommitmentV1(ingress.body),
          finalBody: ingress.body
        })
      }
      await runNextForwardHttpsTargetProcessorWorkV3(this.targetStore, {
        walType: FORWARD_HTTPS_TARGET_WAL_TYPE.PROCESSOR_PREPARED,
        stableSessionId,
        body: forwardHttpsForwardedRequestCommitmentV1(ingress.body)
      })
      let answer
      try {
        answer = await this.responder.respond(Object.freeze({
          request: forwarded.request,
          requestBytes: b4a.from(ingress.body),
          forwardedRequestCommitment: forwardHttpsForwardedRequestCommitmentV1(ingress.body),
          signal: context.signal
        }))
      } catch {
        answer = null
      }
      if (!answer || !Object.values(FORWARD_HTTPS_RESPONSE_KIND_V1).includes(answer.responseKind) ||
          !(FORWARD_HTTPS_V3_RESULT_MATRIX[forwarded.request.requestKind] || []).includes(answer.responseKind)) {
        const resultBytes = this._errorResult(forwarded, ingress, ERROR_CODE.INTERNAL, true)
        entry.model.persistResult(ingress.body, resultBytes)
        await burn()
        return encodeResultTurn({
          resultRole: FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT,
          wireV3AbiHash: this.wireV3AbiHash,
          exchangeId: ingress.targetLocalExchangeId,
          originRequestCommitment: forwarded.request.originRequestCommitment,
          stableSessionId: forwarded.request.stableSessionId,
          sequence: forwarded.request.sequence,
          resultBytes
        })
      }
      const resultBytes = this._successResult(forwarded, ingress, answer)
      entry.model.persistResult(ingress.body, resultBytes)
      await runNextForwardHttpsTargetProcessorWorkV3(this.targetStore, {
        walType: FORWARD_HTTPS_TARGET_WAL_TYPE.PROCESSOR_COMPLETED,
        stableSessionId,
        body: resultBytes
      })
      await burn()
      return encodeResultTurn({
        resultRole: FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT,
        wireV3AbiHash: this.wireV3AbiHash,
        exchangeId: ingress.targetLocalExchangeId,
        originRequestCommitment: forwarded.request.originRequestCommitment,
        stableSessionId: forwarded.request.stableSessionId,
        sequence: forwarded.request.sequence,
        resultBytes
      })
    })
  }
}

const FORWARD_HTTPS_V3_RESULT_MATRIX = Object.freeze({
  [FORWARD_HTTPS_REQUEST_KIND_V1.OPEN]: Object.freeze([
    FORWARD_HTTPS_RESPONSE_KIND_V1.OPEN_ACCEPT,
    FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR
  ]),
  [FORWARD_HTTPS_REQUEST_KIND_V1.DATA]: Object.freeze([
    FORWARD_HTTPS_RESPONSE_KIND_V1.ACK,
    FORWARD_HTTPS_RESPONSE_KIND_V1.DATA,
    FORWARD_HTTPS_RESPONSE_KIND_V1.WINDOW,
    FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE,
    FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR
  ]),
  [FORWARD_HTTPS_REQUEST_KIND_V1.WINDOW]: Object.freeze([
    FORWARD_HTTPS_RESPONSE_KIND_V1.ACK,
    FORWARD_HTTPS_RESPONSE_KIND_V1.DATA,
    FORWARD_HTTPS_RESPONSE_KIND_V1.WINDOW,
    FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE,
    FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR
  ]),
  [FORWARD_HTTPS_REQUEST_KIND_V1.CLOSE]: Object.freeze([
    FORWARD_HTTPS_RESPONSE_KIND_V1.ACK,
    FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE,
    FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR
  ]),
  [FORWARD_HTTPS_REQUEST_KIND_V1.POLL]: Object.freeze([
    FORWARD_HTTPS_RESPONSE_KIND_V1.NOOP,
    FORWARD_HTTPS_RESPONSE_KIND_V1.DATA,
    FORWARD_HTTPS_RESPONSE_KIND_V1.WINDOW,
    FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE,
    FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR
  ])
})

// ---------------------------------------------------------------------------
// Bounded deterministic one-hop responder. OPEN negotiates the exact class-1
// circuit and answers OPEN_ACCEPT; DATA and WINDOW answer ACK; CLOSE answers
// ACK and finishes the session. The responder is the only application
// authority behind the target store and never sees caller metadata.
// ---------------------------------------------------------------------------

export function createForwardHttpsEchoResponderVnext (options = {}) {
  const relayBinding = options.relayBinding
  if (!relayBinding || typeof relayBinding !== 'object') throw new TypeError('relayBinding is required')
  const grantedWireClass = options.grantedWireClass == null ? 3 : options.grantedWireClass
  if (!Number.isInteger(grantedWireClass) || grantedWireClass < 1 || grantedWireClass > 3) {
    throw new TypeError('grantedWireClass is outside 1..3')
  }
  const maxDataBytes = Object.freeze({ 1: 4096, 2: 16384, 3: 65535 })[grantedWireClass]
  return Object.freeze({
    async respond (input) {
      const request = input.request
      if (request.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.OPEN) {
        const inner = request.inner
        const hopTuple = Object.freeze({
          grantedWireClass,
          circuitClass: 1,
          grantedInitialWindow: 65_536,
          maxDataBytes,
          maxCircuitBytes: 16n * 1024n * 1024n,
          idleMillis: 30_000,
          lifetimeMillis: 600_000
        })
        const nextHopAccept = {
          version: 1,
          previousRelayKey: b4a.from(relayBinding.relayPublicKey),
          previousDescriptorSequence: relayBinding.descriptorSequence,
          previousDescriptorHash: b4a.from(relayBinding.descriptorHash),
          nextRelayKey: b4a.from(relayBinding.relayPublicKey),
          nextDescriptorSequence: relayBinding.descriptorSequence,
          nextDescriptorHash: b4a.from(relayBinding.descriptorHash),
          nextRelayBinding: relayBinding,
          routeId: b4a.from(inner.routeId),
          circuitNonce: b4a.from(inner.circuitNonce),
          nextStreamId: 1n,
          grantedWireClass: hopTuple.grantedWireClass,
          circuitClass: hopTuple.circuitClass,
          grantedInitialWindow: hopTuple.grantedInitialWindow,
          maxDataBytes: hopTuple.maxDataBytes,
          maxCircuitBytes: hopTuple.maxCircuitBytes,
          idleMillis: hopTuple.idleMillis,
          lifetimeMillis: hopTuple.lifetimeMillis,
          openedAtEpoch: Math.floor(Date.now() / 1000),
          hopOpenCommitment: forwardOpenRequestCommitment(inner),
          acceptedRouteScopeHash: b4a.alloc(32),
          acceptedRelayCount: 2,
          handshakeFlight2: b4a.alloc(96),
          nextSignature: b4a.alloc(64)
        }
        return Object.freeze({
          responseKind: FORWARD_HTTPS_RESPONSE_KIND_V1.OPEN_ACCEPT,
          inner: {
            version: 1,
            relayBinding,
            routeId: b4a.from(inner.routeId),
            nextDescriptorSequence: relayBinding.descriptorSequence,
            nextDescriptorHash: b4a.from(relayBinding.descriptorHash),
            circuitNonce: b4a.from(inner.circuitNonce),
            grantedWireClass: hopTuple.grantedWireClass,
            circuitClass: hopTuple.circuitClass,
            streamId: 1n,
            grantedInitialWindow: hopTuple.grantedInitialWindow,
            maxDataBytes: hopTuple.maxDataBytes,
            maxCircuitBytes: hopTuple.maxCircuitBytes,
            idleMillis: hopTuple.idleMillis,
            lifetimeMillis: hopTuple.lifetimeMillis,
            openedAtEpoch: nextHopAccept.openedAtEpoch,
            requestCommitment: forwardOpenRequestCommitment(inner),
            acceptedRouteScopeHash: b4a.alloc(32),
            acceptedRelayCount: 2,
            nextHopAccept,
            signature: b4a.alloc(64)
          }
        })
      }
      if (request.requestKind === FORWARD_HTTPS_REQUEST_KIND_V1.CLOSE) {
        return Object.freeze({
          responseKind: FORWARD_HTTPS_RESPONSE_KIND_V1.CLOSE,
          inner: {
            version: 1,
            circuitNonce: b4a.from(request.inner.circuitNonce),
            closeKind: request.inner.closeKind,
            finalSendOffset: request.inner.finalSendOffset,
            reasonCode: request.inner.reasonCode
          }
        })
      }
      return Object.freeze({ responseKind: FORWARD_HTTPS_RESPONSE_KIND_V1.ACK, inner: null })
    }
  })
}

// Minimal v8-shaped responder callbacks handed to the accepted target store at
// composite open. The turn-level store API drives WAL rows directly and never
// invokes these; they exist so the composite's exact required callback shape
// is satisfied by real, bounded functions rather than stubs.
export function createForwardHttpsResponderCallbacksVnext () {
  return Object.freeze({
    createResponderState () {
      return Object.freeze({ ingressFrames: 0, outcomeFrames: 0, closed: false })
    },
    advanceResponderIngress (state) {
      if (state && typeof state.ingressFrames === 'number') state.ingressFrames++
    },
    advanceResponderOutcome (state) {
      if (state && typeof state.outcomeFrames === 'number') state.outcomeFrames++
    }
  })
}

// ---------------------------------------------------------------------------
// Private IPC v4 server: one role per socket, peercred-verified on accept,
// exact transcript accumulation with daemon-observed EOF before response.
// ---------------------------------------------------------------------------

function socketIdentity (stat) {
  return `${stat.dev}:${stat.ino}`
}

async function removeStaleSocket (socketPath) {
  try {
    const stat = await fs.lstat(socketPath)
    if (!stat.isSocket() || stat.isSymbolicLink()) fail('forward IPC path is not a stale Unix socket')
    await fs.unlink(socketPath)
  } catch (error) {
    if (error && error.code === 'ENOENT') return
    throw error
  }
}

export const FORWARD_HTTPS_IPC_ROLE_VNEXT = Object.freeze({
  SOURCE_ORIGIN: 'SOURCE_ORIGIN',
  TARGET_INGRESS: 'TARGET_INGRESS'
})

export class ForwardHttpsIpcServerVnext {
  constructor (options = {}) {
    if (typeof options.socketPath !== 'string' || !path.isAbsolute(options.socketPath) ||
        path.normalize(options.socketPath) !== options.socketPath || options.socketPath.includes('\0')) {
      throw new TypeError('socketPath must be canonical absolute and NUL-free')
    }
    this.role = options.role
    if (this.role !== FORWARD_HTTPS_IPC_ROLE_VNEXT.SOURCE_ORIGIN &&
        this.role !== FORWARD_HTTPS_IPC_ROLE_VNEXT.TARGET_INGRESS) {
      throw new TypeError('role must be SOURCE_ORIGIN or TARGET_INGRESS')
    }
    this.socketPath = options.socketPath
    this.socketMode = options.socketMode == null ? 0o660 : options.socketMode
    this.socketGroupGid = options.socketGroupGid
    this.expectedPeerUid = options.expectedPeerUid
    this.expectedPeerGid = options.expectedPeerGid
    this.runtime = options.runtime
    this.timeoutMs = options.timeoutMs == null ? 35_000 : options.timeoutMs
    this.onPeerCredentials = options.onPeerCredentials || (() => {})
    this.onError = options.onError || (() => {})
    if (!Number.isInteger(this.socketGroupGid) || !Number.isInteger(this.expectedPeerUid) || !Number.isInteger(this.expectedPeerGid)) {
      throw new TypeError('expected peer UID/GID and socketGroupGid are required')
    }
    if (!this.runtime) throw new TypeError('runtime is required')
    this.transcriptBytes = this.role === FORWARD_HTTPS_IPC_ROLE_VNEXT.SOURCE_ORIGIN
      ? SOURCE_ORIGIN_TRANSCRIPT_BYTES
      : TARGET_INGRESS_TRANSCRIPT_BYTES
    this.handler = this.role === FORWARD_HTTPS_IPC_ROLE_VNEXT.SOURCE_ORIGIN
      ? this.runtime.handleOriginTranscript
      : this.runtime.handleTargetIngressTranscript
    if (typeof this.handler !== 'function') throw new TypeError('runtime does not handle this transcript role')
    this.server = null
    this.identity = null
    this.sockets = new Set()
  }

  async start () {
    if (this.server) return this
    await fs.mkdir(path.dirname(this.socketPath), { recursive: true, mode: 0o750 })
    await removeStaleSocket(this.socketPath)
    const server = net.createServer({ allowHalfOpen: true }, socket => this._accept(socket))
    server.maxConnections = 1024
    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(this.socketPath, resolve)
    })
    const before = await fs.lstat(this.socketPath)
    if (!before.isSocket() || before.isSymbolicLink()) fail('bound forward IPC path is not a Unix socket')
    await fs.chown(this.socketPath, -1, this.socketGroupGid)
    await fs.chmod(this.socketPath, this.socketMode)
    const after = await fs.lstat(this.socketPath)
    if (!after.isSocket() || socketIdentity(after) !== socketIdentity(before) ||
        after.gid !== this.socketGroupGid || (after.mode & 0o777) !== this.socketMode) {
      fail('forward IPC socket identity or permissions drifted during bind')
    }
    this.identity = socketIdentity(after)
    this.server = server
    return this
  }

  _accept (socket) {
    let credentials
    try {
      credentials = socketPeerCredentials(socket)
      if (credentials.uid !== this.expectedPeerUid || credentials.gid !== this.expectedPeerGid) {
        fail('forward IPC peer credentials are unauthorized', FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.PEERCRED)
      }
      this.onPeerCredentials(credentials)
    } catch (error) {
      this.onError(error)
      socket.destroy()
      return
    }
    this.sockets.add(socket)
    socket.once('close', () => this.sockets.delete(socket))
    socket.setTimeout(this.timeoutMs, () => socket.destroy())
    const accumulator = new LocalForwardHttpsTranscriptAccumulatorV4(this.role)
    const chunks = []
    let total = 0
    socket.on('data', chunk => {
      try {
        if (total + chunk.byteLength > this.transcriptBytes) {
          fail('private IPC v4 transcript exceeded its exact bound', FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.INVALID)
        }
        accumulator.write(chunk)
        chunks.push(b4a.from(chunk))
        total += chunk.byteLength
      } catch (error) {
        this.onError(error)
        socket.destroy()
      }
    })
    socket.once('end', () => {
      const task = (async () => {
        if (total !== this.transcriptBytes) {
          fail('private IPC v4 transcript ended short of its exact bound', FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.INVALID)
        }
        accumulator.end()
        const result = exactBytes(await this.handler(
          b4a.concat(chunks, total),
          { credentials }
        ), RESULT_TRANSCRIPT_BYTES, 'private IPC v4 result turn')
        if (!socket.destroyed) socket.end(result)
      })()
      task.catch(error => {
        this.onError(error)
        socket.destroy()
      })
    })
    socket.once('error', () => {})
  }

  async close () {
    const server = this.server
    if (!server) return
    for (const socket of this.sockets) socket.destroy()
    await new Promise(resolve => server.close(resolve))
    try {
      const stat = await fs.lstat(this.socketPath)
      if (stat.isSocket() && socketIdentity(stat) === this.identity) await fs.unlink(this.socketPath)
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error
    }
    this.server = null
  }
}

// The accumulator bounds and validates the ingress bytes; the handler
// re-decodes the assembled exact transcript with daemon-observed EOF.

export const FORWARD_HTTPS_RUNTIME_VNEXT_LIMITS = Object.freeze({
  exactRequestBytes: REQUEST_BYTES,
  exactResultBytes: RESULT_BYTES,
  sourceOriginTranscriptBytes: SOURCE_ORIGIN_TRANSCRIPT_BYTES,
  targetIngressTranscriptBytes: TARGET_INGRESS_TRANSCRIPT_BYTES,
  resultTranscriptBytes: RESULT_TRANSCRIPT_BYTES,
  maxExchangeDeadlineMillis: MAX_DEADLINE_MILLIS,
  transportBudgetBytes: FORWARD_HTTPS_V3_LIMITS.TRANSPORT_BUDGET_BYTES,
  transportExchangeBytes: FORWARD_HTTPS_V3_LIMITS.TRANSPORT_EXCHANGE_BYTES,
  descriptorOperationBits: 0,
  advertisedOperationBits: 0,
  readinessOperationBits: 0,
  runtimeReady: false,
  releaseReady: false
})

// ---------------------------------------------------------------------------
// Bounded target dialer: the source daemon's exact-byte HTTPS client to the
// operator-pinned target edge. One exact 65536-byte POST, one exact
// 65536-byte result, no credentials, no redirect following, no compression
// or chunking. TLS is transport confidentiality only; target authority comes
// from the signed descriptor and catalogue pins, never from PKI.
// ---------------------------------------------------------------------------

export function createForwardHttpsTargetDialerVnext (options = {}) {
  if (typeof options.url !== 'string') throw new TypeError('operator-pinned target edge url is required')
  const base = new URL(options.url)
  if (base.protocol !== 'https:' && !(options.allowInsecureLoopback === true && base.protocol === 'http:')) {
    throw new TypeError('target edge url must be HTTPS')
  }
  if (base.username || base.password || base.search || base.hash) {
    throw new TypeError('target edge url must be a credential-free authority anchor')
  }
  const timeoutMs = options.timeoutMs == null ? 15_000 : options.timeoutMs
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 35_000) {
    throw new TypeError('target dial timeout is outside its bound')
  }
  const transport = base.protocol === 'https:' ? https : http
  const agentOptions = base.protocol === 'https:'
    ? { rejectUnauthorized: options.rejectUnauthorized !== false }
    : {}
  return async function dialTarget (input) {
    const forwardedBytes = exactBytes(input && input.forwardedBytes, REQUEST_BYTES, 'forwarded request')
    return new Promise((resolve, reject) => {
      const chunks = []
      let total = 0
      const request = transport.request({
        method: 'POST',
        hostname: base.hostname,
        port: base.port || (base.protocol === 'https:' ? 443 : 80),
        path: base.pathname,
        agent: false,
        ...agentOptions,
        headers: {
          'content-type': 'application/vnd.hiverelay.blind-v1',
          'content-length': REQUEST_BYTES
        },
        timeout: timeoutMs
      }, response => {
        if (response.statusCode !== 200) {
          request.destroy()
          reject(new ForwardHttpsRuntimeVnextError(
            `target edge returned status ${response.statusCode}`,
            FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.TARGET_UNAVAILABLE))
          return
        }
        const declared = response.headers['content-length']
        if (response.headers['content-encoding'] != null || response.headers['transfer-encoding'] != null ||
            declared == null || Number(declared) !== RESULT_BYTES) {
          request.destroy()
          reject(new ForwardHttpsRuntimeVnextError('target edge result is not one exact bounded body',
            FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.RESULT_INVALID))
          return
        }
        response.on('data', chunk => {
          total += chunk.byteLength
          if (total > RESULT_BYTES) {
            request.destroy()
            reject(new ForwardHttpsRuntimeVnextError('target edge result exceeded its exact bound',
              FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.RESULT_INVALID))
            return
          }
          chunks.push(b4a.from(chunk))
        })
        response.on('end', () => {
          if (total !== RESULT_BYTES) {
            reject(new ForwardHttpsRuntimeVnextError('target edge result ended short of its exact bound',
              FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.RESULT_INVALID))
            return
          }
          resolve(b4a.concat(chunks, total))
        })
        response.on('error', reject)
      })
      request.on('timeout', () => {
        request.destroy()
        reject(new ForwardHttpsRuntimeVnextError('target edge dial deadline elapsed',
          FORWARD_HTTPS_RUNTIME_VNEXT_ERROR_CODE.TARGET_UNAVAILABLE))
      })
      request.on('error', reject)
      if (input && input.signal) {
        if (input.signal.aborted) {
          request.destroy()
          reject(Object.assign(new Error('target dial aborted'), { code: 'ABORT_ERR' }))
          return
        }
        input.signal.addEventListener('abort', () => {
          request.destroy()
          reject(input.signal.reason || Object.assign(new Error('target dial aborted'), { code: 'ABORT_ERR' }))
        }, { once: true })
      }
      request.end(forwardedBytes)
    })
  }
}

// ---------------------------------------------------------------------------
// Relay assembly: the accepted production unary runtime (DESCRIBE/CELL/INBOX/
// CORE) plus the accepted forward storage authority and this module's forward
// runtimes behind peercred-authenticated IPC v4 sockets. Socket identities for
// source-origin, target-ingress, generic unary and native v2 stream are
// asserted distinct per the frozen private IPC v4 contract.
// ---------------------------------------------------------------------------

export async function assembleForwardHttpsRelayVnext (options = {}) {
  const {
    assembleProductionBlindDaemon
  } = await import('./production-runtime.js')
  const {
    openForwardHttpsStorageAuthorityV3,
    forwardHttpsStorageAuthorityV3Status,
    closeForwardHttpsStorageAuthorityV3
  } = await import('./forward-https-storage-authority-v3.js')
  const {
    assertLocalForwardHttpsSocketSeparationV4
  } = await import('@hiverelay/blind-ipc')

  const unary = await assembleProductionBlindDaemon({
    bootstrap: options.bootstrap,
    runtimeConfig: options.runtimeConfig,
    environment: options.environment,
    enableCellRuntime: true,
    enableInboxRuntime: true,
    enableCoreRuntime: true,
    resolveAdmissionAdapter: options.resolveAdmissionAdapter,
    releaseGate: options.releaseGate,
    testOnlyPrivateIpcReplayJournalOptions: options.testOnlyPrivateIpcReplayJournalOptions,
    onError: options.onError
  })

  const forward = options.forward || {}
  const relaySecretKey = b4a.from(exactBytes(forward.relaySecretKey, 64, 'forward.relaySecretKey', true))
  const relayPublicKey = b4a.from(exactBytes(forward.relayPublicKey, 32, 'forward.relayPublicKey', true))
  const descriptorSnapshot = unary.descriptorState.requireCurrent()
  const storage = forward.storage
  if (!storage || typeof storage !== 'object') throw new TypeError('forward.storage is required')
  const responderCallbacks = createForwardHttpsResponderCallbacksVnext()
  const signResult = async input => signDetached(relaySecretKey, exactBytes(input && input.payload, input && input.payload ? input.payload.byteLength : 0, 'signResult.payload'))
  const storageOptions = {
    root: storage.root,
    manifestKey: b4a.from(exactBytes(storage.manifestKey, 32, 'forward.storage.manifestKey', true)),
    atRestKey: b4a.from(exactBytes(storage.atRestKey, 32, 'forward.storage.atRestKey', true)),
    wireV3AbiHash: b4a.from(exactBytes(forward.wireV3AbiHash, 32, 'forward.wireV3AbiHash', true)),
    privateIpcV4Hash: b4a.from(exactBytes(forward.privateIpcV4Hash, 32, 'forward.privateIpcV4Hash', true)),
    signedLaunchTopologyHash: b4a.from(exactBytes(forward.signedLaunchTopologyHash, 32, 'forward.signedLaunchTopologyHash', true)),
    sourceStoreId: b4a.from(exactBytes(storage.sourceStoreId, 32, 'forward.storage.sourceStoreId', true)),
    targetStoreId: b4a.from(exactBytes(storage.targetStoreId, 32, 'forward.storage.targetStoreId', true)),
    mapGeneration: u64(storage.mapGeneration, 'forward.storage.mapGeneration'),
    ownerFenceTokenHash: b4a.from(exactBytes(storage.ownerFenceTokenHash, 32, 'forward.storage.ownerFenceTokenHash', true)),
    sourceDurabilityContinuityHash: b4a.from(exactBytes(storage.sourceDurabilityContinuityHash, 32, 'forward.storage.sourceDurabilityContinuityHash', true)),
    targetDurabilityContinuityHash: b4a.from(exactBytes(storage.targetDurabilityContinuityHash, 32, 'forward.storage.targetDurabilityContinuityHash', true)),
    targetSignerPublicKey: b4a.from(relayPublicKey),
    targetSignerDescriptorSequence: descriptorSnapshot.descriptorSequence,
    targetSignerDescriptorHash: b4a.from(descriptorSnapshot.hash),
    signResult,
    createResponderState: responderCallbacks.createResponderState,
    advanceResponderIngress: responderCallbacks.advanceResponderIngress,
    advanceResponderOutcome: responderCallbacks.advanceResponderOutcome,
    epochSeconds: forward.epochSeconds || defaultEpochSeconds,
    monotonicMillis: forward.monotonicMillis || defaultMonotonicMillis
  }
  if (storage.limits) storageOptions.limits = storage.limits
  if (storage.faultInjector) storageOptions.faultInjector = storage.faultInjector

  let storageAuthority = null
  let sourceRuntime = null
  let targetRuntime = null
  let sourceIpc = null
  let targetIpc = null
  const relay = {
    unary,
    storageAuthority: null,
    sourceRuntime: null,
    targetRuntime: null,
    sourceIpc: null,
    targetIpc: null,
    started: false,
    closed: false,
    async start () {
      if (relay.closed) fail('relay is closed')
      if (!relay.started) {
        await unary.start()
        if (sourceIpc) await sourceIpc.start()
        if (targetIpc) await targetIpc.start()
        relay.started = true
      }
      return relay
    },
    async close () {
      if (relay.closed) return
      relay.closed = true
      let failure = null
      if (sourceIpc) await sourceIpc.close().catch(error => { failure = failure || error })
      if (targetIpc) await targetIpc.close().catch(error => { failure = failure || error })
      if (sourceRuntime) sourceRuntime.close()
      if (targetRuntime) targetRuntime.close()
      if (storageAuthority) await closeForwardHttpsStorageAuthorityV3(storageAuthority).catch(error => { failure = failure || error })
      await unary.close().catch(error => { failure = failure || error })
      relaySecretKey.fill(0)
      if (failure) throw failure
    },
    status () {
      return Object.freeze({
        started: relay.started,
        closed: relay.closed,
        unary: unary.status(),
        forwardStorage: storageAuthority ? forwardHttpsStorageAuthorityV3Status(storageAuthority) : null,
        descriptorOperationBits: 0,
        advertisedOperationBits: 0,
        readinessOperationBits: 0,
        runtimeReady: false,
        releaseReady: false
      })
    }
  }
  try {
    storageAuthority = await openForwardHttpsStorageAuthorityV3(storageOptions)
    relay.storageAuthority = storageAuthority
    const peer = {
      expectedPeerUid: forward.expectedPeerUid,
      expectedPeerGid: forward.expectedPeerGid,
      socketGroupGid: forward.socketGroupGid
    }
    if (forward.source) {
      sourceRuntime = new ForwardHttpsSourceRuntimeVnext({
        storageAuthority,
        descriptorState: unary.descriptorState,
        relayPublicKey,
        secretKey: relaySecretKey,
        wireV3AbiHash: storageOptions.wireV3AbiHash,
        signedLaunchTopologyHash: storageOptions.signedLaunchTopologyHash,
        endpointId: forward.endpointId,
        resolveTargetDescriptor: forward.source.resolveTargetDescriptor,
        resolveCatalogEntry: forward.source.resolveCatalogEntry,
        dialTarget: forward.source.dialTarget,
        nowEpoch: forward.nowEpoch,
        monotonicMillis: forward.monotonicMillis,
        budgetBytes: forward.source.budgetBytes
      })
      sourceIpc = new ForwardHttpsIpcServerVnext({
        role: FORWARD_HTTPS_IPC_ROLE_VNEXT.SOURCE_ORIGIN,
        socketPath: forward.source.socketPath,
        ...peer,
        runtime: sourceRuntime,
        onPeerCredentials: forward.onPeerCredentials,
        onError: options.onError
      })
      relay.sourceRuntime = sourceRuntime
      relay.sourceIpc = sourceIpc
    }
    if (forward.target) {
      const relayBinding = unary.descriptorState.resultBinding(descriptorSnapshot)
      targetRuntime = new ForwardHttpsTargetRuntimeVnext({
        storageAuthority,
        descriptorState: unary.descriptorState,
        relayPublicKey,
        secretKey: relaySecretKey,
        wireV3AbiHash: storageOptions.wireV3AbiHash,
        signedLaunchTopologyHash: storageOptions.signedLaunchTopologyHash,
        endpointId: forward.endpointId,
        resolveCatalogEntry: forward.target.resolveCatalogEntry,
        responder: forward.target.responder || createForwardHttpsEchoResponderVnext({ relayBinding }),
        nowEpoch: forward.nowEpoch,
        monotonicMillis: forward.monotonicMillis
      })
      targetIpc = new ForwardHttpsIpcServerVnext({
        role: FORWARD_HTTPS_IPC_ROLE_VNEXT.TARGET_INGRESS,
        socketPath: forward.target.socketPath,
        ...peer,
        runtime: targetRuntime,
        onPeerCredentials: forward.onPeerCredentials,
        onError: options.onError
      })
      relay.targetRuntime = targetRuntime
      relay.targetIpc = targetIpc
    }
    assertLocalForwardHttpsSocketSeparationV4({
      sourceOrigin: forward.source ? forward.source.socketPath : 'unused:source-origin',
      targetIngress: forward.target ? forward.target.socketPath : 'unused:target-ingress',
      genericUnary: options.bootstrap.unarySocketPath,
      nativeV2Stream: options.bootstrap.streamSocketPath
    })
    return relay
  } catch (error) {
    if (sourceRuntime) sourceRuntime.close()
    if (targetRuntime) targetRuntime.close()
    if (storageAuthority) await closeForwardHttpsStorageAuthorityV3(storageAuthority).catch(() => {})
    await unary.close().catch(() => {})
    relaySecretKey.fill(0)
    throw error
  }
}
