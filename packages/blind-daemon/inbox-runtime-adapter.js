import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  FAMILY,
  INBOX_APPEND_RESULT,
  INBOX_FRAME_CLASS,
  INBOX_RECEIPT_RESULT,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  blake2b256,
  decodeCanonical,
  encodeCanonical,
  inboxAppendAckV1,
  inboxCreateCommitment,
  inboxPhysicalTopic,
  inboxReadEntriesCommitment,
  inboxReadResultV1,
  inboxReceiptV1,
  relayResultBindingV1,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'

const SIGNATURE_BYTES = sodium.crypto_sign_BYTES

export const BLIND_INBOX_RUNTIME_BLOCKERS = Object.freeze([
  'FINAL_STORE_FORMAT_AUTHORITY_UNPUBLISHED',
  'SHARED_ALL_FAMILY_WAL_DISPATCH_UNASSEMBLED',
  'INBOX_CHECKPOINT_ENGINE_RESTORE_UNASSEMBLED',
  'INBOX_PROVISIONAL_APPEND_RECONCILIATION_UNASSEMBLED',
  'WATCH_PER_CONNECTION_SCOPE_UNASSEMBLED'
])

export const BLIND_INBOX_RUNTIME_STATUS = Object.freeze({
  family: 'INBOX',
  operations: Object.freeze(['CREATE', 'RENEW', 'CLOSE', 'APPEND', 'READ', 'WATCH']),
  coordinatorHooksImplemented: true,
  storageOwnedSpendMutationAtomicity: true,
  deterministicMutationReplayAcrossDescriptorRefresh: true,
  chargedReadWatchRetryPins: true,
  signedCanonicalResults: true,
  productionReady: false,
  blockers: BLIND_INBOX_RUNTIME_BLOCKERS
})

const COMMITTED_INBOX_RESULTS = new WeakSet()

function committedInboxResult (body) {
  const result = Object.freeze({ body: b4a.from(body) })
  COMMITTED_INBOX_RESULTS.add(result)
  return result
}

export function isCommittedInboxResult (value) {
  return Boolean(value && typeof value === 'object' && COMMITTED_INBOX_RESULTS.has(value))
}

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function same (left, right) {
  return Boolean(left && right && left.byteLength === right.byteLength && b4a.equals(left, right))
}

function nonzero (value) {
  if (!value || typeof value.byteLength !== 'number') return false
  for (const byte of value) if (byte !== 0) return true
  return false
}

function inboxInput (input) {
  if (!input || !input.profile || input.profile.familyId !== FAMILY.INBOX || !input.request) {
    fail('INTERNAL', 'INBOX runtime hook received another family or no request')
  }
  return input
}

function admittedRead (input) {
  return input.profile.operationId === OPERATION.INBOX.WATCH ||
    (input.profile.operationId === OPERATION.INBOX.READ && input.request.admission != null)
}

function admittedOperation (input) {
  return input.profile.operationId === OPERATION.INBOX.CREATE ||
    input.profile.operationId === OPERATION.INBOX.RENEW ||
    input.profile.operationId === OPERATION.INBOX.APPEND || admittedRead(input)
}

function signedBytes (codec, value) {
  const complete = encodeCanonical(codec, value)
  if (complete.byteLength <= SIGNATURE_BYTES || !value.signature || value.signature.byteLength !== SIGNATURE_BYTES) {
    fail('INTERNAL', 'signed INBOX result has no canonical trailing signature')
  }
  return { complete, unsigned: complete.subarray(0, complete.byteLength - SIGNATURE_BYTES) }
}

async function signValue (signer, codec, value, domainId, relayPublicKey, signal) {
  value.signature = b4a.alloc(SIGNATURE_BYTES)
  const { unsigned } = signedBytes(codec, value)
  value.signature = b4a.from(await signer.sign({
    domainId,
    publicKey: b4a.from(relayPublicKey),
    payload: resultSignaturePayload(domainId, unsigned),
    canonicalUnsignedBytes: b4a.from(unsigned),
    signal
  }))
  if (value.signature.byteLength !== SIGNATURE_BYTES) fail('INTERNAL', 'INBOX signer returned an invalid signature')
  return encodeCanonical(codec, value)
}

function verifySignedValue (codec, value, domainId, publicKey) {
  try {
    const { unsigned } = signedBytes(codec, value)
    return sodium.crypto_sign_verify_detached(value.signature,
      resultSignaturePayload(domainId, unsigned), publicKey)
  } catch {
    return false
  }
}

function decodedBinding (canonicalBytes) {
  return decodeCanonical(relayResultBindingV1, canonicalBytes, { copyBytes: true })
}

function topicCommitment (topic) {
  return blake2b256(topic)
}

function receiptResult (operationId) {
  if (operationId === OPERATION.INBOX.CREATE) return INBOX_RECEIPT_RESULT.CREATED
  if (operationId === OPERATION.INBOX.RENEW) return INBOX_RECEIPT_RESULT.RENEWED
  if (operationId === OPERATION.INBOX.CLOSE) return INBOX_RECEIPT_RESULT.CLOSED
  fail('INTERNAL', 'operation has no Inbox receipt result')
}

async function signedReceipt (adapter, input, stored) {
  const operationId = input.profile.operationId
  const relayBinding = decodedBinding(stored.resultBindingBytes)
  return signValue(adapter.signer, inboxReceiptV1, {
    version: 1,
    relayBinding,
    topicCommitment: topicCommitment(input.request.physicalTopic),
    stateRevision: stored.stateRevision,
    leaseClass: stored.leaseClass,
    leaseEpoch: stored.leaseEpoch,
    requestNonce: b4a.from(input.request.clientNonce),
    requestCommitment: b4a.from(input.requestCommitment),
    result: receiptResult(operationId),
    signature: b4a.alloc(SIGNATURE_BYTES)
  }, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT,
  relayBinding.relayPublicKey,
  input.signal)
}

async function signedAppend (adapter, input, stored) {
  const frame = stored.frame
  const relayBinding = decodedBinding(stored.resultBindingBytes)
  const value = {
    version: 1,
    relayBinding,
    topicCommitment: topicCommitment(input.request.physicalTopic),
    frameHash: b4a.from(frame.frameHash),
    appendRevision: frame.appendRevision,
    storedAtEpoch: frame.storedAtEpoch,
    expiresAtEpoch: frame.expiresAtEpoch,
    requestNonce: b4a.from(input.request.clientNonce),
    requestCommitment: b4a.from(input.requestCommitment),
    result: INBOX_APPEND_RESULT.STORED,
    signature: stored.ackSignature == null ? b4a.alloc(SIGNATURE_BYTES) : b4a.from(stored.ackSignature)
  }
  if (stored.ackSignature == null) {
    return signValue(adapter.signer, inboxAppendAckV1, value,
      RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK,
      relayBinding.relayPublicKey,
      input.signal)
  }
  const body = encodeCanonical(inboxAppendAckV1, value)
  if (!stored.resultCommitment || !same(blake2b256(body), stored.resultCommitment) ||
      !verifySignedValue(inboxAppendAckV1, value,
        RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, value.relayBinding.relayPublicKey)) {
    fail('INTERNAL', 'stored INBOX APPEND acknowledgement authority is invalid')
  }
  return body
}

function publicEntries (entries) {
  return entries.map(entry => ({
    appendRevision: entry.appendRevision,
    frameHash: b4a.from(entry.frameHash),
    frameClass: entry.frameClass,
    frame: b4a.from(entry.frame)
  }))
}

async function signedRead (adapter, input, stored) {
  const entries = publicEntries(stored.entries)
  const relayBinding = decodedBinding(stored.resultBindingBytes)
  const expectedCommitment = inboxReadEntriesCommitment(entries)
  if (stored.entriesCommitment && !same(stored.entriesCommitment, expectedCommitment)) {
    fail('INTERNAL', 'INBOX storage returned a substituted entries commitment')
  }
  return signValue(adapter.signer, inboxReadResultV1, {
    version: 1,
    relayBinding,
    requestNonce: b4a.from(input.request.clientNonce),
    requestCommitment: b4a.from(input.requestCommitment),
    snapshotRevision: stored.snapshotRevision,
    entries,
    entriesCommitment: expectedCommitment,
    nextCursor: stored.nextCursor == null ? null : b4a.from(stored.nextCursor),
    signature: b4a.alloc(SIGNATURE_BYTES)
  }, RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT,
  relayBinding.relayPublicKey,
  input.signal)
}

function maximumResultBytes (input, inbox) {
  let largest = 0
  for (let frameClass = 1; frameClass <= 3; frameClass++) {
    if ((inbox.frameClassBits & (1 << (frameClass - 1))) !== 0) largest = Math.max(largest, INBOX_FRAME_CLASS[frameClass])
  }
  if (largest === 0) fail('INTERNAL', 'stored Inbox enables no frame class')
  return Math.min(input.profile.maxResultBodyBytes, 4096 + input.request.limit * (41 + largest))
}

export class BlindInboxRuntimeAdapter {
  constructor (options = {}) {
    if (!options.storage || typeof options.storage.inspectInboxState !== 'function' ||
        typeof options.storage.preparedInboxOperationState !== 'function' ||
        typeof options.storage.closeRequestState !== 'function' ||
        typeof options.storage.verifyManagementCapability !== 'function' ||
        typeof options.storage.verifyAppendCapability !== 'function' ||
        typeof options.storage.checkCapacity !== 'function' ||
        typeof options.storage.createInbox !== 'function' ||
        typeof options.storage.renewInbox !== 'function' ||
        typeof options.storage.closeInbox !== 'function' ||
        typeof options.storage.appendFrame !== 'function' ||
        typeof options.storage.finalizeAppendAck !== 'function' ||
        typeof options.storage.readPage !== 'function' ||
        typeof options.storage.pinChargedPage !== 'function' ||
        typeof options.storage.chargedPageState !== 'function' ||
        typeof options.storage.readPinnedPage !== 'function' ||
        typeof options.storage.finalizeChargedPage !== 'function') {
      throw new TypeError('complete BlindInboxStorageEngine runtime authority is required')
    }
    if (!options.descriptorState || typeof options.descriptorState.resultBinding !== 'function') {
      throw new TypeError('descriptorState is required')
    }
    if (!options.signer || typeof options.signer.sign !== 'function') throw new TypeError('INBOX signer is required')
    this.storage = options.storage
    this.descriptorState = options.descriptorState
    this.signer = options.signer

    this.relationVerifier = Object.freeze({ verify: input => this.verifyRelation(input) })
    this.capabilityVerifier = Object.freeze({ verify: input => this.verifyCapability(input) })
    this.cheapStateVerifier = Object.freeze({ inspect: input => this.inspectCheapState(input) })
    this.terminalStateVerifier = Object.freeze({ check: input => this.checkTerminalState(input) })
    this.capacityGuard = Object.freeze({ check: input => this.checkCapacity(input) })
    this.operationExecutor = Object.freeze({ execute: input => this.execute(input) })
    this.transactionCoordinator = Object.freeze({
      lookup: input => this.lookupTransaction(input),
      run: (input, execute) => this.runTransaction(input, execute),
      replay: input => this.replayTransaction(input)
    })
    this.resultVerifier = Object.freeze({ verify: input => this.verifyResult(input) })
  }

  status () {
    return BLIND_INBOX_RUNTIME_STATUS
  }

  async verifyRelation (raw) {
    const input = inboxInput(raw)
    if (input.profile.operationId === OPERATION.INBOX.CREATE) {
      try {
        return same(inboxPhysicalTopic(input.request), input.request.physicalTopic)
      } catch {
        return false
      }
    }
    return nonzero(input.request.physicalTopic)
  }

  async verifyCapability (raw) {
    const input = inboxInput(raw)
    const operationId = input.profile.operationId
    if (operationId === OPERATION.INBOX.CREATE) {
      try {
        const commitment = inboxCreateCommitment({ ...input.request, relayPublicKey: input.descriptor.relayPublicKey })
        return sodium.crypto_sign_verify_detached(input.request.createSignature,
          commitment, input.request.createPublicKey)
      } catch {
        return false
      }
    }
    if (operationId === OPERATION.INBOX.RENEW || operationId === OPERATION.INBOX.CLOSE) {
      return this.storage.verifyManagementCapability({
        operationId,
        physicalTopic: input.request.physicalTopic,
        requestCommitment: input.requestCommitment,
        signature: input.request.signature
      })
    }
    if (operationId === OPERATION.INBOX.APPEND) {
      return this.storage.verifyAppendCapability({
        physicalTopic: input.request.physicalTopic,
        requestCommitment: input.requestCommitment,
        signature: input.request.appendSignature
      })
    }
    return true
  }

  async inspectCheapState (raw) {
    const input = inboxInput(raw)
    if (input.profile.operationId === OPERATION.INBOX.CREATE) return {}
    const state = this.storage.inspectInboxState(input.request.physicalTopic)
    if (!state || !state.publiclyVisible) {
      return {
        absent: true,
        inboxRetentionClass: 1,
        inboxFrameClassBits: 1,
        canonicalResultBytes: 1,
        predictedResultBodyBytes: 1
      }
    }
    const value = {
      inboxRetentionClass: state.inbox.retentionClass,
      inboxFrameClassBits: state.inbox.frameClassBits
    }
    if (input.profile.operationId === OPERATION.INBOX.READ ||
        input.profile.operationId === OPERATION.INBOX.WATCH) {
      value.canonicalResultBytes = maximumResultBytes(input, state.inbox)
      value.predictedResultBodyBytes = value.canonicalResultBytes
    }
    return value
  }

  async checkTerminalState (raw) {
    const input = inboxInput(raw)
    const operationId = input.profile.operationId
    let exactMutationReplay = false
    if (operationId === OPERATION.INBOX.CREATE || operationId === OPERATION.INBOX.RENEW ||
        operationId === OPERATION.INBOX.APPEND) {
      const spend = this.storage.preparedInboxOperationState({
        operationId,
        preparedAdmission: input.preparedAdmission,
        requestCommitment: input.requestCommitment
      })
      if (spend.kind === 'conflict') fail('SPEND_REPLAY', 'INBOX admission spend conflicts with another request')
      if (spend.kind === 'terminal') fail('RETRY_TERMINAL', 'INBOX admission retry is terminal')
      exactMutationReplay = spend.kind === 'replay'
    }
    if (admittedRead(input)) {
      const spend = this.storage.chargedPageState({
        operationId,
        preparedAdmission: input.preparedAdmission
      })
      if (spend.kind === 'conflict') fail('SPEND_REPLAY', 'INBOX read spend conflicts with another request')
      if (spend.kind === 'terminal') fail('RETRY_TERMINAL', 'INBOX read retry is terminal')
    }
    if (operationId === OPERATION.INBOX.CLOSE &&
        this.storage.closeRequestState(input.requestCommitment).kind === 'replay') return
    if (operationId === OPERATION.INBOX.CREATE) return
    if (exactMutationReplay && operationId === OPERATION.INBOX.APPEND) return
    const state = this.storage.inspectInboxState(input.request.physicalTopic)
    if (!state || !state.publiclyVisible) fail('NOT_FOUND', 'inbox is absent')
    if (exactMutationReplay) return
    if ((operationId === OPERATION.INBOX.RENEW || operationId === OPERATION.INBOX.CLOSE) &&
        (state.inbox.stateRevision !== input.request.expectedRevision ||
          state.inbox.leaseEpoch !== input.request.expectedLeaseEpoch)) {
      fail('STALE_REVISION', 'Inbox management CAS is stale')
    }
    if (operationId === OPERATION.INBOX.APPEND &&
        (state.inbox.frameClassBits & (1 << (input.request.frameClass - 1))) === 0) {
      fail('TOO_LARGE', 'Inbox frame class is not enabled')
    }
  }

  async checkCapacity (raw) {
    const input = inboxInput(raw)
    const operationId = input.profile.operationId
    if (operationId === OPERATION.INBOX.CREATE || operationId === OPERATION.INBOX.RENEW ||
        operationId === OPERATION.INBOX.APPEND) {
      const spend = this.storage.preparedInboxOperationState({
        operationId,
        preparedAdmission: input.preparedAdmission,
        requestCommitment: input.requestCommitment
      })
      if (spend.kind === 'replay') return true
    }
    if (admittedRead(input)) {
      const spend = this.storage.chargedPageState({
        operationId,
        preparedAdmission: input.preparedAdmission
      })
      if (spend.kind === 'replay' || spend.kind === 'reserved') return true
    }
    return this.storage.checkCapacity({
      operationId,
      request: input.request,
      preparedAdmission: input.preparedAdmission,
      requestCommitment: input.requestCommitment
    })
  }

  async lookupTransaction (raw) {
    const input = inboxInput(raw)
    if (!admittedOperation(input)) fail('INTERNAL', 'only admitted INBOX operations have a transaction')
    if (!admittedRead(input)) return Object.freeze({ kind: 'fresh' })
    const state = this.storage.chargedPageState({
      operationId: input.profile.operationId,
      preparedAdmission: input.preparedAdmission
    })
    return Object.freeze({ kind: state.kind === 'replay' || state.kind === 'reserved' ? 'replay' : 'fresh' })
  }

  async runTransaction (raw, execute) {
    const input = inboxInput(raw)
    if (typeof execute !== 'function' || !admittedOperation(input)) fail('INTERNAL', 'INBOX transaction invocation is invalid')
    return execute(Object.freeze({ kind: 'blind-inbox-storage-owned' }))
  }

  async replayTransaction (raw) {
    const input = inboxInput({ ...raw, descriptorState: this.descriptorState })
    if (!admittedRead(input)) fail('INTERNAL', 'only charged INBOX READ/WATCH has a standalone replay path')
    return this.executeChargedRead(input, true)
  }

  async executeChargedRead (input, replay = false) {
    const stored = replay
      ? await this.storage.readPinnedPage({ spendTag: input.preparedAdmission.spendTag })
      : await this.storage.pinChargedPage({
        operationId: input.profile.operationId,
        request: input.request,
        requestCommitment: input.requestCommitment,
        preparedAdmission: input.preparedAdmission,
        resultBinding: this.descriptorState.resultBinding(input.descriptorSnapshot),
        signal: input.signal
      })
    const body = await signedRead(this, input, stored)
    const commitment = blake2b256(body)
    if (stored.resultCommitment && !same(stored.resultCommitment, commitment)) {
      fail('INTERNAL', 'charged INBOX read reconstruction changed after finalization')
    }
    await this.storage.finalizeChargedPage({
      spendTag: stored.spendTag,
      requestCommitment: stored.requestCommitment,
      resultCommitment: commitment
    })
    return committedInboxResult(body)
  }

  async execute (raw) {
    const input = inboxInput({ ...raw, descriptorState: this.descriptorState })
    const operationId = input.profile.operationId
    if (admittedOperation(input) &&
        (!input.transaction || input.transaction.kind !== 'blind-inbox-storage-owned')) {
      fail('INTERNAL', 'admitted INBOX operation escaped its storage-owned transaction')
    }
    if (operationId === OPERATION.INBOX.CREATE) {
      const stored = await this.storage.createInbox({
        request: input.request,
        requestCommitment: input.requestCommitment,
        preparedAdmission: input.preparedAdmission,
        resultBinding: this.descriptorState.resultBinding(input.descriptorSnapshot)
      })
      return committedInboxResult(await signedReceipt(this, input, stored))
    }
    if (operationId === OPERATION.INBOX.RENEW) {
      const stored = await this.storage.renewInbox({
        request: input.request,
        requestCommitment: input.requestCommitment,
        preparedAdmission: input.preparedAdmission,
        resultBinding: this.descriptorState.resultBinding(input.descriptorSnapshot)
      })
      return committedInboxResult(await signedReceipt(this, input, stored))
    }
    if (operationId === OPERATION.INBOX.CLOSE) {
      const stored = await this.storage.closeInbox({
        request: input.request,
        requestCommitment: input.requestCommitment,
        resultBinding: this.descriptorState.resultBinding(input.descriptorSnapshot)
      })
      return committedInboxResult(await signedReceipt(this, input, stored))
    }
    if (operationId === OPERATION.INBOX.APPEND) {
      const stored = await this.storage.appendFrame({
        request: input.request,
        requestCommitment: input.requestCommitment,
        preparedAdmission: input.preparedAdmission,
        resultBinding: this.descriptorState.resultBinding(input.descriptorSnapshot),
        signal: input.signal
      })
      const body = await signedAppend(this, input, stored)
      const value = decodeCanonical(inboxAppendAckV1, body, { copyBytes: true })
      await this.storage.finalizeAppendAck({
        spendTag: stored.spendTag,
        requestCommitment: stored.requestCommitment,
        ackSignature: value.signature,
        resultCommitment: blake2b256(body)
      })
      return committedInboxResult(body)
    }
    if (operationId === OPERATION.INBOX.READ || operationId === OPERATION.INBOX.WATCH) {
      if (admittedRead(input)) return this.executeChargedRead(input)
      const stored = await this.storage.readPage({ request: input.request, signal: input.signal })
      const body = await signedRead(this, input, {
        ...stored,
        resultBindingBytes: encodeCanonical(relayResultBindingV1,
          this.descriptorState.resultBinding(input.descriptorSnapshot))
      })
      return { body }
    }
    fail('INTERNAL', 'registered INBOX operation has no runtime implementation')
  }

  async verifyResult (input) {
    if (!input || input.familyId !== FAMILY.INBOX || !input.result || !input.request ||
        !input.expectedRelayBinding || !input.expectedRelayBinding.relayPublicKey) return false
    const value = input.result
    const request = input.request
    const publicKey = input.expectedRelayBinding.relayPublicKey
    if (input.operationId === OPERATION.INBOX.CREATE || input.operationId === OPERATION.INBOX.RENEW ||
        input.operationId === OPERATION.INBOX.CLOSE) {
      if (!verifySignedValue(inboxReceiptV1, value, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, publicKey) ||
          !same(value.topicCommitment, topicCommitment(request.physicalTopic)) ||
          !same(value.requestNonce, request.clientNonce) ||
          !same(value.requestCommitment, input.requestCommitment) || value.result !== receiptResult(input.operationId)) return false
      if (input.operationId === OPERATION.INBOX.CREATE) {
        return value.stateRevision === 0n && value.leaseClass === request.leaseClass &&
          value.leaseEpoch > request.allocationEpoch
      }
      if (input.operationId === OPERATION.INBOX.RENEW) {
        return value.stateRevision === request.expectedRevision + 1n && value.leaseClass === request.leaseClass &&
          value.leaseEpoch > request.expectedLeaseEpoch
      }
      return value.stateRevision === request.expectedRevision + 1n && value.leaseClass === 0
    }
    if (input.operationId === OPERATION.INBOX.APPEND) {
      return verifySignedValue(inboxAppendAckV1, value,
        RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, publicKey) &&
        same(value.topicCommitment, topicCommitment(request.physicalTopic)) &&
        same(value.frameHash, request.frameHash) && same(value.requestNonce, request.clientNonce) &&
        same(value.requestCommitment, input.requestCommitment) &&
        value.result === INBOX_APPEND_RESULT.STORED && value.appendRevision > 0n &&
        value.expiresAtEpoch > value.storedAtEpoch
    }
    if (input.operationId === OPERATION.INBOX.READ || input.operationId === OPERATION.INBOX.WATCH) {
      if (!verifySignedValue(inboxReadResultV1, value,
        RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT, publicKey) ||
          !same(value.requestNonce, request.clientNonce) ||
          !same(value.requestCommitment, input.requestCommitment) ||
          !same(value.entriesCommitment, inboxReadEntriesCommitment(value.entries)) ||
          value.entries.length > request.limit) return false
      let previous = input.operationId === OPERATION.INBOX.WATCH ? request.afterRevision : -1n
      for (const entry of value.entries) {
        if (entry.appendRevision <= previous || entry.appendRevision > value.snapshotRevision ||
            entry.frame.byteLength !== INBOX_FRAME_CLASS[entry.frameClass] ||
            !same(blake2b256(entry.frame), entry.frameHash)) return false
        previous = entry.appendRevision
      }
      return input.operationId !== OPERATION.INBOX.WATCH || value.snapshotRevision >= request.afterRevision
    }
    return false
  }
}
