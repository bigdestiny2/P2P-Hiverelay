import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  CELL_RECEIPT_RESULT,
  CELL_SIZE_CLASS,
  FAMILY,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  allocationCommitment,
  batchGetEntriesCommitment,
  batchGetResultV1,
  blake2b256,
  blindReceiptV1,
  cellStorageSlot,
  decodeCanonical,
  encodeCanonical,
  getCellResultV1,
  proveCellResultV1,
  relayResultBindingV1,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'

const CELL_PROTOCOL = b4a.from('hiverelay-blind-cell-v1', 'ascii')
const SIGNATURE_BYTES = sodium.crypto_sign_BYTES

export const BLIND_CELL_RUNTIME_BLOCKERS = Object.freeze([])

export const BLIND_CELL_RUNTIME_STATUS = Object.freeze({
  family: 'CELL',
  operations: Object.freeze(['PUT', 'GET', 'RENEW', 'DROP', 'PROVE', 'BATCH_GET']),
  stagedPutExecutionPath: true,
  unchargedReadPath: true,
  storageOwnedSpendAndMutationAtomicity: true,
  deterministicMutationReplaySnapshots: true,
  deterministicMutationResultBindingAcrossDescriptorRefresh: true,
  chargedReadRetryPins: true,
  chargedReadFinalizationSourceLock: true,
  chargedReadPinExpiry: true,
  chargedReadCheckpointState: true,
  admissionWalCommitRecordPersisted: true,
  productionReady: true,
  blockers: BLIND_CELL_RUNTIME_BLOCKERS
})

const COMMITTED_CELL_RESULTS = new WeakSet()

function committedCellResult (body) {
  const value = Object.freeze({ body: b4a.from(body) })
  COMMITTED_CELL_RESULTS.add(value)
  return value
}

export function isCommittedCellResult (value) {
  return Boolean(value && typeof value === 'object' && COMMITTED_CELL_RESULTS.has(value))
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

function cellInput (input) {
  if (!input || !input.profile || input.profile.familyId !== FAMILY.CELL || !input.request) {
    fail('INTERNAL', 'CELL runtime hook received another family or no request')
  }
  return input
}

function isChargedRead (input) {
  return (input.profile.operationId === OPERATION.CELL.GET ||
    input.profile.operationId === OPERATION.CELL.PROVE ||
    input.profile.operationId === OPERATION.CELL.BATCH_GET) && input.request.admission != null
}

function isAdmittedCellTransaction (input) {
  return input.profile.operationId === OPERATION.CELL.PUT ||
    input.profile.operationId === OPERATION.CELL.RENEW || isChargedRead(input)
}

function resultBindingBytes (input) {
  return encodeCanonical(relayResultBindingV1,
    input.descriptorState.resultBinding(input.descriptorSnapshot))
}

function chargedBatchResultBytes (bindingBytes, states) {
  let bytes = 162 + bindingBytes.byteLength
  for (const state of states) {
    bytes += !state || !state.publiclyVisible ? 1 : 2 + CELL_SIZE_CLASS[state.cell.sizeClass]
  }
  return bytes
}

function signedBytes (codec, value) {
  const complete = encodeCanonical(codec, value)
  if (complete.byteLength <= SIGNATURE_BYTES || !value.signature || value.signature.byteLength !== SIGNATURE_BYTES) {
    fail('INTERNAL', 'signed CELL result has no canonical trailing signature')
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
  if (value.signature.byteLength !== SIGNATURE_BYTES) fail('INTERNAL', 'CELL signer returned an invalid signature')
  return encodeCanonical(codec, value)
}

function verifySignedValue (codec, value, domainId, publicKey) {
  const { unsigned } = signedBytes(codec, value)
  try {
    return sodium.crypto_sign_verify_detached(
      value.signature,
      resultSignaturePayload(domainId, unsigned),
      publicKey
    )
  } catch {
    return false
  }
}

function receiptValue (input, stored, result) {
  const cell = stored.cell
  const relayBinding = stored.resultBindingBytes == null
    ? input.descriptorState.resultBinding(input.descriptorSnapshot)
    : decodeCanonical(relayResultBindingV1, stored.resultBindingBytes, { copyBytes: true })
  return {
    version: 1,
    protocol: b4a.from(CELL_PROTOCOL),
    relayBinding,
    slotCommitment: blake2b256(input.request.storageSlot),
    cellBlobHash: b4a.from(cell.cellBlobHash),
    allocationCommitment: b4a.from(cell.allocationCommitment),
    requestCommitment: b4a.from(input.requestCommitment),
    sizeClass: cell.sizeClass,
    allocationEpoch: cell.allocationEpoch,
    leaseClass: result === CELL_RECEIPT_RESULT.DROPPED ? 0 : cell.leaseClass,
    leaseEpoch: cell.leaseEpoch,
    stateRevision: cell.stateRevision,
    receiptEpoch: stored.receiptEpoch,
    requestNonce: b4a.from(input.request.clientNonce),
    result,
    signature: b4a.alloc(SIGNATURE_BYTES)
  }
}

async function signedReceipt (adapter, input, stored, result) {
  const value = receiptValue(input, stored, result)
  return signValue(adapter.signer, blindReceiptV1, value,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT,
    input.descriptor.relayPublicKey,
    input.signal)
}

function managementCommitmentMatches (value, input, expectedResult) {
  return same(value.requestCommitment, input.requestCommitment) &&
    same(value.requestNonce, input.request.clientNonce) &&
    same(value.slotCommitment, blake2b256(input.request.storageSlot)) &&
    value.result === expectedResult
}

export class BlindCellRuntimeAdapter {
  constructor (options = {}) {
    if (!options.storage || typeof options.storage.readCell !== 'function' ||
        typeof options.storage.readCells !== 'function' ||
        typeof options.storage.inspectCellState !== 'function' ||
        typeof options.storage.inspectCellsState !== 'function' ||
        typeof options.storage.verifyCellManagementCapability !== 'function' ||
        typeof options.storage.preparedCellOperationState !== 'function' ||
        typeof options.storage.chargedCellReadState !== 'function' ||
        typeof options.storage.chargedCellRead !== 'function' ||
        typeof options.storage.finalizeChargedCellRead !== 'function' ||
        typeof options.storage.checkCellCapacity !== 'function') {
      throw new TypeError('complete BlindCellStorageEngine runtime authority is required')
    }
    if (!options.descriptorState || typeof options.descriptorState.resultBinding !== 'function') {
      throw new TypeError('descriptorState is required')
    }
    if (!options.signer || typeof options.signer.sign !== 'function') throw new TypeError('CELL signer is required')
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
    return BLIND_CELL_RUNTIME_STATUS
  }

  async verifyRelation (raw) {
    const input = cellInput(raw)
    if (input.profile.operationId === OPERATION.CELL.BATCH_GET) {
      return input.request.slots.every(nonzero)
    }
    if (input.profile.operationId !== OPERATION.CELL.PUT) return nonzero(input.request.storageSlot)
    return same(cellStorageSlot(input.request), input.request.storageSlot)
  }

  async verifyCapability (raw) {
    const input = cellInput(raw)
    if (input.profile.operationId === OPERATION.CELL.PUT) {
      let commitment
      try {
        commitment = allocationCommitment({
          ...input.request,
          relayPublicKey: input.descriptor.relayPublicKey,
          declaredCellBlobHash: input.request.declaredBlobHash
        })
        return sodium.crypto_sign_verify_detached(
          input.request.createSignature,
          commitment,
          input.request.createPublicKey
        )
      } catch {
        return false
      }
    }
    if (input.profile.operationId === OPERATION.CELL.RENEW ||
        input.profile.operationId === OPERATION.CELL.DROP) {
      return this.storage.verifyCellManagementCapability({
        operationId: input.profile.operationId,
        storageSlot: input.request.storageSlot,
        requestCommitment: input.requestCommitment,
        signature: input.request.signature
      })
    }
    return true
  }

  async inspectCheapState (raw) {
    const input = cellInput(raw)
    if (input.profile.operationId === OPERATION.CELL.PUT ||
        input.profile.operationId === OPERATION.CELL.DROP) return {}
    if (input.profile.operationId === OPERATION.CELL.BATCH_GET) {
      const states = await this.storage.inspectCellsState(input.request.slots)
      const canonicalResultBytes = chargedBatchResultBytes(resultBindingBytes({
        ...input,
        descriptorState: this.descriptorState
      }), states)
      return { canonicalResultBytes, predictedResultBodyBytes: canonicalResultBytes }
    }
    const state = await this.storage.inspectCellState(input.request.storageSlot)
    if (!state || !state.publiclyVisible) return { absent: true }
    const value = { storedCellSizeClass: state.cell.sizeClass }
    if (input.profile.operationId === OPERATION.CELL.GET) {
      value.predictedResultBodyBytes = 2 + CELL_SIZE_CLASS[state.cell.sizeClass]
    } else if (input.profile.operationId === OPERATION.CELL.PROVE) {
      value.predictedResultBodyBytes = 273 + resultBindingBytes({
        ...input,
        descriptorState: this.descriptorState
      }).byteLength + CELL_SIZE_CLASS[state.cell.sizeClass]
    }
    return value
  }

  async checkTerminalState (raw) {
    const input = cellInput(raw)
    const operationId = input.profile.operationId
    if (isChargedRead(input)) return
    if (operationId === OPERATION.CELL.PUT) {
      const state = await this.storage.preparedCellOperationState({
        operationId,
        preparedAdmission: input.preparedAdmission,
        requestCommitment: input.requestCommitment
      })
      if (state.kind === 'conflict') fail('SPEND_REPLAY', 'admission spend is already bound to another request')
      if (state.kind === 'terminal') fail('RETRY_TERMINAL', 'CELL.PUT admission is terminal')
      return
    }
    if (operationId === OPERATION.CELL.RENEW) {
      const spend = await this.storage.preparedCellOperationState({
        operationId,
        preparedAdmission: input.preparedAdmission,
        requestCommitment: input.requestCommitment
      })
      if (spend.kind === 'conflict') fail('SPEND_REPLAY', 'admission spend is already bound to another request')
      if (spend.kind === 'terminal') fail('RETRY_TERMINAL', 'CELL.RENEW admission is terminal')
      if (spend.kind === 'replay') return
    }
    if (operationId === OPERATION.CELL.DROP) {
      const prior = await this.storage.cellRequestResultState(input.requestCommitment)
      if (prior.kind === 'replay') return
    }
    if (operationId === OPERATION.CELL.BATCH_GET) return
    const state = await this.storage.inspectCellState(input.request.storageSlot)
    if (!state || (operationId !== OPERATION.CELL.RENEW && operationId !== OPERATION.CELL.DROP &&
      !state.publiclyVisible) || state.cell.objectState !== 'PRESENT') {
      fail('NOT_FOUND', 'cell is absent')
    }
    if (operationId === OPERATION.CELL.RENEW &&
        this.storage.status().epochFloor > state.cell.leaseEpoch + 4) {
      fail('NOT_FOUND', 'cell is outside its renewable lease grace')
    }
    if ((operationId === OPERATION.CELL.RENEW || operationId === OPERATION.CELL.DROP) &&
        (state.cell.stateRevision !== input.request.expectedRevision ||
          state.cell.leaseEpoch !== input.request.expectedLeaseEpoch)) {
      fail('STALE_REVISION', 'cell management CAS is stale')
    }
  }

  async checkCapacity (raw) {
    const input = cellInput(raw)
    return this.storage.checkCellCapacity({
      operationId: input.profile.operationId,
      request: input.request,
      preparedAdmission: input.preparedAdmission,
      requestCommitment: input.requestCommitment,
      resultBinding: isChargedRead(input)
        ? this.descriptorState.resultBinding(input.descriptorSnapshot)
        : null
    })
  }

  async lookupTransaction (raw) {
    const input = cellInput(raw)
    if (!isAdmittedCellTransaction(input)) {
      fail('INTERNAL', 'only admitted CELL operations have a storage-owned transaction')
    }
    if (isChargedRead(input)) {
      const state = await this.storage.chargedCellReadState({
        operationId: input.profile.operationId,
        request: input.request,
        preparedAdmission: input.preparedAdmission,
        requestCommitment: input.requestCommitment,
        resultBinding: this.descriptorState.resultBinding(input.descriptorSnapshot)
      })
      return Object.freeze({ kind: state.kind === 'replay' ? 'replay' : 'fresh' })
    }
    // The storage engine performs the authoritative spend lookup and exact
    // replay under the same WAL locks as the mutation. Reporting "fresh" here
    // deliberately keeps both first execution and retry on that one atomic path.
    return Object.freeze({ kind: 'fresh' })
  }

  async runTransaction (raw, execute) {
    const input = cellInput(raw)
    if (typeof execute !== 'function' || !isAdmittedCellTransaction(input)) {
      fail('INTERNAL', 'CELL transaction invocation is invalid')
    }
    return execute(Object.freeze({ kind: 'blind-cell-storage-owned' }))
  }

  async replayTransaction (raw) {
    const input = cellInput({ ...raw, descriptorState: this.descriptorState })
    if (!isChargedRead(input)) {
      fail('INTERNAL', 'only a charged CELL read has a standalone exact replay path')
    }
    return this.executeChargedRead(input)
  }

  async executeChargedRead (input) {
    const stored = await this.storage.chargedCellRead({
      operationId: input.profile.operationId,
      request: input.request,
      preparedAdmission: input.preparedAdmission,
      requestCommitment: input.requestCommitment,
      resultBinding: this.descriptorState.resultBinding(input.descriptorSnapshot)
    })
    let body
    if (input.profile.operationId === OPERATION.CELL.GET) {
      const found = stored.entries[0]
      body = encodeCanonical(getCellResultV1, {
        version: 1,
        sizeClass: found.sizeClass,
        cellBlob: b4a.from(found.cellBlob)
      })
    } else if (input.profile.operationId === OPERATION.CELL.PROVE) {
      const found = stored.entries[0]
      const receipt = await signedReceipt(this, input, {
        cell: found.pin,
        receiptEpoch: stored.receiptEpoch,
        resultBindingBytes: stored.resultBindingBytes
      }, CELL_RECEIPT_RESULT.SERVED)
      body = encodeCanonical(proveCellResultV1, {
        version: 1,
        receipt: signedReceiptValue(receipt),
        sizeClass: found.sizeClass,
        cellBlob: b4a.from(found.cellBlob)
      })
    } else {
      const entries = stored.entries.map(entry => entry.status === 0
        ? { status: 0 }
        : { status: 1, sizeClass: entry.sizeClass, cellBlob: b4a.from(entry.cellBlob) })
      body = await signValue(this.signer, batchGetResultV1, {
        version: 1,
        relayBinding: decodeCanonical(relayResultBindingV1, stored.resultBindingBytes, { copyBytes: true }),
        requestNonce: b4a.from(input.request.clientNonce),
        requestCommitment: b4a.from(input.requestCommitment),
        entries,
        entriesCommitment: batchGetEntriesCommitment(entries),
        signature: b4a.alloc(SIGNATURE_BYTES)
      }, RESULT_SIGNATURE_DOMAIN_ID.BATCH_GET_RESULT,
      input.descriptor.relayPublicKey,
      input.signal)
    }
    const resultCommitment = blake2b256(body)
    if (stored.resultCommitment && !same(stored.resultCommitment, resultCommitment)) {
      fail('INTERNAL', 'charged CELL read reconstruction changed after finalization')
    }
    await this.storage.finalizeChargedCellRead({
      spendTag: stored.spendTag,
      requestCommitment: stored.requestCommitment,
      resultCommitment
    })
    return committedCellResult(body)
  }

  async execute (raw) {
    const input = cellInput({ ...raw, descriptorState: this.descriptorState })
    const operationId = input.profile.operationId
    if (isAdmittedCellTransaction(input) &&
        (!input.transaction || input.transaction.kind !== 'blind-cell-storage-owned')) {
      fail('INTERNAL', 'admitted CELL operation escaped its storage-owned transaction')
    }
    if (operationId === OPERATION.CELL.PUT) {
      const resultBinding = this.descriptorState.resultBinding(input.descriptorSnapshot)
      const stored = await this.storage.putCell({
        request: input.request,
        preparedAdmission: input.preparedAdmission,
        source: input.opaqueBodySource,
        resultBinding
      })
      return committedCellResult(await signedReceipt(this, input, stored, CELL_RECEIPT_RESULT.STORED))
    }
    if (operationId === OPERATION.CELL.GET) {
      if (isChargedRead(input)) return this.executeChargedRead(input)
      const found = await this.storage.readCell(input.request.storageSlot)
      return {
        version: 1,
        sizeClass: found.sizeClass,
        cellBlob: b4a.from(found.cellBlob)
      }
    }
    if (operationId === OPERATION.CELL.RENEW) {
      const resultBinding = this.descriptorState.resultBinding(input.descriptorSnapshot)
      const stored = await this.storage.renewCell({
        request: input.request,
        preparedAdmission: input.preparedAdmission,
        resultBinding
      })
      return committedCellResult(await signedReceipt(this, input, stored, CELL_RECEIPT_RESULT.RENEWED))
    }
    if (operationId === OPERATION.CELL.DROP) {
      const stored = await this.storage.dropCell({
        request: input.request,
        resultBinding: this.descriptorState.resultBinding(input.descriptorSnapshot)
      })
      return committedCellResult(await signedReceipt(this, input, stored, CELL_RECEIPT_RESULT.DROPPED))
    }
    if (operationId === OPERATION.CELL.PROVE) {
      if (isChargedRead(input)) return this.executeChargedRead(input)
      const found = await this.storage.readCell(input.request.storageSlot)
      const signed = await signedReceipt(this, input, {
        cell: found.cell,
        receiptEpoch: found.receiptEpoch
      }, CELL_RECEIPT_RESULT.SERVED)
      return {
        version: 1,
        receipt: signedReceiptValue(signed),
        sizeClass: found.sizeClass,
        cellBlob: b4a.from(found.cellBlob)
      }
    }
    if (operationId === OPERATION.CELL.BATCH_GET) {
      if (isChargedRead(input)) return this.executeChargedRead(input)
      const found = await this.storage.readCells(input.request.slots)
      const entries = found.map(entry => entry == null
        ? { status: 0 }
        : { status: 1, sizeClass: entry.sizeClass, cellBlob: b4a.from(entry.cellBlob) })
      const value = {
        version: 1,
        relayBinding: this.descriptorState.resultBinding(input.descriptorSnapshot),
        requestNonce: b4a.from(input.request.clientNonce),
        requestCommitment: b4a.from(input.requestCommitment),
        entries,
        entriesCommitment: batchGetEntriesCommitment(entries),
        signature: b4a.alloc(SIGNATURE_BYTES)
      }
      return signValue(this.signer, batchGetResultV1, value,
        RESULT_SIGNATURE_DOMAIN_ID.BATCH_GET_RESULT,
        input.descriptor.relayPublicKey,
        input.signal)
    }
    fail('INTERNAL', 'registered CELL operation has no runtime implementation')
  }

  async verifyResult (input) {
    if (!input || input.familyId !== FAMILY.CELL || !input.result || !input.request) return false
    const value = input.result
    const request = input.request
    const publicKey = input.expectedRelayBinding && input.expectedRelayBinding.relayPublicKey
    if (input.operationId === OPERATION.CELL.GET) {
      return value.sizeClass >= 1 && value.sizeClass <= 5 &&
        value.cellBlob.byteLength === CELL_SIZE_CLASS[value.sizeClass]
    }
    if (!publicKey) return false
    if (input.operationId === OPERATION.CELL.BATCH_GET) {
      if (!verifySignedValue(batchGetResultV1, value,
        RESULT_SIGNATURE_DOMAIN_ID.BATCH_GET_RESULT, publicKey) ||
          !same(value.requestNonce, request.clientNonce) ||
          !same(value.requestCommitment, input.requestCommitment) ||
          value.entries.length !== request.slots.length ||
          !same(value.entriesCommitment, batchGetEntriesCommitment(value.entries))) return false
      return value.entries.every(entry => entry.status === 0 ||
        (entry.status === 1 && entry.sizeClass >= 1 && entry.sizeClass <= 5 &&
          entry.cellBlob.byteLength === CELL_SIZE_CLASS[entry.sizeClass]))
    }
    const receipt = input.operationId === OPERATION.CELL.PROVE ? value.receipt : value
    if (!verifySignedValue(blindReceiptV1, receipt,
      RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, publicKey) ||
        !same(receipt.requestCommitment, input.requestCommitment) ||
        !same(receipt.requestNonce, request.clientNonce) ||
        !same(receipt.slotCommitment, blake2b256(request.storageSlot))) return false
    if (input.operationId === OPERATION.CELL.PUT) {
      const allocation = allocationCommitment({
        ...request,
        relayPublicKey: publicKey,
        declaredCellBlobHash: request.declaredBlobHash
      })
      return managementCommitmentMatches(receipt, input, CELL_RECEIPT_RESULT.STORED) &&
        same(receipt.cellBlobHash, request.declaredBlobHash) &&
        same(receipt.allocationCommitment, allocation) &&
        receipt.sizeClass === request.sizeClass && receipt.allocationEpoch === request.allocationEpoch &&
        receipt.leaseClass === request.leaseClass && receipt.stateRevision === 0n
    }
    if (input.operationId === OPERATION.CELL.RENEW) {
      return managementCommitmentMatches(receipt, input, CELL_RECEIPT_RESULT.RENEWED) &&
        receipt.leaseClass === request.leaseClass &&
        receipt.stateRevision === request.expectedRevision + 1n &&
        receipt.leaseEpoch > request.expectedLeaseEpoch
    }
    if (input.operationId === OPERATION.CELL.DROP) {
      return managementCommitmentMatches(receipt, input, CELL_RECEIPT_RESULT.DROPPED) &&
        receipt.leaseClass === 0 && receipt.stateRevision === request.expectedRevision + 1n
    }
    if (input.operationId === OPERATION.CELL.PROVE) {
      return managementCommitmentMatches(receipt, input, CELL_RECEIPT_RESULT.SERVED) &&
        receipt.sizeClass === value.sizeClass && value.cellBlob.byteLength === CELL_SIZE_CLASS[value.sizeClass] &&
        same(blake2b256(value.cellBlob), receipt.cellBlobHash)
    }
    return false
  }
}

function signedReceiptValue (canonicalBytes) {
  // Kept local to avoid accepting a caller-provided mutable receipt between
  // signing and embedding in PROVE.
  return decodeCanonical(blindReceiptV1, canonicalBytes, { copyBytes: true })
}
