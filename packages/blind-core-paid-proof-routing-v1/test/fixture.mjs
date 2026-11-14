import fs from 'node:fs/promises'
import path from 'node:path'
import { createRequire } from 'node:module'
import assert from 'node:assert/strict'
import sodium from 'sodium-universal'
import {
  FAMILY, FRAME_KIND, OPERATION, RESULT_SIGNATURE_DOMAIN_ID, TRANSPORT_ID, TRANSPORT_SUPPORT,
  admissionParametersHash, admissionParametersV1, blindServiceDescriptorV1, blindErrorV1,
  coreMirrorRequestV1, coreServeChallengeV1, coreServeRequestCommitment, blake2b256,
  decodeCanonical, decodeDispatchFrame, encodeCanonical, resultSignaturePayload
} from '../../blind-protocol/index.js'
import { BlindOperationCoordinator } from '../../blind-daemon/coordinator.js'
import { AdmissionCoordinator } from '../../blind-daemon/admission-coordinator.js'
import { DescriptorState } from '../../blind-daemon/descriptor-state.js'
import { ResourceBudget } from '../../blind-daemon/resource-budget.js'
import { descriptorValue, parameterValue, bindDurability } from '../../blind-daemon/test/coordinator-fixtures.js'
import { RealCoreUpstreamV1, headHash } from '../../blind-core-upstream-hc11-v1/index.js'
import { BlindCorePaidProofRuntimeV1, BlindCorePaidProofStorageV1 } from '../index.js'
const require = createRequire(new URL('../../blind-core-upstream-hc11-v1/package.json', import.meta.url))
const Corestore = require('corestore'); const crypto = require('hypercore-crypto')
export const cloneRequest = request => decodeCanonical(coreServeChallengeV1, encodeCanonical(coreServeChallengeV1, request), { copyBytes: true })
export async function setup (t, opts = {}) {
  const parent = new URL('../.scratch/', import.meta.url)
  await fs.mkdir(parent, { recursive: true })
  const root = opts.restoreRoot || await fs.mkdtemp(path.join(parent.pathname, 'routing-')); await fs.chmod(root, 0o700)
  const h = {}; const secretKey = Buffer.alloc(64); let writerStore
  t.after(async () => { await h?.upstream?.close(); await h?.storage?.close(); await writerStore?.close(); secretKey?.fill(0); if (!opts.restoreRoot) await fs.rm(root, { recursive: true, force: true }) })
  let writer
  if (opts.restoreRoot) writer = { key: Buffer.from(opts.corePublicKey, 'hex'), replicate () { throw new Error('offline process attempted source acquisition') } }
  else {
    writerStore = new Corestore(path.join(root, 'writer'))
    writer = writerStore.get({ keyPair: crypto.keyPair(Buffer.alloc(32, 27)), encryptionKey: Buffer.alloc(32, 28) })
    await writer.ready(); await writer.append([Buffer.from('encrypted original one'), Buffer.from('encrypted original two')])
  }
  let epoch = 1000; let millis = 21600000000n; let ownerLive = true; let connections = 0; let preparedCount = 0; let frameNumber = 0
  const publicKey = Buffer.alloc(32)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, Buffer.alloc(32, 42))
  const sign = ({ payload }) => { const signature = Buffer.alloc(64); sodium.crypto_sign_detached(signature, payload, secretKey); return signature }
  const verify = async ({ signature, payload, publicKey }) => sodium.crypto_sign_verify_detached(signature, payload, publicKey)
  function signed (codec, value, domainId) {
    value.signature = Buffer.alloc(64)
    const placeholder = encodeCanonical(codec, value)
    value.signature = sign({ payload: resultSignaturePayload(domainId, placeholder.subarray(0, -64)) })
    return encodeCanonical(codec, value)
  }
  const parameters = parameterValue(publicKey, { validFromEpoch: epoch, expiresEpoch: epoch + 4 })
  for (let resourceClass = 1; resourceClass <= 6; resourceClass++) parameters.resourceCosts.push({ familyId: FAMILY.CORE, operationId: OPERATION.CORE.PROVE, resourceClass, leaseClass: 0, costUnits: 1n })
  parameters.resourceCosts.sort((a, b) => a.familyId - b.familyId || a.operationId - b.operationId || a.resourceClass - b.resourceClass || a.leaseClass - b.leaseClass)
  const parameterBytes = signed(admissionParametersV1, parameters, RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS)
  const parameterHash = admissionParametersHash(parameterBytes)
  const descriptor = descriptorValue({ relayPublicKey: publicKey, issuedEpoch: epoch, expiresEpoch: epoch + 4 })
  descriptor.admissionProfiles = [descriptor.admissionProfiles[0]]
  Object.assign(descriptor.admissionProfiles[0], { profileId: parameters.profileId, schemeId: parameters.schemeId, parameterHash, conformanceClass: parameters.conformanceClass, roleBits: parameters.roleBits })
  bindDurability(descriptor)
  const descriptorBytes = signed(blindServiceDescriptorV1, descriptor, RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR)
  const issued = new Set()
  const admissionToken = byte => { const token = Buffer.alloc(32, byte); issued.add(token.toString('hex')); return { profileId: parameters.profileId, schemeId: parameters.schemeId, parameterHash: Buffer.from(parameterHash), token } }
  const acknowledge = async () => {}
  acknowledge.assertWritable = () => { if (!ownerLive) { const e = new Error('fixture owner lease lost'); e.code = 'OWNER_FENCE'; throw e } }
  const storageOptions = { root: path.join(root, 'blind-store'), relayPublicKey: publicKey, partitionKey: Buffer.alloc(32, 0x81), ownerFenceTokenHash: Buffer.alloc(32, 0x91), durabilityContinuityHash: descriptor.durabilityContinuityHash, nowEpoch: () => epoch, nowUnixMillis: () => millis, maximumCorpusBytes: 1024 * 1024, onBlindWriteAcknowledged: acknowledge }
  if (!opts.restoreRoot) await fs.mkdir(storageOptions.root, { mode: 0o700 })
  Object.assign(h, { root, writer, writerStore, publicKey, admissionToken, events: [], reads: [], lookupInputs: [], storage: null, runtime: null, upstream: null, coordinator: null, budget: null })
  async function open () {
    h.storage = new BlindCorePaidProofStorageV1(storageOptions); await h.storage.open()
    const originalRead = h.storage.transactionStore.readOpaque.bind(h.storage.transactionStore)
    h.storage.transactionStore.readOpaque = async (...args) => { h.reads.push({ objectId: args[0].objectId.toString('hex'), reserved: h.budget?.items || 0 }); return originalRead(...args) }
    const state = new DescriptorState({ epochNow: () => epoch, verifySignature: verify }); await state.activate(descriptorBytes)
    h.budget = new ResourceBudget({ maxItems: 16, maxBytes: 32 * 1024 * 1024 })
    h.upstream = new RealCoreUpstreamV1({ root: path.join(root, 'upstream'), connect: () => { connections++; return writer.replicate(false) }, readCorpus: async ({ request }) => { h.lookupInputs.push(Buffer.from(request.signedHeadHash)); const active = h.storage.inspectCore(request.corePublicKey); return h.storage.transactionStore.readOpaque(active.corpus, active.corpus.byteLength, active.corpus.hash) } })
    h.runtime = new BlindCorePaidProofRuntimeV1({ storage: h.storage, upstream: h.upstream, descriptorState: state, signer: { async sign (input) { return sign(input) } } })
    const admission = new AdmissionCoordinator({
      descriptorState: state,
      verifySignature: verify,
      resolveAdapter: async () => ({
        async prepare (input) {
          h.events.push('admission'); preparedCount++; await h.beforePrepare?.(input)
          if (!issued.has(input.admission.token.toString('hex'))) { const e = new Error('fixture admission token was not issued'); e.code = 'SPEND_INVALID'; throw e }
          return { spendTag: blake2b256(input.admission.token), requestCommitment: Buffer.from(input.requestCommitment), costClass: { ...input.costClass }, walCommitRecord: Buffer.from(input.admission.token), profileId: input.admission.profileId, schemeId: input.admission.schemeId, parameterHash: Buffer.from(input.admission.parameterHash) }
        }
      })
    }); await admission.installParameters(parameterBytes)
    const hooks = {}
    for (const field of ['relationVerifier', 'capabilityVerifier', 'cheapStateVerifier', 'terminalStateVerifier', 'capacityGuard', 'operationExecutor', 'transactionCoordinator', 'resultVerifier']) {
      hooks[field] = Object.fromEntries(Object.entries(h.runtime[field]).map(([name, fn]) => [name, async (...args) => { try { return await fn(...args) } catch (error) { h.events.push({ field, code: error.code, error: error.message }); throw error } }]))
    }
    const originalInspect = hooks.cheapStateVerifier.inspect
    hooks.cheapStateVerifier = { inspect: input => { h.events.push('cheap'); return originalInspect(input) } }
    h.coordinator = new BlindOperationCoordinator({
      descriptorState: state,
      admission,
      budget: h.budget,
      ...hooks,
      readiness: { async evaluate () { const snapshot = state.requireCurrent(); return { kind: 1, endpoint: { endpointId: 1 }, descriptorSequence: snapshot.descriptorSequence, descriptorHash: snapshot.hash, transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP, readyRoleBits: 1, readyOperationBits: snapshot.descriptor.enabledOperationBits, effectiveEpochFloor: epoch, capacityBand: snapshot.descriptor.capacityBand } } },
      authenticatedSessionVerifier: { async verify () { throw new Error('no stream path is qualified') } }
    })
    h.descriptorState = state
  }
  await open()
  h.restart = async () => { await h.upstream.close(); await h.storage.close(); await open() }
  h.head = async () => ({ corePublicKey: Buffer.from(writer.key), fork: BigInt(writer.fork), length: BigInt(writer.length), signedHeadHash: headHash({ corePublicKey: writer.key, fork: writer.fork, length: writer.length, treeHash: await writer.treeHash() }) })
  h.dispatch = async (operationId, request, requestId = null) => {
    const now = process.hrtime.bigint() / 1000000n
    const result = await h.coordinator.dispatch({ frameKind: FRAME_KIND.REQUEST, familyId: FAMILY.CORE, operationId, requestId: requestId || Buffer.alloc(16, ++frameNumber), body: encodeCanonical(operationId === OPERATION.CORE.MIRROR ? coreMirrorRequestV1 : coreServeChallengeV1, request) }, { endpointId: 1, transportId: TRANSPORT_ID.HTTPS_DIRECT, transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP, outerClass: null, acceptedMonotonicMillis: now, absoluteDeadlineMonotonicMillis: now + 15000n })
    const frame = decodeDispatchFrame(result.dispatch, { copyBody: true })
    if (frame.frameKind === FRAME_KIND.ERROR) { const value = decodeCanonical(blindErrorV1, frame.body); const e = new Error('coordinator error ' + value.code + ' ' + JSON.stringify(h.events)); e.code = value.code; throw e }
    assert.equal(frame.frameKind, FRAME_KIND.RESPONSE)
    return { body: Buffer.from(frame.body), dispatch: Buffer.from(result.dispatch) }
  }
  h.mirror = async byte => { const request = { version: 1, ...await h.head(), leaseClass: 1, clientNonce: Buffer.alloc(32, byte), admission: admissionToken(byte) }; await h.dispatch(OPERATION.CORE.MIRROR, request); assert.ok(h.storage.inspectCore(writer.key)); return request }
  h.prove = (head, byte, charged = true) => ({ version: 1, corePublicKey: Buffer.from(head.corePublicKey), fork: head.fork, length: head.length, signedHeadHash: Buffer.from(head.signedHeadHash), blockIndices: head.length === 1n ? [0n] : [0n, head.length - 1n], clientNonce: Buffer.alloc(32, byte), admission: charged ? admissionToken(byte) : null })
  h.input = request => {
    const requestCommitment = coreServeRequestCommitment({ ...request, relayPublicKey: publicKey })
    return { profile: { familyId: FAMILY.CORE, operationId: OPERATION.CORE.PROVE }, request, requestCommitment, descriptorSnapshot: h.descriptorState.requireCurrent(), preparedAdmission: request.admission == null ? null : { spendTag: blake2b256(request.admission.token), requestCommitment, profileId: request.admission.profileId, schemeId: request.admission.schemeId, parameterHash: request.admission.parameterHash, costClass: { resourceClass: 1, leaseClass: 0, costUnits: 1n }, walCommitRecord: Buffer.from(request.admission.token) } }
  }
  h.stats = () => ({ connections, preparedCount, ...h.storage.status().accounting, walSequence: h.storage.transactionStore.walSequence, walHash: Buffer.from(h.storage.transactionStore.walHash) })
  h.advanceMillis = value => { millis += value }; h.loseOwner = () => { ownerLive = false }; h.advanceEpoch = value => { epoch += value }
  return h
}
