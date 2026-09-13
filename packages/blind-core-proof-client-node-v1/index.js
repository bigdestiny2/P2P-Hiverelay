import { performance } from 'node:perf_hooks'
import { RealCoreUpstreamV1 } from '../blind-core-upstream-hc11-v1/index.js'
import { PROFILE_DIGEST, ownedBytes, requestHead, indicesOf } from '../blind-core-upstream-hc11-v1/format.js'
import { FAMILY, OPERATION, assertAdvertisedOperation } from '../blind-protocol/wire-runtime-authority.js'
import { coreServeChallengeV1, coreServeResultV1 } from '../blind-protocol/schemas.js'
import { decodeCanonical, encodeCanonical } from '../blind-protocol/codec.js'
import { coreServeRequestCommitment } from '../blind-protocol/hashes.js'
import { verifiedEndpointContext } from '../blind-client/verified-endpoint.js'
import { verifyOperationResult } from '../blind-client/results.js'

const profile = assertAdvertisedOperation(FAMILY.CORE, OPERATION.CORE.PROVE)
const same = (left, right) => Buffer.from(left).equals(Buffer.from(right))
const failure = (code, message) => Object.assign(new Error(message), { code })
const aborted = () => failure('CORE_CLIENT_ABORTED', 'Private CORE proof request cancelled or timed out')
const unavailable = () => { throw failure('CORE_CLIENT_INPUT', 'Proof verification cannot acquire a source or read a relay corpus') }

function deadline (value) {
  if (!Number.isSafeInteger(value) || value < 10 || value > 60000) throw failure('CORE_CLIENT_INPUT', 'timeoutMillis must be 10..60000')
  return value
}

function contextIdentity (endpoint) {
  const context = verifiedEndpointContext(endpoint)
  if (context.familyId !== FAMILY.CORE || context.operationId !== OPERATION.CORE.PROVE) {
    throw failure('CORE_CLIENT_INPUT', 'A qualified CORE.PROVE endpoint is required')
  }
  // Every qualified namespace/durability/destination field is included, not only
  // the relay signing key. Never retain mutable caller-owned context arrays.
  return JSON.stringify(Object.entries(context).map(([key, value]) => [key,
    value instanceof Uint8Array
      ? { bytes: Buffer.from(value).toString('hex') }
      : typeof value === 'bigint' ? { integer: String(value) } : value]))
}

function snapshot (options) {
  if (!options || typeof options !== 'object' || 'coreProofVerifier' in options || 'verifier' in options) {
    throw failure('CORE_CLIENT_INPUT', 'Canonical request options required; caller proof verdicts are forbidden')
  }
  const endpoint = options.endpoint
  const identity = contextIdentity(endpoint)
  const requestBytes = ownedBytes(options.requestBytes, profile.maxRequestBodyBytes, 'canonical CORE request')
  const request = decodeCanonical(coreServeChallengeV1, requestBytes, { copyBytes: true })
  const commitment = ownedBytes(options.requestCommitment, 32, 'request commitment', 32)
  const relayPublicKey = verifiedEndpointContext(endpoint).relayPublicKey
  if (!same(commitment, coreServeRequestCommitment({ ...request, relayPublicKey }))) {
    throw failure('CORE_CLIENT_INPUT', 'Canonical request does not reproduce its commitment')
  }
  return { endpoint, identity, requestBytes, request, commitment, externalWitnessVerifier: options.externalWitnessVerifier }
}

export const STATUS = Object.freeze({
  profile: 'private-node-core-proof-client-v1',
  privateUpstreamProfile: PROFILE_DIGEST.toString('hex'),
  defaultSelected: false,
  productionReady: false,
  durableAttemptComposed: false,
  browserQualified: false,
  bareQualified: false,
  pear34Qualified: false
})

export class NodeCoreProofClientV1 {
  #upstream
  #transport
  #timeout
  #job = null
  #closing = false

  constructor (options = {}) {
    if ('verifier' in options || 'coreProofVerifier' in options || 'upstream' in options ||
        !same(ownedBytes(options.profileDigest, 32, 'explicit private profile digest', 32), PROFILE_DIGEST)) {
      throw failure('CORE_CLIENT_INPUT', 'Explicit accepted private HC11 profile required; no injected verifier')
    }
    if (options.transport != null && typeof options.transport.request !== 'function') throw failure('CORE_CLIENT_INPUT', 'transport.request must be a function')
    this.#transport = options.transport == null ? null : options.transport.request.bind(options.transport)
    this.#timeout = deadline(options.timeoutMillis ?? 10000)
    this.#upstream = new RealCoreUpstreamV1({ root: options.root, connect: unavailable, readCorpus: unavailable, limits: { ...options.limits, maxConcurrent: 1, timeoutMillis: this.#timeout } })
  }

  status () {
    const native = this.#upstream.status()
    return Object.freeze({
      ...STATUS,
      inFlight: this.#job || native.inFlight ? 1 : 0,
      nativeInFlight: native.inFlight,
      closing: this.#closing || native.closing,
      stage: this.#job?.stage ?? (native.inFlight ? 'native-cleanup' : 'idle')
    })
  }

  async prove (options) { return this.#run(options, true) }
  async verifyResult (options) { return this.#run(options, false) }

  #run (options, send) {
    const native = this.#upstream.status()
    if (this.#closing || native.closing) throw failure('CORE_CLIENT_CLOSED', 'Private proof client is fenced or closing')
    // One slot includes late transport and native cleanup. An aborted verifier
    // promise may settle before native resources; native.inFlight still charges it.
    if (this.#job || native.inFlight) throw failure('CORE_CLIENT_BUSY', 'Private proof client capacity is retained')
    if (send && !this.#transport) throw failure('CORE_CLIENT_INPUT', 'prove requires a transport')
    const signal = options?.signal
    if (signal != null && !(signal instanceof AbortSignal)) throw failure('CORE_CLIENT_INPUT', 'signal must be an AbortSignal')
    if (signal?.aborted) throw aborted()
    const timeoutMillis = deadline(options?.timeoutMillis ?? this.#timeout)
    const expiresAt = performance.now() + timeoutMillis
    const prepared = snapshot(options)
    indicesOf(prepared.request.blockIndices, requestHead(prepared.request, this.#upstream.limits))
    const supplied = send ? null : ownedBytes(options.resultBytes, profile.maxResultBodyBytes, 'canonical CORE result')
    const controller = new AbortController()
    const abort = () => controller.abort(aborted())
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) abort()
    const check = () => {
      if (performance.now() >= expiresAt) abort()
      if (controller.signal.aborted) throw aborted()
    }
    const cancellation = new Promise((resolve, reject) => controller.signal.addEventListener('abort', () => reject(aborted()), { once: true }))
    cancellation.catch(() => {})
    const timer = setTimeout(abort, Math.max(0, expiresAt - performance.now()))
    const job = { stage: send ? 'transport' : 'verification', controller, done: null }
    this.#job = job
    job.done = (async () => {
      try {
        check()
        let bytes = supplied
        if (send) {
          // Retain admission while an uncooperative transport is unresolved.
          const response = await this.#transport({
            endpoint: prepared.endpoint,
            familyId: FAMILY.CORE,
            operationId: OPERATION.CORE.PROVE,
            expectedResultBodyBytes: profile.maxResultBodyBytes,
            body: Buffer.from(prepared.requestBytes),
            signal: controller.signal,
            timeoutMillis
          })
          check()
          if (!response || response.ok !== true) throw failure('CORE_CLIENT_REMOTE', 'Relay did not return a successful CORE proof response')
          bytes = ownedBytes(response.body, profile.maxResultBodyBytes, 'canonical CORE result')
        }
        if (contextIdentity(prepared.endpoint) !== prepared.identity) throw failure('CORE_CLIENT_INPUT', 'Qualified endpoint changed during request')
        const decoded = decodeCanonical(coreServeResultV1, bytes, { copyBytes: true })
        job.stage = 'verification'
        const verified = await this.#upstream.verifyProofBundle({ request: prepared.request, proof: decoded.proofsAndBlocks, signal: controller.signal })
        check()
        if (verified !== true) throw failure('CORE_CLIENT_PROOF', 'Actual HC11 verification did not return strict true')
        let consumed = false
        const verifiedResult = verifyOperationResult({
          endpoint: prepared.endpoint,
          request: prepared.request,
          requestCommitment: prepared.commitment,
          resultBytes: bytes,
          externalWitnessVerifier: prepared.externalWitnessVerifier,
          coreProofVerifier: ({ request, acknowledgement, proofsAndBlocks }) => {
            if (consumed) return false
            consumed = true
            // This closure is local to one awaited native proof, never returned,
            // caller supplied, cached or reused. Full canonical admission and
            // result bytes plus the exact endpoint namespace must still match.
            return verified === true && !controller.signal.aborted &&
              contextIdentity(prepared.endpoint) === prepared.identity &&
              same(encodeCanonical(coreServeChallengeV1, request), prepared.requestBytes) &&
              same(encodeCanonical(coreServeResultV1, { version: 1, acknowledgement, proofsAndBlocks }), bytes)
          }
        })
        check()
        return verifiedResult
      } finally {
        clearTimeout(timer)
        signal?.removeEventListener('abort', abort)
        this.#job = null
      }
    })()
    job.done.catch(() => {})
    return Promise.race([job.done, cancellation])
  }

  async close ({ timeoutMillis = 1000 } = {}) {
    deadline(timeoutMillis)
    this.#closing = true
    const job = this.#job
    job?.controller.abort(aborted())
    const native = this.#upstream.close({ timeoutMillis })
    let timer
    try {
      return await Promise.race([
        Promise.all([job?.done.catch(() => {}), native]).then(([, closed]) => closed === true && this.#job === null && this.#upstream.status().inFlight === 0),
        new Promise(resolve => { timer = setTimeout(() => resolve(false), timeoutMillis) })
      ])
    } finally { clearTimeout(timer) }
  }
}
