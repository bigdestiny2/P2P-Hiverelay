import fs from 'node:fs/promises'
import path from 'node:path'
import { Transform } from 'node:stream'
import Corestore from 'corestore'
import crypto from 'hypercore-crypto'
import {
  CoreUpstreamError, HEAD_BYTES, decodeContainer, decodeFrame, encodeContainer,
  encodeFrame, fail, headHash, indicesOf, limitsOf, matchHead, ownedBytes, requestHead
} from './format.js'
export { CoreUpstreamError, PROFILE_DIGEST, headHash, limitsOf } from './format.js'

export const STATUS = Object.freeze({ profile: 'private-hc11-upstream-v1', defaultSelected: false, productionReady: false, openReplication: false, clientVerificationComposed: false })
const abortError = () => new CoreUpstreamError('CORE_ABORTED', 'CORE operation cancelled or timed out')

class Scope {
  constructor (signal, timeout) {
    this.controller = new AbortController()
    this.resources = []; this.pending = []
    this.abort = () => this.controller.abort(abortError())
    this.external = signal
    signal?.addEventListener('abort', this.abort, { once: true })
    if (signal?.aborted) this.abort()
    this.timer = setTimeout(this.abort, timeout)
    this.aborted = new Promise((resolve, reject) => {
      if (this.signal.aborted) reject(this.signal.reason)
      else this.signal.addEventListener('abort', () => reject(this.signal.reason), { once: true })
    })
    this.aborted.catch(() => {})
    this.signal.addEventListener('abort', () => { for (const r of this.resources) r.stop() }, { once: true })
  }

  get signal () { return this.controller.signal }
  check () { if (this.signal.aborted) throw this.signal.reason }
  wait (promise) { return Promise.race([Promise.resolve(promise), this.aborted]) }
  own (stop, close) {
    const resource = { stop: () => { try { stop() } catch {} }, close }
    this.resources.push(resource)
    if (this.signal.aborted) resource.stop()
  }

  stream (stream) {
    if (!stream || typeof stream.destroy !== 'function' || typeof stream.pipe !== 'function' || typeof stream.once !== 'function') fail('CORE_INPUT', 'connector must return an owned duplex stream')
    let settle
    const closed = new Promise(resolve => { settle = resolve })
    stream.once('close', settle)
    stream.on('error', () => this.abort())
    if (stream.destroyed && stream.closed) settle()
    this.own(() => stream.destroy(), () => closed)
    return stream
  }

  // Pending connector acquisition stays charged even when cancellation wins.
  // Late returned resources are immediately destroyed and fully drained.
  acquire (promise, adopt) {
    const pending = Promise.resolve(promise).then(value => { adopt(value); return value })
    this.pending.push(pending.catch(() => {}))
    return this.wait(pending)
  }

  async finish () {
    await Promise.all(this.pending)
    for (const r of this.resources) r.stop()
    const settled = await Promise.allSettled(this.resources.map(r => Promise.resolve().then(r.close)))
    clearTimeout(this.timer)
    this.external?.removeEventListener('abort', this.abort)
    if (settled.some(r => r.status === 'rejected')) fail('CORE_RELEASE_FAILED', 'owned upstream cleanup failed; capacity remains fenced')
  }
}

export class RealCoreUpstreamV1 {
  constructor ({ root, connect, readCorpus, limits = {} } = {}) {
    if (typeof root !== 'string' || !path.isAbsolute(root) || path.normalize(root) !== root || root.includes('\0')) throw new TypeError('canonical absolute private scratch root required')
    if (typeof connect !== 'function' || typeof readCorpus !== 'function') throw new TypeError('owned source connector and persisted corpus reader required')
    this.root = root; this.connect = connect; this.readCorpus = readCorpus
    this.limits = limitsOf(limits); this.jobs = new Set(); this.closing = false
    this.opening = null
  }

  async ready () {
    if (!this.opening) {
      this.opening = (async () => {
        await fs.mkdir(this.root, { recursive: true, mode: 0o700 })
        const st = await fs.lstat(this.root)
        if (!st.isDirectory() || st.isSymbolicLink() || (st.mode & 0o077) !== 0 || await fs.realpath(this.root) !== this.root) fail('CORE_INPUT', 'private scratch root must be a real directory')
      })()
    }
    return this.opening
  }

  status () { return { ...STATUS, inFlight: this.jobs.size, reservedCorpusBytes: this.jobs.size * this.limits.maxCorpusBytes, closing: this.closing } }
  async close ({ timeoutMillis = 1000 } = {}) {
    if (!Number.isSafeInteger(timeoutMillis) || timeoutMillis < 1 || timeoutMillis > 60000) throw new TypeError('close deadline must be 1..60000 milliseconds')
    this.closing = true
    for (const job of this.jobs) job.scope.abort()
    let timer
    try { return await Promise.race([Promise.allSettled([...this.jobs].map(j => j.done)).then(() => this.jobs.size === 0), new Promise(resolve => { timer = setTimeout(() => resolve(false), timeoutMillis) })]) } finally { clearTimeout(timer) }
  }

  _run (operation, external, prepare = () => {}) {
    if (this.closing) return Promise.reject(new CoreUpstreamError('CORE_CLOSED', 'adapter closing'))
    if (external?.aborted) return Promise.reject(abortError())
    if (this.jobs.size >= this.limits.maxConcurrent) return Promise.reject(new CoreUpstreamError('CORE_BUSY', 'private upstream capacity exhausted'))
    const scope = new Scope(external, this.limits.timeoutMillis)
    const job = { scope, done: null }; this.jobs.add(job)
    let prepared; let prepareError
    try { prepared = prepare() } catch (e) { prepareError = e }
    job.done = (async () => {
      let result; let error
      try { if (prepareError) throw prepareError; await this.ready(); scope.check(); result = await operation(scope, prepared) } catch (e) { error = e }
      let released = true
      try { await scope.finish() } catch (e) { error ||= e; released = false; this.closing = true }
      if (released) this.jobs.delete(job)
      scope.check()
      if (error) throw error
      return result
    })()
    job.done.catch(() => {})
    return scope.wait(job.done)
  }

  async _store (scope) {
    scope.check()
    const root = await fs.mkdtemp(path.join(this.root, 'acquire-'))
    const store = new Corestore(root)
    let closing
    const close = () => { closing ||= store.close(); return closing }
    // Store removal only after its actual native handle closes.
    scope.own(() => { close().catch(() => {}) }, async () => { await close(); await fs.rm(root, { recursive: true, force: true }) })
    await scope.wait(store.ready()); scope.check()
    return store
  }

  async _verify (core, decoded, request, scope) {
    matchHead(decoded.head, request)
    const all = [decoded.headProof, ...decoded.proofs]
    for (const proof of all) {
      scope.check()
      if (proof.fork !== request.fork || proof.upgrade.length !== request.length) fail('CORE_HEAD_INVALID', 'proof requests another head')
      let batch
      try { batch = await scope.wait(core.verifyFullyRemote(proof)) } catch (e) {
        scope.check(); throw new CoreUpstreamError('CORE_HEAD_INVALID', 'upstream signature or Merkle proof invalid')
      }
      if (batch.fork !== request.fork || batch.length !== request.length || !Buffer.from(batch.hash()).equals(decoded.head.treeHash)) fail('CORE_HEAD_INVALID', 'authenticated upstream head differs')
    }
  }

  async _decodeVerified (bytes, request, scope, bundle = false) {
    const decoded = decodeContainer(bytes, this.limits, bundle)
    const store = await this._store(scope)
    const verifier = store.get({ key: request.corePublicKey, writable: false })
    await scope.wait(verifier.ready())
    await this._verify(verifier, decoded, request, scope)
    return decoded
  }

  activateMirror ({ request, previousGeneration = null, signal } = {}) {
    // Defensive owned copies are made before any yield/connector call.
    const wanted = requestHead(request, this.limits)
    const previous = previousGeneration == null ? null : requestHead(previousGeneration, this.limits)
    if (previous && !previous.corePublicKey.equals(wanted.corePublicKey)) fail('CORE_INPUT', 'previous floor key differs')
    if (previous && (wanted.fork < previous.fork || (wanted.fork === previous.fork && wanted.length < previous.length))) fail('CORE_HEAD_INVALID', 'candidate is below previous floor')
    return this._run(async scope => {
      try {
        const store = await this._store(scope)
        const core = store.get({ key: wanted.corePublicKey, writable: false })
        await scope.wait(core.ready()); scope.check()
        const remote = await scope.acquire(this.connect({ corePublicKey: Buffer.from(wanted.corePublicKey), signal: scope.signal, maxWireBytes: this.limits.maxWireBytes }), stream => scope.stream(stream))
        scope.check()
        const local = scope.stream(core.replicate(true))
        let wireBytes = 0
        const meter = () => scope.stream(new Transform({
          transform: (chunk, encoding, done) => {
            wireBytes += chunk.length
            if (wireBytes > this.limits.maxWireBytes) { scope.abort(); done(abortError()); return }
            done(null, chunk)
          }
        }))
        local.pipe(meter()).pipe(remote).pipe(meter()).pipe(local)
        const range = core.download({ start: 0, end: wanted.length, linear: true })
        scope.own(() => range.destroy(), async () => { await range.done().catch(() => {}) })
        if (await scope.wait(range.done()) !== true) throw abortError()
        scope.check()
        if (core.fork !== wanted.fork || core.length !== wanted.length) fail('CORE_HEAD_INVALID', 'live source is not exact requested head')
        if (!await scope.wait(core.has(0, wanted.length))) fail('CORE_UNAVAILABLE', 'full sponsored range is not local')
        const snapshot = core.snapshot(); await scope.wait(snapshot.ready())
        const headFrame = encodeFrame(snapshot, await scope.wait(snapshot.proof({ upgrade: { start: 0, length: wanted.length } })), this.limits, true)
        const headProof = decodeFrame(headFrame, this.limits, true)
        const batch = await scope.wait(snapshot.verifyFullyRemote(headProof))
        const head = { corePublicKey: wanted.corePublicKey, fork: batch.fork, length: batch.length, treeHash: Buffer.from(batch.hash()) }
        matchHead(head, wanted)
        if (previous && previous.fork === head.fork) {
          const treeHash = Buffer.from(await scope.wait(snapshot.treeHash(previous.length)))
          if (!headHash({ corePublicKey: head.corePublicKey, fork: previous.fork, length: previous.length, treeHash }).equals(previous.signedHeadHash)) fail('CORE_HEAD_INVALID', 'same-fork candidate does not extend previous head')
        }
        const frames = []; let size = 8 + 32 + HEAD_BYTES + 4 + headFrame.length + 4
        for (let index = 0; index < wanted.length; index++) {
          scope.check()
          const value = await scope.wait(snapshot.get(index, { raw: true, wait: false }))
          if (value === null) fail('CORE_UNAVAILABLE', 'sponsored block is absent locally')
          if (value.length > this.limits.maxBlockBytes) fail('CORE_TOO_LARGE', 'ciphertext block exceeds private bound')
          const frame = encodeFrame(snapshot, await scope.wait(snapshot.proof({ block: { index }, upgrade: { start: 0, length: wanted.length } })), this.limits)
          size += 4 + frame.length
          if (size > this.limits.maxCorpusBytes) fail('CORE_TOO_LARGE', 'proof corpus exceeds private bound')
          frames.push(frame)
        }
        const corpus = encodeContainer(head, headFrame, frames, this.limits)
        await this._verify(snapshot, decodeContainer(corpus, this.limits), wanted, scope)
        return Object.freeze({ verified: true, corpus, corpusByteLength: corpus.length, corpusHash: crypto.hash(corpus) })
      } catch (e) {
        scope.check()
        if (e.code === 'CORE_HEAD_INVALID' || e.code === 'CORE_FORMAT' || e.code === 'CORE_TOO_LARGE') return Object.freeze({ verified: false })
        throw e
      }
    }, signal)
  }

  estimateProofBytes ({ request, signal } = {}) {
    const wanted = requestHead(request, this.limits); const indices = indicesOf(request.blockIndices, wanted)
    // Reader must enforce its storage/namespace/owner authority before returning
    // bounded bytes. It cannot certify cryptography: we verify those bytes here.
    return this._run(async scope => {
      const corpus = ownedBytes(await scope.acquire(this.readCorpus({ request: { ...wanted, corePublicKey: Buffer.from(wanted.corePublicKey), signedHeadHash: Buffer.from(wanted.signedHeadHash), blockIndices: [...indices] }, maxBytes: this.limits.maxCorpusBytes, signal: scope.signal }), () => {}), this.limits.maxCorpusBytes, 'persisted corpus')
      const decoded = await this._decodeVerified(corpus, wanted, scope)
      return encodeContainer(decoded.head, decoded.headFrame, indices.map(i => decoded.frames[i]), this.limits, true).length
    }, signal)
  }

  serveProof ({ generation, blockIndices, corpus, signal } = {}) {
    const wanted = requestHead(generation, this.limits); const indices = indicesOf(blockIndices, wanted)
    return this._run(async (scope, bytes) => {
      const decoded = await this._decodeVerified(bytes, wanted, scope)
      return encodeContainer(decoded.head, decoded.headFrame, indices.map(i => decoded.frames[i]), this.limits, true)
    }, signal, () => ownedBytes(corpus, this.limits.maxCorpusBytes, 'persisted corpus'))
  }

  verifyProofBundle ({ request, proof, signal } = {}) {
    const wanted = requestHead(request, this.limits); const indices = indicesOf(request.blockIndices, wanted)
    return this._run(async (scope, bytes) => {
      const decoded = await this._decodeVerified(bytes, wanted, scope, true)
      if (decoded.proofs.length !== indices.length || decoded.proofs.some((p, i) => p.block.index !== indices[i])) fail('CORE_HEAD_INVALID', 'proof does not answer exact sample')
      return true
    }, signal, () => ownedBytes(proof, this.limits.maxProofBytes, 'proof bundle'))
  }
}
