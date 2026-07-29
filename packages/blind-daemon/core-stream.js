import b4a from 'b4a'
import {
  BlindProtocolError,
  CORE_SESSION_CLASS,
  FAMILY,
  TRANSPORT_ID,
  blake2b256,
  coreOpenReplicationRequestCommitment,
  coreOpenReplicationResultV1,
  coreOpenReplicationV1,
  decodeCanonical,
  encodeCanonical
} from '@hiverelay/blind-protocol'

const MAX_U64 = (1n << 64n) - 1n
const MAX_U32 = 0xffffffff
const CORE_RETRY_DOMAIN = b4a.from('hiverelay.blind.core-open-retry.v1', 'ascii')

function fail (code, message) {
  throw new BlindProtocolError(code, message)
}

function asBytes (value, field, minimum = 1, maximum = 256) {
  if (typeof value === 'string') value = b4a.from(value, 'utf8')
  if (!value || typeof value.byteLength !== 'number') fail('BAD_ENCODING', `${field} must be bytes or a string`)
  const output = b4a.isBuffer(value)
    ? value
    : ArrayBuffer.isView(value)
      ? b4a.from(value.buffer, value.byteOffset, value.byteLength)
      : b4a.from(value)
  if (output.byteLength < minimum || output.byteLength > maximum) {
    fail('BAD_ENCODING', `${field} must be ${minimum}..${maximum} bytes`)
  }
  return output
}

function fixed32 (value, field) {
  return asBytes(value, field, 32, 32)
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_ENCODING', `${field} is outside u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail('BAD_ENCODING', `${field} is outside u64`)
  return value
}

function u32 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_U32) fail('BAD_ENCODING', `${field} is outside u32`)
  return value
}

function sameBytes (left, right) {
  return left.byteLength === right.byteLength && b4a.equals(left, right)
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function byteKey (value) {
  return b4a.toString(value, 'hex')
}

function parentKey (value) {
  return byteKey(asBytes(value, 'parentSessionId'))
}

function normalizeRequest (value) {
  if (value && typeof value.byteLength === 'number') return decodeCanonical(coreOpenReplicationV1, value)
  return decodeCanonical(coreOpenReplicationV1, encodeCanonical(coreOpenReplicationV1, value))
}

export function coreOpenReplicationLogicalRetryKey (relayPublicKey, request) {
  return blake2b256(b4a.concat([
    CORE_RETRY_DOMAIN,
    relayPublicKey,
    request.wireProfileHash,
    b4a.from([request.sessionClass]),
    request.clientNonce
  ]))
}

function validatePort (value, field, writeRequired = true) {
  if (!value || typeof value !== 'object') throw new TypeError(`${field} must be an injected stream port`)
  if (writeRequired && typeof value.write !== 'function') throw new TypeError(`${field}.write must be a function`)
  for (const method of ['end', 'abort', 'close']) {
    if (value[method] != null && typeof value[method] !== 'function') throw new TypeError(`${field}.${method} must be a function`)
  }
  return value
}

function deferred () {
  let resolve
  let reject
  const promise = new Promise((_resolve, _reject) => {
    resolve = _resolve
    reject = _reject
  })
  // Exact retries observe this promise. The originating OPEN still reports its
  // own exception, so retain a rejection handler when no retry is waiting.
  promise.catch(() => {})
  return { promise, resolve, reject }
}

function raceAbort (operation, signal) {
  if (signal.aborted) fail('RETRY_TERMINAL', 'stream is terminal')
  let onAbort
  const aborted = new Promise((resolve, reject) => {
    onAbort = () => reject(new BlindProtocolError('RETRY_TERMINAL', 'stream became terminal'))
    signal.addEventListener('abort', onAbort, { once: true })
  })
  return Promise.race([Promise.resolve(operation), aborted]).finally(() => {
    signal.removeEventListener('abort', onAbort)
  })
}

function opaqueCopy (value, maximum) {
  if (typeof value === 'string') fail('BAD_ENCODING', 'CORE child chunks must be bytes')
  const input = asBytes(value, 'opaque upstream bytes', 1, Number.MAX_SAFE_INTEGER)
  if (input.byteLength > maximum) fail('TOO_LARGE', 'CORE child chunk exceeds the bounded buffer window')
  return b4a.from(input)
}

class CoreChildStream {
  constructor (record, upstream) {
    this.record = record
    this.scope = record.scope
    this.upstream = validatePort(upstream, 'upstream')
    this.caller = null
    this.attached = false
    this.callerEnded = false
    this.upstreamEnded = false
    this.callerFinQueued = false
    this.upstreamFinQueued = false
    this.queues = { caller: Promise.resolve(), upstream: Promise.resolve() }
    this.teardownPromise = null
  }

  attach (caller) {
    this.scope.assertActive()
    if (this.attached) fail('RETRY_TERMINAL', 'CORE child stream is already attached')
    this.caller = validatePort(caller, 'caller')
    this.attached = true
    return this
  }

  _enqueue (direction, operation) {
    const previous = this.queues[direction]
    const next = previous.then(operation, operation)
    this.queues[direction] = next.catch(() => {})
    return next
  }

  fromCaller (value) {
    let chunk
    let release
    try {
      if (!this.attached || this.callerEnded || this.callerFinQueued) {
        fail('RETRY_TERMINAL', 'CORE caller send side is closed')
      }
      chunk = opaqueCopy(value, this.scope.maxBufferedBytes)
      this.scope.countBytes(chunk.byteLength)
      release = this.scope.reserveBuffer(chunk.byteLength)
    } catch (error) {
      this.scope.close('chunk-invalid').catch(() => {})
      return Promise.reject(error)
    }
    return this._enqueue('caller', async () => {
      try {
        if (!this.attached || this.callerEnded) fail('RETRY_TERMINAL', 'CORE caller send side is closed')
        await raceAbort(this.upstream.write(chunk, { signal: this.scope.signal }), this.scope.signal)
      } catch (error) {
        await this.scope.close('upstream-write-failed')
        throw error
      } finally {
        release()
      }
    })
  }

  fromUpstream (value) {
    let chunk
    let release
    try {
      if (!this.attached || this.upstreamEnded || this.upstreamFinQueued) {
        this.scope.close('upstream-before-attach').catch(() => {})
        fail('RETRY_TERMINAL', 'CORE upstream produced bytes without a live caller')
      }
      chunk = opaqueCopy(value, this.scope.maxBufferedBytes)
      this.scope.countBytes(chunk.byteLength)
      release = this.scope.reserveBuffer(chunk.byteLength)
    } catch (error) {
      this.scope.close('chunk-invalid').catch(() => {})
      return Promise.reject(error)
    }
    return this._enqueue('upstream', async () => {
      try {
        if (!this.attached || this.upstreamEnded) {
          await this.scope.close('upstream-before-attach')
          fail('RETRY_TERMINAL', 'CORE upstream produced bytes without a live caller')
        }
        await raceAbort(this.caller.write(chunk, { signal: this.scope.signal }), this.scope.signal)
      } catch (error) {
        await this.scope.close('caller-write-failed')
        throw error
      } finally {
        release()
      }
    })
  }

  callerFin () {
    try {
      this.scope.assertActive()
      if (!this.attached || this.callerEnded || this.callerFinQueued) {
        fail('RETRY_TERMINAL', 'CORE caller send side is already closed')
      }
      this.callerFinQueued = true
    } catch (error) {
      return Promise.reject(error)
    }
    return this._enqueue('caller', async () => {
      try {
        this.scope.assertActive()
        this.callerEnded = true
        if (typeof this.upstream.end === 'function') {
          await raceAbort(this.upstream.end({ signal: this.scope.signal }), this.scope.signal)
        }
        if (this.upstreamEnded) await this.scope.close('clean-fin')
      } catch (error) {
        await this.scope.close('upstream-fin-failed')
        throw error
      }
    })
  }

  upstreamFin () {
    try {
      this.scope.assertActive()
      if (!this.attached || this.upstreamEnded || this.upstreamFinQueued) {
        fail('RETRY_TERMINAL', 'CORE upstream send side is already closed')
      }
      this.upstreamFinQueued = true
    } catch (error) {
      return Promise.reject(error)
    }
    return this._enqueue('upstream', async () => {
      try {
        this.scope.assertActive()
        this.upstreamEnded = true
        if (typeof this.caller.end === 'function') {
          await raceAbort(this.caller.end({ signal: this.scope.signal }), this.scope.signal)
        }
        if (this.callerEnded) await this.scope.close('clean-fin')
      } catch (error) {
        await this.scope.close('caller-fin-failed')
        throw error
      }
    })
  }

  close (reason = 'core-abort') {
    return this.scope.close(reason)
  }

  async _teardown (reason) {
    if (this.teardownPromise) return this.teardownPromise
    const settling = Promise.allSettled([
      this._closePort(this.upstream, reason),
      this._closePort(this.caller, reason)
    ])
    let timer
    const bounded = new Promise(resolve => {
      timer = setTimeout(resolve, this.record.teardownTimeoutMillis)
      if (timer.unref) timer.unref()
    })
    this.teardownPromise = Promise.race([settling, bounded]).finally(() => clearTimeout(timer))
    await this.teardownPromise
  }

  async _closePort (port, reason) {
    if (!port) return
    if (typeof port.abort === 'function') return port.abort(reason)
    if (typeof port.close === 'function') return port.close(reason)
  }
}

export class CoreReplicationStreamService {
  constructor (options = {}) {
    if (!options.plane || typeof options.plane.createSession !== 'function' ||
        typeof options.plane.issueTicket !== 'function' || typeof options.plane.consumeTicket !== 'function') {
      throw new TypeError('a StreamSessionPlane is required')
    }
    this.plane = options.plane
    this.relayPublicKey = b4a.from(fixed32(options.relayPublicKey, 'relayPublicKey'))
    this.wireProfileHash = b4a.from(fixed32(options.wireProfileHash, 'wireProfileHash'))
    if (isZero(this.relayPublicKey) || isZero(this.wireProfileHash)) {
      throw new TypeError('relayPublicKey and wireProfileHash must be nonzero')
    }
    this.authenticateParent = options.authenticateParent
    this.authorizeAdmission = options.authorizeAdmission
    this.allocateStreamId = options.allocateStreamId
    this.buildResult = options.buildResult
    this.openUpstream = options.openUpstream
    this.persistence = options.persistence
    this.nowEpoch = options.nowEpoch
    this.onPersistenceError = typeof options.onPersistenceError === 'function'
      ? options.onPersistenceError
      : () => {}
    this.teardownTimeoutMillis = Number.isSafeInteger(options.teardownTimeoutMillis) &&
      options.teardownTimeoutMillis > 0 && options.teardownTimeoutMillis <= 30000
      ? options.teardownTimeoutMillis
      : 5000
    this.persistenceFailure = null
    for (const [name, hook] of [
      ['authenticateParent', this.authenticateParent],
      ['authorizeAdmission', this.authorizeAdmission],
      ['allocateStreamId', this.allocateStreamId],
      ['buildResult', this.buildResult],
      ['openUpstream', this.openUpstream],
      ['nowEpoch', this.nowEpoch]
    ]) {
      if (typeof hook !== 'function') throw new TypeError(`${name} hook is required`)
    }
    if (!this.persistence || typeof this.persistence.reserve !== 'function' ||
        typeof this.persistence.activate !== 'function' || typeof this.persistence.terminal !== 'function') {
      throw new TypeError('persistence reserve/activate/terminal hooks are required')
    }
    this.maxRecords = Number.isSafeInteger(options.maxRecords) && options.maxRecords > 0 ? options.maxRecords : 4096
    this.recordsByLogical = new Map()
    this.recordsBySpend = new Map()
    this.controlChannels = new Map()
    this.recordsByScope = new Map()
    if (options.recoveredRecords != null) this._restoreRecoveredRecords(options.recoveredRecords)
  }

  async open (rawRequest, context = {}) {
    if (this.persistenceFailure) fail('BUSY', 'CORE stream persistence requires recovery')
    const request = normalizeRequest(rawRequest)
    if (!sameBytes(request.wireProfileHash, this.wireProfileHash)) {
      fail('CONFLICT', 'CORE wire profile does not match the signed descriptor')
    }
    if (context.transportId !== TRANSPORT_ID.DIRECT_PROTOMUX_NOISE &&
        context.transportId !== TRANSPORT_ID.TOR_V3_ONION) {
      fail('TRANSPORT_UNSUPPORTED', 'CORE replication requires a native authenticated stream transport')
    }

    const auth = await this.authenticateParent({ request, context })
    if (!auth || auth.verified !== true || auth.authenticatedExporter !== true) {
      fail('TRANSPORT_UNSUPPORTED', 'authenticated parent exporter is unavailable')
    }
    const computedBinding = fixed32(auth.computedParentChannelBinding, 'computedParentChannelBinding')
    if (!sameBytes(computedBinding, request.parentChannelBinding) ||
        u64(auth.controlChannelId, 'authenticated controlChannelId') !== request.controlChannelId) {
      fail('BAD_ENCODING', 'CORE parent channel binding does not match the authenticated channel')
    }
    const parentSessionId = asBytes(auth.parentSessionId, 'parentSessionId')
    if (isZero(parentSessionId)) fail('BAD_ENCODING', 'authenticated parentSessionId must be nonzero')
    const parent = parentKey(parentSessionId)
    const readiness = auth.readiness
    const commitment = coreOpenReplicationRequestCommitment({
      relayPublicKey: this.relayPublicKey,
      wireProfileHash: request.wireProfileHash,
      sessionClass: request.sessionClass,
      controlChannelId: request.controlChannelId,
      parentChannelBinding: request.parentChannelBinding,
      clientNonce: request.clientNonce
    })
    const logical = coreOpenReplicationLogicalRetryKey(this.relayPublicKey, request)
    const logicalKey = byteKey(logical)

    let existing = this.recordsByLogical.get(logicalKey)
    if (existing) return this._retry(existing, request, commitment, parent)

    const channelKey = `${parent}:${request.controlChannelId}`
    if (this.controlChannels.has(channelKey)) {
      fail('BAD_ENCODING', 'controlChannelId was already used in this authenticated session')
    }

    const admission = await this.authorizeAdmission({
      operation: 'core-open-replication',
      admission: request.admission,
      sessionClass: request.sessionClass,
      requestCommitment: b4a.from(commitment),
      signal: context.signal
    })
    if (!admission || admission.accepted !== true) fail('SPEND_INVALID', 'CORE admission was not accepted')
    const spendTag = asBytes(admission.spendTag, 'spendTag', 1, 128)
    if (isZero(spendTag)) fail('SPEND_INVALID', 'CORE admission spend tag must be nonzero')
    const spendKey = byteKey(spendTag)

    // Admission may yield. Recheck both indexes before creating any durable or
    // upstream state.
    existing = this.recordsByLogical.get(logicalKey)
    if (existing) return this._retry(existing, request, commitment, parent)
    if (this.recordsBySpend.has(spendKey)) fail('SPEND_REPLAY', 'CORE admission spend tag was already used')
    if (this.recordsByLogical.size >= this.maxRecords) fail('BUSY', 'CORE retry record capacity is exhausted')

    const streamId = u64(await this.allocateStreamId({ family: FAMILY.CORE, request, context }), 'streamId')
    if (streamId === 0n) fail('INTERNAL', 'CORE stream allocator returned zero')
    const limits = CORE_SESSION_CLASS[request.sessionClass]
    const openedAtEpoch = u32(await this.nowEpoch(), 'openedAtEpoch')
    const wait = deferred()
    const record = {
      family: FAMILY.CORE,
      logicalKey,
      logicalRetryKey: b4a.from(logical),
      spendKey,
      spendTag: b4a.from(spendTag),
      channelKey,
      parent,
      parentSessionId: b4a.from(parentSessionId),
      request,
      requestCommitment: b4a.from(commitment),
      streamId,
      limits,
      openedAtEpoch,
      status: 'reserving',
      result: null,
      scope: null,
      child: null,
      ticket: null,
      ticketIssuedMonotonicMillis: null,
      preparedAdmission: admission.preparedAdmission || admission,
      teardownTimeoutMillis: this.teardownTimeoutMillis,
      wait
    }
    this.recordsByLogical.set(logicalKey, record)
    this.recordsBySpend.set(spendKey, record)
    this.controlChannels.set(channelKey, record)

    try {
      record.scope = this.plane.createSession({
        family: FAMILY.CORE,
        streamId,
        maxBytes: BigInt(limits.maxSessionBytes),
        maxBufferedBytes: Math.min(this.plane.maxPerStreamBufferedBytes, 1024 * 1024 + 65535),
        idleMillis: limits.idleMillis,
        lifetimeMillis: limits.lifetimeMillis,
        readiness,
        metadata: { operation: 'CORE.OPEN_REPLICATION', logicalKey },
        onClose: reason => this._onScopeClose(record, reason)
      })
      this.recordsByScope.set(record.scope.key, record)
      record.result = await this._buildAndValidateResult(record)
      await this.persistence.reserve(this._persistentRecord(record, 'RESERVED'))
      record.status = 'reserved'

      const upstream = await this.openUpstream({
        wireProfileHash: b4a.from(this.wireProfileHash),
        sessionClass: request.sessionClass,
        streamId,
        signal: record.scope.signal
      })
      record.scope.assertActive()
      record.child = new CoreChildStream(record, upstream)
      await this.persistence.activate(this._persistentRecord(record, 'LIVE'))
      record.status = 'live'
      record.ticket = this.plane.issueTicket(record.scope, record.parentSessionId)
      record.ticketIssuedMonotonicMillis = this.plane.now()
      const response = this._response(record, false)
      wait.resolve(response)
      return response
    } catch (error) {
      record.status = 'terminal'
      record.terminalReason = error && error.code ? error.code : 'open-failed'
      if (record.scope) await record.scope.close('core-open-failed')
      else await this._persistTerminal(record, 'core-open-failed')
      const terminal = error instanceof BlindProtocolError
        ? error
        : new BlindProtocolError('INTERNAL', 'CORE upstream allocation failed terminally')
      wait.reject(terminal)
      throw terminal
    }
  }

  async _retry (record, request, commitment, parent) {
    const sameLogicalChannel = record.parent === parent &&
      record.request.controlChannelId === request.controlChannelId &&
      sameBytes(record.request.parentChannelBinding, request.parentChannelBinding)
    if (!sameLogicalChannel) {
      fail('RETRY_TERMINAL', 'CORE logical retry moved to another authenticated channel')
    }
    if (!sameBytes(record.requestCommitment, commitment)) {
      fail('SPEND_REPLAY', 'CORE retry changed its committed fields')
    }
    if (record.status === 'reserving' || record.status === 'reserved') return record.wait.promise
    if (record.status !== 'live' || !record.scope || !record.scope.poll()) {
      fail('RETRY_TERMINAL', 'CORE child stream is no longer live')
    }
    return this._response(record, true)
  }

  _response (record, retried) {
    if (!record.child.attached) {
      const now = this.plane.now()
      const ticketExpired = record.ticket == null || record.ticketIssuedMonotonicMillis == null ||
        now - record.ticketIssuedMonotonicMillis >= BigInt(this.plane.tickets.ttlMillis)
      if (ticketExpired) {
        this.plane.tickets.revokeScope(record.scope.key)
        record.ticket = this.plane.issueTicket(record.scope, record.parentSessionId)
        record.ticketIssuedMonotonicMillis = now
      }
    }
    return {
      result: record.result,
      ticket: record.child.attached ? null : b4a.from(record.ticket),
      attached: record.child.attached,
      retried
    }
  }

  attach (ticket, input) {
    if (!input || typeof input !== 'object') throw new TypeError('CORE attachment input is required')
    const parentSessionId = asBytes(input.parentSessionId, 'parentSessionId')
    const expected = {
      family: FAMILY.CORE,
      streamId: input.streamId,
      descriptorSequence: input.descriptorSequence,
      descriptorHash: input.descriptorHash,
      parentSessionId
    }
    const scope = this.plane.consumeTicket(ticket, expected)
    const record = this.recordsByScope.get(scope.key)
    if (!record || record.status !== 'live' || record.parent !== parentKey(parentSessionId)) {
      fail('RETRY_TERMINAL', 'CORE ticket has no matching live open record')
    }
    record.child.attach(input.caller)
    record.ticket = null
    record.ticketIssuedMonotonicMillis = null
    return record.child
  }

  async _buildAndValidateResult (record) {
    const result = await this.buildResult({
      request: record.request,
      relayPublicKey: b4a.from(this.relayPublicKey),
      streamId: record.streamId,
      maxSessionBytes: BigInt(record.limits.maxSessionBytes),
      idleMillis: record.limits.idleMillis,
      lifetimeMillis: record.limits.lifetimeMillis,
      openedAtEpoch: record.openedAtEpoch,
      requestCommitment: b4a.from(record.requestCommitment)
    })
    const decoded = decodeCanonical(coreOpenReplicationResultV1,
      encodeCanonical(coreOpenReplicationResultV1, result))
    const request = record.request
    if (!sameBytes(decoded.relayBinding.relayPublicKey, this.relayPublicKey) ||
        !sameBytes(decoded.wireProfileHash, request.wireProfileHash) ||
        decoded.sessionClass !== request.sessionClass || decoded.controlChannelId !== request.controlChannelId ||
        !sameBytes(decoded.parentChannelBinding, request.parentChannelBinding) ||
        decoded.streamId !== record.streamId || decoded.maxSessionBytes !== BigInt(record.limits.maxSessionBytes) ||
        decoded.idleMillis !== record.limits.idleMillis || decoded.lifetimeMillis !== record.limits.lifetimeMillis ||
        decoded.openedAtEpoch !== record.openedAtEpoch || !sameBytes(decoded.requestNonce, request.clientNonce) ||
        !sameBytes(decoded.requestCommitment, record.requestCommitment)) {
      fail('INTERNAL', 'CORE result builder changed a frozen open field')
    }
    return decoded
  }

  _persistentRecord (record, state) {
    return {
      family: FAMILY.CORE,
      operation: 'OPEN_REPLICATION',
      state,
      logicalRetryKey: b4a.from(record.logicalRetryKey),
      spendTag: b4a.from(record.spendTag),
      requestCommitment: b4a.from(record.requestCommitment),
      wireProfileHash: b4a.from(record.request.wireProfileHash),
      sessionClass: record.request.sessionClass,
      clientNonce: b4a.from(record.request.clientNonce),
      parentSessionId: b4a.from(record.parentSessionId),
      controlChannelId: record.request.controlChannelId,
      parentChannelBinding: b4a.from(record.request.parentChannelBinding),
      streamId: record.streamId,
      maxSessionBytes: BigInt(record.limits.maxSessionBytes),
      idleMillis: record.limits.idleMillis,
      lifetimeMillis: record.limits.lifetimeMillis,
      openedAtEpoch: record.openedAtEpoch,
      result: record.result,
      preparedAdmission: record.preparedAdmission
    }
  }

  _restoreRecoveredRecords (records) {
    if (!records || typeof records[Symbol.iterator] !== 'function') {
      throw new TypeError('recovered CORE records must be iterable')
    }
    for (const recovered of records) {
      if (!recovered || recovered.lifecycleState !== 3 || recovered.terminalReason == null) {
        throw new TypeError('recovered CORE OPEN records must already be terminal')
      }
      const request = {
        wireProfileHash: b4a.from(fixed32(recovered.wireProfileHash, 'recovered wireProfileHash')),
        sessionClass: recovered.sessionClass,
        controlChannelId: u64(recovered.controlChannelId, 'recovered controlChannelId'),
        parentChannelBinding: b4a.from(fixed32(recovered.parentChannelBinding,
          'recovered parentChannelBinding')),
        clientNonce: b4a.from(fixed32(recovered.clientNonce, 'recovered clientNonce'))
      }
      const logicalRetryKey = coreOpenReplicationLogicalRetryKey(this.relayPublicKey, request)
      if (!sameBytes(logicalRetryKey, fixed32(recovered.logicalRetryKey, 'recovered logicalRetryKey'))) {
        throw new TypeError('recovered CORE OPEN logical retry key is invalid')
      }
      const requestCommitment = coreOpenReplicationRequestCommitment({
        relayPublicKey: this.relayPublicKey,
        ...request
      })
      if (!sameBytes(requestCommitment, fixed32(recovered.requestCommitment,
        'recovered requestCommitment'))) {
        throw new TypeError('recovered CORE OPEN request commitment is invalid')
      }
      const logicalKey = byteKey(logicalRetryKey)
      const spendTag = b4a.from(asBytes(recovered.spendTag, 'recovered spendTag', 1, 128))
      const spendKey = byteKey(spendTag)
      const parentSessionId = b4a.from(asBytes(recovered.parentSessionId,
        'recovered parentSessionId', 1, 256))
      const parent = parentKey(parentSessionId)
      const channelKey = `${parent}:${request.controlChannelId}`
      if (this.recordsByLogical.has(logicalKey) || this.recordsBySpend.has(spendKey) ||
          this.controlChannels.has(channelKey) || this.recordsByLogical.size >= this.maxRecords) {
        throw new TypeError('recovered CORE OPEN indexes collide or exceed their bound')
      }
      const limits = CORE_SESSION_CLASS[request.sessionClass]
      if (!limits || recovered.maxSessionBytes !== BigInt(limits.maxSessionBytes) ||
          recovered.idleMillis !== limits.idleMillis || recovered.lifetimeMillis !== limits.lifetimeMillis) {
        throw new TypeError('recovered CORE OPEN class limits are invalid')
      }
      const result = recovered.resultBytes == null
        ? null
        : decodeCanonical(coreOpenReplicationResultV1, recovered.resultBytes, { copyBytes: true })
      const record = {
        family: FAMILY.CORE,
        logicalKey,
        logicalRetryKey: b4a.from(logicalRetryKey),
        spendKey,
        spendTag,
        channelKey,
        parent,
        parentSessionId,
        request,
        requestCommitment: b4a.from(requestCommitment),
        streamId: recovered.streamId,
        limits,
        openedAtEpoch: recovered.openedAtEpoch,
        status: 'terminal',
        terminalReason: b4a.toString(recovered.terminalReason, 'ascii'),
        terminalPersisted: true,
        result,
        scope: null,
        child: null,
        ticket: null,
        ticketIssuedMonotonicMillis: null,
        preparedAdmission: null,
        wait: deferred()
      }
      this.recordsByLogical.set(logicalKey, record)
      this.recordsBySpend.set(spendKey, record)
      this.controlChannels.set(channelKey, record)
    }
  }

  async _onScopeClose (record, reason) {
    record.status = 'terminal'
    record.terminalReason = reason
    await this._persistTerminal(record, reason)
    if (record.child) await record.child._teardown(reason)
  }

  async _persistTerminal (record, reason) {
    if (record.terminalPersisted) return
    record.terminalPersisted = true
    try {
      await this.persistence.terminal({
        ...this._persistentRecord(record, 'TERMINAL'),
        terminalReason: String(reason).slice(0, 64)
      })
    } catch (error) {
      this.persistenceFailure = error
      try { await this.onPersistenceError(error, this._persistentRecord(record, 'TERMINAL')) } catch {}
      // The child remains terminal in memory and restart recovery forces every
      // retained RESERVED/LIVE record terminal before accepting another OPEN.
    }
  }

  async close (reason = 'daemon-shutdown') {
    const closing = []
    for (const record of this.recordsByLogical.values()) {
      if (record.scope && !record.scope.closed) closing.push(record.scope.close(reason))
    }
    await Promise.allSettled(closing)
  }
}
