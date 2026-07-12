import b4a from 'b4a'
import {
  BlindProtocolError,
  DISPATCH_LIMITS,
  FAMILY,
  FORWARD_CIRCUIT_CLASS,
  FORWARD_CLOSE_KIND,
  FRAME_KIND,
  OPERATION,
  STREAM_WIRE_CLASS,
  blindForwardCloseV1,
  blindForwardDataV1,
  blindForwardHopAcceptV1,
  blindForwardHopOpenV1,
  blindForwardOpenResultV1,
  blindForwardOpenV1,
  blindForwardRouteScopeV1,
  blindForwardWindowV1,
  blindTransportRouteV1,
  blake2b256,
  decodeCanonical,
  decodeDispatchFrame,
  encodeCanonical,
  encodeDispatchFrame,
  forwardOpenRequestCommitment
} from '@hiverelay/blind-protocol'
import {
  FORWARD_PARENT_ORIGIN,
  extendForwardRouteScope,
  normalizeForwardParentContext,
  verifyForwardRouteScope
} from './forward-route-scope.js'

const MAX_U64 = (1n << 64n) - 1n
const FORWARD_NONCE_DOMAIN = b4a.from('hiverelay.blind.forward-open-live-key.v1', 'ascii')
const ZERO_REQUEST_ID = b4a.alloc(16)
const FORBIDDEN_DESTINATION_FIELDS = Object.freeze([
  'destination', 'host', 'hostname', 'ip', 'onion', 'port', 'url', 'nextHop', 'socketPath'
])

export const FORWARD_SIDE = Object.freeze({ CALLER: 1, NEXT_HOP: 2 })

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

function fixed (value, length, field) {
  return asBytes(value, field, length, length)
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_ENCODING', `${field} is outside u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail('BAD_ENCODING', `${field} is outside u64`)
  return value
}

function sameBytes (left, right) {
  return left.byteLength === right.byteLength && b4a.equals(left, right)
}

function allZero (value) {
  for (const byte of value) {
    if (byte !== 0) return false
  }
  return true
}

function byteKey (value) {
  return b4a.toString(value, 'hex')
}

function parentKey (value) {
  return byteKey(asBytes(value, 'parentSessionId'))
}

function normalizeOpen (value) {
  if (value && typeof value.byteLength === 'number') return decodeCanonical(blindForwardOpenV1, value)
  if (value && typeof value === 'object') {
    for (const field of FORBIDDEN_DESTINATION_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(value, field)) {
        fail('BAD_ENCODING', `FORWARD.OPEN cannot carry caller-selected ${field}`)
      }
    }
  }
  return decodeCanonical(blindForwardOpenV1, encodeCanonical(blindForwardOpenV1, value))
}

function validatePort (value, field) {
  if (!value || typeof value !== 'object' || typeof value.write !== 'function') {
    throw new TypeError(`${field} must be an injected bounded stream port with write()`)
  }
  for (const method of ['abort', 'close']) {
    if (value[method] != null && typeof value[method] !== 'function') throw new TypeError(`${field}.${method} must be a function`)
  }
  return value
}

function opposite (side) {
  if (side === FORWARD_SIDE.CALLER) return FORWARD_SIDE.NEXT_HOP
  if (side === FORWARD_SIDE.NEXT_HOP) return FORWARD_SIDE.CALLER
  fail('BAD_ENCODING', 'FORWARD side is not registered')
}

function deferred () {
  let resolve
  let reject
  const promise = new Promise((_resolve, _reject) => {
    resolve = _resolve
    reject = _reject
  })
  promise.catch(() => {})
  return { promise, resolve, reject }
}

function raceAbort (operation, signal) {
  if (signal.aborted) fail('RETRY_TERMINAL', 'FORWARD circuit is terminal')
  let onAbort
  const aborted = new Promise((resolve, reject) => {
    onAbort = () => reject(new BlindProtocolError('RETRY_TERMINAL', 'FORWARD circuit became terminal'))
    signal.addEventListener('abort', onAbort, { once: true })
  })
  return Promise.race([Promise.resolve(operation), aborted]).finally(() => {
    signal.removeEventListener('abort', onAbort)
  })
}

function nonceIndexKey (relayPublicKey, circuitNonce) {
  return byteKey(blake2b256(b4a.concat([FORWARD_NONCE_DOMAIN, relayPublicKey, circuitNonce])))
}

function decodeActiveBody (frame) {
  if (frame.operationId === OPERATION.FORWARD.DATA) {
    return decodeCanonical(blindForwardDataV1, frame.body)
  }
  if (frame.operationId === OPERATION.FORWARD.WINDOW) {
    return decodeCanonical(blindForwardWindowV1, frame.body)
  }
  if (frame.operationId === OPERATION.FORWARD.CLOSE) {
    return decodeCanonical(blindForwardCloseV1, frame.body)
  }
  fail('BAD_ENCODING', 'FORWARD active frame has an unknown operation')
}

function streamState (initialWindow) {
  return {
    nextSequence: 0n,
    nextOffset: 0n,
    consumedThrough: 0n,
    availableCredit: initialWindow,
    fin: false
  }
}

export class ForwardCircuit {
  constructor (options) {
    this.scope = options.scope
    this.circuitNonce = b4a.from(fixed(options.circuitNonce, 32, 'circuitNonce'))
    this.callerStreamId = u64(options.callerStreamId, 'callerStreamId')
    this.nextStreamId = u64(options.nextStreamId, 'nextStreamId')
    if (this.callerStreamId === 0n || this.nextStreamId === 0n) fail('BAD_ENCODING', 'FORWARD stream IDs must be nonzero')
    this.wireClass = options.wireClass
    this.circuitClass = options.circuitClass
    this.maxDataBytes = STREAM_WIRE_CLASS[this.wireClass]
    this.limits = FORWARD_CIRCUIT_CLASS[this.circuitClass]
    if (!this.maxDataBytes || !this.limits) fail('BAD_ENCODING', 'FORWARD class is not registered')
    this.ports = new Map([[FORWARD_SIDE.NEXT_HOP, validatePort(options.nextPort, 'nextPort')]])
    this.states = new Map([
      [FORWARD_SIDE.CALLER, streamState(this.limits.grantedInitialWindow)],
      [FORWARD_SIDE.NEXT_HOP, streamState(this.limits.grantedInitialWindow)]
    ])
    this.queues = new Map([
      [FORWARD_SIDE.CALLER, Promise.resolve()],
      [FORWARD_SIDE.NEXT_HOP, Promise.resolve()]
    ])
    this.attached = false
    this.teardownPromise = null
  }

  attachCaller (port) {
    this.scope.assertActive()
    if (this.attached) fail('RETRY_TERMINAL', 'FORWARD caller is already attached')
    this.ports.set(FORWARD_SIDE.CALLER, validatePort(port, 'callerPort'))
    this.attached = true
    return this
  }

  receive (side, rawFrame) {
    let prepared
    try {
      prepared = this._prepare(side, rawFrame)
    } catch (error) {
      this.scope.close('malformed-forward-frame').catch(this.scope.plane.onError)
      throw error
    }
    const previous = this.queues.get(side)
    const next = previous.then(() => this._deliver(prepared), () => this._deliver(prepared))
    this.queues.set(side, next.catch(() => {}))
    return next
  }

  _prepare (side, rawFrame) {
    this.scope.assertActive()
    opposite(side)
    const frame = decodeDispatchFrame(rawFrame, { copyBody: true })
    const sourceStreamId = side === FORWARD_SIDE.CALLER ? this.callerStreamId : this.nextStreamId
    if (frame.frameKind !== FRAME_KIND.STREAM || frame.familyId !== FAMILY.FORWARD ||
        frame.streamId !== sourceStreamId) {
      fail('BAD_ENCODING', 'FORWARD active frame is bound to another stream')
    }
    const state = this.states.get(side)
    if (frame.sequence !== state.nextSequence) fail('BAD_ENCODING', 'FORWARD sequence is not exact +1')
    state.nextSequence++
    const body = decodeActiveBody(frame)
    if (!sameBytes(body.circuitNonce, this.circuitNonce)) fail('BAD_ENCODING', 'FORWARD circuit nonce changed')

    let reservation = null
    let abortAfterDelivery = false
    if (frame.operationId === OPERATION.FORWARD.DATA) {
      if (state.fin) fail('RETRY_TERMINAL', 'FORWARD DATA followed FIN')
      if (body.offset !== state.nextOffset) fail('BAD_ENCODING', 'FORWARD DATA offset is not exact')
      if (body.bytes.byteLength > this.maxDataBytes) fail('TOO_LARGE', 'FORWARD DATA exceeds the negotiated wire class')
      if (body.bytes.byteLength > state.availableCredit) fail('TOO_LARGE', 'FORWARD DATA exceeds receiver credit')
      this.scope.countBytes(body.bytes.byteLength)
      reservation = this.scope.reserveBuffer(body.bytes.byteLength)
      state.nextOffset += BigInt(body.bytes.byteLength)
      state.availableCredit -= body.bytes.byteLength
    } else if (frame.operationId === OPERATION.FORWARD.WINDOW) {
      const sent = this.states.get(opposite(side))
      if (body.consumedThrough <= sent.consumedThrough || body.consumedThrough > sent.nextOffset) {
        fail('BAD_ENCODING', 'FORWARD WINDOW consumedThrough is not a strict sent-byte advance')
      }
      const consumedDelta = body.consumedThrough - sent.consumedThrough
      if (BigInt(body.creditIncrement) > consumedDelta) {
        fail('BAD_ENCODING', 'FORWARD WINDOW grants bytes that were not released')
      }
      const nextAvailable = sent.availableCredit + body.creditIncrement
      const remainingOutstanding = sent.nextOffset - body.consumedThrough
      if (nextAvailable > DISPATCH_LIMITS.MAX_FORWARD_WINDOW_BYTES ||
          BigInt(nextAvailable) + remainingOutstanding > BigInt(DISPATCH_LIMITS.MAX_FORWARD_WINDOW_BYTES)) {
        fail('TOO_LARGE', 'FORWARD WINDOW raises active credit above one MiB')
      }
      sent.consumedThrough = body.consumedThrough
      sent.availableCredit = nextAvailable
      this.scope.touch()
    } else {
      if (body.finalSendOffset !== state.nextOffset) fail('BAD_ENCODING', 'FORWARD CLOSE final offset does not match')
      if (body.closeKind === FORWARD_CLOSE_KIND.FIN) {
        if (state.fin) fail('RETRY_TERMINAL', 'FORWARD send side already sent FIN')
        state.fin = true
        this.scope.touch()
      } else {
        abortAfterDelivery = true
      }
    }

    const targetSide = opposite(side)
    const targetStreamId = targetSide === FORWARD_SIDE.CALLER ? this.callerStreamId : this.nextStreamId
    const outbound = encodeDispatchFrame({
      frameKind: FRAME_KIND.STREAM,
      familyId: FAMILY.FORWARD,
      operationId: frame.operationId,
      requestId: ZERO_REQUEST_ID,
      streamId: targetStreamId,
      sequence: frame.sequence,
      body: frame.body
    })
    return { side, targetSide, outbound, reservation, abortAfterDelivery }
  }

  async _deliver (prepared) {
    const port = this.ports.get(prepared.targetSide)
    if (!port) {
      if (prepared.reservation) prepared.reservation()
      await this.scope.close('forward-target-unattached')
      fail('RETRY_TERMINAL', 'FORWARD target side is not attached')
    }
    try {
      await raceAbort(port.write(prepared.outbound, { signal: this.scope.signal }), this.scope.signal)
    } catch (error) {
      await this.scope.close('forward-write-failed')
      throw error
    } finally {
      if (prepared.reservation) prepared.reservation()
    }
    if (prepared.abortAfterDelivery) {
      await this.scope.close('forward-abort')
      return
    }
    const caller = this.states.get(FORWARD_SIDE.CALLER)
    const next = this.states.get(FORWARD_SIDE.NEXT_HOP)
    if (caller.fin && next.fin && this.scope.bufferedBytes === 0) await this.scope.close('clean-fin')
  }

  close (reason = 'forward-abort') {
    return this.scope.close(reason)
  }

  async _teardown (reason) {
    if (this.teardownPromise) return this.teardownPromise
    this.teardownPromise = Promise.allSettled([...this.ports.values()].map(port => {
      if (typeof port.abort === 'function') return port.abort(reason)
      if (typeof port.close === 'function') return port.close(reason)
      return null
    }))
    await this.teardownPromise
  }
}

export class ForwardStreamService {
  constructor (options = {}) {
    if (!options.plane || typeof options.plane.createSession !== 'function' ||
        typeof options.plane.issueTicket !== 'function' || typeof options.plane.consumeTicket !== 'function') {
      throw new TypeError('a StreamSessionPlane is required')
    }
    this.plane = options.plane
    this.relayPublicKey = b4a.from(fixed(options.relayPublicKey, 32, 'relayPublicKey'))
    this.authenticateParent = options.authenticateParent
    this.authorizeRoute = options.authorizeRoute
    this.authorizeAdmission = options.authorizeAdmission
    this.allocateStreamId = options.allocateStreamId
    this.buildHopOpen = options.buildHopOpen
    this.dialAuthorizedRoute = options.dialAuthorizedRoute
    this.verifyHopAccept = options.verifyHopAccept
    this.buildResult = options.buildResult
    this.verifyRouteScopeSignature = options.verifyRouteScopeSignature
    this.verifyRouteScopeDescriptor = options.verifyRouteScopeDescriptor
    this.signRouteScope = options.signRouteScope
    this.epochNow = typeof options.epochNow === 'function'
      ? options.epochNow
      : () => Math.floor(Date.now() / (6 * 60 * 60 * 1000))
    this.persistence = options.persistence
    for (const [name, hook] of [
      ['authenticateParent', this.authenticateParent],
      ['authorizeRoute', this.authorizeRoute],
      ['authorizeAdmission', this.authorizeAdmission],
      ['allocateStreamId', this.allocateStreamId],
      ['buildHopOpen', this.buildHopOpen],
      ['dialAuthorizedRoute', this.dialAuthorizedRoute],
      ['verifyHopAccept', this.verifyHopAccept],
      ['buildResult', this.buildResult],
      ['verifyRouteScopeSignature', this.verifyRouteScopeSignature],
      ['verifyRouteScopeDescriptor', this.verifyRouteScopeDescriptor],
      ['signRouteScope', this.signRouteScope]
    ]) {
      if (typeof hook !== 'function') throw new TypeError(`${name} hook is required`)
    }
    if (!this.persistence || typeof this.persistence.reserve !== 'function' ||
        typeof this.persistence.activate !== 'function' || typeof this.persistence.terminal !== 'function') {
      throw new TypeError('persistence reserve/activate/terminal hooks are required')
    }
    this.maxRecords = Number.isSafeInteger(options.maxRecords) && options.maxRecords > 0 ? options.maxRecords : 4096
    this.recordsByNonce = new Map()
    this.recordsBySpend = new Map()
    this.recordsByScope = new Map()
    this.routeCounts = new Map()
    this.claimsByNonce = new Map()
    this.closing = false
  }

  async open (rawRequest, context = {}) {
    const request = normalizeOpen(rawRequest)
    const auth = await this.authenticateParent({ request, context })
    if (!auth || auth.verified !== true) fail('TRANSPORT_UNSUPPORTED', 'FORWARD parent channel is not authenticated')
    const parentRouteContext = normalizeForwardParentContext(auth.forwardParentContext)
    if (parentRouteContext.origin === FORWARD_PARENT_ORIGIN.DIRECT) {
      if (!allZero(request.parentRouteScopeHash)) {
        fail('CONFLICT', 'direct FORWARD parent requires the zero route-scope root')
      }
    } else if (!sameBytes(request.parentRouteScopeHash, parentRouteContext.inheritedScopeHash)) {
      fail('CONFLICT', 'forwarded FORWARD parent route scope was reset or changed')
    }
    const verifiedParentRouteScope = parentRouteContext.origin === FORWARD_PARENT_ORIGIN.FORWARDED
      ? await verifyForwardRouteScope(parentRouteContext.routeScope, {
        nowEpoch: this.epochNow(),
        verifySignature: this.verifyRouteScopeSignature,
        verifyDescriptorBinding: this.verifyRouteScopeDescriptor,
        signal: context.signal
      })
      : null
    const parentSessionId = asBytes(auth.parentSessionId, 'parentSessionId')
    const parent = parentKey(parentSessionId)
    const commitment = forwardOpenRequestCommitment({ previousRelayKey: this.relayPublicKey, ...request })
    const nonceKey = nonceIndexKey(this.relayPublicKey, request.circuitNonce)

    const authorization = await this.authorizeRoute({
      routeId: b4a.from(request.routeId),
      nextDescriptorSequence: request.nextDescriptorSequence,
      nextDescriptorHash: b4a.from(request.nextDescriptorHash),
      requestedWireClass: request.requestedWireClass,
      circuitClass: request.circuitClass,
      parentSessionId: b4a.from(parentSessionId),
      signal: context.signal
    })
    const route = this._validateAuthorization(authorization, request)

    const routeScope = await this._prepareRouteScope({
      auth,
      parentRouteContext,
      verifiedParentRouteScope,
      route,
      request,
      requestCommitment: commitment,
      signal: context.signal
    })
    const acceptedRouteScopeHash = b4a.from(routeScope.hops[routeScope.hops.length - 1].scopeHash)
    const acceptedRelayCount = routeScope.hops.length
    const nonceClaim = this._claimNonce({
      nonceKey,
      parent,
      requestCommitment: commitment,
      routeScopeHash: acceptedRouteScopeHash
    })
    if (nonceClaim.record) {
      return this._retry(nonceClaim.record, commitment, parent, acceptedRouteScopeHash)
    }
    if (!nonceClaim.owner) return nonceClaim.claim.wait.promise
    const claim = nonceClaim.claim

    let admission
    try {
      admission = await this.authorizeAdmission({
        operation: 'forward-open',
        admission: request.hopAdmission,
        circuitClass: request.circuitClass,
        requestCommitment: b4a.from(commitment),
        routeId: b4a.from(request.routeId),
        signal: context.signal
      })
      this._assertClaimOwner(claim)
      if (!admission || admission.accepted !== true) fail('SPEND_INVALID', 'FORWARD admission was not accepted')
    } catch (error) {
      throw this._terminalizeUnrecordedClaim(claim, error, 'FORWARD admission failed terminally')
    }

    let spendTag
    let spendKey
    let routeKey
    let activeForRoute
    let tuple
    let maxDataBytes
    try {
      spendTag = asBytes(admission.spendTag, 'spendTag', 1, 128)
      spendKey = byteKey(spendTag)
      if (this.recordsBySpend.has(spendKey)) fail('SPEND_REPLAY', 'FORWARD admission spend tag was already used')
      routeKey = byteKey(route.routeId)
      activeForRoute = this.routeCounts.get(routeKey) || 0
      if (activeForRoute >= route.maxConcurrentStreams) fail('BUSY', 'signed route stream capacity is exhausted')
      tuple = FORWARD_CIRCUIT_CLASS[request.circuitClass]
      maxDataBytes = STREAM_WIRE_CLASS[request.requestedWireClass]
    } catch (error) {
      throw this._terminalizeUnrecordedClaim(claim, error, 'FORWARD claimed open failed terminally')
    }

    let callerStreamId
    try {
      callerStreamId = u64(await this.allocateStreamId({ family: FAMILY.FORWARD, request, context }), 'streamId')
      this._assertClaimOwner(claim)
      if (callerStreamId === 0n) fail('INTERNAL', 'FORWARD stream allocator returned zero')
    } catch (error) {
      throw this._terminalizeUnrecordedClaim(claim, error, 'FORWARD stream allocation failed terminally')
    }
    const wait = claim.wait
    const record = {
      family: FAMILY.FORWARD,
      nonceKey,
      spendKey,
      spendTag: b4a.from(spendTag),
      parent,
      parentSessionId: b4a.from(parentSessionId),
      request,
      requestCommitment: b4a.from(commitment),
      routeScopeHash: b4a.from(acceptedRouteScopeHash),
      route,
      routeKey,
      authorization,
      parentRouteContext,
      routeScope,
      acceptedRouteScopeHash,
      acceptedRelayCount,
      callerStreamId,
      tuple,
      maxDataBytes,
      status: 'reserving',
      scope: null,
      circuit: null,
      result: null,
      hopOpen: null,
      hopAccept: null,
      nextStreamId: null,
      ticket: null,
      ticketIssuedMonotonicMillis: null,
      routeCounted: true,
      wait
    }
    this.routeCounts.set(routeKey, activeForRoute + 1)
    this.recordsByNonce.set(nonceKey, record)
    this.recordsBySpend.set(spendKey, record)

    try {
      record.scope = this.plane.createSession({
        family: FAMILY.FORWARD,
        streamId: callerStreamId,
        maxBytes: BigInt(tuple.maxCircuitBytes),
        maxBufferedBytes: Math.min(this.plane.maxPerStreamBufferedBytes,
          tuple.grantedInitialWindow + maxDataBytes),
        idleMillis: tuple.idleMillis,
        lifetimeMillis: tuple.lifetimeMillis,
        readiness: auth.readiness,
        metadata: {
          operation: 'FORWARD.OPEN',
          routeId: routeKey,
          nonceKey,
          routeScopeHash: byteKey(record.acceptedRouteScopeHash),
          relayCount: record.acceptedRelayCount
        },
        onClose: reason => this._onScopeClose(record, reason)
      })
      this.recordsByScope.set(record.scope.key, record)
      record.hopOpen = await this._buildAndValidateHopOpen(record)
      await this.persistence.reserve(this._persistentRecord(record, 'FORWARD_RESERVED'))
      record.status = 'reserved'

      // dialPlan is emitted only by the verified catalog hook. Neither the
      // caller request nor arbitrary host/IP/URL material reaches this API.
      const adjacent = await this.dialAuthorizedRoute({
        dialPlan: authorization.dialPlan,
        nextRelayKey: b4a.from(route.nextRelayKey),
        nextEndpointId: route.nextEndpointId,
        hopOpen: record.hopOpen,
        signal: record.scope.signal
      })
      if (!adjacent || typeof adjacent !== 'object') fail('INTERNAL', 'authorized FORWARD dial returned no adjacent stream')
      record.nextStreamId = u64(adjacent.nextStreamId, 'nextStreamId')
      if (record.nextStreamId === 0n) fail('INTERNAL', 'next hop returned a zero stream ID')
      record.hopAccept = decodeCanonical(blindForwardHopAcceptV1,
        encodeCanonical(blindForwardHopAcceptV1, adjacent.hopAccept))
      const accepted = await this.verifyHopAccept({
        hopOpen: record.hopOpen,
        hopAccept: record.hopAccept,
        route,
        request,
        signal: record.scope.signal
      })
      if (accepted !== true) fail('CONFLICT', 'next-hop accept failed authenticated verification')
      if (record.hopAccept.nextStreamId !== record.nextStreamId) fail('CONFLICT', 'next-hop stream ID changed in its accept')
      if (!sameBytes(record.hopAccept.acceptedRouteScopeHash, record.acceptedRouteScopeHash) ||
          record.hopAccept.acceptedRelayCount !== record.acceptedRelayCount) {
        fail('CONFLICT', 'next-hop accept changed the authenticated route scope')
      }
      record.scope.assertActive()
      record.circuit = new ForwardCircuit({
        scope: record.scope,
        circuitNonce: request.circuitNonce,
        callerStreamId,
        nextStreamId: record.nextStreamId,
        wireClass: request.requestedWireClass,
        circuitClass: request.circuitClass,
        nextPort: adjacent.port
      })
      record.result = await this._buildAndValidateResult(record)
      await this.persistence.activate(this._persistentRecord(record, 'LIVE'))
      record.status = 'live'
      record.ticket = this.plane.issueTicket(record.scope, record.parentSessionId)
      record.ticketIssuedMonotonicMillis = this.plane.now()
      const response = this._response(record, false)
      this._resolveRecordedClaim(claim, response)
      return response
    } catch (error) {
      record.status = 'terminal'
      record.terminalReason = error && error.code ? error.code : 'open-failed'
      if (record.scope) await record.scope.close('forward-open-failed')
      else await this._persistTerminal(record, 'forward-open-failed')
      const terminal = error instanceof BlindProtocolError
        ? error
        : new BlindProtocolError('INTERNAL', 'FORWARD authorized dial failed terminally')
      this._rejectRecordedClaim(claim, terminal)
      throw terminal
    }
  }

  _validateAuthorization (authorization, request) {
    if (!authorization || authorization.verified !== true || authorization.dialPlan == null) {
      fail('NOT_FOUND', 'FORWARD route is absent or not verified in the signed catalog')
    }
    const route = decodeCanonical(blindTransportRouteV1,
      encodeCanonical(blindTransportRouteV1, authorization.route))
    if (route.routeKind < 2 || route.routeKind > 5 ||
        !sameBytes(route.previousRelayKey, this.relayPublicKey) ||
        !sameBytes(route.routeId, request.routeId) ||
        route.nextDescriptorSequence !== request.nextDescriptorSequence ||
        !sameBytes(route.nextDescriptorHash, request.nextDescriptorHash)) {
      fail('CONFLICT', 'FORWARD request does not match its signed app-free route')
    }
    if ((route.wireClassBits & (1 << request.requestedWireClass)) === 0) {
      fail('CONFLICT', 'FORWARD wire class is not authorized by the route')
    }
    const openBytes = encodeCanonical(blindForwardOpenV1, request).byteLength
    const tuple = FORWARD_CIRCUIT_CLASS[request.circuitClass]
    if (route.maxOpenBytes < openBytes || route.maxCircuitBytes < BigInt(tuple.maxCircuitBytes) ||
        route.maxConcurrentStreams < 1) {
      fail('TOO_LARGE', 'FORWARD request exceeds a signed route bound')
    }
    return route
  }

  async _prepareRouteScope (input) {
    const nowEpoch = this.epochNow()
    const parent = input.parentRouteContext
    let inherited = null
    if (parent.origin === FORWARD_PARENT_ORIGIN.FORWARDED) {
      inherited = input.verifiedParentRouteScope
      if (inherited == null) fail('INTERNAL', 'verified FORWARD parent route scope is absent')
      if (!sameBytes(inherited.hops[inherited.hops.length - 1].scopeHash, parent.inheritedScopeHash) ||
          inherited.hops.length !== parent.inheritedRelayCount) {
        fail('CONFLICT', 'authenticated FORWARD parent route context changed after verification')
      }
      if (input.route.maxRelayCount !== inherited.maxRelayCount) {
        // maxRelayCount is inside the signed genesis preimage. The selected V1
        // shape has no monotonic effective-limit field, so a continuation
        // cannot reduce and propagate the value without invalidating every
        // prefix signature. Require the immutable root value at every hop.
        fail('CONFLICT', 'FORWARD continuation changed the signed root relay-count bound')
      }
      if (input.route.expiresEpoch !== inherited.expiresEpoch) {
        // expiresEpoch is also inside the signed genesis preimage and has no
        // independently propagated effective value in V1. Reject both an
        // extension and a local-only reduction that a later hop could lose.
        fail('CONFLICT', 'FORWARD continuation changed the signed root expiry')
      }
      if (inherited.hops.length >= input.route.maxRelayCount) {
        fail('TOO_LARGE', 'FORWARD continuation exceeds the signed route relay-count bound')
      }
    }
    const priorHops = inherited == null ? [] : inherited.hops
    if (priorHops.some(hop => sameBytes(hop.relayPublicKey, this.relayPublicKey))) {
      fail('CONFLICT', 'FORWARD continuation repeats the current relay')
    }
    if (sameBytes(input.route.nextRelayKey, this.relayPublicKey) ||
        priorHops.some(hop => sameBytes(hop.relayPublicKey, input.route.nextRelayKey))) {
      fail('CONFLICT', 'FORWARD continuation would create a relay cycle')
    }
    const routeScope = await extendForwardRouteScope({
      routeScope: inherited,
      rootRouteId: input.request.routeId,
      rootCircuitNonce: input.request.circuitNonce,
      rootRequestCommitment: input.requestCommitment,
      maxRelayCount: input.route.maxRelayCount,
      expiresEpoch: input.route.expiresEpoch,
      relayPublicKey: this.relayPublicKey,
      descriptor: input.auth.readiness,
      sign: this.signRouteScope,
      signal: input.signal
    })
    const verified = await verifyForwardRouteScope(routeScope, {
      nowEpoch,
      verifySignature: this.verifyRouteScopeSignature,
      verifyDescriptorBinding: this.verifyRouteScopeDescriptor,
      signal: input.signal
    })
    const last = verified.hops[verified.hops.length - 1]
    if (!sameBytes(last.relayPublicKey, this.relayPublicKey) || verified.hops.length > input.route.maxRelayCount) {
      fail('INTERNAL', 'FORWARD route-scope signer changed the bounded append')
    }
    return verified
  }

  _claimNonce (input) {
    if (this.closing) fail('BUSY', 'FORWARD service is draining')
    const record = this.recordsByNonce.get(input.nonceKey)
    if (record) return { owner: false, record, claim: null }
    const existing = this.claimsByNonce.get(input.nonceKey)
    if (existing) {
      this._assertNonceBinding(existing, input.parent, input.requestCommitment, input.routeScopeHash)
      return { owner: false, record: null, claim: existing }
    }
    let unrecordedClaims = 0
    for (const nonceKey of this.claimsByNonce.keys()) {
      if (!this.recordsByNonce.has(nonceKey)) unrecordedClaims++
    }
    if (this.recordsByNonce.size + unrecordedClaims >= this.maxRecords) {
      fail('BUSY', 'FORWARD retry record capacity is exhausted')
    }
    const claim = {
      nonceKey: input.nonceKey,
      parent: input.parent,
      requestCommitment: b4a.from(input.requestCommitment),
      routeScopeHash: b4a.from(input.routeScopeHash),
      status: 'claiming',
      wait: deferred(),
      error: null
    }
    this.claimsByNonce.set(input.nonceKey, claim)
    return { owner: true, record: null, claim }
  }

  _assertNonceBinding (value, parent, commitment, routeScopeHash) {
    if (value.parent !== parent) fail('RETRY_TERMINAL', 'FORWARD retry moved to another authenticated parent')
    if (!sameBytes(value.requestCommitment, commitment) ||
        !sameBytes(value.routeScopeHash, routeScopeHash)) {
      fail('CONFLICT', 'FORWARD circuit nonce was reused with another route scope')
    }
  }

  _terminalizeUnrecordedClaim (claim, error, message) {
    if (claim.status === 'terminal') return claim.error
    const terminal = error instanceof BlindProtocolError
      ? error
      : new BlindProtocolError('INTERNAL', message)
    claim.status = 'terminal'
    claim.error = terminal
    claim.wait.reject(terminal)
    if (this.claimsByNonce.get(claim.nonceKey) === claim) this.claimsByNonce.delete(claim.nonceKey)
    return terminal
  }

  _assertClaimOwner (claim) {
    if (claim.status !== 'claiming' || this.claimsByNonce.get(claim.nonceKey) !== claim) {
      throw claim.error || new BlindProtocolError('RETRY_TERMINAL', 'FORWARD nonce claim is terminal')
    }
  }

  _resolveRecordedClaim (claim, response) {
    if (this.claimsByNonce.get(claim.nonceKey) === claim) this.claimsByNonce.delete(claim.nonceKey)
    claim.status = 'live'
    claim.wait.resolve(response)
  }

  _rejectRecordedClaim (claim, error) {
    if (this.claimsByNonce.get(claim.nonceKey) === claim) this.claimsByNonce.delete(claim.nonceKey)
    claim.status = 'terminal'
    claim.error = error
    claim.wait.reject(error)
  }

  async _retry (record, commitment, parent, routeScopeHash) {
    this._assertNonceBinding(record, parent, commitment, routeScopeHash)
    if (record.status === 'reserving' || record.status === 'reserved') return record.wait.promise
    if (record.status !== 'live' || !record.scope || !record.scope.poll()) {
      fail('RETRY_TERMINAL', 'FORWARD circuit is no longer live')
    }
    return this._response(record, true)
  }

  _response (record, retried) {
    if (!record.circuit.attached) {
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
      ticket: record.circuit.attached ? null : b4a.from(record.ticket),
      attached: record.circuit.attached,
      retried
    }
  }

  attach (ticket, input) {
    if (!input || typeof input !== 'object') throw new TypeError('FORWARD attachment input is required')
    const parentSessionId = asBytes(input.parentSessionId, 'parentSessionId')
    const scope = this.plane.consumeTicket(ticket, {
      family: FAMILY.FORWARD,
      streamId: input.streamId,
      descriptorSequence: input.descriptorSequence,
      descriptorHash: input.descriptorHash,
      parentSessionId
    })
    const record = this.recordsByScope.get(scope.key)
    if (!record || record.status !== 'live' || record.parent !== parentKey(parentSessionId)) {
      fail('RETRY_TERMINAL', 'FORWARD ticket has no matching live open record')
    }
    record.circuit.attachCaller(input.callerPort)
    record.ticket = null
    record.ticketIssuedMonotonicMillis = null
    return record.circuit
  }

  async _buildAndValidateHopOpen (record) {
    const value = await this.buildHopOpen({
      route: record.route,
      request: record.request,
      callerStreamId: record.callerStreamId,
      grantedInitialWindow: record.tuple.grantedInitialWindow,
      maxDataBytes: record.maxDataBytes,
      maxCircuitBytes: BigInt(record.tuple.maxCircuitBytes),
      idleMillis: record.tuple.idleMillis,
      lifetimeMillis: record.tuple.lifetimeMillis,
      clientRequestCommitment: b4a.from(record.requestCommitment),
      routeScope: record.routeScope
    })
    const hop = decodeCanonical(blindForwardHopOpenV1, encodeCanonical(blindForwardHopOpenV1, value))
    const request = record.request
    if (!sameBytes(hop.route.routeId, request.routeId) || !sameBytes(hop.circuitNonce, request.circuitNonce) ||
        hop.requestedWireClass !== request.requestedWireClass || hop.circuitClass !== request.circuitClass ||
        hop.grantedInitialWindow !== record.tuple.grantedInitialWindow || hop.maxDataBytes !== record.maxDataBytes ||
        hop.maxCircuitBytes !== BigInt(record.tuple.maxCircuitBytes) || hop.idleMillis !== record.tuple.idleMillis ||
        hop.lifetimeMillis !== record.tuple.lifetimeMillis ||
        !sameBytes(hop.clientRequestCommitment, record.requestCommitment) ||
        !sameBytes(hop.routeScope.hops[hop.routeScope.hops.length - 1].scopeHash,
          record.acceptedRouteScopeHash) ||
        hop.routeScope.hops.length !== record.acceptedRelayCount ||
        !sameBytes(encodeCanonical(blindForwardRouteScopeV1, hop.routeScope),
          encodeCanonical(blindForwardRouteScopeV1, record.routeScope))) {
      fail('INTERNAL', 'FORWARD HopOpen builder changed a frozen field')
    }
    return hop
  }

  async _buildAndValidateResult (record) {
    const value = await this.buildResult({
      request: record.request,
      callerStreamId: record.callerStreamId,
      grantedInitialWindow: record.tuple.grantedInitialWindow,
      maxDataBytes: record.maxDataBytes,
      maxCircuitBytes: BigInt(record.tuple.maxCircuitBytes),
      idleMillis: record.tuple.idleMillis,
      lifetimeMillis: record.tuple.lifetimeMillis,
      requestCommitment: b4a.from(record.requestCommitment),
      acceptedRouteScopeHash: b4a.from(record.acceptedRouteScopeHash),
      acceptedRelayCount: record.acceptedRelayCount,
      hopAccept: record.hopAccept
    })
    const result = decodeCanonical(blindForwardOpenResultV1,
      encodeCanonical(blindForwardOpenResultV1, value))
    const request = record.request
    if (!sameBytes(result.relayBinding.relayPublicKey, this.relayPublicKey) ||
        !sameBytes(result.routeId, request.routeId) || result.nextDescriptorSequence !== request.nextDescriptorSequence ||
        !sameBytes(result.nextDescriptorHash, request.nextDescriptorHash) ||
        !sameBytes(result.circuitNonce, request.circuitNonce) || result.grantedWireClass !== request.requestedWireClass ||
        result.circuitClass !== request.circuitClass || result.streamId !== record.callerStreamId ||
        result.grantedInitialWindow !== record.tuple.grantedInitialWindow || result.maxDataBytes !== record.maxDataBytes ||
        result.maxCircuitBytes !== BigInt(record.tuple.maxCircuitBytes) || result.idleMillis !== record.tuple.idleMillis ||
        result.lifetimeMillis !== record.tuple.lifetimeMillis ||
        !sameBytes(result.requestCommitment, record.requestCommitment) ||
        !sameBytes(result.acceptedRouteScopeHash, record.acceptedRouteScopeHash) ||
        result.acceptedRelayCount !== record.acceptedRelayCount) {
      fail('INTERNAL', 'FORWARD result builder changed a frozen open field')
    }
    return result
  }

  _persistentRecord (record, state) {
    return {
      family: FAMILY.FORWARD,
      operation: 'OPEN',
      state,
      spendTag: b4a.from(record.spendTag),
      requestCommitment: b4a.from(record.requestCommitment),
      parentSessionId: b4a.from(record.parentSessionId),
      routeId: b4a.from(record.request.routeId),
      routeScopeHash: b4a.from(record.acceptedRouteScopeHash),
      relayCount: record.acceptedRelayCount,
      routeScope: record.routeScope,
      circuitNonce: b4a.from(record.request.circuitNonce),
      callerStreamId: record.callerStreamId,
      nextStreamId: record.nextStreamId,
      hopOpen: record.hopOpen,
      hopAccept: record.hopAccept,
      result: record.result
    }
  }

  async _onScopeClose (record, reason) {
    if (record.circuit) await record.circuit._teardown(reason)
    record.status = 'terminal'
    record.terminalReason = reason
    if (record.routeCounted) {
      record.routeCounted = false
      const count = this.routeCounts.get(record.routeKey) || 0
      if (count <= 1) this.routeCounts.delete(record.routeKey)
      else this.routeCounts.set(record.routeKey, count - 1)
    }
    await this._persistTerminal(record, reason)
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
      this.plane.onError(error)
    }
  }

  async close (reason = 'daemon-shutdown') {
    this.closing = true
    for (const [nonceKey, claim] of this.claimsByNonce) {
      if (!this.recordsByNonce.has(nonceKey) && claim.status === 'claiming') {
        this._terminalizeUnrecordedClaim(claim,
          new BlindProtocolError('RETRY_TERMINAL', 'FORWARD service closed during nonce claim'),
          'FORWARD service closed during nonce claim')
      }
    }
    const closing = []
    for (const record of this.recordsByNonce.values()) {
      if (record.scope && !record.scope.closed) closing.push(record.scope.close(reason))
    }
    await Promise.allSettled(closing)
  }
}
