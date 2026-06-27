/**
 * Circuit Relay Protocol
 *
 * Provides NAT traversal fallback when direct hole-punching fails.
 * The relay forwards opaque, E2E-encrypted bytes between two peers
 * over a Protomux data-plane message — the relay never sees plaintext
 * (peers do their own Noise handshake on top of the byte channel).
 *
 * Flow:
 *   1. Peer A (behind NAT) opens a hiverelay-circuit channel to Relay R
 *      and sends RESERVE. R grants the reservation and sends STATUS=ok.
 *   2. Peer B opens its own channel to R and sends CONNECT(targetPubkey=A).
 *      R finds the matching reservation and bridges the circuit.
 *   3. R sends READY(circuitId) to BOTH peers — they now know they can
 *      start exchanging data on this circuitId.
 *   4. Either peer can call DATA(circuitId, bytes). R forwards the bytes
 *      to the other peer's channel as a DATA message. Bandwidth + byte
 *      caps are enforced server-side.
 *   5. Either peer (or R, on close/expiry) tears down. R sends CLOSE
 *      with the circuitId.
 *
 * v0.8.19 history: previous implementation tried to forward raw bytes
 * between two protomux underlying streams via Relay.createCircuit. That
 * was structurally broken — `channel.stream` is undefined in modern
 * protomux (only `_mux.stream` exists, and raw-byte forwarding between
 * two `_mux.stream`s would corrupt every other channel sharing them).
 * The bridge code path therefore never executed successfully. We replaced
 * it with a proper protomux data-plane message + channel-keyed circuit
 * routing. Same release fixes a silent auth bypass — the reserve/connect
 * identity checks were reading `channel.stream?.remotePublicKey` (always
 * undefined), which short-circuited the whole check to "pass." Now reads
 * `channel._mux.stream.remotePublicKey` correctly.
 */

import Protomux from 'protomux'
import c from 'compact-encoding'
import b4a from 'b4a'
import { EventEmitter } from 'events'
import { ERR, relayReserveEncoding } from './messages.js'
import { CIRCUIT_PROTOCOL_NAME } from '../constants.js'

const DEFAULT_RESERVATION_TTL = 60 * 60 * 1000 // 1 hour
const DEFAULT_MAX_CIRCUIT_BYTES = 64 * 1024 * 1024 // 64 MB
const DEFAULT_MAX_CIRCUITS_PER_PEER = 5
export const CIRCUIT_ID_BYTES = 16
export const MAX_CIRCUIT_DATA_MSG_BYTES = 64 * 1024 // 64 KB per data frame (protects against giant single-frame DoS)
export const MAX_CIRCUIT_STATUS_MESSAGE_BYTES = 1024

function validDecodeState (state) {
  const buffer = state && state.buffer
  if (!buffer || !Number.isSafeInteger(state.start) || !Number.isSafeInteger(state.end)) return false
  return state.start >= 0 && state.end >= state.start && state.end <= buffer.length
}

function malformed (state, error) {
  if (state && Number.isSafeInteger(state.end)) {
    const buffer = state.buffer
    state.start = Math.min(Math.max(state.end, 0), buffer ? buffer.length : state.end)
  }
  return { error }
}

function assertFixedBytes (value, size, field) {
  if (!value || value.byteLength !== size) throw new Error(`${field} must be ${size} bytes`)
  return value
}

function encodeUintValue (value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${field} must be a non-negative integer`)
  return value
}

function encodeStatusMessage (msg) {
  const message = msg.message || ''
  if (b4a.byteLength(message) > MAX_CIRCUIT_STATUS_MESSAGE_BYTES) throw new Error('status message too large')
  return message
}

function decodeUint (state, error = 'malformed uint') {
  if (!validDecodeState(state)) return malformed(state, error)
  let value
  try {
    value = c.uint.decode(state)
  } catch (_) {
    return malformed(state, error)
  }
  if (!Number.isSafeInteger(value) || value < 0) return malformed(state, error)
  return { value }
}

function decodeFixedBytes (state, size, error) {
  if (!validDecodeState(state)) return malformed(state, error)
  const end = state.start + size
  if (end > state.end) return malformed(state, error)
  const value = state.buffer.subarray(state.start, end)
  state.start = end
  return { value }
}

function decodeBytes (state, maxBytes, tooLargeError, malformedError) {
  if (!validDecodeState(state)) return malformed(state, malformedError)
  let len
  const lenState = { buffer: state.buffer, start: state.start, end: state.end }
  try {
    len = c.uint.decode(lenState)
  } catch (_) {
    return malformed(state, malformedError)
  }
  if (!Number.isSafeInteger(len) || len < 0) return malformed(state, malformedError)
  if (len > maxBytes) {
    state.start = Math.min(state.end, lenState.start + len)
    return { error: tooLargeError }
  }
  const end = lenState.start + len
  if (end > state.end) return malformed(state, malformedError)
  const value = state.buffer.subarray(lenState.start, end)
  state.start = end
  return { value }
}

export const circuitConnectEncoding = {
  preencode (state, msg) {
    const targetPubkey = assertFixedBytes(msg.targetPubkey, 32, 'targetPubkey')
    const sourcePubkey = assertFixedBytes(msg.sourcePubkey, 32, 'sourcePubkey')
    c.fixed32.preencode(state, targetPubkey)
    c.fixed32.preencode(state, sourcePubkey)
  },
  encode (state, msg) {
    const targetPubkey = assertFixedBytes(msg.targetPubkey, 32, 'targetPubkey')
    const sourcePubkey = assertFixedBytes(msg.sourcePubkey, 32, 'sourcePubkey')
    c.fixed32.encode(state, targetPubkey)
    c.fixed32.encode(state, sourcePubkey)
  },
  decode (state) {
    const target = decodeFixedBytes(state, 32, 'malformed connect')
    if (target.error) return { targetPubkey: null, sourcePubkey: null, error: target.error }
    const source = decodeFixedBytes(state, 32, 'malformed connect')
    if (source.error) return { targetPubkey: target.value, sourcePubkey: null, error: source.error }
    return { targetPubkey: target.value, sourcePubkey: source.value }
  }
}

export const circuitStatusEncoding = {
  preencode (state, msg) {
    const code = encodeUintValue(msg.code, 'status code')
    const message = encodeStatusMessage(msg)
    c.uint.preencode(state, code)
    c.string.preencode(state, message)
  },
  encode (state, msg) {
    const code = encodeUintValue(msg.code, 'status code')
    const message = encodeStatusMessage(msg)
    c.uint.encode(state, code)
    c.string.encode(state, message)
  },
  decode (state) {
    const code = decodeUint(state, 'malformed status')
    if (code.error) return { code: ERR.INVALID_REQUEST, message: code.error, error: code.error }
    const message = decodeBytes(state, MAX_CIRCUIT_STATUS_MESSAGE_BYTES, 'status message too large', 'malformed status')
    if (message.error) return { code: ERR.INVALID_REQUEST, message: message.error, error: message.error }
    return { code: code.value, message: b4a.toString(message.value, 'utf8') }
  }
}

// circuitId (16 bytes) + data (variable)
export const circuitDataEncoding = {
  preencode (state, msg) {
    const circuitId = assertFixedBytes(msg.circuitId, CIRCUIT_ID_BYTES, 'circuitId')
    if (!msg.data || msg.data.byteLength > MAX_CIRCUIT_DATA_MSG_BYTES) throw new Error('frame too large')
    c.fixed(CIRCUIT_ID_BYTES).preencode(state, circuitId)
    c.buffer.preencode(state, msg.data)
  },
  encode (state, msg) {
    const circuitId = assertFixedBytes(msg.circuitId, CIRCUIT_ID_BYTES, 'circuitId')
    if (!msg.data || msg.data.byteLength > MAX_CIRCUIT_DATA_MSG_BYTES) throw new Error('frame too large')
    c.fixed(CIRCUIT_ID_BYTES).encode(state, circuitId)
    c.buffer.encode(state, msg.data)
  },
  decode (state) {
    const circuitId = decodeFixedBytes(state, CIRCUIT_ID_BYTES, 'malformed data')
    if (circuitId.error) return { circuitId: null, data: null, error: circuitId.error }
    const data = decodeBytes(state, MAX_CIRCUIT_DATA_MSG_BYTES, 'frame too large', 'malformed data')
    return data.error ? { circuitId: circuitId.value, data: null, error: data.error } : { circuitId: circuitId.value, data: data.value }
  }
}

// circuitId (16 bytes) + remotePubkey (32 bytes) — tells the peer what
// the other end's identity is, so they can run a verified Noise handshake
// on top of the byte channel.
export const circuitReadyEncoding = {
  preencode (state, msg) {
    const circuitId = assertFixedBytes(msg.circuitId, CIRCUIT_ID_BYTES, 'circuitId')
    const remotePubkey = assertFixedBytes(msg.remotePubkey, 32, 'remotePubkey')
    c.fixed(CIRCUIT_ID_BYTES).preencode(state, circuitId)
    c.fixed32.preencode(state, remotePubkey)
  },
  encode (state, msg) {
    const circuitId = assertFixedBytes(msg.circuitId, CIRCUIT_ID_BYTES, 'circuitId')
    const remotePubkey = assertFixedBytes(msg.remotePubkey, 32, 'remotePubkey')
    c.fixed(CIRCUIT_ID_BYTES).encode(state, circuitId)
    c.fixed32.encode(state, remotePubkey)
  },
  decode (state) {
    const circuitId = decodeFixedBytes(state, CIRCUIT_ID_BYTES, 'malformed ready')
    if (circuitId.error) return { circuitId: null, remotePubkey: null, error: circuitId.error }
    const remotePubkey = decodeFixedBytes(state, 32, 'malformed ready')
    if (remotePubkey.error) return { circuitId: circuitId.value, remotePubkey: null, error: remotePubkey.error }
    return { circuitId: circuitId.value, remotePubkey: remotePubkey.value }
  }
}

// circuitId (16 bytes) + reason code (uint)
export const circuitCloseEncoding = {
  preencode (state, msg) {
    const circuitId = assertFixedBytes(msg.circuitId, CIRCUIT_ID_BYTES, 'circuitId')
    const reason = encodeUintValue(msg.reason, 'close reason')
    c.fixed(CIRCUIT_ID_BYTES).preencode(state, circuitId)
    c.uint.preencode(state, reason)
  },
  encode (state, msg) {
    const circuitId = assertFixedBytes(msg.circuitId, CIRCUIT_ID_BYTES, 'circuitId')
    const reason = encodeUintValue(msg.reason, 'close reason')
    c.fixed(CIRCUIT_ID_BYTES).encode(state, circuitId)
    c.uint.encode(state, reason)
  },
  decode (state) {
    const circuitId = decodeFixedBytes(state, CIRCUIT_ID_BYTES, 'malformed close')
    if (circuitId.error) return { circuitId: null, reason: ERR.INVALID_REQUEST, error: circuitId.error }
    const reason = decodeUint(state, 'malformed close')
    if (reason.error) return { circuitId: circuitId.value, reason: ERR.INVALID_REQUEST, error: reason.error }
    return { circuitId: circuitId.value, reason: reason.value }
  }
}

// Pull the authenticated remote pubkey off the underlying noise stream.
// Modern protomux Channels expose this via `_mux.stream`, not `.stream`.
// Defensive: also try the legacy `.stream` path in case a different
// protomux version is in use (returns undefined harmlessly if neither
// exists — caller decides what to do).
function authenticatedKeyFor (channel) {
  if (!channel) return null
  // Modern protomux (≥3.x)
  if (channel._mux && channel._mux.stream && channel._mux.stream.remotePublicKey) {
    return channel._mux.stream.remotePublicKey
  }
  // Legacy
  if (channel.stream && channel.stream.remotePublicKey) {
    return channel.stream.remotePublicKey
  }
  return null
}

export class CircuitRelay extends EventEmitter {
  constructor (swarm, relay, opts = {}) {
    super()
    this.swarm = swarm
    this.relay = relay // The Relay instance from relay.js
    this.reservationTTL = opts.reservationTTL || DEFAULT_RESERVATION_TTL
    this.maxCircuitBytes = opts.maxCircuitBytes || DEFAULT_MAX_CIRCUIT_BYTES
    this.maxCircuitsPerPeer = opts.maxCircuitsPerPeer || DEFAULT_MAX_CIRCUITS_PER_PEER
    this.maxDataMsgBytes = Math.min(opts.maxDataMsgBytes || MAX_CIRCUIT_DATA_MSG_BYTES, MAX_CIRCUIT_DATA_MSG_BYTES)

    // Reservations: peer pubkey hex -> { channel, peerPubkey, expiresAt, circuitCount, maxBytes }
    this.reservations = new Map()
    // Pending connect requests: target pubkey hex -> [{ sourceChannel, sourcePubkey, addedAt }]
    this.pendingConnects = new Map()
    // Active circuits: circuitId hex -> { sourceChannel, destChannel, sourcePubkey, destPubkey, bytesRelayed, startedAt, sourcePeerKey, maxBytes }
    this.activeCircuits = new Map()
    // Per-peer reservation rate limit: max 5 reserves per minute
    this._reserveAttempts = new Map() // peer hex -> [timestamps]
    this._maxReservesPerMin = opts.maxReservesPerMin || 5
    this._maxPendingConnects = opts.maxPendingConnects || 100

    this._cleanupInterval = setInterval(() => this._cleanupExpired(), 60_000)
    if (this._cleanupInterval.unref) this._cleanupInterval.unref()
  }

  /**
   * Attach circuit relay protocol to a connection
   */
  attach (conn) {
    const mux = Protomux.from(conn)

    const channel = mux.createChannel({
      protocol: CIRCUIT_PROTOCOL_NAME,
      id: null,
      onopen: () => this.emit('channel-open', channel),
      onclose: () => this._onChannelClose(channel)
    })

    const reserveMsg = channel.addMessage({
      encoding: relayReserveEncoding,
      onmessage: (msg) => this._onReserve(channel, msg)
    })

    const connectMsg = channel.addMessage({
      encoding: circuitConnectEncoding,
      onmessage: (msg) => this._onConnect(channel, msg)
    })

    const statusMsg = channel.addMessage({
      encoding: circuitStatusEncoding,
      onmessage: (msg) => this.emit('status', msg)
    })

    // v0.8.19: data-plane message. Carries opaque bytes between bridged
    // peers. Server validates the sender is part of the named circuit,
    // applies byte/bandwidth caps, then forwards to the other end.
    const dataMsg = channel.addMessage({
      encoding: circuitDataEncoding,
      onmessage: (msg) => this._onCircuitData(channel, msg)
    })

    // v0.8.19: server→client notification "circuit is bridged, start
    // sending." Sent to BOTH endpoints once the bridge is established.
    // Carries circuitId + the remote peer's pubkey so the receiver can
    // run a verified Noise handshake over the byte channel.
    const readyMsg = channel.addMessage({
      encoding: circuitReadyEncoding,
      onmessage: (msg) => this.emit('ready', msg)
    })

    // v0.8.19: explicit close notification. Server emits when a circuit
    // tears down (peer disconnect, byte cap, TTL, etc.) so clients can
    // surface a clean error rather than a generic stream drop.
    const closeMsg = channel.addMessage({
      encoding: circuitCloseEncoding,
      onmessage: (msg) => this.emit('circuit-closed-remote', msg)
    })

    channel._hiverelay = { reserveMsg, connectMsg, statusMsg, dataMsg, readyMsg, closeMsg }
    channel.open()

    return channel
  }

  _onReserve (channel, msg) {
    // v0.8.19 (security): authenticated-key check now reads the underlying
    // noise stream correctly via _mux.stream. Previously read channel.stream
    // (always undefined in modern protomux), causing the check to short-
    // circuit and silently bypass the identity binding — a publisher could
    // reserve a circuit under any pubkey, enabling MitM if the bridge worked.
    const authenticatedKey = authenticatedKeyFor(channel)
    if (authenticatedKey && msg.peerPubkey && !b4a.equals(authenticatedKey, msg.peerPubkey)) {
      this._sendStatus(channel, ERR.NOT_FOUND, 'Peer identity mismatch')
      return
    }

    const peerHex = b4a.toString(msg.peerPubkey, 'hex')

    // Per-peer reserve rate limiting
    const now = Date.now()
    const attempts = this._reserveAttempts.get(peerHex) || []
    const recentAttempts = attempts.filter(t => now - t < 60_000)
    if (recentAttempts.length >= this._maxReservesPerMin) {
      this._sendStatus(channel, ERR.CAPACITY_FULL, 'Reserve rate limited')
      return
    }
    recentAttempts.push(now)
    this._reserveAttempts.set(peerHex, recentAttempts)

    // Check capacity
    if (this.relay && this.relay.circuits && this.relay.circuits.size >= this.relay.maxConnections) {
      this._sendStatus(channel, ERR.CAPACITY_FULL, 'Relay at capacity')
      return
    }

    // Grant reservation
    this.reservations.set(peerHex, {
      channel,
      peerPubkey: msg.peerPubkey,
      expiresAt: Date.now() + this.reservationTTL,
      circuitCount: 0,
      maxDurationMs: msg.maxDurationMs || this.reservationTTL,
      maxBytes: msg.maxBytes || this.maxCircuitBytes
    })

    this._sendStatus(channel, ERR.NONE, 'Reservation granted')

    this.emit('reservation-granted', {
      peer: peerHex,
      ttl: this.reservationTTL
    })

    // Check for pending connect requests for this peer
    const pending = this.pendingConnects.get(peerHex)
    if (pending) {
      for (const req of pending) {
        this._bridgeCircuit(req.sourceChannel, channel, req.sourcePubkey, msg.peerPubkey)
      }
      this.pendingConnects.delete(peerHex)
    }
  }

  _onConnect (channel, msg) {
    if (!msg || msg.error || !msg.targetPubkey || !msg.sourcePubkey) {
      this._sendStatus(channel, ERR.INVALID_REQUEST, msg && msg.error ? msg.error : 'Malformed connect')
      return
    }

    // v0.8.19 (security): same auth fix as _onReserve. See note there.
    const authenticatedKey = authenticatedKeyFor(channel)
    if (authenticatedKey && msg.sourcePubkey && !b4a.equals(authenticatedKey, msg.sourcePubkey)) {
      this._sendStatus(channel, ERR.NOT_FOUND, 'Source identity mismatch')
      return
    }

    // Enforce pending-connect queue bounds
    let totalPending = 0
    for (const reqs of this.pendingConnects.values()) totalPending += reqs.length
    if (totalPending >= this._maxPendingConnects) {
      this.emit('debug', 'Rejecting connect: pending connects at capacity (' + totalPending + ')')
      this._sendStatus(channel, ERR.CAPACITY_FULL, 'Too many pending connects')
      return
    }

    const targetHex = b4a.toString(msg.targetPubkey, 'hex')
    const reservation = this.reservations.get(targetHex)

    if (!reservation || reservation.expiresAt < Date.now()) {
      // No live reservation — queue the connect request so it can fire
      // if the target reserves shortly. Preserves the existing semantics
      // around pendingConnects.
      const arr = this.pendingConnects.get(targetHex) || []
      arr.push({ sourceChannel: channel, sourcePubkey: msg.sourcePubkey, addedAt: Date.now() })
      this.pendingConnects.set(targetHex, arr)
      this._sendStatus(channel, ERR.NOT_FOUND, 'No reservation for target peer (queued)')
      return
    }

    if (reservation.circuitCount >= this.maxCircuitsPerPeer) {
      this._sendStatus(channel, ERR.CAPACITY_FULL, 'Max circuits per peer reached')
      return
    }

    this._bridgeCircuit(channel, reservation.channel, msg.sourcePubkey, msg.targetPubkey)
    reservation.circuitCount++
  }

  /**
   * Wire two channels together. v0.8.19: this no longer forwards raw
   * stream bytes (impossible over protomux). Instead we register the
   * circuit in `activeCircuits` keyed by circuitId; the dataMsg handler
   * uses that table to route DATA frames between the two channels.
   */
  _bridgeCircuit (sourceChannel, destChannel, sourcePubkey, destPubkey) {
    const circuitIdBuf = b4a.concat([sourcePubkey, destPubkey]).slice(0, CIRCUIT_ID_BYTES)
    const circuitId = b4a.toString(circuitIdBuf, 'hex')
    const sourcePeerKey = b4a.toString(sourcePubkey, 'hex')
    const destPeerKey = b4a.toString(destPubkey, 'hex')

    // Per-peer circuit-count accounting via the Relay class. Lets the
    // operator's maxConnections + maxCircuitsPerPeer caps apply uniformly,
    // and feeds the existing /status counters (totalCircuitsServed,
    // totalBytesRelayed) which dashboards already read.
    if (this.relay && typeof this.relay.registerCircuit === 'function') {
      const accepted = this.relay.registerCircuit(circuitId, sourcePeerKey, this.maxCircuitBytes)
      if (!accepted) {
        this._sendStatus(sourceChannel, ERR.CAPACITY_FULL, 'Relay at capacity')
        return
      }
    }

    this.activeCircuits.set(circuitId, {
      sourceChannel,
      destChannel,
      sourcePubkey,
      destPubkey,
      sourcePeerKey,
      destPeerKey,
      bytesRelayed: 0,
      startedAt: Date.now(),
      maxBytes: this.maxCircuitBytes
    })

    // Tell BOTH peers the circuit is ready. Each gets the OTHER's pubkey
    // so they can run a verified Noise handshake on top of the byte
    // channel. (Previously only the connecting side got a status; the
    // reservation holder had no signal that anyone had connected.)
    this._sendReady(sourceChannel, circuitIdBuf, destPubkey)
    this._sendReady(destChannel, circuitIdBuf, sourcePubkey)

    this.emit('circuit-bridged', {
      circuitId,
      source: sourcePeerKey.slice(0, 8),
      dest: destPeerKey.slice(0, 8)
    })
  }

  _onCircuitData (channel, msg) {
    if (!msg || msg.error || !msg.circuitId || !msg.data) {
      if (msg && msg.circuitId) this._closeCircuit(b4a.toString(msg.circuitId, 'hex'), 'FRAME_TOO_LARGE')
      return
    }

    const circuitIdHex = b4a.toString(msg.circuitId, 'hex')
    const circuit = this.activeCircuits.get(circuitIdHex)
    if (!circuit) {
      // Either circuit was never opened, or it's already torn down.
      // Silently drop — sending CLOSE here would create a feedback loop
      // if the peer is retrying.
      return
    }

    // Verify the sender is one of the two endpoints of this circuit.
    // Without this, any peer with the circuitId could inject data.
    if (channel !== circuit.sourceChannel && channel !== circuit.destChannel) {
      this.emit('debug', 'Circuit data from non-endpoint channel: ' + circuitIdHex)
      return
    }

    // Per-message size guard (DoS protection — caller can't blow up the
    // relay with a single giant frame).
    const dataLen = msg.data ? msg.data.byteLength : 0
    if (dataLen > this.maxDataMsgBytes) {
      this.emit('debug', 'Circuit data frame too large: ' + dataLen + ' bytes')
      this._closeCircuit(circuitIdHex, 'FRAME_TOO_LARGE')
      return
    }

    // Per-circuit byte cap.
    if (circuit.bytesRelayed + dataLen > circuit.maxBytes) {
      this._closeCircuit(circuitIdHex, 'BYTES_EXCEEDED')
      return
    }

    // Relay-wide bandwidth cap (uses the same per-second bucket logic
    // as before, just via the new accounting method).
    if (this.relay && typeof this.relay.recordCircuitBytes === 'function') {
      const ok = this.relay.recordCircuitBytes(circuitIdHex, dataLen)
      if (!ok) {
        this._closeCircuit(circuitIdHex, 'BANDWIDTH_EXCEEDED')
        return
      }
    }

    circuit.bytesRelayed += dataLen

    // Forward to the other endpoint.
    const otherChannel = channel === circuit.sourceChannel
      ? circuit.destChannel
      : circuit.sourceChannel

    if (otherChannel && otherChannel.opened && otherChannel._hiverelay) {
      try {
        otherChannel._hiverelay.dataMsg.send({ circuitId: msg.circuitId, data: msg.data })
      } catch (err) {
        this.emit('debug', 'Circuit forward failed: ' + (err && err.message))
        this._closeCircuit(circuitIdHex, 'FORWARD_FAILED')
      }
    } else {
      // Other side is gone — close the circuit cleanly.
      this._closeCircuit(circuitIdHex, 'PEER_CLOSED')
    }
  }

  _closeCircuit (circuitIdHex, reason) {
    const circuit = this.activeCircuits.get(circuitIdHex)
    if (!circuit) return
    this.activeCircuits.delete(circuitIdHex)

    // Notify the Relay class so counters decrement.
    if (this.relay && typeof this.relay.closeCircuit === 'function') {
      try { this.relay.closeCircuit(circuitIdHex, reason) } catch (_) {}
    }

    // Decrement reservation circuit count if the dest still has one.
    const destHex = circuit.destPeerKey
    const reservation = destHex && this.reservations.get(destHex)
    if (reservation && reservation.circuitCount > 0) reservation.circuitCount--

    // Tell both peers, best-effort.
    const reasonCode = REASON_CODES[reason] || REASON_CODES.UNKNOWN
    const circuitIdBuf = b4a.from(circuitIdHex, 'hex')
    for (const ch of [circuit.sourceChannel, circuit.destChannel]) {
      if (ch && ch.opened && ch._hiverelay) {
        try { ch._hiverelay.closeMsg.send({ circuitId: circuitIdBuf, reason: reasonCode }) } catch (_) {}
      }
    }

    this.emit('circuit-closed', { circuitId: circuitIdHex, reason, bytesRelayed: circuit.bytesRelayed, durationMs: Date.now() - circuit.startedAt })
  }

  _sendStatus (channel, code, message) {
    if (channel.opened && channel._hiverelay) {
      channel._hiverelay.statusMsg.send({ code, message })
    }
  }

  _sendReady (channel, circuitIdBuf, remotePubkey) {
    if (channel.opened && channel._hiverelay) {
      try {
        channel._hiverelay.readyMsg.send({ circuitId: circuitIdBuf, remotePubkey })
      } catch (err) {
        this.emit('debug', 'sendReady failed: ' + (err && err.message))
      }
    }
  }

  _onChannelClose (channel) {
    // Remove reservations held by this channel
    for (const [key, res] of this.reservations) {
      if (res.channel === channel) {
        this.reservations.delete(key)
      }
    }
    // Tear down any active circuits this channel was part of
    for (const [circuitIdHex, circuit] of this.activeCircuits) {
      if (circuit.sourceChannel === channel || circuit.destChannel === channel) {
        this._closeCircuit(circuitIdHex, 'PEER_CLOSED')
      }
    }
    this.emit('channel-close', channel)
  }

  _cleanupExpired () {
    const now = Date.now()
    for (const [key, res] of this.reservations) {
      if (res.expiresAt < now) {
        this.reservations.delete(key)
        this.emit('reservation-expired', { peer: key })
      }
    }
    // Evict stale pending connects (older than reservation TTL)
    for (const [key, reqs] of this.pendingConnects) {
      const active = reqs.filter(r => !r.addedAt || now - r.addedAt < this.reservationTTL)
      if (active.length === 0) this.pendingConnects.delete(key)
      else this.pendingConnects.set(key, active)
    }
    // Prune stale rate limit entries
    for (const [key, attempts] of this._reserveAttempts) {
      const recent = attempts.filter(t => now - t < 60_000)
      if (recent.length === 0) this._reserveAttempts.delete(key)
      else this._reserveAttempts.set(key, recent)
    }
    // Tear down circuits that have been open too long (defense in depth
    // — the Relay class also has a duration timer, but if accounting
    // wasn't called we still want a cleanup here).
    for (const [circuitIdHex, circuit] of this.activeCircuits) {
      if (now - circuit.startedAt > this.reservationTTL) {
        this._closeCircuit(circuitIdHex, 'DURATION_EXCEEDED')
      }
    }
  }

  getStats () {
    return {
      activeReservations: this.reservations.size,
      pendingConnects: this.pendingConnects.size,
      activeCircuits: this.activeCircuits.size
    }
  }

  destroy () {
    clearInterval(this._cleanupInterval)
    // Best-effort close every active circuit
    for (const circuitIdHex of [...this.activeCircuits.keys()]) {
      this._closeCircuit(circuitIdHex, 'SHUTDOWN')
    }
    this.reservations.clear()
    this.pendingConnects.clear()
    this._reserveAttempts.clear()
  }
}

const REASON_CODES = {
  UNKNOWN: 0,
  PEER_CLOSED: 1,
  BYTES_EXCEEDED: 2,
  BANDWIDTH_EXCEEDED: 3,
  DURATION_EXCEEDED: 4,
  FRAME_TOO_LARGE: 5,
  FORWARD_FAILED: 6,
  SHUTDOWN: 7
}

export { REASON_CODES }
