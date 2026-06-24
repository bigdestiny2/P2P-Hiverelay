/**
 * Forward Relay Protocol  (`hiverelay-forward`)
 *
 * A demand-dialled relay hop: a client opens a forward channel, sends
 * OPEN(targetPubkey), and the relay dials that target over the DHT and
 * byte-bridges the channel's DATA frames to/from the target stream. Unlike
 * CircuitRelay (which bridges two *client* channels and needs the target to
 * pre-RESERVE), ForwardRelay dials the target on demand — the target needs
 * no relay awareness (it just sees a normal incoming DHT connection from the
 * relay). The relay forwards opaque bytes; for end-to-end secrecy the peers
 * layer their own Noise / sealed payload on top (the relay sees transport
 * traffic, exactly like a Tor relay does — confidentiality is the caller's
 * job via a sealed/confidential tier).
 *
 * Why it exists: it turns a HiveRelay node into a usable relay TRANSPORT for
 * apps behind NAT / UDP-blocking, and it composes into onion routing — a
 * client reaches relay2 *through* relay1's forward channel, then the seller
 * through relay2, so no single relay links the client to the target.
 *
 *   client → OPEN(target) → relay → dht.connect(target)
 *   client ⇄ DATA(bytes)  ⇄ relay ⇄ raw bytes ⇄ target
 *
 * Flow:
 *   1. client opens a `hiverelay-forward` channel, sends OPEN(target).
 *   2. relay (if enabled + under caps + target allowed) dials target,
 *      replies STATUS=ok, starts bridging.
 *   3. either side sends DATA(bytes); relay forwards (byte/bandwidth/frame
 *      caps enforced server-side).
 *   4. either side / the relay (on error, cap, target close) sends CLOSE.
 *
 * SECURITY: this is an opt-in capability (operators enable it) and only ever
 * reaches DHT peers (a 32-byte pubkey, never an arbitrary IP), bounded by
 * per-peer concurrency + per-forward byte + per-frame caps and the node's
 * existing SwarmFirewall. It is NOT an open internet proxy.
 */

import Protomux from 'protomux'
import c from 'compact-encoding'
import b4a from 'b4a'
import { EventEmitter } from 'events'
import { FORWARD_PROTOCOL_NAME } from '../constants.js'

const DEFAULT_MAX_FORWARD_BYTES = 64 * 1024 * 1024 // 64 MB per forward
const DEFAULT_MAX_FORWARDS_PER_PEER = 5
export const MAX_FORWARD_DATA_MSG_BYTES = 64 * 1024 // 64 KB per frame (DoS guard)
export const MAX_FORWARD_STATUS_MESSAGE_BYTES = 1024
// Per-peer dial RATE cap (distinct from the concurrency cap above). Without
// it, a peer can churn OPEN/CLOSE to make the relay dial arbitrary DHT
// pubkeys in a tight loop — DHT-peer scanning / connection laundering /
// outbound-dial amplification — while never exceeding the concurrency cap.
const DEFAULT_MAX_DIALS_PER_MIN_PER_PEER = 30
const DIAL_WINDOW_MS = 60 * 1000

// STATUS codes
const OK = 0
const ERR_DISABLED = 1
const ERR_CAPACITY = 2
const ERR_TARGET = 3
const ERR_BADREQ = 4

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

function encodeStatusMessage (m) {
  const message = m.message || ''
  if (b4a.byteLength(message) > MAX_FORWARD_STATUS_MESSAGE_BYTES) throw new Error('status message too large')
  return message
}

function encodeUintValue (value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${field} must be a non-negative integer`)
  return value
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

export const forwardOpenEncoding = {
  preencode (state, m) { c.fixed32.preencode(state, assertFixedBytes(m.target, 32, 'target')) },
  encode (state, m) { c.fixed32.encode(state, assertFixedBytes(m.target, 32, 'target')) },
  decode (state) {
    const decoded = decodeFixedBytes(state, 32, 'malformed target')
    return decoded.error ? { target: null, error: decoded.error } : { target: decoded.value }
  }
}
export const forwardDataEncoding = {
  preencode (state, m) {
    if (!m.data || m.data.byteLength > MAX_FORWARD_DATA_MSG_BYTES) throw new Error('frame too large')
    c.buffer.preencode(state, m.data)
  },
  encode (state, m) {
    if (!m.data || m.data.byteLength > MAX_FORWARD_DATA_MSG_BYTES) throw new Error('frame too large')
    c.buffer.encode(state, m.data)
  },
  decode (state) {
    const decoded = decodeBytes(state, MAX_FORWARD_DATA_MSG_BYTES, 'frame too large', 'malformed data')
    return decoded.error ? { data: null, error: decoded.error } : { data: decoded.value }
  }
}
export const forwardStatusEncoding = {
  preencode (state, m) {
    const code = encodeUintValue(m.code, 'status code')
    const message = encodeStatusMessage(m)
    c.uint.preencode(state, code)
    c.string.preencode(state, message)
  },
  encode (state, m) {
    const code = encodeUintValue(m.code, 'status code')
    const message = encodeStatusMessage(m)
    c.uint.encode(state, code)
    c.string.encode(state, message)
  },
  decode (state) {
    const code = decodeUint(state, 'malformed status')
    if (code.error) return { code: ERR_BADREQ, message: code.error, error: code.error }
    const message = decodeBytes(state, MAX_FORWARD_STATUS_MESSAGE_BYTES, 'status message too large', 'malformed status')
    if (message.error) return { code: ERR_BADREQ, message: message.error, error: message.error }
    return { code: code.value, message: b4a.toString(message.value, 'utf8') }
  }
}
export const forwardCloseEncoding = {
  preencode (state, m) { c.uint.preencode(state, encodeUintValue(m.reason || 0, 'close reason')) },
  encode (state, m) { c.uint.encode(state, encodeUintValue(m.reason || 0, 'close reason')) },
  decode (state) {
    const reason = decodeUint(state, 'malformed close')
    return reason.error ? { reason: ERR_BADREQ, error: reason.error } : { reason: reason.value }
  }
}

// Authenticated remote pubkey off the underlying noise stream (modern
// protomux exposes it via `_mux.stream`).
function remotePubOf (channel) {
  if (channel && channel._mux && channel._mux.stream && channel._mux.stream.remotePublicKey) return channel._mux.stream.remotePublicKey
  if (channel && channel.stream && channel.stream.remotePublicKey) return channel.stream.remotePublicKey
  return null
}

export class ForwardRelay extends EventEmitter {
  constructor (swarm, opts = {}) {
    super()
    this.swarm = swarm
    this.enabled = opts.enabled !== false // default ON when constructed; RelayNode gates construction by config
    this.maxForwardBytes = opts.maxForwardBytes || DEFAULT_MAX_FORWARD_BYTES
    this.maxForwardsPerPeer = opts.maxForwardsPerPeer || DEFAULT_MAX_FORWARDS_PER_PEER
    this.maxDataMsgBytes = Math.min(opts.maxDataMsgBytes || MAX_FORWARD_DATA_MSG_BYTES, MAX_FORWARD_DATA_MSG_BYTES)
    this.maxDialsPerMinPerPeer = opts.maxDialsPerMinPerPeer || DEFAULT_MAX_DIALS_PER_MIN_PER_PEER
    this.allowTarget = typeof opts.allowTarget === 'function' ? opts.allowTarget : null // optional policy hook
    this._perPeer = new Map() // peer hex -> active forward count
    this._dialWindow = new Map() // peer hex -> { windowStart, count } (dial-rate limiter)
    this._active = new Set() // active forward states (for teardown)
  }

  /**
   * Sliding 60s window per-peer dial-rate check. Returns false (and does
   * NOT consume a slot) when the peer has already hit the cap this window.
   * Time-bucketed so it's O(1) and self-evicting on the next window.
   */
  _allowDial (peerHex) {
    const now = Date.now()
    const w = this._dialWindow.get(peerHex)
    if (!w || (now - w.windowStart) >= DIAL_WINDOW_MS) {
      this._dialWindow.set(peerHex, { windowStart: now, count: 1 })
      return true
    }
    if (w.count >= this.maxDialsPerMinPerPeer) return false
    w.count++
    return true
  }

  /** Attach the forward protocol to a Hyperswarm connection. */
  attach (conn) {
    const mux = Protomux.from(conn)
    const channel = mux.createChannel({
      protocol: FORWARD_PROTOCOL_NAME,
      id: null,
      onclose: () => this._teardownChannel(channel)
    })
    const statusMsg = channel.addMessage({ encoding: forwardStatusEncoding })
    const dataMsg = channel.addMessage({ encoding: forwardDataEncoding, onmessage: (m) => this._onData(channel, m) })
    const closeMsg = channel.addMessage({ encoding: forwardCloseEncoding, onmessage: () => this._teardownChannel(channel) })
    const openMsg = channel.addMessage({ encoding: forwardOpenEncoding, onmessage: (m) => this._onOpen(channel, m, { statusMsg, dataMsg, closeMsg }) })
    channel._forward = { statusMsg, dataMsg, closeMsg, openMsg, state: null }
    channel.open()
    return channel
  }

  _onOpen (channel, msg, msgs) {
    const fw = channel._forward
    if (!fw || fw.state) return // already opened on this channel
    if (!this.enabled) return msgs.statusMsg.send({ code: ERR_DISABLED, message: 'forward relay disabled' })

    const peer = remotePubOf(channel)
    const peerHex = peer ? b4a.toString(peer, 'hex') : null
    if (!peerHex) return msgs.statusMsg.send({ code: ERR_BADREQ, message: 'no authenticated peer' })

    const target = msg && msg.target
    if (!target || target.byteLength !== 32) return msgs.statusMsg.send({ code: ERR_BADREQ, message: 'target must be a 32-byte pubkey' })
    const targetHex = b4a.toString(target, 'hex')
    if (targetHex === peerHex) return msgs.statusMsg.send({ code: ERR_BADREQ, message: 'cannot forward to self' })
    if (this.allowTarget && !this.allowTarget(targetHex, peerHex)) return msgs.statusMsg.send({ code: ERR_TARGET, message: 'target not allowed' })

    const count = this._perPeer.get(peerHex) || 0
    if (count >= this.maxForwardsPerPeer) return msgs.statusMsg.send({ code: ERR_CAPACITY, message: 'forward limit reached' })

    // Rate-limit dials per peer (consumes a slot even if the dial below
    // fails, so churning failed/rapid OPENs can't be used to scan the DHT
    // or amplify outbound dials).
    if (!this._allowDial(peerHex)) {
      return msgs.statusMsg.send({ code: ERR_CAPACITY, message: 'dial rate limit reached' })
    }

    let targetStream
    try {
      targetStream = this.swarm.dht.connect(target)
    } catch (err) {
      return msgs.statusMsg.send({ code: ERR_TARGET, message: 'dial failed' })
    }

    const state = { channel, peerHex, targetHex, stream: targetStream, bytes: 0, msgs }
    fw.state = state
    this._active.add(state)
    this._perPeer.set(peerHex, count + 1)

    targetStream.on('error', () => this._teardown(state, ERR_TARGET))
    targetStream.on('close', () => this._teardown(state, OK))
    // target → client (chunked to the frame cap)
    targetStream.on('data', (chunk) => {
      if (!fw.state) return
      for (let i = 0; i < chunk.length; i += this.maxDataMsgBytes) {
        const slice = chunk.subarray(i, Math.min(i + this.maxDataMsgBytes, chunk.length))
        state.bytes += slice.byteLength
        if (state.bytes > this.maxForwardBytes) return this._teardown(state, ERR_CAPACITY)
        try { msgs.dataMsg.send({ data: slice }) } catch (_) { return this._teardown(state, ERR_TARGET) }
      }
    })

    msgs.statusMsg.send({ code: OK, message: 'forwarding to ' + targetHex.slice(0, 12) })
    this.emit('forward-open', { peer: peerHex, target: targetHex })
  }

  _onData (channel, msg) {
    const st = channel._forward && channel._forward.state
    if (!st || !msg) return
    if (msg.error || !msg.data) return this._teardown(st, ERR_BADREQ)
    if (msg.data.byteLength > this.maxDataMsgBytes) return this._teardown(st, ERR_BADREQ)
    st.bytes += msg.data.byteLength
    if (st.bytes > this.maxForwardBytes) return this._teardown(st, ERR_CAPACITY)
    try { st.stream.write(msg.data) } catch (_) { this._teardown(st, ERR_TARGET) }
  }

  _teardownChannel (channel) {
    const st = channel && channel._forward && channel._forward.state
    if (st) this._teardown(st, OK)
  }

  _teardown (state, reason) {
    if (!this._active.has(state)) return
    this._active.delete(state)
    const n = (this._perPeer.get(state.peerHex) || 1) - 1
    if (n <= 0) this._perPeer.delete(state.peerHex); else this._perPeer.set(state.peerHex, n)
    try { state.msgs.closeMsg.send({ reason: reason || 0 }) } catch (_) {}
    try { state.stream.destroy() } catch (_) {}
    if (state.channel && state.channel._forward) state.channel._forward.state = null
    this.emit('forward-close', { peer: state.peerHex, target: state.targetHex, bytes: state.bytes })
  }

  destroy () {
    for (const st of [...this._active]) this._teardown(st, OK)
    this._perPeer.clear()
    this._dialWindow.clear()
  }
}

export default ForwardRelay
