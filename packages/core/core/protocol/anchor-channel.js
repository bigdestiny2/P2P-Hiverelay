/**
 * Anchor Proof Protomux Channel
 *
 * Lets relays request and verify each other's signed anchor proofs over the
 * existing Hyperswarm connection — no HTTPS dependency. AutoHeal uses this
 * to gate which peers count as live replicas of an archive-tier drive.
 *
 * Why a dedicated channel: the previous implementation relied on
 * HTTPS GET /api/anchors/<appKey>/proof. That works fine for relays exposing
 * a public HTTP endpoint, but breaks on pure-swarm fleets and NAT'd peers.
 * By riding the existing Protomux mux, we get reachability wherever
 * Hyperswarm itself reaches.
 *
 * Wire encoding: 4-byte length prefix + JSON, identical to the services
 * protocol. Future: compact-encoding once the schemas stabilize.
 *
 * Messages:
 *   1: REQUEST   { id, appKey }                     — ask peer for proof
 *   2: RESPONSE  { id, proof }                      — return signed proof
 *   3: ERROR     { id, error }                      — return error message
 *
 * Each request gets a unique id; the responder echoes it. Pending requests
 * have a 5s timeout (proof generation should be sub-millisecond — the
 * timeout exists to free memory if the peer drops).
 */

import b4a from 'b4a'
import Protomux from 'protomux'
import { EventEmitter } from 'events'
import { createLengthPrefixedJsonEncoding } from './json-message-encoding.js'

export const ANCHOR_PROTOCOL = 'hiverelay-anchor'
export const ANCHOR_CHANNEL_ID = b4a.from('anchor-v1')

const MSG_REQUEST = 1
const MSG_RESPONSE = 2
const MSG_ERROR = 3

const DEFAULT_TIMEOUT_MS = 5000
export const MAX_ANCHOR_MESSAGE_BYTES = 64 * 1024 // 64 KB — proofs are <2 KB; cap protects against abuse
export const anchorMessageEncoding = createLengthPrefixedJsonEncoding({
  maxBytes: MAX_ANCHOR_MESSAGE_BYTES
})

export class AnchorProtocol extends EventEmitter {
  /**
   * @param {object} opts
   * @param {function} opts.proofProvider Async (appKey) → { ok, proof?, error? }
   *   Called when a peer requests our proof for an appKey. Production wires
   *   this to RelayNode.createAnchorProof (which signs over the relay's
   *   identity key); tests inject a mock.
   */
  constructor (opts = {}) {
    super()
    this.channels = new Map() // remotePubkey hex → channel + msgHandler
    this._pendingRequests = new Map() // requestId → { resolve, reject, timer }
    this._nextId = 1
    this._proofProvider = opts.proofProvider || (async () => ({ ok: false, error: 'no-provider' }))
    this.requestTimeout = opts.requestTimeout || DEFAULT_TIMEOUT_MS
  }

  /**
   * Attach to a Protomux instance for a given peer connection.
   * Returns true if the channel was opened, false if the mux already has it
   * or the peer didn't open the channel.
   */
  attach (mux, remotePubkey) {
    mux = Protomux.from(mux)
    if (this.channels.has(remotePubkey)) return false

    const channel = mux.createChannel({
      protocol: ANCHOR_PROTOCOL,
      id: ANCHOR_CHANNEL_ID,
      onopen: () => this.emit('channel-open', { remotePubkey }),
      onclose: () => this._onClose(remotePubkey)
    })
    if (!channel) return false

    const msgHandler = channel.addMessage({
      encoding: anchorMessageEncoding,
      onmessage: (msg) => this._onMessage(remotePubkey, msg)
    })

    this.channels.set(remotePubkey, { channel, msgHandler })
    channel.open()
    return true
  }

  /**
   * Request an anchor proof from a peer over the channel.
   * Resolves with { ok, proof? } | { ok: false, error }.
   */
  async requestProof (remotePubkey, appKey) {
    const entry = this.channels.get(remotePubkey)
    if (!entry) return { ok: false, error: 'no-channel' }

    const id = this._nextId++
    return new Promise((resolve) => {
      // We deliberately don't .unref() the timer — brittle's deadlock
      // detector treats unref'd timers as "no pending work" and aborts
      // tests prematurely. The timer is short (5s default) and pending
      // requests are cleaned up by destroy(), so we don't risk leaks.
      const timer = setTimeout(() => {
        if (this._pendingRequests.has(id)) {
          this._pendingRequests.delete(id)
          resolve({ ok: false, error: 'timeout' })
        }
      }, this.requestTimeout)

      this._pendingRequests.set(id, { resolve, timer })
      try {
        entry.msgHandler.send({ type: MSG_REQUEST, id, appKey })
      } catch (err) {
        clearTimeout(timer)
        this._pendingRequests.delete(id)
        resolve({ ok: false, error: 'send-error: ' + (err.message || 'unknown') })
      }
    })
  }

  _onMessage (remotePubkey, msg) {
    if (!msg || msg.type === -1) return

    if (msg.type === MSG_REQUEST) {
      // Peer is asking for our proof of `appKey`. Look it up via the
      // injected provider and respond.
      this._handleIncomingRequest(remotePubkey, msg).catch((err) => {
        this.emit('handler-error', { remotePubkey, appKey: msg.appKey, error: err.message })
      })
      return
    }

    if (msg.type === MSG_RESPONSE || msg.type === MSG_ERROR) {
      const pending = this._pendingRequests.get(msg.id)
      if (!pending) return
      clearTimeout(pending.timer)
      this._pendingRequests.delete(msg.id)
      if (msg.type === MSG_RESPONSE) {
        pending.resolve({ ok: true, proof: msg.proof })
      } else {
        pending.resolve({ ok: false, error: msg.error || 'unknown-error' })
      }
    }
  }

  async _handleIncomingRequest (remotePubkey, msg) {
    const entry = this.channels.get(remotePubkey)
    if (!entry) return
    let result
    try {
      result = await this._proofProvider(msg.appKey)
    } catch (err) {
      result = { ok: false, error: 'provider-error: ' + (err.message || 'unknown') }
    }
    try {
      if (result.ok) {
        entry.msgHandler.send({ type: MSG_RESPONSE, id: msg.id, proof: result.proof })
      } else {
        entry.msgHandler.send({ type: MSG_ERROR, id: msg.id, error: result.error || 'no-proof' })
      }
    } catch (err) {
      this.emit('send-error', { remotePubkey, appKey: msg.appKey, error: err.message })
    }
  }

  _onClose (remotePubkey) {
    this.channels.delete(remotePubkey)
    this.emit('channel-close', { remotePubkey })
  }

  detach (remotePubkey) {
    const entry = this.channels.get(remotePubkey)
    if (!entry) return
    try { entry.channel.close() } catch {}
    this.channels.delete(remotePubkey)
  }

  destroy () {
    for (const pending of this._pendingRequests.values()) {
      clearTimeout(pending.timer)
      pending.resolve({ ok: false, error: 'destroyed' })
    }
    this._pendingRequests.clear()
    for (const remotePubkey of [...this.channels.keys()]) this.detach(remotePubkey)
  }
}
