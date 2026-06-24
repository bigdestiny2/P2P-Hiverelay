/**
 * Custody Protomux Channel
 *
 * Real-time push of custody pipeline entries between connected relays.
 * The registry already replicates entries through its append-only Hypercore
 * log — that gives us durability + ordering. But log replication carries
 * seconds-to-minutes latency.
 *
 * For interactive flows ("I just signed a receipt; please count my vote
 * toward quorum NOW"), we want push semantics. This channel does that:
 * a relay broadcasts each new custody entry to every connected peer via
 * a dedicated mux channel, and peers apply it locally as soon as it
 * arrives — without waiting for the next log replication tick.
 *
 * Hypercore replication remains the durable transport. This channel is the
 * push fast-path. Receivers gracefully ignore duplicates (the registry's
 * own dedup logic catches them).
 *
 * Wire encoding: 4-byte length prefix + JSON, identical to the services
 * and anchor protocols.
 *
 * Messages:
 *   1: PUSH      { entry }                          — broadcast new custody entry
 *   2: ACK       { entryHash }                      — peer acknowledges receipt (optional)
 *
 * The entry payload is the SAME JSON that lives in the registry log.
 * Receivers run it through `_applyEntry()` exactly like a log-replicated
 * entry — same validation, same dedup, same emit semantics.
 */

import b4a from 'b4a'
import Protomux from 'protomux'
import { EventEmitter } from 'events'
import { createLengthPrefixedJsonEncoding } from './json-message-encoding.js'

export const CUSTODY_PROTOCOL = 'hiverelay-custody'
export const CUSTODY_CHANNEL_ID = b4a.from('custody-v1')

const MSG_PUSH = 1
const MSG_ACK = 2
export const MAX_CUSTODY_MESSAGE_BYTES = 256 * 1024 // 256 KB — custody entries are small (<2 KB typical)
export const custodyMessageEncoding = createLengthPrefixedJsonEncoding({
  maxBytes: MAX_CUSTODY_MESSAGE_BYTES
})

const ALLOWED_TYPES = new Set([
  'custody-intent',
  'custody-receipt',
  'custody-commit',
  'source-retired',
  'custody-proof',
  'custody-non-serving-proof',
  'custody-expiry-witness'
])

export class CustodyProtocol extends EventEmitter {
  /**
   * @param {object} opts
   * @param {function} opts.applyEntry Async (entry, fromPeer) → boolean
   *   Called when a peer pushes us a custody entry. Production wires this
   *   to SeedingRegistry._applyPushedEntry which dedups + validates +
   *   appends to the local log. Returns true if the entry was new and
   *   applied, false if it was a duplicate.
   */
  constructor (opts = {}) {
    super()
    this.channels = new Map() // remotePubkey hex → channel + msgHandler
    this._applyEntry = opts.applyEntry || (async () => false)
  }

  attach (mux, remotePubkey) {
    mux = Protomux.from(mux)
    if (this.channels.has(remotePubkey)) return false

    const channel = mux.createChannel({
      protocol: CUSTODY_PROTOCOL,
      id: CUSTODY_CHANNEL_ID,
      onopen: () => this.emit('channel-open', { remotePubkey }),
      onclose: () => this._onClose(remotePubkey)
    })
    if (!channel) return false

    const msgHandler = channel.addMessage({
      encoding: custodyMessageEncoding,
      onmessage: (msg) => this._onMessage(remotePubkey, msg)
    })

    this.channels.set(remotePubkey, { channel, msgHandler })
    channel.open()
    return true
  }

  /**
   * Broadcast a custody entry to every connected peer. Called by the
   * SeedingRegistry whenever it appends a new entry locally.
   *
   * Best-effort fire-and-forget: peers that aren't reachable will pick
   * the entry up on the next log replication. We don't retry sends.
   */
  broadcast (entry) {
    if (!entry || typeof entry !== 'object') return 0
    if (!ALLOWED_TYPES.has(entry.type)) return 0
    let sent = 0
    for (const { msgHandler } of this.channels.values()) {
      try {
        msgHandler.send({ type: MSG_PUSH, entry })
        sent++
      } catch (err) {
        this.emit('send-error', { error: err.message })
      }
    }
    return sent
  }

  _onMessage (remotePubkey, msg) {
    if (!msg || msg.type === -1) return

    if (msg.type === MSG_PUSH) {
      this._handlePush(remotePubkey, msg.entry).catch((err) => {
        this.emit('apply-error', { remotePubkey, error: err.message })
      })
      return
    }

    if (msg.type === MSG_ACK) {
      this.emit('peer-ack', { remotePubkey, entryHash: msg.entryHash })
    }
  }

  async _handlePush (remotePubkey, entry) {
    if (!entry || typeof entry !== 'object') return
    if (!ALLOWED_TYPES.has(entry.type)) {
      this.emit('reject-push', { remotePubkey, reason: 'bad-type', type: entry.type })
      return
    }
    let applied = false
    try {
      applied = await this._applyEntry(entry, remotePubkey)
    } catch (err) {
      this.emit('apply-error', { remotePubkey, error: err.message })
      return
    }
    this.emit(applied ? 'applied' : 'duplicate', { remotePubkey, type: entry.type })
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
    for (const remotePubkey of [...this.channels.keys()]) this.detach(remotePubkey)
  }
}
