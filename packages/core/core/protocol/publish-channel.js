/**
 * Publisher Submit Protomux Channel — `hiverelay-publish` v1
 *
 * Lets external publishers submit publisher-signed custody-pipeline
 * entries (intent, commit, source-retired) and seed requests to a relay
 * over Hyperswarm, without going through HTTPS.
 *
 * Motivation: Pear manifesto §5 — "every application must work peer-to-peer
 * with zero HiveRelay nodes online; infrastructure improves the experience
 * but does not enable it." The existing v0.8.6 publisher-signed REST
 * endpoints (`/api/v1/seed`, `/api/v1/custody/*`) give publishers an
 * HTTPS-based path to submit entries, which means escrow-style apps
 * become HTTPS-dependent. This channel adds the equivalent semantics over
 * Hyperswarm so apps can do the whole custody pipeline without HTTPS.
 *
 * Distinct from `hiverelay-custody` (which is relay-to-relay broadcast
 * of already-appended entries — push fast-path) — this channel is
 * publisher-to-relay request/response. Both can coexist: a publisher
 * submits over `hiverelay-publish`, the relay validates + appends,
 * `hiverelay-custody` then gossips the entry to peer relays.
 *
 * Wire encoding: identical to other Protomux channels in this codebase —
 * 4-byte length prefix + JSON.
 *
 * Messages:
 *   1: SUBMIT  { id, kind: 'intent'|'commit'|'source-retired'|'seed', body }
 *   2: RESULT  { id, ok, error?, retryable?, result? }
 *
 * `id` is a publisher-chosen 32-bit unsigned integer used to correlate
 * the RESULT back to the SUBMIT. Reuse across submits on the same channel
 * is fine; the server only correlates within a single in-flight submit.
 *
 * Authorisation: NONE at the channel layer. The publisher's signature on
 * the entry body IS the authorisation, identical to the v0.8.6
 * `/api/v1/*` REST endpoints. The server-side handler validates the
 * embedded Ed25519 signature before append/seed.
 *
 * On the server side, `attach(mux, remotePubkey, handlers)` wires the
 * channel to a connection and delegates SUBMIT handling to four callbacks
 * the consumer provides — typically the RelayNode injects them so they
 * call into `seedingRegistry.publishCustodyIntent`, `publishCustodyCommit`,
 * `publishSourceRetired`, and `node.seedApp` respectively. This keeps the
 * channel decoupled from the registry's internal shape.
 *
 * On the client side, `submit(kind, body)` sends a SUBMIT and returns a
 * promise that resolves with the RESULT (or rejects with the error +
 * retryable flag from the server). One in-flight tracker per channel
 * instance; the client-side wrapper picks unique ids.
 */

import b4a from 'b4a'
import Protomux from 'protomux'
import { EventEmitter } from 'events'

export const PUBLISH_PROTOCOL = 'hiverelay-publish'
export const PUBLISH_CHANNEL_ID = b4a.from('publish-v1')

const MSG_SUBMIT = 1
const MSG_RESULT = 2

const MAX_MESSAGE_BYTES = 256 * 1024 // 256 KB — entries are small (<2 KB typical); generous bound for future fields

export const SUBMIT_KINDS = new Set([
  'intent', // SUBMIT_INTENT — publisher-signed custody-intent
  'commit', // SUBMIT_COMMIT — publisher-signed custody-commit
  'source-retired', // SUBMIT_SOURCE_RETIRED — publisher-signed source-retired
  'seed' // SUBMIT_SEED — publisher-signed seed-request payload
])

const encoding = {
  preencode (state, msg) {
    const json = JSON.stringify(msg)
    state.end += 4 + b4a.byteLength(json)
  },
  encode (state, msg) {
    const json = JSON.stringify(msg)
    const buf = b4a.from(json)
    state.buffer.writeUInt32BE(buf.length, state.start)
    buf.copy(state.buffer, state.start + 4)
    state.start += 4 + buf.length
  },
  decode (state) {
    const len = state.buffer.readUInt32BE(state.start)
    if (len > MAX_MESSAGE_BYTES) {
      state.start += 4 + len
      return { type: -1, error: 'message too large' }
    }
    const json = state.buffer.subarray(state.start + 4, state.start + 4 + len).toString()
    state.start += 4 + len
    try { return JSON.parse(json) } catch { return { type: -1, error: 'bad json' } }
  }
}

/**
 * Server-side protocol handler. One instance per RelayNode; attached to
 * each inbound connection separately so each publisher gets their own
 * channel.
 *
 * Handler signatures — each is `async (body) => { ok, error?, retryable?,
 * result? }`. Consumer is responsible for signature verification + any
 * other validation (we just route by `kind`). If a handler throws, the
 * channel returns `{ ok: false, error: err.message, retryable: false }`.
 *
 * @example
 *   const proto = new PublishProtocol({
 *     onSubmitIntent: (body) => registry.publishCustodyIntent(body, null).then(r => ({ ok: true, result: r })),
 *     onSubmitCommit: (body) => registry.publishCustodyCommit(body, null).then(r => ({ ok: true, result: r })),
 *     onSubmitSourceRetired: (body) => registry.publishSourceRetired(body, null).then(r => ({ ok: true, result: r })),
 *     onSubmitSeed: (body) => node.seedApp(body.appKey, opts).then(r => ({ ok: true, result: r }))
 *   })
 *   swarm.on('connection', (conn, info) => proto.attach(conn, info.publicKey))
 */
export class PublishProtocol extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.channels = new Map() // remotePubkey (hex or buffer key) → { channel, msgHandler }
    this._onSubmitIntent = opts.onSubmitIntent || defaultUnsupported('intent')
    this._onSubmitCommit = opts.onSubmitCommit || defaultUnsupported('commit')
    this._onSubmitSourceRetired = opts.onSubmitSourceRetired || defaultUnsupported('source-retired')
    this._onSubmitSeed = opts.onSubmitSeed || defaultUnsupported('seed')
  }

  attach (mux, remotePubkey) {
    mux = Protomux.from(mux)
    const key = stringifyPubkey(remotePubkey)
    if (this.channels.has(key)) return false

    const channel = mux.createChannel({
      protocol: PUBLISH_PROTOCOL,
      id: PUBLISH_CHANNEL_ID,
      onopen: () => this.emit('channel-open', { remotePubkey: key }),
      onclose: () => this._onClose(key)
    })
    if (!channel) return false

    const msgHandler = channel.addMessage({
      encoding,
      onmessage: (msg) => this._onMessage(key, msgHandler, msg)
    })

    this.channels.set(key, { channel, msgHandler })
    channel.open()
    return true
  }

  _onMessage (remotePubkey, msgHandler, msg) {
    if (!msg || msg.type === -1) return
    if (msg.type !== MSG_SUBMIT) return // RESULT inbound on server side is ignored

    const { id, kind, body } = msg
    if (typeof id !== 'number' || !Number.isInteger(id) || id < 0) {
      this._sendResult(msgHandler, { id, ok: false, error: 'id must be a non-negative integer' })
      return
    }
    if (!SUBMIT_KINDS.has(kind)) {
      this._sendResult(msgHandler, { id, ok: false, error: `unknown submit kind: ${kind}` })
      return
    }
    if (!body || typeof body !== 'object') {
      this._sendResult(msgHandler, { id, ok: false, error: 'body must be an object' })
      return
    }

    this._dispatch(kind, body)
      .then((res) => {
        const safe = normaliseResult(res)
        this._sendResult(msgHandler, { id, ...safe })
        this.emit('submit-handled', { remotePubkey, kind, ok: safe.ok })
      })
      .catch((err) => {
        // Convert thrown errors into a RESULT — handlers shouldn't have to
        // wrap themselves in try/catch.
        const message = (err && err.message) ? err.message : String(err || 'unknown error')
        this._sendResult(msgHandler, { id, ok: false, error: message, retryable: false })
        this.emit('submit-handled', { remotePubkey, kind, ok: false, error: message })
      })
  }

  _dispatch (kind, body) {
    switch (kind) {
      case 'intent': return this._onSubmitIntent(body)
      case 'commit': return this._onSubmitCommit(body)
      case 'source-retired': return this._onSubmitSourceRetired(body)
      case 'seed': return this._onSubmitSeed(body)
      default: return Promise.resolve({ ok: false, error: `unknown kind: ${kind}` })
    }
  }

  _sendResult (msgHandler, result) {
    try {
      msgHandler.send({ type: MSG_RESULT, ...result })
    } catch (err) {
      this.emit('send-error', { error: err.message })
    }
  }

  _onClose (remotePubkey) {
    this.channels.delete(remotePubkey)
    this.emit('channel-close', { remotePubkey })
  }

  detach (remotePubkey) {
    const key = stringifyPubkey(remotePubkey)
    const entry = this.channels.get(key)
    if (!entry) return
    try { entry.channel.close() } catch {}
    this.channels.delete(key)
  }

  destroy () {
    for (const key of [...this.channels.keys()]) this.detach(key)
  }
}

/**
 * Client-side helper. Wraps a single connection's publish-channel with a
 * promise-returning `submit(kind, body)` method. Tracks in-flight submits
 * by id and correlates RESULT messages back to the originating promise.
 *
 * Typical use:
 *   const client = new PublishProtocolClient()
 *   client.attach(conn, remotePubkey)
 *   const res = await client.submit('seed', signedSeedRequestBody)
 *   if (res.ok) ... else if (res.retryable) ... else fail
 */
export class PublishProtocolClient extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.channels = new Map() // remotePubkey → { channel, msgHandler, pending: Map<id, {resolve, reject}> }
    this._nextId = 1
    this._submitTimeoutMs = Number.isFinite(opts.submitTimeoutMs) && opts.submitTimeoutMs > 0
      ? opts.submitTimeoutMs
      : 15_000
  }

  attach (mux, remotePubkey) {
    mux = Protomux.from(mux)
    const key = stringifyPubkey(remotePubkey)
    if (this.channels.has(key)) return false

    const pending = new Map()
    const channel = mux.createChannel({
      protocol: PUBLISH_PROTOCOL,
      id: PUBLISH_CHANNEL_ID,
      onopen: () => this.emit('channel-open', { remotePubkey: key }),
      onclose: () => this._onClose(key)
    })
    if (!channel) return false

    const msgHandler = channel.addMessage({
      encoding,
      onmessage: (msg) => this._onMessage(key, msg)
    })

    this.channels.set(key, { channel, msgHandler, pending })
    channel.open()
    return true
  }

  /**
   * Submit a publisher-signed entry over the channel.
   *
   * @param {string} remotePubkey  the relay to submit to
   * @param {string} kind          one of 'intent' | 'commit' | 'source-retired' | 'seed'
   * @param {object} body          the publisher-signed payload — same shape the
   *                               /api/v1/* REST endpoints accept
   * @returns {Promise<{ok, error?, retryable?, result?}>}
   */
  submit (remotePubkey, kind, body) {
    const key = stringifyPubkey(remotePubkey)
    const entry = this.channels.get(key)
    if (!entry) return Promise.reject(new Error(`no publish channel attached to ${key.slice(0, 8)}`))
    if (!SUBMIT_KINDS.has(kind)) return Promise.reject(new Error(`unknown submit kind: ${kind}`))

    const id = this._nextId++
    if (this._nextId >= 0xffffffff) this._nextId = 1
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        entry.pending.delete(id)
        reject(new Error(`submit timeout after ${this._submitTimeoutMs}ms`))
      }, this._submitTimeoutMs)
      entry.pending.set(id, {
        resolve: (res) => { clearTimeout(timer); resolve(res) },
        reject: (err) => { clearTimeout(timer); reject(err) }
      })
      try {
        entry.msgHandler.send({ type: MSG_SUBMIT, id, kind, body })
      } catch (err) {
        clearTimeout(timer)
        entry.pending.delete(id)
        reject(err)
      }
    })
  }

  _onMessage (remotePubkey, msg) {
    if (!msg || msg.type === -1) return
    if (msg.type !== MSG_RESULT) return // SUBMIT inbound on client side is ignored
    const entry = this.channels.get(remotePubkey)
    if (!entry) return
    const waiter = entry.pending.get(msg.id)
    if (!waiter) return
    entry.pending.delete(msg.id)
    waiter.resolve({
      ok: !!msg.ok,
      error: msg.error,
      retryable: msg.retryable === true,
      result: msg.result
    })
  }

  _onClose (remotePubkey) {
    const entry = this.channels.get(remotePubkey)
    if (entry) {
      // Reject any in-flight submits — the channel closed before their result arrived.
      for (const waiter of entry.pending.values()) {
        try { waiter.reject(new Error('publish channel closed before result arrived')) } catch {}
      }
      entry.pending.clear()
    }
    this.channels.delete(remotePubkey)
    this.emit('channel-close', { remotePubkey })
  }

  detach (remotePubkey) {
    const key = stringifyPubkey(remotePubkey)
    const entry = this.channels.get(key)
    if (!entry) return
    try { entry.channel.close() } catch {}
    this._onClose(key)
  }

  destroy () {
    for (const key of [...this.channels.keys()]) this.detach(key)
  }
}

// ── Internal helpers ─────────────────────────────────────────────────────

function stringifyPubkey (pk) {
  if (typeof pk === 'string') return pk
  if (pk && pk.byteLength) return b4a.toString(pk, 'hex')
  return String(pk)
}

function defaultUnsupported (kind) {
  return async () => ({ ok: false, error: `submit kind '${kind}' not configured on this relay`, retryable: false })
}

function normaliseResult (res) {
  if (!res || typeof res !== 'object') return { ok: false, error: 'handler returned non-object result' }
  return {
    ok: !!res.ok,
    error: typeof res.error === 'string' ? res.error : undefined,
    retryable: res.retryable === true ? true : undefined,
    result: res.result !== undefined ? res.result : undefined
  }
}
