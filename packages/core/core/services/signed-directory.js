/**
 * SignedDirectory  (`hiverelay-signed-directory`)
 *
 * An always-on, openly-writable registry of signed records keyed by
 * author pubkey. First consumer: marketplace offer discovery (sellers
 * publish a signed Offer; buyers list + verify). Generic shape so future
 * apps (job boards, file-share directories, signed gossip feeds) can
 * reuse without modification.
 *
 * Trust model — identical to a Hyperswarm topic announce:
 *   - Records are signed over (authorPubkey, timestamp, payload).
 *   - The relay can omit, reorder, delay, or refuse records.
 *   - The relay CANNOT forge records (no private key access).
 *   - Buyers MUST verify signatures + timestamps client-side.
 *
 * Why it exists: topic-swarm announces are ephemeral and pull-only; a
 * client that joins late misses everything. SignedDirectory gives
 * sellers a persistent landing pad (TTL-bounded) so a buyer joining
 * after the seller's announce still sees the offer. Combine with the
 * topic-swarm as a P2P fallback and you get always-on discovery that
 * degrades cleanly when the relay is unreachable.
 *
 * Wire protocol (`hiverelay-signed-directory`):
 *
 *   client → server:
 *     PUBLISH(authorPubkey, timestamp, payload, signature)  // publish a record
 *     LIST_REQ(since)                                       // request all entries newer than `since`
 *
 *   server → client:
 *     STATUS(code, message)                                 // result of PUBLISH or out-of-band signal
 *     LIST_RES(entries[])                                   // response to LIST_REQ
 *     NOTIFY(authorPubkey, timestamp, payload, signature)   // push on new publish
 *
 *   relay ↔ relay (same channel, NOTIFY is the replication primitive):
 *     A receives PUBLISH → A validates + stores → A broadcasts NOTIFY to
 *     every other open channel (including peer relays). Peer relays
 *     receive NOTIFY, validate + store, but do NOT re-broadcast — that
 *     gives single-hop replication with no loops.
 *
 * SECURITY:
 *   - Opt-in (config.signedDirectory.enabled); default off per the same
 *     posture as forwardRelay.
 *   - Per-peer publish rate limit (5/min default), per-record size cap
 *     (8 KB default), per-author cap (1 by default — newest-timestamp-wins),
 *     global entry cap (10k default with TTL-then-LRU eviction), and a
 *     clock-skew tolerance window (±60s default) so a malicious author
 *     can't pre-claim "2099-01-01" and squat their pubkey indefinitely.
 *   - Signature verified via Ed25519 (sodium crypto_sign_verify_detached)
 *     against authorPubkey. No verification of payload semantics — the
 *     relay never knows what an "Offer" is, by design.
 */

import Protomux from 'protomux'
import c from 'compact-encoding'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'

const PROTOCOL_NAME = 'hiverelay-signed-directory'

// Storage policy defaults — see issue #33 + PRODUCTION.md for rationale.
const DEFAULT_MAX_ENTRY_BYTES = 8 * 1024
const DEFAULT_TTL_SECONDS = 24 * 60 * 60
const DEFAULT_MAX_ENTRIES_PER_AUTHOR = 1
const DEFAULT_PUBLISH_RATE_PER_MINUTE = 5
const DEFAULT_MAX_TOTAL_ENTRIES = 10_000
const DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS = 60

// STATUS codes
const OK = 0
const ERR_DISABLED = 1
const ERR_BADREQ = 2
const ERR_BAD_SIGNATURE = 3
const ERR_TOO_LARGE = 4
const ERR_BAD_TIMESTAMP = 5
const ERR_RATE_LIMITED = 6
const ERR_STORAGE_FULL = 7
const ERR_OLDER_THAN_EXISTING = 8

// ── encodings ──────────────────────────────────────────────────────

const entryEncoding = {
  preencode (state, m) {
    c.fixed32.preencode(state, m.authorPubkey)
    c.uint.preencode(state, m.timestamp)
    c.buffer.preencode(state, m.payload)
    c.fixed64.preencode(state, m.signature)
  },
  encode (state, m) {
    c.fixed32.encode(state, m.authorPubkey)
    c.uint.encode(state, m.timestamp)
    c.buffer.encode(state, m.payload)
    c.fixed64.encode(state, m.signature)
  },
  decode (state) {
    return {
      authorPubkey: c.fixed32.decode(state),
      timestamp: c.uint.decode(state),
      payload: c.buffer.decode(state),
      signature: c.fixed64.decode(state)
    }
  }
}

const listReqEncoding = {
  preencode (state, m) { c.uint.preencode(state, m.since || 0) },
  encode (state, m) { c.uint.encode(state, m.since || 0) },
  decode (state) { return { since: c.uint.decode(state) } }
}

const listResEncoding = {
  preencode (state, m) { c.array(entryEncoding).preencode(state, m.entries) },
  encode (state, m) { c.array(entryEncoding).encode(state, m.entries) },
  decode (state) { return { entries: c.array(entryEncoding).decode(state) } }
}

const statusEncoding = {
  preencode (state, m) {
    c.uint.preencode(state, m.code)
    c.string.preencode(state, m.message || '')
  },
  encode (state, m) {
    c.uint.encode(state, m.code)
    c.string.encode(state, m.message || '')
  },
  decode (state) {
    return { code: c.uint.decode(state), message: c.string.decode(state) }
  }
}

// ── signing helpers ────────────────────────────────────────────────

/**
 * Canonical byte-form for signing/verifying a directory entry.
 *
 *   SIGN_OVER = SHA256( authorPubkey || timestamp_LE_8 || payload )
 *
 * The hash gives us a fixed-length signing target regardless of payload
 * size + decouples signature format from wire layout. timestamp is
 * little-endian uint64.
 */
export function entryDigest (authorPubkey, timestamp, payload) {
  const tsBuf = b4a.alloc(8)
  // We only support timestamps up to Number.MAX_SAFE_INTEGER in JS, but
  // an 8-byte LE encoding is what we'd want on the wire anyway.
  const ms = Number(timestamp)
  tsBuf.writeUInt32LE(ms >>> 0, 0)
  tsBuf.writeUInt32LE(Math.floor(ms / 0x100000000) >>> 0, 4)
  const concatenated = b4a.concat([authorPubkey, tsBuf, payload])
  const out = b4a.alloc(32)
  sodium.crypto_hash_sha256(out, concatenated)
  return out
}

/** Sign an entry. Returns a 64-byte detached signature. */
export function signEntry (authorKeyPair, timestamp, payload) {
  const digest = entryDigest(authorKeyPair.publicKey, timestamp, payload)
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, digest, authorKeyPair.secretKey)
  return sig
}

/** Verify an entry's signature. Returns true on valid. */
export function verifyEntry (entry) {
  if (!entry || !entry.authorPubkey || !entry.signature || !entry.payload) return false
  if (entry.authorPubkey.byteLength !== 32) return false
  if (entry.signature.byteLength !== 64) return false
  const digest = entryDigest(entry.authorPubkey, entry.timestamp, entry.payload)
  return sodium.crypto_sign_verify_detached(entry.signature, digest, entry.authorPubkey)
}

// ── authenticated peer pubkey off the noise stream ─────────────────

function remotePubOf (channel) {
  if (channel && channel._mux && channel._mux.stream && channel._mux.stream.remotePublicKey) {
    return channel._mux.stream.remotePublicKey
  }
  if (channel && channel.stream && channel.stream.remotePublicKey) {
    return channel.stream.remotePublicKey
  }
  return null
}

// ── service ────────────────────────────────────────────────────────

export class SignedDirectory extends EventEmitter {
  constructor (swarm, opts = {}) {
    super()
    this.swarm = swarm
    this.enabled = opts.enabled !== false
    this.maxEntryBytes = Number.isFinite(opts.maxEntryBytes) ? opts.maxEntryBytes : DEFAULT_MAX_ENTRY_BYTES
    this.ttlSeconds = Number.isFinite(opts.ttlSeconds) ? opts.ttlSeconds : DEFAULT_TTL_SECONDS
    this.maxEntriesPerAuthor = Number.isFinite(opts.maxEntriesPerAuthor) ? opts.maxEntriesPerAuthor : DEFAULT_MAX_ENTRIES_PER_AUTHOR
    this.publishRatePerMinute = Number.isFinite(opts.publishRatePerMinute) ? opts.publishRatePerMinute : DEFAULT_PUBLISH_RATE_PER_MINUTE
    this.maxTotalEntries = Number.isFinite(opts.maxTotalEntries) ? opts.maxTotalEntries : DEFAULT_MAX_TOTAL_ENTRIES
    this.clockSkewToleranceSeconds = Number.isFinite(opts.clockSkewToleranceSeconds) ? opts.clockSkewToleranceSeconds : DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS

    // Storage: authorPubkeyHex -> { authorPubkey, timestamp, payload, signature, receivedAt }
    // v1 is in-memory only. Short TTL + cross-relay replication makes
    // single-relay persistence less critical. v2 (Hyperbee-backed)
    // is tracked in #33 follow-ups.
    this._entries = new Map()

    // Per-peer publish rate-limit tracking: peerHex -> [recent attempt ms]
    this._publishAttempts = new Map()

    // Open channels (for NOTIFY broadcast on local publish)
    this._channels = new Set()

    this.stats = {
      totalPublished: 0,
      totalRejected: 0,
      totalReplicated: 0,
      totalEvicted: 0,
      rejectedReasons: {}
    }

    this._cleanupInterval = setInterval(() => this._cleanupExpired(), 60_000)
    if (this._cleanupInterval && this._cleanupInterval.unref) this._cleanupInterval.unref()
  }

  /** Attach the directory protocol to a Hyperswarm connection. */
  attach (conn) {
    const mux = Protomux.from(conn)
    const channel = mux.createChannel({
      protocol: PROTOCOL_NAME,
      id: null,
      onclose: () => this._channels.delete(channel)
    })
    const statusMsg = channel.addMessage({ encoding: statusEncoding })
    const listResMsg = channel.addMessage({ encoding: listResEncoding })
    const notifyMsg = channel.addMessage({
      encoding: entryEncoding,
      onmessage: (m) => this._onNotify(channel, m)
    })
    const publishMsg = channel.addMessage({
      encoding: entryEncoding,
      onmessage: (m) => this._onPublish(channel, m)
    })
    const listReqMsg = channel.addMessage({
      encoding: listReqEncoding,
      onmessage: (m) => this._onListReq(channel, m)
    })

    channel._directory = { statusMsg, listResMsg, notifyMsg, publishMsg, listReqMsg }
    channel.open()
    this._channels.add(channel)
    return channel
  }

  // ── handlers ─────────────────────────────────────────────────────

  _onPublish (channel, entry) {
    if (!this.enabled) {
      this._reject(channel, ERR_DISABLED, 'directory disabled')
      return
    }
    const peer = remotePubOf(channel)
    const peerHex = peer ? b4a.toString(peer, 'hex') : null
    const result = this._tryStore(entry, { peerHex, source: 'publish' })
    if (!result.ok) {
      this._reject(channel, result.code, result.message)
      return
    }
    this._respondStatus(channel, OK, 'stored')
    // Broadcast to all OTHER open channels — single-hop replication.
    this._broadcastNotify(entry, channel)
  }

  _onNotify (channel, entry) {
    if (!this.enabled) return
    // NOTIFY is the relay-to-relay replication path. Same validation as
    // PUBLISH, but we don't re-broadcast (single-hop only) and we don't
    // apply the per-peer rate limit (peer relays legitimately push many
    // entries — the limit is for client publishers, not for replication).
    const peer = remotePubOf(channel)
    const peerHex = peer ? b4a.toString(peer, 'hex') : null
    const result = this._tryStore(entry, {
      peerHex,
      source: 'notify',
      skipRateLimit: true
    })
    if (result.ok && result.stored) {
      this.stats.totalReplicated++
    }
    // We deliberately don't respond on NOTIFY — it's a push, fire and
    // forget. If we did want acks we'd add a separate ACK message type.
  }

  _onListReq (channel, msg) {
    if (!this.enabled) {
      this._respondStatus(channel, ERR_DISABLED, 'directory disabled')
      return
    }
    const since = (msg && msg.since) || 0
    const now = Math.floor(Date.now() / 1000)
    const entries = []
    for (const e of this._entries.values()) {
      if (e.timestamp < since) continue
      if ((now - e.timestamp) > this.ttlSeconds) continue
      entries.push({
        authorPubkey: e.authorPubkey,
        timestamp: e.timestamp,
        payload: e.payload,
        signature: e.signature
      })
    }
    this._respondListRes(channel, entries)
  }

  // ── core storage logic ───────────────────────────────────────────

  /**
   * Try to store an entry. Returns { ok, code?, message?, stored? }.
   * `stored` is true if the entry actually replaced/added something;
   * false if we accepted but it was older than what we already have.
   *
   * `opts.source` is 'publish' (from client) or 'notify' (from peer relay);
   * `opts.skipRateLimit` lets NOTIFY bypass the per-peer rate (relays
   * legitimately push many).
   */
  _tryStore (entry, opts = {}) {
    // 1. Shape validation
    if (!entry || !entry.authorPubkey || !entry.payload || !entry.signature) {
      this._countReject('BADREQ')
      return { ok: false, code: ERR_BADREQ, message: 'missing field' }
    }
    if (entry.authorPubkey.byteLength !== 32) {
      this._countReject('BADREQ')
      return { ok: false, code: ERR_BADREQ, message: 'authorPubkey must be 32 bytes' }
    }

    // 2. Size cap
    if (entry.payload.byteLength > this.maxEntryBytes) {
      this._countReject('TOO_LARGE')
      return { ok: false, code: ERR_TOO_LARGE, message: 'entry exceeds maxEntryBytes' }
    }

    // 3. Timestamp / clock skew validation
    const now = Math.floor(Date.now() / 1000)
    if (!Number.isFinite(entry.timestamp) || entry.timestamp <= 0) {
      this._countReject('BAD_TIMESTAMP')
      return { ok: false, code: ERR_BAD_TIMESTAMP, message: 'timestamp invalid' }
    }
    if (entry.timestamp - now > this.clockSkewToleranceSeconds) {
      this._countReject('BAD_TIMESTAMP_FUTURE')
      return { ok: false, code: ERR_BAD_TIMESTAMP, message: 'timestamp too far in the future' }
    }
    // Reject entries already expired by TTL on arrival (don't admit dead-on-arrival).
    if (now - entry.timestamp > this.ttlSeconds) {
      this._countReject('BAD_TIMESTAMP_EXPIRED')
      return { ok: false, code: ERR_BAD_TIMESTAMP, message: 'timestamp older than TTL' }
    }

    // 4. Signature
    if (!verifyEntry(entry)) {
      this._countReject('BAD_SIGNATURE')
      return { ok: false, code: ERR_BAD_SIGNATURE, message: 'signature verification failed' }
    }

    // 5. Per-peer publish rate limit (only for PUBLISH path; NOTIFY skips).
    if (!opts.skipRateLimit && opts.peerHex) {
      const arr = this._publishAttempts.get(opts.peerHex) || []
      const recent = arr.filter((t) => now * 1000 - t < 60_000)
      if (recent.length >= this.publishRatePerMinute) {
        this._countReject('RATE_LIMITED')
        return { ok: false, code: ERR_RATE_LIMITED, message: 'publish rate exceeded' }
      }
      recent.push(Date.now())
      this._publishAttempts.set(opts.peerHex, recent)
    }

    // 6. Newest-timestamp-wins per author. With maxEntriesPerAuthor=1
    //    (the v1 default) we simply overwrite if newer.
    const authorHex = b4a.toString(entry.authorPubkey, 'hex')
    const existing = this._entries.get(authorHex)
    if (existing && existing.timestamp >= entry.timestamp) {
      // Idempotent: we accept the publish but don't replace older record.
      // Returning ok:true, stored:false so the client gets a positive
      // ack (the directory's state already matches their intent).
      return { ok: true, stored: false }
    }

    // 7. Global cap with TTL-oldest-first eviction.
    if (!existing && this._entries.size >= this.maxTotalEntries) {
      const evicted = this._evictOneByTtl(now)
      if (!evicted) {
        this._countReject('STORAGE_FULL')
        return { ok: false, code: ERR_STORAGE_FULL, message: 'storage at capacity' }
      }
    }

    // 8. Store
    this._entries.set(authorHex, {
      authorPubkey: entry.authorPubkey,
      timestamp: entry.timestamp,
      payload: entry.payload,
      signature: entry.signature,
      receivedAt: Date.now()
    })

    this.stats.totalPublished++
    this.emit('entry-stored', { authorHex, timestamp: entry.timestamp, source: opts.source })
    return { ok: true, stored: true }
  }

  _evictOneByTtl (now) {
    // Find the entry with the smallest timestamp (oldest by author clock,
    // which is what TTL is measured against). Tie-broken by receivedAt
    // (oldest delivery wins).
    let oldestKey = null
    let oldestTs = Infinity
    let oldestRecv = Infinity
    for (const [k, e] of this._entries) {
      if (e.timestamp < oldestTs || (e.timestamp === oldestTs && e.receivedAt < oldestRecv)) {
        oldestTs = e.timestamp
        oldestRecv = e.receivedAt
        oldestKey = k
      }
    }
    if (oldestKey) {
      this._entries.delete(oldestKey)
      this.stats.totalEvicted++
      this.emit('entry-evicted', { authorHex: oldestKey, reason: 'capacity' })
      return true
    }
    return false
  }

  _cleanupExpired () {
    const now = Math.floor(Date.now() / 1000)
    let removed = 0
    for (const [k, e] of this._entries) {
      if (now - e.timestamp > this.ttlSeconds) {
        this._entries.delete(k)
        removed++
      }
    }
    if (removed > 0) {
      this.stats.totalEvicted += removed
      this.emit('entries-expired', { count: removed })
    }
    // Prune the publish-attempt buckets too.
    const nowMs = Date.now()
    for (const [peerHex, arr] of this._publishAttempts) {
      const recent = arr.filter((t) => nowMs - t < 60_000)
      if (recent.length === 0) this._publishAttempts.delete(peerHex)
      else this._publishAttempts.set(peerHex, recent)
    }
  }

  _broadcastNotify (entry, sourceChannel) {
    for (const ch of this._channels) {
      if (ch === sourceChannel) continue
      if (!ch.opened || !ch._directory) continue
      try { ch._directory.notifyMsg.send(entry) } catch (_) {}
    }
  }

  // ── helpers ──────────────────────────────────────────────────────

  _reject (channel, code, message) {
    this.stats.totalRejected++
    this._respondStatus(channel, code, message)
  }

  _respondStatus (channel, code, message) {
    if (channel.opened && channel._directory) {
      try { channel._directory.statusMsg.send({ code, message }) } catch (_) {}
    }
  }

  _respondListRes (channel, entries) {
    if (channel.opened && channel._directory) {
      try { channel._directory.listResMsg.send({ entries }) } catch (_) {}
    }
  }

  _countReject (reason) {
    this.stats.totalRejected++
    this.stats.rejectedReasons[reason] = (this.stats.rejectedReasons[reason] || 0) + 1
  }

  // ── direct API (used by tests + by future buyer/seller adapters) ─

  /**
   * Direct publish — same validation path as the wire protocol, no
   * per-peer rate limit since there's no peer.
   */
  publishLocal (entry) {
    return this._tryStore(entry, { source: 'publish-local', skipRateLimit: true })
  }

  /** Snapshot of all non-expired entries. */
  list () {
    const now = Math.floor(Date.now() / 1000)
    const out = []
    for (const e of this._entries.values()) {
      if ((now - e.timestamp) > this.ttlSeconds) continue
      out.push({
        authorPubkey: e.authorPubkey,
        timestamp: e.timestamp,
        payload: e.payload,
        signature: e.signature
      })
    }
    return out
  }

  getStats () {
    return {
      enabled: this.enabled,
      entries: this._entries.size,
      maxTotalEntries: this.maxTotalEntries,
      attachedChannels: this._channels.size,
      ttlSeconds: this.ttlSeconds,
      ...this.stats
    }
  }

  destroy () {
    if (this._cleanupInterval) {
      clearInterval(this._cleanupInterval)
      this._cleanupInterval = null
    }
    this._entries.clear()
    this._publishAttempts.clear()
    this._channels.clear()
  }
}

// Status-code constants surfaced for buyer/seller adapters that want to
// branch on specific failure reasons.
export const STATUS = {
  OK,
  ERR_DISABLED,
  ERR_BADREQ,
  ERR_BAD_SIGNATURE,
  ERR_TOO_LARGE,
  ERR_BAD_TIMESTAMP,
  ERR_RATE_LIMITED,
  ERR_STORAGE_FULL,
  ERR_OLDER_THAN_EXISTING
}

export default SignedDirectory
