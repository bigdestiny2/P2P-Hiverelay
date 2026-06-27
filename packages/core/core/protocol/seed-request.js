/**
 * Seed Request Protocol
 *
 * Handles publishing and accepting seed requests over protomux channels.
 * Publishers request relays to seed their Hypercores/Hyperdrives.
 * Relays discover and accept requests matching their capacity.
 */

import Protomux from 'protomux'
import c from 'compact-encoding'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { EventEmitter } from 'events'
import {
  seedRequestEncoding,
  seedAcceptEncoding,
  unseedRequestEncoding,
  seedDenyEncoding
} from './messages.js'
import { TokenBucketRateLimiter } from './rate-limiter.js'
import { SEED_PROTOCOL_NAME } from '../constants.js'

const PROTOCOL_VERSION = { major: 1, minor: 0 }
const MAX_PROTOCOL_HANDSHAKE_BYTES = 256

// Rate limit: 100 requests per minute, burst of 20
const RATE_LIMIT_TOKENS_PER_MIN = 100
const RATE_LIMIT_BURST = 20

// All-zero buffer check — fixed-width wire fields use zero-fill to mean
// "absent" (e.g. an unsigned relaySignature from a keyPair-less node).
function isZeroBuf (buf) {
  if (!buf || !b4a.isBuffer(buf)) return true
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) return false
  }
  return true
}

function keyHex (key) {
  return key && key.byteLength === 32 ? b4a.toString(key, 'hex') : null
}

function parseProtocolHandshake (handshake) {
  if (!handshake) return { remote: null }
  const size = typeof handshake === 'string'
    ? b4a.byteLength(handshake)
    : (handshake && Number.isSafeInteger(handshake.byteLength) ? handshake.byteLength : 0)
  if (size <= 0) return { error: 'malformed handshake' }
  if (size > MAX_PROTOCOL_HANDSHAKE_BYTES) return { error: 'handshake too large' }

  let remote
  try {
    const text = typeof handshake === 'string' ? handshake : b4a.toString(handshake)
    remote = JSON.parse(text)
  } catch {
    return { error: 'malformed handshake' }
  }

  if (!remote || typeof remote !== 'object' || Array.isArray(remote) ||
      !Number.isSafeInteger(remote.major) || remote.major < 0 ||
      !Number.isSafeInteger(remote.minor) || remote.minor < 0) {
    return { error: 'malformed handshake' }
  }

  return {
    remote: {
      major: remote.major,
      minor: remote.minor
    }
  }
}

export class SeedProtocol extends EventEmitter {
  constructor (swarm, opts = {}) {
    super()
    this.swarm = swarm
    this.keyPair = opts.keyPair || null
    this.pendingRequests = new Map() // appKey hex -> seed request
    this.acceptedSeeds = new Map() // appKey hex -> { relay pubkey, accepted at }
    this.channels = new Set()
    this._maxPendingRequests = opts.maxPendingRequests || 1000
    this._pendingTTL = opts.pendingTTL || 30 * 60 * 1000 // 30 min default
    this._pendingCleanup = setInterval(() => this._evictStalePending(), 60_000)
    if (this._pendingCleanup.unref) this._pendingCleanup.unref()
    this._seenUnseedNonces = new Map() // dedup key -> timestamp
    this._unseedNonceCleanup = setInterval(() => this._evictStaleNonces(), 60_000)
    if (this._unseedNonceCleanup.unref) this._unseedNonceCleanup.unref()
    this.rateLimiter = new TokenBucketRateLimiter({
      tokensPerMinute: opts.rateLimitTokens || RATE_LIMIT_TOKENS_PER_MIN,
      burstSize: opts.rateLimitBurst || RATE_LIMIT_BURST
    })
  }

  /**
   * Attach the seed protocol to a Hyperswarm connection
   */
  attach (conn) {
    const mux = Protomux.from(conn)

    const channel = mux.createChannel({
      protocol: SEED_PROTOCOL_NAME,
      id: null,
      handshake: c.raw,
      onopen: () => this._onOpen(channel),
      onclose: () => this._onClose(channel)
    })

    const seedRequestMsg = channel.addMessage({
      encoding: seedRequestEncoding,
      onmessage: (msg) => this._onSeedRequest(channel, msg)
    })

    const seedAcceptMsg = channel.addMessage({
      encoding: seedAcceptEncoding,
      onmessage: (msg) => this._onSeedAccept(channel, msg)
    })

    const unseedRequestMsg = channel.addMessage({
      encoding: unseedRequestEncoding,
      onmessage: (msg) => this._onUnseedRequest(channel, msg)
    })

    // 4th message — added after unseedRequest so the wire ids of the first
    // three stay stable. Peers that predate seedDeny drop unknown ids
    // (protomux _recv ignores type >= messages.length), degrading to the
    // old behavior: timeout.
    const seedDenyMsg = channel.addMessage({
      encoding: seedDenyEncoding,
      onmessage: (msg) => this._onSeedDeny(channel, msg)
    })

    channel._hiverelay = { seedRequestMsg, seedAcceptMsg, unseedRequestMsg, seedDenyMsg }
    channel.open(b4a.from(JSON.stringify(PROTOCOL_VERSION)))

    this.channels.add(channel)
    return channel
  }

  /**
   * Publish a seed request to connected relays
   *
   * `request.delegationCert` (optional) — if the publisher is a secondary device
   * acting on behalf of a primary identity, this object carries the chain of
   * authority. Verifiers (relays) check it via `verifyDelegationCert`. The cert
   * is attached as an in-memory pass-through and travels alongside the request
   * when consumers serialize the request via JSON; the binary protomux
   * encoding does not include it (yet), so wire-level transport will arrive in
   * a follow-up. Keeping the field on the object today preserves the API
   * contract for callers that publish via the registry (JSON storage).
   */
  publishSeedRequest (request) {
    const appKeyHex = b4a.toString(request.appKey, 'hex')

    // Sign the request
    if (this.keyPair) {
      const payload = this._serializeForSigning(request)
      request.publisherPubkey = this.keyPair.publicKey
      request.publisherSignature = b4a.alloc(64)
      sodium.crypto_sign_detached(request.publisherSignature, payload, this.keyPair.secretKey)
    }

    if (this.pendingRequests.size >= this._maxPendingRequests) {
      // Evict oldest entry
      const oldest = this.pendingRequests.keys().next().value
      this.pendingRequests.delete(oldest)
    }
    request._addedAt = Date.now()
    this.pendingRequests.set(appKeyHex, request)

    // Broadcast to all connected channels
    for (const channel of this.channels) {
      if (channel.opened && channel._hiverelay) {
        channel._hiverelay.seedRequestMsg.send(request)
      }
    }

    this.emit('request-published', { appKey: appKeyHex })
  }

  /**
   * Accept a seed request (called by relay nodes)
   */
  acceptSeedRequest (appKey, relayPubkey, region, availableStorage) {
    const acceptance = {
      appKey,
      relayPubkey,
      region,
      availableStorageBytes: availableStorage,
      relaySignature: b4a.alloc(64)
    }

    if (this.keyPair) {
      const payload = b4a.concat([appKey, relayPubkey, b4a.from(region)])
      sodium.crypto_sign_detached(acceptance.relaySignature, payload, this.keyPair.secretKey)
    }

    for (const channel of this.channels) {
      if (channel.opened && channel._hiverelay) {
        channel._hiverelay.seedAcceptMsg.send(acceptance)
      }
    }

    this.emit('request-accepted', {
      appKey: b4a.toString(appKey, 'hex'),
      relay: b4a.toString(relayPubkey, 'hex')
    })
  }

  /**
   * Publish an unseed request to connected relays (developer kill switch)
   */
  publishUnseedRequest (appKey, publisherPubkey, publisherSignature, timestamp) {
    const request = {
      appKey,
      timestamp: timestamp || Date.now(),
      publisherPubkey,
      publisherSignature
    }

    for (const channel of this.channels) {
      if (channel.opened && channel._hiverelay) {
        channel._hiverelay.unseedRequestMsg.send(request)
      }
    }

    this.emit('unseed-published', { appKey: b4a.toString(appKey, 'hex') })
  }

  _onUnseedRequest (channel, msg) {
    if (!msg || msg.error) {
      this.emit('invalid-unseed', { appKey: keyHex(msg && msg.appKey), reason: msg && msg.error ? msg.error : 'malformed unseed request' })
      return
    }

    const peerKey = channel.stream && channel.stream.remotePublicKey
      ? b4a.toString(channel.stream.remotePublicKey, 'hex')
      : 'unknown'

    // Rate limit
    const rateCheck = this.rateLimiter.check(peerKey)
    if (!rateCheck.allowed) return

    // Verify signature: publisher signs (appKey + 'unseed' + timestamp)
    if (!this._verifyUnseedSignature(msg)) {
      this.emit('invalid-unseed', { appKey: keyHex(msg.appKey), reason: 'bad signature' })
      return
    }

    // Check timestamp freshness (reject if older than 5 minutes)
    const age = Date.now() - msg.timestamp
    if (age > 5 * 60 * 1000 || age < -60_000) {
      this.emit('invalid-unseed', { appKey: b4a.toString(msg.appKey, 'hex'), reason: 'stale timestamp' })
      return
    }

    // Replay protection: use signature as unique nonce (unique per request)
    const dedupKey = b4a.toString(msg.publisherSignature, 'hex')
    if (this._seenUnseedNonces.has(dedupKey)) {
      return // silently drop replay
    }
    this._seenUnseedNonces.set(dedupKey, Date.now())

    this.emit('unseed-request', msg)
  }

  _verifyUnseedSignature (msg) {
    if (!msg || !msg.appKey || msg.appKey.byteLength !== 32 ||
        !Number.isSafeInteger(msg.timestamp) || msg.timestamp < 0 ||
        !msg.publisherPubkey || msg.publisherPubkey.byteLength !== 32 ||
        !msg.publisherSignature || msg.publisherSignature.byteLength !== 64) return false
    const payload = b4a.concat([
      msg.appKey,
      b4a.from('unseed'),
      this._uint64Buf(msg.timestamp)
    ])
    return sodium.crypto_sign_verify_detached(msg.publisherSignature, payload, msg.publisherPubkey)
  }

  _uint64Buf (n) {
    const buf = b4a.alloc(8)
    const view = new DataView(buf.buffer, buf.byteOffset)
    view.setBigUint64(0, BigInt(n))
    return buf
  }

  _onSeedRequest (channel, msg) {
    if (!msg || msg.error) {
      this.emit('invalid-request', {
        appKey: keyHex(msg && msg.appKey),
        reason: msg && msg.error ? msg.error : 'malformed seed request',
        reasonCode: 'malformed-seed-request'
      })
      return
    }

    // Get peer key for rate limiting
    const peerKey = channel.stream && channel.stream.remotePublicKey
      ? b4a.toString(channel.stream.remotePublicKey, 'hex')
      : 'unknown'

    // Check rate limit. Deliberately NO deny reply here — answering
    // rate-limited peers would hand them response amplification.
    const rateCheck = this.rateLimiter.check(peerKey)
    if (!rateCheck.allowed) {
      if (rateCheck.banned) {
        this.emit('rate-limit-exceeded', { peer: peerKey, banned: true, until: rateCheck.bannedUntil })
      }
      return
    }

    // Verify publisher signature. Silent denial is hostile — the publisher
    // would just time out — so tell them WHY, with the archive-tier case
    // called out specifically (durability ≥ 1 is only committable via a v2
    // publisher signature; see verifySeedRequestSignature's v1 rejection).
    if (!this._verifyRequestSignature(msg)) {
      const isArchive = Number.isFinite(msg.durability) && msg.durability > 0
      const missingSig = !msg.publisherPubkey || !msg.publisherSignature ||
        !b4a.isBuffer(msg.publisherSignature) || isZeroBuf(msg.publisherSignature)
      let reasonCode
      let detail
      if (isArchive && missingSig) {
        reasonCode = 'archive-requires-publisher-signature'
        detail = 'durability ' + msg.durability + ' (archive tier) requires a v2 publisher-signed seed request; bare-key requests can only be pinned by the relay operator via the authenticated /seed API'
      } else if (missingSig) {
        reasonCode = 'signature-required'
        detail = 'seed requests over this channel must be publisher-signed'
      } else {
        reasonCode = 'bad-signature'
        detail = isArchive
          ? 'signature did not verify; note archive tier (durability ≥ 1) requires the v2 signing layout'
          : 'publisher signature did not verify'
      }
      this.emit('invalid-request', { appKey: b4a.toString(msg.appKey, 'hex'), reason: 'bad signature', reasonCode })
      this.denySeedRequest(channel, msg.appKey, reasonCode, detail)
      return
    }

    // Pass the channel along so the node-level handler (capacity,
    // accept-mode, delegation checks) can reply with a deny reason too.
    this.emit('seed-request', msg, channel)
  }

  /**
   * Send a signed deny (or queued-for-review notice) back on the channel a
   * seed request arrived on. Best-effort: never throws, never broadcasts.
   */
  denySeedRequest (channel, appKey, reasonCode, detail = '') {
    try {
      if (!channel || !channel.opened || !channel._hiverelay || !channel._hiverelay.seedDenyMsg) return false
      const relayPubkey = this.keyPair ? this.keyPair.publicKey : b4a.alloc(32)
      const deny = {
        appKey,
        relayPubkey,
        reasonCode: String(reasonCode).slice(0, 128),
        detail: String(detail || '').slice(0, 512),
        relaySignature: b4a.alloc(64)
      }
      if (this.keyPair) {
        const payload = b4a.concat([appKey, relayPubkey, b4a.from(deny.reasonCode)])
        sodium.crypto_sign_detached(deny.relaySignature, payload, this.keyPair.secretKey)
      }
      channel._hiverelay.seedDenyMsg.send(deny)
      this.emit('request-denied', {
        appKey: b4a.toString(appKey, 'hex'),
        reasonCode: deny.reasonCode
      })
      return true
    } catch (_) {
      return false
    }
  }

  _onSeedDeny (channel, msg) {
    if (!msg || msg.error) {
      this.emit('invalid-deny', { appKey: keyHex(msg && msg.appKey), reason: msg && msg.error ? msg.error : 'malformed seed deny' })
      return
    }

    const peerKey = channel.stream && channel.stream.remotePublicKey
      ? b4a.toString(channel.stream.remotePublicKey, 'hex')
      : 'unknown'

    const rateCheck = this.rateLimiter.check(peerKey)
    if (!rateCheck.allowed) return

    // Anti-spoof: the deny must claim the pubkey of the peer that sent it.
    // The noise stream authenticates the remote key, so a relay can only
    // deny on its own behalf — never forge denials from other relays.
    if (channel.stream && channel.stream.remotePublicKey &&
        !b4a.equals(msg.relayPubkey, channel.stream.remotePublicKey)) {
      this.emit('invalid-deny', { appKey: keyHex(msg.appKey), reason: 'relayPubkey mismatch' })
      return
    }

    // Verify the relay signature when one is present (all-zero = unsigned,
    // allowed only so keyPair-less test relays still interoperate).
    if (!isZeroBuf(msg.relaySignature)) {
      const payload = b4a.concat([msg.appKey, msg.relayPubkey, b4a.from(msg.reasonCode)])
      if (!sodium.crypto_sign_verify_detached(msg.relaySignature, payload, msg.relayPubkey)) {
        this.emit('invalid-deny', { appKey: keyHex(msg.appKey), reason: 'bad signature' })
        return
      }
    }

    this.emit('seed-denied', {
      appKey: b4a.toString(msg.appKey, 'hex'),
      relay: b4a.toString(msg.relayPubkey, 'hex'),
      reasonCode: msg.reasonCode,
      detail: msg.detail || '',
      terminal: msg.reasonCode !== 'queued-for-review'
    })
  }

  _onSeedAccept (channel, msg) {
    if (!msg || msg.error) {
      this.emit('invalid-accept', { appKey: keyHex(msg && msg.appKey), reason: msg && msg.error ? msg.error : 'malformed seed accept' })
      return
    }

    // Get peer key for rate limiting
    const peerKey = channel.stream && channel.stream.remotePublicKey
      ? b4a.toString(channel.stream.remotePublicKey, 'hex')
      : 'unknown'

    // Check rate limit
    const rateCheck = this.rateLimiter.check(peerKey)
    if (!rateCheck.allowed) {
      if (rateCheck.banned) {
        this.emit('rate-limit-exceeded', { peer: peerKey, banned: true, until: rateCheck.bannedUntil })
      }
      return
    }

    // Verify relay signature before processing acceptance
    if (!this._verifyAcceptSignature(msg)) {
      this.emit('invalid-accept', { appKey: keyHex(msg.appKey), reason: 'bad signature' })
      return
    }

    const appKeyHex = b4a.toString(msg.appKey, 'hex')
    this.acceptedSeeds.set(appKeyHex, {
      relayPubkey: msg.relayPubkey,
      region: msg.region,
      acceptedAt: Date.now()
    })

    this.emit('seed-accepted', msg)
  }

  _onOpen (channel) {
    // Validate protocol version from handshake
    if (channel.handshake) {
      const parsed = parseProtocolHandshake(channel.handshake)
      if (parsed.error) {
        this.emit('invalid-handshake', { reason: parsed.error })
        channel.close()
        return
      }
      if (parsed.remote && parsed.remote.major !== PROTOCOL_VERSION.major) {
        this.emit('version-mismatch', { local: PROTOCOL_VERSION, remote: parsed.remote })
        channel.close()
        return
      }
    }

    this.emit('channel-open', channel)

    // Send all pending requests to newly connected peer
    for (const request of this.pendingRequests.values()) {
      if (channel._hiverelay) {
        channel._hiverelay.seedRequestMsg.send(request)
      }
    }
  }

  _onClose (channel) {
    this.channels.delete(channel)
    this.emit('channel-close', channel)
  }

  _verifyRequestSignature (msg) {
    return verifySeedRequestSignature(msg)
  }

  _verifyAcceptSignature (msg) {
    if (!msg || !msg.appKey || msg.appKey.byteLength !== 32 ||
        !msg.relayPubkey || msg.relayPubkey.byteLength !== 32 ||
        typeof msg.region !== 'string' ||
        !msg.relaySignature || msg.relaySignature.byteLength !== 64) return false
    const payload = b4a.concat([msg.appKey, msg.relayPubkey, b4a.from(msg.region)])
    return sodium.crypto_sign_verify_detached(msg.relaySignature, payload, msg.relayPubkey)
  }

  _serializeForSigning (msg) {
    return serializeSeedRequestForSigning(msg)
  }

  _serializeForSigningLegacy (msg) {
    return serializeSeedRequestForSigningLegacy(msg)
  }

  _evictStaleNonces () {
    const now = Date.now()
    for (const [key, ts] of this._seenUnseedNonces) {
      if (now - ts > 6 * 60 * 1000) {
        this._seenUnseedNonces.delete(key)
      }
    }
  }

  _evictStalePending () {
    const now = Date.now()
    for (const [key, req] of this.pendingRequests) {
      const age = now - (req._addedAt || 0)
      if (age > this._pendingTTL) this.pendingRequests.delete(key)
    }
  }

  destroy () {
    clearInterval(this._pendingCleanup)
    clearInterval(this._unseedNonceCleanup)
    this._seenUnseedNonces.clear()
    for (const channel of this.channels) {
      channel.close()
    }
    this.channels.clear()
    this.pendingRequests.clear()
    this.acceptedSeeds.clear()
    this.rateLimiter.destroy()
  }
}

/**
 * Canonical v2 serialization of a seed request for publisher signing.
 *
 * Layout (40 bytes after appKey + hash(discoveryKeys)):
 *   [0]      replicationFactor (uint8)
 *   [1]      revocable flag    (uint8: 1=revocable, 0=non-revocable)
 *   [2]      durability tier   (uint8: 0=standard, 1=archive, ...)
 *   [3..7]   reserved          (zeros for forward-compat)
 *   [8..15]  maxStorageBytes   (uint64 BE)
 *   [16..23] ttlSeconds        (uint64 BE)
 *   [24..27] bountyRate        (uint32 BE)
 *   [28..35] unseedFreezeMs    (uint64 BE)
 *   [36..39] reserved          (zeros)
 *
 * Bytes 0..27 match the original v1 layout — older verifiers that only
 * read 28 bytes still see the same prefix. Older publishers omit the
 * trailing bytes entirely; verifySeedRequestSignature falls back to v1
 * (28-byte) verification when the request advertised the permissive
 * defaults.
 *
 * Exported so the REST layer (api.js /api/v1/seed) can verify
 * publisher-signed seed requests without instantiating SeedProtocol.
 */
export function serializeSeedRequestForSigning (msg) {
  const parts = [msg.appKey]

  const discoveryKeysHash = b4a.alloc(32)
  if (msg.discoveryKeys && msg.discoveryKeys.length > 0) {
    const dkConcat = b4a.concat(msg.discoveryKeys)
    sodium.crypto_generichash(discoveryKeysHash, dkConcat)
  }
  parts.push(discoveryKeysHash)

  const meta = b4a.alloc(40)
  const view = new DataView(meta.buffer, meta.byteOffset)
  view.setUint8(0, msg.replicationFactor)
  view.setUint8(1, msg.revocable === false ? 0 : 1)
  view.setUint8(2, msg.durability || 0)
  view.setBigUint64(8, BigInt(msg.maxStorageBytes))
  view.setBigUint64(16, BigInt(msg.ttlSeconds))
  view.setUint32(24, msg.bountyRate || 0)
  view.setBigUint64(28, BigInt(msg.unseedFreezeMs || 0))
  parts.push(meta)
  return b4a.concat(parts)
}

/**
 * Legacy v1 (28-byte) serialization. Kept for backward compatibility — used
 * by verifySeedRequestSignature as a fallback when the v2 verify fails AND
 * the request advertised permissive defaults.
 */
export function serializeSeedRequestForSigningLegacy (msg) {
  const parts = [msg.appKey]
  const discoveryKeysHash = b4a.alloc(32)
  if (msg.discoveryKeys && msg.discoveryKeys.length > 0) {
    const dkConcat = b4a.concat(msg.discoveryKeys)
    sodium.crypto_generichash(discoveryKeysHash, dkConcat)
  }
  parts.push(discoveryKeysHash)
  const meta = b4a.alloc(28)
  const view = new DataView(meta.buffer, meta.byteOffset)
  view.setUint8(0, msg.replicationFactor)
  view.setBigUint64(8, BigInt(msg.maxStorageBytes))
  view.setBigUint64(16, BigInt(msg.ttlSeconds))
  view.setUint32(24, msg.bountyRate || 0)
  parts.push(meta)
  return b4a.concat(parts)
}

/**
 * Verify a seed request's publisher signature.
 *
 * `msg` must have publisherPubkey (Buffer 32) + publisherSignature
 * (Buffer 64) + the seed-request fields covered by the canonical
 * serialization (appKey, discoveryKeys[], replicationFactor,
 * maxStorageBytes, ttlSeconds, bountyRate, and optionally revocable,
 * unseedFreezeMs, durability).
 *
 * Returns true if the v2 layout verifies, OR if the v1 (legacy) layout
 * verifies AND the request advertised the permissive defaults — same
 * back-compat behavior the Protomux protocol uses.
 *
 * Exported so the REST layer (api.js /api/v1/seed) can verify
 * publisher-signed seed requests without instantiating SeedProtocol.
 */
export function verifySeedRequestSignature (msg) {
  if (!msg || !msg.publisherPubkey || !msg.publisherSignature) return false

  const v2 = serializeSeedRequestForSigning(msg)
  if (sodium.crypto_sign_verify_detached(msg.publisherSignature, v2, msg.publisherPubkey)) {
    return true
  }

  // v1 fallback: only allowed when the request claims the permissive
  // defaults. A v1 signature CANNOT legitimately commit to non-default
  // revocability/freeze/durability — claiming those with a v1-shaped
  // signature is a protocol violation and we reject.
  if (msg.revocable === false ||
      (msg.unseedFreezeMs && msg.unseedFreezeMs > 0) ||
      (msg.durability && msg.durability > 0)) {
    return false
  }
  const v1 = serializeSeedRequestForSigningLegacy(msg)
  return sodium.crypto_sign_verify_detached(msg.publisherSignature, v1, msg.publisherPubkey)
}
