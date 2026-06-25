import { sanitizeReputationRecord } from './api-reputation-read.js'
import { redactPubkeyHex } from '../privacy.js'

export const MAX_PEER_LIST_ENTRIES = 1000

export function buildPeerListPayload ({
  swarm = null,
  connections = null,
  reputation = null,
  now = Date.now(),
  publicKeyAlias = false,
  includeLastActivity = false,
  maxPeers = MAX_PEER_LIST_ENTRIES,
  // Metadata minimization: by default the bounded peer list returns a
  // non-reversible salted digest of each peer pubkey instead of the raw
  // 64-char key, so the public-facing surface can't be used to reconstruct
  // who-connected-when. An authenticated operator view passes redact:false
  // to get the real keys (e.g. for allow/blocklist management).
  redact = true
} = {}) {
  const peers = []
  const items = swarm && swarm.connections && typeof swarm.connections[Symbol.iterator] === 'function'
    ? swarm.connections
    : []
  const limit = normalizeLimit(maxPeers)
  let total = 0

  for (const conn of items) {
    total++
    if (peers.length >= limit) continue
    // Reputation is keyed on the REAL pubkey; redaction only affects output.
    const realPubkey = publicKeyHex(conn && conn.remotePublicKey)
    const shownPubkey = redact ? redactPubkeyHex(realPubkey) : realPubkey
    const entry = connections && typeof connections.get === 'function' ? connections.get(conn) : null
    const peer = {
      remotePublicKey: shownPubkey,
      type: connectionType(conn && conn.type),
      connectedFor: connectedFor(entry, now)
    }
    if (publicKeyAlias) peer.publicKey = shownPubkey
    if (includeLastActivity) peer.lastActivity = lastActivity(entry, now)
    if (realPubkey && reputation && typeof reputation.getRecord === 'function') {
      peer.reputation = sanitizeReputationRecord(reputation.getRecord(realPubkey))
    }
    peers.push(peer)
  }

  return {
    count: peers.length,
    total,
    truncated: total > peers.length,
    redacted: !!redact,
    peers
  }
}

function normalizeLimit (value) {
  if (!Number.isSafeInteger(value)) return MAX_PEER_LIST_ENTRIES
  if (value < 0) return 0
  return Math.min(value, MAX_PEER_LIST_ENTRIES)
}

function publicKeyHex (value) {
  if (!value || typeof value.length !== 'number' || value.length !== 32) return null
  return Buffer.from(value).toString('hex')
}

function connectionType (value) {
  if (typeof value !== 'string') return null
  const type = value.trim()
  if (!type || type.length > 32 || !/^[a-z0-9_-]+$/i.test(type)) return null
  return type
}

function connectedFor (entry, now) {
  const lastActivity = entry && entry.lastActivity
  if (!Number.isFinite(lastActivity) || !Number.isFinite(now)) return null
  return Math.max(0, Math.floor(now - lastActivity))
}

function lastActivity (entry, now) {
  const value = entry && entry.lastActivity
  if (!Number.isFinite(value)) return null
  if (!Number.isFinite(now)) return Math.max(0, Math.floor(value))
  return Math.max(0, Math.min(Math.floor(value), Math.floor(now)))
}
