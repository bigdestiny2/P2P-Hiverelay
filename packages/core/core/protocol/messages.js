/**
 * HiveRelay Wire Protocol Messages
 *
 * All messages are encoded using compact-encoding and framed over
 * protomux channels on Hyperswarm connections.
 *
 * Protocol ID: 'hiverelay/1.0.0'
 */

import c from 'compact-encoding'
// b4a available via compact-encoding internals

// Message type constants
export const MSG = {
  // Seeding Registry (0x01 - 0x0F)
  SEED_REQUEST: 0x01,
  SEED_ACCEPT: 0x02,
  SEED_REJECT: 0x03,
  SEED_CANCEL: 0x04,
  SEED_HEARTBEAT: 0x05,
  SEED_STATUS: 0x06,
  SEED_UNSEED: 0x07,

  // Circuit Relay (0x10 - 0x1F)
  RELAY_RESERVE: 0x10,
  RELAY_RESERVE_OK: 0x11,
  RELAY_RESERVE_DENY: 0x12,
  RELAY_CONNECT: 0x13,
  RELAY_CONNECT_OK: 0x14,
  RELAY_CONNECT_DENY: 0x15,
  RELAY_DATA: 0x16,
  RELAY_CLOSE: 0x17,
  RELAY_UPGRADE: 0x18,

  // Proof of Relay (0x20 - 0x2F)
  PROOF_CHALLENGE: 0x20,
  PROOF_RESPONSE: 0x21,
  BANDWIDTH_RECEIPT: 0x22,
  RECEIPT_ACK: 0x23,

  // Peer Discovery (0x30 - 0x3F)
  PEER_ANNOUNCE: 0x30,
  PEER_QUERY: 0x31,
  PEER_RESPONSE: 0x32
}

// Error codes
export const ERR = {
  NONE: 0x00,
  CAPACITY_FULL: 0x01,
  INVALID_REQUEST: 0x02,
  NOT_FOUND: 0x03,
  TIMEOUT: 0x04,
  STORAGE_EXCEEDED: 0x05,
  BANDWIDTH_EXCEEDED: 0x06,
  DURATION_EXCEEDED: 0x07,
  PROOF_FAILED: 0x08,
  UNAUTHORIZED: 0x09,
  PROTOCOL_ERROR: 0x0A,
  INTERNAL_ERROR: 0xFF
}

// Region codes (ISO 3166-1 alpha-2 + continent codes)
export const REGIONS = {
  NA: 'North America',
  SA: 'South America',
  EU: 'Europe',
  AF: 'Africa',
  AS: 'Asia',
  OC: 'Oceania'
}

// --- Encoding schemas ---

// Durability tiers — controls how aggressively the network maintains
// replicas of a drive. Encoded as uint at the end of the seed request.
//
//   0  STANDARD  — current default. Network seeds N times where the
//                  publisher requested. No active replication enforcement.
//   1  ARCHIVE   — auto-heal target. Network maintains the drive at a
//                  diversity threshold (≥7 replicas, ≥4 regions, ≥5
//                  operators). When a replica drops, healthy relays
//                  recruit themselves to restore the threshold.
//
// Higher tiers are reserved for future use (PINNED, MIRROR, etc.). Like
// revocability, this is committed by publisher signature so the publisher
// cannot lie about the tier they originally requested.
export const DURABILITY_STANDARD = 0
export const DURABILITY_ARCHIVE = 1

// Wire format for the seed-request includes three newer fields:
// `revocable`, `unseedFreezeMs`, and `durability`. All three are appended
// after the existing payload for forward compatibility; older peers
// decode the prefix successfully and ignore the trailing bytes.
//
// All three values are committed to the publisher signature (see
// SeedProtocol._serializeForSigning).
export const seedRequestEncoding = {
  preencode (state, msg) {
    c.fixed32.preencode(state, msg.appKey)
    c.uint.preencode(state, msg.discoveryKeys.length)
    for (const dk of msg.discoveryKeys) {
      c.fixed32.preencode(state, dk)
    }
    c.uint.preencode(state, msg.replicationFactor)
    c.string.preencode(state, JSON.stringify(msg.geoPreference))
    c.uint.preencode(state, msg.maxStorageBytes)
    c.uint.preencode(state, msg.bountyRate)
    c.uint.preencode(state, msg.ttlSeconds)
    c.fixed32.preencode(state, msg.publisherPubkey)
    c.fixed64.preencode(state, msg.publisherSignature)
    c.uint.preencode(state, msg.revocable === false ? 0 : 1)
    c.uint.preencode(state, msg.unseedFreezeMs || 0)
    c.uint.preencode(state, msg.durability || DURABILITY_STANDARD)
  },
  encode (state, msg) {
    c.fixed32.encode(state, msg.appKey)
    c.uint.encode(state, msg.discoveryKeys.length)
    for (const dk of msg.discoveryKeys) {
      c.fixed32.encode(state, dk)
    }
    c.uint.encode(state, msg.replicationFactor)
    c.string.encode(state, JSON.stringify(msg.geoPreference))
    c.uint.encode(state, msg.maxStorageBytes)
    c.uint.encode(state, msg.bountyRate)
    c.uint.encode(state, msg.ttlSeconds)
    c.fixed32.encode(state, msg.publisherPubkey)
    c.fixed64.encode(state, msg.publisherSignature)
    c.uint.encode(state, msg.revocable === false ? 0 : 1)
    c.uint.encode(state, msg.unseedFreezeMs || 0)
    c.uint.encode(state, msg.durability || DURABILITY_STANDARD)
  },
  decode (state) {
    const appKey = c.fixed32.decode(state)
    const dkLen = c.uint.decode(state)
    const discoveryKeys = []
    for (let i = 0; i < dkLen; i++) {
      discoveryKeys.push(c.fixed32.decode(state))
    }
    const out = {
      appKey,
      discoveryKeys,
      replicationFactor: c.uint.decode(state),
      geoPreference: JSON.parse(c.string.decode(state)),
      maxStorageBytes: c.uint.decode(state),
      bountyRate: c.uint.decode(state),
      ttlSeconds: c.uint.decode(state),
      publisherPubkey: c.fixed32.decode(state),
      publisherSignature: c.fixed64.decode(state)
    }
    // Backward-compatible decode of the revocability + durability tail.
    // Older clients produce wire data without these fields; treat the
    // absence as the permissive default.
    try { out.revocable = c.uint.decode(state) !== 0 } catch { out.revocable = true }
    try { out.unseedFreezeMs = c.uint.decode(state) } catch { out.unseedFreezeMs = 0 }
    try { out.durability = c.uint.decode(state) } catch { out.durability = DURABILITY_STANDARD }
    return out
  }
}

export const seedAcceptEncoding = {
  preencode (state, msg) {
    c.fixed32.preencode(state, msg.appKey)
    c.fixed32.preencode(state, msg.relayPubkey)
    c.string.preencode(state, msg.region)
    c.uint.preencode(state, msg.availableStorageBytes)
    c.fixed64.preencode(state, msg.relaySignature)
  },
  encode (state, msg) {
    c.fixed32.encode(state, msg.appKey)
    c.fixed32.encode(state, msg.relayPubkey)
    c.string.encode(state, msg.region)
    c.uint.encode(state, msg.availableStorageBytes)
    c.fixed64.encode(state, msg.relaySignature)
  },
  decode (state) {
    return {
      appKey: c.fixed32.decode(state),
      relayPubkey: c.fixed32.decode(state),
      region: c.string.decode(state),
      availableStorageBytes: c.uint.decode(state),
      relaySignature: c.fixed64.decode(state)
    }
  }
}

/**
 * Seed deny: relay tells the requesting publisher WHY a seed request was
 * refused (or queued), instead of going silent and letting the publisher
 * time out. Reason codes are stable machine-readable strings:
 *
 *   'signature-required'                    — no publisher signature at all
 *   'archive-requires-publisher-signature'  — durability ≥ 1 without a valid
 *                                             v2 publisher signature
 *   'bad-signature'                         — signature present but invalid
 *   'insufficient-storage'                  — relay capacity exhausted
 *   'accept-mode:<mode>'                    — relay policy refused (allowlist/closed)
 *   'delegation:<reason>'                   — delegation cert chain failed
 *   'queued-for-review'                     — NOT terminal: pending operator approval
 *
 * Sent only on the requesting channel (never broadcast), signed by the
 * relay's keyPair when available. Old peers that predate this message
 * ignore it (protomux drops unknown message ids), so the worst case
 * degrades to today's behavior: timeout.
 */
export const seedDenyEncoding = {
  preencode (state, msg) {
    c.fixed32.preencode(state, msg.appKey)
    c.fixed32.preencode(state, msg.relayPubkey)
    c.string.preencode(state, msg.reasonCode)
    c.string.preencode(state, msg.detail || '')
    c.fixed64.preencode(state, msg.relaySignature)
  },
  encode (state, msg) {
    c.fixed32.encode(state, msg.appKey)
    c.fixed32.encode(state, msg.relayPubkey)
    c.string.encode(state, msg.reasonCode)
    c.string.encode(state, msg.detail || '')
    c.fixed64.encode(state, msg.relaySignature)
  },
  decode (state) {
    return {
      appKey: c.fixed32.decode(state),
      relayPubkey: c.fixed32.decode(state),
      reasonCode: c.string.decode(state),
      detail: c.string.decode(state),
      relaySignature: c.fixed64.decode(state)
    }
  }
}

/**
 * Unseed request: developer requests relay to stop seeding their app.
 * Signed by the publisher's key to prove ownership.
 * { appKey: Buffer(32), timestamp: uint, publisherPubkey: Buffer(32), publisherSignature: Buffer(64) }
 */
export const unseedRequestEncoding = {
  preencode (state, msg) {
    c.fixed32.preencode(state, msg.appKey)
    c.uint.preencode(state, msg.timestamp)
    c.fixed32.preencode(state, msg.publisherPubkey)
    c.fixed64.preencode(state, msg.publisherSignature)
  },
  encode (state, msg) {
    c.fixed32.encode(state, msg.appKey)
    c.uint.encode(state, msg.timestamp)
    c.fixed32.encode(state, msg.publisherPubkey)
    c.fixed64.encode(state, msg.publisherSignature)
  },
  decode (state) {
    return {
      appKey: c.fixed32.decode(state),
      timestamp: c.uint.decode(state),
      publisherPubkey: c.fixed32.decode(state),
      publisherSignature: c.fixed64.decode(state)
    }
  }
}

export const proofChallengeEncoding = {
  preencode (state, msg) {
    c.fixed32.preencode(state, msg.coreKey)
    c.uint.preencode(state, msg.blockIndex)
    c.fixed32.preencode(state, msg.nonce)
    c.uint.preencode(state, msg.maxLatencyMs)
  },
  encode (state, msg) {
    c.fixed32.encode(state, msg.coreKey)
    c.uint.encode(state, msg.blockIndex)
    c.fixed32.encode(state, msg.nonce)
    c.uint.encode(state, msg.maxLatencyMs)
  },
  decode (state) {
    return {
      coreKey: c.fixed32.decode(state),
      blockIndex: c.uint.decode(state),
      nonce: c.fixed32.decode(state),
      maxLatencyMs: c.uint.decode(state)
    }
  }
}

export const proofResponseEncoding = {
  preencode (state, msg) {
    c.fixed32.preencode(state, msg.coreKey)
    c.uint.preencode(state, msg.blockIndex)
    c.buffer.preencode(state, msg.blockData)
    c.buffer.preencode(state, msg.merkleProof)
    c.fixed32.preencode(state, msg.nonce)
  },
  encode (state, msg) {
    c.fixed32.encode(state, msg.coreKey)
    c.uint.encode(state, msg.blockIndex)
    c.buffer.encode(state, msg.blockData)
    c.buffer.encode(state, msg.merkleProof)
    c.fixed32.encode(state, msg.nonce)
  },
  decode (state) {
    return {
      coreKey: c.fixed32.decode(state),
      blockIndex: c.uint.decode(state),
      blockData: c.buffer.decode(state),
      merkleProof: c.buffer.decode(state),
      nonce: c.fixed32.decode(state)
    }
  }
}

// bandwidthReceiptEncoding removed — BandwidthReceipt class does its own signing/encoding

export const relayReserveEncoding = {
  preencode (state, msg) {
    c.fixed32.preencode(state, msg.peerPubkey)
    c.uint.preencode(state, msg.maxDurationMs)
    c.uint.preencode(state, msg.maxBytes)
  },
  encode (state, msg) {
    c.fixed32.encode(state, msg.peerPubkey)
    c.uint.encode(state, msg.maxDurationMs)
    c.uint.encode(state, msg.maxBytes)
  },
  decode (state) {
    return {
      peerPubkey: c.fixed32.decode(state),
      maxDurationMs: c.uint.decode(state),
      maxBytes: c.uint.decode(state)
    }
  }
}
