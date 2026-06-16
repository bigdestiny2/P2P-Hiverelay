// Environment-driven config for the index sidecar. All knobs have safe
// defaults so the sidecar runs on-box next to a relay with zero config.
import { join } from 'path'

const Z32_KEY_RE = /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/

function int (v, d) {
  const n = parseInt(v, 10)
  return Number.isFinite(n) ? n : d
}

// Positive integer with a floor — rejects 0/negatives that would otherwise
// degrade into a ~1ms busy-poll or a silently-ignored page size.
function posInt (v, d, min) {
  const n = parseInt(v, 10)
  return Number.isFinite(n) && n >= min ? n : d
}

function bool (v, d) {
  if (v === undefined || v === null || v === '') return d
  return /^(1|true|yes|on)$/i.test(String(v))
}

export function loadConfig (env = process.env) {
  const roomKey = env.INDEX_ROOM_KEY || null
  if (roomKey && !Z32_KEY_RE.test(roomKey)) {
    throw new Error('INDEX_ROOM_KEY must be a 52-char z32 key')
  }
  return {
    // Relay loopback the sidecar reads from + publishes its room key to.
    // Default matches the relay's default apiPort (9100).
    relayUrl: (env.RELAY_URL || 'http://127.0.0.1:9100').replace(/\/+$/, ''),
    relayApiKey: env.RELAY_API_KEY || null,
    // The sidecar's own query HTTP server (the relay reverse-proxies to it).
    host: env.INDEX_HOST || '127.0.0.1',
    port: int(env.INDEX_PORT, 9300),
    // corestore-7 store for the schema-sheets room (separate from the relay).
    storageDir: env.STORAGE_DIR || join(process.cwd(), 'store'),
    // Optional persisted room key (z32). When absent a new room is created and
    // its key persisted to <storageDir>/room-key.
    roomKey,
    // Relay identity (hex) — used for the membership name + relay-directory.
    // Discovered from the relay's capability doc when not set.
    relayPubkey: env.RELAY_PUBKEY || null,
    // Projection cadence (floored at 1s to avoid a busy-poll).
    pollIntervalMs: posInt(env.POLL_INTERVAL_MS, 15000, 1000),
    // Join hyperswarm so clients can blind-replicate the room read-only.
    enableSwarm: bool(env.ENABLE_SWARM, true),
    // Default page size for query routes (matches /catalog.json conventions).
    pageSize: posInt(env.INDEX_PAGE_SIZE, 100, 1)
  }
}
