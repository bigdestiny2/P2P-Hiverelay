/**
 * Shared constants and utility helpers for HiveRelay.
 *
 * Consolidates values and functions that were duplicated across the
 * codebase (relay-node, client SDK, gateway, network-discovery, etc.).
 */

import b4a from 'b4a'
import sodium from 'sodium-universal'

// ─── Discovery ───────────────────────────────────────────────

/**
 * Well-known 32-byte DHT topic that all HiveRelay nodes join for
 * peer discovery.  Derived deterministically from the string
 * 'hiverelay-discovery-v1' via BLAKE2b (crypto_generichash).
 *
 * This is the GLOBAL topic — every relay joins it. As the network
 * grows, region-sharded topics (regionTopic) carry most of the load
 * and the global topic becomes a fallback / fresh-relay onboarding.
 */
const RELAY_DISCOVERY_TOPIC = b4a.alloc(32)
sodium.crypto_generichash(RELAY_DISCOVERY_TOPIC, b4a.from('hiverelay-discovery-v1'))

/**
 * Hash a discovery namespace string into a 32-byte DHT topic.
 * @param {string} ns
 * @returns {Buffer}
 */
function _topicOf (ns) {
  const t = b4a.alloc(32)
  sodium.crypto_generichash(t, b4a.from(ns))
  return t
}

/**
 * Region-sharded discovery topic.
 *
 * Splits the global topic into per-region buckets so the DHT peer-list
 * stays a manageable size and clients can preferentially discover
 * peers in their own region (lower latency).
 *
 *   regionTopic('NA') → blake2b('hiverelay-discovery-v1-region-NA')
 *
 * Conventions:
 *   - Region codes are uppercased (NA, EU, AS, SA, AF, OC)
 *   - Unknown region falls back to 'global'
 *   - Relays SHOULD join their primary region topic + the global
 *     RELAY_DISCOVERY_TOPIC for cross-region discovery
 *   - Clients SHOULD join their region first, fall back to global
 *
 * @param {string} region
 * @returns {Buffer} 32-byte topic
 */
function regionTopic (region) {
  const code = region ? String(region).toUpperCase() : 'GLOBAL'
  return _topicOf('hiverelay-discovery-v1-region-' + code)
}

/**
 * Foundation network discovery topic — operator-of-last-resort layer
 * (per docs/OPERATOR-INCENTIVES-Y1.md). Foundation relays announce
 * here so clients running in 'foundation' quorum mode can pin a
 * trusted floor without scanning the full DHT.
 *
 * @returns {Buffer} 32-byte topic
 */
const FOUNDATION_TOPIC = _topicOf('hiverelay-foundation-v1')

// ─── Epoch-rotating discovery (opt-in privacy) ───────────────
//
// The static RELAY_DISCOVERY_TOPIC lets a passive DHT observer enumerate the
// entire relay set indefinitely from a single vantage point. An epoch-rotated
// topic — blake2b('…-epoch-<bucket>') where bucket = floor(now / period) —
// changes every period, so a snapshot only reveals the CURRENT window's
// participants. This mirrors Tor v3 onion services' time-rotated blinded
// descriptors. Nodes that opt in join the current AND next bucket (an overlap
// window that absorbs clock skew and covers the rollover boundary) so there is
// no discovery gap. In 'additive' mode they ALSO keep the static topic (full
// backward-compat, partial privacy); in 'strict' mode they drop the static
// topic for maximum unlinkability at the cost of discoverability by legacy peers.

const DISCOVERY_EPOCH_MS = 60 * 60 * 1000 // 1 hour

/**
 * Topic for a specific epoch bucket.
 * @param {number} bucket
 * @returns {Buffer} 32-byte topic
 */
function epochDiscoveryTopic (bucket) {
  return _topicOf('hiverelay-discovery-v1-epoch-' + bucket)
}

/**
 * The epoch topics a node should currently be joined to: the current bucket
 * plus the next one (overlap window). Pure — pass `now`/`periodMs` for tests.
 *
 * @param {number|null} [now=Date.now()]
 * @param {number} [periodMs=DISCOVERY_EPOCH_MS]
 * @returns {Buffer[]} [currentTopic, nextTopic]
 */
function epochDiscoveryTopics (now = null, periodMs = DISCOVERY_EPOCH_MS) {
  const t = Number.isFinite(now) ? now : Date.now()
  const period = Number.isFinite(periodMs) && periodMs > 0 ? periodMs : DISCOVERY_EPOCH_MS
  const bucket = Math.floor(t / period)
  return [epochDiscoveryTopic(bucket), epochDiscoveryTopic(bucket + 1)]
}

function destroyDiscoveryHandle (handle) {
  if (!handle || typeof handle.destroy !== 'function') return
  try {
    const done = handle.destroy()
    if (done && typeof done.catch === 'function') done.catch(() => {})
  } catch (_) {}
}

/**
 * Keep a swarm joined to exactly the current and next epoch discovery topics.
 * `joined` is a Map keyed by topic hex with Hyperswarm discovery handles as
 * values. Old buckets are destroyed as soon as they roll out of the active
 * current+next window.
 *
 * @param {Map<string, *>} joined
 * @param {*} swarm
 * @param {{ server: boolean, client: boolean }} joinOpts
 * @param {number|null} [now=Date.now()]
 * @param {number} [periodMs=DISCOVERY_EPOCH_MS]
 * @returns {Map<string, *>} the same joined map
 */
function syncEpochDiscoveryTopics (joined, swarm, joinOpts, now = null, periodMs = DISCOVERY_EPOCH_MS, onRetire = null) {
  const handles = joined instanceof Map ? joined : new Map()
  if (!swarm || typeof swarm.join !== 'function') return handles

  const active = new Set()
  for (const topic of epochDiscoveryTopics(now, periodMs)) {
    const key = b4a.toString(topic, 'hex')
    active.add(key)
    if (!handles.has(key)) {
      handles.set(key, swarm.join(topic, joinOpts))
    }
  }

  for (const [key, handle] of handles) {
    if (!active.has(key)) {
      handles.delete(key)
      if (typeof onRetire === 'function') onRetire(handle, key)
      else destroyDiscoveryHandle(handle)
    }
  }

  return handles
}

/**
 * Destroy every tracked epoch discovery handle and empty the map.
 * @param {Map<string, *>} joined
 */
function clearEpochDiscoveryTopics (joined) {
  if (!(joined instanceof Map)) return
  for (const handle of joined.values()) destroyDiscoveryHandle(handle)
  joined.clear()
}

// ─── Protomux protocol names ─────────────────────────────────

const SEED_PROTOCOL_NAME = 'hiverelay-seed'
const CIRCUIT_PROTOCOL_NAME = 'hiverelay-circuit'
const FORWARD_PROTOCOL_NAME = 'hiverelay-forward'
const SERVICES_PROTOCOL_NAME = 'hiverelay-services'

// ─── Privacy tiers ───────────────────────────────────────────

/**
 * Supported relay privacy tiers for app data paths.
 */
const PRIVACY_TIERS = new Set(['public', 'local-first', 'p2p-only'])
const CONTENT_TYPES = new Set(['app', 'drive', 'dataset', 'media'])
const STORAGE_CLASSES = new Set(['persistent', 'temporary'])
const AVAILABILITY_CLASSES = new Set(['always-on', 'best-effort', 'atomic-handoff'])

/**
 * Normalize a privacy tier string.
 * Returns fallback when missing/invalid.
 *
 * @param {*} tier
 * @param {string|null} [fallback='public']
 * @returns {string|null}
 */
function normalizePrivacyTier (tier, fallback = 'public') {
  if (tier === undefined || tier === null || tier === '') return fallback
  const normalized = String(tier).toLowerCase()
  return PRIVACY_TIERS.has(normalized) ? normalized : fallback
}

/**
 * Normalize a content type string.
 * Returns fallback when missing/invalid.
 *
 * @param {*} type
 * @param {string|null} [fallback='app']
 * @returns {string|null}
 */
function normalizeContentType (type, fallback = 'app') {
  if (type === undefined || type === null || type === '') return fallback
  const normalized = String(type).toLowerCase()
  return CONTENT_TYPES.has(normalized) ? normalized : fallback
}

/**
 * Normalize a storage class string.
 * Returns fallback when missing/invalid.
 *
 * @param {*} storageClass
 * @param {string|null} [fallback='persistent']
 * @returns {string|null}
 */
function normalizeStorageClass (storageClass, fallback = 'persistent') {
  if (storageClass === undefined || storageClass === null || storageClass === '') return fallback
  const normalized = String(storageClass).toLowerCase()
  return STORAGE_CLASSES.has(normalized) ? normalized : fallback
}

/**
 * Normalize an availability class string.
 * Returns fallback when missing/invalid.
 *
 * @param {*} availabilityClass
 * @param {string|null} [fallback='always-on']
 * @returns {string|null}
 */
function normalizeAvailabilityClass (availabilityClass, fallback = 'always-on') {
  if (availabilityClass === undefined || availabilityClass === null || availabilityClass === '') return fallback
  const normalized = String(availabilityClass).toLowerCase()
  return AVAILABILITY_CLASSES.has(normalized) ? normalized : fallback
}

// ─── Validation ──────────────────────────────────────────────

/**
 * Validate a hex-encoded key string.
 * @param {*} str - value to check
 * @param {number} [len=64] - expected character length (64 for 32-byte keys)
 * @returns {boolean}
 */
function isValidHexKey (str, len = 64) {
  return typeof str === 'string' && str.length === len && /^[0-9a-f]+$/i.test(str)
}

// ─── Versioning ──────────────────────────────────────────────

/**
 * Compare two semver-style version strings.
 * @param {string} a
 * @param {string} b
 * @returns {-1|0|1}
 */
function compareVersions (a, b) {
  const pa = (a || '0.0.0').split('.').map(Number)
  const pb = (b || '0.0.0').split('.').map(Number)
  for (let i = 0; i < 3; i++) {
    const na = pa[i] || 0
    const nb = pb[i] || 0
    if (na > nb) return 1
    if (na < nb) return -1
  }
  return 0
}

// ─── Binary helpers ──────────────────────────────────────────

/**
 * Convert a number to an 8-byte big-endian Buffer (uint64).
 * @param {number} n
 * @returns {Buffer}
 */
function uint64ToBuffer (n) {
  const buf = b4a.alloc(8)
  const view = new DataView(buf.buffer, buf.byteOffset, 8)
  view.setBigUint64(0, BigInt(n), false) // big-endian
  return buf
}

export {
  RELAY_DISCOVERY_TOPIC,
  FOUNDATION_TOPIC,
  DISCOVERY_EPOCH_MS,
  epochDiscoveryTopic,
  epochDiscoveryTopics,
  syncEpochDiscoveryTopics,
  clearEpochDiscoveryTopics,
  regionTopic,
  SEED_PROTOCOL_NAME,
  CIRCUIT_PROTOCOL_NAME,
  FORWARD_PROTOCOL_NAME,
  SERVICES_PROTOCOL_NAME,
  PRIVACY_TIERS,
  CONTENT_TYPES,
  STORAGE_CLASSES,
  AVAILABILITY_CLASSES,
  normalizePrivacyTier,
  normalizeContentType,
  normalizeStorageClass,
  normalizeAvailabilityClass,
  isValidHexKey,
  compareVersions,
  uint64ToBuffer
}
