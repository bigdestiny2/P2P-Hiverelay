/**
 * Author-published seeding manifest.
 *
 * A seeding manifest is a short, signed document an author publishes to
 * declare "my drives are seeded on these relays; please fetch here." It's
 * the author-side complement to per-relay federation.follow() — the operator
 * says "I mirror these pubkeys", and the author says "I'm seeded at these
 * relays".
 *
 * Clients fetch a manifest by author pubkey (from any relay that caches it)
 * and use it to decide which relays to connect to for that author's content.
 *
 * Shape:
 *
 *   {
 *     type: 'hiverelay/seeding-manifest',
 *     version: 1,
 *     pubkey: '<author hex>',
 *     timestamp: 1729555555555,
 *     relays: [
 *       { url: 'hyperswarm://<pk>', role: 'primary' },
 *       { url: 'wss://relay.example.com/dht', role: 'backup' }
 *     ],
 *     drives: [
 *       { driveKey: '<hex>', channel: 'production' },
 *       // Optional `lifetime` hint — see LIFETIME_VALUES below.
 *       { driveKey: '<hex>', channel: 'beta', lifetime: 'session' }
 *     ],
 *     signature: '<hex, covers a canonical serialization>'
 *   }
 *
 * Signature coverage: `type|version|pubkey|timestamp|relays_json|drives_json`
 * where each JSON blob is canonicalized (keys sorted, no whitespace). This
 * keeps verification deterministic across runtimes and JSON encoders.
 *
 * ─── Drive lifetimes ────────────────────────────────────────────────────────
 * The optional `lifetime` field on a drive entry hints to the seeding side
 * how long the drive's content is expected to stay relevant. It's an
 * application-level signal, NOT a contract — the relay is still free to
 * keep data longer (e.g. for audit) or evict earlier under pressure. But it
 * lets operators size storage policies for ephemeral workloads (per-hand
 * poker reveal shares, ephemeral chat backlogs, etc.) without conflating
 * them with long-lived publication drives.
 *
 * Valid values:
 *   'persistent'  — default; drive is treated as long-lived publication
 *                   content. Author expects it to be retained indefinitely.
 *   'session'     — drive is bound to an active session (e.g. ~24h). After
 *                   expiry, the relay MAY evict if storage pressure is high.
 *   'ephemeral'   — short-lived; eviction allowed as soon as practical
 *                   (~1h or end of holding session). Useful for per-round
 *                   game state, one-shot share material, throwaway transcripts.
 *
 * Backward compatibility: omitting `lifetime` is equivalent to 'persistent'.
 * Old verifiers tolerate the new field — they re-canonicalize through
 * `sortKeys()` (which preserves all keys), so signatures over new manifests
 * verify with old code; the old code just doesn't act on the hint. New
 * verifiers treat absent `lifetime` as 'persistent' for backward parity.
 *
 * This file does NOT enforce eviction — that's the seeder's job. We only
 * define the spec, the validator, and a small `defaultLifetimeTtlMs()` helper
 * consumers can use as a starting policy if they don't have their own.
 */

import b4a from 'b4a'
import sodium from 'sodium-universal'

const MANIFEST_TYPE = 'hiverelay/seeding-manifest'
const MANIFEST_VERSION = 1
const VALID_RELAY_ROLES = new Set(['primary', 'backup', 'mirror'])
// Drive lifetime classes — see the file header for semantics. The default
// when absent is 'persistent' (preserves pre-lifetime-field behaviour).
const LIFETIME_VALUES = new Set(['persistent', 'session', 'ephemeral'])
const DEFAULT_LIFETIME = 'persistent'
// Default TTL hints for each lifetime class. These are SUGGESTIONS the
// seeder is free to override based on its own storage policy / pressure
// signals. 'persistent' has no TTL (Infinity); 'session' is roughly a day
// (typical app session boundary); 'ephemeral' is roughly an hour (covers
// per-round game state without bloating disk).
const LIFETIME_TTL_MS = Object.freeze({
  persistent: Infinity,
  session: 24 * 60 * 60 * 1000,
  ephemeral: 60 * 60 * 1000
})
// Manifests newer than this many milliseconds in the future are rejected to
// limit replay/timestamp-tampering windows. 5 min is a reasonable default
// that accommodates clock drift without opening a meaningful replay window.
const TIMESTAMP_SKEW_MS = 5 * 60 * 1000
// Absolute bounds — refuse to even try to sign/verify a manifest bigger
// than this. Prevents DoS via enormous payload.
const MAX_RELAYS = 32
const MAX_DRIVES = 512

/**
 * Build + sign a seeding manifest.
 *
 * @param {object} args
 * @param {object} args.keyPair          Ed25519 keypair { publicKey, secretKey }
 * @param {Array}  args.relays           [{url, role}]
 * @param {Array}  args.drives           [{driveKey, channel?}]
 * @param {number} [args.timestamp]      ms epoch, defaults to Date.now()
 * @returns {object} signed manifest
 */
export function createSeedingManifest ({ keyPair, relays, drives, timestamp }) {
  if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) {
    throw new Error('createSeedingManifest: missing keyPair')
  }
  const normRelays = normalizeRelays(relays)
  const normDrives = normalizeDrives(drives)
  if (normRelays.length > MAX_RELAYS) throw new Error('too many relays (max ' + MAX_RELAYS + ')')
  if (normDrives.length > MAX_DRIVES) throw new Error('too many drives (max ' + MAX_DRIVES + ')')

  const manifest = {
    type: MANIFEST_TYPE,
    version: MANIFEST_VERSION,
    pubkey: b4a.toString(keyPair.publicKey, 'hex'),
    timestamp: typeof timestamp === 'number' ? timestamp : Date.now(),
    relays: normRelays,
    drives: normDrives
  }

  const payload = canonicalPayload(manifest)
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, payload, keyPair.secretKey)
  manifest.signature = b4a.toString(sig, 'hex')
  return manifest
}

/**
 * Verify a seeding manifest. Pure — no clock side effects besides Date.now().
 *
 *   {valid: true, pubkey}                      — accept
 *   {valid: false, reason: '<short string>'}   — reject with machine-readable reason
 *
 * @param {object} manifest
 * @param {object} [opts]
 * @param {number} [opts.now]  — Date.now() equivalent, for deterministic tests
 * @returns {{valid: boolean, pubkey?: string, reason?: string}}
 */
export function verifySeedingManifest (manifest, opts = {}) {
  try {
    if (!manifest || typeof manifest !== 'object') return { valid: false, reason: 'not an object' }
    if (manifest.type !== MANIFEST_TYPE) return { valid: false, reason: 'wrong type' }
    if (manifest.version !== MANIFEST_VERSION) return { valid: false, reason: 'unsupported version' }
    if (typeof manifest.pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(manifest.pubkey)) {
      return { valid: false, reason: 'bad pubkey' }
    }
    if (typeof manifest.timestamp !== 'number' || !Number.isFinite(manifest.timestamp)) {
      return { valid: false, reason: 'bad timestamp' }
    }
    const now = typeof opts.now === 'number' ? opts.now : Date.now()
    if (manifest.timestamp > now + TIMESTAMP_SKEW_MS) {
      return { valid: false, reason: 'timestamp in the future' }
    }
    if (!Array.isArray(manifest.relays)) return { valid: false, reason: 'relays not array' }
    if (!Array.isArray(manifest.drives)) return { valid: false, reason: 'drives not array' }
    if (manifest.relays.length > MAX_RELAYS) return { valid: false, reason: 'too many relays' }
    if (manifest.drives.length > MAX_DRIVES) return { valid: false, reason: 'too many drives' }

    // Re-validate shape (rejecting junk entries early).
    try {
      normalizeRelays(manifest.relays)
      normalizeDrives(manifest.drives)
    } catch (err) {
      return { valid: false, reason: err.message || 'bad entries' }
    }

    if (typeof manifest.signature !== 'string' || !/^[0-9a-f]{128}$/i.test(manifest.signature)) {
      return { valid: false, reason: 'bad signature' }
    }

    const payload = canonicalPayload(manifest)
    const sig = b4a.from(manifest.signature, 'hex')
    const pub = b4a.from(manifest.pubkey, 'hex')
    const ok = sodium.crypto_sign_verify_detached(sig, payload, pub)
    if (!ok) return { valid: false, reason: 'signature verification failed' }
    return { valid: true, pubkey: manifest.pubkey }
  } catch (err) {
    return { valid: false, reason: err.message || 'error' }
  }
}

/**
 * Is `a` a later version of `b` for the same author? Used by relays caching
 * multiple manifests from one author — newer timestamp wins. If pubkeys
 * differ, a is not a replacement at all.
 */
export function isNewerManifest (a, b) {
  if (!b) return true
  if (!a || a.pubkey !== b.pubkey) return false
  return (a.timestamp || 0) > (b.timestamp || 0)
}

// ─── Internal helpers ─────────────────────────────────────────────

function normalizeRelays (relays) {
  if (!Array.isArray(relays)) throw new Error('relays must be an array')
  const out = []
  for (const r of relays) {
    if (!r || typeof r !== 'object') throw new Error('relay entry not an object')
    if (typeof r.url !== 'string' || r.url.length === 0 || r.url.length > 512) {
      throw new Error('bad relay url')
    }
    const role = r.role || 'primary'
    if (!VALID_RELAY_ROLES.has(role)) throw new Error('bad relay role: ' + role)
    out.push({ url: r.url, role })
  }
  return out
}

function normalizeDrives (drives) {
  if (!Array.isArray(drives)) throw new Error('drives must be an array')
  const out = []
  for (const d of drives) {
    if (!d || typeof d !== 'object') throw new Error('drive entry not an object')
    if (typeof d.driveKey !== 'string' || !/^[0-9a-f]{64}$/i.test(d.driveKey)) {
      throw new Error('bad driveKey')
    }
    const entry = { driveKey: d.driveKey.toLowerCase() }
    if (d.channel !== undefined) {
      if (typeof d.channel !== 'string' || d.channel.length > 64) {
        throw new Error('bad channel')
      }
      entry.channel = d.channel
    }
    // Optional lifetime hint. Reject unknown values rather than silently
    // dropping — a typo like 'sesion' should error loudly at publish time,
    // not become an unenforced no-op that the operator can't debug later.
    // We only include the field in the normalized output when it was
    // explicitly set, so default-'persistent' callers continue to produce
    // byte-identical canonical payloads to pre-lifetime-field code.
    if (d.lifetime !== undefined) {
      if (typeof d.lifetime !== 'string' || !LIFETIME_VALUES.has(d.lifetime)) {
        throw new Error('bad lifetime: ' + d.lifetime)
      }
      // Don't emit the field for the default value — keeps the canonical
      // signing payload stable for the common case and avoids needing a
      // version bump just to add a hint.
      if (d.lifetime !== DEFAULT_LIFETIME) entry.lifetime = d.lifetime
    }
    out.push(entry)
  }
  return out
}

/**
 * Canonical signable payload. We don't use JSON.stringify directly on the
 * whole manifest because JSON key order is implementation-defined in the
 * spec (though v8/node/bare happen to be stable). Instead we build a
 * fixed-order concatenation of:
 *
 *   type\n version\n pubkey\n timestamp\n relays_json\n drives_json
 *
 * where relays_json and drives_json each serialize an array of entries with
 * keys sorted alphabetically.
 */
function canonicalPayload (manifest) {
  const parts = [
    manifest.type,
    String(manifest.version),
    manifest.pubkey,
    String(manifest.timestamp),
    serializeArray(manifest.relays),
    serializeArray(manifest.drives)
  ]
  return b4a.from(parts.join('\n'), 'utf8')
}

function serializeArray (arr) {
  return JSON.stringify((arr || []).map(sortKeys))
}

function sortKeys (obj) {
  if (!obj || typeof obj !== 'object') return obj
  const out = {}
  for (const k of Object.keys(obj).sort()) out[k] = obj[k]
  return out
}

/**
 * Look up the recommended TTL for a drive lifetime class. Returns a number
 * in milliseconds, or `Infinity` for 'persistent'. Unknown values fall back
 * to the persistent TTL — this is the safer default: never accidentally evict
 * something an old/forward-compat manifest is asking us to hold.
 *
 * Consumers (seeder, manifest-store) call this to seed their initial
 * retention policy. They are free to override with their own operator-config
 * knobs; this is just a sensible starting point that everyone agrees on.
 *
 * @param {string} [lifetime] One of LIFETIME_VALUES, or undefined.
 * @returns {number} TTL in ms (Infinity for persistent / unknown).
 */
export function defaultLifetimeTtlMs (lifetime) {
  if (lifetime === undefined || lifetime === null) return LIFETIME_TTL_MS[DEFAULT_LIFETIME]
  return LIFETIME_TTL_MS[lifetime] !== undefined
    ? LIFETIME_TTL_MS[lifetime]
    : LIFETIME_TTL_MS[DEFAULT_LIFETIME]
}

/**
 * Resolve a drive entry's effective lifetime, applying the default. Useful
 * for code that doesn't want to re-implement the "absent === persistent"
 * rule everywhere.
 *
 * @param {{lifetime?: string}} driveEntry
 * @returns {string} One of LIFETIME_VALUES.
 */
export function driveLifetime (driveEntry) {
  if (!driveEntry || typeof driveEntry !== 'object') return DEFAULT_LIFETIME
  if (driveEntry.lifetime && LIFETIME_VALUES.has(driveEntry.lifetime)) return driveEntry.lifetime
  return DEFAULT_LIFETIME
}

export {
  MANIFEST_TYPE,
  MANIFEST_VERSION,
  MAX_RELAYS,
  MAX_DRIVES,
  TIMESTAMP_SKEW_MS,
  LIFETIME_VALUES,
  DEFAULT_LIFETIME,
  LIFETIME_TTL_MS
}
