/**
 * Client-side shard recovery + discovery helpers (M4).
 *
 * These run on the recovering client, not the relay. Given a signed custody
 * shareManifest, fetch >= shareThreshold shards by hash from whichever relays
 * hold them, verify each by re-hashing (content-address integrity — no relay
 * is trusted), and return the collected shares for PVSS reconstruction.
 */
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { normalizeShardAddress, shardHash } from './shard-engine.js'

/** DHT topic a holder announces on so a recovering client can find it. */
export function shardAnnounceTopic (address) {
  const hash = normalizeShardAddress(address)
  if (!hash) throw new Error('shardAnnounceTopic: invalid shard address')
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from('shard\0' + hash, 'utf8'))
  return out // 32-byte topic
}

/**
 * @param manifest        [{ shareIndex, shard }] from a verified custody-intent
 * @param shareThreshold  k — how many distinct valid shares are needed
 * @param fetch           async (shardAddress) => bytes | null  (hits relays)
 * @returns { ok, collected: [{ shareIndex, shard, bytes }], missing: [...], enough }
 */
export async function recoverShards ({ manifest, shareThreshold, fetch } = {}) {
  if (!Array.isArray(manifest)) throw new Error('recoverShards: manifest array required')
  if (typeof fetch !== 'function') throw new Error('recoverShards: fetch(shard) required')
  const need = Number.isInteger(shareThreshold) && shareThreshold > 0 ? shareThreshold : manifest.length
  const collected = []
  const missing = []
  for (const entry of manifest) {
    if (collected.length >= need) break
    const hash = normalizeShardAddress(entry.shard)
    if (!hash) { missing.push(entry); continue }
    let bytes = null
    try {
      bytes = await fetch('shard:' + hash)
    } catch {
      bytes = null
    }
    // content-address integrity: a relay returning wrong bytes is caught here.
    if (bytes && shardHash(bytes) === hash) {
      collected.push({ shareIndex: entry.shareIndex, shard: 'shard:' + hash, bytes })
    } else {
      missing.push(entry)
    }
  }
  return { ok: collected.length >= need, enough: collected.length >= need, collected, missing }
}
