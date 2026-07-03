/**
 * Blind-shard dispersal + recovery (CLIENT-SIDE).
 *
 * The connective layer between PVSS secret-sharing (secret-sharing.js) and the
 * content-addressed blind shard store (/api/v1/shard). It turns a secret into
 * `n` self-verifying shares, encodes each as a canonical OPAQUE shard blob, and
 * disperses them so NO SINGLE RELAY holds >= threshold shares — then lets any
 * reader collect >= threshold shards and reconstruct the secret AT THE EDGE.
 * A relay only ever sees opaque, content-addressed bytes; below the threshold a
 * held share is COMPUTATIONALLY hidden (secp256k1 DL/DDH — each shard exposes
 * S_i = p(i)*G, so this is the standard PVSS-in-the-exponent tradeoff, not the
 * information-theoretic hiding of plain Shamir).
 *
 * INTEGRITY CONTRACT: recoverSecret binds each fetched share to the point the
 * manifest commits to (shareCommitment), so a relay cannot substitute a
 * forged-but-self-consistent share (a valid DLEQ proof alone does NOT prove a
 * share matches the dealer's polynomial). That binding is only as trustworthy
 * as the manifest: callers MUST obtain the shareManifest from a publisher-signed
 * custody intent (verify the intent + that its shareCommitments derive from the
 * signed commitmentRoot) before trusting a reconstruction. An unauthenticated
 * manifest can commit to anything.
 *
 * This is the "public plaintext, blind custody" path: encrypt content with a
 * random key, store the ciphertext, and disperse the KEY as blind shards here —
 * no single operator can produce the plaintext, a reader can.
 *
 * Transport-agnostic: the caller injects put()/fetch() (HTTP /api/v1/shard, the
 * P2P service RPC, or in-process for tests).
 */
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { keygen, split, decryptShare, reconstruct } from './secret-sharing.js'

export const SHARE_SHARD_VERSION = 1
export const SHARE_SHARD_SCHEME = 'pvss-secp256k1-v1'

const HEX_32 = /^[0-9a-f]{64}$/
const POINT = /^[0-9a-f]{66}$/

// blake2b-256(bytes) as 'shard:<lowercase-hex>' — byte-identical to the relay
// shard store's shardHash (shard-engine.js), so an address computed locally
// matches what a relay returns on PUT and stores under.
export function shardAddressOf (bytes) {
  const buf = b4a.isBuffer(bytes) ? bytes : b4a.from(bytes)
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, buf)
  return 'shard:' + b4a.toString(out, 'hex')
}

function normalizeAddress (addr) {
  const raw = typeof addr === 'string' && addr.startsWith('shard:') ? addr.slice('shard:'.length) : String(addr)
  return 'shard:' + raw.toLowerCase()
}

function assertShare (s, where) {
  if (!s || typeof s !== 'object') throw new Error(where + ': share object required')
  if (!Number.isInteger(s.index) || s.index < 1) throw new Error(where + ': bad share index')
  if (!POINT.test(s.share)) throw new Error(where + ': bad share point')
  if (!POINT.test(s.shareholder)) throw new Error(where + ': bad shareholder point')
  if (!POINT.test(s.encryptedShare)) throw new Error(where + ': bad encryptedShare point')
  if (!s.proof || !HEX_32.test(s.proof.e) || !HEX_32.test(s.proof.s)) throw new Error(where + ': bad DLEQ proof')
}

/**
 * Canonical, deterministic bytes for a decrypted PVSS share so that
 * blake2b(encodeShareShard(s)) is a STABLE content address across runs and
 * hosts. Built as a fixed-order JSON string (not JSON.stringify) so the
 * encoding never depends on engine key-ordering. All values are validated
 * hex/points + an integer index, so no escaping is required.
 */
export function encodeShareShard (share) {
  assertShare(share, 'encodeShareShard')
  const canonical =
    '{"v":' + SHARE_SHARD_VERSION +
    ',"scheme":"' + SHARE_SHARD_SCHEME + '"' +
    ',"index":' + share.index +
    ',"share":"' + share.share + '"' +
    ',"shareholder":"' + share.shareholder + '"' +
    ',"encryptedShare":"' + share.encryptedShare + '"' +
    ',"proof":{"e":"' + share.proof.e + '","s":"' + share.proof.s + '"}}'
  return b4a.from(canonical, 'utf8')
}

/** Inverse of encodeShareShard. Validates version/scheme/shape. */
export function decodeShareShard (bytes) {
  let obj
  try {
    obj = JSON.parse(b4a.toString(b4a.isBuffer(bytes) ? bytes : b4a.from(bytes), 'utf8'))
  } catch {
    throw new Error('decodeShareShard: not JSON')
  }
  if (obj.v !== SHARE_SHARD_VERSION) throw new Error('decodeShareShard: unsupported version')
  if (obj.scheme !== SHARE_SHARD_SCHEME) throw new Error('decodeShareShard: unsupported scheme')
  const share = {
    index: obj.index,
    share: obj.share,
    shareholder: obj.shareholder,
    encryptedShare: obj.encryptedShare,
    proof: obj.proof && { e: obj.proof.e, s: obj.proof.s }
  }
  assertShare(share, 'decodeShareShard')
  return share
}

/**
 * DEALER: split a secret into `count` self-verifying shares (threshold `k`),
 * encode each as an opaque shard, and PUT it via the injected put().
 *
 * Shareholders are EPHEMERAL keys generated here — disjoint from the custodying
 * relays (as split() requires) and held only long enough to produce plain,
 * DLEQ-self-verifying shares that any reader can later reconstruct without a
 * secret key.
 *
 * @param {object} p
 * @param {number} p.count      n — total shares / relays (>= threshold)
 * @param {number} p.threshold  k — shares required to reconstruct
 * @param {string} [p.secret]   64-hex scalar; random if omitted
 * @param {(shardBytes:Uint8Array, meta:{shareIndex:number}) => Promise<string>} p.put
 *        stores one shard and returns its 'shard:<hash>' address
 * @returns {Promise<{ key, secretPoint, threshold, count, commitmentRoot,
 *   shareManifest:Array<{shareIndex:number, shard:string, shareCommitment:string}> }>}
 *   key/secretPoint are DEALER-PRIVATE — exactly what a reader reconstructs.
 */
export async function disperseSecret ({ count, threshold, secret, put } = {}) {
  if (typeof put !== 'function') throw new Error('disperseSecret: put(shardBytes, meta) required')
  const plan = await planDispersal({ count, threshold, secret })

  const shareManifest = []
  for (const s of plan.shares) {
    const shard = await put(s.bytes, { shareIndex: s.shareIndex })
    if (normalizeAddress(shard) !== s.shard) {
      throw new Error('disperseSecret: relay stored a different hash for share ' + s.shareIndex)
    }
    shareManifest.push({ shareIndex: s.shareIndex, shard: s.shard, shareCommitment: s.shareCommitment })
  }

  return {
    key: plan.key,
    secretPoint: plan.secretPoint,
    threshold: plan.threshold,
    count: plan.count,
    commitmentRoot: plan.commitmentRoot,
    shareManifest
  }
}

/**
 * DEALER, phase 1 — split + encode every share WITHOUT storing anything, so a
 * caller can learn each share's content address up front (to bind them into a
 * signed custody intent and PUBLISH that intent to the relays) BEFORE the shards
 * are PUT and authorized against it. disperseSecret() is this plus the PUT loop.
 *
 * @param {object} p
 * @param {number} p.count      n — total shares (>= threshold)
 * @param {number} p.threshold  k
 * @param {string} [p.secret]   64-hex scalar; random if omitted
 * @returns {Promise<{ key, secretPoint, threshold, count, commitmentRoot,
 *   shares:Array<{shareIndex:number, bytes:Uint8Array, shard:string, shareCommitment:string}> }>}
 *   shares are ordered by shareIndex; `shard` is the content address the relay
 *   will store the bytes under, `shareCommitment` = S_i = p(i)*G.
 */
export async function planDispersal ({ count, threshold, secret } = {}) {
  if (!Number.isInteger(count) || count < 1) throw new Error('planDispersal: count >= 1 required')
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > count) {
    throw new Error('planDispersal: 1 <= threshold <= count required')
  }

  const holders = []
  for (let i = 0; i < count; i++) holders.push(await keygen())
  const dealt = await split({ threshold, shareholders: holders.map(h => h.publicKey), secret })

  const shares = []
  for (const enc of dealt.public.encryptedShares) {
    const holder = holders[enc.index - 1]
    const share = await decryptShare({ encryptedShare: enc, secretKey: holder.secretKey })
    const bytes = encodeShareShard(share)
    // shareCommitment for index i IS S_i = p(i)*G — the same Feldman-verifiable
    // point a reader checks and a relay's shareVerified gate binds its blob to
    // (BLIND-SHARD-STORE-SPEC.md §9.3).
    shares.push({ shareIndex: enc.index, bytes, shard: shardAddressOf(bytes), shareCommitment: share.share })
  }

  return {
    key: dealt.key,
    secretPoint: dealt.secretPoint,
    threshold,
    count,
    commitmentRoot: dealt.public.commitmentRoot,
    shares
  }
}

/**
 * READER: collect >= threshold shards named by the manifest via the injected
 * fetch(), verify each by content address, decode, and reconstruct the secret —
 * entirely at the reader's edge. No relay ever holds the whole secret.
 *
 * Each manifest entry MUST carry the committed share point
 * (shareCommitment = S_i = p(i)*G); a fetched share whose point does not equal
 * that commitment is rejected. See the INTEGRITY CONTRACT above.
 *
 * @param {object} p
 * @param {Array<{shareIndex:number, shard:string, shareCommitment:string}>} p.shareManifest
 * @param {number} p.threshold  k
 * @param {(shardAddress:string) => Promise<Uint8Array|null>} p.fetch
 *        returns the opaque shard bytes for an address, or null if unavailable
 * @returns {Promise<{ ok:boolean, key?:string, secretPoint?:string,
 *   used?:number, collected:number, need:number, reason?:string }>}
 */
export async function recoverSecret ({ shareManifest, threshold, fetch } = {}) {
  if (!Array.isArray(shareManifest)) throw new Error('recoverSecret: shareManifest array required')
  if (!Number.isInteger(threshold) || threshold < 1) throw new Error('recoverSecret: threshold >= 1 required')
  if (typeof fetch !== 'function') throw new Error('recoverSecret: fetch(shard) required')

  const shares = []
  const seenAddr = new Set()
  const seenIndex = new Set()
  for (const entry of shareManifest) {
    if (shares.length >= threshold) break
    if (!entry || typeof entry.shard !== 'string') continue
    // The manifest MUST commit to this share's point. Without a well-formed
    // commitment the share cannot be validated, so it is unusable (fail closed).
    const commitment = typeof entry.shareCommitment === 'string' ? entry.shareCommitment.toLowerCase() : null
    if (!commitment || !POINT.test(commitment)) continue
    const address = normalizeAddress(entry.shard)
    if (seenAddr.has(address)) continue
    seenAddr.add(address)
    let bytes = null
    try { bytes = await fetch(address) } catch { bytes = null }
    if (!bytes || !bytes.length) continue
    // Content-address integrity: a relay returning wrong/garbage bytes for the
    // hash is caught here — no relay is trusted for the bytes.
    if (shardAddressOf(bytes) !== address) continue
    let share
    try { share = decodeShareShard(bytes) } catch { continue }
    // Commitment binding: the decoded share point MUST equal the point the
    // (authenticated) manifest commits to. A valid DLEQ proof alone is forgeable
    // — it only proves S_i is the honest decryption of an attacker-suppliable
    // encryptedShare — so this equality is what actually stops a substituted
    // share from silently reconstructing a WRONG secret.
    if (share.share.toLowerCase() !== commitment) continue
    if (seenIndex.has(share.index)) continue // duplicate share index is unusable
    seenIndex.add(share.index)
    shares.push(share)
  }

  if (shares.length < threshold) {
    return { ok: false, collected: shares.length, need: threshold, reason: 'INSUFFICIENT_SHARDS' }
  }
  // reconstruct() re-verifies every share's DLEQ proof and Lagrange-interpolates
  // in the exponent — a substituted/forged share throws rather than corrupts.
  const out = await reconstruct({ shares, threshold })
  return { ok: true, key: out.key, secretPoint: out.secretPoint, used: shares.length, collected: shares.length, need: threshold }
}
