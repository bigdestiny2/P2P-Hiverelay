/**
 * Blind-custody dispersal — the app-facing one-call orchestration over a relay
 * set. It ties together the pieces proven separately:
 *
 *   planDispersal (blind-shards)  — split a secret into n opaque shards
 *   createHttpShardPut/Fetch (shard-transport) — move them over /api/v1/shard
 *   the custody intent            — the signed binding a relay authorizes against
 *
 * `disperse()` plans the shards, assigns share i to relay i (so no operator holds
 * >= threshold), lets the app PUBLISH the signed custody intent (relays authorize
 * PUTs against it) and SIGN each custody pin, then PUTs every shard to its relay.
 * `recover()` gathers >= threshold shards from the relay set and reconstructs the
 * secret at the reader's edge.
 *
 * SIGNING + PUBLISHING ARE INJECTED, not done here: the publisher key and each
 * relay's write credential belong to the app, and the custody-pin signature must
 * stay byte-identical to the relay's verifier. This module owns the ORCHESTRATION
 * (planning, relay assignment, routing, reconstruction) — never the app's keys.
 *
 * The returned `shareAssignments` + `shareManifest` + `commitmentRoot` are exactly
 * the fields a v2 custody intent binds, so the app can build/sign the intent with
 * custody.js `createCustodyIntent` and hand it to `publishIntent`.
 */
import { planDispersal, recoverSecret } from './blind-shards.js'
import { createHttpShardPut, createHttpShardFetch } from './shard-transport.js'

function assertRelays (relays, threshold, where) {
  if (!Array.isArray(relays) || relays.length < 1) throw new Error(where + ': relays[] required')
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > relays.length) {
    throw new Error(where + ': 1 <= threshold <= relays.length required')
  }
  for (const r of relays) {
    if (!r || typeof r.baseUrl !== 'string' || !r.baseUrl) throw new Error(where + ': each relay needs a baseUrl')
  }
}

/**
 * DEALER: disperse `secret` across `relays` (share i → relays[i]), k-of-n.
 *
 * @param {string|undefined} secret  64-hex scalar; random if omitted
 * @param {object} o
 * @param {Array<{baseUrl:string, pubkey?:string}>} o.relays  the n custodians, in
 *        share-index order (share i is assigned to relays[i-1])
 * @param {number} o.threshold  k — shards needed to reconstruct
 * @param {(ctx:{hash:string, address:string, shareIndex:number, relay:object}) => Promise<object>|object} o.signPin
 *        signs the custody pin for one shard PUT
 * @param {(relay:object, intent:{shareManifest, shareAssignments, commitmentRoot, threshold, count}) => Promise<any>} [o.publishIntent]
 *        publishes the signed custody intent to a relay so its PUT authorizes;
 *        called once per relay before any PUT. Omit only against relays whose
 *        authorization is arranged out of band (e.g. tests with a stub resolver).
 * @param {typeof fetch} [o.fetch]
 * @returns {Promise<{ key, secretPoint, threshold, count, commitmentRoot,
 *   shareManifest, shareAssignments, refs:Array<object> }>}
 *   key/secretPoint are DEALER-PRIVATE (what a reader reconstructs).
 */
export async function disperse (secret, { relays, threshold, signPin, publishIntent, fetch } = {}) {
  assertRelays(relays, threshold, 'disperse')
  if (typeof signPin !== 'function') throw new Error('disperse: signPin(ctx) required')

  const plan = await planDispersal({ count: relays.length, threshold, secret })

  const shareAssignments = plan.shares.map((s) => ({
    relayPubkey: relays[s.shareIndex - 1].pubkey,
    shareIndex: s.shareIndex
  }))
  const shareManifest = plan.shares.map((s) => ({
    shareIndex: s.shareIndex,
    shard: s.shard,
    shareCommitment: s.shareCommitment
  }))
  const intent = { shareManifest, shareAssignments, commitmentRoot: plan.commitmentRoot, threshold, count: relays.length }

  // Publish the (app-signed) intent to every relay FIRST, so each PUT authorizes
  // against a custody intent the relay has already indexed.
  if (typeof publishIntent === 'function') {
    for (const relay of relays) await publishIntent(relay, intent)
  }

  // Route share i → relays[i] and PUT over /api/v1/shard.
  const refs = []
  for (const s of plan.shares) {
    const relay = relays[s.shareIndex - 1]
    const put = createHttpShardPut({
      baseUrl: relay.baseUrl,
      signPin: (ctx) => signPin({ ...ctx, shareIndex: s.shareIndex, relay }),
      fetch
    })
    refs.push({ shareIndex: s.shareIndex, shard: await put(s.bytes, { shareIndex: s.shareIndex }) })
  }

  return {
    key: plan.key,
    secretPoint: plan.secretPoint,
    threshold,
    count: relays.length,
    commitmentRoot: plan.commitmentRoot,
    shareManifest,
    shareAssignments,
    refs
  }
}

/**
 * READER: gather >= threshold shards from `relays` and reconstruct the secret.
 * Integrity rests on an AUTHENTIC `shareManifest` (from a publisher-signed custody
 * intent) — see the contract in blind-shards.js.
 *
 * @param {object} o
 * @param {Array<{baseUrl:string}>} o.relays
 * @param {Array<{shareIndex:number, shard:string, shareCommitment:string}>} o.shareManifest
 * @param {number} o.threshold
 * @param {typeof fetch} [o.fetch]
 * @returns {Promise<{ ok, key?, secretPoint?, used?, collected, need, reason? }>}
 */
export async function recover ({ relays, shareManifest, threshold, fetch } = {}) {
  if (!Array.isArray(relays) || !relays.length) throw new Error('recover: relays[] required')
  const baseUrls = relays.map((r) => r && r.baseUrl).filter(Boolean)
  const fetchShard = createHttpShardFetch({ baseUrls, fetch })
  return recoverSecret({ shareManifest, threshold, fetch: fetchShard })
}
