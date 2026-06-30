/**
 * StorageProofService — Tier-2 trustless seed verification (relay side).
 *
 * Answers `prove({ coreKey, index, nonce })` with a signed Hypercore Merkle
 * proof for block `index` of a SEEDED drive's metadata core, signed with the
 * relay's swarm identity key. The caller verifies it with `verifyStorageProof`
 * against the drive key alone — the relay is trusted for nothing. See
 * packages/core/core/protocol/proof-of-storage.js for the proof itself.
 *
 * SECURITY:
 *  - PRIVACY GATE: never confirms possession of a BLIND / privacy-redacted
 *    drive. A signed proof is cryptographic, relay-attributable evidence that
 *    this relay holds a key; serving it for a blind drive would defeat the
 *    catalog's deliberate redaction (AppRegistry._shouldRedactEntry). Blind/
 *    redacted keys return NOT_SEEDED — INDISTINGUISHABLE from a key the relay
 *    genuinely doesn't hold, so prove() can't be used as a possession oracle.
 *  - PHANTOM-CORE DoS GUARD: only serves keys present in node.appRegistry. It
 *    NEVER calls store.get() on a caller-supplied key (which would create an
 *    unbounded phantom Hypercore per request).
 *  - RATE LIMIT: a GLOBAL token bucket caps total proof work regardless of how
 *    many ephemeral swarm identities connect (the per-caller bucket alone is
 *    bypassable by rotating identities). The global bucket is consumed only for
 *    REAL proof work — cheap rejects (bad input / not-seeded / blind) never
 *    spend it, so a not-seeded flood can't starve honest callers. The per-caller
 *    bucket Map is idle-evicted + size-capped so it can't grow unbounded.
 *  - buildStorageProof reads LOCAL storage only and throws BLOCK_NOT_LOCAL /
 *    BLOCK_OUT_OF_RANGE if the relay doesn't actually hold the block.
 *
 * v1 proves the drive's METADATA core (drive.core) — the head the client learns
 * from open(), so its minLength pin lines up. Proving the blobs core is a
 * follow-up (needs a `core: meta|blobs` selector + a timeout-guarded getBlobs()).
 */

import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import {
  PROOF_KIND_RETRIEVABILITY,
  RETRIEVABILITY_PROOF_LIMITATION,
  RETRIEVABILITY_PROOF_SIGNATURE_PROFILE,
  STORAGE_PROOF_LEGACY_SIGNATURE_PROFILE
} from 'p2p-hiverelay/core/protocol/proof-of-storage.js'
import { RetrievabilityProofProvider } from 'p2p-hiverelay/core/relay-node/retrievability-proof.js'

export class StorageProofService extends ServiceProvider {
  constructor (opts = {}) {
    super()
    this._provider = new RetrievabilityProofProvider(opts)
  }

  get _buckets () {
    return this._provider._buckets
  }

  manifest () {
    return {
      name: 'storage-proof',
      version: '1.0.0',
      description: 'Signed challenge-response proof-of-retrievability for seeded blocks',
      capabilities: ['prove'],
      proofKind: PROOF_KIND_RETRIEVABILITY,
      proofLimit: RETRIEVABILITY_PROOF_LIMITATION,
      signatureProfiles: [
        STORAGE_PROOF_LEGACY_SIGNATURE_PROFILE,
        RETRIEVABILITY_PROOF_SIGNATURE_PROFILE
      ],
      preferredSignatureProfile: RETRIEVABILITY_PROOF_SIGNATURE_PROFILE
    }
  }

  async start (context = {}) {
    this._provider.start(context)
  }

  async stop () {
    await this._provider.stop()
  }

  /**
   * Produce a signed proof of possession for block `index` of a seeded,
   * non-private drive's metadata core.
   * @param {{coreKey:string, index:number, nonce:string, signatureProfile?:string}} params
   * @param {{remotePubkey?:Buffer|string, caller?:string}} context
   */
  async prove (params = {}, context = {}) {
    return this._provider.prove(params, context)
  }
}
