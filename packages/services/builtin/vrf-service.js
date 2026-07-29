/**
 * VRF Service — Verifiable Random Functions (RFC 9381)
 *
 * Offers ECVRF-EDWARDS25519-SHA512-TAI as a relay capability: the relay holds
 * a secret key and, for any input `alpha`, returns a deterministic pseudorandom
 * output `beta` plus a proof `pi` that anyone can verify against the relay's
 * VRF public key. The relay cannot bias `beta`, and verifiers need no trust.
 *
 * Use cases this unlocks for apps:
 *   - Unbiasable shuffles / deals (e.g. poker, lotteries)
 *   - Fair leader / committee / arbitrator selection
 *   - A public, chained randomness beacon (see beacon.js)
 *
 * Key handling: rather than reuse the node's EdDSA identity key directly (which
 * would mean the same scalar signs protocol messages AND produces VRF proofs),
 * we derive a DEDICATED VRF seed from it via domain separation:
 *
 *     vrf_seed = SHA-512("hiverelay/vrf-key/v1" || node_seed)[0:32]
 *
 * This yields a stable VRF keypair that is deterministically tied to the node
 * but cryptographically separated from its signing key. The VRF public key is
 * therefore NOT the node's identity pubkey — consumers fetch it via `pubkey`.
 *
 * Capabilities:
 *   - prove          : VRF-prove an input under the relay key → { pi, beta }
 *   - verify         : verify (pubkey, alpha, pi) → { valid, beta }
 *   - proof-to-hash  : map a proof to its output beta (does NOT verify)
 *   - pubkey         : the relay's VRF public key + suite
 *   - info           : suite params + beacon status
 *   - select         : verifiable committee sortition over candidates (prove →
 *                      beta → weighted/uniform draw without replacement)
 *   - shuffle        : verifiable permutation of a list (prove → beta → shuffle)
 *   - select-verify  : recheck a committee against (pubkey, alpha, pi, candidates)
 *   - shuffle-verify : recheck an order against (pubkey, alpha, pi, items)
 *   - beacon-info    : beacon genesis/round/retention
 *   - beacon-latest  : the most recent beacon round
 *   - beacon-round   : a specific retained round
 *   - beacon-range   : recent retained rounds
 *   - beacon-verify  : server-side chain verification of retained rounds
 *
 * select/shuffle are the bridge from raw randomness to decisions: the relay
 * binds the draw to a caller-supplied context via `alpha` (e.g. a disputeId or
 * a poker handId), proves it, and applies the deterministic sortition primitive
 * to `beta`. The returned { pi, beta, committee/order } is fully self-verifying
 * — anyone can verify(pubkey, alpha, pi) then replay the sortition locally (or
 * call select-verify / shuffle-verify) with no trust in the relay.
 */

import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import { sha512 } from '@noble/hashes/sha2.js'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import {
  prove, verify, proofToHash, publicKey, toHex, params, PROOF_LEN, SECKEY_LEN
} from './vrf/ecvrf.js'
import { VrfBeacon, verifyBeaconChain, DEFAULT_DOMAIN, DEFAULT_RETAIN } from './vrf/beacon.js'
import {
  seededShuffle, weightedSample, verifyCommittee, verifyShuffle
} from './vrf/sortition.js'

const VRF_KEY_DOMAIN = 'hiverelay/vrf-key/v1'
const DEFAULT_MAX_ALPHA_BYTES = 4096
const DEFAULT_MAX_SORTITION_ITEMS = 100_000
const MIN_BEACON_INTERVAL_MS = 1000
const DEFAULT_BEACON_INTERVAL_MS = 30_000

function toBytes (value, name) {
  if (value instanceof Uint8Array) return value
  if (b4a.isBuffer(value)) return new Uint8Array(value)
  if (typeof value === 'string') {
    if (value.length % 2 !== 0 || /[^0-9a-fA-F]/.test(value)) {
      throw new Error(`INVALID_PARAM: ${name} must be valid hex`)
    }
    const out = new Uint8Array(value.length / 2)
    for (let i = 0; i < out.length; i++) out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16)
    return out
  }
  throw new Error(`INVALID_PARAM: ${name} must be a hex string`)
}

/** Domain-separated derivation of a dedicated VRF seed from a node seed. */
function deriveVrfSeed (nodeSeed) {
  const domain = new TextEncoder().encode(VRF_KEY_DOMAIN)
  const input = new Uint8Array(domain.length + nodeSeed.length)
  input.set(domain, 0)
  input.set(nodeSeed, domain.length)
  return sha512(input).slice(0, 32)
}

export class VRFService extends ServiceProvider {
  constructor (opts = {}) {
    super()
    this.node = null
    this._seed = null // 32-byte VRF seed (dedicated, derived)
    this._pubkey = null // hex
    this.ephemeral = false
    this.maxAlphaBytes = opts.maxAlphaBytes || DEFAULT_MAX_ALPHA_BYTES
    this.maxSortitionItems = opts.maxSortitionItems || DEFAULT_MAX_SORTITION_ITEMS

    // Stash a node keypair if the relay handed one in (bare-relay does).
    this._keyPair = opts.keyPair || null
    // Allow an explicit override seed (mainly for tests / fixed deployments).
    this._explicitSeed = opts.seed ? toBytes(opts.seed, 'seed') : null

    // Beacon is opt-in. opts.beacon: { enabled, intervalMs, domain, retain }.
    // Node's generic PluginLoader constructs every provider before it has the
    // service context, so start() also accepts context.config.vrfBeacon when
    // no explicit constructor descriptor was supplied.
    this._beaconConfigExplicit = Object.prototype.hasOwnProperty.call(opts, 'beacon')
    this._configureBeacon(opts.beacon)
    this.beacon = null
    this._beaconTimer = null
  }

  _configureBeacon (value) {
    const b = value && typeof value === 'object' && !Array.isArray(value) ? value : {}
    this.beaconConfig = {
      enabled: b.enabled === true,
      intervalMs: Math.max(MIN_BEACON_INTERVAL_MS, b.intervalMs || DEFAULT_BEACON_INTERVAL_MS),
      domain: b.domain || DEFAULT_DOMAIN,
      retain: b.retain || DEFAULT_RETAIN
    }
  }

  manifest () {
    return {
      name: 'vrf',
      version: '1.0.0',
      description: 'Verifiable Random Functions (ECVRF-EDWARDS25519-SHA512-TAI, RFC 9381) + chained randomness beacon',
      capabilities: [
        'prove', 'verify', 'proof-to-hash', 'pubkey', 'info',
        'select', 'shuffle', 'select-verify', 'shuffle-verify',
        'beacon-info', 'beacon-latest', 'beacon-round', 'beacon-range', 'beacon-verify'
      ]
    }
  }

  async start (context = {}) {
    this.node = context.node || null
    if (!this._beaconConfigExplicit && context.config && context.config.vrfBeacon) {
      this._configureBeacon(context.config.vrfBeacon)
    }

    // Resolve the source key material, in priority order.
    let nodeSeed = null
    if (this._explicitSeed) {
      // Explicit seed is used directly as the VRF seed (no extra derivation).
      this._seed = this._explicitSeed
    } else {
      const secretKey = this._keyPair?.secretKey || this.node?.keyPair?.secretKey
      if (secretKey) {
        // sodium ed25519 secret key is seed(32) || pubkey(32); take the seed.
        nodeSeed = new Uint8Array(b4a.isBuffer(secretKey) ? secretKey : b4a.from(secretKey)).slice(0, 32)
        this._seed = deriveVrfSeed(nodeSeed)
      } else {
        // No node key available — generate a stable-for-this-process seed so the
        // service still functions. Its pubkey won't survive a restart; operators
        // who need a persistent beacon must run with a node keypair.
        this._seed = sha512(this._randomBytes(32)).slice(0, 32)
        this.ephemeral = true
      }
    }

    if (this._seed.length !== SECKEY_LEN) throw new Error('VRF_SEED_INVALID')
    this._pubkey = toHex(publicKey(this._seed))

    if (this.beaconConfig.enabled) this._startBeacon()
  }

  async stop () {
    if (this._beaconTimer) {
      clearInterval(this._beaconTimer)
      this._beaconTimer = null
    }
  }

  /** Supervision hook: the service is healthy once it has a usable VRF key. */
  healthCheck () {
    return this._seed != null && this._pubkey != null
  }

  _randomBytes (n) {
    const out = b4a.alloc(n)
    sodium.randombytes_buf(out)
    return new Uint8Array(out)
  }

  _startBeacon () {
    const proveFn = (alphaBytes) => prove(this._seed, alphaBytes)
    this.beacon = new VrfBeacon({
      proveFn,
      pubkey: this._pubkey,
      domain: this.beaconConfig.domain,
      retain: this.beaconConfig.retain
    })
    // Produce the first round immediately so latest() is populated.
    try { this.beacon.advance() } catch {}
    this._beaconTimer = setInterval(() => {
      try { this.beacon.advance() } catch {}
    }, this.beaconConfig.intervalMs)
    if (typeof this._beaconTimer.unref === 'function') this._beaconTimer.unref()
  }

  _assertReady () {
    if (!this._seed) throw new Error('SERVICE_UNAVAILABLE: VRF key not initialized')
  }

  // ── core VRF RPC ──────────────────────────────────────────────────────────

  async prove (params_ = {}) {
    this._assertReady()
    if (params_.alpha == null) throw new Error('INVALID_PARAM: alpha is required (hex)')
    const alpha = toBytes(params_.alpha, 'alpha')
    if (alpha.length > this.maxAlphaBytes) {
      throw new Error(`INVALID_PARAM: alpha exceeds ${this.maxAlphaBytes} bytes`)
    }
    const pi = prove(this._seed, alpha)
    const beta = proofToHash(pi)
    return {
      alpha: toHex(alpha),
      pi: toHex(pi),
      beta: toHex(beta),
      pubkey: this._pubkey,
      suite: params.suite
    }
  }

  async verify (params_ = {}) {
    const { pubkey, alpha, pi } = params_
    if (pubkey == null || alpha == null || pi == null) {
      throw new Error('INVALID_PARAM: pubkey, alpha and pi are required')
    }
    let valid = false
    let beta = null
    try {
      valid = verify(pubkey, alpha, pi)
      if (valid) beta = toHex(proofToHash(pi))
    } catch {
      valid = false
    }
    return { valid, beta }
  }

  async 'proof-to-hash' (params_ = {}) {
    if (params_.pi == null) throw new Error('INVALID_PARAM: pi is required')
    const piBytes = toBytes(params_.pi, 'pi')
    if (piBytes.length !== PROOF_LEN) throw new Error('INVALID_PARAM: pi must be 80 bytes')
    return { beta: toHex(proofToHash(piBytes)) }
  }

  async pubkey () {
    this._assertReady()
    return { pubkey: this._pubkey, suite: params.suite, ephemeral: this.ephemeral }
  }

  async info () {
    return {
      suite: params.suite,
      proofLen: params.proofLen,
      betaLen: params.betaLen,
      pubkey: this._pubkey,
      ephemeral: this.ephemeral,
      beacon: this.beacon
        ? { ...this.beacon.info(), intervalMs: this.beaconConfig.intervalMs }
        : { enabled: false }
    }
  }

  // ── sortition RPC (committee selection + shuffling) ───────────────────────

  /** Validate + VRF-prove a context alpha, returning { pi, betaBytes }. */
  _proveAlpha (rawAlpha) {
    if (rawAlpha == null) throw new Error('INVALID_PARAM: alpha is required (hex)')
    const alpha = toBytes(rawAlpha, 'alpha')
    if (alpha.length > this.maxAlphaBytes) {
      throw new Error(`INVALID_PARAM: alpha exceeds ${this.maxAlphaBytes} bytes`)
    }
    const pi = prove(this._seed, alpha)
    return { alpha, pi, betaBytes: proofToHash(pi) }
  }

  /**
   * Verifiable committee sortition. The relay binds the draw to `alpha` (the
   * caller's context, e.g. a disputeId), proves it, and selects `count`
   * candidates from `candidates` using beta as the seed. With weighted=true,
   * candidates must be { id, weight } with non-negative INTEGER weights (use the
   * sortition quantizeWeights helper for reputation floats). Returns the proof
   * so the result is independently checkable via verify + verifyCommittee (or
   * the select-verify capability).
   */
  async select (params_ = {}) {
    this._assertReady()
    const { candidates } = params_
    if (!Array.isArray(candidates)) throw new Error('INVALID_PARAM: candidates must be an array')
    if (candidates.length > this.maxSortitionItems) {
      throw new Error(`INVALID_PARAM: candidates exceeds ${this.maxSortitionItems}`)
    }
    const count = Number(params_.count)
    if (!Number.isInteger(count) || count < 0) {
      throw new Error('INVALID_PARAM: count must be a non-negative integer')
    }
    const weighted = params_.weighted === true
    const domain = params_.domain
    const { alpha, pi, betaBytes } = this._proveAlpha(params_.alpha)
    let committee
    try {
      committee = weightedSample({ seed: betaBytes, candidates, count, weighted, domain })
    } catch (err) {
      throw new Error('INVALID_PARAM: ' + err.message)
    }
    return {
      alpha: toHex(alpha),
      pi: toHex(pi),
      beta: toHex(betaBytes),
      pubkey: this._pubkey,
      suite: params.suite,
      count,
      weighted,
      committee
    }
  }

  /**
   * Verifiable permutation. Proves `alpha` and returns `items` deterministically
   * shuffled by beta. Items are returned as-is (any JSON), so the ordering — not
   * the contents — is what the proof attests.
   */
  async shuffle (params_ = {}) {
    this._assertReady()
    const { items } = params_
    if (!Array.isArray(items)) throw new Error('INVALID_PARAM: items must be an array')
    if (items.length > this.maxSortitionItems) {
      throw new Error(`INVALID_PARAM: items exceeds ${this.maxSortitionItems}`)
    }
    const domain = params_.domain
    const { alpha, pi, betaBytes } = this._proveAlpha(params_.alpha)
    const order = seededShuffle(betaBytes, items, domain ? { domain } : {})
    return {
      alpha: toHex(alpha),
      pi: toHex(pi),
      beta: toHex(betaBytes),
      pubkey: this._pubkey,
      suite: params.suite,
      count: items.length,
      order
    }
  }

  /**
   * Re-check a committee with no trust in the producing relay: verifies the VRF
   * proof under `pubkey`, derives beta, and confirms `committee` is exactly what
   * the sortition yields for (candidates, count, weighted, domain).
   */
  async 'select-verify' (params_ = {}) {
    const { pubkey, alpha, pi, candidates, count, weighted = false, domain, committee } = params_
    if (pubkey == null || alpha == null || pi == null) {
      throw new Error('INVALID_PARAM: pubkey, alpha and pi are required')
    }
    if (!Array.isArray(candidates)) throw new Error('INVALID_PARAM: candidates must be an array')
    if (!Array.isArray(committee)) throw new Error('INVALID_PARAM: committee must be an array')
    let vrfValid = false
    let committeeValid = false
    let beta = null
    try {
      vrfValid = verify(pubkey, alpha, pi)
      if (vrfValid) {
        const betaBytes = proofToHash(pi)
        beta = toHex(betaBytes)
        committeeValid = verifyCommittee({
          seed: betaBytes, candidates, count: Number(count), weighted: weighted === true, domain, expected: committee
        })
      }
    } catch {
      vrfValid = false
    }
    return { valid: vrfValid && committeeValid, vrfValid, committeeValid, beta }
  }

  /** Re-check a shuffle: verifies the VRF proof, derives beta, replays the order. */
  async 'shuffle-verify' (params_ = {}) {
    const { pubkey, alpha, pi, items, domain, order } = params_
    if (pubkey == null || alpha == null || pi == null) {
      throw new Error('INVALID_PARAM: pubkey, alpha and pi are required')
    }
    if (!Array.isArray(items)) throw new Error('INVALID_PARAM: items must be an array')
    if (!Array.isArray(order)) throw new Error('INVALID_PARAM: order must be an array')
    let vrfValid = false
    let orderValid = false
    let beta = null
    try {
      vrfValid = verify(pubkey, alpha, pi)
      if (vrfValid) {
        const betaBytes = proofToHash(pi)
        beta = toHex(betaBytes)
        orderValid = verifyShuffle(betaBytes, items, order, domain ? { domain } : {})
      }
    } catch {
      vrfValid = false
    }
    return { valid: vrfValid && orderValid, vrfValid, orderValid, beta }
  }

  // ── beacon RPC ──────────────────────────────────────────────────────────────

  _assertBeacon () {
    if (!this.beacon) throw new Error('BEACON_DISABLED: VRF beacon is not enabled on this relay')
  }

  async 'beacon-info' () {
    this._assertBeacon()
    return { ...this.beacon.info(), intervalMs: this.beaconConfig.intervalMs, genesis: this.beacon.genesis() }
  }

  async 'beacon-latest' () {
    this._assertBeacon()
    const latest = this.beacon.latest()
    if (!latest) return { round: 0, ...this.beacon.genesis(), pending: true }
    return latest
  }

  async 'beacon-round' (params_ = {}) {
    this._assertBeacon()
    const r = Number(params_.round)
    if (!Number.isInteger(r) || r < 0) throw new Error('INVALID_PARAM: round must be a non-negative integer')
    if (r === 0) return this.beacon.genesis()
    const record = this.beacon.round(r)
    if (!record) throw new Error('NOT_FOUND: round not retained')
    return record
  }

  async 'beacon-range' (params_ = {}) {
    this._assertBeacon()
    const count = params_.count != null ? Number(params_.count) : 16
    return { records: this.beacon.range(count), info: this.beacon.info() }
  }

  async 'beacon-verify' (params_ = {}) {
    this._assertBeacon()
    const count = params_.count != null ? Number(params_.count) : this.beacon.range(this.beacon.retain).length
    const records = this.beacon.range(count)
    return verifyBeaconChain({ pubkey: this._pubkey, domain: this.beaconConfig.domain, records })
  }
}
