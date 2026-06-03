/**
 * Decentralized Arbitration Service
 *
 * Peer-adjudicated dispute resolution for the relay network.
 * Disputes are submitted with evidence (bandwidth receipts, proof-of-relay
 * results, SLA contracts). High-reputation relay nodes vote on the outcome.
 * Winners gain reputation; losers are slashed.
 *
 * Arbitrator eligibility: score > 100, reliability > 0.95, 50+ challenges,
 * not a party to the dispute.
 *
 * ─── Application disputes (poker/*) ─────────────────────────────────────────
 * In addition to the original relay-level dispute classes (sla-violation,
 * proof-failure, receipt-dispute), this service now accepts a small set of
 * application-level dispute types for the poker substrate. These piggyback
 * on the same arbitration machinery (submit → vote → resolve → slash) but
 * carry app-specific evidence shapes:
 *
 *   'poker/missing-share'    — a player was expected to publish a
 *                              decryption share for a board / hole card by
 *                              tick T, didn't. Evidence: signed-log proof
 *                              that the share is absent past the deadline.
 *
 *   'poker/invalid-share'    — a published share fails the verification
 *                              equation for ciphertext X. Evidence: the
 *                              ciphertext, the bad share, and the falsifying
 *                              witness (everything the verifier needs to
 *                              re-check the failure deterministically).
 *
 *   'poker/refused-reveal'   — a player was in the pot at showdown and did
 *                              not publish their reveal within the timeout
 *                              window. Evidence: signed-log proof of the
 *                              showdown state + the timeout deadline.
 *
 * The arbitration service does NOT re-run the poker protocol. It accepts
 * the structured evidence at submit time, runs a fast schema/well-formedness
 * check, and surfaces the result to voters. Voters (relay operators with
 * sufficient reputation) verify the cryptographic claim independently before
 * casting their vote. The final verdict triggers slashing the respondent's
 * stake escrow exactly the same way an SLA violation slashes a relay deposit.
 *
 * Adding new app dispute classes should follow the same pattern: extend
 * VALID_DISPUTE_TYPES, add a verifier in `_appEvidenceVerifiers`, and document
 * the evidence shape here.
 *
 * ─── Verifiable arbitrator panels (opt-in) ──────────────────────────────────
 * By default this service uses OPEN voting: any peer that clears the
 * eligibility bar may vote, and the first `minVotes` decide. That is simple
 * and unchanged.
 *
 * When `panel.enabled` is set (constructor opts or node config), each new
 * dispute instead draws a fixed committee up-front via the VRF service: alpha
 * is bound to the immutable dispute content, the relay proves it, and the
 * resulting unbiasable `beta` seeds a reputation-WEIGHTED sortition over the
 * eligible pool (sortition.js). Only the drawn members may then vote. The
 * dispute records the candidate snapshot + proof, so any peer can replay
 * verify(vrfPubkey, alpha, pi) → beta → weightedSample(...) and confirm the
 * committee was not hand-picked.
 *
 * Trust note: the VRF holder (the relay) cannot bias WHICH members are drawn
 * from a given pool, but — holding the key — it could in principle grind the
 * alpha by re-deriving it. We bind alpha to immutable dispute fields to make
 * that observable; for adversarial deployments the alpha should additionally
 * fold in an external/committee randomness beacon the relay does not control.
 * If a panel cannot be formed (VRF unavailable, pool smaller than the panel
 * size) the dispute transparently falls back to open voting.
 */

import crypto from 'crypto'
import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import { quantizeWeights } from './vrf/sortition.js'

const MIN_ARBITRATOR_SCORE = 100
const MIN_ARBITRATOR_RELIABILITY = 0.95
const MIN_ARBITRATOR_CHALLENGES = 50
const DEFAULT_MIN_VOTES = 3
const MIN_VOTES_FLOOR = 3

// Verifiable-panel defaults. Panels are OFF unless explicitly enabled.
const DEFAULT_PANEL_SIZE = 5
const PANEL_VRF_SERVICE = 'vrf'
const PANEL_ALPHA_DOMAIN = 'hiverelay/arb-panel/v1'

// Relay-level disputes — the original three classes, unchanged.
const RELAY_DISPUTE_TYPES = ['sla-violation', 'proof-failure', 'receipt-dispute']

// Application-level disputes for the poker substrate. See the file header
// for evidence shape. Namespaced `poker/*` so other apps can claim their own
// namespaces (`liars-dice/*`, `mafia/*`, etc.) without colliding.
const POKER_DISPUTE_TYPES = [
  'poker/missing-share',
  'poker/invalid-share',
  'poker/refused-reveal'
]

const VALID_DISPUTE_TYPES = [...RELAY_DISPUTE_TYPES, ...POKER_DISPUTE_TYPES]

// Loose upper bounds on evidence size for app disputes. Generous enough to
// fit a reasonable autobase-log proof slice + ciphertext + signature blobs,
// tight enough to refuse griefing-by-megabyte. Tune up if real poker traffic
// shows we need more.
const MAX_APP_EVIDENCE_BYTES = 64 * 1024
// Maximum ciphertext / share byte length for poker evidence. ElGamal-style
// ciphertexts and decryption shares are small (<1 KB even at high security
// levels) — anything bigger is almost certainly malformed.
const MAX_POKER_BLOB_BYTES = 2048

export class ArbitrationService extends ServiceProvider {
  constructor (opts = {}) {
    super()
    this.disputes = new Map() // id -> dispute
    this.node = null
    this.config = {}
    // Panel config from constructor opts; merged with node config in start().
    this._panelOpts = opts.panel || null
    this.panelConfig = this._resolvePanelConfig(this._panelOpts)
  }

  /** Merge panel settings from (defaults ← node config ← constructor opts). */
  _resolvePanelConfig (...sources) {
    const merged = {}
    for (const s of sources) { if (s && typeof s === 'object') Object.assign(merged, s) }
    return {
      enabled: merged.enabled === true,
      // A panel must be at least the vote floor or it could never resolve.
      size: Math.max(MIN_VOTES_FLOOR, Number(merged.size) || DEFAULT_PANEL_SIZE),
      weighted: merged.weighted !== false, // reputation-weighted by default
      vrfService: typeof merged.vrfService === 'string' ? merged.vrfService : PANEL_VRF_SERVICE
    }
  }

  manifest () {
    return {
      name: 'arbitration',
      version: '1.0.0',
      description: 'Decentralized dispute resolution for relay incentives',
      capabilities: ['submit', 'vote', 'get', 'list', 'evidence']
    }
  }

  async start (context) {
    this.node = context.node
    this.config = context.config || this.config || {}
    // Node config may carry arbitration.panel; constructor opts win over it.
    const nodePanel = this.config.arbitration?.panel || this.config.arbitrationPanel || null
    this.panelConfig = this._resolvePanelConfig(nodePanel, this._panelOpts)
  }

  async stop () {
    this.disputes.clear()
  }

  /**
   * Submit a new dispute.
   *
   * Relay-level disputes (sla-violation / proof-failure / receipt-dispute)
   * carry their classic evidence (receipts / proofResults / slaContract).
   *
   * Application-level disputes (poker/*) carry their evidence under
   * `params.appEvidence` as a single typed object. The shape is validated
   * at submit time by `_validateAppEvidence` — malformed evidence rejects
   * loudly so the claimant can fix it before votes are wasted on it.
   *
   * @param {object} params
   * @param {string} params.type - One of VALID_DISPUTE_TYPES
   * @param {string} params.respondent - Pubkey hex of the accused party
   *   (relay pubkey for relay disputes; player pubkey for poker disputes)
   * @param {object} [params.receipts] - BandwidthReceipt evidence
   * @param {object} [params.proofResults] - Proof-of-relay challenge results
   * @param {object} [params.slaContract] - SLA contract data
   * @param {object} [params.appEvidence] - Typed evidence for application
   *   disputes. Schema depends on `type`; see the file header.
   * @param {number} [params.penalty] - Requested penalty in sats
   */
  async submit (params, context) {
    if (!params.type || !VALID_DISPUTE_TYPES.includes(params.type)) {
      throw new Error('ARBITRATION_INVALID_TYPE')
    }
    if (!params.respondent || typeof params.respondent !== 'string') {
      throw new Error('ARBITRATION_MISSING_RESPONDENT')
    }

    // App-level disputes MUST carry typed evidence — there's no fallback
    // evidence shape that would make sense (you can't slash a player for
    // 'missing-share' without a pointer to which share was missing).
    // Validate the shape up-front so voters never see malformed cases.
    const isAppDispute = POKER_DISPUTE_TYPES.includes(params.type)
    if (isAppDispute) {
      if (!params.appEvidence || typeof params.appEvidence !== 'object') {
        throw new Error('ARBITRATION_MISSING_APP_EVIDENCE')
      }
      // Throws ARBITRATION_BAD_APP_EVIDENCE with a specific reason on
      // shape mismatch. Caught nowhere here — propagates to the caller.
      this._validateAppEvidence(params.type, params.appEvidence)
    }

    const id = crypto.randomBytes(16).toString('hex')
    // Use authenticated identity when available, fall back to params for local calls
    const claimant = context?.remotePubkey || (context?.caller === 'remote' ? null : params.claimant) || 'local'
    if (context?.caller === 'remote' && !context.remotePubkey) {
      throw new Error('ARBITRATION_UNAUTHORIZED')
    }

    if (claimant === params.respondent) {
      throw new Error('ARBITRATION_SELF_DISPUTE')
    }

    const dispute = {
      id,
      type: params.type,
      claimant,
      respondent: params.respondent,
      evidence: {
        receipts: params.receipts || [],
        proofResults: params.proofResults || [],
        slaContract: params.slaContract || null,
        // App-typed evidence lives alongside the relay-typed slots so a
        // single dispute can in principle carry both (e.g. a future class
        // that mixes relay receipts with a poker share). For now only one
        // side is populated per dispute.
        appEvidence: isAppDispute ? params.appEvidence : null
      },
      votes: new Map(),
      status: 'open',
      verdict: null,
      penalty: Math.min(Math.max(0, params.penalty || 0), this.config?.maxPenalty || 1000000),
      createdAt: Date.now(),
      resolvedAt: null,
      minVotes: Math.max(MIN_VOTES_FLOOR, params.minVotes || this.config?.minVotes || DEFAULT_MIN_VOTES),
      // Verifiable committee (null when panels are off or selection fell back).
      panel: null
    }

    // Per-dispute override: params.panel === true/false forces panels on/off
    // for this dispute regardless of the service default.
    const wantPanel = params.panel === true || (params.panel !== false && this.panelConfig.enabled)
    if (wantPanel) {
      dispute.panel = await this._formPanel(dispute)
      // If a committee was actually drawn, cap the quorum to its size so the
      // dispute can resolve once enough panellists have voted.
      if (dispute.panel?.active) {
        dispute.minVotes = Math.min(dispute.minVotes, dispute.panel.members.length)
      }
    }

    this.disputes.set(id, dispute)

    this.node?.router?.pubsub?.publish('arbitration/submitted', {
      disputeId: id,
      type: dispute.type,
      respondent: dispute.respondent,
      panel: dispute.panel?.active ? dispute.panel.members : null
    })

    return this._serialize(dispute)
  }

  /**
   * Cast a vote on a dispute.
   * @param {object} params
   * @param {string} params.id - Dispute ID
   * @param {string} params.verdict - 'claimant' or 'respondent'
   */
  async vote (params, context) {
    const dispute = this.disputes.get(params.id)
    if (!dispute) throw new Error('DISPUTE_NOT_FOUND')
    if (dispute.status === 'resolved') throw new Error('DISPUTE_ALREADY_RESOLVED')

    if (!params.verdict || !['claimant', 'respondent'].includes(params.verdict)) {
      throw new Error('ARBITRATION_INVALID_VERDICT')
    }

    // Remote callers must use their authenticated identity
    const voter = context?.caller === 'remote'
      ? context.remotePubkey
      : (params.voterPubkey || context?.remotePubkey)
    if (!voter) throw new Error('ARBITRATION_MISSING_VOTER')

    // Eligibility check
    if (!this._isEligibleArbitrator(voter, dispute)) {
      throw new Error('ARBITRATOR_INELIGIBLE')
    }

    // If a verifiable panel was drawn for this dispute, only its members may
    // vote. Open-voting disputes (panel null/inactive) skip this gate.
    if (dispute.panel?.active && !dispute.panel.members.includes(voter)) {
      throw new Error('ARBITRATOR_NOT_ON_PANEL')
    }

    if (dispute.votes.has(voter)) {
      throw new Error('ARBITRATION_ALREADY_VOTED')
    }

    // Record vote
    dispute.votes.set(voter, params.verdict)
    if (dispute.status === 'open') dispute.status = 'voting'

    // Check if resolution threshold met
    if (dispute.votes.size >= dispute.minVotes) {
      this._resolve(dispute)
    }

    return this._serialize(dispute)
  }

  /**
   * Get a dispute by ID.
   */
  async get (params) {
    const dispute = this.disputes.get(params.id)
    if (!dispute) throw new Error('DISPUTE_NOT_FOUND')
    return this._serialize(dispute)
  }

  /**
   * List disputes, optionally filtered.
   * @param {object} [params] - { status?, type? }
   */
  async list (params = {}) {
    const result = []
    for (const dispute of this.disputes.values()) {
      if (params.status && dispute.status !== params.status) continue
      if (params.type && dispute.type !== params.type) continue
      result.push(this._serialize(dispute))
    }
    return result
  }

  /**
   * Verify evidence attached to a dispute.
   *
   * - Bandwidth receipts are verified via BandwidthReceipt.verify().
   * - Poker / app evidence is verified via the per-type verifier in
   *   `_verifyAppEvidence` and surfaced under `appEvidence`. Verifiers are
   *   deliberately conservative: a verifier that can't make a determination
   *   returns `{ verdict: 'inconclusive', reason }` rather than guessing.
   *   Voters take inconclusive verdicts as a signal to inspect raw evidence
   *   themselves before voting.
   */
  async evidence (params) {
    const dispute = this.disputes.get(params.id)
    if (!dispute) throw new Error('DISPUTE_NOT_FOUND')

    const receiptResults = []

    for (const receipt of dispute.evidence.receipts) {
      let valid = false
      try {
        // Dynamic import to avoid hard dep
        const { BandwidthReceipt } = await import('../../protocol/bandwidth-receipt.js')
        valid = BandwidthReceipt.verify(receipt)
      } catch {
        valid = false
      }
      receiptResults.push({ receipt, valid })
    }

    // App-level evidence: only present on poker/* disputes today. The
    // verifier never throws — anything it can't classify becomes an
    // 'inconclusive' verdict the voter handles manually.
    let appEvidenceResult = null
    if (dispute.evidence.appEvidence) {
      appEvidenceResult = this._verifyAppEvidence(dispute.type, dispute.evidence.appEvidence)
    }

    return {
      receipts: receiptResults,
      proofResults: dispute.evidence.proofResults,
      slaContract: dispute.evidence.slaContract,
      appEvidence: appEvidenceResult
    }
  }

  // ─── App evidence: schema validation (at submit time) ──────────────────────
  //
  // These checks are intentionally CHEAP — shape, type, byte budget, basic
  // identifier well-formedness. They're not cryptographic. Their purpose is
  // to reject obviously-malformed disputes at submission so voters never
  // waste a vote on something that can't be evaluated. The actual
  // cryptographic re-check is `_verifyAppEvidence`, run at `evidence()` time
  // and by voters before they cast their vote.

  _validateAppEvidence (type, ae) {
    const size = JSON.stringify(ae).length
    if (size > MAX_APP_EVIDENCE_BYTES) {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:oversized')
    }
    switch (type) {
      case 'poker/missing-share':
        return this._validateMissingShare(ae)
      case 'poker/invalid-share':
        return this._validateInvalidShare(ae)
      case 'poker/refused-reveal':
        return this._validateRefusedReveal(ae)
      default:
        // Unknown app type — should be unreachable because submit() guards
        // on VALID_DISPUTE_TYPES first, but defend in depth.
        throw new Error('ARBITRATION_BAD_APP_EVIDENCE:unknown-type')
    }
  }

  /**
   * 'poker/missing-share' evidence shape:
   *
   *   {
   *     tableKey:   <hex 64>,   // pubkey of the table autobase/log
   *     handId:     <string>,   // identifier within the table
   *     cardIndex:  <int>,      // position in the shuffled deck the share
   *                             //   was for (board card or hole)
   *     deadline:   <ms epoch>, // timestamp by which the share was due
   *     logProof:   <object>,   // signed-log slice showing the deadline tick
   *                             //   passed without the expected share entry
   *   }
   */
  _validateMissingShare (ae) {
    if (!isHexKey(ae.tableKey)) throw new Error('ARBITRATION_BAD_APP_EVIDENCE:tableKey')
    if (typeof ae.handId !== 'string' || ae.handId.length === 0 || ae.handId.length > 128) {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:handId')
    }
    if (!Number.isInteger(ae.cardIndex) || ae.cardIndex < 0 || ae.cardIndex >= 52) {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:cardIndex')
    }
    if (typeof ae.deadline !== 'number' || !Number.isFinite(ae.deadline)) {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:deadline')
    }
    if (!ae.logProof || typeof ae.logProof !== 'object') {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:logProof')
    }
  }

  /**
   * 'poker/invalid-share' evidence shape:
   *
   *   {
   *     tableKey:    <hex 64>,
   *     handId:      <string>,
   *     cardIndex:   <int>,
   *     ciphertext:  <hex>,   // the deck ciphertext at cardIndex
   *     share:       <hex>,   // the respondent's published share
   *     witness:     <object> // the falsifying witness (proof equation inputs)
   *   }
   */
  _validateInvalidShare (ae) {
    if (!isHexKey(ae.tableKey)) throw new Error('ARBITRATION_BAD_APP_EVIDENCE:tableKey')
    if (typeof ae.handId !== 'string' || ae.handId.length === 0 || ae.handId.length > 128) {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:handId')
    }
    if (!Number.isInteger(ae.cardIndex) || ae.cardIndex < 0 || ae.cardIndex >= 52) {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:cardIndex')
    }
    if (!isBoundedHex(ae.ciphertext, MAX_POKER_BLOB_BYTES)) {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:ciphertext')
    }
    if (!isBoundedHex(ae.share, MAX_POKER_BLOB_BYTES)) {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:share')
    }
    if (!ae.witness || typeof ae.witness !== 'object') {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:witness')
    }
  }

  /**
   * 'poker/refused-reveal' evidence shape:
   *
   *   {
   *     tableKey:        <hex 64>,
   *     handId:          <string>,
   *     showdownDeadline:<ms epoch>,
   *     potCommitProof:  <object>, // signed-log slice showing the respondent
   *                                // was still in the pot at showdown
   *     logProof:        <object>, // signed-log slice showing the deadline
   *                                // tick passed without a reveal entry
   *   }
   */
  _validateRefusedReveal (ae) {
    if (!isHexKey(ae.tableKey)) throw new Error('ARBITRATION_BAD_APP_EVIDENCE:tableKey')
    if (typeof ae.handId !== 'string' || ae.handId.length === 0 || ae.handId.length > 128) {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:handId')
    }
    if (typeof ae.showdownDeadline !== 'number' || !Number.isFinite(ae.showdownDeadline)) {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:showdownDeadline')
    }
    if (!ae.potCommitProof || typeof ae.potCommitProof !== 'object') {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:potCommitProof')
    }
    if (!ae.logProof || typeof ae.logProof !== 'object') {
      throw new Error('ARBITRATION_BAD_APP_EVIDENCE:logProof')
    }
  }

  // ─── App evidence: cryptographic verification (at evidence() time) ─────────
  //
  // These do the actual claim re-check. They are intentionally pluggable —
  // operators can swap in their own verifier via `setAppEvidenceVerifier`
  // (e.g. to wire in a project-specific shuffle proof library). The bundled
  // verifiers are conservative stubs: they only return a positive verdict
  // when they have enough information to be sure. Otherwise they return
  // 'inconclusive' and voters fall back to manual review.

  _verifyAppEvidence (type, ae) {
    const custom = this._appEvidenceVerifiers && this._appEvidenceVerifiers[type]
    if (typeof custom === 'function') {
      try {
        const r = custom(ae)
        return normalizeAppVerdict(r)
      } catch (err) {
        return { verdict: 'inconclusive', reason: 'verifier-threw:' + (err.message || 'unknown') }
      }
    }
    // Default: no verifier registered. We can still surface basic structural
    // confirmation so voters know shape validation passed at submit time.
    return { verdict: 'inconclusive', reason: 'no-verifier-registered' }
  }

  /**
   * Register a cryptographic verifier for an app dispute type. The verifier
   * is called with the typed evidence object and must return either:
   *   { verdict: 'claim-supported' | 'claim-refuted' | 'inconclusive', reason }
   * or a boolean (true → 'claim-supported', false → 'claim-refuted').
   *
   * Verifiers MUST be deterministic and side-effect-free — they may be
   * called by many voters independently and the answers must agree.
   *
   * @param {string} type - One of POKER_DISPUTE_TYPES (or future namespaces)
   * @param {(ae: object) => any} fn
   */
  setAppEvidenceVerifier (type, fn) {
    if (!POKER_DISPUTE_TYPES.includes(type)) {
      throw new Error('ARBITRATION_UNKNOWN_APP_TYPE:' + type)
    }
    if (typeof fn !== 'function') {
      throw new Error('ARBITRATION_BAD_VERIFIER')
    }
    if (!this._appEvidenceVerifiers) this._appEvidenceVerifiers = {}
    this._appEvidenceVerifiers[type] = fn
  }

  // --- Internal ---

  /**
   * Derive the VRF input `alpha` for a dispute's panel draw. Bound to immutable
   * dispute fields so the proof attests to THIS dispute and the binding is
   * auditable. Returns a 32-byte hex string.
   */
  _panelAlpha (dispute) {
    const h = crypto.createHash('sha256')
    for (const part of [
      PANEL_ALPHA_DOMAIN,
      dispute.id,
      dispute.type,
      String(dispute.claimant),
      String(dispute.respondent),
      String(dispute.createdAt)
    ]) {
      h.update(Buffer.from(String(part), 'utf8'))
      h.update(Buffer.from([0x00])) // length-independent separator
    }
    return h.digest('hex')
  }

  /**
   * Draw a verifiable arbitrator committee for a dispute via the VRF service.
   * Never throws: any failure (no VRF service, no reputation, pool too small)
   * returns an inactive panel with a reason and the dispute falls back to open
   * voting. On success returns the proof + candidate snapshot needed to replay
   * the draw independently.
   */
  async _formPanel (dispute) {
    const size = this.panelConfig.size
    const reputation = this.node?.reputation
    const registry = this.node?.serviceRegistry
    if (!registry) return { active: false, reason: 'no-service-registry' }
    if (!reputation || !(reputation.records instanceof Map)) {
      return { active: false, reason: 'no-reputation' }
    }

    // Build the eligible candidate pool, excluding the parties. Weight each by
    // score x reliability — both are positive for anyone past the eligibility
    // bar, so (unlike the full composite, which zeroes out on missing latency)
    // every eligible arbitrator keeps a meaningful, drawable weight.
    const candidates = []
    for (const [pubkey, record] of reputation.records) {
      if (pubkey === dispute.claimant || pubkey === dispute.respondent) continue
      if (!this._isEligibleArbitrator(pubkey, dispute)) continue
      const reliability = record.totalChallenges > 0
        ? record.passedChallenges / record.totalChallenges
        : 0
      candidates.push({ id: pubkey, weight: record.score * reliability })
    }

    if (candidates.length < size) {
      return { active: false, reason: 'insufficient-eligible-pool', poolSize: candidates.length, size }
    }

    // Integer weights for the pure-integer VRF sortition (so prover and any
    // verifier agree exactly). Unweighted panels collapse to a uniform draw.
    const drawCandidates = this.panelConfig.weighted
      ? quantizeWeights(candidates)
      : candidates.map(c => ({ id: c.id, weight: 1 }))

    const alpha = this._panelAlpha(dispute)
    let result
    try {
      result = await registry.handleRequest(this.panelConfig.vrfService, 'select', {
        alpha,
        candidates: drawCandidates,
        count: size,
        weighted: this.panelConfig.weighted
      }, { caller: 'local' })
    } catch (err) {
      return { active: false, reason: 'vrf-unavailable:' + (err?.message || 'unknown') }
    }

    if (!result || !Array.isArray(result.committee) || result.committee.length === 0) {
      return { active: false, reason: 'empty-committee' }
    }

    return {
      active: true,
      weighted: this.panelConfig.weighted,
      size,
      poolSize: candidates.length,
      vrfService: this.panelConfig.vrfService,
      vrfPubkey: result.pubkey,
      suite: result.suite,
      alpha: result.alpha,
      pi: result.pi,
      beta: result.beta,
      // Snapshot the exact pool + weights used, so the draw is replayable.
      candidates: drawCandidates,
      members: result.committee
    }
  }

  _isEligibleArbitrator (pubkey, dispute) {
    // Cannot be a party to the dispute
    if (pubkey === dispute.claimant || pubkey === dispute.respondent) {
      return false
    }

    if (!this.node?.reputation) return false

    const record = this.node.reputation.getRecord(pubkey)
    if (!record) return false

    if (record.score < MIN_ARBITRATOR_SCORE) return false
    if (record.totalChallenges < MIN_ARBITRATOR_CHALLENGES) return false

    const reliability = this.node.reputation.getReliability(pubkey)
    if (reliability < MIN_ARBITRATOR_RELIABILITY) return false

    return true
  }

  _resolve (dispute) {
    let claimantVotes = 0
    let respondentVotes = 0
    const voters = { claimant: [], respondent: [] }

    for (const [voter, verdict] of dispute.votes) {
      if (verdict === 'claimant') {
        claimantVotes++
        voters.claimant.push(voter)
      } else {
        respondentVotes++
        voters.respondent.push(voter)
      }
    }

    dispute.verdict = claimantVotes >= respondentVotes ? 'claimant' : 'respondent'
    dispute.status = 'resolved'
    dispute.resolvedAt = Date.now()

    // Slash respondent if claimant wins.
    //
    // Wrapped in try/catch because:
    //   1. For app-level disputes (poker/*) the respondent is a PLAYER
    //      pubkey, which the relay's paymentManager (focused on relay-to-
    //      relay incentives) likely doesn't know about — a strict
    //      paymentManager would throw on an unknown account.
    //   2. Even for relay-level disputes a misconfigured paymentManager
    //      shouldn't be able to block dispute resolution — the verdict has
    //      already been recorded above, and the arbitration/resolved
    //      pubsub event below must still fire so downstream subscribers
    //      (escrow contracts, dashboards, audit log) see the outcome.
    //
    // Slash failures are surfaced as 'slash-failed' so operators can
    // reconcile out-of-band; we explicitly do NOT roll back the verdict.
    if (dispute.verdict === 'claimant' && dispute.penalty > 0) {
      try {
        this.node?.paymentManager?.slash(
          dispute.respondent,
          dispute.penalty,
          `Arbitration ${dispute.id}: ${dispute.type}`
        )
      } catch (err) {
        dispute.slashError = err && err.message ? err.message : 'unknown'
        this.node?.router?.pubsub?.publish('arbitration/slash-failed', {
          disputeId: dispute.id,
          respondent: dispute.respondent,
          penalty: dispute.penalty,
          error: dispute.slashError
        })
      }
    }

    // Reputation adjustments for voters. Same fault-isolation argument as
    // the slash above — a misbehaving reputation provider mustn't block
    // verdict propagation.
    if (this.node?.reputation) {
      const winnerSide = voters[dispute.verdict]
      const loserSide = dispute.verdict === 'claimant' ? voters.respondent : voters.claimant
      try {
        for (const voter of winnerSide) this.node.reputation.recordChallenge(voter, true, 0)   // +10
        for (const voter of loserSide)  this.node.reputation.recordChallenge(voter, false, 0)  // -20
      } catch (err) {
        dispute.reputationError = err && err.message ? err.message : 'unknown'
      }
    }

    this.node?.router?.pubsub?.publish('arbitration/resolved', {
      disputeId: dispute.id,
      verdict: dispute.verdict,
      penalty: dispute.penalty,
      slashError: dispute.slashError || null,
      reputationError: dispute.reputationError || null
    })
  }

  _serialize (dispute) {
    return {
      ...dispute,
      votes: [...dispute.votes.entries()].map(([voter, verdict]) => ({ voter, verdict }))
    }
  }
}

// ─── Module-local helpers ────────────────────────────────────────────────────

function isHexKey (s) {
  return typeof s === 'string' && /^[0-9a-f]{64}$/i.test(s)
}

function isBoundedHex (s, maxBytes) {
  if (typeof s !== 'string') return false
  if (!/^[0-9a-f]+$/i.test(s)) return false
  // 2 hex chars per byte.
  return s.length > 0 && s.length <= maxBytes * 2
}

function normalizeAppVerdict (r) {
  if (r === true) return { verdict: 'claim-supported', reason: 'verifier-true' }
  if (r === false) return { verdict: 'claim-refuted', reason: 'verifier-false' }
  if (r && typeof r === 'object' && typeof r.verdict === 'string') {
    const ok = ['claim-supported', 'claim-refuted', 'inconclusive'].includes(r.verdict)
    if (!ok) return { verdict: 'inconclusive', reason: 'verifier-bad-verdict' }
    return { verdict: r.verdict, reason: r.reason || '' }
  }
  return { verdict: 'inconclusive', reason: 'verifier-bad-return' }
}

// Re-export the dispute type sets so consumers (poker app glue, tests, docs
// generators) can introspect without hard-coding the list. Keeps a single
// source of truth on what the arbitration service will accept.
export {
  RELAY_DISPUTE_TYPES,
  POKER_DISPUTE_TYPES,
  VALID_DISPUTE_TYPES,
  MAX_APP_EVIDENCE_BYTES,
  MAX_POKER_BLOB_BYTES
}
