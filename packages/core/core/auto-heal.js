/**
 * AutoHeal — diversity-enforced replica maintenance for archive-tier drives.
 *
 * Background scheduler that watches for archive-tier drives whose live
 * replica fleet has dropped below a diversity threshold and recruits this
 * relay as a fresh replica when doing so would meaningfully restore
 * diversity. Operates on cross-relay capability data already gathered by
 * the federation layer — it doesn't introduce new wire traffic; it just
 * computes a different decision over the existing data.
 *
 * Defaults target durable archival (≥7 replicas across ≥4 regions and ≥5
 * distinct operators). All thresholds are configurable via constructor
 * opts so operators can tune for their network density.
 *
 * State model:
 *
 *   For each archive drive seen via the cross-relay catalog:
 *     - Map<appKey, ReplicaSet>
 *     - ReplicaSet = { relayPubkey → { region, anchored, lastSeen } }
 *     - lastSeen pruned after `staleMs` (default 24h)
 *
 *   On each tick:
 *     1. Refresh ReplicaSets from the local app-registry catalog AND from
 *        peer-fetched catalogs cached on `node.federation`.
 *     2. For each archive drive: compute current (replicas, regions, operators).
 *     3. If below any threshold, decide whether THIS relay should recruit
 *        itself (would it improve diversity? do we have capacity? does
 *        accept-mode allow it?).
 *     4. If yes → call node.seedApp() with the same durability tier.
 *
 * What this is NOT:
 *   - Not a global coordinator. Every relay runs the same logic
 *     independently. Convergence comes from the diversity scoring: a relay
 *     in an over-represented region won't recruit itself, while one in an
 *     under-represented region will. Eventually the threshold is met.
 *   - Not a guarantee. Relies on at least one peer having the data
 *     reachable; can't rebuild a drive nobody has.
 *   - Not a replication protocol. Replication itself runs through the
 *     existing Hyperdrive + Hyperswarm path. AutoHeal just decides when to
 *     ask the local relay's seedApp() to start that replication.
 */

import EventEmitter from 'events'
import { fetchAndVerifyAnchorProof } from './anchor-proof-verifier.js'

// Default thresholds — tuned for an archival use case where availability
// matters more than over-replication. Operators can override via opts.
//
// Note: minReplicas is the SLO floor (anything below = degraded). targetReplicas
// is what AutoHeal recruits up to, leaving headroom for churn / transient
// outages. Without that buffer, any single offline replica drops the network
// below SLO. See scripts/simulate-auto-heal-bridge.js scenarioChurn for the
// reactive-recruitment discovery this targets.
export const DEFAULT_THRESHOLDS = {
  minReplicas: 7,
  minRegions: 4,
  minOperators: 5,
  // Recruit to minReplicas + replicaBuffer to absorb transient offline dips.
  // Defaults to +2 over min, matching the SLO of "≤2 simultaneous failures
  // tolerated". Operators can set replicaBuffer: 0 to disable the buffer.
  replicaBuffer: 2
}

const DEFAULT_TICK_MS = 30 * 60 * 1000 // 30 min — slow loop; archival isn't latency-sensitive
const DEFAULT_STALE_MS = 24 * 60 * 60 * 1000 // 24h — peer info stale after this
const ARCHIVE_TIER = 1

export class AutoHeal extends EventEmitter {
  constructor (node, opts = {}) {
    super()
    this.node = node
    this.tickMs = opts.tickMs || DEFAULT_TICK_MS
    this.staleMs = opts.staleMs || DEFAULT_STALE_MS
    this.thresholds = { ...DEFAULT_THRESHOLDS, ...(opts.thresholds || {}) }
    // Don't ever try to recruit ourselves into more than this many archive
    // drives in a single tick — back-pressure against a thundering herd
    // of new archive content all becoming our responsibility at once.
    this.maxRecruitsPerTick = opts.maxRecruitsPerTick || 3
    // Soft storage cap — refuse to recruit past this fraction of
    // maxStorageBytes. Default 90% leaves headroom for the seed-request
    // path + manifest growth between ticks.
    this.storageMargin = opts.storageMargin ?? 0.90
    // Cryptographic proof bridge — when true, AutoHeal counts a peer as
    // a live replica only when it produces a recently-verified signed
    // anchor proof from `/api/anchors/<appKey>/proof`. Without proofs,
    // diversity scoring trusts the peer's self-reported `anchored: true`.
    //
    // Default ON for archive-tier drives because the whole point of the
    // tier is durable, verifiable preservation. Operators can disable
    // for staging/testnet via `verifyProofs: false`.
    this.verifyProofs = opts.verifyProofs !== false
    // How fresh a proof must be to count. Default 1h — long enough that
    // the per-archive proof-emit timer (every 30 min) has time to refresh,
    // short enough that a relay that silently dropped a drive is detected
    // within an hour.
    this.proofFreshnessMs = opts.proofFreshnessMs || 60 * 60 * 1000
    // After AutoHeal recruits a new replica, give it this much grace
    // before we expect a fresh proof — replication takes time, and
    // demanding instant anchored-proof would prevent recruitment from
    // ever counting toward diversity.
    this.proofGraceMs = opts.proofGraceMs || 60 * 60 * 1000
    // Inject a fetcher for tests; in production we use the real fetch.
    this._fetchProof = opts.fetchProof || fetchAndVerifyAnchorProof
    // Optional Protomux anchor channel — when present, the fetcher prefers
    // it over HTTPS so we work on pure-swarm and NAT'd fleets. The channel
    // routes by peer pubkey; HTTPS is the fallback for peers without an
    // open channel.
    this._anchorChannel = opts.anchorChannel || null
    // Per-tick proof-fetch budget. Beyond ~1K relays × 1K drives, fetching
    // every anchored peer's proof every tick is too expensive (O(K·N) per
    // relay per cycle). When we have more pending fetches than this, we
    // sample the most-stale entries first; remaining peers get verified
    // on subsequent ticks. With proofFreshnessMs/2 cache window this still
    // ensures every peer's proof is refreshed within the freshness window
    // — just not all in one tick.
    this.maxProofsPerTick = opts.maxProofsPerTick || 64
    // Cache of verified proofs: `${appKey}:${peerPubkey}` → { proof, fetchedAt }
    // Prevents fetching the same proof every tick. Entries auto-expire
    // when they exceed proofFreshnessMs.
    this._proofCache = new Map()
    // ReplicaSets observed across the network: appKey → { relayPubkey → meta }
    this._fleet = new Map()
    // Per-drive recruit-failure backoff. appKey → { failures, retryAt }.
    // Prevents tick-by-tick retry storms on permanently un-replicable drives.
    this._backoff = new Map()
    // Test seam — set to a deterministic [0,1) value to make jitter
    // decisions reproducible. In production it's Math.random.
    this._random = opts.random || (() => Math.random())
    this._timer = null
    this._running = false
  }

  start () {
    if (this._running) return
    this._running = true
    this._timer = setInterval(() => this._tick().catch((err) => {
      this.emit('tick-error', { error: err.message })
    }), this.tickMs)
    if (this._timer.unref) this._timer.unref()
    // Run once shortly after start so newly-booted relays don't have to
    // wait a full tick before discovering archive drives that need help.
    setTimeout(() => this._tick().catch(() => {}), 5000).unref?.()
    this.emit('started')
  }

  async stop () {
    if (!this._running) return
    this._running = false
    if (this._timer) {
      clearInterval(this._timer)
      this._timer = null
    }
    this.emit('stopped')
  }

  /**
   * Public snapshot for /api/health-detail and similar admin endpoints.
   * Returns the current view of archive-tier drives this relay is tracking
   * + whether each meets the diversity threshold.
   */
  snapshot () {
    const drives = []
    for (const [appKey, replicas] of this._fleet) {
      const live = this._liveReplicas(replicas, appKey)
      const back = this._backoff.get(appKey) || null
      drives.push({
        appKey,
        replicas: live.replicas,
        regions: live.regions,
        operators: live.operators,
        meetsThreshold: this._meetsThreshold(live),
        haveLocally: this.node.appRegistry?.has?.(appKey) === true,
        backoff: back
          ? { failures: back.failures, retryInMs: Math.max(0, back.retryAt - Date.now()) }
          : null
      })
    }
    return {
      enabled: true,
      running: this._running,
      tickMs: this.tickMs,
      thresholds: this.thresholds,
      maxRecruitsPerTick: this.maxRecruitsPerTick,
      storageMargin: this.storageMargin,
      verifyProofs: this.verifyProofs,
      proofFreshnessMs: this.proofFreshnessMs,
      maxProofsPerTick: this.maxProofsPerTick,
      tracked: drives.length,
      below: drives.filter(d => !d.meetsThreshold).length,
      backoffs: this._backoff.size,
      proofCacheSize: this._proofCache.size,
      drives
    }
  }

  // ─── Internal: tick ────────────────────────────────────────────────

  async _tick () {
    if (!this._running) return
    if (!this.node.appRegistry) return

    // 1. Refresh from local catalog + peer catalogs.
    this._refreshFromLocal()
    this._refreshFromFederation()
    this._pruneStale()

    // 1b. Verify peer-claimed anchored bits via signed anchor proofs. This
    // upgrades the trust model from "peer says they have it" to "peer
    // cryptographically demonstrates they have it." Stale-cache aware: we
    // only fetch a proof if we don't have one in the cache or the cached
    // one is older than freshnessMs.
    if (this.verifyProofs) await this._refreshAnchorProofs()

    // 2. For each archive drive, decide whether to recruit.
    let recruits = 0
    for (const [appKey, replicas] of this._fleet) {
      if (recruits >= this.maxRecruitsPerTick) break

      const live = this._liveReplicas(replicas, appKey)
      if (this._meetsThreshold(live)) continue

      // Already seeding it locally? Nothing to do.
      if (this.node.appRegistry.has(appKey)) continue

      // Would adding US to this fleet meaningfully improve diversity?
      //
      // Three cases qualify (see the wouldAddDiversity expression below):
      //   A. We close a region gap — fleet doesn't already have our region.
      //   B. We close an operator gap — fleet doesn't already have our
      //      operator. Operator-diversity protects against correlated
      //      infrastructure failures (e.g., one cloud region going down).
      //   C. Both diversity dimensions are met but replicas < target — we
      //      fill a buffer slot, requiring meetsOperatorThreshold AND that
      //      our operator isn't already at the per-operator fairshare cap
      //      (sybil-cluster resistance).
      //
      // Cases that DO NOT qualify:
      //   - We share both region AND operator with the existing fleet, AND
      //     the buffer-pad clause (C) doesn't apply — recruiting wouldn't
      //     add a fault domain or fill the buffer. Stand down.
      //   - Our operator is already at the fairshare cap. Even if we're a
      //     valid relay, recruiting more from one operator dilutes diversity.
      const ourRegion = this._localRegion()
      const ourOperator = this._localOperator()
      const ourPubkey = this._localPubkey()
      const addsRegion = !live.regions.includes(ourRegion)
      const addsOperator = !live.operators.includes(ourOperator)
      const meetsRegionThreshold = live.regions.length >= this.thresholds.minRegions
      const meetsOperatorThreshold = live.operators.length >= this.thresholds.minOperators
      const belowReplicas = live.replicas < this._targetReplicas()
      // Per-operator cap. Even when both diversity thresholds are met, a
      // single operator with many relays could still pad the replica count
      // (sybil cluster). Cap any operator at ceil(target / minOperators)
      // replicas — that's the fairshare ceiling beyond which a single
      // operator dominates. Default ON; set maxPerOperator: 0 to disable.
      const ourOperatorCount = live.raw.filter(r => r.operator === ourOperator).length
      const fairshareCap = Math.ceil(this._targetReplicas() / this.thresholds.minOperators)
      const maxPerOperator = this.thresholds.maxPerOperator ?? fairshareCap
      const operatorAtCap = maxPerOperator > 0 && ourOperatorCount >= maxPerOperator

      // Three valid recruit paths:
      //   A. We close a region gap (addsRegion). Highest-value.
      //   B. We close an operator gap (addsOperator). Equally high-value —
      //      operator-diversity protects against correlated infrastructure
      //      failures (a whole AWS region going down).
      //   C. Both diversity dimensions are at threshold but replica count is
      //      below target — fill buffer with a redundant peer. Requires
      //      meetsOperatorThreshold AND that our operator isn't already at
      //      the per-operator cap (sybil-resistance).
      const wouldAddDiversity = (
        !replicas.has(ourPubkey) &&
        !operatorAtCap &&
        (addsRegion || addsOperator ||
          (belowReplicas && meetsRegionThreshold && meetsOperatorThreshold))
      )
      if (!wouldAddDiversity) {
        if (operatorAtCap) {
          this.emit('recruit-skipped', { appKey, reason: 'operator-fairshare-cap', operator: ourOperator })
        }
        continue
      }

      // Capacity / policy gates — same checks the seed-request handler
      // would apply. We refuse to recruit if we'd violate accept-mode
      // (operator may have explicitly closed the relay, set allowlist, etc.).
      if (!this._canAccept(appKey)) continue

      // Storage gate — refuse to recruit when we're already at the operator's
      // storage cap. seedApp() would error or evict; better to decline up
      // front and let a relay with capacity take it. We use a soft margin
      // (default 90%) so we don't keep recruiting until literally full.
      const storage = this._storageCapacity()
      if (!storage.ok) {
        this.emit('recruit-skipped', {
          appKey,
          reason: storage.reason,
          usedBytes: storage.usedBytes,
          maxStorageBytes: storage.maxStorageBytes,
          storageMargin: storage.storageMargin
        })
        continue
      }

      // Backoff gate — if recruiting this drive failed recently, wait before
      // retrying. Prevents tick-by-tick retry storms when a drive is
      // permanently un-replicable (e.g., publisher gone, we can't connect
      // to any peer that has it).
      if (this._isInBackoff(appKey)) continue

      // Convergence jitter — at scale, many archive-aware relays will see
      // the same shortfall in the same tick and all decide to recruit. The
      // result is that a drive needing 1 new replica gets 50, blowing
      // through the diversity target. Mitigation: each relay independently
      // recruits with probability proportional to "how much help is needed
      // vs. how many relays could help." Roughly: with N relays observing
      // the same gap and a gap of K replicas, each relay recruits with
      // probability ≈ K/N.
      //
      // We don't know N (the network's total auto-heal-enabled fleet), so
      // we approximate from the visible fleet size. This isn't perfectly
      // tight but converges fast: relays that lose the dice roll see the
      // recruitment in the next tick's catalog and stand down.
      if (!this._jitterAccept(live)) {
        this.emit('recruit-skipped', { appKey, reason: 'jitter-defer' })
        continue
      }

      // Recruit.
      try {
        await this.node.seedApp(appKey, {
          durability: ARCHIVE_TIER,
          revocable: false, // archive drives are non-revocable by definition
          source: 'auto-heal'
        })
        recruits++
        this._clearBackoff(appKey) // success — clear any prior backoff
        let recruitReason
        if (live.regions.length < this.thresholds.minRegions) recruitReason = 'region-gap'
        else if (live.operators.length < this.thresholds.minOperators) recruitReason = 'operator-gap'
        else recruitReason = 'replica-gap'
        this.emit('recruited', { appKey, before: live, reason: recruitReason })
      } catch (err) {
        this._recordFailure(appKey)
        this.emit('recruit-error', { appKey, error: err.message })
      }
    }
  }

  // ─── Internal: capacity, backoff, jitter ───────────────────────────

  _hasStorageCapacity () {
    return this._storageCapacity().ok
  }

  _storageCapacity () {
    const seeder = this.node.seeder
    const cap = this.node.config?.maxStorageBytes
    if (!seeder || !Number.isFinite(cap) || cap <= 0) {
      return {
        ok: false,
        reason: 'storage-capacity-unavailable',
        usedBytes: null,
        maxStorageBytes: Number.isFinite(cap) ? cap : null,
        storageMargin: null
      }
    }
    const rawUsed = seeder.totalBytesStored
    const used = Number.isFinite(rawUsed) && rawUsed > 0 ? rawUsed : 0
    const rawMargin = this.storageMargin
    const margin = Number.isFinite(rawMargin) && rawMargin > 0 ? Math.min(rawMargin, 1) : 0.90
    if (used >= cap * margin) {
      return {
        ok: false,
        reason: 'storage-full',
        usedBytes: used,
        maxStorageBytes: cap,
        storageMargin: margin
      }
    }
    return {
      ok: true,
      reason: null,
      usedBytes: used,
      maxStorageBytes: cap,
      storageMargin: margin
    }
  }

  _isInBackoff (appKey) {
    const entry = this._backoff.get(appKey)
    if (!entry) return false
    if (Date.now() >= entry.retryAt) {
      this._backoff.delete(appKey)
      return false
    }
    return true
  }

  _recordFailure (appKey) {
    const prior = this._backoff.get(appKey)
    const failures = (prior?.failures || 0) + 1
    // Exponential backoff with cap: 5min, 15min, 1h, 4h, 24h, 24h (max).
    const delays = [5 * 60_000, 15 * 60_000, 60 * 60_000, 4 * 60 * 60_000, 24 * 60 * 60_000]
    const delay = delays[Math.min(failures - 1, delays.length - 1)]
    this._backoff.set(appKey, {
      failures,
      retryAt: Date.now() + delay
    })
  }

  _clearBackoff (appKey) {
    this._backoff.delete(appKey)
  }

  _jitterAccept (live) {
    // Estimate how many relays could fix this gap and how big the gap is.
    // visiblePeers ≈ relays we know about that aren't already replicas.
    // We need (replicas + regions + operators) all to hit threshold; use the
    // worst single-dimension shortfall as gap.
    const replicaGap = Math.max(0, this._targetReplicas() - live.replicas)
    const regionGap = Math.max(0, this.thresholds.minRegions - live.regions.length)
    const operatorGap = Math.max(0, this.thresholds.minOperators - live.operators.length)
    const gap = Math.max(replicaGap, regionGap, operatorGap)
    if (gap <= 0) return true // shouldn't happen; meetsThreshold gates above

    // Estimate fleet of helpers from federation snapshot. Default to a
    // conservative N=20 if we have less data than that.
    const peerCount = this._fleetSize() || 20
    const helpers = Math.max(peerCount, 3)
    const probability = Math.min(1, (gap * 2) / helpers) // 2× for safety margin
    return this._random() < probability
  }

  _fleetSize () {
    if (!this.node.federation || typeof this.node.federation.snapshot !== 'function') return 0
    const snap = this.node.federation.snapshot()
    return Array.isArray(snap?.peerCatalogs) ? snap.peerCatalogs.length : 0
  }

  // ─── Internal: data refresh ────────────────────────────────────────

  _refreshFromLocal () {
    const now = Date.now()
    const ourPubkey = this._localPubkey()
    const ourRegion = this._localRegion()
    const ourOperator = this._localOperator()
    if (!this.node.appRegistry.catalog) return

    for (const entry of this.node.appRegistry.catalog()) {
      if ((entry.durability || 0) !== ARCHIVE_TIER) continue
      const set = this._setFor(entry.appKey)
      set.set(ourPubkey, {
        region: ourRegion,
        operator: ourOperator,
        anchored: entry.anchored === true,
        lastSeen: now
      })
    }
  }

  _refreshFromFederation () {
    if (!this.node.federation || typeof this.node.federation.snapshot !== 'function') return
    const now = Date.now()
    const snap = this.node.federation.snapshot()
    if (!Array.isArray(snap?.peerCatalogs)) return

    for (const peer of snap.peerCatalogs) {
      const peerPubkey = peer.pubkey
      const peerRegion = peer.region || 'unknown'
      // Operator identity: prefer the peer's self-declared operator ID
      // (set in their capability doc / catalog response). When absent, fall
      // back to the relay pubkey — which means each relay counts as its own
      // operator. That's safe for honest networks but allows sybil clusters
      // to inflate operator-diversity. Production deployments should expose
      // a stable operator field so diversity scoring reflects real fault
      // domains, not raw key counts.
      const peerOperator = peer.operator || peerPubkey
      if (!peerPubkey || !Array.isArray(peer.apps)) continue

      for (const app of peer.apps) {
        if ((app.durability || 0) !== ARCHIVE_TIER) continue
        const appKey = app.appKey || app.driveKey || app.key
        if (!appKey) continue

        const set = this._setFor(appKey)
        set.set(peerPubkey, {
          region: peerRegion,
          operator: peerOperator,
          anchored: app.anchored === true,
          lastSeen: now
        })
      }
    }
  }

  _pruneStale () {
    const cutoff = Date.now() - this.staleMs
    for (const [appKey, replicas] of this._fleet) {
      for (const [pubkey, meta] of replicas) {
        if (meta.lastSeen < cutoff) replicas.delete(pubkey)
      }
      if (replicas.size === 0) this._fleet.delete(appKey)
    }
  }

  _setFor (appKey) {
    let s = this._fleet.get(appKey)
    if (!s) {
      s = new Map()
      this._fleet.set(appKey, s)
    }
    return s
  }

  // ─── Internal: scoring / policy ────────────────────────────────────

  _liveReplicas (replicas, appKey) {
    // Count only ANCHORED replicas — a relay that accepted the seed but
    // hasn't actually replicated bytes is not a real availability vote.
    //
    // When verifyProofs is on, "anchored" requires a recently-verified
    // signed anchor proof in addition to the peer's self-report. This
    // raises the bar from "they say they have it" to "we cryptographically
    // confirmed they had it within the freshness window."
    //
    // Local relay (us) is always trusted because we trust our own registry.
    const ourPubkey = this._localPubkey()
    const anchored = []
    for (const [pubkey, meta] of replicas) {
      if (!meta.anchored) continue
      if (this.verifyProofs && pubkey !== ourPubkey && appKey) {
        if (!this._hasFreshProof(appKey, pubkey)) continue
      }
      // Operator: meta.operator if peer declared one; else pubkey (each relay
      // counts as its own operator — backward-compat for catalogs without
      // operator IDs).
      anchored.push({ pubkey, region: meta.region, operator: meta.operator || pubkey })
    }
    const regions = [...new Set(anchored.map(r => r.region).filter(Boolean))]
    const operators = [...new Set(anchored.map(r => r.operator).filter(Boolean))]
    return {
      replicas: anchored.length,
      regions,
      operators,
      raw: anchored
    }
  }

  _hasFreshProof (appKey, peerPubkey) {
    const cached = this._proofCache.get(`${appKey}:${peerPubkey}`)
    if (!cached) return false
    const age = Date.now() - cached.fetchedAt
    if (age > this.proofFreshnessMs) return false
    if (cached.result.ok !== true) return false
    return cached.result.proof.anchored === true
  }

  async _refreshAnchorProofs () {
    if (!this.node.federation || typeof this.node.federation.snapshot !== 'function') return
    const snap = this.node.federation.snapshot()
    if (!Array.isArray(snap?.peerCatalogs)) return

    // Build a peer pubkey → URL map so we know where to fetch from
    const peerToUrl = new Map()
    for (const peer of snap.peerCatalogs) {
      if (peer.pubkey && peer.url) peerToUrl.set(peer.pubkey, peer.url)
    }

    const ourPubkey = this._localPubkey()
    // Phase 1: collect candidates with their staleness so we can prioritize.
    // A candidate is a (appKey, peerPubkey) pair we haven't recently verified.
    const candidates = []
    for (const [appKey, replicas] of this._fleet) {
      for (const [peerPubkey, meta] of replicas) {
        if (!meta.anchored) continue
        if (peerPubkey === ourPubkey) continue
        const url = peerToUrl.get(peerPubkey)
        if (!url) continue
        const cacheKey = `${appKey}:${peerPubkey}`
        const cached = this._proofCache.get(cacheKey)
        // Skip if recently fetched (cache covers freshnessMs/2 to ensure
        // we always have a valid cache entry between ticks)
        if (cached && (Date.now() - cached.fetchedAt) < this.proofFreshnessMs / 2) continue
        const staleness = cached ? Date.now() - cached.fetchedAt : Infinity
        candidates.push({ appKey, peerPubkey, url, staleness, cacheKey })
      }
    }

    // Phase 2: sort by staleness desc (oldest first → highest priority) and
    // cap at the per-tick budget. Prevents O(K·N) blow-up on large fleets;
    // remaining entries are picked up by subsequent ticks before they expire
    // (cache window is freshnessMs/2 wide).
    candidates.sort((a, b) => b.staleness - a.staleness)
    const selected = candidates.slice(0, this.maxProofsPerTick)
    if (candidates.length > selected.length) {
      this.emit('proof-budget-throttled', {
        candidates: candidates.length,
        budget: this.maxProofsPerTick,
        deferred: candidates.length - selected.length
      })
    }

    const tasks = selected.map(c => this._fetchProof(c.url, c.appKey, {
      expectedPubkey: c.peerPubkey,
      freshnessMs: this.proofFreshnessMs * 2, // give some slack on remote clock
      anchorChannel: this._anchorChannel,
      peerPubkey: c.peerPubkey
    }).then(result => {
      this._proofCache.set(c.cacheKey, { result, fetchedAt: Date.now() })
      if (!result.ok) {
        this.emit('proof-failed', { appKey: c.appKey, peerPubkey: c.peerPubkey, reason: result.reason })
      }
    }).catch(() => {
      this._proofCache.set(c.cacheKey, {
        result: { ok: false, reason: 'fetch-error' },
        fetchedAt: Date.now()
      })
    }))

    // Cap concurrent fetches at 16 — even within a tick, we don't want to
    // open hundreds of sockets at once.
    const BATCH = 16
    for (let i = 0; i < tasks.length; i += BATCH) {
      await Promise.all(tasks.slice(i, i + BATCH))
    }

    // Prune stale cache entries
    const cutoff = Date.now() - this.proofFreshnessMs
    for (const [key, entry] of this._proofCache) {
      if (entry.fetchedAt < cutoff) this._proofCache.delete(key)
    }
  }

  // Target = min + buffer. We keep recruiting until we hit target so that
  // transient churn (one host briefly offline) doesn't drop us below min.
  _targetReplicas () {
    return this.thresholds.minReplicas + (this.thresholds.replicaBuffer ?? 0)
  }

  _meetsThreshold (live) {
    return (
      live.replicas >= this._targetReplicas() &&
      live.regions.length >= this.thresholds.minRegions &&
      live.operators.length >= this.thresholds.minOperators
    )
  }

  _localPubkey () {
    if (this.node.swarm?.keyPair?.publicKey) {
      const pk = this.node.swarm.keyPair.publicKey
      return typeof pk === 'string' ? pk : pk.toString('hex')
    }
    return 'self'
  }

  _localRegion () {
    return (this.node.config?.regions?.[0]) || 'unknown'
  }

  _localOperator () {
    // Operators can declare their identity in node.config.operator (string).
    // Most natural value: the org / deployment owner identifier (e.g.,
    // "acme-corp"). Without it, fall back to pubkey so we have *something*.
    return this.node.config?.operator || this._localPubkey()
  }

  _canAccept (appKey) {
    if (typeof this.node._resolveAcceptMode !== 'function') return true
    if (typeof this.node._decideAcceptance !== 'function') return true
    const mode = this.node._resolveAcceptMode()
    const decision = this.node._decideAcceptance({
      appKey,
      source: 'auto-heal',
      durability: ARCHIVE_TIER
    }, mode)
    return decision === 'accept'
  }
}
