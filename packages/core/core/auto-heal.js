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
import { positiveStorageBound } from '../config/storage-cap.js'
import { CompletionScheduler, strictPositiveInteger } from './completion-scheduler.js'
import { GenerationPopulation } from './generation-population.js'

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
const MAX_PASS_BUDGET = 64
const MAX_PUBLIC_DRIVE_DETAILS = 32
const MAX_THRESHOLD = 262_144

function strictNonNegativeInteger (value, label, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 0 || value > max) {
    throw new RangeError(`${label} must be a safe integer in [0,${max}]`)
  }
  return value
}

export class AutoHeal extends EventEmitter {
  constructor (node, opts = {}) {
    super()
    this.node = node
    this.tickMs = strictPositiveInteger(opts.tickMs ?? DEFAULT_TICK_MS, 'autoHeal tickMs')
    this.staleMs = strictPositiveInteger(opts.staleMs ?? DEFAULT_STALE_MS, 'autoHeal staleMs')
    const thresholds = { ...DEFAULT_THRESHOLDS, ...(opts.thresholds || {}) }
    this.thresholds = Object.freeze({
      ...thresholds,
      minReplicas: strictPositiveInteger(thresholds.minReplicas, 'autoHeal minReplicas', MAX_THRESHOLD),
      minRegions: strictPositiveInteger(thresholds.minRegions, 'autoHeal minRegions', MAX_THRESHOLD),
      minOperators: strictPositiveInteger(thresholds.minOperators, 'autoHeal minOperators', MAX_THRESHOLD),
      replicaBuffer: strictNonNegativeInteger(thresholds.replicaBuffer ?? 0, 'autoHeal replicaBuffer', MAX_THRESHOLD),
      ...(thresholds.maxPerOperator === undefined
        ? {}
        : { maxPerOperator: strictNonNegativeInteger(thresholds.maxPerOperator, 'autoHeal maxPerOperator', MAX_THRESHOLD) })
    })
    if (this.thresholds.minReplicas + this.thresholds.replicaBuffer > MAX_THRESHOLD) {
      throw new RangeError(`autoHeal targetReplicas must be a safe integer in [1,${MAX_THRESHOLD}]`)
    }
    // Don't ever try to recruit ourselves into more than this many archive
    // drives in a single tick — back-pressure against a thundering herd
    // of new archive content all becoming our responsibility at once.
    this.maxRecruitsPerTick = strictPositiveInteger(
      opts.maxRecruitsPerTick ?? 3,
      'autoHeal maxRecruitsPerTick',
      MAX_PASS_BUDGET
    )
    // admission() refreshes filesystem identity and measures the exact storage
    // tree synchronously. Bound those expensive evaluations independently of
    // successful recruits so a huge peer catalog cannot turn one tick into an
    // unbounded sequence of event-loop-blocking disk walks.
    this.maxCapacityChecksPerTick = strictPositiveInteger(
      opts.maxCapacityChecksPerTick ?? this.maxRecruitsPerTick,
      'autoHeal maxCapacityChecksPerTick',
      MAX_PASS_BUDGET
    )
    this.localRefreshBudget = strictPositiveInteger(
      opts.localRefreshBudget ?? MAX_PASS_BUDGET,
      'autoHeal localRefreshBudget',
      MAX_PASS_BUDGET
    )
    this.federationRefreshBudget = strictPositiveInteger(
      opts.federationRefreshBudget ?? MAX_PASS_BUDGET,
      'autoHeal federationRefreshBudget',
      MAX_PASS_BUDGET
    )
    this.decisionBudget = strictPositiveInteger(
      opts.decisionBudget ?? MAX_PASS_BUDGET,
      'autoHeal decisionBudget',
      MAX_PASS_BUDGET
    )
    this.proofScanBudget = strictPositiveInteger(
      opts.proofScanBudget ?? MAX_PASS_BUDGET,
      'autoHeal proofScanBudget',
      MAX_PASS_BUDGET
    )
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
    this.proofFreshnessMs = strictPositiveInteger(
      opts.proofFreshnessMs ?? 60 * 60 * 1000,
      'autoHeal proofFreshnessMs',
      Math.floor(Number.MAX_SAFE_INTEGER / 2)
    )
    // After AutoHeal recruits a new replica, give it this much grace
    // before we expect a fresh proof — replication takes time, and
    // demanding instant anchored-proof would prevent recruitment from
    // ever counting toward diversity.
    this.proofGraceMs = strictPositiveInteger(
      opts.proofGraceMs ?? 60 * 60 * 1000,
      'autoHeal proofGraceMs'
    )
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
    this.maxProofsPerTick = strictPositiveInteger(
      opts.maxProofsPerTick ?? MAX_PASS_BUDGET,
      'autoHeal maxProofsPerTick',
      MAX_PASS_BUDGET
    )
    // Cache of verified proofs: `${appKey}:${peerPubkey}` → { proof, fetchedAt }
    // Prevents fetching the same proof every tick. Entries auto-expire
    // when they exceed proofFreshnessMs.
    this._proofCache = new Map()
    this._proofCachePopulation = new GenerationPopulation({
      name: 'auto-heal-proof-cache',
      allowedConsumers: ['auto-heal-proof-cache']
    })
    // ReplicaSets observed across the network: appKey → { relayPubkey → meta }
    this._fleet = new Map()
    this._fleetPopulation = new GenerationPopulation({
      name: 'auto-heal-fleet',
      allowedConsumers: ['auto-heal-proof', 'auto-heal-decision']
    })
    this._replicaPopulations = new Map()
    // Per-drive recruit-failure backoff. appKey → { failures, retryAt }.
    // Prevents tick-by-tick retry storms on permanently un-replicable drives.
    this._backoff = new Map()
    // Test seam — set to a deterministic [0,1) value to make jitter
    // decisions reproducible. In production it's Math.random.
    this._random = opts.random || (() => Math.random())
    this._initialTimer = null
    this._scheduler = null
    this._running = false
    this._phase = 'local-refresh'
    this._federationState = null
    this._proofActive = null
    this._decisionActive = null
    this._decisionCycleRecruits = 0
    this._decisionCycleCapacityChecks = 0
    this._snapshotBuild = { below: 0, drives: [] }
    this._snapshotComplete = Object.freeze({ tracked: 0, below: 0, drives: Object.freeze([]), completedAt: null })
  }

  start () {
    if (this._running) return
    this._running = true
    this._scheduler = new CompletionScheduler({
      name: 'auto-heal',
      intervalMs: this.tickMs,
      run: async () => {
        try {
          return await this._tick()
        } catch (err) {
          this.emit('tick-error', { error: err.message })
          throw err
        }
      }
    })
    this._scheduler.start({ immediate: false })
    // Run once shortly after start so newly-booted relays don't have to
    // wait a full tick before discovering archive drives that need help.
    this._initialTimer = setTimeout(() => {
      this._initialTimer = null
      if (this._running) this._scheduler?.trigger('initial')
    }, 5000)
    if (this._initialTimer.unref) this._initialTimer.unref()
    this.emit('started')
  }

  async stop () {
    if (!this._running && !this._scheduler) return
    this._running = false
    if (this._initialTimer) clearTimeout(this._initialTimer)
    this._initialTimer = null
    const scheduler = this._scheduler
    this._scheduler = null
    if (scheduler) await scheduler.stop()
    this._releaseCursors()
    this.emit('stopped')
  }

  _releaseCursors () {
    this.node.appRegistry?.releasePopulationConsumer?.('auto-heal')
    this.node.federation?.releaseAutoHealCursor?.()
    this._fleetPopulation.unregister('auto-heal-proof')
    this._fleetPopulation.unregister('auto-heal-decision')
    this._proofCachePopulation.unregister('auto-heal-proof-cache')
    for (const population of this._replicaPopulations.values()) {
      population.unregister('auto-heal-proof')
      population.unregister('auto-heal-decision')
    }
    this._phase = 'local-refresh'
    this._federationState = null
    this._proofActive = null
    this._decisionActive = null
    this._decisionCycleRecruits = 0
    this._decisionCycleCapacityChecks = 0
    this._snapshotBuild = { below: 0, drives: [] }
  }

  /**
   * Public snapshot for /api/health-detail and similar admin endpoints.
   * Returns the current view of archive-tier drives this relay is tracking
   * + whether each meets the diversity threshold.
   */
  snapshot () {
    return {
      enabled: true,
      running: this._running,
      tickMs: this.tickMs,
      thresholds: this.thresholds,
      maxRecruitsPerTick: this.maxRecruitsPerTick,
      maxCapacityChecksPerTick: this.maxCapacityChecksPerTick,
      storageMargin: this.storageMargin,
      verifyProofs: this.verifyProofs,
      proofFreshnessMs: this.proofFreshnessMs,
      maxProofsPerTick: this.maxProofsPerTick,
      localRefreshBudget: this.localRefreshBudget,
      federationRefreshBudget: this.federationRefreshBudget,
      decisionBudget: this.decisionBudget,
      proofScanBudget: this.proofScanBudget,
      tracked: this._snapshotComplete.tracked,
      below: this._snapshotComplete.below,
      backoffs: this._backoff.size,
      proofCacheSize: this._proofCache.size,
      completedAt: this._snapshotComplete.completedAt,
      drives: this._snapshotComplete.drives,
      scheduler: this._scheduler ? this._scheduler.snapshot() : null
    }
  }

  // ─── Internal: tick ────────────────────────────────────────────────

  async _tick () {
    if (!this._running || !this.node.appRegistry) return { complete: true }

    // A phase advances only after its own frozen high-water cycle completes.
    // Small fleets can finish all four phases in one invocation; large fleets
    // yield after a finite page and the completion scheduler resumes at once.
    for (let advances = 0; advances < 4; advances++) {
      if (this._phase === 'local-refresh') {
        const result = this._refreshFromLocal()
        if (!result.complete) return { complete: false, phase: this._phase, ...result }
        this._phase = 'federation-refresh'
        continue
      }
      if (this._phase === 'federation-refresh') {
        const result = this._refreshFromFederation()
        if (!result.complete) return { complete: false, phase: this._phase, ...result }
        this._phase = 'proofs'
        continue
      }
      if (this._phase === 'proofs') {
        const result = this.verifyProofs
          ? await this._refreshAnchorProofs()
          : { complete: true, examined: 0 }
        if (!this._running) return { complete: true, phase: 'stopped' }
        if (!result.complete) return { complete: false, phase: this._phase, ...result }
        this._phase = 'decision'
        continue
      }
      const result = await this._runDecisionPass()
      if (!result.complete) return { complete: false, phase: this._phase, ...result }
      this._phase = 'local-refresh'
      return { complete: true, phase: 'complete', ...result }
    }
    return { complete: false, phase: this._phase }
  }

  _newLiveBuild () {
    return {
      replicas: 0,
      regions: new Set(),
      operators: new Set(),
      ourOperatorCount: 0,
      hasOurRegion: false,
      hasOurOperator: false,
      maxStorage: null
    }
  }

  _countLiveReplica (build, appKey, pubkey, meta) {
    const bound = positiveStorageBound(meta?.maxStorage)
    if (bound !== null) build.maxStorage = Math.max(build.maxStorage || 0, bound)
    if (!meta || meta.anchored !== true) return
    if (this.verifyProofs && pubkey !== this._localPubkey() && !this._hasFreshProof(appKey, pubkey)) return
    const region = meta.region || 'unknown'
    const operator = meta.operator || pubkey
    build.replicas++
    build.regions.add(region)
    build.operators.add(operator)
    if (region === this._localRegion()) build.hasOurRegion = true
    if (operator === this._localOperator()) {
      build.hasOurOperator = true
      build.ourOperatorCount++
    }
  }

  _liveFromBuild (build) {
    const regions = [...build.regions].slice(0, MAX_PASS_BUDGET)
    const operators = [...build.operators].slice(0, MAX_PASS_BUDGET)
    return {
      replicas: build.replicas,
      regions,
      operators,
      regionCount: build.regions.size,
      operatorCount: build.operators.size,
      ourOperatorCount: build.ourOperatorCount,
      hasOurRegion: build.hasOurRegion,
      hasOurOperator: build.hasOurOperator,
      maxStorage: build.maxStorage
    }
  }

  async _runDecisionPass () {
    if (!this._fleetPopulation.isRegistered('auto-heal-decision')) {
      this._fleetPopulation.register('auto-heal-decision')
    }
    let remaining = this.decisionBudget
    let cycleComplete = false
    let completedHighWater = null

    while (remaining > 0 && !cycleComplete) {
      if (!this._decisionActive) {
        const apps = this._fleetPopulation.page(
          'auto-heal-decision',
          1,
          appKey => this._fleet.get(appKey)
        )
        remaining -= apps.examined
        const item = apps.entries[0]
        if (!item) {
          if (apps.complete) {
            cycleComplete = true
            completedHighWater = apps.completedHighWater
          }
          continue
        }
        const population = this._replicaPopulations.get(item.key)
        if (!population) continue
        if (!population.isRegistered('auto-heal-decision')) population.register('auto-heal-decision')
        this._decisionActive = {
          appKey: item.key,
          outerComplete: apps.complete,
          completedHighWater: apps.complete ? apps.completedHighWater : null,
          build: this._newLiveBuild()
        }
        if (remaining === 0) break
      }

      const active = this._decisionActive
      const replicas = this._fleet.get(active.appKey)
      const population = this._replicaPopulations.get(active.appKey)
      if (!replicas || !population) {
        this._decisionActive = null
        if (active.outerComplete) {
          cycleComplete = true
          completedHighWater = active.completedHighWater
        }
        continue
      }
      const page = population.page(
        'auto-heal-decision',
        remaining,
        pubkey => replicas.get(pubkey)
      )
      remaining -= page.examined
      const cutoff = Date.now() - this.staleMs
      for (const item of page.entries) {
        if (item.value.lastSeen < cutoff) {
          replicas.delete(item.key)
          population.delete(item.key)
          continue
        }
        this._countLiveReplica(active.build, active.appKey, item.key, item.value)
      }
      if (!page.complete) break

      population.unregister('auto-heal-decision')
      if (replicas.size === 0) {
        this._dropEmptyFleetEntry(active.appKey)
      } else {
        const live = this._liveFromBuild(active.build)
        await this._considerRecruit(active.appKey, replicas, live)
        this._recordSnapshotDrive(active.appKey, live)
      }
      this._decisionActive = null
      if (active.outerComplete) {
        cycleComplete = true
        completedHighWater = active.completedHighWater
      }
    }

    if (cycleComplete) {
      this._fleetPopulation.unregister('auto-heal-decision')
      this._snapshotComplete = Object.freeze({
        tracked: this._fleet.size,
        below: this._snapshotBuild.below,
        drives: Object.freeze(this._snapshotBuild.drives),
        completedAt: Date.now(),
        completedHighWater
      })
      this._snapshotBuild = { below: 0, drives: [] }
      this._decisionCycleRecruits = 0
      this._decisionCycleCapacityChecks = 0
    }
    return {
      complete: cycleComplete,
      examined: this.decisionBudget - remaining,
      completedHighWater
    }
  }

  _recordSnapshotDrive (appKey, live) {
    const meetsThreshold = this._meetsThreshold(live)
    if (!meetsThreshold) this._snapshotBuild.below++
    if (this._snapshotBuild.drives.length >= MAX_PUBLIC_DRIVE_DETAILS) return
    const back = this._backoff.get(appKey) || null
    this._snapshotBuild.drives.push(Object.freeze({
      appKey,
      replicas: live.replicas,
      regions: Object.freeze([...live.regions]),
      operators: Object.freeze([...live.operators]),
      regionCount: live.regionCount,
      operatorCount: live.operatorCount,
      meetsThreshold,
      haveLocally: this.node.appRegistry?.has?.(appKey) === true,
      backoff: back
        ? Object.freeze({ failures: back.failures, retryInMs: Math.max(0, back.retryAt - Date.now()) })
        : null
    }))
  }

  async _considerRecruit (appKey, replicas, live) {
    if (!this._running) return false
    if (this._meetsThreshold(live)) return false
    if (this._decisionCycleRecruits >= this.maxRecruitsPerTick) return false
    if (this.node.appRegistry.has(appKey)) return false

    const ourOperator = this._localOperator()
    const ourPubkey = this._localPubkey()
    const addsRegion = !live.hasOurRegion
    const addsOperator = !live.hasOurOperator
    const meetsRegionThreshold = live.regionCount >= this.thresholds.minRegions
    const meetsOperatorThreshold = live.operatorCount >= this.thresholds.minOperators
    const belowReplicas = live.replicas < this._targetReplicas()
    const fairshareCap = Math.ceil(this._targetReplicas() / this.thresholds.minOperators)
    const maxPerOperator = this.thresholds.maxPerOperator ?? fairshareCap
    const operatorAtCap = maxPerOperator > 0 && live.ourOperatorCount >= maxPerOperator
    const wouldAddDiversity = !replicas.has(ourPubkey) && !operatorAtCap &&
      (addsRegion || addsOperator || (belowReplicas && meetsRegionThreshold && meetsOperatorThreshold))
    if (!wouldAddDiversity) {
      if (operatorAtCap) {
        this.emit('recruit-skipped', { appKey, reason: 'operator-fairshare-cap', operator: ourOperator })
      }
      return false
    }
    if (!this._canAccept(appKey)) return false

    const maxStorage = positiveStorageBound(live.maxStorage)
    if (maxStorage === null) {
      this.emit('recruit-skipped', { appKey, reason: 'storage-bound-invalid' })
      return false
    }
    if (this._isInBackoff(appKey)) return false
    if (!this._jitterAccept(live)) {
      this.emit('recruit-skipped', { appKey, reason: 'jitter-defer' })
      return false
    }
    if (this._decisionCycleCapacityChecks >= this.maxCapacityChecksPerTick) {
      this.emit('recruit-skipped', {
        appKey,
        reason: 'capacity-check-budget',
        maxCapacityChecksPerTick: this.maxCapacityChecksPerTick
      })
      return false
    }
    this._decisionCycleCapacityChecks++
    const storage = this._storageCapacity(maxStorage)
    if (!storage.ok) {
      this.emit('recruit-skipped', {
        appKey,
        reason: storage.reason,
        usedBytes: storage.usedBytes,
        maxStorageBytes: storage.maxStorageBytes,
        storageMargin: storage.storageMargin,
        requestedBytes: maxStorage,
        availableBytes: storage.availableBytes
      })
      return false
    }

    try {
      await this.node.seedApp(appKey, {
        durability: ARCHIVE_TIER,
        revocable: false,
        source: 'auto-heal',
        maxStorage
      })
      this._decisionCycleRecruits++
      this._clearBackoff(appKey)
      let reason
      if (live.regionCount < this.thresholds.minRegions) reason = 'region-gap'
      else if (live.operatorCount < this.thresholds.minOperators) reason = 'operator-gap'
      else reason = 'replica-gap'
      this.emit('recruited', { appKey, before: live, reason })
      return true
    } catch (err) {
      this._recordFailure(appKey)
      this.emit('recruit-error', { appKey, error: err.message })
      return false
    }
  }

  // ─── Internal: capacity, backoff, jitter ───────────────────────────

  _hasStorageCapacity () {
    return this._storageCapacity().ok
  }

  _storageCapacity (additionalBytes = 0) {
    const rawMargin = this.storageMargin
    const margin = Number.isFinite(rawMargin) && rawMargin > 0 ? Math.min(rawMargin, 1) : 0.90
    const requested = Number(additionalBytes)
    const authority = this.node.storageAdmission
    const unavailable = (reason = 'storage-capacity-unavailable', details = {}) => ({
      ok: false,
      reason,
      usedBytes: null,
      maxStorageBytes: null,
      availableBytes: 0,
      storageMargin: margin,
      ...details
    })

    if (!Number.isSafeInteger(requested) || requested < 0) {
      return unavailable('storage-bound-invalid')
    }
    if (!authority || typeof authority.cachedRejection !== 'function') {
      return unavailable()
    }

    let hint
    try {
      const storageSummary = this.node.storageAccounting?.getSummary?.() || null
      hint = authority.cachedRejection(requested, {
        storageSummary,
        limitRatio: margin
      })
    } catch (_) {
      return unavailable('storage-capacity-unavailable')
    }

    if (!hint || typeof hint !== 'object' || typeof hint.reject !== 'boolean' ||
        (hint.reject === false && hint.exactRequired !== true)) {
      return unavailable('storage-capacity-unavailable')
    }

    const cap = Number(hint?.effectiveCapBytes)
    const used = Number(hint?.usedBytes)
    const available = Number(hint?.informationalAvailableBytes)
    if (hint?.reject === true) {
      return {
        ok: false,
        reason: hint.reason || 'storage-capacity-unavailable',
        usedBytes: Number.isSafeInteger(used) ? used : null,
        maxStorageBytes: Number.isSafeInteger(cap) ? cap : null,
        availableBytes: Number.isSafeInteger(available) ? available : 0,
        storageMargin: margin
      }
    }
    // `ok` means only "not rejected by the complete cache". seedApp() still
    // performs the sole exact drive reservation before any session/range.
    return {
      ok: true,
      reason: hint?.reason || null,
      exactRequired: true,
      usedBytes: Number.isSafeInteger(used) ? used : null,
      maxStorageBytes: Number.isSafeInteger(cap) ? cap : null,
      availableBytes: Number.isSafeInteger(available) ? available : 0,
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
    const regionGap = Math.max(0, this.thresholds.minRegions - live.regionCount)
    const operatorGap = Math.max(0, this.thresholds.minOperators - live.operatorCount)
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
    const count = this.node.federation?.peerCatalogCount
    return Number.isSafeInteger(count) && count >= 0 ? count : 0
  }

  // ─── Internal: data refresh ────────────────────────────────────────

  _refreshFromLocal () {
    const now = Date.now()
    const ourPubkey = this._localPubkey()
    const ourRegion = this._localRegion()
    const ourOperator = this._localOperator()
    if (typeof this.node.appRegistry.page !== 'function') {
      throw new Error('AutoHeal requires bounded AppRegistry pages')
    }
    const page = this.node.appRegistry.page('auto-heal', this.localRefreshBudget)
    for (const item of page.entries) {
      const entry = item.value
      if ((entry.durability || 0) !== ARCHIVE_TIER) {
        this._removeReplica(item.key, ourPubkey)
        continue
      }
      const bound = positiveStorageBound(entry.maxStorageBytes ?? entry.maxStorage)
      this._upsertReplica(item.key, ourPubkey, {
        region: ourRegion,
        operator: ourOperator,
        anchored: entry.anchored === true,
        lastSeen: now,
        url: null,
        maxStorage: bound
      })
    }
    return page
  }

  _refreshFromFederation () {
    if (!this.node.federation) return { complete: true, examined: 0 }
    if (typeof this.node.federation.getAutoHealPage !== 'function') {
      throw new Error('AutoHeal requires bounded federation pages')
    }
    const now = Date.now()
    const page = this.node.federation.getAutoHealPage(
      this._federationState,
      this.federationRefreshBudget
    )
    this._federationState = page.state
    for (const item of page.entries) {
      const peer = item.peer
      const app = item.app
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
      if (!peerPubkey || !app || (app.durability || 0) !== ARCHIVE_TIER) continue
      const appKey = app.appKey || app.driveKey || app.key
      if (!appKey) continue
      const bound = positiveStorageBound(app.maxStorageBytes ?? app.maxStorage)

      this._upsertReplica(appKey, peerPubkey, {
        region: peerRegion,
        operator: peerOperator,
        anchored: app.anchored === true,
        lastSeen: now,
        url: peer.url || null,
        maxStorage: bound
      })
    }
    return page
  }

  _upsertReplica (appKey, pubkey, meta) {
    const replicas = this._setFor(appKey)
    const population = this._replicaPopulations.get(appKey)
    if (!replicas.has(pubkey)) population.insert(pubkey)
    replicas.set(pubkey, meta)
  }

  _setFor (appKey) {
    let s = this._fleet.get(appKey)
    if (!s) {
      s = new Map()
      this._fleetPopulation.insert(appKey)
      this._fleet.set(appKey, s)
      this._replicaPopulations.set(appKey, new GenerationPopulation({
        name: `auto-heal-replicas:${appKey}`,
        allowedConsumers: ['auto-heal-proof', 'auto-heal-decision']
      }))
    }
    return s
  }

  _removeReplica (appKey, pubkey) {
    const replicas = this._fleet.get(appKey)
    const population = this._replicaPopulations.get(appKey)
    if (!replicas || !population || !replicas.delete(pubkey)) return false
    population.delete(pubkey)
    return true
  }

  _dropEmptyFleetEntry (appKey) {
    const replicas = this._fleet.get(appKey)
    if (replicas && replicas.size > 0) return false
    const population = this._replicaPopulations.get(appKey)
    population?.unregister('auto-heal-proof')
    population?.unregister('auto-heal-decision')
    this._replicaPopulations.delete(appKey)
    if (this._fleet.delete(appKey)) this._fleetPopulation.delete(appKey)
    return true
  }

  // ─── Internal: scoring / policy ────────────────────────────────────

  _hasFreshProof (appKey, peerPubkey) {
    const cached = this._proofCache.get(`${appKey}:${peerPubkey}`)
    if (!cached) return false
    const age = Date.now() - cached.fetchedAt
    if (age > this.proofFreshnessMs) return false
    if (cached.result.ok !== true) return false
    return cached.result.proof.anchored === true
  }

  async _refreshAnchorProofs () {
    if (!this._fleetPopulation.isRegistered('auto-heal-proof')) {
      this._fleetPopulation.register('auto-heal-proof')
    }
    let remaining = this.proofScanBudget
    let cycleComplete = false
    let completedHighWater = null
    const ourPubkey = this._localPubkey()
    const selected = []

    while (remaining > 0 && !cycleComplete && selected.length < this.maxProofsPerTick) {
      if (!this._proofActive) {
        const apps = this._fleetPopulation.page(
          'auto-heal-proof',
          1,
          appKey => this._fleet.get(appKey)
        )
        remaining -= apps.examined
        const item = apps.entries[0]
        if (!item) {
          if (apps.complete) {
            cycleComplete = true
            completedHighWater = apps.completedHighWater
          }
          continue
        }
        const population = this._replicaPopulations.get(item.key)
        if (!population) continue
        if (!population.isRegistered('auto-heal-proof')) population.register('auto-heal-proof')
        this._proofActive = {
          appKey: item.key,
          outerComplete: apps.complete,
          completedHighWater: apps.complete ? apps.completedHighWater : null
        }
        if (remaining === 0) break
      }

      const active = this._proofActive
      const replicas = this._fleet.get(active.appKey)
      const population = this._replicaPopulations.get(active.appKey)
      if (!replicas || !population) {
        this._proofActive = null
        if (active.outerComplete) {
          cycleComplete = true
          completedHighWater = active.completedHighWater
        }
        continue
      }
      const page = population.page('auto-heal-proof', 1, pubkey => replicas.get(pubkey))
      remaining -= page.examined
      const item = page.entries[0]
      if (item) {
        const meta = item.value
        const cacheKey = `${active.appKey}:${item.key}`
        const cached = this._proofCache.get(cacheKey)
        if (meta.anchored === true && item.key !== ourPubkey && meta.url &&
            (!cached || (Date.now() - cached.fetchedAt) >= this.proofFreshnessMs / 2)) {
          selected.push({
            appKey: active.appKey,
            peerPubkey: item.key,
            url: meta.url,
            cacheKey
          })
        }
      }
      if (page.complete) {
        population.unregister('auto-heal-proof')
        this._proofActive = null
        if (active.outerComplete) {
          cycleComplete = true
          completedHighWater = active.completedHighWater
        }
      }
    }

    if (selected.length >= this.maxProofsPerTick && !cycleComplete) {
      this.emit('proof-budget-throttled', {
        candidates: selected.length + 1,
        budget: this.maxProofsPerTick,
        deferred: 1
      })
    }

    // Items enter this fixed queue only after their outer and child
    // population inspections consumed budget. Workers launch lazily.
    let position = 0
    const workers = Array.from({ length: Math.min(16, selected.length) }, async () => {
      while (position < selected.length) {
        const candidate = selected[position++]
        try {
          const result = await this._fetchProof(candidate.url, candidate.appKey, {
            expectedPubkey: candidate.peerPubkey,
            freshnessMs: this.proofFreshnessMs * 2,
            anchorChannel: this._anchorChannel,
            peerPubkey: candidate.peerPubkey
          })
          this._setProofCache(candidate.cacheKey, { result, fetchedAt: Date.now() })
          if (!result.ok) {
            this.emit('proof-failed', {
              appKey: candidate.appKey,
              peerPubkey: candidate.peerPubkey,
              reason: result.reason
            })
          }
        } catch {
          this._setProofCache(candidate.cacheKey, {
            result: { ok: false, reason: 'fetch-error' },
            fetchedAt: Date.now()
          })
        }
      }
    })
    await Promise.all(workers)

    if (cycleComplete) {
      this._fleetPopulation.unregister('auto-heal-proof')
    }
    this._pruneProofCache()
    return {
      complete: cycleComplete,
      examined: this.proofScanBudget - remaining,
      fetched: selected.length,
      completedHighWater
    }
  }

  _setProofCache (key, value) {
    if (!this._proofCache.has(key)) this._proofCachePopulation.insert(key)
    this._proofCache.set(key, value)
  }

  _pruneProofCache () {
    if (!this._proofCachePopulation.isRegistered('auto-heal-proof-cache')) {
      this._proofCachePopulation.register('auto-heal-proof-cache')
    }
    const cutoff = Date.now() - this.proofFreshnessMs
    const page = this._proofCachePopulation.page(
      'auto-heal-proof-cache',
      this.proofScanBudget,
      key => this._proofCache.get(key)
    )
    for (const item of page.entries) {
      if (item.value.fetchedAt < cutoff) {
        this._proofCache.delete(item.key)
        this._proofCachePopulation.delete(item.key)
      }
    }
    if (page.complete) this._proofCachePopulation.unregister('auto-heal-proof-cache')
    return page
  }

  // Target = min + buffer. We keep recruiting until we hit target so that
  // transient churn (one host briefly offline) doesn't drop us below min.
  _targetReplicas () {
    return this.thresholds.minReplicas + (this.thresholds.replicaBuffer ?? 0)
  }

  _meetsThreshold (live) {
    return (
      live.replicas >= this._targetReplicas() &&
      live.regionCount >= this.thresholds.minRegions &&
      live.operatorCount >= this.thresholds.minOperators
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
