// eviction.js — over-replication shedding under disk pressure (Phase A).
//
// Root cause this addresses (2026-06-11): every fleet restart let the
// replication-repair pass adopt entries from the shared registry until
// each relay converged toward hosting the UNION of all catalogs — 5/5
// replicas of everything when targetReplicaFloor asks for 2 — and the
// storage guard that should have bounded adoption compared against the
// always-zero seeder.totalBytesStored. Disks filled; nobody asked for
// 5x durability.
//
// Policy (deliberately conservative — money-adjacent durability
// contracts are at stake):
//   - Runs only under disk pressure (DiskMonitor usedPct ≥
//     diskPressurePct) and stops once enough has been shed to project
//     below resumePct.
//   - An entry is a candidate ONLY if:
//       · durability === 0       (archive tier / operator pin is sacred)
//       · no custodyIntentId     (custody contracts are sacred)
//       · older than minAgeMs    (never churn fresh publishes)
//       · census says the network keeps ≥ target + floorMargin replicas
//         AFTER we leave (replication-health current/target, refreshed
//         every 60s by _checkReplicationHealth)
//   - Deterministic stagger: of the holders, only the K farthest by
//     XOR(relayPubkey, appKey) may shed in a given pass, where K is the
//     network's replica surplus. Two pressured relays therefore never
//     race to drop the same entry past the floor.
//   - Eviction = unseed (stop serving, drop registry entry) + purge the
//     drive's cores from disk (bytes actually return) + tombstone in the
//     app registry so boot-replay and repair don't resurrect it unless
//     the network later falls UNDER floor.
//
// Every eviction emits an audit event the node logs — operators can see
// exactly what was shed and why.

import { EventEmitter } from 'events'
import b4a from 'b4a'
import Hyperdrive from 'hyperdrive'
import { raceTimeout } from './storage-accounting.js'
import { buildDedupReport, compareSupersessionEntries } from './dedup-report.js'

const DEFAULTS = {
  enabled: false,
  diskPressurePct: 80,
  resumePct: 70,
  floorMargin: 1,
  minAgeMs: 6 * 60 * 60 * 1000, // 6h (see config/default.js — 3 days let boxes fill before shedding)
  sweepIntervalMs: 10 * 60 * 1000,
  maxEvictionsPerSweep: 20,
  // Replica target when an entry has no replication-health row (boot-
  // replayed entries without an active registry request). Wired from
  // config.targetReplicaFloor by relay-node.
  targetFloor: 2,
  // Above this disk usage the deterministic-stagger rank check is
  // bypassed (floor + margin still enforced). Rationale: rank defers to
  // the FARTHEST holders, but holders below diskPressurePct never sweep
  // — on an asymmetric fleet the deferral never resolves and a critical
  // box starves politely (utah, 2026-06-11: 337 entries rank-deferred
  // at 99% disk while bern sat at 8%). The floorMargin absorbs the
  // worst case of two pressured relays dropping the same entry in the
  // same sweep window.
  rankBypassPct: 92,
  // Per-operation timeouts (v0.15.6). Cores damaged by a disk-full
  // crash can wedge any await forever; one hung candidate must cost the
  // sweep seconds, not freeze it permanently.
  registryTimeoutMs: 5_000,
  measureTimeoutMs: 10_000,
  unseedTimeoutMs: 30_000,
  purgeTimeoutMs: 60_000
}

const TIMEOUT = Symbol('eviction-timeout')

/**
 * Purge a drive's cores from disk, surviving corruption. The normal
 * path opens a Hyperdrive and purges meta + blobs together — but a
 * header truncated by a disk-full crash makes that throw
 * DECODING_ERROR before the blobs core can even be located. Fallback:
 * purge the meta core directly via the corestore. The orphaned blob
 * core (locatable only through the now-unreadable header) stays on
 * disk — bounded loss, and a corrupt drive serves nobody, so removing
 * what we can plus tombstoning is strictly better than leaving it.
 *
 * Returns 'drive' | 'meta-only'. Throws only if both paths fail.
 */
export async function purgeDriveCores (store, appKeyHex, { purgeTimeoutMs = 60_000 } = {}) {
  const key = b4a.from(appKeyHex, 'hex')
  try {
    const drive = new Hyperdrive(store.session(), key)
    const full = await raceTimeout(
      (async () => { await drive.ready(); await drive.purge(); return true })(),
      purgeTimeoutMs,
      TIMEOUT
    )
    if (full === true) return 'drive'
  } catch {
    // fall through to meta-only
  }
  const core = store.get(key)
  const meta = await raceTimeout(
    (async () => { try { await core.ready() } catch {} await core.purge(); return true })(),
    purgeTimeoutMs,
    TIMEOUT
  )
  if (meta === true) return 'meta-only'
  try { await core.close() } catch {}
  const err = new Error('purge failed on both drive and meta-core paths')
  err.code = 'PURGE_FAILED'
  throw err
}

/**
 * Sacred-entry guard shared by the sweep and the operator's manual-purge
 * path: archive tier and custody contracts are non-evictable even with
 * explicit operator action — those are durability promises to publishers,
 * not housekeeping preferences. Throws with a stable code.
 */
export function assertPurgable (entry, now = Date.now()) {
  if (!entry) {
    const err = new Error('entry not found')
    err.code = 'NOT_FOUND'
    throw err
  }
  if ((entry.durability || 0) >= 1) {
    const err = new Error('archive-tier entry (durability >= 1) is not evictable')
    err.code = 'ARCHIVE_TIER'
    throw err
  }
  if (entry.custodyIntentId) {
    const err = new Error('custody-bound entry is not evictable')
    err.code = 'CUSTODY_BOUND'
    throw err
  }
  // A paid pin-lease is sacred until its window lapses — shedding it early
  // would be taking payment and not delivering (a refund/trust problem the
  // MVP has no settlement layer to resolve). Once expired, the custody-expiry
  // sweep unseeds it normally.
  if (entry.leaseManaged === true && Number.isFinite(entry.retainUntil) && entry.retainUntil > now) {
    const err = new Error('paid-lease entry is not evictable until its lease expires')
    err.code = 'LEASE_BOUND'
    throw err
  }
}

/** Lexicographic compare of XOR(a, b) buffers — bigger = farther. */
export function xorDistance (aHex, bHex) {
  const a = b4a.from(aHex, 'hex')
  const b = b4a.from(bHex, 'hex')
  const n = Math.min(a.byteLength, b.byteLength)
  const out = b4a.alloc(n)
  for (let i = 0; i < n; i++) out[i] = a[i] ^ b[i]
  return out
}

function compareBuffers (x, y) {
  const n = Math.min(x.byteLength, y.byteLength)
  for (let i = 0; i < n; i++) {
    if (x[i] !== y[i]) return x[i] - y[i]
  }
  return x.byteLength - y.byteLength
}

export class EvictionManager extends EventEmitter {
  /**
   * Dependency-injected for testability; relay-node/index.js wires the
   * real implementations.
   *
   * @param {object} deps
   * @param {object} deps.appRegistry            get/entries/markEvicted/isEvicted
   * @param {object} deps.seedingRegistry        getRelaysForApp(appKey)
   * @param {object} deps.storageAccounting      getBytes/measure/getSummary
   * @param {object} deps.diskMonitor            getInfo() -> { usedPct, totalBytes }
   * @param {function} deps.getReplicationHealth () -> Map(appKey -> {current,target})
   * @param {string} deps.myPubkeyHex
   * @param {function} deps.unseed               async (appKeyHex) -> void
   * @param {object} [deps.store]                corestore (for purge); omit in tests with purgeDrive injected
   * @param {function} [deps.purgeDrive]         async (appKeyHex) -> void (test seam)
   * @param {function} [deps.getStorageCap]      () -> number — the operator-DESIGNATED
   *   maxStorageBytes cap (0/undefined = unlimited). When our measured usage
   *   exceeds it, the sweep runs even below whole-disk pressure, so an operator
   *   who designates "give HiveRelay N GB of this box" gets shed down to N GB
   *   without needing the physical disk to be near-full.
   * @param {object} [config]                    eviction config block
   */
  constructor (deps, config = {}) {
    super()
    for (const k of ['appRegistry', 'seedingRegistry', 'storageAccounting', 'diskMonitor', 'getReplicationHealth', 'myPubkeyHex', 'unseed']) {
      if (!deps[k]) throw new Error('EvictionManager: missing dep ' + k)
    }
    this.deps = deps
    this._getStorageCap = typeof deps.getStorageCap === 'function' ? deps.getStorageCap : () => 0
    this.config = { ...DEFAULTS, ...config }

    this._interval = null
    this._sweeping = false
    this._evictedTotal = 0
    this._freedBytesTotal = 0
    this._lastSweep = null // { at, scanned, candidates, evicted, freedBytes, skipped }
  }

  start () {
    if (this._interval) return
    this._interval = setInterval(() => {
      this.sweep().catch(err => this.emit('error', err))
    }, this.config.sweepIntervalMs)
    if (this._interval.unref) this._interval.unref()
  }

  stop () {
    if (this._interval) {
      clearInterval(this._interval)
      this._interval = null
    }
  }

  // Our measured on-disk footprint, via the same StorageAccounting summary
  // the operator dashboard reports (st.blocks*512, matches df) — used to test
  // the designated-cap gate. Best-effort: 0 if unavailable (→ cap gate off).
  _measuredUsedBytes () {
    try {
      const s = this.deps.storageAccounting.getSummary()
      return Number(s && s.totalBytes) || 0
    } catch (_) {
      return 0
    }
  }

  async _purgeDrive (appKeyHex) {
    if (this.deps.purgeDrive) return this.deps.purgeDrive(appKeyHex)
    return purgeDriveCores(this.deps.store, appKeyHex, { purgeTimeoutMs: this.config.purgeTimeoutMs })
  }

  /**
   * Reclaim disk held by SUPERSEDED app versions — entries whose appId is
   * indexed to a newer appKey, i.e. stale versions the catalog already hides
   * but whose cores still occupy disk. This is single-relay dedup, NOT fleet
   * eviction: it ignores the cross-relay census entirely (a stale version is
   * dead regardless of how many relays hold the CURRENT one) and is gated only
   * by assertPurgable — archive/custody/lease entries are never reclaimed even
   * when superseded.
   *
   * Distinct from sweep(): no disk-pressure gate, no replica-floor check. Uses
   * the same proven teardown (unseed → markEvicted tombstone → purge cores).
   *
   * @param {object} [opts]
   * @param {boolean} [opts.dryRun=true]  report-only (no deletes) by default
   * @param {number}  [opts.retainVersions=0] keep the N newest superseded versions per appId
   * @param {string[]} [opts.retainKeys] exact signed rollback drive keys to retain
   * @param {string} [opts.appId] limit reclamation to one exact app id
   * @param {string} [opts.publisherPubkey] limit reclamation to one publisher
   * @param {number}  [opts.max=Infinity]  cap reclaims this pass
   * @returns {{dryRun, reclaimed:[], skipped:[], freedBytes, candidates}}
   */
  async reclaimSuperseded (opts = {}) {
    const dryRun = opts.dryRun !== false
    const retainVersions = Number.isFinite(opts.retainVersions) ? Math.max(0, opts.retainVersions) : 0
    const retainKeys = Array.isArray(opts.retainKeys)
      ? new Set(opts.retainKeys.filter(key => typeof key === 'string').map(key => key.toLowerCase()))
      : null
    const appId = typeof opts.appId === 'string' && opts.appId.length > 0 ? opts.appId : null
    const publisherPubkey = typeof opts.publisherPubkey === 'string' && opts.publisherPubkey.length > 0
      ? opts.publisherPubkey.toLowerCase()
      : null
    const max = Number.isFinite(opts.max) ? opts.max : Infinity
    const now = Date.now()

    const report = buildDedupReport(this.deps.appRegistry, this.deps.storageAccounting)
    const reclaimed = []
    const skipped = []
    let freedBytes = 0

    for (const group of report.supersededVersions.groups) {
      if (appId && group.appId !== appId) continue
      if (publisherPubkey && group.publisherPubkey?.toLowerCase() !== publisherPubkey) continue
      const current = this.deps.appRegistry.get(group.current)
      let candidates = group.superseded
      if (retainKeys) {
        candidates = group.superseded.filter(candidate => !retainKeys.has(candidate.appKey.toLowerCase()))
      } else if (retainVersions > 0) {
        // Keep the retainVersions newest superseded versions; reclaim the rest.
        // Deterministic order: version desc, then born-time desc, then appKey —
        // so versionless/equal-version ties don't reclaim on iteration order.
        candidates = [...group.superseded]
          .map(s => {
            const e = this.deps.appRegistry.get(s.appKey) || {}
            return { ...s, version: e.version || '0.0.0', bornAt: e.seededAt || e.startedAt || 0 }
          })
          .sort((a, b) => compareSupersessionEntries(b, a) || (b.bornAt - a.bornAt) || (a.appKey < b.appKey ? -1 : a.appKey > b.appKey ? 1 : 0))
          .slice(retainVersions)
      }
      for (const s of candidates) {
        if (reclaimed.length >= max) break
        const entry = this.deps.appRegistry.get(s.appKey)
        if (!entry) continue
        // Belt-and-suspenders: re-verify (independently of the report) that this
        // entry is provably an OLDER version of the SAME publisher's current —
        // a stale index or appId collision must never delete a live/unrelated
        // drive. The report already enforces this; this is defense-in-depth
        // against drift between report-build and now.
        if (!current ||
            !entry.publisherPubkey || entry.publisherPubkey !== current.publisherPubkey ||
            compareSupersessionEntries(entry, current) >= 0) {
          skipped.push({ appKey: s.appKey, reason: 'supersession-unverified' })
          continue
        }
        // Never reclaim a sacred entry, even if superseded.
        try {
          assertPurgable(entry, now)
        } catch (err) {
          skipped.push({ appKey: s.appKey, reason: err.code || 'not-purgable' })
          continue
        }
        if (dryRun) {
          reclaimed.push({ appKey: s.appKey, bytes: s.bytes, appId: group.appId })
          freedBytes += (s.bytes || 0)
          continue
        }
        // Bound a wedged unseed (a disk-full-corrupt core can hang the await
        // forever) — same guard the sweep uses. Bail BEFORE markEvicted/purge
        // so the tombstone-before-purge ordering is preserved.
        const unseeded = await raceTimeout(
          Promise.resolve().then(() => this.deps.unseed(s.appKey, { evictedAt: now })).then(() => true),
          this.config.unseedTimeoutMs,
          TIMEOUT
        )
        if (unseeded === TIMEOUT) {
          skipped.push({ appKey: s.appKey, reason: 'unseed-timeout' })
          continue
        }
        try {
          await this.deps.appRegistry.markEvicted(s.appKey, now)
          await this._purgeDrive(s.appKey)
          reclaimed.push({ appKey: s.appKey, bytes: s.bytes, appId: group.appId })
          freedBytes += (s.bytes || 0)
          this._freedBytesTotal += (s.bytes || 0)
          this.emit('reclaimed', { appKey: s.appKey, bytes: s.bytes || 0, appId: group.appId, reason: 'superseded' })
        } catch (err) {
          skipped.push({ appKey: s.appKey, reason: err.code || err.message })
        }
      }
    }

    const result = {
      dryRun,
      reclaimed,
      skipped,
      freedBytes,
      candidates: report.supersededVersions.count,
      unmeasured: report.supersededVersions.unmeasured,
      note: report.note
    }
    this.emit('reclaim-sweep', result)
    return result
  }

  /**
   * One eviction pass. Safe to call manually (operator API) — applies
   * the same pressure gate unless { force: true }.
   */
  async sweep (opts = {}) {
    if (this._sweeping) return { skipped: 'sweep-in-progress' }
    this._sweeping = true
    try {
      const now = opts.now || Date.now()
      const disk = this.deps.diskMonitor.getInfo()
      if (!disk || !Number.isFinite(disk.usedPct)) {
        return this._finish({ at: now, skipped: 'no-disk-signal', scanned: 0, candidates: 0, evicted: [], freedBytes: 0 })
      }
      // Over the operator-DESIGNATED cap? Then shed regardless of whole-disk
      // pressure — this is what makes "designate N GB and shrink to fit" work
      // on a box whose physical disk is nowhere near full. Cap 0 = unlimited.
      const cap = Number(this._getStorageCap()) || 0
      const usedBytes = this._measuredUsedBytes()
      const overCap = cap > 0 && usedBytes > cap
      if (!opts.force && !overCap && disk.usedPct < this.config.diskPressurePct) {
        return this._finish({ at: now, skipped: 'below-pressure', usedPct: disk.usedPct, scanned: 0, candidates: 0, evicted: [], freedBytes: 0 })
      }

      const health = this.deps.getReplicationHealth() || new Map()
      const my = this.deps.myPubkeyHex
      const candidates = []
      let scanned = 0
      // Skip-reason counters — without these, "candidates: 0" on a full
      // disk is undiagnosable from the outside (learned on the utah
      // canary, 2026-06-11).
      const skips = { archive: 0, custody: 0, lease: 0, young: 0, noBirth: 0, noCensus: 0, floor: 0, rank: 0, registryError: 0 }

      for (const [appKey, entry] of this.deps.appRegistry.entries()) {
        scanned++
        if (!entry) continue
        if ((entry.durability || 0) >= 1) { skips.archive++; continue } // archive / operator pin
        if (entry.custodyIntentId) { skips.custody++; continue } // custody contract
        // Paid pin-lease — sacred until its window lapses (don't take payment
        // then shed early). After expiry the custody-expiry sweep unseeds it.
        if (entry.leaseManaged === true && Number.isFinite(entry.retainUntil) && entry.retainUntil > now) { skips.lease++; continue }
        const bornAt = entry.addedAt || entry.startedAt || entry.seededAt || entry.firstSeenAt || 0
        if (!bornAt) { skips.noBirth++; continue }
        if (now - bornAt < this.config.minAgeMs) { skips.young++; continue }

        let relays
        try {
          relays = await raceTimeout(
            Promise.resolve(this.deps.seedingRegistry.getRelaysForApp(appKey)),
            this.config.registryTimeoutMs,
            TIMEOUT
          )
          if (relays === TIMEOUT) { skips.registryError++; continue }
        } catch {
          skips.registryError++
          continue
        }
        const holders = (relays || []).map(r => r.relayPubkey).filter(Boolean)

        // Census: the replication-health row when present (it knows the
        // per-request replicationFactor), else fall back to the registry
        // acceptance list with target = the configured replica floor.
        // The health map computes `current` from the SAME acceptance
        // records (getRelaysForApp), so the fallback is exactly as
        // trustworthy — it only lacks a per-request target. Without
        // this, boot-replayed entries with no active request (417 of
        // utah's 961 on the 2026-06-11 canary) are permanently
        // un-evictable. Entries with NO acceptance records at all stay
        // untouchable — never evict blind.
        let h = health.get(appKey)
        if (!h || !Number.isFinite(h.current) || !Number.isFinite(h.target)) {
          if (!holders.length) { skips.noCensus++; continue }
          h = { current: holders.length, target: Math.max(1, this.config.targetFloor) }
          skips.censusFallback = (skips.censusFallback || 0) + 1 // informational: counted AND still considered
        }
        const weAreCounted = holders.includes(my)
        // Replicas remaining if we leave. When the census doesn't count
        // us, leaving changes nothing — but then our copy is also not
        // load-bearing for the floor, so the same threshold applies.
        const remaining = weAreCounted ? h.current - 1 : h.current
        if (remaining < h.target + this.config.floorMargin) { skips.floor++; continue }

        // Deterministic stagger: only the K farthest holders may shed
        // this entry, K = how many copies the network can spare. Skipped
        // above rankBypassPct — politeness must not starve a critical
        // box when the farther holders are unpressured and will never
        // act (floor + margin remain the real safety). Also skipped when
        // we are over the operator's DESIGNATED cap: the operator asked us
        // to shrink to N bytes, so rank-politeness must not block it (floor
        // + margin still protect the network).
        const surplus = remaining - (h.target + this.config.floorMargin) + 1
        if (!overCap && disk.usedPct < this.config.rankBypassPct && weAreCounted && holders.length > 1) {
          const ranked = holders
            .map(pk => ({ pk, d: xorDistance(pk, appKey) }))
            .sort((a, b) => compareBuffers(b.d, a.d)) // farthest first
          const ourRank = ranked.findIndex(r => r.pk === my)
          if (ourRank === -1 || ourRank >= surplus) { skips.rank++; continue }
        }

        let bytes = this.deps.storageAccounting.getBytes(appKey)
        if (bytes == null) {
          bytes = await raceTimeout(
            Promise.resolve().then(() => this.deps.storageAccounting.measure(appKey)),
            this.config.measureTimeoutMs,
            0
          )
        }
        candidates.push({ appKey, bytes: bytes || 0, remaining, target: h.target })
      }

      // Biggest first — free the most disk with the fewest contract exits.
      candidates.sort((a, b) => b.bytes - a.bytes)

      const evicted = []
      let freedBytes = 0
      const volTotal = disk.totalBytes || null
      for (const cand of candidates) {
        if (evicted.length >= this.config.maxEvictionsPerSweep) break
        // Keep shedding while EITHER reason to sweep still holds: we're still
        // over the operator-designated cap, OR the physical disk is still
        // pressured. Stop once both are satisfied. (Pre-cap behaviour — stop at
        // resumePct — is preserved when no cap is set.)
        const stillOverCap = cap > 0 && (usedBytes - freedBytes) > cap
        const stillPressured = volTotal ? (disk.usedPct - (freedBytes / volTotal) * 100) > this.config.resumePct : true
        if (!stillOverCap && !stillPressured) break
        try {
          const unseeded = await raceTimeout(
            Promise.resolve().then(() => this.deps.unseed(cand.appKey, { evictedAt: now })).then(() => true),
            this.config.unseedTimeoutMs,
            TIMEOUT
          )
          if (unseeded === TIMEOUT) {
            this.emit('evict-failed', { appKey: cand.appKey, error: 'unseed timeout' })
            continue
          }
          // Tombstone as soon as the registry entry is gone — even if the
          // purge below fails (corrupt core), repair must not re-adopt a
          // drive we just established the network holds in surplus.
          await this.deps.appRegistry.markEvicted(cand.appKey, now)
          await this._purgeDrive(cand.appKey)
          freedBytes += cand.bytes
          this._evictedTotal++
          this._freedBytesTotal += cand.bytes
          evicted.push(cand.appKey)
          this.emit('evicted', {
            appKey: cand.appKey,
            bytes: cand.bytes,
            remainingReplicas: cand.remaining,
            target: cand.target,
            usedPct: disk.usedPct
          })
        } catch (err) {
          this.emit('evict-failed', { appKey: cand.appKey, error: err.code || err.message })
        }
      }

      return this._finish({ at: now, usedPct: disk.usedPct, scanned, candidates: candidates.length, skips, evicted, freedBytes })
    } finally {
      this._sweeping = false
    }
  }

  _finish (summary) {
    this._lastSweep = summary
    this.emit('sweep', summary)
    return summary
  }

  getSummary () {
    return {
      enabled: true,
      evictedTotal: this._evictedTotal,
      freedBytesTotal: this._freedBytesTotal,
      lastSweep: this._lastSweep
    }
  }
}
