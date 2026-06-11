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

const DEFAULTS = {
  enabled: false,
  diskPressurePct: 80,
  resumePct: 70,
  floorMargin: 1,
  minAgeMs: 3 * 24 * 60 * 60 * 1000, // 3 days
  sweepIntervalMs: 10 * 60 * 1000,
  maxEvictionsPerSweep: 20,
  // Replica target when an entry has no replication-health row (boot-
  // replayed entries without an active registry request). Wired from
  // config.targetReplicaFloor by relay-node.
  targetFloor: 2
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
   * @param {object} [config]                    eviction config block
   */
  constructor (deps, config = {}) {
    super()
    for (const k of ['appRegistry', 'seedingRegistry', 'storageAccounting', 'diskMonitor', 'getReplicationHealth', 'myPubkeyHex', 'unseed']) {
      if (!deps[k]) throw new Error('EvictionManager: missing dep ' + k)
    }
    this.deps = deps
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

  async _purgeDrive (appKeyHex) {
    if (this.deps.purgeDrive) return this.deps.purgeDrive(appKeyHex)
    // Fresh main session over the (now unseeded) cores; purge() frees the
    // meta + blob core files on disk and closes the drive.
    const drive = new Hyperdrive(this.deps.store.session(), b4a.from(appKeyHex, 'hex'))
    await drive.ready()
    await drive.purge()
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
      if (!opts.force && disk.usedPct < this.config.diskPressurePct) {
        return this._finish({ at: now, skipped: 'below-pressure', usedPct: disk.usedPct, scanned: 0, candidates: 0, evicted: [], freedBytes: 0 })
      }

      const health = this.deps.getReplicationHealth() || new Map()
      const my = this.deps.myPubkeyHex
      const candidates = []
      let scanned = 0
      // Skip-reason counters — without these, "candidates: 0" on a full
      // disk is undiagnosable from the outside (learned on the utah
      // canary, 2026-06-11).
      const skips = { archive: 0, custody: 0, young: 0, noBirth: 0, noCensus: 0, floor: 0, rank: 0, registryError: 0 }

      for (const [appKey, entry] of this.deps.appRegistry.entries()) {
        scanned++
        if (!entry) continue
        if ((entry.durability || 0) >= 1) { skips.archive++; continue } // archive / operator pin
        if (entry.custodyIntentId) { skips.custody++; continue } // custody contract
        const bornAt = entry.addedAt || entry.startedAt || entry.seededAt || entry.firstSeenAt || 0
        if (!bornAt) { skips.noBirth++; continue }
        if (now - bornAt < this.config.minAgeMs) { skips.young++; continue }

        let relays
        try {
          relays = await this.deps.seedingRegistry.getRelaysForApp(appKey)
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
        // this entry, K = how many copies the network can spare.
        const surplus = remaining - (h.target + this.config.floorMargin) + 1
        if (weAreCounted && holders.length > 1) {
          const ranked = holders
            .map(pk => ({ pk, d: xorDistance(pk, appKey) }))
            .sort((a, b) => compareBuffers(b.d, a.d)) // farthest first
          const ourRank = ranked.findIndex(r => r.pk === my)
          if (ourRank === -1 || ourRank >= surplus) { skips.rank++; continue }
        }

        let bytes = this.deps.storageAccounting.getBytes(appKey)
        if (bytes == null) {
          try { bytes = await this.deps.storageAccounting.measure(appKey) } catch { bytes = 0 }
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
        if (volTotal) {
          const projectedPct = disk.usedPct - (freedBytes / volTotal) * 100
          if (projectedPct <= this.config.resumePct) break
        }
        try {
          await this.deps.unseed(cand.appKey)
          await this._purgeDrive(cand.appKey)
          this.deps.appRegistry.markEvicted(cand.appKey, now)
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
          this.emit('evict-failed', { appKey: cand.appKey, error: err.message })
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
