// disk-monitor.js — periodic disk-usage check for the storage volume.
//
// Issue #27: PR #25 (v0.8.22) traced back to milkyb-iad's 1 GB Fly volume
// hitting 100% full. The disk-full root cause took several hours to find
// because no relay-side signal surfaced "this volume is near capacity" —
// the visible symptoms all looked like code bugs in the new replication
// layers. This module is the cheap operator-visible signal that closes
// that gap.
//
// Design:
//   - Background poll via `df -kP <storagePath>` on a 30s timer
//   - Result cached in memory; getInfo() returns it synchronously
//   - getStats() (called by /status) reads the cache; no I/O on the
//     hot path so uptime monitors + Prometheus scrapers don't add df
//     overhead
//   - Optional /health gate via threshold — returns 503 above critical
//     so load balancers can drain traffic
//
// Linux + macOS only. `df` exists on Windows but its output format is
// different; the relay isn't a Windows target so this is acceptable.

import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

const DEFAULT_REFRESH_MS = 30_000
const DF_TIMEOUT_MS = 5_000
const DEFAULT_WARN_PCT = 85
const DEFAULT_CRITICAL_PCT = 95

export class DiskMonitor {
  constructor (storagePath, opts = {}) {
    if (!storagePath) throw new Error('DiskMonitor: storagePath is required')
    this.storagePath = storagePath
    this.warnThreshold = Number.isFinite(opts.warnThreshold)
      ? opts.warnThreshold
      : DEFAULT_WARN_PCT
    this.criticalThreshold = Number.isFinite(opts.criticalThreshold)
      ? opts.criticalThreshold
      : DEFAULT_CRITICAL_PCT
    this.refreshIntervalMs = Number.isFinite(opts.refreshIntervalMs)
      ? Math.max(5_000, opts.refreshIntervalMs)
      : DEFAULT_REFRESH_MS

    this._cache = null
    this._refreshInterval = null
    this._refreshing = null
    this._started = false
  }

  /**
   * Begin background refresh polling. First poll fires immediately so the
   * first /status request after startup gets real data (modulo the few ms
   * df takes to return).
   */
  start () {
    if (this._started) return
    this._started = true

    // Initial refresh — don't await; getInfo() will return null until it
    // settles, which is fine for a transient startup window.
    this._refreshing = this._refresh().catch(() => {})

    this._refreshInterval = setInterval(() => {
      this._refreshing = this._refresh().catch(() => {})
    }, this.refreshIntervalMs)
    if (this._refreshInterval.unref) this._refreshInterval.unref()
  }

  stop () {
    if (this._refreshInterval) {
      clearInterval(this._refreshInterval)
      this._refreshInterval = null
    }
    this._started = false
  }

  /**
   * Returns the latest cached disk info, or null if the first poll hasn't
   * completed yet (startup window).
   *
   * Shape:
   *   {
   *     usedPct: number (0-100, integer),
   *     usedBytes: number,
   *     freeBytes: number,
   *     totalBytes: number,
   *     mountPath: string,
   *     status: 'ok' | 'warn' | 'critical',
   *     checkedAt: number (ms since epoch)
   *   }
   *
   * Or, if df has failed every time so far and there's no prior good
   * sample:
   *   { error: string, checkedAt: number }
   */
  getInfo () {
    return this._cache
  }

  /**
   * Force a fresh poll and return the result. Useful for tests and for the
   * one-off /api/health-detail endpoint that wants up-to-the-second data.
   */
  async refresh () {
    await this._refresh()
    return this._cache
  }

  async _refresh () {
    try {
      const { stdout } = await execFileAsync('df', ['-kP', this.storagePath], {
        timeout: DF_TIMEOUT_MS
      })
      const parsed = this._parseDf(stdout)

      // Preserve prior cache fields if parsing returns a partial result.
      const usedPct = parsed.totalBytes > 0
        ? Math.round((parsed.usedBytes / parsed.totalBytes) * 100)
        : 0

      const status = usedPct >= this.criticalThreshold
        ? 'critical'
        : usedPct >= this.warnThreshold
          ? 'warn'
          : 'ok'

      this._cache = {
        usedPct,
        usedBytes: parsed.usedBytes,
        freeBytes: parsed.freeBytes,
        totalBytes: parsed.totalBytes,
        mountPath: parsed.mountPath,
        status,
        checkedAt: Date.now()
      }
    } catch (err) {
      // Keep prior good cache if we have one (transient df failures
      // shouldn't blank the field). If we don't have one, surface the
      // error so operators can see why disk info is missing.
      if (!this._cache || this._cache.error) {
        this._cache = { error: String((err && err.message) || err), checkedAt: Date.now() }
      }
    }
  }

  /**
   * Parse one row of POSIX df -kP output. Format:
   *
   *   Filesystem     1024-blocks      Used Available Capacity Mounted on
   *   /dev/sda1         51190108  23456789  25178945      48% /
   *
   * Returns { totalBytes, usedBytes, freeBytes, mountPath }.
   * Internal — exported for tests via the named export below.
   */
  _parseDf (stdout) {
    const lines = String(stdout).trim().split('\n')
    if (lines.length < 2) throw new Error('df returned no data row')
    // df sometimes wraps long filesystem paths to the next line — join
    // and re-split on whitespace, then take the LAST 5 fields (capacity
    // 1k-blocks used available capacity% mountpoint) so the filesystem
    // column can contain spaces if it has to.
    const tokens = lines.slice(1).join(' ').split(/\s+/).filter(Boolean)
    if (tokens.length < 6) throw new Error('df row has fewer than 6 columns: ' + tokens.length)
    const totalBlocks = parseInt(tokens[tokens.length - 5], 10)
    const usedBlocks = parseInt(tokens[tokens.length - 4], 10)
    const availBlocks = parseInt(tokens[tokens.length - 3], 10)
    const mountPath = tokens[tokens.length - 1]

    if (!Number.isFinite(totalBlocks) || !Number.isFinite(usedBlocks) || !Number.isFinite(availBlocks)) {
      throw new Error('df output failed to parse: ' + tokens.slice(-5).join(' '))
    }

    return {
      totalBytes: totalBlocks * 1024,
      usedBytes: usedBlocks * 1024,
      freeBytes: availBlocks * 1024,
      mountPath
    }
  }
}

// Exported for unit tests that want to verify parsing against canned df
// output without actually running df.
export function parseDfOutput (stdout) {
  const dm = new DiskMonitor('/tmp')
  return dm._parseDf(stdout)
}
