import { EventEmitter } from 'events'

const MAX_SNAPSHOTS = 1440 // 24 hours of minutely snapshots
const MAX_PROMETHEUS_VALUE = Number.MAX_SAFE_INTEGER

export class Metrics extends EventEmitter {
  constructor (relayNode) {
    super()
    this.node = relayNode
    this.startedAt = Date.now()
    this._errorCount = 0

    // Circular buffer for snapshots
    this._buf = new Array(MAX_SNAPSHOTS)
    this._head = 0
    this._size = 0
    this.snapshotInterval = null

    // Track connection errors
    this.node.on('connection-error', () => { this._errorCount++ })

    this._startSnapshots()
  }

  _startSnapshots () {
    // Take a snapshot every 60 seconds
    this.snapshotInterval = setInterval(() => {
      this._buf[this._head] = this._snapshot()
      this._head = (this._head + 1) % MAX_SNAPSHOTS
      if (this._size < MAX_SNAPSHOTS) this._size++
    }, 60_000)
    if (typeof this.snapshotInterval.unref === 'function') this.snapshotInterval.unref()
  }

  get snapshots () {
    if (this._size === 0) return []
    if (this._size < MAX_SNAPSHOTS) {
      return this._buf.slice(0, this._size)
    }
    // Wrap around: oldest is at _head, newest is at _head - 1
    return [...this._buf.slice(this._head), ...this._buf.slice(0, this._head)]
  }

  getSummary () {
    const stats = this._stats()
    const uptimeMs = Date.now() - this.startedAt

    return {
      uptime: {
        ms: uptimeMs,
        hours: Math.round(uptimeMs / 3600000 * 100) / 100,
        human: this._formatUptime(uptimeMs)
      },
      current: stats,
      snapshotCount: this._size
    }
  }

  // Prometheus-compatible metrics output
  toPrometheus () {
    const stats = this._stats()
    const uptimeMs = Date.now() - this.startedAt
    const lines = []

    pushMetric(lines, 'hiverelay_uptime_seconds', 'Relay node uptime in seconds', 'gauge', Math.round(uptimeMs / 1000))

    pushMetric(lines, 'hiverelay_seeded_apps', 'Number of apps being seeded', 'gauge', stats.seededApps)

    pushMetric(lines, 'hiverelay_connections', 'Active peer connections', 'gauge', stats.connections)

    if (stats.seeder) {
      pushMetric(lines, 'hiverelay_cores_seeded', 'Number of Hypercores being seeded via Seeder.seedCore (registry log + standalone cores). Does NOT count appRegistry-managed Hyperdrive cores — see hiverelay_app_registry_cores.', 'gauge', stats.seeder.coresSeeded)

      pushMetric(lines, 'hiverelay_bytes_stored', 'Total bytes stored on disk', 'gauge', stats.seeder.totalBytesStored)

      pushMetric(lines, 'hiverelay_bytes_served', 'Bytes served from Seeder.seedCore-routed cores only (registry log + standalone cores). Reads ~0 on registry-drive relays — use hiverelay_bytes_served_measured for the honest total.', 'counter', stats.seeder.totalBytesServed)
    }

    if (stats.served) {
      // Honest served total: 'upload' bytes summed across EVERY replicated
      // core (registry log + appRegistry drive meta/blob cores), not just
      // the Seeder.seedCore-routed cores hiverelay_bytes_served counts.
      pushMetric(lines, 'hiverelay_bytes_served_measured', 'Total bytes served to peers across all replicated cores (replication-layer measured)', 'counter', stats.served.totalBytesServed)

      pushMetric(lines, 'hiverelay_blocks_served_measured', 'Total blocks uploaded to peers across all replicated cores', 'counter', stats.served.totalBlocksServed)
    }

    if (stats.appRegistry) {
      // v0.8.28 (#29): operator-visible counts for appRegistry-managed
      // Hyperdrives. The existing hiverelay_cores_seeded only counted
      // the seedingRegistry's log core (the only thing that went
      // through Seeder.seedCore), so a relay with 555 seeded apps
      // reported coresSeeded=1. These four counters give Prometheus
      // the actual operational state.
      pushMetric(lines, 'hiverelay_app_registry_entries', 'Number of appRegistry entries (one per published app/drive)', 'gauge', stats.appRegistry.entries)

      pushMetric(lines, 'hiverelay_app_registry_anchored', 'Number of entries with blob blocks fully replicated locally', 'gauge', stats.appRegistry.anchored)

      pushMetric(lines, 'hiverelay_app_registry_unanchored', 'Number of entries waiting on the repair pass to pull blocks', 'gauge', stats.appRegistry.unanchored)

      pushMetric(lines, 'hiverelay_app_registry_cores', 'Total underlying Hypercores managed via appRegistry (2 per Hyperdrive: meta + blob)', 'gauge', stats.appRegistry.cores)
    }

    if (stats.relay) {
      pushMetric(lines, 'hiverelay_active_circuits', 'Active relay circuits', 'gauge', stats.relay.activeCircuits)

      pushMetric(lines, 'hiverelay_total_circuits_served', 'Total circuits served', 'counter', stats.relay.totalCircuitsServed)

      pushMetric(lines, 'hiverelay_bytes_relayed', 'Total bytes relayed', 'counter', stats.relay.totalBytesRelayed)
    }

    // Process metrics
    const mem = process.memoryUsage()
    pushMetric(lines, 'hiverelay_process_heap_bytes', 'Process heap memory in bytes', 'gauge', mem.heapUsed)

    pushMetric(lines, 'hiverelay_process_rss_bytes', 'Process resident set size in bytes', 'gauge', mem.rss)

    // Error counter
    pushMetric(lines, 'hiverelay_errors_total', 'Total connection errors', 'counter', this._errorCount)

    return lines.join('\n') + '\n'
  }

  _stats () {
    if (!this.node || typeof this.node.getStats !== 'function') return {}
    return this.node.getStats({ includeSecrets: false }) || {}
  }

  _snapshot () {
    return {
      timestamp: Date.now(),
      ...this._stats()
    }
  }

  _formatUptime (ms) {
    const days = Math.floor(ms / 86400000)
    const hours = Math.floor((ms % 86400000) / 3600000)
    const minutes = Math.floor((ms % 3600000) / 60000)
    const parts = []
    if (days > 0) parts.push(`${days}d`)
    if (hours > 0) parts.push(`${hours}h`)
    parts.push(`${minutes}m`)
    return parts.join(' ')
  }

  stop () {
    if (this.snapshotInterval) {
      clearInterval(this.snapshotInterval)
      this.snapshotInterval = null
    }
  }
}

function pushMetric (lines, name, help, type, value) {
  lines.push(`# HELP ${name} ${help}`)
  lines.push(`# TYPE ${name} ${type}`)
  lines.push(`${name} ${prometheusNumber(value)}`)
}

export function prometheusNumber (value) {
  const number = Number(value)
  if (!Number.isFinite(number) || number < 0) return 0
  return Math.min(number, MAX_PROMETHEUS_VALUE)
}
