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

    // DHT-relay WS pure-pipe transport. Aggregate-only, matching the
    // transport's own neutrality contract: byte totals are frame-length
    // sums across all connections (the pipe's metering signal), never
    // per-client, never tied to an address.
    if (stats.dhtRelayWs) {
      pushMetric(lines, 'hiverelay_dhtrelay_active_connections', 'Active dht-relay-ws client connections', 'gauge', stats.dhtRelayWs.activeConnections)

      pushMetric(lines, 'hiverelay_dhtrelay_connections_total', 'Total dht-relay-ws connections served', 'counter', stats.dhtRelayWs.totalConnectionsServed)

      pushMetric(lines, 'hiverelay_dhtrelay_rate_limited_total', 'dht-relay-ws upgrades refused by the per-IP rate limiter', 'counter', stats.dhtRelayWs.totalRateLimited)

      pushMetric(lines, 'hiverelay_dhtrelay_reaped_total', 'dht-relay-ws connections reaped by the supervisor (dead socket, no first frame, backpressure, session limit, rx rate)', 'counter', stats.dhtRelayWs.totalReaped)

      pushMetric(lines, 'hiverelay_dhtrelay_bytes_in_total', 'Total bytes received across all dht-relay-ws connections (frame lengths only)', 'counter', stats.dhtRelayWs.totalBytesIn)

      pushMetric(lines, 'hiverelay_dhtrelay_bytes_out_total', 'Total bytes sent across all dht-relay-ws connections (frame lengths only)', 'counter', stats.dhtRelayWs.totalBytesOut)
    }

    // Process/resource metrics come from the bounded async sampler when it is
    // available. The exporter never opens procfs/cgroup files itself.
    const diagnostics = this._resourceDiagnostics()
    const sampledMemory = diagnostics?.process?.memory?.supported === true
      ? diagnostics.process.memory
      : null
    const mem = sampledMemory
      ? { heapUsed: sampledMemory.heapUsedBytes, rss: sampledMemory.rssBytes }
      : process.memoryUsage()
    pushMetric(lines, 'hiverelay_process_heap_bytes', 'Process heap memory in bytes', 'gauge', mem.heapUsed)

    pushMetric(lines, 'hiverelay_process_rss_bytes', 'Process resident set size in bytes', 'gauge', mem.rss)

    if (sampledMemory) {
      pushMetric(lines, 'hiverelay_process_heap_total_bytes', 'Process total heap memory in bytes', 'gauge', sampledMemory.heapTotalBytes)
      pushMetric(lines, 'hiverelay_process_heap_used_bytes', 'Process used heap memory in bytes', 'gauge', sampledMemory.heapUsedBytes)
      pushMetric(lines, 'hiverelay_process_external_bytes', 'Process external memory in bytes', 'gauge', sampledMemory.externalBytes)
      pushMetric(lines, 'hiverelay_process_arraybuffers_bytes', 'Process ArrayBuffer memory in bytes', 'gauge', sampledMemory.arrayBuffersBytes)
    }

    appendResourceMetrics(lines, diagnostics)

    // Error counter
    pushMetric(lines, 'hiverelay_errors_total', 'Total connection errors', 'counter', this._errorCount)

    return lines.join('\n') + '\n'
  }

  _stats () {
    if (!this.node || typeof this.node.getStats !== 'function') return {}
    return this.node.getStats({ includeSecrets: false }) || {}
  }

  _resourceDiagnostics () {
    if (!this.node || typeof this.node.getResourceDiagnostics !== 'function') return null
    try {
      const snapshot = this.node.getResourceDiagnostics()
      if (snapshot?.kind !== 'HiveRelayResourceDiagnosticsV1' || snapshot.version !== 1) return null
      return snapshot
    } catch {
      return null
    }
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

function appendResourceMetrics (lines, diagnostics) {
  if (!diagnostics) {
    pushMetric(lines, 'hiverelay_resource_diagnostics_available', 'Whether a bounded resource diagnostic sample is available', 'gauge', 0)
    return
  }
  pushMetric(lines, 'hiverelay_resource_diagnostics_available', 'Whether a bounded resource diagnostic sample is available', 'gauge', diagnostics.sample?.available === true ? 1 : 0)
  const fds = diagnostics.process?.fileDescriptors
  if (fds?.supported === true && Number.isFinite(fds.value)) {
    pushMetric(lines, 'hiverelay_process_open_fds', 'Bounded observed open file descriptor count', 'gauge', fds.value)
    pushMetric(lines, 'hiverelay_process_open_fds_truncated', 'Whether the file descriptor count reached its inspection cap', 'gauge', fds.truncated === true ? 1 : 0)
  }
  const io = diagnostics.process?.io
  appendCounterMetrics(lines, 'hiverelay_process_read_bytes', 'Process storage read bytes', io?.readBytes)
  appendCounterMetrics(lines, 'hiverelay_process_read_operations', 'Process read operations', io?.readOperations)
  appendCounterMetrics(lines, 'hiverelay_process_major_faults', 'Process major faults', diagnostics.process?.majorFaults)

  const cgroup = diagnostics.cgroup
  if (cgroup?.supported === true) {
    pushOptionalMetric(lines, 'hiverelay_cgroup_memory_current_bytes', 'Cgroup current memory in bytes', cgroup.memory?.current?.value)
    pushOptionalMetric(lines, 'hiverelay_cgroup_memory_max_bytes', 'Cgroup memory limit in bytes', cgroup.memory?.max?.value)
    pushOptionalMetric(lines, 'hiverelay_cgroup_memory_peak_bytes', 'Cgroup peak memory in bytes', cgroup.memory?.peak?.value)
    pushMetric(lines, 'hiverelay_cgroup_memory_max_unlimited', 'Whether the cgroup memory limit is unlimited', 'gauge', cgroup.memory?.max?.unlimited === true ? 1 : 0)
  }

  const eventLoop = diagnostics.latency?.eventLoop
  if (eventLoop?.supported === true) {
    pushOptionalMetric(lines, 'hiverelay_event_loop_delay_p50_ms', 'Event-loop delay p50 in milliseconds', eventLoop.p50Ms)
    pushOptionalMetric(lines, 'hiverelay_event_loop_delay_p99_ms', 'Event-loop delay p99 in milliseconds', eventLoop.p99Ms)
    pushOptionalMetric(lines, 'hiverelay_event_loop_delay_max_ms', 'Event-loop delay maximum in milliseconds', eventLoop.maxMs)
  }
  const health = diagnostics.latency?.health
  pushOptionalMetric(lines, 'hiverelay_health_handler_latency_p50_ms', 'Health handler latency p50 in milliseconds', health?.p50Ms)
  pushOptionalMetric(lines, 'hiverelay_health_handler_latency_p99_ms', 'Health handler latency p99 in milliseconds', health?.p99Ms)
  pushOptionalMetric(lines, 'hiverelay_health_handler_latency_max_ms', 'Health handler latency maximum in milliseconds', health?.maxMs)
  pushOptionalMetric(lines, 'hiverelay_health_handler_requests_total', 'Health handler requests observed', health?.requests, 'counter')
  pushOptionalMetric(lines, 'hiverelay_health_handler_empty_total', 'Health handler empty responses observed', health?.emptyResponses, 'counter')
  pushOptionalMetric(lines, 'hiverelay_health_handler_timeouts_total', 'Health handler timeouts observed', health?.timeouts, 'counter')

  const open = diagnostics.resources?.open
  pushOptionalMetric(lines, 'hiverelay_open_store_cores', 'Open Corestore cores tracked by served accounting', open?.storeCores)
  pushOptionalMetric(lines, 'hiverelay_open_hyperdrives', 'Open Hyperdrives owned by AppRegistry', open?.hyperdrives)
  pushOptionalMetric(lines, 'hiverelay_open_relay_sessions', 'Open relay replication sessions', open?.relaySessions)
  const accounting = diagnostics.resources?.accounting
  pushOptionalMetric(lines, 'hiverelay_accounting_epoch_active', 'Whether a storage accounting epoch is active', accounting?.epochActive === true ? 1 : 0)
  pushOptionalMetric(lines, 'hiverelay_accounting_epoch_operations_inflight', 'Storage accounting epoch operations in flight', accounting?.operationsInFlight)
  pushOptionalMetric(lines, 'hiverelay_shared_flights_pending', 'Pending shared core/drive operations', diagnostics.resources?.flights?.pending)
  pushOptionalMetric(lines, 'hiverelay_shared_flights_orphaned', 'Unresolved orphaned shared core/drive operations', diagnostics.resources?.flights?.orphanedPending)
}

function appendCounterMetrics (lines, name, help, counter) {
  if (counter?.supported !== true) return
  pushOptionalMetric(lines, `${name}_total`, help, counter.value, 'counter')
  pushOptionalMetric(lines, `${name}_per_second`, help + ' per second over the latest observation window', counter.ratePerSecond)
  pushMetric(lines, `${name}_reset`, `Whether ${help.toLowerCase()} reset in the latest observation window`, 'gauge', counter.reset === true ? 1 : 0)
}

function pushOptionalMetric (lines, name, help, value, type = 'gauge') {
  if (!Number.isFinite(value) || value < 0) return
  pushMetric(lines, name, help, type, value)
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
