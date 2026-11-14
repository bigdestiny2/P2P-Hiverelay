import { EventEmitter } from 'events'
import test from 'brittle'
import { Metrics, prometheusNumber } from '../../packages/core/core/relay-node/metrics.js'

test('metrics: Prometheus exporter uses redacted stats and clamps sample values', (t) => {
  const calls = []
  const node = new EventEmitter()
  node.getStats = function (opts) {
    calls.push(opts)
    return {
      seededApps: '5\nhiverelay_injected 1',
      connections: Infinity,
      seeder: {
        coresSeeded: '12.5',
        totalBytesStored: -7,
        totalBytesServed: 'nope'
      },
      served: {
        totalBytesServed: 42,
        totalBlocksServed: NaN
      },
      appRegistry: {
        entries: 3,
        anchored: '2',
        unanchored: 'bad',
        cores: 6
      },
      relay: {
        activeCircuits: -1,
        totalCircuitsServed: 4,
        totalBytesRelayed: '5e2'
      },
      tor: { onionAddress: 'secret.onion' },
      holesail: { connectionKey: 'secret-key' }
    }
  }
  const metrics = new Metrics(node)
  t.teardown(() => metrics.stop())

  const out = metrics.toPrometheus()

  t.alike(calls[0], { includeSecrets: false })
  t.absent(out.includes('secret.onion'))
  t.absent(out.includes('secret-key'))
  t.absent(out.includes('hiverelay_injected 1'))
  t.absent(out.includes('Infinity'))
  t.absent(out.includes('NaN'))
  t.ok(out.includes('hiverelay_seeded_apps 0'))
  t.ok(out.includes('hiverelay_connections 0'))
  t.ok(out.includes('hiverelay_cores_seeded 12.5'))
  t.ok(out.includes('hiverelay_bytes_stored 0'))
  t.ok(out.includes('hiverelay_bytes_served 0'))
  t.ok(out.includes('hiverelay_blocks_served_measured 0'))
  t.ok(out.includes('hiverelay_active_circuits 0'))
  t.ok(out.includes('hiverelay_bytes_relayed 500'))
})

test('metrics: snapshots and summaries request public-redacted stats', (t) => {
  const calls = []
  const node = new EventEmitter()
  node.getStats = function (opts) {
    calls.push(opts)
    if (opts && opts.includeSecrets === false) {
      return {
        seededApps: 1,
        tor: { enabled: true, onionAddress: null },
        holesail: { enabled: true, connectionKey: null }
      }
    }
    return {
      seededApps: 1,
      tor: { enabled: true, onionAddress: 'secret.onion' },
      holesail: { enabled: true, connectionKey: 'secret-key' }
    }
  }
  const metrics = new Metrics(node)
  t.teardown(() => metrics.stop())

  const snapshot = metrics._snapshot()
  const summary = metrics.getSummary()

  t.alike(calls, [{ includeSecrets: false }, { includeSecrets: false }])
  t.is(snapshot.tor.onionAddress, null)
  t.is(snapshot.holesail.connectionKey, null)
  t.is(summary.current.tor.onionAddress, null)
  t.is(summary.current.holesail.connectionKey, null)
})

test('metrics: Prometheus sample sanitizer emits finite non-negative numbers', (t) => {
  t.is(prometheusNumber('3.25'), 3.25)
  t.is(prometheusNumber(-1), 0)
  t.is(prometheusNumber(Infinity), 0)
  t.is(prometheusNumber('bad\n1'), 0)
  t.is(prometheusNumber(Number.MAX_SAFE_INTEGER + 1000), Number.MAX_SAFE_INTEGER)
})

test('metrics: exporter consumes only the cached bounded resource snapshot', (t) => {
  const node = new EventEmitter()
  node.getStats = () => ({ seededApps: 0, connections: 0 })
  node.getResourceDiagnostics = () => ({
    kind: 'HiveRelayResourceDiagnosticsV1',
    version: 1,
    sample: { available: true },
    process: {
      memory: {
        supported: true,
        rssBytes: 100,
        heapTotalBytes: 90,
        heapUsedBytes: 80,
        externalBytes: 70,
        arrayBuffersBytes: 60
      },
      fileDescriptors: { supported: true, value: 12, truncated: false },
      io: {
        readBytes: { supported: true, value: 1000, ratePerSecond: 25, reset: false },
        readOperations: { supported: true, value: 50, ratePerSecond: 2, reset: true }
      },
      majorFaults: { supported: true, value: 4, ratePerSecond: 1, reset: false }
    },
    cgroup: {
      supported: true,
      memory: {
        current: { value: 200 },
        max: { value: 400, unlimited: false },
        peak: { value: 300 }
      }
    },
    latency: {
      eventLoop: { supported: true, p50Ms: 1, p99Ms: 2, maxMs: 3 },
      health: { p50Ms: 4, p99Ms: 5, maxMs: 6, requests: 7, emptyResponses: 0, timeouts: 0 }
    },
    resources: {
      open: { storeCores: 8, hyperdrives: 9, relaySessions: 10 },
      accounting: { available: true, epochActive: true, operationsInFlight: 2 },
      flights: { pending: 1, orphanedPending: 0 }
    }
  })
  const metrics = new Metrics(node)
  t.teardown(() => metrics.stop())
  const out = metrics.toPrometheus()

  t.ok(out.includes('hiverelay_process_rss_bytes 100'))
  t.ok(out.includes('hiverelay_process_heap_bytes 80'))
  t.ok(out.includes('hiverelay_process_external_bytes 70'))
  t.ok(out.includes('hiverelay_process_arraybuffers_bytes 60'))
  t.ok(out.includes('hiverelay_process_open_fds 12'))
  t.ok(out.includes('hiverelay_process_read_bytes_per_second 25'))
  t.ok(out.includes('hiverelay_process_read_operations_reset 1'))
  t.ok(out.includes('hiverelay_cgroup_memory_current_bytes 200'))
  t.ok(out.includes('hiverelay_event_loop_delay_p99_ms 2'))
  t.ok(out.includes('hiverelay_health_handler_latency_p99_ms 5'))
  t.ok(out.includes('hiverelay_open_store_cores 8'))
  t.ok(out.includes('hiverelay_accounting_epoch_active 1'))
  t.ok(out.includes('hiverelay_shared_flights_pending 1'))
})
